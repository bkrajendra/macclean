//! The cancellable, incremental, error-tolerant filesystem scan.
//! Ported from Python `scan_stream` / `exact_candidates`.

use crate::model::*;
use crate::rules::{self, RuleIndex, Strategy};
use crate::safety;
use crate::scope;
use crate::session::{now_ms, StoredCandidate};
use crate::sysinfo;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Progress is emitted every this-many walked directories (Python parity).
const PROGRESS_EVERY_DIRS: u64 = 250;

/// Events streamed during a scan.
pub enum ScanEvent {
    Started {
        scan_id: String,
        roots: Vec<PathBuf>,
    },
    Candidate(ScanCandidate),
    Progress {
        scanned_dirs: u64,
        current_dir: PathBuf,
        items_found: u64,
        bytes_found: u64,
        errors: u64,
    },
    Error(ScanError),
    Finished(ScanSummary),
}

/// What a completed [`scan`] hands back to the caller (the Tauri layer turns
/// `candidates` into a session).
pub struct ScanReport {
    pub summary: ScanSummary,
    pub candidates: Vec<StoredCandidate>,
}

/// A shareable cancel flag.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    pub fn raw(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }
}

struct ScanRun<'a, F: FnMut(ScanEvent)> {
    scope: Scope,
    rule_index: RuleIndex,
    rule_homes: Vec<PathBuf>,
    cancel: &'a CancelToken,
    emit: &'a mut F,

    seen: HashSet<PathBuf>,
    candidates: Vec<StoredCandidate>,
    total_bytes: u64,
    scanned_dirs: u64,
    permission_denied: u64,
    errors: Vec<ScanError>,
}

impl<F: FnMut(ScanEvent)> ScanRun<'_, F> {
    fn emit_progress(&mut self, current: &Path) {
        let ev = ScanEvent::Progress {
            scanned_dirs: self.scanned_dirs,
            current_dir: current.to_path_buf(),
            items_found: self.candidates.len() as u64,
            bytes_found: self.total_bytes,
            errors: self.errors.len() as u64,
        };
        (self.emit)(ev);
    }

    fn record_error(&mut self, path: &Path, err: &io::Error) {
        let kind = match err.kind() {
            io::ErrorKind::PermissionDenied => {
                self.permission_denied += 1;
                ScanErrorKind::PermissionDenied
            }
            io::ErrorKind::NotFound => ScanErrorKind::NotFound,
            _ => ScanErrorKind::Io,
        };
        let e = ScanError {
            path: path.to_string_lossy().into_owned(),
            kind,
            message: err.to_string(),
        };
        self.errors.push(e.clone());
        (self.emit)(ScanEvent::Error(e));
    }

    /// Emit one candidate if it passes all gates (existence, protected, dedupe).
    fn emit_item(&mut self, path: &Path, label: &str, category: Category) {
        if self.cancel.is_cancelled() {
            return;
        }
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        if safety::is_protected(path) {
            return;
        }
        let real = safety::real(path);
        if !self.seen.insert(real.clone()) {
            return;
        }

        let is_symlink = meta.file_type().is_symlink();
        let is_dir = !is_symlink && meta.is_dir();
        let (size, item_count) = if is_dir {
            dir_stats(path)
        } else {
            (meta.len(), 1)
        };

        #[cfg(unix)]
        let (dev, ino) = (meta.dev(), meta.ino());
        #[cfg(not(unix))]
        let (dev, ino) = (0u64, 0u64);

        let stored = StoredCandidate {
            id: uuid::Uuid::new_v4().simple().to_string(),
            path: path.to_path_buf(),
            real_path: real,
            display_path: safety::display_path(path),
            group: rules::path_group(path),
            size_bytes: size,
            item_count,
            is_dir,
            is_symlink,
            category,
            label: label.to_string(),
            dev,
            ino,
        };

        self.total_bytes += size;
        (self.emit)(ScanEvent::Candidate(stored.to_wire()));
        self.candidates.push(stored);
    }

    /// Python `exact_candidates`, folded straight into `emit_item`.
    fn run_exact_rules(&mut self) {
        let homes = scope::homes_for_scope(self.scope);
        for home in &homes {
            for rule in rules::HOME_EXACT_RULES {
                if self.cancel.is_cancelled() {
                    return;
                }
                let base = rules::home_rule_base(rule, home);
                self.apply_exact(&base, rule.strategy, rule.label, rule.category);
            }
        }
        if matches!(self.scope, Scope::FullMac) {
            for rule in rules::SYSTEM_EXACT_RULES {
                if self.cancel.is_cancelled() {
                    return;
                }
                let base = PathBuf::from(rule.template);
                self.apply_exact(&base, rule.strategy, rule.label, rule.category);
            }
        }
    }

    fn apply_exact(&mut self, base: &Path, strategy: Strategy, label: &str, category: Category) {
        match strategy {
            Strategy::Path => self.emit_item(base, label, category),
            Strategy::Children => match std::fs::read_dir(base) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if self.cancel.is_cancelled() {
                            return;
                        }
                        self.emit_item(&entry.path(), label, category);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => self.record_error(base, &e),
            },
        }
    }

    /// The recursive directory walk (Python's `os.walk` loop).
    fn run_walk(&mut self, roots: &[PathBuf]) {
        for root in roots {
            if self.cancel.is_cancelled() {
                return;
            }
            if !root.is_dir() {
                continue;
            }
            let mut it = walkdir::WalkDir::new(root).follow_links(false).into_iter();

            loop {
                if self.cancel.is_cancelled() {
                    return;
                }
                let entry = match it.next() {
                    None => break,
                    Some(Ok(e)) => e,
                    Some(Err(err)) => {
                        let path = err.path().map(Path::to_path_buf).unwrap_or_default();
                        if let Some(io_err) = err.io_error() {
                            let io_err = io::Error::new(io_err.kind(), io_err.to_string());
                            self.record_error(&path, &io_err);
                        }
                        continue;
                    }
                };

                let path = entry.path().to_path_buf();
                let file_type = entry.file_type();
                let name = entry.file_name().to_string_lossy().into_owned();

                if file_type.is_dir() {
                    if rules::is_excluded_dir(&name) {
                        it.skip_current_dir();
                        continue;
                    }
                    if let Some(rule) = self.rule_index.dirs.get(name.as_str()).copied() {
                        let (label, category) =
                            self.resolve_label(&path, rule.label, rule.category);
                        self.emit_item(&path, &label, category);
                        it.skip_current_dir();
                        continue;
                    }
                    self.scanned_dirs += 1;
                    if self.scanned_dirs % PROGRESS_EVERY_DIRS == 0 {
                        self.emit_progress(&path);
                    }
                } else if file_type.is_symlink() {
                    // Never followed. A symlinked *file* can still match a file
                    // rule (Python behaviour); a symlinked *dir* is simply not
                    // descended and not matched by a dir rule.
                    self.match_file(&path, &name);
                } else if file_type.is_file() {
                    self.match_file(&path, &name);
                }
            }
        }
    }

    fn match_file(&mut self, path: &Path, name: &str) {
        if let Some(rule) = self.rule_index.file_exact.get(name).copied() {
            self.emit_item(path, rule.label, rule.category);
            return;
        }
        let suffix_hit = self
            .rule_index
            .file_suffix
            .iter()
            .find(|r| name.ends_with(r.key))
            .copied();
        if let Some(rule) = suffix_hit {
            self.emit_item(path, rule.label, rule.category);
        }
    }

    /// For `home` / `full_mac` scopes a recursive match inside an exact-rule tree
    /// is relabelled (`classify_exact_rule`).
    fn resolve_label(
        &self,
        path: &Path,
        default_label: &str,
        default_category: Category,
    ) -> (String, Category) {
        if matches!(self.scope, Scope::Home | Scope::FullMac) {
            return rules::classify_exact_rule(path, &self.rule_homes);
        }
        (default_label.to_string(), default_category)
    }
}

/// `(total_bytes, file_count)` for a directory tree: native, symlink-free.
/// Errors contribute 0 (Python `get_size` parity).
pub fn dir_stats(path: &Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut files = 0u64;
    for entry in walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        if let Ok(m) = entry.metadata() {
            bytes += m.len();
            files += 1;
        }
    }
    (bytes, files)
}

/// Size of a directory tree (see [`dir_stats`]).
pub fn dir_size(path: &Path) -> u64 {
    dir_stats(path).0
}

/// Run a full scan for `options`, streaming [`ScanEvent`]s through `emit`.
///
/// This mirrors the Python `scan_stream`: the scope's directory roots are
/// walked with the recursive rules for the mode, **and** the user-level exact
/// cache rules are always applied (the `FullMac` scope adds the system exact
/// rules). `cancel` can be tripped from another thread at any time.
pub fn scan<F: FnMut(ScanEvent)>(
    options: &ScanOptions,
    cancel: &CancelToken,
    emit: F,
) -> ScanReport {
    scan_with_id(new_scan_id(), options, cancel, emit)
}

/// Like [`scan`] but with a caller-supplied scan id (so the Tauri layer can
/// return the id before the scan thread finishes).
pub fn scan_with_id<F: FnMut(ScanEvent)>(
    scan_id: impl Into<String>,
    options: &ScanOptions,
    cancel: &CancelToken,
    emit: F,
) -> ScanReport {
    let roots = scope::roots(options.scope, &options.extra_roots);
    scan_roots_with_id(
        scan_id,
        roots,
        options.mode,
        options.scope,
        true,
        cancel,
        emit,
    )
}

pub fn new_scan_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Scan exactly `roots` with the recursive rules for `mode`.
///
/// When `include_exact_rules` is `true` the scope's exact cache rules also run
/// (against the scope's home / system paths) — this is what [`scan`] uses. With
/// `false`, only the given directory trees are walked, which is the right
/// primitive for a "scan just this folder" action and for hermetic tests.
pub fn scan_with_roots<F: FnMut(ScanEvent)>(
    roots: Vec<PathBuf>,
    mode: Mode,
    scope_: Scope,
    include_exact_rules: bool,
    cancel: &CancelToken,
    emit: F,
) -> ScanReport {
    scan_roots_with_id(
        new_scan_id(),
        roots,
        mode,
        scope_,
        include_exact_rules,
        cancel,
        emit,
    )
}

/// The scan primitive: caller-supplied id, explicit roots.
#[allow(clippy::too_many_arguments)]
pub fn scan_roots_with_id<F: FnMut(ScanEvent)>(
    scan_id: impl Into<String>,
    roots: Vec<PathBuf>,
    mode: Mode,
    scope_: Scope,
    include_exact_rules: bool,
    cancel: &CancelToken,
    mut emit: F,
) -> ScanReport {
    let started_at_ms = now_ms();
    let scan_id = scan_id.into();

    emit(ScanEvent::Started {
        scan_id: scan_id.clone(),
        roots: roots.clone(),
    });

    let rule_homes = if matches!(scope_, Scope::Home | Scope::FullMac) {
        scope::homes_for_scope(scope_)
    } else {
        Vec::new()
    };

    let mut run = ScanRun {
        scope: scope_,
        rule_index: rules::rules_for_mode(mode),
        rule_homes,
        cancel,
        emit: &mut emit,
        seen: HashSet::new(),
        candidates: Vec::new(),
        total_bytes: 0,
        scanned_dirs: 0,
        permission_denied: 0,
        errors: Vec::new(),
    };

    if include_exact_rules {
        run.run_exact_rules();
    }
    if !cancel.is_cancelled() {
        run.run_walk(&roots);
    }

    let state = if cancel.is_cancelled() {
        ScanState::Cancelled
    } else {
        ScanState::Completed
    };

    let candidates = std::mem::take(&mut run.candidates);
    let errors = std::mem::take(&mut run.errors);
    let scanned_dirs = run.scanned_dirs;
    let permission_denied = run.permission_denied;
    drop(run);

    let summary = build_summary(
        &scan_id,
        mode,
        scope_,
        state,
        &roots,
        &candidates,
        scanned_dirs,
        errors,
        permission_denied,
        started_at_ms,
    );

    emit(ScanEvent::Finished(summary.clone()));
    ScanReport {
        summary,
        candidates,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_summary(
    scan_id: &str,
    mode: Mode,
    scope_: Scope,
    state: ScanState,
    roots: &[PathBuf],
    candidates: &[StoredCandidate],
    scanned_dirs: u64,
    errors: Vec<ScanError>,
    permission_denied: u64,
    started_at_ms: u64,
) -> ScanSummary {
    use std::collections::BTreeMap;

    let mut cat: BTreeMap<&'static str, (Category, u64, u64)> = BTreeMap::new();
    let mut grp: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut total_bytes = 0u64;

    for c in candidates {
        total_bytes += c.size_bytes;
        let e = cat.entry(c.category.label()).or_insert((c.category, 0, 0));
        e.1 += 1;
        e.2 += c.size_bytes;
        let g = grp.entry(c.group.clone()).or_insert((0, 0));
        g.0 += 1;
        g.1 += c.size_bytes;
    }

    let categories = cat
        .into_values()
        .map(|(category, count, bytes)| CategorySummary {
            category,
            count,
            bytes,
        })
        .collect();
    let groups = grp
        .into_iter()
        .map(|(group, (count, bytes))| GroupSummary {
            display_group: safety::display_path(&group),
            group,
            count,
            bytes,
        })
        .collect();

    ScanSummary {
        scan_id: scan_id.to_string(),
        mode,
        scope: scope_,
        state,
        roots: roots
            .iter()
            .map(|r| r.to_string_lossy().into_owned())
            .collect(),
        total_bytes,
        total_count: candidates.len() as u64,
        scanned_dirs,
        categories,
        groups,
        errors,
        permission_denied_count: permission_denied,
        is_admin: sysinfo::is_admin(),
        started_at_ms,
        finished_at_ms: now_ms(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Hermetic: scan exactly `dir`, recursive rules only, no `~` exact rules.
    #[allow(clippy::type_complexity)]
    fn collect_at(
        dir: &Path,
        mode: Mode,
        cancel: &CancelToken,
    ) -> (Vec<ScanCandidate>, Vec<ScanSummary>, u64) {
        let mut cands = Vec::new();
        let mut summaries = Vec::new();
        let mut progress_events = 0u64;
        scan_with_roots(
            vec![dir.to_path_buf()],
            mode,
            Scope::Projects,
            false,
            cancel,
            |ev| match ev {
                ScanEvent::Candidate(c) => cands.push(c),
                ScanEvent::Finished(s) => summaries.push(s),
                ScanEvent::Progress { .. } => progress_events += 1,
                _ => {}
            },
        );
        (cands, summaries, progress_events)
    }

    #[test]
    fn scans_and_dedupes() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("app/node_modules/pkg")).unwrap();
        fs::write(
            dir.path().join("app/node_modules/pkg/x.js"),
            vec![0u8; 2048],
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("app/src/__pycache__")).unwrap();

        let (cands, summaries, _) = collect_at(dir.path(), Mode::Safe, &CancelToken::new());

        let names: Vec<_> = cands.iter().map(|c| c.rule_label.clone()).collect();
        assert!(names.contains(&"Node modules".to_string()));
        assert!(names.contains(&"Python bytecode cache".to_string()));
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.state, ScanState::Completed);
        assert_eq!(s.total_count, cands.len() as u64);
        assert!(s.total_bytes >= 2048);
        assert_eq!(
            cands
                .iter()
                .filter(|c| c.rule_label == "Node modules")
                .count(),
            1
        );
    }

    #[test]
    fn safe_mode_skips_build_dirs_aggressive_includes_them() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("app/build")).unwrap();
        fs::create_dir_all(dir.path().join("app/dist")).unwrap();
        fs::create_dir_all(dir.path().join("app/node_modules")).unwrap();

        let (safe, _, _) = collect_at(dir.path(), Mode::Safe, &CancelToken::new());
        assert!(!safe.iter().any(|c| c.rule_label == "Build output"));
        assert!(!safe.iter().any(|c| c.rule_label == "Distribution output"));

        let (aggressive, _, _) = collect_at(dir.path(), Mode::Aggressive, &CancelToken::new());
        assert!(aggressive.iter().any(|c| c.rule_label == "Build output"));
        assert!(aggressive
            .iter()
            .any(|c| c.rule_label == "Distribution output"));
    }

    #[test]
    fn progress_events_emitted_during_walk() {
        // Ported from tests/test_main.py::ScanStreamTests::test_progress_events_emitted_during_walk
        let dir = tempdir().unwrap();
        for i in 0..300 {
            fs::create_dir_all(dir.path().join(format!("pkg{i}/src"))).unwrap();
        }
        let mut first_progress: Option<(u64, PathBuf)> = None;
        scan_with_roots(
            vec![dir.path().to_path_buf()],
            Mode::Safe,
            Scope::Projects,
            false,
            &CancelToken::new(),
            |ev| {
                if let ScanEvent::Progress {
                    scanned_dirs,
                    current_dir,
                    ..
                } = ev
                {
                    if first_progress.is_none() {
                        first_progress = Some((scanned_dirs, current_dir));
                    }
                }
            },
        );
        let (dirs, current) = first_progress.expect("expected a progress event");
        assert!(dirs >= 250);
        assert!(current.starts_with(dir.path()));
    }

    #[test]
    fn cancel_before_start_yields_no_candidates() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("app/node_modules")).unwrap();
        let cancel = CancelToken::new();
        cancel.cancel();
        let (cands, summaries, _) = collect_at(dir.path(), Mode::Safe, &cancel);
        assert!(cands.is_empty());
        assert_eq!(summaries[0].state, ScanState::Cancelled);
    }

    #[test]
    fn cancel_midway_stops_early() {
        let dir = tempdir().unwrap();
        for i in 0..1500 {
            fs::create_dir_all(dir.path().join(format!("p{i}/node_modules"))).unwrap();
        }
        let cancel = CancelToken::new();
        let mut count = 0;
        scan_with_roots(
            vec![dir.path().to_path_buf()],
            Mode::Safe,
            Scope::Projects,
            false,
            &cancel,
            |ev| {
                if let ScanEvent::Candidate(_) = ev {
                    count += 1;
                    if count == 5 {
                        cancel.cancel();
                    }
                }
            },
        );
        assert!(
            count < 1500,
            "cancel should have stopped the scan early (got {count})"
        );
    }

    #[test]
    fn symlinked_directory_is_not_followed() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("real/node_modules")).unwrap();
        let linkfarm = dir.path().join("app/vendor");
        fs::create_dir_all(linkfarm.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), &linkfarm).unwrap();

        let (cands, _, _) = collect_at(dir.path(), Mode::Safe, &CancelToken::new());
        assert_eq!(
            cands
                .iter()
                .filter(|c| c.rule_label == "Node modules")
                .count(),
            1
        );
    }
}
