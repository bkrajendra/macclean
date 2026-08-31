//! Scan-session registry and the delete-time validation gate.
//!
//! A deletion is only ever permitted for a candidate that *this* process
//! discovered during a still-valid scan session, and only after re-checking —
//! at delete time — that nothing about the path has changed in a way that
//! invalidates the scan result (design.md §10).

use crate::model::{Category, DeleteStatus, Mode, ScanCandidate, Scope};
use crate::{rules, safety, scope};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Python parity: `SCAN_SESSION_TTL_SECONDS` and `SCAN_SESSION_LIMIT`.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_LIMIT: usize = 24;

/// A candidate as recorded by the scanner, with the extra identity information
/// needed to detect tampering / TOCTOU at delete time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCandidate {
    pub id: String,
    pub path: PathBuf,
    pub real_path: PathBuf,
    pub display_path: String,
    pub group: String,
    pub size_bytes: u64,
    pub item_count: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub category: Category,
    pub label: String,
    pub dev: u64,
    pub ino: u64,
}

impl StoredCandidate {
    pub fn to_wire(&self) -> ScanCandidate {
        ScanCandidate {
            id: self.id.clone(),
            path: self.path.to_string_lossy().into_owned(),
            display_path: self.display_path.clone(),
            group: self.group.clone(),
            size_bytes: self.size_bytes,
            item_count: self.item_count,
            is_dir: self.is_dir,
            is_symlink: self.is_symlink,
            category: self.category,
            rule_label: self.label.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ScanSession {
    pub scan_id: String,
    pub scope: Scope,
    pub mode: Mode,
    pub roots: Vec<PathBuf>,
    pub created_at: Instant,
    pub created_wall_ms: u64,
    pub candidates: HashMap<String, StoredCandidate>,
}

impl ScanSession {
    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

pub struct SessionStore {
    sessions: HashMap<String, ScanSession>,
    ttl: Duration,
    limit: usize,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_LIMIT)
    }
}

impl SessionStore {
    pub fn new(ttl: Duration, limit: usize) -> Self {
        SessionStore {
            sessions: HashMap::new(),
            ttl,
            limit,
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Drop expired sessions, then trim oldest until within `limit`
    /// (`prune_scan_sessions`).
    pub fn prune(&mut self) {
        let ttl = self.ttl;
        self.sessions.retain(|_, s| !s.is_expired(ttl));
        if self.sessions.len() <= self.limit {
            return;
        }
        let mut by_age: Vec<(String, Instant)> = self
            .sessions
            .iter()
            .map(|(k, s)| (k.clone(), s.created_at))
            .collect();
        by_age.sort_by_key(|(_, t)| *t);
        let excess = self.sessions.len() - self.limit;
        for (k, _) in by_age.into_iter().take(excess) {
            self.sessions.remove(&k);
        }
    }

    pub fn insert(
        &mut self,
        scan_id: String,
        scope: Scope,
        mode: Mode,
        roots: Vec<PathBuf>,
        candidates: Vec<StoredCandidate>,
    ) {
        self.prune();
        let map = candidates.into_iter().map(|c| (c.id.clone(), c)).collect();
        let session = ScanSession {
            scan_id: scan_id.clone(),
            scope,
            mode,
            roots,
            created_at: Instant::now(),
            created_wall_ms: now_ms(),
            candidates: map,
        };
        self.sessions.insert(scan_id, session);
        self.prune();
    }

    pub fn get(&self, scan_id: &str) -> Option<&ScanSession> {
        self.sessions
            .get(scan_id)
            .filter(|s| !s.is_expired(self.ttl))
    }

    pub fn remove_candidate(&mut self, scan_id: &str, candidate_id: &str) {
        if let Some(s) = self.sessions.get_mut(scan_id) {
            s.candidates.remove(candidate_id);
        }
    }

    /// The eight delete-time checks (design.md §10). Returns the stored candidate
    /// on success, or the [`DeleteStatus`] describing the first failed check.
    pub fn validate_for_delete(
        &self,
        scan_id: &str,
        candidate_id: &str,
    ) -> Result<StoredCandidate, DeleteStatus> {
        // 1. session exists and is not expired
        let session = self.get(scan_id).ok_or(DeleteStatus::NotInSession)?;

        // 2. candidate was discovered in this session
        let cand = session
            .candidates
            .get(candidate_id)
            .ok_or(DeleteStatus::NotInSession)?
            .clone();

        // 3. path is still inside a root this scan was permitted to walk, or
        //    inside one of the exact-rule cache trees for the scan's scope.
        let real_now = safety::real(&cand.path);
        let contained = session
            .roots
            .iter()
            .any(|r| safety::is_within_real(r, &real_now))
            || is_exact_rule_path(&real_now, session.scope);
        if !contained {
            return Err(DeleteStatus::NotInSession);
        }

        // 4 & 8. path is still not protected
        if safety::is_protected(&cand.path) {
            return Err(DeleteStatus::Protected);
        }

        // 7. the file or directory still exists
        let meta = match std::fs::symlink_metadata(&cand.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DeleteStatus::AlreadyMissing)
            }
            Err(_) => return Err(DeleteStatus::Changed),
        };

        // 5. path is unchanged since the scan (file-type + identity)
        let is_symlink = meta.file_type().is_symlink();
        let is_dir = !is_symlink && meta.is_dir();
        if is_symlink != cand.is_symlink || is_dir != cand.is_dir {
            return Err(DeleteStatus::Changed);
        }
        #[cfg(unix)]
        {
            if (meta.dev(), meta.ino()) != (cand.dev, cand.ino) {
                return Err(DeleteStatus::Changed);
            }
        }

        // 6. the requested operation is "delete" — the only supported op.
        Ok(cand)
    }
}

fn is_exact_rule_path(real: &std::path::Path, scope: Scope) -> bool {
    // Children of the exact-rule trees are legitimate even though they may sit
    // just outside the scope's directory roots (e.g. `~/Library/Caches/*` for
    // the `Home` scope, whose only root is `~`). Being under `~` already covers
    // Home; this covers the `FullMac` system trees.
    for home in scope::homes_for_scope(scope) {
        for rule in rules::HOME_EXACT_RULES {
            if safety::is_within_real(rules::home_rule_base(rule, &home), real) {
                return true;
            }
        }
    }
    if matches!(scope, Scope::FullMac) {
        for rule in rules::SYSTEM_EXACT_RULES {
            if safety::is_within_real(std::path::Path::new(rule.template), real) {
                return true;
            }
        }
    }
    false
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn stored(id: &str, path: PathBuf) -> StoredCandidate {
        let meta = std::fs::symlink_metadata(&path).ok();
        #[cfg(unix)]
        let (dev, ino) = meta.as_ref().map(|m| (m.dev(), m.ino())).unwrap_or((0, 0));
        #[cfg(not(unix))]
        let (dev, ino) = (0u64, 0u64);
        StoredCandidate {
            id: id.to_string(),
            real_path: safety::real(&path),
            display_path: path.to_string_lossy().into_owned(),
            group: "g".into(),
            size_bytes: 10,
            item_count: 1,
            is_dir: meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
            is_symlink: false,
            category: Category::Dependencies,
            label: "x".into(),
            dev,
            ino,
            path,
        }
    }

    #[test]
    fn prune_drops_expired_sessions() {
        let mut store = SessionStore::new(Duration::from_millis(30), 10);
        store.insert("a".into(), Scope::Projects, Mode::Safe, vec![], vec![]);
        assert_eq!(store.len(), 1);
        std::thread::sleep(Duration::from_millis(60));
        store.prune();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn prune_enforces_limit_dropping_oldest() {
        let mut store = SessionStore::new(Duration::from_secs(3600), 2);
        store.insert("a".into(), Scope::Projects, Mode::Safe, vec![], vec![]);
        std::thread::sleep(Duration::from_millis(5));
        store.insert("b".into(), Scope::Projects, Mode::Safe, vec![], vec![]);
        std::thread::sleep(Duration::from_millis(5));
        store.insert("c".into(), Scope::Projects, Mode::Safe, vec![], vec![]);
        assert_eq!(store.len(), 2);
        assert!(store.get("a").is_none());
        assert!(store.get("c").is_some());
    }

    #[test]
    fn unknown_scan_id_rejected() {
        let store = SessionStore::default();
        assert_eq!(
            store.validate_for_delete("nope", "x"),
            Err(DeleteStatus::NotInSession)
        );
    }

    #[test]
    fn candidate_not_in_session_rejected() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("node_modules");
        fs::create_dir(&target).unwrap();
        let mut store = SessionStore::default();
        store.insert(
            "s".into(),
            Scope::Projects,
            Mode::Safe,
            vec![dir.path().to_path_buf()],
            vec![stored("c1", target)],
        );
        assert_eq!(
            store.validate_for_delete("s", "other"),
            Err(DeleteStatus::NotInSession)
        );
        assert!(store.validate_for_delete("s", "c1").is_ok());
    }

    #[test]
    fn missing_path_reported_as_already_missing() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("node_modules");
        fs::create_dir(&target).unwrap();
        let mut store = SessionStore::default();
        store.insert(
            "s".into(),
            Scope::Projects,
            Mode::Safe,
            vec![dir.path().to_path_buf()],
            vec![stored("c1", target.clone())],
        );
        fs::remove_dir_all(&target).unwrap();
        assert_eq!(
            store.validate_for_delete("s", "c1"),
            Err(DeleteStatus::AlreadyMissing)
        );
    }

    #[test]
    fn type_change_since_scan_reported_as_changed() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("node_modules");
        fs::create_dir(&target).unwrap();
        let mut store = SessionStore::default();
        store.insert(
            "s".into(),
            Scope::Projects,
            Mode::Safe,
            vec![dir.path().to_path_buf()],
            vec![stored("c1", target.clone())],
        );
        fs::remove_dir_all(&target).unwrap();
        fs::write(&target, b"now a file").unwrap();
        assert_eq!(
            store.validate_for_delete("s", "c1"),
            Err(DeleteStatus::Changed)
        );
    }
}
