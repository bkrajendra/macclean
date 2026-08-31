//! Defensive deletion with per-item outcomes.
//!
//! `delete_selected` is the only entry point the app uses. It never trusts a
//! path: every candidate id is re-validated through
//! [`crate::session::SessionStore::validate_for_delete`] first, and
//! [`crate::safety::is_protected`] is checked once more immediately before the
//! `remove_*` call.

use crate::model::{DeleteOutcome, DeleteRequest, DeleteResult, DeleteStatus};
use crate::rules::human_size;
use crate::safety;
use crate::session::{SessionStore, StoredCandidate};
use std::io;
use std::path::Path;

/// Measure a path's size the way the scanner does (native recursive sum, errors
/// contribute 0), for accurate "freed" reporting.
fn measure(path: &Path, is_dir: bool) -> u64 {
    if is_dir {
        crate::scanner::dir_size(path)
    } else {
        std::fs::symlink_metadata(path)
            .map(|m| m.len())
            .unwrap_or(0)
    }
}

/// Perform the actual removal for one already-validated candidate.
pub fn delete_candidate(cand: &StoredCandidate) -> DeleteOutcome {
    let path = cand.path.as_path();
    let mut outcome = DeleteOutcome {
        id: cand.id.clone(),
        path: path.to_string_lossy().into_owned(),
        display_path: cand.display_path.clone(),
        status: DeleteStatus::Skipped,
        freed_bytes: 0,
        message: None,
    };

    // Final, immediate protected-path re-check (TOCTOU guard).
    if safety::is_protected(path) {
        outcome.status = DeleteStatus::Protected;
        outcome.message = Some("Path is protected and was not deleted.".into());
        return outcome;
    }

    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            outcome.status = DeleteStatus::AlreadyMissing;
            return outcome;
        }
        Err(e) => {
            outcome.status = map_err(&e);
            outcome.message = Some(e.to_string());
            return outcome;
        }
    };

    let is_symlink = meta.file_type().is_symlink();
    let is_dir = !is_symlink && meta.is_dir();
    let freed = measure(path, is_dir);

    let result = if is_symlink || meta.is_file() {
        // Symlinks: remove the link only, never the target.
        std::fs::remove_file(path)
    } else if is_dir {
        // `remove_dir_all` does not follow symlinks — it unlinks them.
        std::fs::remove_dir_all(path)
    } else {
        // FIFO / socket / device node etc.
        std::fs::remove_file(path)
    };

    match result {
        Ok(()) => {
            outcome.status = DeleteStatus::Deleted;
            outcome.freed_bytes = if freed > 0 { freed } else { cand.size_bytes };
        }
        Err(e) => {
            outcome.status = map_err(&e);
            outcome.message = Some(e.to_string());
            // A directory tree may be partially removed; report what went.
            if outcome.status != DeleteStatus::PermissionDenied {
                outcome.freed_bytes = freed.saturating_sub(measure(path, is_dir));
            }
        }
    }
    outcome
}

fn map_err(e: &io::Error) -> DeleteStatus {
    match e.kind() {
        io::ErrorKind::PermissionDenied => DeleteStatus::PermissionDenied,
        io::ErrorKind::NotFound => DeleteStatus::AlreadyMissing,
        _ => DeleteStatus::Failed,
    }
}

/// Progress update passed to [`delete_selected_with`] after each candidate.
pub struct DeleteProgress<'a> {
    pub done: usize,
    pub total: usize,
    pub freed_bytes: u64,
    pub last: &'a DeleteOutcome,
}

/// Validate and delete every requested candidate. The session is mutated so a
/// successfully-deleted candidate can't be targeted twice.
pub fn delete_selected(store: &mut SessionStore, request: &DeleteRequest) -> DeleteResult {
    delete_selected_with(store, request, |_| {})
}

/// [`delete_selected`] with a per-item progress callback (for a live cleanup UI).
pub fn delete_selected_with<F: FnMut(DeleteProgress)>(
    store: &mut SessionStore,
    request: &DeleteRequest,
    mut on_progress: F,
) -> DeleteResult {
    store.prune();
    if store.get(&request.scan_id).is_none() {
        return DeleteResult::invalid(&request.scan_id, &request.candidate_ids);
    }

    let total = request.candidate_ids.len();
    let mut outcomes = Vec::with_capacity(total);
    let (mut deleted_count, mut deleted_bytes, mut skipped_count, mut failed_count) =
        (0u64, 0u64, 0u64, 0u64);

    for (i, id) in request.candidate_ids.iter().enumerate() {
        match store.validate_for_delete(&request.scan_id, id) {
            Ok(cand) => {
                let outcome = delete_candidate(&cand);
                match outcome.status {
                    DeleteStatus::Deleted => {
                        deleted_count += 1;
                        deleted_bytes += outcome.freed_bytes;
                        store.remove_candidate(&request.scan_id, id);
                    }
                    DeleteStatus::AlreadyMissing => {
                        skipped_count += 1;
                        store.remove_candidate(&request.scan_id, id);
                    }
                    DeleteStatus::PermissionDenied | DeleteStatus::Failed => failed_count += 1,
                    _ => skipped_count += 1,
                }
                outcomes.push(outcome);
            }
            Err(status) => {
                if matches!(
                    status,
                    DeleteStatus::PermissionDenied | DeleteStatus::Failed
                ) {
                    failed_count += 1;
                } else {
                    skipped_count += 1;
                }
                outcomes.push(DeleteOutcome {
                    id: id.clone(),
                    path: String::new(),
                    display_path: String::new(),
                    status,
                    freed_bytes: 0,
                    message: Some(explain(status)),
                });
            }
        }
        on_progress(DeleteProgress {
            done: i + 1,
            total,
            freed_bytes: deleted_bytes,
            last: outcomes.last().unwrap(),
        });
    }

    DeleteResult {
        scan_id: request.scan_id.clone(),
        invalid_scan_id: false,
        outcomes,
        deleted_count,
        deleted_bytes,
        skipped_count,
        failed_count,
    }
}

fn explain(status: DeleteStatus) -> String {
    match status {
        DeleteStatus::NotInSession => "Not part of this scan session.".into(),
        DeleteStatus::Protected => "Path is protected.".into(),
        DeleteStatus::AlreadyMissing => "Already gone.".into(),
        DeleteStatus::Changed => "Changed since the scan; skipped for safety.".into(),
        other => format!("{other:?}"),
    }
}

/// Human summary line, e.g. "Deleted 12 items, reclaimed 2.4 GB".
pub fn summary_line(result: &DeleteResult) -> String {
    let mut s = format!(
        "Deleted {} item{}, reclaimed {}",
        result.deleted_count,
        if result.deleted_count == 1 { "" } else { "s" },
        human_size(result.deleted_bytes),
    );
    if result.skipped_count > 0 {
        s.push_str(&format!(", skipped {}", result.skipped_count));
    }
    if result.failed_count > 0 {
        s.push_str(&format!(", {} failed", result.failed_count));
    }
    s.push('.');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Mode, Scope};
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt};
    use tempfile::tempdir;

    fn stored(id: &str, path: std::path::PathBuf) -> StoredCandidate {
        let m = fs::symlink_metadata(&path).unwrap();
        StoredCandidate {
            id: id.into(),
            real_path: safety::real(&path),
            display_path: path.to_string_lossy().into_owned(),
            group: "g".into(),
            size_bytes: 0,
            item_count: 1,
            is_dir: m.is_dir(),
            is_symlink: m.file_type().is_symlink(),
            category: Category::Dependencies,
            label: "Node modules".into(),
            dev: m.dev(),
            ino: m.ino(),
            path,
        }
    }

    fn session_with(root: &Path, cands: Vec<StoredCandidate>) -> SessionStore {
        let mut store = SessionStore::default();
        store.insert(
            "s".into(),
            Scope::Projects,
            Mode::Safe,
            vec![root.to_path_buf()],
            cands,
        );
        store
    }

    #[test]
    fn deletes_a_directory_tree_and_reports_bytes() {
        let dir = tempdir().unwrap();
        let nm = dir.path().join("proj/node_modules");
        fs::create_dir_all(nm.join("pkg")).unwrap();
        fs::write(nm.join("pkg/a.js"), vec![0u8; 4096]).unwrap();

        let mut store = session_with(dir.path(), vec![stored("c1", nm.clone())]);
        let res = delete_selected(
            &mut store,
            &DeleteRequest {
                scan_id: "s".into(),
                candidate_ids: vec!["c1".into()],
            },
        );
        assert!(!res.invalid_scan_id);
        assert_eq!(res.deleted_count, 1);
        assert!(res.deleted_bytes >= 4096);
        assert!(!nm.exists());
    }

    #[test]
    fn symlink_is_unlinked_not_followed() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_payload");
        fs::create_dir_all(&real_dir).unwrap();
        fs::write(real_dir.join("keep.txt"), b"important").unwrap();
        let link = dir.path().join("proj/node_modules");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&real_dir, &link).unwrap();

        let mut store = session_with(dir.path(), vec![stored("c1", link.clone())]);
        let res = delete_selected(
            &mut store,
            &DeleteRequest {
                scan_id: "s".into(),
                candidate_ids: vec!["c1".into()],
            },
        );
        assert_eq!(res.outcomes[0].status, DeleteStatus::Deleted);
        assert!(!link.exists());
        assert!(
            real_dir.join("keep.txt").exists(),
            "target must be untouched"
        );
    }

    #[test]
    fn invalid_scan_id_deletes_nothing() {
        let dir = tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        let mut store = session_with(dir.path(), vec![stored("c1", nm.clone())]);
        let res = delete_selected(
            &mut store,
            &DeleteRequest {
                scan_id: "wrong".into(),
                candidate_ids: vec!["c1".into()],
            },
        );
        assert!(res.invalid_scan_id);
        assert_eq!(res.deleted_count, 0);
        assert!(nm.exists());
    }

    #[test]
    fn already_deleted_candidate_cannot_be_deleted_again() {
        let dir = tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        let mut store = session_with(dir.path(), vec![stored("c1", nm.clone())]);
        let req = DeleteRequest {
            scan_id: "s".into(),
            candidate_ids: vec!["c1".into()],
        };
        let first = delete_selected(&mut store, &req);
        assert_eq!(first.deleted_count, 1);
        let second = delete_selected(&mut store, &req);
        assert_eq!(second.deleted_count, 0);
        assert_eq!(second.outcomes[0].status, DeleteStatus::NotInSession);
    }
}
