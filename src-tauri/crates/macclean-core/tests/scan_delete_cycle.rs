//! End-to-end integration tests for the core engine: build a realistic temp
//! directory tree, scan it, select results, delete them, verify the outcome.
//!
//! Every scan here uses `scan_with_roots(.., include_exact_rules = false)` so it
//! touches only the temp tree — never the real `~/Library`, `~/projects`, or any
//! system directory.

use macclean_core::deleter::delete_selected;
use macclean_core::model::{
    DeleteRequest, DeleteStatus, Mode, ScanCandidate, ScanState, ScanSummary, Scope,
};
use macclean_core::safety;
use macclean_core::scanner::{scan_with_roots, CancelToken, ScanEvent};
use macclean_core::session::{SessionStore, StoredCandidate};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn write(path: &Path, bytes: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![7u8; bytes]).unwrap();
}

/// A moderately realistic `~/projects`-style tree.
fn build_tree(root: &Path) {
    // project A: node_modules + a build dir + a real source file + .DS_Store
    write(&root.join("alpha/src/index.ts"), 400);
    write(&root.join("alpha/node_modules/left-pad/index.js"), 8_000);
    write(&root.join("alpha/node_modules/.bin/tsc"), 1_200);
    write(&root.join("alpha/build/bundle.js"), 20_000);
    write(&root.join("alpha/.DS_Store"), 6_148);

    // project B: python caches + a nested node_modules that must NOT be descended
    write(
        &root.join("beta/app/__pycache__/mod.cpython-312.pyc"),
        3_000,
    );
    write(&root.join("beta/.pytest_cache/v/cache/lastfailed"), 900);
    write(
        &root.join("beta/service/node_modules/dep/node_modules/inner/x.js"),
        5_000,
    );

    // a .git dir that must be skipped entirely
    write(&root.join("beta/.git/objects/ab/cdef"), 10_000);
}

fn run_scan(root: &Path, mode: Mode) -> (Vec<ScanCandidate>, ScanSummary, Vec<StoredCandidate>) {
    let mut cands = Vec::new();
    let mut summary = None;
    let report = scan_with_roots(
        vec![root.to_path_buf()],
        mode,
        Scope::Projects,
        false,
        &CancelToken::new(),
        |ev| match ev {
            ScanEvent::Candidate(c) => cands.push(c),
            ScanEvent::Finished(s) => summary = Some(s),
            _ => {}
        },
    );
    assert_eq!(report.candidates.len(), cands.len());
    (cands, summary.unwrap(), report.candidates)
}

#[test]
fn safe_scan_then_full_delete_cycle() {
    let dir = tempdir().unwrap();
    build_tree(dir.path());

    let (cands, summary, stored) = run_scan(dir.path(), Mode::Safe);

    assert_eq!(summary.state, ScanState::Completed);
    assert_eq!(summary.scope, Scope::Projects);

    let labels: Vec<&str> = cands.iter().map(|c| c.rule_label.as_str()).collect();
    assert!(labels.contains(&"Node modules"));
    assert!(labels.contains(&"Python bytecode cache"));
    assert!(labels.contains(&"Pytest cache"));
    assert!(labels.contains(&"macOS Finder metadata"));
    assert!(!labels.contains(&"Build output")); // safe mode
    assert!(!cands.iter().any(|c| c.path.contains("/.git/"))); // .git excluded
                                                               // nested node_modules is not descended into: exactly two candidates.
    assert_eq!(labels.iter().filter(|l| **l == "Node modules").count(), 2);
    assert!(!cands.iter().any(|c| c.path.ends_with("dep/node_modules")));
    // nothing protected ever leaks into results.
    assert!(!cands
        .iter()
        .any(|c| safety::is_protected(PathBuf::from(&c.path))));
    // real source untouched by the scan
    assert!(dir.path().join("alpha/src/index.ts").exists());

    // ---- session + delete everything found ----
    let mut store = SessionStore::default();
    store.insert(
        summary.scan_id.clone(),
        Scope::Projects,
        Mode::Safe,
        vec![dir.path().to_path_buf()],
        stored,
    );

    let ids: Vec<String> = store
        .get(&summary.scan_id)
        .unwrap()
        .candidates
        .keys()
        .cloned()
        .collect();
    let total = ids.len();

    let result = delete_selected(
        &mut store,
        &DeleteRequest {
            scan_id: summary.scan_id.clone(),
            candidate_ids: ids,
        },
    );

    assert!(!result.invalid_scan_id);
    assert_eq!(result.deleted_count as usize, total);
    assert_eq!(result.failed_count, 0);
    assert!(result.deleted_bytes >= 8_000 + 3_000 + 900 + 6_148);

    assert!(!dir.path().join("alpha/node_modules").exists());
    assert!(!dir.path().join("beta/app/__pycache__").exists());
    assert!(!dir.path().join("alpha/.DS_Store").exists());
    assert!(dir.path().join("alpha/src/index.ts").exists());
    assert!(dir.path().join("beta/.git/objects/ab/cdef").exists());
}

#[test]
fn aggressive_scan_adds_build_output() {
    let dir = tempdir().unwrap();
    build_tree(dir.path());
    let (cands, ..) = run_scan(dir.path(), Mode::Aggressive);
    assert!(cands.iter().any(|c| c.rule_label == "Build output"));
}

#[test]
fn deleting_a_stale_id_after_a_new_scan_is_rejected() {
    let dir = tempdir().unwrap();
    build_tree(dir.path());

    let (_, _, stored_old) = run_scan(dir.path(), Mode::Safe);
    let (_, _, stored_new) = run_scan(dir.path(), Mode::Safe);

    let mut store = SessionStore::default();
    store.insert(
        "old".into(),
        Scope::Projects,
        Mode::Safe,
        vec![dir.path().into()],
        stored_old,
    );
    let stale_ids: Vec<String> = store
        .get("old")
        .unwrap()
        .candidates
        .keys()
        .cloned()
        .collect();
    store.insert(
        "new".into(),
        Scope::Projects,
        Mode::Safe,
        vec![dir.path().into()],
        stored_new,
    );

    let result = delete_selected(
        &mut store,
        &DeleteRequest {
            scan_id: "new".into(),
            candidate_ids: stale_ids,
        },
    );
    assert_eq!(result.deleted_count, 0);
    assert!(result
        .outcomes
        .iter()
        .all(|o| o.status == DeleteStatus::NotInSession));
    assert!(dir.path().join("alpha/node_modules").exists());
}

#[test]
fn partial_selection_only_deletes_selected() {
    let dir = tempdir().unwrap();
    build_tree(dir.path());
    let (_, summary, stored) = run_scan(dir.path(), Mode::Safe);

    let mut store = SessionStore::default();
    store.insert(
        summary.scan_id.clone(),
        Scope::Projects,
        Mode::Safe,
        vec![dir.path().to_path_buf()],
        stored,
    );

    // select only the .DS_Store candidate
    let ds_id = store
        .get(&summary.scan_id)
        .unwrap()
        .candidates
        .values()
        .find(|c| c.label == "macOS Finder metadata")
        .map(|c| c.id.clone())
        .unwrap();

    let result = delete_selected(
        &mut store,
        &DeleteRequest {
            scan_id: summary.scan_id,
            candidate_ids: vec![ds_id],
        },
    );
    assert_eq!(result.deleted_count, 1);
    assert!(!dir.path().join("alpha/.DS_Store").exists());
    assert!(dir.path().join("alpha/node_modules").exists()); // not selected
}
