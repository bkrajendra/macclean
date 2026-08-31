//! Tauri IPC commands. The frontend can only ever ask for a scan, cancel one,
//! poll progress, or delete candidate *ids* from a session — never name a path.

use crate::events::*;
use crate::state::{AppState, ScanHandle};
use macclean_core::model::*;
use macclean_core::scanner::{new_scan_id, scan_with_id, CancelToken, ScanEvent};
use macclean_core::{deleter, rules, scope, sysinfo};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};

const CANDIDATE_BATCH: usize = 96;
const FLUSH_EVERY: Duration = Duration::from_millis(120);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDescriptor {
    pub value: String,
    pub label: String,
    pub description: String,
}

#[tauri::command]
pub fn get_system_info(app: AppHandle) -> SystemInfo {
    sysinfo::system_info(&app.package_info().version.to_string())
}

#[tauri::command]
pub fn get_permission_status() -> PermissionStatus {
    sysinfo::permission_status()
}

#[tauri::command]
pub fn get_rules() -> Vec<RuleInfo> {
    rules::rule_catalogue()
}

#[tauri::command]
pub fn list_scopes() -> Vec<ScopeDescriptor> {
    [Scope::Projects, Scope::Home, Scope::FullMac]
        .into_iter()
        .map(|s| {
            let (label, description) = scope::describe(s);
            ScopeDescriptor {
                value: s.as_wire().to_string(),
                label: label.to_string(),
                description: description.to_string(),
            }
        })
        .collect()
}

#[tauri::command]
pub fn get_scan_progress(state: State<'_, AppState>, scan_id: String) -> Option<ScanProgress> {
    let scans = state.scans.lock().ok()?;
    let handle = scans.get(&scan_id)?;
    handle.progress.lock().ok().map(|p| p.clone())
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>, scan_id: String) -> bool {
    let Ok(scans) = state.scans.lock() else {
        return false;
    };
    match scans.get(&scan_id) {
        Some(handle) => {
            handle.cancel.cancel();
            true
        }
        None => false,
    }
}

/// Start a scan on a background thread. Returns the scan id immediately; results
/// stream over the `scan://*` events and the session is registered on
/// completion.
#[tauri::command]
pub fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    options: ScanOptions,
) -> Result<String, String> {
    state.reap_finished();

    let scan_id = new_scan_id();
    let cancel = CancelToken::new();
    let progress = Arc::new(Mutex::new(ScanProgress {
        scan_id: scan_id.clone(),
        state: ScanState::Scanning,
        scanned_dirs: 0,
        current_dir: String::new(),
        items_found: 0,
        bytes_found: 0,
        errors: 0,
    }));
    let finished = Arc::new(AtomicBool::new(false));

    state
        .scans
        .lock()
        .map_err(|_| "scan registry poisoned".to_string())?
        .insert(
            scan_id.clone(),
            ScanHandle {
                cancel: cancel.clone(),
                progress: progress.clone(),
                finished: finished.clone(),
            },
        );

    let sid = scan_id.clone();
    std::thread::Builder::new()
        .name("macclean-scan".into())
        .spawn(move || {
            run_scan_thread(app, sid, options, cancel, progress, finished);
        })
        .map_err(|e| e.to_string())?;

    Ok(scan_id)
}

fn run_scan_thread(
    app: AppHandle,
    scan_id: String,
    options: ScanOptions,
    cancel: CancelToken,
    progress: Arc<Mutex<ScanProgress>>,
    finished: Arc<AtomicBool>,
) {
    let mut batch: Vec<ScanCandidate> = Vec::with_capacity(CANDIDATE_BATCH);
    let mut last_flush = Instant::now();

    let flush = |app: &AppHandle, batch: &mut Vec<ScanCandidate>| {
        if !batch.is_empty() {
            let _ = app.emit(SCAN_CANDIDATES, std::mem::take(batch));
        }
    };

    let report = scan_with_id(&scan_id, &options, &cancel, |ev| match ev {
        ScanEvent::Started { scan_id, roots } => {
            let _ = app.emit(
                SCAN_STARTED,
                ScanStartedPayload {
                    scan_id,
                    roots: roots
                        .iter()
                        .map(|r| r.to_string_lossy().into_owned())
                        .collect(),
                },
            );
        }
        ScanEvent::Candidate(c) => {
            batch.push(c);
            if batch.len() >= CANDIDATE_BATCH || last_flush.elapsed() >= FLUSH_EVERY {
                flush(&app, &mut batch);
                last_flush = Instant::now();
            }
        }
        ScanEvent::Progress {
            scanned_dirs,
            current_dir,
            items_found,
            bytes_found,
            errors,
        } => {
            flush(&app, &mut batch);
            last_flush = Instant::now();
            let p = ScanProgress {
                scan_id: scan_id.clone(),
                state: ScanState::Scanning,
                scanned_dirs,
                current_dir: current_dir.to_string_lossy().into_owned(),
                items_found,
                bytes_found,
                errors,
            };
            if let Ok(mut slot) = progress.lock() {
                *slot = p.clone();
            }
            let _ = app.emit(SCAN_PROGRESS, p);
        }
        ScanEvent::Error(e) => {
            let _ = app.emit(SCAN_ERROR, e);
        }
        ScanEvent::Finished(_) => {
            flush(&app, &mut batch);
        }
    });

    flush(&app, &mut batch);

    let state = app.state::<AppState>();
    if let Ok(mut sessions) = state.sessions.lock() {
        let roots: Vec<PathBuf> = report.summary.roots.iter().map(PathBuf::from).collect();
        sessions.insert(
            report.summary.scan_id.clone(),
            options.scope,
            options.mode,
            roots,
            report.candidates,
        );
    }
    if let Ok(mut slot) = progress.lock() {
        slot.state = report.summary.state;
        slot.items_found = report.summary.total_count;
        slot.bytes_found = report.summary.total_bytes;
        slot.scanned_dirs = report.summary.scanned_dirs;
    }
    finished.store(true, Ordering::SeqCst);
    let _ = app.emit(SCAN_COMPLETED, report.summary);
}

/// Validate and delete the selected candidate ids. Runs on a blocking task so a
/// large tree removal never stalls the UI; progress streams over
/// `cleanup://progress`.
#[tauri::command]
pub async fn delete_selected(
    app: AppHandle,
    request: DeleteRequest,
) -> Result<DeleteResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "session store poisoned".to_string())?;

        let scan_id = request.scan_id.clone();
        let result = deleter::delete_selected_with(&mut sessions, &request, |p| {
            let _ = app.emit(
                CLEANUP_PROGRESS,
                CleanupProgressPayload {
                    scan_id: scan_id.clone(),
                    done: p.done as u64,
                    total: p.total as u64,
                    freed_bytes: p.freed_bytes,
                    last_path: p.last.display_path.clone(),
                    last_status: p.last.status,
                },
            );
        });
        let _ = app.emit(CLEANUP_COMPLETED, result.clone());
        Ok(result)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn reveal_in_finder(app: AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|e| e.to_string())
}

/// Open System Settings ▸ Privacy & Security ▸ Full Disk Access.
#[tauri::command]
pub fn open_privacy_settings(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(
            "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
            None::<&str>,
        )
        .map_err(|e| e.to_string())
}
