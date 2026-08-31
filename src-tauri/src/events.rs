//! Event names and payloads emitted to the webview during scans and cleanups.
//! Mirrored in `src/lib/api/events.ts`.

use macclean_core::model::DeleteStatus;
use serde::Serialize;

pub const SCAN_STARTED: &str = "scan://started";
pub const SCAN_CANDIDATES: &str = "scan://candidates";
pub const SCAN_PROGRESS: &str = "scan://progress";
pub const SCAN_ERROR: &str = "scan://error";
pub const SCAN_COMPLETED: &str = "scan://completed";

pub const CLEANUP_PROGRESS: &str = "cleanup://progress";
pub const CLEANUP_COMPLETED: &str = "cleanup://completed";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStartedPayload {
    pub scan_id: String,
    pub roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupProgressPayload {
    pub scan_id: String,
    pub done: u64,
    pub total: u64,
    pub freed_bytes: u64,
    pub last_path: String,
    pub last_status: DeleteStatus,
}
