//! Application state managed by Tauri: the scan-session registry and the set of
//! currently-running scans (so they can be cancelled and polled).

use macclean_core::model::ScanProgress;
use macclean_core::scanner::CancelToken;
use macclean_core::session::SessionStore;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// A live scan's control surface.
pub struct ScanHandle {
    pub cancel: CancelToken,
    pub progress: Arc<Mutex<ScanProgress>>,
    pub finished: Arc<AtomicBool>,
}

#[derive(Default)]
pub struct AppState {
    /// Completed scans available for deletion (Rust-owned; TTL + cap enforced).
    pub sessions: Mutex<SessionStore>,
    /// Scans currently in progress, keyed by scan id.
    pub scans: Mutex<HashMap<String, ScanHandle>>,
}

impl AppState {
    /// Drop handles for scans that have finished (keeps the map small).
    pub fn reap_finished(&self) {
        if let Ok(mut scans) = self.scans.lock() {
            scans.retain(|_, h| !h.finished.load(std::sync::atomic::Ordering::SeqCst));
        }
    }
}
