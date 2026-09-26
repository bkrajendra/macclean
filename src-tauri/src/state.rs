//! Application state managed by Tauri: the scan-session registry and the set of
//! currently-running scans (so they can be cancelled and polled).

use macclean_core::model::ScanProgress;
use macclean_core::scanner::CancelToken;
use macclean_core::session::SessionStore;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// Clean Mode's OS-level keyboard lock. `flag` is checked on every intercepted
/// key event by the event tap (see `keyboard_lock.rs`); `thread_started`
/// tracks whether that tap's thread has been spawned yet — it is spawned once,
/// lazily, and then lives for the app's lifetime. Locking and unlocking only
/// ever flip `flag`, never the thread.
#[derive(Default)]
pub struct KeyboardLock {
    pub flag: Arc<AtomicBool>,
    pub thread_started: Mutex<bool>,
}

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
    /// Clean Mode's system-wide keyboard lock.
    pub keyboard_lock: KeyboardLock,
}

impl AppState {
    /// Drop handles for scans that have finished (keeps the map small).
    pub fn reap_finished(&self) {
        if let Ok(mut scans) = self.scans.lock() {
            scans.retain(|_, h| !h.finished.load(std::sync::atomic::Ordering::SeqCst));
        }
    }
}
