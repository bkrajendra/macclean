//! MacClean core engine.
//!
//! Pure Rust. No Tauri, no UI, no global state. Everything the app is allowed to
//! do to the filesystem lives here and is unit-tested in isolation:
//!
//! - [`safety`] — path normalisation and the centralised protected-path policy
//! - [`rules`]  — the cleanup rule catalogue (ported 1:1 from the Python app)
//! - [`scope`]  — scan-scope → filesystem-root resolution and home discovery
//! - [`scanner`] — the cancellable, incremental, error-tolerant filesystem scan
//! - [`session`] — scan-session registry and the delete-time validation gate
//! - [`deleter`] — defensive deletion with per-item outcomes
//! - [`sysinfo`] — disk usage, current user, admin check, permission probes
//!
//! The IPC data contract shared with the frontend is in [`model`].

pub mod deleter;
pub mod model;
pub mod rules;
pub mod safety;
pub mod scanner;
pub mod scope;
pub mod session;
pub mod sysinfo;

pub use model::*;
