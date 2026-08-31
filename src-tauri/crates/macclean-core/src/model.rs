//! The strongly-typed IPC contract shared between the Rust backend and the
//! Svelte frontend. Every type is `serde`-serialisable; the frontend mirrors
//! these in `src/lib/types/ipc.ts`.
//!
//! Enums serialise in `camelCase` (`"safe"`, `"fullMac"`, `"permissionDenied"`);
//! structs serialise with `camelCase` fields.

use serde::{Deserialize, Serialize};

/// Conservative vs. aggressive cleanup. Unknown input normalises to [`Mode::Safe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    #[default]
    Safe,
    Aggressive,
}

impl Mode {
    pub fn normalize(raw: &str) -> Self {
        if raw.eq_ignore_ascii_case("aggressive") {
            Mode::Aggressive
        } else {
            Mode::Safe
        }
    }
}

/// Where the scan looks. Unknown input normalises to [`Scope::Projects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    /// `~/projects` only.
    #[default]
    Projects,
    /// The user's home directory and user-level caches.
    Home,
    /// All discovered user homes plus known system cache locations.
    FullMac,
}

impl Scope {
    pub fn normalize(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "home" => Scope::Home,
            "full_mac" | "fullmac" => Scope::FullMac,
            _ => Scope::Projects,
        }
    }

    pub fn as_wire(&self) -> &'static str {
        match self {
            Scope::Projects => "projects",
            Scope::Home => "home",
            Scope::FullMac => "fullMac",
        }
    }
}

/// Category assigned to every candidate. Values match the legacy Python strings
/// so existing muscle memory and docs keep working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    #[serde(rename = "Dependencies")]
    Dependencies,
    #[serde(rename = "Python")]
    Python,
    #[serde(rename = "Frontend")]
    Frontend,
    #[serde(rename = "Caches")]
    Caches,
    #[serde(rename = "Build")]
    Build,
    #[serde(rename = "Testing")]
    Testing,
    #[serde(rename = "Infrastructure")]
    Infrastructure,
    #[serde(rename = "macOS")]
    MacOs,
    #[serde(rename = "System cache")]
    SystemCache,
    #[serde(rename = "Browser cache")]
    BrowserCache,
    #[serde(rename = "Logs")]
    Logs,
    #[serde(rename = "Developer tools")]
    DeveloperTools,
    #[serde(rename = "Package manager cache")]
    PackageManagerCache,
    #[serde(rename = "Other")]
    Other,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::Dependencies => "Dependencies",
            Category::Python => "Python",
            Category::Frontend => "Frontend",
            Category::Caches => "Caches",
            Category::Build => "Build",
            Category::Testing => "Testing",
            Category::Infrastructure => "Infrastructure",
            Category::MacOs => "macOS",
            Category::SystemCache => "System cache",
            Category::BrowserCache => "Browser cache",
            Category::Logs => "Logs",
            Category::DeveloperTools => "Developer tools",
            Category::PackageManagerCache => "Package manager cache",
            Category::Other => "Other",
        }
    }
}

/// Options for [`crate::scanner::scan`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub mode: Mode,
    pub scope: Scope,
    /// Extra roots to include on top of the scope's roots (also merged with the
    /// `MACCLEAN_EXTRA_SCAN_ROOTS` environment variable).
    #[serde(default)]
    pub extra_roots: Vec<String>,
}

/// One thing that can be cleaned up.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCandidate {
    /// Opaque id, unique within its scan session. The frontend refers to
    /// candidates only by this id — never by path.
    pub id: String,
    /// The path as discovered (may contain symlinked components).
    pub path: String,
    /// A `~`-shortened, display-friendly form of `path`.
    pub display_path: String,
    /// The grouping key (see `rules::path_group`): `/Users/<name>/<child>` or
    /// `/<top-level>`.
    pub group: String,
    pub size_bytes: u64,
    /// Number of files inside (1 for a file candidate).
    pub item_count: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub category: Category,
    /// Human label for the matched rule, e.g. "Node modules".
    pub rule_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanState {
    Idle,
    Scanning,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanErrorKind {
    PermissionDenied,
    NotFound,
    Io,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanError {
    pub path: String,
    pub kind: ScanErrorKind,
    pub message: String,
}

/// Streamed to the frontend during a scan (throttled).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub scan_id: String,
    pub state: ScanState,
    pub scanned_dirs: u64,
    pub current_dir: String,
    pub items_found: u64,
    pub bytes_found: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategorySummary {
    pub category: Category,
    pub count: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub group: String,
    pub display_group: String,
    pub count: u64,
    pub bytes: u64,
}

/// Emitted once when a scan finishes (or is cancelled / fails).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub scan_id: String,
    pub mode: Mode,
    pub scope: Scope,
    pub state: ScanState,
    pub roots: Vec<String>,
    pub total_bytes: u64,
    pub total_count: u64,
    pub scanned_dirs: u64,
    pub categories: Vec<CategorySummary>,
    pub groups: Vec<GroupSummary>,
    pub errors: Vec<ScanError>,
    pub permission_denied_count: u64,
    pub is_admin: bool,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRequest {
    pub scan_id: String,
    pub candidate_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeleteStatus {
    Deleted,
    Skipped,
    Failed,
    PermissionDenied,
    AlreadyMissing,
    Protected,
    NotInSession,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOutcome {
    pub id: String,
    pub path: String,
    pub display_path: String,
    pub status: DeleteStatus,
    pub freed_bytes: u64,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    pub scan_id: String,
    pub invalid_scan_id: bool,
    pub outcomes: Vec<DeleteOutcome>,
    pub deleted_count: u64,
    pub deleted_bytes: u64,
    pub skipped_count: u64,
    pub failed_count: u64,
}

impl DeleteResult {
    pub fn invalid(scan_id: &str, ids: &[String]) -> Self {
        let outcomes = ids
            .iter()
            .map(|id| DeleteOutcome {
                id: id.clone(),
                path: String::new(),
                display_path: String::new(),
                status: DeleteStatus::NotInSession,
                freed_bytes: 0,
                message: Some("Scan session expired or unknown. Run a new scan.".into()),
            })
            .collect();
        DeleteResult {
            scan_id: scan_id.to_string(),
            invalid_scan_id: true,
            outcomes,
            deleted_count: 0,
            deleted_bytes: 0,
            skipped_count: ids.len() as u64,
            failed_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionProbe {
    pub label: String,
    pub path: String,
    pub readable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionStatus {
    /// Best-effort guess at whether the app has Full Disk Access.
    pub full_disk_access: bool,
    pub home_readable: bool,
    /// The `.app` bundle (or executable) this process is running from — so the
    /// user can check they granted access to the right copy.
    pub app_path: String,
    /// True when the running binary is not Developer-ID signed / notarised, so a
    /// Full Disk Access grant may not survive replacing the app bundle.
    pub ad_hoc_signed: bool,
    pub probes: Vec<PermissionProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub platform: String,
    pub arch: String,
    pub current_user: String,
    pub is_admin: bool,
    pub home_dir: String,
    pub projects_dir: String,
    pub total_disk_bytes: u64,
    pub available_disk_bytes: u64,
    pub app_version: String,
}

/// A rule catalogue entry, for the "what does this clean" screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub key: String,
    pub kind: String,
    pub label: String,
    pub category: Category,
    pub safe: bool,
    pub aggressive: bool,
    pub scope: String,
}
