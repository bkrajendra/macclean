//! The cleanup-rule catalogue, ported verbatim from the legacy Python
//! `main.py` (`TARGET_RULES`, `HOME_EXACT_RULES`, `SYSTEM_EXACT_RULES`,
//! `EXCLUDED_DIR_NAMES`, `path_group`, `human_size`, `rules_for_mode`,
//! `classify_exact_rule`).
//!
//! Only the *live* Python `TARGET_RULES` set is ported (the source contains an
//! earlier, shadowed copy where `target` is safe+aggressive; here — as in the
//! running Python app — `target` is aggressive-only).

use crate::model::{Category, Mode, RuleInfo};
use crate::safety;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Match a directory by exact name; emit it and do not descend.
    DirName,
    /// Match a file by exact name.
    FileExact,
    /// Match a file whose name ends with this suffix.
    FileSuffix,
}

impl RuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleKind::DirName => "dir",
            RuleKind::FileExact => "file_exact",
            RuleKind::FileSuffix => "file_suffix",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecursiveRule {
    pub key: &'static str,
    pub kind: RuleKind,
    pub safe: bool,
    pub aggressive: bool,
    pub label: &'static str,
    pub category: Category,
}

impl RecursiveRule {
    pub fn active_in(&self, mode: Mode) -> bool {
        match mode {
            Mode::Safe => self.safe,
            Mode::Aggressive => self.aggressive,
        }
    }
}

/// The 21 recursive rules (`TARGET_RULES`).
pub const RECURSIVE_RULES: &[RecursiveRule] = &[
    RecursiveRule {
        key: "node_modules",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Node modules",
        category: Category::Dependencies,
    },
    RecursiveRule {
        key: "__pycache__",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Python bytecode cache",
        category: Category::Python,
    },
    RecursiveRule {
        key: ".pytest_cache",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Pytest cache",
        category: Category::Python,
    },
    RecursiveRule {
        key: ".mypy_cache",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Mypy cache",
        category: Category::Python,
    },
    RecursiveRule {
        key: ".ruff_cache",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Ruff cache",
        category: Category::Python,
    },
    RecursiveRule {
        key: ".next",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Next.js build cache",
        category: Category::Frontend,
    },
    RecursiveRule {
        key: ".nuxt",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Nuxt build cache",
        category: Category::Frontend,
    },
    RecursiveRule {
        key: ".svelte-kit",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "SvelteKit cache",
        category: Category::Frontend,
    },
    RecursiveRule {
        key: ".parcel-cache",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Parcel cache",
        category: Category::Frontend,
    },
    RecursiveRule {
        key: ".angular",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Angular cache",
        category: Category::Frontend,
    },
    RecursiveRule {
        key: ".cache",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Generic cache folder",
        category: Category::Caches,
    },
    RecursiveRule {
        key: ".gradle",
        kind: RuleKind::DirName,
        safe: true,
        aggressive: true,
        label: "Gradle cache",
        category: Category::Build,
    },
    RecursiveRule {
        key: "build",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Build output",
        category: Category::Build,
    },
    RecursiveRule {
        key: "dist",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Distribution output",
        category: Category::Build,
    },
    RecursiveRule {
        key: "out",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Compiled output",
        category: Category::Build,
    },
    RecursiveRule {
        key: "target",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Rust/Java target output",
        category: Category::Build,
    },
    RecursiveRule {
        key: "coverage",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Coverage report output",
        category: Category::Testing,
    },
    RecursiveRule {
        key: ".tox",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Tox virtualenv cache",
        category: Category::Testing,
    },
    RecursiveRule {
        key: ".terraform",
        kind: RuleKind::DirName,
        safe: false,
        aggressive: true,
        label: "Terraform module cache",
        category: Category::Infrastructure,
    },
    RecursiveRule {
        key: ".DS_Store",
        kind: RuleKind::FileExact,
        safe: true,
        aggressive: true,
        label: "macOS Finder metadata",
        category: Category::MacOs,
    },
    RecursiveRule {
        key: ".pyc",
        kind: RuleKind::FileSuffix,
        safe: false,
        aggressive: true,
        label: "Python compiled file",
        category: Category::Python,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// The base path itself is the candidate.
    Path,
    /// Every direct child of the base path is a candidate.
    Children,
}

#[derive(Debug, Clone, Copy)]
pub struct ExactRule {
    /// For home rules: a path relative to `$HOME`. For system rules: absolute.
    pub template: &'static str,
    pub strategy: Strategy,
    pub label: &'static str,
    pub category: Category,
}

/// The 14 user-level exact rules (`HOME_EXACT_RULES`). All are safe + aggressive.
pub const HOME_EXACT_RULES: &[ExactRule] = &[
    ExactRule {
        template: "Library/Caches",
        strategy: Strategy::Children,
        label: "User app cache",
        category: Category::SystemCache,
    },
    ExactRule {
        template: "Library/Caches/Google/Chrome",
        strategy: Strategy::Children,
        label: "Chrome browser cache",
        category: Category::BrowserCache,
    },
    ExactRule {
        template: "Library/Caches/com.microsoft.edgemac",
        strategy: Strategy::Children,
        label: "Edge browser cache",
        category: Category::BrowserCache,
    },
    ExactRule {
        template: "Library/Caches/BraveSoftware/Brave-Browser",
        strategy: Strategy::Children,
        label: "Brave browser cache",
        category: Category::BrowserCache,
    },
    ExactRule {
        template: "Library/Caches/Mozilla/Firefox",
        strategy: Strategy::Children,
        label: "Firefox browser cache",
        category: Category::BrowserCache,
    },
    ExactRule {
        template: "Library/Caches/com.apple.Safari",
        strategy: Strategy::Children,
        label: "Safari browser cache",
        category: Category::BrowserCache,
    },
    ExactRule {
        template: "Library/Logs",
        strategy: Strategy::Children,
        label: "User logs",
        category: Category::Logs,
    },
    ExactRule {
        template: "Library/Developer/Xcode/DerivedData",
        strategy: Strategy::Path,
        label: "Xcode derived data",
        category: Category::DeveloperTools,
    },
    ExactRule {
        template: ".Trash",
        strategy: Strategy::Children,
        label: "Trash items",
        category: Category::MacOs,
    },
    ExactRule {
        template: ".npm/_cacache",
        strategy: Strategy::Path,
        label: "npm cache",
        category: Category::PackageManagerCache,
    },
    ExactRule {
        template: ".pnpm-store",
        strategy: Strategy::Path,
        label: "pnpm store cache",
        category: Category::PackageManagerCache,
    },
    ExactRule {
        template: ".yarn/cache",
        strategy: Strategy::Path,
        label: "Yarn cache",
        category: Category::PackageManagerCache,
    },
    ExactRule {
        template: ".cache/pip",
        strategy: Strategy::Path,
        label: "pip cache",
        category: Category::PackageManagerCache,
    },
    ExactRule {
        template: ".m2/repository",
        strategy: Strategy::Path,
        label: "Maven local repository cache",
        category: Category::PackageManagerCache,
    },
];

/// The 6 system-level exact rules (`SYSTEM_EXACT_RULES`), used only for the
/// `FullMac` scope. All are safe + aggressive.
pub const SYSTEM_EXACT_RULES: &[ExactRule] = &[
    ExactRule {
        template: "/Library/Caches",
        strategy: Strategy::Children,
        label: "System cache",
        category: Category::SystemCache,
    },
    ExactRule {
        template: "/private/var/folders",
        strategy: Strategy::Children,
        label: "macOS temp cache",
        category: Category::SystemCache,
    },
    ExactRule {
        template: "/Library/Logs",
        strategy: Strategy::Children,
        label: "System logs",
        category: Category::Logs,
    },
    ExactRule {
        template: "/private/var/log",
        strategy: Strategy::Children,
        label: "System temp logs",
        category: Category::Logs,
    },
    ExactRule {
        template: "/opt/homebrew/var/cache",
        strategy: Strategy::Children,
        label: "Homebrew cache",
        category: Category::PackageManagerCache,
    },
    ExactRule {
        template: "/usr/local/var/cache",
        strategy: Strategy::Children,
        label: "Local cache",
        category: Category::PackageManagerCache,
    },
];

/// Directory names never descended into and never emitted (`EXCLUDED_DIR_NAMES`).
pub const EXCLUDED_DIR_NAMES: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    ".Trash",
    "Applications",
    "System",
    "Volumes",
    "dev",
    "proc",
    "sys",
];

pub fn is_excluded_dir(name: &str) -> bool {
    EXCLUDED_DIR_NAMES.contains(&name)
}

/// Split the active recursive rules for `mode` into lookup structures.
pub struct RuleIndex {
    pub dirs: HashMap<&'static str, RecursiveRule>,
    pub file_exact: HashMap<&'static str, RecursiveRule>,
    pub file_suffix: Vec<RecursiveRule>,
}

pub fn rules_for_mode(mode: Mode) -> RuleIndex {
    let mut dirs = HashMap::new();
    let mut file_exact = HashMap::new();
    let mut file_suffix = Vec::new();
    for rule in RECURSIVE_RULES.iter().copied() {
        if !rule.active_in(mode) {
            continue;
        }
        match rule.kind {
            RuleKind::DirName => {
                dirs.insert(rule.key, rule);
            }
            RuleKind::FileExact => {
                file_exact.insert(rule.key, rule);
            }
            RuleKind::FileSuffix => file_suffix.push(rule),
        }
    }
    RuleIndex {
        dirs,
        file_exact,
        file_suffix,
    }
}

/// Expand a home exact rule against a specific home directory.
pub fn home_rule_base(rule: &ExactRule, home: &Path) -> PathBuf {
    home.join(rule.template)
}

/// `classify_exact_rule` — for `home` / `full_mac` scopes, relabel a recursive
/// match by the exact-rule tree it sits inside. Fallback: `("Known cache path",
/// Caches)`.
pub fn classify_exact_rule(path: &Path, home_roots: &[PathBuf]) -> (String, Category) {
    for home in home_roots {
        for rule in HOME_EXACT_RULES {
            let base = home_rule_base(rule, home);
            if safety::is_within_real(&base, path) {
                return (rule.label.to_string(), rule.category);
            }
        }
    }
    for rule in SYSTEM_EXACT_RULES {
        if safety::is_within_real(Path::new(rule.template), path) {
            return (rule.label.to_string(), rule.category);
        }
    }
    ("Known cache path".to_string(), Category::Caches)
}

/// `path_group` — the grouping key for the results UI. Ported 1:1, operating on
/// the lexically-normalised path (matching the Python test vectors).
pub fn path_group(path: &Path) -> String {
    let normalized = safety::normalize(path);
    let comps: Vec<&OsStr> = normalized
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();

    if comps.len() >= 2 && (comps[0] == "Users" || comps[0] == "home") {
        let mut g = PathBuf::from("/");
        g.push(comps[0]);
        g.push(comps[1]);
        if comps.len() >= 3 {
            g.push(comps[2]);
        }
        return g.to_string_lossy().into_owned();
    }
    if let Some(first) = comps.first() {
        return format!("/{}", first.to_string_lossy());
    }
    normalized.to_string_lossy().into_owned()
}

/// `human_size` — 1 decimal place, B/KB/MB/GB/TB, 1024 steps.
pub fn human_size(bytes: u64) -> String {
    let mut size = bytes as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} TB")
}

/// Full rule catalogue for the "what does this clean" screen.
pub fn rule_catalogue() -> Vec<RuleInfo> {
    let mut out = Vec::new();
    for r in RECURSIVE_RULES {
        out.push(RuleInfo {
            key: r.key.to_string(),
            kind: r.kind.as_str().to_string(),
            label: r.label.to_string(),
            category: r.category,
            safe: r.safe,
            aggressive: r.aggressive,
            scope: "recursive".to_string(),
        });
    }
    for r in HOME_EXACT_RULES {
        out.push(RuleInfo {
            key: r.template.to_string(),
            kind: match r.strategy {
                Strategy::Path => "exact_path",
                Strategy::Children => "exact_children",
            }
            .to_string(),
            label: r.label.to_string(),
            category: r.category,
            safe: true,
            aggressive: true,
            scope: "home".to_string(),
        });
    }
    for r in SYSTEM_EXACT_RULES {
        out.push(RuleInfo {
            key: r.template.to_string(),
            kind: match r.strategy {
                Strategy::Path => "exact_path",
                Strategy::Children => "exact_children",
            }
            .to_string(),
            label: r.label.to_string(),
            category: r.category,
            safe: true,
            aggressive: true,
            scope: "system".to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_rule_count_matches_python() {
        assert_eq!(RECURSIVE_RULES.len(), 21);
        assert_eq!(HOME_EXACT_RULES.len(), 14);
        assert_eq!(SYSTEM_EXACT_RULES.len(), 6);
        assert_eq!(EXCLUDED_DIR_NAMES.len(), 10);
    }

    #[test]
    fn safe_mode_excludes_aggressive_only_dirs() {
        let idx = rules_for_mode(Mode::Safe);
        assert!(idx.dirs.contains_key("node_modules"));
        assert!(idx.dirs.contains_key(".cache"));
        assert!(idx.dirs.contains_key(".gradle"));
        // aggressive-only:
        assert!(!idx.dirs.contains_key("build"));
        assert!(!idx.dirs.contains_key("dist"));
        assert!(!idx.dirs.contains_key("out"));
        assert!(!idx.dirs.contains_key("target"));
        assert!(!idx.dirs.contains_key("coverage"));
        assert!(!idx.dirs.contains_key(".tox"));
        assert!(!idx.dirs.contains_key(".terraform"));
        assert!(idx.file_exact.contains_key(".DS_Store"));
        assert!(idx.file_suffix.is_empty()); // .pyc is aggressive-only
    }

    #[test]
    fn aggressive_mode_includes_everything() {
        let idx = rules_for_mode(Mode::Aggressive);
        assert!(idx.dirs.contains_key("build"));
        assert!(idx.dirs.contains_key("target"));
        assert_eq!(idx.file_suffix.len(), 1);
        assert_eq!(idx.file_suffix[0].key, ".pyc");
    }

    #[test]
    fn mode_normalize_matches_python() {
        assert_eq!(Mode::normalize("aggressive"), Mode::Aggressive);
        assert_eq!(Mode::normalize("AGGRESSIVE"), Mode::Aggressive);
        assert_eq!(Mode::normalize("safe"), Mode::Safe);
        assert_eq!(Mode::normalize("nonsense"), Mode::Safe);
        assert_eq!(Mode::normalize(""), Mode::Safe);
    }

    // Ported directly from tests/test_main.py::PathGroupTests
    #[test]
    fn path_group_project_paths_group_to_home_child() {
        assert_eq!(
            path_group(Path::new("/Users/alice/projects/app/node_modules")),
            "/Users/alice/projects"
        );
    }

    #[test]
    fn path_group_library_cache_groups_to_home_library() {
        assert_eq!(
            path_group(Path::new("/Users/alice/Library/Caches/Google/Chrome")),
            "/Users/alice/Library"
        );
    }

    #[test]
    fn path_group_dotdir_directly_under_home_is_own_group() {
        assert_eq!(
            path_group(Path::new("/Users/alice/.pnpm-store")),
            "/Users/alice/.pnpm-store"
        );
    }

    #[test]
    fn path_group_home_root_is_own_group() {
        assert_eq!(path_group(Path::new("/Users/alice")), "/Users/alice");
    }

    #[test]
    fn path_group_system_paths_stay_top_level() {
        assert_eq!(path_group(Path::new("/Library/Caches/foo")), "/Library");
        assert_eq!(path_group(Path::new("/opt/homebrew/var/cache/x")), "/opt");
    }

    #[test]
    fn human_size_matches_python_formatting() {
        assert_eq!(human_size(0), "0.0 B");
        assert_eq!(human_size(512), "512.0 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(human_size(5 * 1024_u64.pow(4)), "5.0 TB");
    }
}
