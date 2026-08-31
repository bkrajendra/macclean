//! Path normalisation and the centralised protected-path policy.
//!
//! See `docs/security/deletion-safety.md` for the rationale. Every deletion in
//! the app passes through [`is_protected`]; the scanner also uses it to refuse to
//! even *emit* a protected path as a candidate.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// The invoking user's home directory (falls back to `/` — which is protected —
/// if it cannot be determined).
pub fn home_dir() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")))
        .clone()
}

/// `~/projects` — the `Projects` scope root (and a protected path in its own right).
pub fn projects_root() -> PathBuf {
    home_dir().join("projects")
}

/// Expand a leading `~` / `~/…` to the user's home. Other paths are returned as-is.
pub fn expand_tilde<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    let mut comps = path.components();
    match comps.next() {
        Some(Component::Normal(first)) if first == "~" => {
            let mut out = home_dir();
            out.extend(comps.as_path());
            out
        }
        _ => {
            // Handle the literal string form "~/x" that `components()` splits oddly.
            if let Some(s) = path.to_str() {
                if let Some(rest) = s.strip_prefix("~/") {
                    return home_dir().join(rest);
                }
                if s == "~" {
                    return home_dir();
                }
            }
            path.to_path_buf()
        }
    }
}

/// Lexically normalise a path: expand `~`, drop `.`, fold `..`, keep it absolute.
/// Never touches the filesystem.
pub fn normalize<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = expand_tilde(path);
    let mut out: Vec<Component> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                match out.last() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(Component::RootDir) | None => {
                        // `/..` == `/`; leading `..` on a relative path is dropped.
                    }
                    _ => {
                        out.push(comp);
                    }
                }
            }
            other => out.push(other),
        }
    }
    let mut buf = PathBuf::new();
    for c in out {
        buf.push(c.as_os_str());
    }
    if buf.as_os_str().is_empty() {
        buf.push("/");
    }
    buf
}

/// Resolve a path to its canonical, symlink-free form. If the leaf does not
/// exist, canonicalise the deepest existing ancestor and re-append the tail so
/// callers still get a firelink-resolved, `..`-free path.
pub fn real<P: AsRef<Path>>(path: P) -> PathBuf {
    let normalized = normalize(path);
    if let Ok(c) = std::fs::canonicalize(&normalized) {
        return c;
    }
    let mut existing = normalized.as_path();
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    while let Some(parent) = existing.parent() {
        if let Some(name) = existing.file_name() {
            tail.push(name);
        }
        existing = parent;
        if let Ok(c) = std::fs::canonicalize(existing) {
            let mut out = c;
            for name in tail.iter().rev() {
                out.push(name);
            }
            return out;
        }
    }
    normalized
}

/// True if `path` is equal to, or lexically contained within, `root`
/// (component-boundary aware). Both are normalised first.
pub fn is_within<R: AsRef<Path>, P: AsRef<Path>>(root: R, path: P) -> bool {
    let root = normalize(root);
    let path = normalize(path);
    path.starts_with(&root)
}

/// Same as [`is_within`] but canonicalises both sides first (symlink-safe).
pub fn is_within_real<R: AsRef<Path>, P: AsRef<Path>>(root: R, path: P) -> bool {
    real(path).starts_with(real(root))
}

fn lc(p: &Path) -> String {
    p.to_string_lossy().to_ascii_lowercase()
}

/// The protected set, canonicalised once, as `(real_path, lowercased_string)`.
fn protected_real() -> &'static Vec<(PathBuf, String)> {
    static SET: OnceLock<Vec<(PathBuf, String)>> = OnceLock::new();
    SET.get_or_init(|| {
        protected_paths()
            .iter()
            .map(|p| {
                let r = real(p);
                let s = lc(&r);
                (r, s)
            })
            .collect()
    })
}

/// `~/Library`, canonicalised once.
fn real_user_library() -> &'static PathBuf {
    static LIB: OnceLock<PathBuf> = OnceLock::new();
    LIB.get_or_init(|| real(home_dir().join("Library")))
}

/// The list of paths MacClean will never delete. Public for the permissions /
/// safety screen and for tests.
pub fn protected_paths() -> Vec<PathBuf> {
    let home = home_dir();
    let system: &[&str] = &[
        "/",
        "/System",
        "/System/Volumes",
        "/System/Volumes/Data",
        "/System/Library",
        "/Library",
        "/Library/Apple",
        "/Library/Caches",
        "/Library/Logs",
        "/Users",
        "/Applications",
        "/Volumes",
        "/private",
        "/private/var",
        "/private/var/db",
        "/private/var/folders",
        "/private/var/log",
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/local",
        "/usr/local/var",
        "/usr/local/var/cache",
        "/var",
        "/etc",
        "/opt",
        "/opt/homebrew",
        "/opt/homebrew/var",
        "/opt/homebrew/var/cache",
        "/cores",
        "/dev",
        "/tmp",
        "/nix",
        "/Network",
        "/home",
    ];

    let home_rel: &[&str] = &[
        "",
        "Library",
        "Library/Caches",
        "Library/Caches/Google/Chrome",
        "Library/Caches/com.microsoft.edgemac",
        "Library/Caches/BraveSoftware/Brave-Browser",
        "Library/Caches/Mozilla/Firefox",
        "Library/Caches/com.apple.Safari",
        "Library/Logs",
        "Library/Preferences",
        "Library/Keychains",
        "Library/Application Support",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Mobile Documents",
        "Library/CloudStorage",
        "Library/Developer",
        "Documents",
        "Desktop",
        "Downloads",
        "Movies",
        "Music",
        "Pictures",
        "Public",
        "Applications",
        ".Trash",
        ".ssh",
        ".gnupg",
        ".config",
        ".aws",
        ".kube",
        ".docker",
        ".cargo",
        ".rustup",
        ".nvm",
        "projects",
    ];

    let mut out: Vec<PathBuf> = system.iter().map(PathBuf::from).collect();
    for rel in home_rel {
        if rel.is_empty() {
            out.push(home.clone());
        } else {
            out.push(home.join(rel));
        }
    }
    out
}

/// The core safety gate. `true` ⇒ MacClean must never delete this path and must
/// never surface it as a cleanup candidate.
pub fn is_protected<P: AsRef<Path>>(path: P) -> bool {
    let candidate = real(&path);
    let candidate_lc = lc(&candidate);

    let set = protected_real();

    // 1. Exact membership (case-insensitive) of the protected set.
    if set.iter().any(|(_, s)| s == &candidate_lc) {
        return true;
    }

    // 2. Candidate is an ancestor of (or equal to) a protected path.
    if set.iter().any(|(p, _)| p.starts_with(&candidate)) {
        return true;
    }

    // 3. Structural depth guard: `/`, `/x`, `/x/y` are always protected.
    if candidate.components().count() < 4 {
        return true;
    }

    // 4. `~/Library/<x>` (one level under the user Library) is protected; only
    //    `~/Library/<x>/<y>...` may be deleted.
    if let Ok(rest) = candidate.strip_prefix(real_user_library()) {
        if rest.components().count() < 2 {
            return true;
        }
    }

    // 5. Any single-segment volume root `/Volumes/<name>`.
    let volumes = Path::new("/Volumes");
    if let Ok(rest) = candidate.strip_prefix(volumes) {
        if rest.components().count() < 2 {
            return true;
        }
    }

    false
}

/// True if `path` (an already-`lstat`-known symlink or not) should have only its
/// own entry removed, never be traversed. Symlinks are always link-only.
pub fn is_link_only(is_symlink: bool) -> bool {
    is_symlink
}

/// `~`-shorten a path for display.
pub fn display_path<P: AsRef<Path>>(path: P) -> String {
    let path = path.as_ref();
    let home = home_dir();
    if path == home {
        return "~".to_string();
    }
    if let Ok(rest) = path.strip_prefix(&home) {
        return format!("~/{}", rest.to_string_lossy());
    }
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_folds_parent_and_cur() {
        assert_eq!(normalize("/a/b/../c/./d"), PathBuf::from("/a/c/d"));
        assert_eq!(normalize("/a/../../b"), PathBuf::from("/b"));
        assert_eq!(normalize("/.."), PathBuf::from("/"));
    }

    #[test]
    fn expand_tilde_string_and_component_forms() {
        let home = home_dir();
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(expand_tilde("~/x/y"), home.join("x/y"));
        assert_eq!(expand_tilde("/absolute"), PathBuf::from("/absolute"));
    }

    #[test]
    fn is_within_is_component_aware() {
        assert!(is_within("/a/b", "/a/b/c"));
        assert!(is_within("/a/b", "/a/b"));
        assert!(!is_within("/a/b", "/a/bc"));
        assert!(!is_within("/a/b", "/a"));
    }

    #[test]
    fn root_and_shallow_paths_are_protected() {
        assert!(is_protected("/"));
        assert!(is_protected("/usr"));
        assert!(is_protected("/System"));
        assert!(is_protected("/Library"));
        assert!(is_protected("/Users"));
        assert!(is_protected("/private"));
        assert!(is_protected("/opt/homebrew"));
        assert!(is_protected("/x/y")); // depth guard
    }

    #[test]
    fn case_insensitive_protection() {
        assert!(is_protected("/USERS"));
        assert!(is_protected("/lIbRaRy"));
    }

    #[test]
    fn parent_dir_escape_is_resolved_then_protected() {
        assert!(is_protected("/Library/Caches/../.."));
        assert!(is_protected("/Users/../Users"));
    }

    #[test]
    fn home_and_key_user_dirs_are_protected() {
        let home = home_dir();
        assert!(is_protected(&home));
        assert!(is_protected(home.join("Library")));
        assert!(is_protected(home.join("Library/Caches")));
        assert!(is_protected(home.join("Library/Logs")));
        assert!(is_protected(home.join("Documents")));
        assert!(is_protected(home.join(".ssh")));
        assert!(is_protected(home.join(".Trash")));
        assert!(is_protected(home.join("projects")));
    }

    #[test]
    fn library_child_depth_guard() {
        let home = home_dir();
        // one level under ~/Library => protected
        assert!(is_protected(home.join("Library/Containers")));
        assert!(is_protected(home.join("Library/SomethingElse")));
        // two levels under ~/Library => allowed (not protected by policy)
        assert!(!is_protected(home.join("Library/Caches/com.example.app")));
        assert!(!is_protected(home.join("Library/Logs/DiagnosticReports")));
    }

    #[test]
    fn legit_cleanup_targets_are_not_protected() {
        let home = home_dir();
        assert!(!is_protected(home.join("projects/app/node_modules")));
        assert!(!is_protected(home.join(".pnpm-store")));
        assert!(!is_protected(home.join(".npm/_cacache")));
        assert!(!is_protected("/Library/Caches/com.apple.Something"));
        assert!(!is_protected("/private/var/folders/aa/bbbbbb/T"));
        assert!(!is_protected("/opt/homebrew/var/cache/foo"));
    }

    #[test]
    fn volume_roots_protected_but_contents_not() {
        assert!(is_protected("/Volumes/Data"));
        assert!(!is_protected("/Volumes/Data/some/deep/node_modules"));
    }
}
