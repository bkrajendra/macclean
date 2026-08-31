//! Scan-scope → filesystem-root resolution, and user-home discovery.
//! Ported from Python `scope_roots`, `discover_user_homes`,
//! `system_roots_for_scope`, `homes_for_scope`, `unique_existing_paths`.

use crate::model::Scope;
use crate::safety;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const EXTRA_ROOTS_ENV: &str = "MACCLEAN_EXTRA_SCAN_ROOTS";

/// De-duplicate by canonical path and drop paths that do not exist. Order is
/// preserved (first occurrence wins) — matches Python `unique_existing_paths`.
pub fn dedupe_existing<I, P>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        if p.as_os_str().is_empty() {
            continue;
        }
        let real = safety::real(p);
        if !seen.insert(real) {
            continue;
        }
        if p.exists() {
            out.push(p.to_path_buf());
        }
    }
    out
}

/// Parse a comma-separated env-var value into candidate roots.
pub fn parse_extra_roots(raw: &str) -> Vec<PathBuf> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(safety::expand_tilde)
        .collect()
}

/// All real user home directories: entries of `/Users` that are directories
/// (excluding `Shared` and `.localized`), plus `$HOME`.
pub fn discover_user_homes() -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    let users = Path::new("/Users");
    if users.is_dir() {
        if let Ok(entries) = std::fs::read_dir(users) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == "Shared" || name == ".localized" {
                    continue;
                }
                let path = entry.path();
                if path.is_dir() {
                    homes.push(path);
                }
            }
        }
    }
    let home = safety::home_dir();
    let home_real = safety::real(&home);
    if home.is_dir() && !homes.iter().any(|h| safety::real(h) == home_real) {
        homes.push(home);
    }
    dedupe_existing(homes)
}

/// macOS system roots included in the `FullMac` scope.
pub fn system_roots() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/Library"),
            PathBuf::from("/opt/homebrew"),
            PathBuf::from("/usr/local"),
        ]
    } else {
        Vec::new()
    }
}

/// The directory roots walked for a scope, with extra roots (param + env var)
/// appended, de-duplicated, existing-only.
pub fn roots(scope: Scope, extra_roots: &[String]) -> Vec<PathBuf> {
    let home = safety::home_dir();
    let mut roots: Vec<PathBuf> = match scope {
        Scope::Projects => vec![safety::projects_root()],
        Scope::Home => vec![home],
        Scope::FullMac => {
            let mut r = discover_user_homes();
            r.extend(system_roots());
            r
        }
    };

    if let Ok(env_roots) = std::env::var(EXTRA_ROOTS_ENV) {
        roots.extend(parse_extra_roots(&env_roots));
    }
    roots.extend(extra_roots.iter().map(safety::expand_tilde));

    dedupe_existing(roots)
}

/// The home directories against which exact rules are expanded for a scope.
pub fn homes_for_scope(scope: Scope) -> Vec<PathBuf> {
    match scope {
        Scope::FullMac => {
            let homes = discover_user_homes();
            if homes.is_empty() {
                vec![safety::home_dir()]
            } else {
                homes
            }
        }
        _ => vec![safety::home_dir()],
    }
}

/// Human label + description for a scope (`SCOPE_DEFINITIONS`).
pub fn describe(scope: Scope) -> (&'static str, &'static str) {
    match scope {
        Scope::Projects => ("Projects", "Scan only ~/projects"),
        Scope::Home => ("User home", "Scan your home folder and user-level caches"),
        Scope::FullMac => ("Full Mac", "Scan user homes plus system cache locations"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_extra_roots_splits_and_trims() {
        let v = parse_extra_roots("/a/b , ,  /c/d ,");
        assert_eq!(v, vec![PathBuf::from("/a/b"), PathBuf::from("/c/d")]);
        assert!(parse_extra_roots("").is_empty());
        assert!(parse_extra_roots("   ").is_empty());
    }

    #[test]
    fn dedupe_existing_drops_missing_and_duplicates() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let missing = dir.path().join("nope");

        let out = dedupe_existing([a.clone(), a.clone(), b.clone(), missing]);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&a));
        assert!(out.contains(&b));
    }

    #[test]
    fn scope_normalize_matches_python() {
        assert_eq!(Scope::normalize("home"), Scope::Home);
        assert_eq!(Scope::normalize("full_mac"), Scope::FullMac);
        assert_eq!(Scope::normalize("fullMac"), Scope::FullMac);
        assert_eq!(Scope::normalize("projects"), Scope::Projects);
        assert_eq!(Scope::normalize("whatever"), Scope::Projects);
    }

    #[test]
    fn homes_for_non_fullmac_is_just_home() {
        assert_eq!(homes_for_scope(Scope::Projects), vec![safety::home_dir()]);
        assert_eq!(homes_for_scope(Scope::Home), vec![safety::home_dir()]);
    }
}
