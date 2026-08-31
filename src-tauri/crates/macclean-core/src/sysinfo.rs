//! System information: current user, admin check, disk usage, and best-effort
//! Full Disk Access probing. Replaces the Python `status_payload` /
//! `is_admin_user` and the `sudo` elevation model with a permissions-aware
//! report.

use crate::model::{PermissionProbe, PermissionStatus, SystemInfo};
use crate::safety;
use std::path::Path;

/// True when the effective uid is 0. MacClean is *not* meant to run this way —
/// this only exists to warn the user if they launched it under `sudo`.
pub fn is_admin() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// `(total_bytes, available_bytes)` for the filesystem containing `path`.
pub fn disk_usage(path: &Path) -> (u64, u64) {
    #[cfg(target_os = "macos")]
    unsafe {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
            return (0, 0);
        };
        let mut s: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut s) == 0 {
            let bsize = s.f_bsize as u64;
            return (
                s.f_blocks.saturating_mul(bsize),
                s.f_bavail.saturating_mul(bsize),
            );
        }
        (0, 0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        (0, 0)
    }
}

fn probe(label: &str, path: std::path::PathBuf) -> Option<(PermissionProbe, bool)> {
    if !path.exists() {
        return None;
    }
    let readable = std::fs::read_dir(&path).is_ok();
    Some((
        PermissionProbe {
            label: label.to_string(),
            path: safety::display_path(&path),
            readable,
        },
        readable,
    ))
}

/// Best-effort guess at whether the app has Full Disk Access.
///
/// A non-FDA process gets `EPERM` opening the user's TCC database or listing
/// Safari / Mail / Messages data; an FDA process succeeds. **Any** one success
/// means FDA is granted (Macs vary in which of these exist). The
/// `com.apple.TCC` *directory* is deliberately not used — it stays unreadable
/// even with FDA and produced a permanent false negative.
pub fn permission_status() -> PermissionStatus {
    let home = safety::home_dir();
    let home_readable = std::fs::read_dir(&home).is_ok();
    let mut probes = Vec::new();
    let mut verdict: Option<bool> = None;

    fn note(v: &mut Option<bool>, readable: bool) {
        match v {
            None => *v = Some(readable),
            Some(false) if readable => *v = Some(true), // any success confirms FDA
            _ => {}
        }
    }

    // Primary: can we open the user's TCC database file?
    let tcc = home.join("Library/Application Support/com.apple.TCC/TCC.db");
    match std::fs::File::open(&tcc) {
        Ok(_) => {
            note(&mut verdict, true);
            probes.push(PermissionProbe {
                label: "TCC database".into(),
                path: safety::display_path(&tcc),
                readable: true,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            note(&mut verdict, false);
            probes.push(PermissionProbe {
                label: "TCC database".into(),
                path: safety::display_path(&tcc),
                readable: false,
            });
        }
        Err(_) => {} // not found / other — inconclusive, skip
    }

    // Corroborating: list well-known FDA-gated data directories.
    for (label, rel) in [
        ("Safari data", "Library/Safari"),
        ("Mail data", "Library/Mail"),
        ("Messages data", "Library/Messages"),
    ] {
        let path = home.join(rel);
        if !path.exists() {
            continue;
        }
        let readable = std::fs::read_dir(&path).is_ok();
        note(&mut verdict, readable);
        probes.push(PermissionProbe {
            label: label.into(),
            path: safety::display_path(&path),
            readable,
        });
    }

    // Context rows (not part of the verdict).
    if let Some((p, _)) = probe("User caches", home.join("Library/Caches")) {
        probes.push(p);
    }
    if let Some((p, _)) = probe("System caches", std::path::PathBuf::from("/Library/Caches")) {
        probes.push(p);
    }

    PermissionStatus {
        full_disk_access: verdict.unwrap_or(home_readable),
        home_readable,
        probes,
    }
}

pub fn system_info(app_version: &str) -> SystemInfo {
    let home = safety::home_dir();
    let (total, available) = disk_usage(&home);
    SystemInfo {
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        current_user: current_user(),
        is_admin: is_admin(),
        home_dir: home.to_string_lossy().into_owned(),
        projects_dir: safety::projects_root().to_string_lossy().into_owned(),
        total_disk_bytes: total,
        available_disk_bytes: available,
        app_version: app_version.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_usage_reports_something_for_home() {
        let (total, avail) = disk_usage(&safety::home_dir());
        if cfg!(target_os = "macos") {
            assert!(total > 0, "expected a real total size on macOS");
            assert!(avail <= total);
        }
    }

    #[test]
    fn system_info_is_populated() {
        let info = system_info("9.9.9");
        assert_eq!(info.app_version, "9.9.9");
        assert!(!info.current_user.is_empty());
        assert!(info.home_dir.starts_with('/'));
        assert!(info.projects_dir.ends_with("projects"));
    }

    #[test]
    fn permission_status_runs() {
        let st = permission_status();
        // We can't assert a specific value (depends on the runner's TCC state),
        // but it must not panic and must return coherent data.
        let _ = st.full_disk_access;
        assert_eq!(
            st.home_readable,
            std::fs::read_dir(safety::home_dir()).is_ok()
        );
    }
}
