# MacClean — macOS Permissions

## Principle

```
normal user application
        │
        ▼
request the access it needs (Full Disk Access)
        │
        ▼
perform only the authorised operation, and report what it could not reach
```

MacClean **never** runs as `root` and **never** invokes `sudo`. If it is launched
under `sudo` it shows a warning (the `is_admin` flag in *About*).

## What needs what

| Locations | Access required |
|-----------|-----------------|
| `~/projects`, `~/.npm`, `~/.pnpm-store`, `~/.cache`, most of `~` | none beyond normal user rights |
| `~/Library/Caches/*`, `~/Library/Logs/*`, `~/Library/Developer/Xcode/DerivedData` | normal user rights (readable without FDA on current macOS, but some app subfolders are TCC‑gated) |
| `~/Library/Safari`, `~/Library/Mail`, `~/Library/Messages`, `~/Library/Application Support/com.apple.*` | **Full Disk Access** |
| `/Library/Caches/*`, `/Library/Logs/*`, `/private/var/folders/*`, `/private/var/log/*` (Full Mac scope) | **Full Disk Access** |
| Homebrew / `/usr/local` caches | normal rights (owned by the user on most setups) |

## How MacClean handles a denial

1. The scan **continues** — one unreadable directory never aborts the scan.
2. Each denied path is recorded as a `ScanError { kind: permissionDenied }` and
   surfaced in the results header ("N locations couldn't be read — see details")
   and the *Locations that couldn't be read* dialog.
3. `permissionDeniedCount` is shown; the app **never** reports a protected or
   unreadable path as "cleaned".
4. The *Permissions* dialog probes a handful of TCC‑gated directories and shows a
   green/red readout, plus a one‑click *Open System Settings* button
   (`x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`).

## Granting Full Disk Access

1. *System Settings ▸ Privacy & Security ▸ Full Disk Access.*
2. Enable **MacClean** (use **+** to add `/Applications/MacClean.app` if it isn't
   listed).
3. Quit and reopen MacClean, then run a new scan.

## Detection

`sysinfo::permission_status()` tries `read_dir` on `~/Library/Safari`,
`~/Library/Mail`, `~/Library/Application Support/com.apple.TCC` and
`~/Library/Messages`. If every one that exists is readable, FDA is reported as
granted. This is a best‑effort heuristic — the authoritative signal is whether a
*Full Mac* scan still reports `permissionDenied` errors.

## Entitlements

`src-tauri/entitlements.plist` — **no** App Sandbox (incompatible with
cross‑home cache cleanup), Hardened Runtime friendly keys only
(`allow-jit`, `allow-unsigned-executable-memory`, `disable-library-validation`,
`automation.apple-events`). Hardened Runtime is required for notarisation.
