# MacClean — Deletion Safety Policy

MacClean deletes files. This document describes the centralised safety policy that
governs **every** deletion, implemented in Rust in
`src-tauri/crates/macclean-core/src/safety.rs` and enforced again at delete time in
`src-tauri/crates/macclean-core/src/session.rs` and `deleter.rs`.

The frontend is never trusted. It cannot name a path to delete — it can only pass
back opaque candidate ids from a scan session that Rust itself produced.

---

## 1. Threat model

| Threat | Mitigation |
|--------|------------|
| Frontend asks to delete an arbitrary path | Delete API takes `(scan_id, candidate_ids[])` only; the path is looked up from the Rust-owned session |
| Frontend replays an old / forged `scan_id` | Sessions expire (1 h TTL, 24-session cap); unknown id → `invalid_scan_id`, nothing deleted |
| Candidate path changed between scan and delete (TOCTOU) | Re-`symlink_metadata` at delete time; identity (dev+inode) and file-type must match what the scan recorded, else `Changed` |
| Symlink swapped in to redirect a recursive delete | Directory deletes use `std::fs::remove_dir_all`, which **removes symlink entries as links and never traverses them**; the top-level path is re-checked as a symlink immediately before deletion |
| `..` / `.` / relative trickery in a path | All paths are lexically normalised **and** `canonicalize`d before any check |
| Case-insensitive filesystem tricks (`/USERS`) | Protected-path comparison is ASCII case-insensitive |
| `/tmp`, `/etc`, `/var` → `/private/*` firelink escapes | `canonicalize` resolves macOS firelinks before checks |
| Deleting a whole protected tree | Protected-path set + component-depth guard + per-scope root containment |
| Crossing into another volume | Recursive operations never descend through `/Volumes`; `/Volumes/*` roots are protected |

---

## 2. Path normalisation  (`safety::normalize`, `safety::real`)

1. Expand a leading `~` to the user's home.
2. Make absolute against the current directory if needed.
3. Lexically fold `.` and `..` **without touching the filesystem**
   (`normalize` — used for display and pre-checks).
4. `std::fs::canonicalize` to resolve symlinks and firelinks
   (`real` — used for all safety decisions). If canonicalisation fails because the
   leaf does not exist, canonicalise the deepest existing ancestor and re-append
   the remainder.

All comparisons below operate on the canonical form, ASCII-lowercased for the
protected-set membership test.

---

## 3. Protected paths  (`safety::is_protected`)

A path is **protected** (never deletable, never emitted as a candidate) if **any**
of the following hold for its canonical form `p`:

### 3.1 Exact / prefix system paths

`p` equals, or is an **ancestor of**, or is **contained in** any of:

```
/                      /System                /Library
/Users                 /Applications          /Volumes
/private                /bin                    /sbin
/usr                   /var                    /etc
/opt                   /cores                  /dev
/tmp                   /home                   /Network
/System/Volumes        /private/var/db          /Library/Apple
```

> "contained in" for `/usr` etc. means MacClean will not delete `/usr/local` as a
> whole, but *candidates discovered by a rule* under `/usr/local/var/cache/*` are
> individual children, which are allowed (they are not themselves in the set and
> clear the depth guard).

### 3.2 User directories

`p` equals any of (`$HOME` = the invoking user's home):

```
$HOME
$HOME/Library            $HOME/Library/Caches      $HOME/Library/Logs
$HOME/Library/Keychains    $HOME/Library/Preferences  $HOME/Library/Application Support
$HOME/Documents           $HOME/Desktop             $HOME/Downloads
$HOME/Movies              $HOME/Music               $HOME/Pictures
$HOME/Public              $HOME/Applications         $HOME/.Trash
$HOME/.ssh                $HOME/.gnupg              $HOME/.config
$HOME/.aws                $HOME/.kube               $HOME/projects   (PROJECTS_ROOT)
```

The *contents* of `$HOME/Library/Caches`, `$HOME/Library/Logs`, `$HOME/.Trash`,
etc. are deletable (that is the whole point of the app); the container itself is
not.

### 3.3 Structural guards

- **Component-depth guard**: fewer than **3** path components after the root
  (`/a`, `/a/b`) → protected. Every real cleanup target is deeper.
- **Home-relative depth guard**: a path under `$HOME/Library` must be at least
  `$HOME/Library/<x>/<y>` (depth ≥ 2 below `Library`) to be deletable;
  `$HOME/Library/<x>` alone is protected.
- **Volume roots**: `/Volumes/<name>` (exactly one component under `/Volumes`) is
  protected.
- **Symlinked leaf**: if the candidate path is itself a symlink, only the link is
  removed — never its target, never a tree through it.

### 3.4 Root containment

At delete time the candidate's canonical path must still be contained in one of
the roots that its originating scan scope resolves to **now** (`scope::roots`).
A candidate whose root disappeared or whose path escaped its root is rejected
(`NotInSession` / `Changed`).

---

## 4. The eight delete-time checks  (design.md §10)

`session::validate_for_delete(scan_id, candidate_id)` returns the stored candidate
only if **all** pass; otherwise it returns the failing `DeleteStatus`:

| # | Check | Failure status |
|---|-------|----------------|
| 1 | The scan session exists and is not expired | `NotInSession` (`invalid_scan_id`) |
| 2 | The candidate id belongs to that session | `NotInSession` |
| 3 | The canonical path is still inside a permitted scope root | `NotInSession` |
| 4 | The path is still `!is_protected` and passes the symlink policy | `Protected` |
| 5 | The path is unchanged since the scan (file-type + dev/inode identity) | `Changed` |
| 6 | The requested operation is "delete" (the only supported op) | `Skipped` |
| 7 | The file or directory still exists | `AlreadyMissing` |
| 8 | The path is not a protected path (explicit re-check) | `Protected` |

Only after this does `deleter::delete_candidate` run, and it re-checks
`is_protected` **once more** immediately before the `remove_*` call.

---

## 5. Deletion mechanics  (`deleter::delete_candidate`)

```text
symlink_metadata(path) ─ NotFound ──────────────▶ AlreadyMissing
                        └ is_symlink ───────────▶ remove_file(link)        → Deleted
                        └ is_dir ──── re-check is_protected ─ fail ─▶ Protected
                                     └ remove_dir_all(path) ─────────▶ Deleted
                        └ is_file ──────────────▶ remove_file(path)        → Deleted

Any io::ErrorKind::PermissionDenied ────────────▶ PermissionDenied
Any other io::Error ────────────────────────────▶ Failed { message }
```

`remove_dir_all` in the Rust standard library does not follow symlinks: a symlink
encountered inside the tree is unlinked, its target is untouched. Freed bytes are
measured immediately before deletion (native recursive sum), falling back to the
size recorded during the scan if measurement fails.

---

## 6. What is deliberately **not** done

- MacClean does **not** run as root and does not use `sudo`. Locations that need
  Full Disk Access are surfaced to the user with instructions (see
  `docs/permissions.md`); denied paths are reported, never silently skipped as
  "cleaned".
- MacClean does **not** move items to the Trash — deletions are permanent, and the
  confirmation dialog says so.
- MacClean does **not** shell out for deletion or sizing.

---

## 7. Tests

`safety.rs`, `session.rs`, and `deleter.rs` carry unit tests for: exact protected
matches, ancestor/descendant protection, depth guards, `..` normalisation,
case-insensitive matches, firelink resolution, symlink-leaf handling, the eight
delete-time checks, TOCTOU (`Changed`) detection, permission-denied mapping, and
missing-path handling. Integration tests in
`src-tauri/crates/macclean-core/tests/` build realistic temp directory trees and
run full scan → select → delete → verify cycles. No test ever touches a real
system directory.
