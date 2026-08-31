# MacClean Migration — Feature Inventory

Source of truth: the Python implementation on branch **`legacy-python`**
(`main.py` @ `ea0d8e6`, `ui/index.html`, `tests/test_main.py`).

This document is the authoritative catalogue of **every** feature, behaviour, scan
rule, safety restriction, and edge case discovered in the Python application, and
where each one lands in the native (Svelte 5 + Tauri 2 + Rust) app.

Legend for **Migration target**:

| Layer | Meaning |
|-------|---------|
| `core` | `src-tauri/crates/macclean-core` — pure Rust logic (filesystem, safety, rules) |
| `tauri` | `src-tauri/src` — IPC commands, event streaming, app state |
| `ui` | `src/` — Svelte 5 presentation |
| `config` | `tauri.conf.json`, workflows, docs |

---

## 1. Application shape

| # | Feature | Python implementation | Python UI | Inputs | Outputs | Safety restrictions | Error handling | Tests | Migration target | Priority |
|---|---------|-----------------------|-----------|--------|---------|---------------------|----------------|-------|------------------|----------|
| 1.1 | App entry / runtime | `HTTPServer` on `localhost:8080`, `BaseHTTPRequestHandler`, auto-opens browser via `webbrowser.open` | Browser tab | `--host`, `--port`, `--no-browser` | Long-running HTTP server | Binds localhost only | n/a | — | Replaced by native Tauri window; **no HTTP server, no browser, no Python** | P0 |
| 1.2 | Static UI delivery | `GET /` reads `ui/index.html` from disk | Full-page SPA | — | HTML | — | 404 on other paths | — | `ui` bundled into the app | P0 |
| 1.3 | Rule catalogue endpoint | `GET /targets` → `TARGET_RULES` JSON | (not shown) | — | JSON array | — | — | — | `core::rules` exposed via `get_rules` command | P2 |
| 1.4 | Status endpoint | `GET /status` → platform, user, admin, roots, scope defs, admin command | Drives admin banner + `~` display | — | JSON | — | `try/except` around fetch | — | `tauri::get_system_info` | P0 |
| 1.5 | Scan stream | `GET /stream?mode=&scope=` → Server-Sent Events | `EventSource` | `mode`, `scope` query params | SSE `start`/`item`/`progress`/`done` | see §5 | broken-pipe detection stops walk | `test_main.py::ScanStreamTests` | `tauri::start_scan` + `scan://*` events | P0 |
| 1.6 | Delete endpoint | `POST /delete` `{paths[], scan_id}` → summary JSON | Delete button flow | `paths[]`, `scan_id` | `{deleted_count, deleted_bytes, deleted_human, skipped[], invalid_scan_id}` | see §6 | per-path `try/except OSError` | — | `tauri::delete_selected` | P0 |
| 1.7 | Admin elevation hint | `admin_run_command()` builds `sudo -E uv run python main.py …` | Amber banner for Full Mac | — | string | — | — | — | Replaced by **Full Disk Access** guidance UI (`ui/permissions`) | P1 |

---

## 2. Cleanup modes  (`normalize_mode`, `rules_for_mode`)

| Mode | Behaviour | Migration target |
|------|-----------|------------------|
| **Safe** (default; any value other than `aggressive` normalises to `safe`) | Only rules whose `modes` set contains `safe` | `core::rules::Mode::Safe` |
| **Aggressive** | Adds build output / compiled artefacts (`build`, `dist`, `out`, `target`, `coverage`, `.tox`, `.terraform`, `*.pyc`) | `core::rules::Mode::Aggressive` |

Exactly two modes. No hidden third mode. Preserve the "unknown → safe" normalisation.

---

## 3. Scan scopes  (`SCOPE_DEFINITIONS`, `normalize_scope`, `scope_roots`, `homes_for_scope`)

| Scope | Roots walked | Notes | Migration target |
|-------|--------------|-------|------------------|
| **`projects`** (default; unknown → `projects`) | `~/projects` (`PROJECTS_ROOT`) | Recursive rules keep their own label/category. **`exact_candidates` still runs against `~`** (Python calls it for every scope via `homes_for_scope`, which returns `[HOME_ROOT]`), so a `projects` scan also lists `~/Library/Caches/*`, `~/Library/Logs/*`, `~/.Trash/*`, `~/.npm/_cacache`, … — preserved verbatim in the port. | `core::scope::Scope::Projects` |
| **`home`** | `~` (`HOME_ROOT`) | Recursive matches re-classified by `classify_exact_rule` against `[~]` | `core::scope::Scope::Home` |
| **`full_mac`** | `discover_user_homes()` + `/Library`, `/opt/homebrew`, `/usr/local` | Also runs `SYSTEM_EXACT_RULES`; recursive matches re-classified against all discovered homes; shows admin hint | `core::scope::Scope::FullMac` |

> `core::scanner::scan_with_roots(.., include_exact_rules = false)` is an added
> primitive (no Python equivalent) that walks only the given directories with the
> recursive rules — used for hermetic tests and a future "scan this folder"
> action. `core::scanner::scan` keeps the exact Python behaviour.

Extra roots: `MACCLEAN_EXTRA_SCAN_ROOTS` env var (comma-separated) is appended to
the root list for **every** scope. → migrate as `ScanOptions.extra_roots` **and**
keep honouring the env var in `core::scope`.

`discover_user_homes()`: entries of `/Users` except `Shared` and `.localized`,
that are directories; plus `HOME_ROOT` if not already present (realpath-compared).
`unique_existing_paths()` de-dupes by `realpath` and drops non-existent paths.

---

## 4. Cleanup rules

### 4.1 Recursive pattern rules  (`TARGET_RULES`, 21 live entries)

`kind` ∈ {`dir`, `file_exact`, `file_suffix`}. A matched **directory** is emitted
as a candidate and **not descended into** (`dirs[:]` pruning).

| key | kind | Safe | Aggressive | label | category |
|-----|------|:----:|:----------:|-------|----------|
| `node_modules` | dir | ✓ | ✓ | Node modules | Dependencies |
| `__pycache__` | dir | ✓ | ✓ | Python bytecode cache | Python |
| `.pytest_cache` | dir | ✓ | ✓ | Pytest cache | Python |
| `.mypy_cache` | dir | ✓ | ✓ | Mypy cache | Python |
| `.ruff_cache` | dir | ✓ | ✓ | Ruff cache | Python |
| `.next` | dir | ✓ | ✓ | Next.js build cache | Frontend |
| `.nuxt` | dir | ✓ | ✓ | Nuxt build cache | Frontend |
| `.svelte-kit` | dir | ✓ | ✓ | SvelteKit cache | Frontend |
| `.parcel-cache` | dir | ✓ | ✓ | Parcel cache | Frontend |
| `.angular` | dir | ✓ | ✓ | Angular cache | Frontend |
| `.cache` | dir | ✓ | ✓ | Generic cache folder | Caches |
| `.gradle` | dir | ✓ | ✓ | Gradle cache | Build |
| `build` | dir | ✗ | ✓ | Build output | Build |
| `dist` | dir | ✗ | ✓ | Distribution output | Build |
| `out` | dir | ✗ | ✓ | Compiled output | Build |
| `target` | dir | ✗ | ✓ | Rust/Java target output | Build |
| `coverage` | dir | ✗ | ✓ | Coverage report output | Testing |
| `.tox` | dir | ✗ | ✓ | Tox virtualenv cache | Testing |
| `.terraform` | dir | ✗ | ✓ | Terraform module cache | Infrastructure |
| `.DS_Store` | file_exact | ✓ | ✓ | macOS Finder metadata | macOS |
| `.pyc` | file_suffix | ✗ | ✓ | Python compiled file | Python |

> Note: the `legacy-python` source contains a **shadowed** earlier `TARGET_RULES`
> block; only the second definition above is live (`target` is aggressive-only).
> The native port uses the **live** set exactly.

Migration target: `core::rules::RECURSIVE_RULES` (const table) + `rules_for_mode`.

### 4.2 User-level exact rules  (`HOME_EXACT_RULES`, 14 entries)

`strategy` ∈ {`path` (emit the path itself), `children` (emit each direct child)}.
All are Safe **and** Aggressive. Templates expand `{home}` per `homes_for_scope`.

| path template | strategy | label | category |
|---------------|----------|-------|----------|
| `{home}/Library/Caches` | children | User app cache | System cache |
| `{home}/Library/Caches/Google/Chrome` | children | Chrome browser cache | Browser cache |
| `{home}/Library/Caches/com.microsoft.edgemac` | children | Edge browser cache | Browser cache |
| `{home}/Library/Caches/BraveSoftware/Brave-Browser` | children | Brave browser cache | Browser cache |
| `{home}/Library/Caches/Mozilla/Firefox` | children | Firefox browser cache | Browser cache |
| `{home}/Library/Caches/com.apple.Safari` | children | Safari browser cache | Browser cache |
| `{home}/Library/Logs` | children | User logs | Logs |
| `{home}/Library/Developer/Xcode/DerivedData` | path | Xcode derived data | Developer tools |
| `{home}/.Trash` | children | Trash items | macOS |
| `{home}/.npm/_cacache` | path | npm cache | Package manager cache |
| `{home}/.pnpm-store` | path | pnpm store cache | Package manager cache |
| `{home}/.yarn/cache` | path | Yarn cache | Package manager cache |
| `{home}/.cache/pip` | path | pip cache | Package manager cache |
| `{home}/.m2/repository` | path | Maven local repository cache | Package manager cache |

### 4.3 System-level exact rules  (`SYSTEM_EXACT_RULES`, 6 entries — `full_mac` only)

| path | strategy | label | category |
|------|----------|-------|----------|
| `/Library/Caches` | children | System cache | System cache |
| `/private/var/folders` | children | macOS temp cache | System cache |
| `/Library/Logs` | children | System logs | Logs |
| `/private/var/log` | children | System temp logs | Logs |
| `/opt/homebrew/var/cache` | children | Homebrew cache | Package manager cache |
| `/usr/local/var/cache` | children | Local cache | Package manager cache |

Migration target: `core::rules::{HOME_EXACT_RULES, SYSTEM_EXACT_RULES}` +
`core::scanner::exact_candidates`.

### 4.4 Reclassification  (`classify_exact_rule`)

For `home` / `full_mac` scopes, a **recursive** match inside an exact-rule tree is
relabelled with that exact rule's label/category (e.g. a `.cache` dir found under
`~/Library/Caches` is reported as "User app cache / System cache"). Fallback when
inside no exact tree: `("Known cache path", "Caches")`.

### 4.5 Excluded directory names  (`EXCLUDED_DIR_NAMES`)

Never descended into, never emitted: `.git`, `.svn`, `.hg`, `.Trash`,
`Applications`, `System`, `Volumes`, `dev`, `proc`, `sys`.
Migration target: `core::scope::EXCLUDED_DIR_NAMES`.

### 4.6 Grouping  (`path_group`)

- Under `/Users/<name>` or `/home/<name>`: group = `/Users/<name>/<first-child>`
  (e.g. `…/projects/app/node_modules` → `/Users/<name>/projects`); a path that
  **is** the home root groups to itself.
- Otherwise: `/<top-level>` (`/Library`, `/opt`, `/private`, `/usr`).

Covered by `test_main.py::PathGroupTests` (5 assertions) — port all of them.
Migration target: `core::rules::path_group`.

---

## 5. Scan behaviour & the SSE protocol  (`scan_stream`)

| Behaviour | Detail | Migration target |
|-----------|--------|------------------|
| Scan id | `uuid4().hex`, issued in the **`start`** event and repeated in `done` | `scan_id: String` returned by `start_scan`, echoed in every event |
| Early session registration | Session persisted with an **empty** path set at scan start; each `emit_item` adds its realpath immediately → partial results are deletable after a stop | `core::session` — register on start, append per candidate |
| Exact candidates first | `exact_candidates(scope, mode)` emitted before the directory walk | same ordering in `core::scanner` |
| Directory walk | `os.walk(topdown=True)`; prune `EXCLUDED_DIR_NAMES` and symlinked dirs; emit + prune matched target dirs | `core::scanner` parallel walk (jwalk) with `process_read_dir` pruning |
| Progress events | every **250** walked directories: `{type:"progress", scanned_dirs, current}` | `scan://progress` (throttled, same 250 cadence + time cap) |
| Item event | `{type:"item", path, size, human, group, category, label}` | `scan://candidates` batches of `ScanCandidate` |
| Size measurement | dirs: `du -sk` × 1024; files: `os.path.getsize`; any error → `0` | `core::scanner::path_size` — **native** recursive sum, errors → 0 |
| De-duplication | `seen` set keyed by `realpath` | `HashSet<PathBuf>` of canonical paths |
| Protected skip | `emit_item` drops paths where `is_protected_delete_path` | `core::safety::is_protected` |
| Non-existent skip | `emit_item` drops paths that don't exist | `symlink_metadata` check |
| Permission errors | `os.walk(onerror=…)` counts `PermissionError` / errno 1,13; never aborts | `ScanError{kind: PermissionDenied}` collected, scan continues |
| Cancellation | client closes `EventSource`; server notices on next failed `send` (progress events guarantee regular writes) | `AtomicBool` cancel flag checked per entry + per progress tick |
| Completion | `done` event: `mode, scope, total, total_bytes, count, scan_id, permissions_denied, is_admin, admin_hint` | `scan://completed` → `ScanSummary` |
| Admin hint | shown when `full_mac` and (not admin or permission_denied>0) | replaced by `PermissionStatus` + permissions UI |
| Session TTL / limit | `SCAN_SESSION_TTL_SECONDS = 3600`, `SCAN_SESSION_LIMIT = 24`, `prune_scan_sessions()` drops expired then oldest | `core::session::SessionStore` with identical constants |

---

## 6. Deletion behaviour  (`delete_paths`)

| Rule | Python | Native |
|------|--------|--------|
| Requires valid `scan_id` | missing/expired session → `invalid_scan_id: true`, everything skipped | same; `DeleteResult.invalid_scan_id` |
| Only session paths | `realpath(path) not in session["paths"]` → skipped | validation check #2 |
| Never protected | `is_protected_delete_path(path)` → skipped | validation check #4/#8 |
| Must still exist | `not os.path.exists(path)` → skipped | validation check #7 → `AlreadyMissing` |
| Directory vs file | `shutil.rmtree` for real dirs, `os.remove` otherwise; **symlinked dirs are unlinked, not walked** (`not os.path.islink`) | `core::deleter` — `remove_dir_all` (does not follow symlinks) for real dirs, `remove_file` for files & symlinks |
| Size accounting | `get_size(path)` measured just before deletion | recompute at delete time, fall back to stored |
| Per-path failure isolation | `try/except OSError` → path added to `skipped` | `DeleteOutcome{status: Failed | PermissionDenied, message}` |
| Post-delete bookkeeping | `allowed.discard(real)` | remove candidate from session |
| Result payload | `deleted_count, deleted_bytes, deleted_human, skipped[], invalid_scan_id` | richer `DeleteResult` with per-item `DeleteOutcome` (Deleted / Skipped / Failed / PermissionDenied / AlreadyMissing / Protected / NotInSession / Changed) |

**Strengthened in the native app** (design.md §10): re-validate root containment,
safety, and "unchanged since scan" (type + identity) for every candidate at delete
time. Never trust the id list beyond looking up the stored candidate.

---

## 7. Protected paths  (`protected_delete_paths`, `is_protected_delete_path`)

Exact `realpath` set: `/`, `/Users`, `/Library`, `/System`, `/Applications`,
`/Volumes`, `/private`, `HOME_ROOT`, `HOME_ROOT/Library`,
`HOME_ROOT/Library/Caches`, `HOME_ROOT/Library/Logs`, `PROJECTS_ROOT`.

Native policy (see `docs/security/deletion-safety.md`) keeps every one of these and
adds: `/bin /sbin /usr /var /opt /etc /cores /dev /tmp /home`, the user's
`Documents Desktop Downloads Movies Music Pictures Public .ssh .gnupg Library/Keychains`,
any volume root under `/Volumes/*`, any path with fewer than 3 real components,
depth guards for `~/Library/*` and `/Library/*`, plus symlink / `..` / case /
mount-boundary handling.

---

## 8. Frontend features  (`ui/index.html`)

| Feature | Detail | Migration target |
|---------|--------|------------------|
| Mode & Scope selectors | 2 + 3 options | `ui/features/dashboard` + `ui/features/settings` |
| Start / Stop scan | Stop keeps partial results selectable | `ui/features/scan` |
| Scan animation | CSS radar; live "items · size found"; current directory strip | `ui/features/scan` (native-feeling progress) |
| Stats row | Detected items, Selected items, Detected reclaimable, Selected reclaimable | `ui/features/results` stat tiles |
| Results grouping | Horizontal tab bar per `group`; **All** tab first; per-tab count·size badge; faded empty tabs | `ui/features/results` category + group filters |
| Row rendering | checkbox, label, size badge, colour-hashed category chip, mono path (`~` shortened) | `ui/features/results/ResultRow` |
| Selection | per-row, "Select visible", "Clear selection", per-tab "Select/Unselect all in this path"; items auto-selected on discovery | `ui/lib/stores/selection` |
| Filtering | free-text search (path/group/label), category `<select>`, sort (size ↑/↓, path A–Z/Z–A) | `ui/features/results/ResultsToolbar` |
| Category filter list | auto-populated from discovered categories | derived store |
| Delete confirmation | in-page modal: count + approx size + "removed permanently, not Trash" | `ui/features/cleanup/CleanupDialog` |
| Celebration | confetti + count-up of reclaimed bytes; auto-dismiss ~6 s; respects `prefers-reduced-motion` | `ui/features/cleanup/CleanupSummary` (restrained, macOS-native) |
| Status pill | idle / active / ok / warn | `ui` status indicator |
| Admin banner | Full-Mac + non-admin / permission-denied messaging + suggested `sudo` command | replaced by `ui/features/permissions` |
| `~` shortening | via `/status` `home_root` | `ui/lib/utils/format` using `SystemInfo.home_dir` |
| `prefers-reduced-motion` | disables aurora drift, radar, confetti, count-up | global CSS + motion guard |
| Empty / loading / error states | "No scan yet", per-tab empty text, stream-drop warning | dedicated components (design.md §7) |

---

## 9. Tests to carry over  (`tests/test_main.py`)

| Python test | Intent | Native equivalent |
|-------------|--------|-------------------|
| `PathGroupTests` ×5 | `path_group` granularity (project child, Library, dot-dir, home root, system top-level) | `core::rules::tests::path_group_*` |
| `ScanStreamTests::test_scan_id_issued_at_start_and_items_use_group` | scan id in `start`; items carry `group`; session holds every emitted path; `done` echoes id | `core::scanner` + `core::session` integration tests |
| `ScanStreamTests::test_progress_events_emitted_during_walk` | progress emitted, `scanned_dirs ≥ 250`, `current` under the scanned root | `core::scanner::tests::progress_emitted` |

Plus **new** coverage required by design.md §21 (protected-path detection, scope
validation, rule matching, classification, duplicate handling, cancellation,
deletion validation, session validation, defensive deletion, permission handling).

---

## 10. Explicitly out of scope / intentionally dropped

| Dropped | Reason |
|---------|--------|
| HTTP server, SSE, `webbrowser.open` | Replaced by Tauri IPC + native window |
| `--host` / `--port` / `--no-browser` CLI flags | No server to configure |
| `sudo -E uv run …` elevation model | Replaced by Full Disk Access request flow (design.md §12) |
| `du` subprocess for sizing | Replaced by native recursive sizing (design.md §8) |
| PyInstaller (`MacClean.spec`) | Replaced by Tauri bundler (`.app` + `.dmg`) |
| Python runtime, `uv`, `pyproject.toml` | Removed from `main`; preserved on `legacy-python` |
