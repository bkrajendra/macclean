# MacClean — Architecture

## Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│  Svelte 5 SPA  (src/)                                                │
│  routes/+page.svelte  →  phase machine: idle → scanning → results    │
│                          → cleaning → summary                        │
│  lib/features/*  views      lib/components/*  primitives             │
│  lib/stores/*    runes (.svelte.ts)   lib/utils/*  pure helpers      │
│  lib/api/*       invoke() + listen() wrappers                        │
└───────────────┬─────────────────────────────────────────────────────┘
                │  Tauri IPC  (JSON, camelCase)
┌───────────────▼─────────────────────────────────────────────────────┐
│  Tauri shell  (src-tauri/src/)                                       │
│  commands.rs  start_scan · cancel_scan · get_scan_progress ·         │
│               delete_selected · get_system_info ·                    │
│               get_permission_status · get_rules · list_scopes ·      │
│               reveal_in_finder · open_privacy_settings ·             │
│               toggle_keyboard_lock                                   │
│  state.rs     AppState { sessions: Mutex<SessionStore>,              │
│                          scans: Mutex<HashMap<id, ScanHandle>>,      │
│                          keyboard_lock: KeyboardLock }                │
│  events.rs    scan://started|candidates|progress|error|completed     │
│               cleanup://progress|completed · cleanMode://key         │
└───────────────┬─────────────────────────────────────────────────────┘
                │  plain function calls
┌───────────────▼─────────────────────────────────────────────────────┐
│  macclean-core  (src-tauri/crates/macclean-core/) — no Tauri, no UI  │
│  model    the serde IPC contract                                     │
│  safety   normalize · real (canonical+ancestor fallback) ·          │
│           is_within · is_protected · display_path                    │
│  rules    RECURSIVE_RULES(21) · HOME_EXACT_RULES(14) ·               │
│           SYSTEM_EXACT_RULES(6) · EXCLUDED_DIR_NAMES ·               │
│           rules_for_mode · classify_exact_rule · path_group ·        │
│           human_size                                                 │
│  scope    roots(scope, extra) · discover_user_homes ·               │
│           homes_for_scope · MACCLEAN_EXTRA_SCAN_ROOTS               │
│  scanner  scan / scan_with_id / scan_with_roots — walkdir, cancel   │
│           token, progress @250 dirs, native recursive sizing,        │
│           dedupe, ScanEvent stream, ScanReport                       │
│  session  SessionStore (TTL 1h, cap 24) · StoredCandidate ·          │
│           validate_for_delete → the 8 checks                         │
│  deleter  delete_selected[_with] · delete_candidate · DeleteOutcome  │
│  sysinfo  is_admin (geteuid) · statfs disk usage · FDA probing       │
└───────────────┬─────────────────────────────────────────────────────┘
                │  std::fs · libc
                ▼
        macOS filesystem / system APIs
```

## Why a separate `macclean-core` crate

- Every filesystem/safety decision is testable without a running app
  (43 unit tests + 4 integration tests, hermetic — no test touches a real system
  directory).
- The Tauri layer is thin glue: spawn a thread, forward events, hold state.
- `clippy -D warnings` and `cargo fmt --check` gate the whole workspace.

## Scan flow

1. `start_scan(options)` generates a `scan_id`, registers a `ScanHandle`
   (cancel flag + shared `ScanProgress`), spawns a `macclean-scan` thread, and
   returns the id immediately.
2. The thread runs `scanner::scan_with_id`, whose `emit` closure:
   - batches `Candidate` events (96 items / 120 ms) → `scan://candidates`
   - forwards `Progress` (every 250 walked dirs) → `scan://progress`
   - forwards `Error` → `scan://error`
3. On completion the thread stores a `ScanSession` (the `StoredCandidate`s, with
   `dev`/`ino` identity) in `AppState.sessions`, marks the handle finished, and
   emits `scan://completed` with the `ScanSummary`.
4. The frontend `scan` store accumulates candidates, auto‑selects each, and on
   `completed` moves to the `results` phase.

## Delete flow

1. `delete_selected({ scanId, candidateIds })` runs on a blocking task.
2. `deleter::delete_selected_with` prunes sessions, rejects an unknown
   `scanId` (`invalidScanId: true`), then for each id runs
   `SessionStore::validate_for_delete` (the eight checks) and, on success,
   `delete_candidate` — which re‑checks `is_protected` immediately before the
   `remove_*` call.
3. Per‑item progress streams over `cleanup://progress`; the final `DeleteResult`
   is both returned and emitted on `cleanup://completed`.
4. The frontend drops `deleted` / `alreadyMissing` candidates from the list and
   shows the summary.

## Clean Mode

A system-wide keyboard lock for physically wiping down the keyboard, entered
from *Settings ▸ Clean Mode* or the header's keyboard-off button.

1. `toggle_keyboard_lock(lock)` is Rust-owned, not frontend-owned: `AppState`
   holds a `KeyboardLock { flag: Arc<AtomicBool>, thread_started: Mutex<bool> }`.
   The first call with `lock: true` lazily spawns a dedicated OS thread
   (`keyboard_lock.rs`) that installs an active `CGEventTap` at
   `kCGHIDEventTap` — gated on **Accessibility** access, *not* Full Disk
   Access — for `KeyDown`/`KeyUp`/`FlagsChanged` only, then parks there
   pumping its run loop for the app's lifetime. Later calls only flip `flag`:
   while true the callback drops every keyboard event system-wide, while
   false it passes everything through. Mouse and trackpad events are not in
   the tap's mask at all, so a click always reaches the app.
2. **Why not `rdev`:** the first version used `rdev::grab`, whose macOS
   backend resolves a Unicode name for every key press via
   `TISCopyCurrentKeyboardInputSource`/`TISGetInputSourceProperty` before the
   user callback even runs. Those Text Input Source APIs assert they're on the
   main dispatch queue; from the tap thread the first key press aborted the
   app (`EXC_BREAKPOINT` in `dispatch_assert_queue`). The tap callback here
   only reads the integer keycode (`KEYBOARD_EVENT_KEYCODE`) and maps it
   through a static table — it must never call TIS/TSM or any other
   main-thread-only API.
3. If the callback is ever slow, macOS disables the tap
   (`kCGEventTapDisabledByTimeout`), which would silently unlock the keyboard;
   the callback re-enables it via `CGEventTapEnable` when that happens.
4. Being a real HID-level tap (not a webview `keydown` handler), the lock
   also blocks native menu-bar accelerators system-wide — ⌘Q, ⌘Tab, ⌘H
   included — in every app, not just MacClean's window. A frontend-only
   `preventDefault` trap can only ever affect events already in the webview.
5. **Window mode:** while locked, the window uses *simple* fullscreen
   (`set_simple_fullscreen`), plus `set_visible_on_all_workspaces` and
   `set_always_on_top`. Native fullscreen was the original choice and was
   wrong: it moves the app to its own Space, and a trackpad swipe — a Dock
   gesture the keyboard tap never sees — switches away from it, leaving the
   overlay behind. Simple fullscreen stays on the current desktop and the
   window joins every desktop, so a swipe lands on the overlay again.
   Known gap: a swipe into *another app's* native-fullscreen Space still
   shows that app (the window lacks `FullScreenAuxiliary`), though the
   keyboard stays locked there too.
6. Tap creation fails synchronously if Accessibility access hasn't been
   granted; the tap thread reports success/failure over a channel, so
   `toggle_keyboard_lock` returns a real `Err`. The frontend surfaces it with
   a button to `open_privacy_settings("accessibility")`.
7. Each swallowed key press emits `cleanMode://key` with the key's name
   (`"KeyA"`, `"Space"`, …) so `CleanModeOverlay`'s keyboard-map visual can
   light the physical key up — the DOM never sees these keystrokes.
8. If the MacClean process dies while locked, macOS tears the event tap down
   with it (it's owned by the process), so a crash can't leave the system
   keyboard-locked.
9. `lib/stores/cleanMode.svelte.ts` mirrors `active`/`pending`/`error` state
   for the UI; `exit()` only hides the overlay after
   `toggle_keyboard_lock(false)` succeeds, so a failed unlock never leaves the
   user without their one way out (the overlay's mouse-only exit button).

## IPC contract

`src/lib/types/ipc.ts` is a hand‑maintained mirror of
`macclean-core/src/model.rs`. Enums serialise `camelCase`
(`"safe"`, `"fullMac"`, `"permissionDenied"`); struct fields serialise
`camelCase`. `Category` values keep the exact legacy strings
(`"System cache"`, `"Package manager cache"`, …).

## State that lives in the browser

Only per‑viewer conveniences: `localStorage["macclean.settings.v1"]` holds the
last‑used mode, scope and extra roots. Everything authoritative is Rust‑owned.
