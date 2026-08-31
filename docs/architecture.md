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
│               reveal_in_finder · open_privacy_settings               │
│  state.rs     AppState { sessions: Mutex<SessionStore>,              │
│                          scans: Mutex<HashMap<id, ScanHandle>> }     │
│  events.rs    scan://started|candidates|progress|error|completed     │
│               cleanup://progress|completed                           │
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

## IPC contract

`src/lib/types/ipc.ts` is a hand‑maintained mirror of
`macclean-core/src/model.rs`. Enums serialise `camelCase`
(`"safe"`, `"fullMac"`, `"permissionDenied"`); struct fields serialise
`camelCase`. `Category` values keep the exact legacy strings
(`"System cache"`, `"Package manager cache"`, …).

## State that lives in the browser

Only per‑viewer conveniences: `localStorage["macclean.settings.v1"]` holds the
last‑used mode, scope and extra roots. Everything authoritative is Rust‑owned.
