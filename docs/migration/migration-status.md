# MacClean Migration — Status

States: **Discovered** → **Designed** → **Implemented** → **Tested** → **Verified**
(*Verified* = works in the built native app).

Updated: 2026-08-31

## Legend

- ✅ done
- 🟡 in progress
- ⬜ not started

## Feature status

| Feature (see `feature-inventory.md`) | Discovered | Designed | Implemented | Tested | Verified |
|-------------------------------------|:----------:|:--------:|:-----------:|:------:|:--------:|
| Native window / no Python runtime (1.1–1.2) | ✅ | ✅ | ✅ | ✅ | ✅ |
| System info command (`get_system_info`, 1.4) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rule catalogue command (`get_rules`, 1.3) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scan modes: Safe / Aggressive (§2) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scan scopes: Projects / Home / Full Mac (§3) | ✅ | ✅ | ✅ | ✅ | ✅ |
| `MACCLEAN_EXTRA_SCAN_ROOTS` + `extra_roots` (§3) | ✅ | ✅ | ✅ | ✅ | ✅ |
| User-home discovery (§3) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Recursive pattern rules ×21 (§4.1) | ✅ | ✅ | ✅ | ✅ | ✅ |
| User exact rules ×14 (§4.2) | ✅ | ✅ | ✅ | ✅ | ✅ |
| System exact rules ×6 (§4.3) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Exact-tree reclassification (§4.4) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Excluded directory names (§4.5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| `path_group` grouping (§4.6) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scanner: parallel, cancellable, incremental (§5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scanner: native recursive sizing (§5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scanner: progress events @250 dirs (§5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scanner: dedupe by canonical path (§5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scanner: per-error isolation, no abort (§5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scan-session model: TTL 3600 / limit 24 (§5) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Deletion: session-scoped, re-validated (§6, §10) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Deletion: defensive (symlink/missing/perm) (§6) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Deletion: detailed per-item outcomes (§6) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Protected-path policy (§7, §11) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Path normalisation / traversal / symlink / case (§7) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Permissions: Full Disk Access probe + UI (§12) | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPC: strongly-typed Serde contract (§9) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: dashboard / idle state (§7) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: scanning view (progress/current/stop) (§7) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: results (virtualised list, groups) (§7, §22) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: selection / select-all / clear (§8) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: filter / search / sort (§8) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: destructive-action confirmation (§7) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: cleanup summary (Deleted/Skipped/Failed/…) (§13) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: settings view (§6) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: permissions view (§12) | ✅ | ✅ | ✅ | ✅ | ✅ |
| UI: empty / loading / error states (§7) | ✅ | ✅ | ✅ | ✅ | ✅ |
| macOS: disk usage / reveal in Finder / open (§14) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Logging & diagnostics (§27) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rust unit tests (§21) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rust integration tests (tempdir trees) (§21) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Frontend tests (Vitest) (§21) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Workflow test: scan→select→delete→verify (§21) | ✅ | ✅ | ✅ | ✅ | ✅ |
| CI workflow (`ci.yml`) (§17) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Release workflow + semver automation (`release.yml`) (§16–17) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Release artifacts: `.dmg` + `.app.zip` + `SHA256SUMS` (§18) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Code-signing / notarisation hooks (opt-in, off) (§19) | ✅ | ✅ | ✅ | n/a | n/a |
| Updater scaffolding (opt-in, off) (§20) | ✅ | ✅ | ✅ | n/a | n/a |
| README rewrite + docs (§24) | ✅ | ✅ | ✅ | n/a | ✅ |
| Remove Python from `main` (§23) | ✅ | ✅ | ✅ | n/a | ✅ |

## Notes

- **CI green on GitHub Actions** (`main`): `Frontend (check · lint · test · build)`,
  `Rust (fmt · clippy · test)` — full-workspace `cargo fmt --check` +
  `cargo clippy --workspace --all-targets -D warnings` + `cargo test --workspace` —
  `Tauri build validation`, and `Dependency audit`.
- **Release green on GitHub Actions**: `release.yml` on the first push to `main`
  determined `v1.0.0` (no prior tag ⇒ first native release), built the universal
  bundle, ran all tests, tagged `v1.0.0`, and published the GitHub Release with
  `MacClean_1.0.0_universal.dmg`, `MacClean_1.0.0_universal.app.zip` and
  `SHA256SUMS.txt` →
  <https://github.com/bkrajendra/macclean/releases/tag/v1.0.0>
- **Local verification**: 47 Rust tests + 38 Vitest tests green; `svelte-check`
  and `prettier` clean; a local `tauri build` produced `MacClean.app` + a `.dmg`.
- Signing / notarisation and the Tauri updater are intentionally inert until
  valid Apple credentials / an updater signing key are added as GitHub Secrets
  **and** the repo variables `ENABLE_APPLE_SIGNING` / `ENABLE_TAURI_UPDATER` are
  set to `true` — the workflow steps activate automatically then.
