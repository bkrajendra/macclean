# Contributing to MacClean

## Setup

```bash
npm ci                       # frontend deps
rustup target add aarch64-apple-darwin
npm run tauri dev            # run the app with hot reload
```

## Before you push

Everything below runs in CI and must pass:

```bash
# frontend
npm run check                # svelte-check
npx prettier --check .
npm run test                 # Vitest

# rust
cd src-tauri
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`npm run format` fixes formatting; `cargo fmt` fixes Rust.

## Where code goes

| Concern                                                        | Location                          | Notes                                                                        |
| -------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------------------------- |
| Anything that touches the filesystem, safety, or cleanup rules | `src-tauri/crates/macclean-core/` | pure Rust, **must** have unit tests; never touch a real system dir in a test |
| IPC commands, event streaming, app state                       | `src-tauri/src/`                  | thin glue only                                                               |
| Presentation, interaction                                      | `src/lib/`                        | never builds a filesystem path — only sends candidate ids                    |
| Pure UI logic (filter/sort/format)                             | `src/lib/utils/*.ts`              | plain `.ts`, unit‑tested                                                     |
| Reactive state                                                 | `src/lib/stores/*.svelte.ts`      | Svelte 5 runes                                                               |

Keep the IPC contract in sync: `macclean-core/src/model.rs` ↔
`src/lib/types/ipc.ts` ↔ `src-tauri/src/events.rs` ↔ `src/lib/api/events.ts`.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/) — the release
pipeline derives the next version from them:

- `feat: …` → minor bump
- `fix: …` / `perf: …` → patch bump
- `feat!: …` or a `BREAKING CHANGE:` footer → major bump
- `chore:` / `docs:` / `test:` / `ci:` / `refactor:` → patch bump, no changelog entry

## Safety

MacClean deletes files. Any change to `safety.rs`, `session.rs` or `deleter.rs`
must keep [`docs/security/deletion-safety.md`](docs/security/deletion-safety.md)
accurate and add a test for the new behaviour. When in doubt, refuse the
deletion.

## Pull requests

Open against `main`. CI must be green. New user‑visible behaviour: update the
relevant `docs/` file and, if it changes the migration surface,
`docs/migration/feature-inventory.md`.
