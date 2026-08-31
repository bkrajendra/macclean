# MacClean Complete Migration: Python → Svelte 5 + Tauri 2 + Rust

You are working on the GitHub repository:

`https://github.com/bkrajendra/macclean`

This repository currently contains a Python-based macOS cleanup application. Your task is to inspect the existing application completely and migrate it into a production-quality native macOS desktop application using:

* Svelte 5
* TypeScript
* Vite
* Tauri 2
* Rust
* Tailwind CSS
* shadcn-style Svelte components / Melt UI or an equivalent accessible component system
* Lucide icons or equivalent
* GitHub Actions

The result must be a self-contained macOS desktop application distributed as a native application bundle and release artifact, with no Python runtime dependency.

---

## 1. Critical repository rule

Before making any functional changes:

1. Inspect the entire existing repository.
2. Understand the current Python implementation, UI, tests, documentation, and existing design specifications.
3. Identify every feature currently implemented.
4. Identify every user-visible behavior.
5. Identify every scan rule.
6. Identify every deletion/safety restriction.
7. Identify existing edge-case handling.
8. Identify existing tests and convert their intent into the new test suite.
9. Preserve all important existing functionality unless there is a strong technical reason to change it.
10. Do not remove an existing feature merely because the current UI does not expose it clearly.

The current Python implementation is the source of truth for existing behavior.

Do not begin by redesigning the feature set from assumptions.

Create a migration inventory before implementing the new application.

---

# 2. Git repository strategy

The current repository has `main` as the existing branch.

Before replacing the implementation:

1. Create a snapshot branch from the current `main`.
2. Name the snapshot branch:

`legacy-python`

3. The snapshot must preserve the current Python application exactly as it exists before migration.
4. Do not modify the legacy snapshot.
5. All new migration work must ultimately go into `main`.
6. Do not create a long-lived migration branch as the final source of truth.
7. `main` becomes the new Svelte/Tauri/Rust application.
8. Preserve Git history wherever practical rather than deleting the repository history.

The intended end state is:

```text
legacy-python
    ↓
complete snapshot of old Python application

main
    ↓
new Svelte 5 + Tauri 2 + Rust application
```

Do not destroy or rewrite the old implementation until the snapshot branch exists remotely.

---

# 3. Mandatory initial reconnaissance

Perform a complete repository audit before migration.

Inspect:

```text
main.py
ui/
tests/
README.md
pyproject.toml
uv.lock
MacClean.spec
AGENTS.md
docs/
docs/superpowers/
```

Also inspect Git history where useful to understand why functionality exists.

Create a temporary internal feature inventory containing:

```text
Feature
Current implementation
Current UI
Inputs
Outputs
Filesystem locations
Safety restrictions
Error handling
Tests
Migration target
Priority
```

Do not leave this merely as analysis in your context. Create a repository document:

`docs/migration/feature-inventory.md`

This document must describe all discovered functionality.

Also create:

`docs/migration/migration-status.md`

Track migration status by feature:

```text
Discovered
Designed
Implemented
Tested
Verified
```

Do not mark functionality as complete until it works in the new application.

---

# 4. Existing functionality must be preserved

The current application is a macOS cleanup tool.

At minimum, thoroughly inspect and preserve functionality covering:

## Cleanup modes

* Safe
* Aggressive

## Scan scopes

* Projects
* User Home
* Full Mac

## Recursive cleanup rules

Inspect the current implementation and preserve the exact behavior for existing targets such as:

* node_modules
* target
* **pycache**
* .pytest_cache
* .mypy_cache
* .ruff_cache
* .next
* .nuxt
* .svelte-kit
* .parcel-cache
* .angular
* .cache
* .gradle
* .DS_Store
* build
* dist
* out
* coverage
* .tox
* .terraform
* *.pyc

Do not assume this list is exhaustive. Derive the actual list from the source code.

## Exact cache locations

Inspect and preserve every existing exact-path rule including locations under:

* `~/Library/Caches`
* `~/Library/Logs`
* Xcode DerivedData
* Trash
* npm cache
* pnpm cache
* Yarn cache
* pip cache
* Maven cache
* system caches
* system logs
* Homebrew caches
* `/private/var/folders`
* other paths implemented by the Python application

Do not rely only on README documentation. Verify the actual source implementation.

## Safety behavior

Preserve and improve:

* protected root paths
* path traversal protection
* symlink handling
* scan-session validation
* deletion only of discovered items
* deletion only for current scan results
* permission-denied handling
* nonexistent path handling
* race conditions between scan and delete
* duplicate candidates
* inaccessible directories
* filesystem errors
* cancellation handling

Any existing safety rule must not regress.

---

# 5. Native architecture

Do not port the Python server architecture directly.

The new application must be a real Tauri desktop application.

Use:

```text
Svelte 5
    ↓
Tauri IPC
    ↓
Rust application layer
    ↓
Rust scanner / safety engine
    ↓
macOS filesystem / system APIs
```

There must be no localhost HTTP server required for normal operation.

There must be no browser window launched separately.

There must be no Python runtime dependency.

There must be no requirement to install:

* Python
* uv
* pip
* Node.js
* Rust

for the end user.

The released application must be self-contained.

---

# 6. Svelte frontend architecture

Use Svelte 5 with TypeScript.

Use runes where appropriate:

```text
$state
$derived
$effect
```

Avoid unnecessarily mixing legacy Svelte patterns with the new architecture.

Suggested structure:

```text
src/
├── lib/
│   ├── components/
│   ├── ui/
│   ├── stores/
│   ├── api/
│   ├── types/
│   ├── utils/
│   └── constants/
├── routes/
├── features/
│   ├── dashboard/
│   ├── scan/
│   ├── results/
│   ├── cleanup/
│   ├── settings/
│   └── permissions/
└── app.html
```

Organize by feature rather than creating a giant component tree.

Keep the frontend free from filesystem implementation details.

---

# 7. UI requirements

The application should feel like a modern premium macOS utility.

Do not simply reproduce the old HTML interface.

Create a clean native-feeling design using:

* Svelte 5
* Tailwind
* accessible component primitives
* subtle gradients
* restrained shadows
* modern typography
* macOS-friendly spacing
* polished transitions
* clear information hierarchy
* excellent empty states
* clear progress states
* meaningful loading states
* clear error states

Avoid:

* generic admin dashboard appearance
* excessive cards
* excessive borders
* visual clutter
* oversized controls
* unnecessary animations
* web-app-looking navigation

The application should visually resemble a modern Mac utility rather than a browser application.

The main experience should focus on:

```text
MacClean

[ Scan ]

Potentially reclaimable space
XX.X GB

Items found
XXXX

Categories
...

[ Start Scan ]
```

During scanning:

```text
Scanning…

Current location
~/Library/...

Progress
██████████████████░░░░

Items found
XXXX

Space found
XX.X GB

[ Stop Scan ]
```

After scanning:

```text
Scan complete

XX.X GB reclaimable

System Cache       4.8 GB
Developer          3.2 GB
Dependencies       2.1 GB
Logs               800 MB
Other              500 MB

[ Review Results ]
[ Clean Selected ]
```

Results should support:

* selection
* select all
* deselect all
* category filtering
* search
* sort
* path display
* size display
* item count
* expandable groups where useful
* clear destructive-action confirmation

---

# 8. Scanner design

The Rust scanner must be implemented as a real native filesystem scanner.

Do not invoke shell commands unnecessarily.

Prefer Rust filesystem APIs.

Use parallelism carefully for large directory trees where beneficial.

The scanner must:

* avoid blocking the UI thread
* support cancellation
* report progress
* report discovered candidates incrementally
* report errors without aborting the entire scan
* avoid following dangerous symlinks
* prevent recursive traversal outside allowed roots
* normalize paths
* canonicalize where appropriate
* de-duplicate results
* track total bytes
* track candidate counts
* classify results by category

Example conceptual API:

```text
start_scan(options)
cancel_scan(scan_id)
get_scan_status(scan_id)
get_scan_results(scan_id)
delete_selected(scan_id, items)
```

However, do not blindly use these exact APIs. Design the IPC layer based on the actual application requirements.

---

# 9. IPC architecture

Define a strongly typed contract between Svelte and Rust.

Do not pass arbitrary untyped JSON when a strongly typed structure is practical.

Create shared conceptual models such as:

```text
ScanMode
ScanScope
ScanOptions
ScanProgress
ScanCandidate
ScanCategory
ScanSummary
DeleteRequest
DeleteResult
PermissionStatus
```

Serialize using Serde.

The frontend must never construct arbitrary filesystem operations.

The Rust backend validates every path and operation independently.

---

# 10. Scan session security model

Preserve the existing concept that deletion must only be allowed for items discovered during the current scan.

Strengthen the model.

Every scan should have an internal identifier.

The application should associate discovered candidates with the scan session.

Deletion should verify:

1. The scan exists.
2. The candidate was discovered during that scan.
3. The path is still inside the permitted root.
4. The path is still considered safe.
5. The path has not changed in a way that invalidates the result.
6. The requested operation is allowed.
7. The file or directory still exists.
8. The application is not deleting a protected path.

Never trust the frontend to enforce these rules.

Rust must enforce them.

---

# 11. Protected paths

Build a centralized safety policy in Rust.

Never allow deletion of critical paths such as:

```text
/
 /Users
 /System
 /Applications
 /Library
 /Volumes
 /private
 /bin
 /sbin
 /usr
 /var
```

But do not blindly copy this list.

Review the existing application logic and design a robust macOS-specific protected-path policy.

Protection must consider:

* symlink resolution
* normalized paths
* relative path tricks
* case sensitivity
* mount boundaries
* aliases
* special directories

Document the policy in:

`docs/security/deletion-safety.md`

---

# 12. Permissions

The application must handle modern macOS permissions correctly.

Investigate the permissions required for:

* user home directories
* Library directories
* system cache locations
* Full Disk Access
* protected application containers
* other TCC-protected locations

Do not assume that running the entire application as root is acceptable.

Do not make `sudo` the default architecture.

Prefer:

```text
normal user application
        ↓
request required access
        ↓
perform authorized operation
```

When access is denied:

* identify the affected category/path
* continue scanning where possible
* show the user what could not be accessed
* explain how to grant access
* never silently claim that a protected path was cleaned

Create a dedicated permissions UI.

---

# 13. Deletion implementation

Deletion must be defensive.

Handle:

* files
* directories
* symlinks
* missing files
* permission errors
* partially deleted trees
* concurrent changes
* files disappearing between scan and delete

Provide detailed results:

```text
Deleted
Skipped
Failed
Permission denied
Already missing
```

The UI should show the user a reliable cleanup summary.

---

# 14. macOS integration

Investigate and use native macOS APIs where appropriate.

Potential areas include:

* system information
* disk usage
* application discovery
* Trash
* file metadata
* permission-related workflows
* application opening
* native dialogs
* system notifications where appropriate

Do not introduce unnecessary shell commands.

When a native macOS API is the correct tool, use it.

---

# 15. Single-binary / packaging requirement

The final application must be distributable without Python.

Build a standard macOS Tauri application bundle:

```text
MacClean.app
```

and release artifacts suitable for distribution.

Do not require the user to install:

```text
Python
uv
Node
Rust
Homebrew
```

The runtime must be self-contained.

Support Apple Silicon first:

```text
aarch64-apple-darwin
```

Also evaluate whether Intel support should be retained:

```text
x86_64-apple-darwin
```

Prefer universal binaries if the additional build complexity is reasonable.

Document the supported architecture(s).

---

# 16. Versioning and release model

Implement automatic versioning through GitHub Actions.

Use semantic versioning:

```text
MAJOR.MINOR.PATCH
```

The release workflow should automatically determine and increment the release version when changes are pushed to `main`.

Do not generate uncontrolled versions such as:

```text
v1
v2
v3
```

Use a proper semantic release strategy.

Preferred behavior:

```text
current latest release
        ↓
new push to main
        ↓
determine next semantic version
        ↓
update application version
        ↓
build
        ↓
test
        ↓
create git tag
        ↓
create GitHub Release
        ↓
upload MacClean artifacts
```

Tags must use:

```text
vMAJOR.MINOR.PATCH
```

Example:

```text
v1.0.0
v1.0.1
v1.1.0
```

The first migration release should be clearly identifiable as the first native release.

Do not create a release if the build or tests fail.

---

# 17. GitHub Actions

Create production-ready workflows under:

```text
.github/workflows/
```

At minimum provide:

```text
ci.yml
release.yml
```

## CI

Run on pushes and pull requests.

Perform:

* Svelte/TypeScript type checking
* frontend linting
* frontend tests
* Rust formatting validation
* Rust clippy
* Rust unit tests
* Tauri build validation
* security/dependency checks where practical

## Release

Run on pushes to `main`.

The workflow must:

1. Determine the next semantic version.
2. Update the application version consistently.
3. Build the application.
4. Run tests.
5. Package release artifacts.
6. Create the Git tag.
7. Push the tag.
8. Create the GitHub Release.
9. Upload release artifacts.

Do not push a tag before a successful build.

Do not create a GitHub Release from an unsuccessful build.

Use least-privilege GitHub Actions permissions.

Pin GitHub Actions to appropriate stable versions.

---

# 18. Release artifacts

The release should contain useful macOS artifacts.

At minimum investigate producing:

```text
.dmg
.app.zip
```

Optionally provide:

```text
.pkg
```

if there is a good reason.

The release notes should contain:

* version
* release date
* supported architectures
* installation instructions
* notable changes
* known limitations
* permission requirements

---

# 19. Code signing and notarization

Design the GitHub Actions pipeline so Apple code signing and notarization can be added cleanly.

Do not hard-code secrets.

Use GitHub Secrets / environment variables for credentials.

Prepare the workflow for:

* Apple Developer certificate
* App signing identity
* App Store Connect API key or appropriate notarization credentials
* notarization
* stapling

If credentials are not available during migration, keep signing disabled or clearly configurable, but make the workflow structure ready for production signing.

Never commit signing certificates or credentials.

---

# 20. Automatic update support

Evaluate Tauri's updater capabilities.

Structure the project so an updater can be enabled later without changing the application architecture.

Do not block the initial release if update signing infrastructure has not yet been configured.

---

# 21. Testing

The migration must not rely only on manual UI testing.

Create:

## Rust unit tests

Test:

* path normalization
* protected path detection
* scope validation
* rule matching
* candidate classification
* duplicate handling
* scan cancellation
* deletion validation
* session validation

## Rust integration tests

Test realistic temporary directory structures.

Do not use real system directories in destructive tests.

## Frontend tests

Test:

* scan state
* progress state
* result rendering
* selection behavior
* filters
* sorting
* error states
* deletion confirmation

## End-to-end testing

Where practical, test the Tauri application workflow:

```text
launch
→ scan
→ display candidates
→ select
→ delete
→ verify result
```

Tests must never delete real user data.

---

# 22. Performance requirements

The new native scanner should be at least competitive with the existing Python implementation and preferably substantially faster for large directory trees.

Avoid:

* loading millions of filesystem entries into frontend memory
* sending one IPC event per file if batching is better
* repeatedly calculating directory sizes unnecessarily
* blocking the main Tauri thread
* excessive UI rerenders

Use batching for large result sets.

Consider:

```text
Rust scanner
    ↓
batch results
    ↓
IPC
    ↓
Svelte store
    ↓
virtualized result list
```

Use a virtualized list if result counts can become large.

---

# 23. Existing Python code migration

Do not mechanically translate Python to Rust.

For each Python feature:

1. Understand its behavior.
2. Determine whether it belongs in:

   * Rust core
   * macOS integration
   * Svelte UI
   * configuration
3. Redesign the implementation idiomatically.
4. Preserve observable behavior.
5. Add tests.
6. Verify against the Python behavior.

The Python code should eventually become unnecessary.

The final `main` branch should not require the old Python runtime.

Once migration is complete and validated, remove obsolete Python application files from `main`.

Keep them available through:

```text
legacy-python
```

---

# 24. Documentation

Rewrite the main README for the native application.

Include:

* overview
* features
* screenshots/placeholders
* supported macOS versions
* installation
* build from source
* developer setup
* architecture
* permission requirements
* safety model
* release process
* contribution instructions

Do not leave instructions saying to run:

```text
uv run python main.py
```

in the new `main` branch.

Move historical Python instructions to documentation associated with the legacy snapshot if necessary.

---

# 25. Project configuration

Create a clean Tauri/Svelte project structure.

Expected major files should include something similar to:

```text
package.json
vite.config.ts
svelte.config.js
tsconfig.json

src/
src-tauri/
    Cargo.toml
    tauri.conf.json
    src/

.github/
    workflows/
        ci.yml
        release.yml
```

Do not blindly copy this structure if a better idiomatic Tauri/Svelte structure is justified.

---

# 26. Security requirements

Treat this as a security-sensitive filesystem application.

Never trust:

* frontend paths
* frontend deletion requests
* serialized scan results
* user-provided paths
* environment variables without validation

Rust must enforce the security boundary.

Audit all filesystem operations.

Avoid shell execution unless absolutely necessary.

When shell execution is unavoidable:

* use fixed executable paths or validated executable lookup
* avoid shell interpolation
* pass arguments separately
* never construct shell command strings from user input

---

# 27. Logging and diagnostics

Provide structured internal logging.

Do not expose sensitive filesystem information unnecessarily.

Use Tauri/Rust logging appropriate for production.

Provide a diagnostics path that can help investigate:

* permission failures
* scan failures
* deletion failures
* application startup problems

Do not log sensitive file contents.

---

# 28. Migration completion criteria

The migration is complete only when all of the following are true:

* The repository has a `legacy-python` snapshot branch.
* `main` contains the new Tauri/Svelte/Rust application.
* The Python runtime is not required.
* Existing functional behavior has been inventoried.
* Existing features have been migrated.
* Existing safety semantics have been preserved or strengthened.
* Rust owns filesystem and deletion operations.
* Svelte owns presentation.
* Tauri provides the desktop bridge.
* The application launches as a native macOS app.
* The app can scan.
* The app can display scan results.
* The app can filter/search/sort results.
* The app can select results.
* The app can safely delete selected results.
* Permission errors are handled correctly.
* Scan cancellation works.
* Large scans do not freeze the UI.
* Automated tests pass.
* CI passes.
* Release workflow works.
* Versioning is automated.
* Git tags are created automatically.
* GitHub Releases are created automatically.
* Release artifacts are attached automatically.
* README is updated.
* Migration documentation is complete.

---

# 29. Important agent behavior

You are authorized to make the migration rather than merely proposing it.

Do not stop after analysis.

Do not provide a toy proof of concept.

Do not create a partial UI and call the migration complete.

Do not silently omit features because the implementation is inconvenient.

When you discover functionality that is not immediately obvious, add it to the migration inventory and migrate it.

When you encounter ambiguity, inspect the implementation, history, tests, and documentation before making a decision.

Prefer the safest technically sound implementation.

Do not ask for confirmation for normal engineering decisions.

Only stop and report a blocker when it genuinely requires an external credential, unavailable service, or irreversible action that cannot be safely completed.

---

# 30. Final implementation report

At the end, provide a concise report containing:

```text
Repository
Snapshot branch
New architecture
Migrated features
New features
Safety changes
macOS permissions model
Test coverage
CI workflow
Release workflow
Versioning strategy
Supported architectures
Known limitations
```

Also provide the final repository structure.

The final result must be a serious production-quality migration of the existing MacClean application, not a demonstration project.
