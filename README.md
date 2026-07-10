# MacClean

MacClean is a local macOS cleanup web app that scans safe-to-remove caches and build artifacts and lets you delete selected items from a browser UI.

CAUTION: Ensure to validate before selecting artifacts to delete, most caches are harmeless to delete, but few functionalities might break which depends on some artifacts. You should be 100% aware of what you are deleting.

## What it cleans

### Recursive pattern cleanup (safe + aggressive)

- `node_modules`
- `target` (Maven/Rust target folders)
- `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`
- `.next`, `.nuxt`, `.svelte-kit`, `.parcel-cache`, `.angular`
- `.cache`, `.gradle`
- `.DS_Store`

Aggressive mode also includes:

- `build`, `dist`, `out`, `coverage`, `.tox`, `.terraform`
- `*.pyc`

### Exact cache locations (safe + aggressive)

User-level:

- `~/Library/Caches/*`
- `~/Library/Logs/*`
- `~/Library/Developer/Xcode/DerivedData`
- `~/.Trash/*`
- `~/.npm/_cacache`
- `~/.pnpm-store`
- `~/.yarn/cache`
- `~/.cache/pip`
- `~/.m2/repository`

System-level (Full Mac scope):

- `/Library/Caches/*`
- `/Library/Logs/*`
- `/opt/homebrew/var/cache/*`
- `/usr/local/var/cache/*`

Browser cache coverage comes from user app caches under `~/Library/Caches/*` (e.g., Chrome/Firefox/Safari related cache folders).

## Prerequisites (Mac)

- macOS
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) installed

Install `uv`:

- Homebrew: `brew install uv`
- Official installer: `curl -LsSf https://astral.sh/uv/install.sh | sh`

## Run on Mac

1. Clone and enter the project:
   - `git clone https://github.com/bkrajendra/macclean.git`
   - `cd macclean`
2. Start the app:
   - `uv run python main.py`
3. Open:
   - `http://localhost:8080`

Optional flags:

- `uv run python main.py --host 0.0.0.0 --port 8080`
- `uv run python main.py --no-browser`

## Run with administrator privileges (recommended for Full Mac scans)

For deeper system coverage, start with `sudo`:

- `sudo -E uv run python main.py --host localhost --port 8080`

Notes:

- Full Mac scan can still run without admin, but protected folders may be skipped.
- The UI shows permission-denied counts and prints a suggested elevated launch command.

## How to use

1. Choose **Mode**:
   - **Safe**: conservative cache cleanup.
   - **Aggressive**: includes extra build/compiled artifacts.
2. Choose **Scope**:
   - **Projects**: focus on `~/projects`.
   - **User home**: scan your home directory + user cache locations.
   - **Full Mac**: scan user homes + known system cache locations.
3. Click **Start scan**. While scanning, all controls are disabled except **Stop scan**, which keeps everything found so far selectable and deletable.
4. Review candidates in the system-path tabs, filter/search/sort, and adjust selections.
5. Click **Delete selected** and confirm. A summary shows how much space was reclaimed.

## Safety model

- Deletes are only allowed for items discovered in the most recent scan session.
- Core protected paths are never deleted (e.g. `/`, `/Users`, `/System`, `/Applications`, `/Library`, home root itself).
- If scan session expires, deletion is blocked until you run a fresh scan.
