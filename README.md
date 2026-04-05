# MacClean

MacClean is a lightweight local web app for reclaiming disk space on macOS developer machines.
It scans `~/projects` for removable build artifacts and caches, then lets you delete selected items from a browser UI.

## What it cleans

- Dependency folders like `node_modules`
- Build outputs like `build`, `dist`, `target`, `out` (aggressive mode)
- Language and tool caches like `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.gradle`, `.cache`
- macOS metadata files like `.DS_Store`

## Prerequisites (Mac)

- macOS
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) installed

Install `uv` on macOS:

- With Homebrew: `brew install uv`
- Or with the official installer: `curl -LsSf https://astral.sh/uv/install.sh | sh`

## Run on Mac

1. Clone the repository:
   - `git clone <your-repo-url>`
   - `cd macclean`

2. Ensure the scan root exists:
   - `mkdir -p ~/projects`

3. Start the app:
   - `uv run python main.py`

4. Open in browser:
   - `http://localhost:8080`

## Quick demo data (optional)

If your `~/projects` directory does not yet contain build artifacts, create sample folders:

- `mkdir -p ~/projects/sample/node_modules`
- `mkdir -p ~/projects/sample/__pycache__`
- `mkdir -p ~/projects/sample/build`
- `touch ~/projects/sample/.DS_Store`

Run a scan again in the UI and you should see cleanup candidates.

## How to use

1. Choose a mode:
   - **Safe**: conservative targets (recommended for regular use)
   - **Aggressive**: includes additional build artifacts and compiled files
2. Click **Start Scan**
3. Review items grouped by project
4. Optionally filter/search/sort and adjust checkboxes
5. Click **Delete Selected** and confirm

## Notes

- The app only deletes paths inside `~/projects`.
- It is a local tool; no cloud service is required.
- If the browser does not auto-open, manually visit `http://localhost:8080`.
