# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

MacClean is a zero-dependency Python 3.12 web app (stdlib only) that scans `~/projects` for cleanable build artifacts and lets users delete them via a browser UI on `localhost:8080`.

### Running the app

```bash
uv run python main.py
```

The server starts on port 8080. The app expects `~/projects` to exist — create it with sample subdirectories if testing scan functionality (e.g. `mkdir -p ~/projects/sample/node_modules`).

### Key caveats

- **No external dependencies**: `pyproject.toml` has `dependencies = []`. The only tooling needed is `uv` and Python 3.12+.
- **No test suite**: There are no automated tests in this repository.
- **No linter config**: No ruff, flake8, mypy, or other linter configuration exists.
- **Scan target**: The app scans `~/projects` (hardcoded in `main.py` as `SEARCH_ROOT`). This directory must exist for the scan to find anything.
- **`webbrowser.open`**: `main.py` calls `webbrowser.open` on startup. In headless/cloud environments this may produce a harmless error; the server still starts fine.
