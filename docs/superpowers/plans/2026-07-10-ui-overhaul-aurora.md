# MacClean UI Overhaul (Aurora) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the MacClean web UI as a vibrant, light, tabbed "system paths" experience with an animated cancellable scan and a confetti celebration after cleanup, plus the small backend protocol changes that support it.

**Architecture:** The stdlib Python server (`main.py`) gains finer-grained result grouping, a scan ID issued at scan start, incremental scan-session persistence, and periodic progress events over the existing SSE stream. `ui/index.html` is rewritten as a fully self-contained file (inline CSS + JS, no CDN) implementing tabs, the scan panel with Stop, a delete-confirmation modal, and a celebration overlay.

**Tech Stack:** Python 3.12 stdlib only; vanilla HTML/CSS/JS in one file; stdlib `unittest` for backend tests.

**Spec:** `docs/superpowers/specs/2026-07-10-ui-overhaul-design.md`

## Global Constraints

- Python 3.12, stdlib only — `pyproject.toml` `dependencies = []` must stay empty.
- `ui/index.html` must load zero network resources (no CDN, no webfonts) — system font stacks only (`ui-rounded`, `-apple-system`, `ui-monospace`).
- Light theme only: background `#fafaff`; no dark backgrounds anywhere. Text ink is deep indigo `#312e5a`, never pure black.
- All user-facing "project" wording becomes "system path(s)"; scope option labels ("Projects", "User home", "Full Mac") are unchanged.
- Copy is sentence case, active voice ("Start scan", "Stop scan", "Delete 12 items").
- `prefers-reduced-motion: reduce` disables aurora drift, radar animation, confetti, and count-up (value appears immediately).
- Commit after every task on branch `ui-overhaul-aurora`. Do NOT stage the user's unrelated pending changes (`pyproject.toml`, `uv.lock`, `MacClean.spec`).

## Design tokens (used by Tasks 4–6)

```css
:root {
  --bg: #fafaff;
  --ink: #312e5a;
  --ink-soft: #6d69a0;
  --card: rgba(255, 255, 255, 0.78);
  --line: rgba(99, 102, 241, 0.16);
  --indigo: #6366f1;
  --violet: #8b5cf6;
  --pink: #ec4899;
  --cyan: #22d3ee;
  --mint: #10b981;
  --coral: #f43f5e;
  --amber: #d97706;
  --grad: linear-gradient(135deg, var(--indigo), var(--violet) 52%, var(--pink));
  --shadow: 0 8px 30px rgba(99, 102, 241, 0.12);
  --radius: 20px;
  --font-display: ui-rounded, "SF Pro Rounded", -apple-system, "Segoe UI", sans-serif;
  --font-body: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
```

Category chips: deterministic hash of the category name into this 8-entry palette (background, text):

```js
const CHIP_COLORS = [
  ["#e0e7ff", "#4338ca"], ["#fce7f3", "#be185d"], ["#cffafe", "#0e7490"],
  ["#d1fae5", "#047857"], ["#fef3c7", "#b45309"], ["#ede9fe", "#6d28d9"],
  ["#ffe4e6", "#be123c"], ["#dcfce7", "#15803d"],
];
function chipStyle(category) {
  let hash = 0;
  for (const ch of category) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  const [bg, fg] = CHIP_COLORS[hash % CHIP_COLORS.length];
  return `background:${bg};color:${fg}`;
}
```

---

### Task 1: Remove shadowed and dead backend code

**Files:**
- Modify: `main.py` (first `TARGET_RULES` block ~lines 52–200, first `rules_for_mode` ~lines 381–389, `is_safe_path` ~lines 621–627)

**Interfaces:**
- Produces: a single `TARGET_RULES` definition (the currently-effective second one, where `build`/`dist`/`out`/`target`/`coverage` are aggressive-only) and a single `rules_for_mode`. No behavior change.

- [ ] **Step 1: Capture current effective behavior**

Run:
```bash
uv run python -c "import main; r=main.rules_for_mode('safe'); print(sorted(r['dirs'])); print(sorted(main.rules_for_mode('aggressive')['dirs']))"
```
Save the output — it is the baseline.

- [ ] **Step 2: Delete the shadowed code**

In `main.py` delete, entirely:
1. The FIRST `TARGET_RULES = [...]` assignment (the one appearing before `HOME_EXACT_RULES`, containing `"label": "Maven/Rust target output"` with `"modes": {"safe", "aggressive"}` for `target`).
2. The FIRST `def rules_for_mode(mode):` (the one appearing between `normalize_scope` and `path_is_within`).
3. `def is_safe_path(path):` (references undefined `SEARCH_ROOT`; never called).

Keep the SECOND `TARGET_RULES` and SECOND `rules_for_mode` (currently after `homes_for_scope`) exactly as they are.

- [ ] **Step 3: Verify behavior unchanged**

Re-run the Step 1 command. Output must be byte-identical to the baseline. Also run `uv run python -c "import main"` — no errors.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "refactor: remove shadowed TARGET_RULES/rules_for_mode and dead is_safe_path"
```

---

### Task 2: Finer-grained path grouping

**Files:**
- Modify: `main.py` (`path_group`)
- Create: `tests/test_main.py`

**Interfaces:**
- Produces: `path_group(path: str) -> str` — for paths under `/Users/<name>` (or `/home/<name>`) returns `/Users/<name>/<first-child>` (or the home root itself when the path IS the home root); otherwise `/<top-level>`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_main.py`:

```python
import unittest

import main


class PathGroupTests(unittest.TestCase):
    def test_project_paths_group_to_home_child(self):
        self.assertEqual(
            main.path_group("/Users/alice/projects/app/node_modules"),
            "/Users/alice/projects",
        )

    def test_library_cache_groups_to_home_library(self):
        self.assertEqual(
            main.path_group("/Users/alice/Library/Caches/Google/Chrome"),
            "/Users/alice/Library",
        )

    def test_dotdir_directly_under_home_is_own_group(self):
        self.assertEqual(
            main.path_group("/Users/alice/.pnpm-store"),
            "/Users/alice/.pnpm-store",
        )

    def test_home_root_is_own_group(self):
        self.assertEqual(main.path_group("/Users/alice"), "/Users/alice")

    def test_system_paths_stay_top_level(self):
        self.assertEqual(main.path_group("/Library/Caches/foo"), "/Library")
        self.assertEqual(main.path_group("/opt/homebrew/var/cache/x"), "/opt")


if __name__ == "__main__":
    unittest.main()
```

(Use `/Users/...` fixtures only — `/home` is a magic symlink on macOS and `os.path.realpath` would rewrite it.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m unittest discover -s tests -t . -v`
Expected: `test_project_paths_group_to_home_child` and `test_dotdir_directly_under_home_is_own_group` FAIL (current code returns `/Users/alice` for both).

- [ ] **Step 3: Implement**

Replace `path_group` in `main.py`:

```python
def path_group(path):
    normalized = os.path.realpath(path)
    parts = normalized.split(os.sep)
    if len(parts) > 2 and parts[1] in {"Users", "home"}:
        home = os.sep + os.path.join(parts[1], parts[2])
        if len(parts) > 3:
            return os.path.join(home, parts[3])
        return home
    if len(parts) > 1 and parts[1]:
        return os.sep + parts[1]
    return normalized
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m unittest discover -s tests -t . -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add main.py tests/test_main.py
git commit -m "feat: group cleanup candidates one level below user homes"
```

---

### Task 3: Scan protocol — scan_id at start, incremental sessions, progress events, `group` field

**Files:**
- Modify: `main.py` (`scan_stream`)
- Modify: `tests/test_main.py`

**Interfaces:**
- Produces SSE events consumed by Task 4/5:
  - `start`: gains `"scan_id": <hex>` (kept in `done` too).
  - `item`: field `project` RENAMED to `group` (value from `path_group`).
  - NEW `progress`: `{"type": "progress", "scanned_dirs": int, "current": str}` every 250 walked directories.
  - Items found before a disconnect are deletable: the scan session is registered at scan start and paths are added as emitted.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_main.py`:

```python
import io
import json
import os
import tempfile
import types


def parse_sse(raw):
    events = []
    for block in raw.decode().split("\n\n"):
        block = block.strip()
        if block.startswith("data: "):
            events.append(json.loads(block[len("data: "):]))
    return events


class ScanStreamTests(unittest.TestCase):
    def test_scan_id_issued_at_start_and_items_use_group(self):
        with tempfile.TemporaryDirectory() as projects, \
                tempfile.TemporaryDirectory() as fake_home:
            os.makedirs(os.path.join(projects, "app", "node_modules"))
            old_projects, old_home = main.PROJECTS_ROOT, main.HOME_ROOT
            main.PROJECTS_ROOT, main.HOME_ROOT = projects, fake_home
            try:
                handler = types.SimpleNamespace(wfile=io.BytesIO())
                main.scan_stream(handler, mode="safe", scope="projects")
            finally:
                main.PROJECTS_ROOT, main.HOME_ROOT = old_projects, old_home

            events = parse_sse(handler.wfile.getvalue())
            start = events[0]
            self.assertEqual(start["type"], "start")
            self.assertTrue(start.get("scan_id"))

            items = [e for e in events if e["type"] == "item"]
            self.assertTrue(items)
            self.assertTrue(all("group" in item for item in items))
            self.assertTrue(all("project" not in item for item in items))

            session = main.SCAN_SESSIONS.get(start["scan_id"])
            self.assertIsNotNone(session)
            item_paths = {os.path.realpath(i["path"]) for i in items}
            self.assertTrue(item_paths <= session["paths"])

            done = events[-1]
            self.assertEqual(done["type"], "done")
            self.assertEqual(done["scan_id"], start["scan_id"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest discover -s tests -t . -v`
Expected: `test_scan_id_issued_at_start_and_items_use_group` FAILS (`scan_id` missing from start event / `group` missing from items).

- [ ] **Step 3: Implement in `scan_stream`**

1. After `scan_id = uuid.uuid4().hex`, register the session immediately:
   ```python
   persist_scan_session(scan_id, set(), scope)
   ```
2. In `emit_item`, after `allowed_paths.add(real)`:
   ```python
   session = SCAN_SESSIONS.get(scan_id)
   if session is not None:
       session["paths"].add(real)
   ```
3. In the `emit_item` send payload, rename `"project": path_group(path)` to `"group": path_group(path)`.
4. Add `"scan_id": scan_id` to the `start` event payload.
5. Progress events — before the roots loop add `dirs_walked = 0`; inside the walk loop, as the first statement after the `client_connected` check:
   ```python
   dirs_walked += 1
   if dirs_walked % 250 == 0:
       send({"type": "progress", "scanned_dirs": dirs_walked, "current": walk_root})
   ```
6. Leave the final `persist_scan_session(scan_id, allowed_paths, scope)` call in place (it refreshes the session even if pruned mid-scan).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m unittest discover -s tests -t . -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add main.py tests/test_main.py
git commit -m "feat: cancellable scan protocol (early scan_id, progress events, group field)"
```

---

### Task 4: Rewrite `ui/index.html` — aurora theme, tabbed system paths, terminology

**Files:**
- Modify: `ui/index.html` (full rewrite; single self-contained file)

**Interfaces:**
- Consumes: `/status` (`home_root`, `is_admin`, `admin_command`, `scope_definitions`), `/stream` events from Task 3, `/delete`.
- Produces element IDs and functions used by Tasks 5–6: `scanBtn, stopBtn, deleteBtn, mode, scope, searchInput, categoryFilter, sortBy, selectVisibleBtn, clearSelectionBtn, statusPill, detectedCount, selectedCount, detectedSize, selectedSize, tabBar, listPanel, emptyState, message, adminInfo, scanPanel, scanItems, scanSize, scanPath, confirmModal, confirmTitle, confirmBody, confirmCancel, confirmDelete, celebration, celebrateAmount, celebrateSub, celebrateClose, confettiCanvas`; functions `formatBytes, prettyPath, chipStyle, setStatus, setMessage, updateAdminInfo, closeSource, filteredItems, groupsFor, updateCategoryFilter, metrics, render, scheduleRender, setBusyState, loadStatus, startScan, stopScan, openConfirm, closeConfirm, performDelete, celebrate, dismissCelebration, selectVisible, clearSelection`.

Functional parity in this task: scan (no scan panel yet — plain disabled state), tabs, filters, selection, delete still via `window.confirm` (replaced in Task 6). Tasks 5–6 add the scan panel and modals; their placeholder containers (`scanPanel`, `confirmModal`, `celebration`) are present but `hidden`.

- [ ] **Step 1: Write the new document skeleton**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MacClean</title>
  <style>/* Task 4 Step 2 */</style>
</head>
<body>
  <main class="shell">
    <header class="card hero">
      <div class="hero-top">
        <div>
          <h1 class="logo">MacClean</h1>
          <p class="tagline">Find and clear caches, build output, and leftovers across your Mac.</p>
        </div>
        <div class="actions">
          <button id="scanBtn" class="btn btn-primary">Start scan</button>
          <button id="stopBtn" class="btn btn-stop" hidden>Stop scan</button>
          <button id="deleteBtn" class="btn btn-danger" disabled>Delete selected</button>
        </div>
      </div>
      <div class="controls">
        <label class="field"><span>Mode</span>
          <select id="mode">
            <option value="safe">Safe (recommended)</option>
            <option value="aggressive">Aggressive</option>
          </select></label>
        <label class="field"><span>Scope</span>
          <select id="scope">
            <option value="projects">Projects</option>
            <option value="home">User home</option>
            <option value="full_mac">Full Mac</option>
          </select></label>
        <label class="field"><span>Search</span>
          <input id="searchInput" type="text" placeholder="Search path or label"></label>
        <label class="field"><span>Category</span>
          <select id="categoryFilter"><option value="all">All categories</option></select></label>
        <label class="field"><span>Sort</span>
          <select id="sortBy">
            <option value="size_desc">Largest first</option>
            <option value="size_asc">Smallest first</option>
            <option value="path_asc">Path A-Z</option>
            <option value="path_desc">Path Z-A</option>
          </select></label>
      </div>
      <div class="toolbar">
        <button id="selectVisibleBtn" class="btn btn-ghost">Select visible</button>
        <button id="clearSelectionBtn" class="btn btn-ghost">Clear selection</button>
        <span id="statusPill" class="pill">Idle</span>
      </div>
      <div id="adminInfo" class="admin-note" hidden></div>
    </header>

    <section id="scanPanel" class="card scan-panel" hidden><!-- Task 5 --></section>

    <section class="stats">
      <article class="card stat"><p>Detected items</p><p id="detectedCount" class="stat-num">0</p></article>
      <article class="card stat"><p>Selected items</p><p id="selectedCount" class="stat-num">0</p></article>
      <article class="card stat"><p>Detected reclaimable</p><p id="detectedSize" class="stat-num">0 B</p></article>
      <article class="card stat"><p>Selected reclaimable</p><p id="selectedSize" class="stat-num">0 B</p></article>
    </section>

    <section class="card results">
      <div class="results-head">
        <h2>Cleanup candidates</h2>
        <p>Grouped by system path. Uncheck anything you want to keep.</p>
      </div>
      <div id="tabBar" class="tabs" role="tablist"></div>
      <div id="listPanel" class="list" role="tabpanel"></div>
      <div id="emptyState" class="empty" hidden>No scan yet. Choose a scope and start a scan.</div>
    </section>

    <p id="message" class="msg"></p>
  </main>

  <div id="confirmModal" class="overlay" hidden><!-- Task 6 --></div>
  <div id="celebration" class="overlay" hidden><!-- Task 6 --></div>

  <script>/* Task 4 Step 3 */</script>
</body>
</html>
```

- [ ] **Step 2: Write the aurora CSS**

Inside `<style>`: the `:root` token block from "Design tokens" above, then:

```css
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; background: var(--bg); color: var(--ink);
  font-family: var(--font-body); -webkit-font-smoothing: antialiased;
}
body::before {
  content: ""; position: fixed; inset: -20%; z-index: -1; pointer-events: none;
  background:
    radial-gradient(40% 35% at 15% 20%, rgba(99,102,241,.20), transparent 70%),
    radial-gradient(35% 30% at 85% 15%, rgba(236,72,153,.16), transparent 70%),
    radial-gradient(45% 40% at 70% 85%, rgba(34,211,238,.16), transparent 70%),
    radial-gradient(30% 30% at 25% 80%, rgba(139,92,246,.14), transparent 70%);
  animation: aurora-drift 24s ease-in-out infinite alternate;
}
@keyframes aurora-drift { to { transform: translate(4%, -3%) scale(1.08); } }
.shell { max-width: 72rem; margin: 0 auto; padding: 2rem 1.25rem 3rem; }
.card {
  background: var(--card); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
}
.logo {
  margin: 0; font-family: var(--font-display); font-size: 2rem; letter-spacing: -0.02em;
  background: var(--grad); -webkit-background-clip: text; background-clip: text; color: transparent;
}
.stat-num {
  margin: .25rem 0 0; font-family: var(--font-display); font-size: 1.9rem; font-weight: 700;
  background: var(--grad); -webkit-background-clip: text; background-clip: text; color: transparent;
}
.btn { border: 0; border-radius: 999px; padding: .6rem 1.2rem; font: 600 .9rem var(--font-body); cursor: pointer; transition: transform .15s, box-shadow .15s, opacity .15s; }
.btn:disabled { opacity: .45; cursor: not-allowed; }
.btn:not(:disabled):hover { transform: translateY(-1px); }
.btn-primary { background: var(--grad); color: #fff; box-shadow: 0 6px 18px rgba(139,92,246,.35); }
.btn-danger { background: linear-gradient(135deg, var(--coral), var(--pink)); color: #fff; box-shadow: 0 6px 18px rgba(244,63,94,.3); }
.btn-stop { background: linear-gradient(135deg, var(--amber), var(--coral)); color: #fff; box-shadow: 0 6px 18px rgba(217,119,6,.3); }
.btn-ghost { background: #fff; color: var(--ink); border: 1px solid var(--line); }
.tabs { display: flex; gap: .5rem; overflow-x: auto; padding: 1rem 1.25rem 0; }
.tab {
  flex: 0 0 auto; display: inline-flex; align-items: center; gap: .5rem;
  border: 1px solid var(--line); border-radius: 999px; background: #fff;
  padding: .45rem .9rem; font: 600 .82rem var(--font-body); color: var(--ink); cursor: pointer;
}
.tab .badge { font-family: var(--font-mono); font-size: .7rem; color: var(--ink-soft); }
.tab[aria-selected="true"] { background: var(--grad); border-color: transparent; color: #fff; }
.tab[aria-selected="true"] .badge { color: rgba(255,255,255,.85); }
.tab.faded { opacity: .45; }
.chip { display: inline-block; border-radius: 999px; padding: .1rem .55rem; font: 600 .7rem var(--font-body); }
.path { font-family: var(--font-mono); font-size: .72rem; color: var(--ink-soft); word-break: break-all; }
.overlay { position: fixed; inset: 0; z-index: 50; display: grid; place-items: center; background: rgba(250,250,255,.72); backdrop-filter: blur(10px); }
@media (prefers-reduced-motion: reduce) {
  body::before, .radar * { animation: none !important; }
  .btn { transition: none; }
}
```

Plus straightforward layout rules for `.hero-top` (flex, wrap, space-between), `.controls` (grid, `repeat(auto-fit, minmax(10rem, 1fr))`, gap .75rem), `.field` (label block: small uppercase `--ink-soft` caption + white input/select, 1px `--line` border, radius 12px, focus ring `2px solid var(--violet)` via `outline`), `.toolbar` (flex + gap, margin-top), `.pill` (rounded full, tinted per status class: `.pill-idle` lavender, `.pill-active` indigo tint, `.pill-ok` mint tint, `.pill-warn` amber tint), `.stats` (grid 4-up, collapsing to 2-up under 40rem), `.stat` (padding 1rem 1.25rem; first `p` small caption `--ink-soft`), `.results-head` (padding 1.25rem, `h2` in `--font-display`), `.list` (max-height 56vh, overflow auto, padding 1rem 1.25rem), item rows (`.row`: flex, gap .75rem, padding .7rem, radius 14px, hover background `rgba(99,102,241,.06)`; checkbox `accent-color: var(--violet)`), `.size-badge` (mono, 600, `--indigo`), `.admin-note` (amber tint background, small text), `.msg` (small, `--ink-soft`), `.empty` (centered padding, `--ink-soft`).

- [ ] **Step 3: Write the JS core**

State and helpers (top of `<script>`):

```js
const state = {
  items: [], selected: new Set(),
  mode: "safe", scope: "projects", sortBy: "size_desc", category: "all", query: "",
  scanning: false, deleting: false, source: null,
  scanId: "", scanRoots: [], permissionsDenied: 0,
  isAdmin: false, adminHint: "", adminCommand: "",
  homeRoot: "", activeTab: "all",
  scannedDirs: 0, currentDir: "",
};
```

`el` map of all IDs listed in Interfaces. Keep `formatBytes`, `setMessage`, `updateAdminInfo`, `closeSource`, `filteredItems`, `updateCategoryFilter`, `loadStatus` bodies from the old file, with these changes:

- `loadStatus` also stores `state.homeRoot = payload.home_root || ""`.
- `setStatus(text, tone)` sets `el.statusPill.textContent` and `className = "pill pill-" + tone` with tones `idle|active|ok|warn`.
- New:

```js
function prettyPath(p) {
  if (state.homeRoot && p === state.homeRoot) return "~";
  if (state.homeRoot && p.startsWith(state.homeRoot + "/")) return "~" + p.slice(state.homeRoot.length);
  return p;
}
function groupsFor(items) {
  const map = new Map();
  for (const item of items) {
    if (!map.has(item.group)) map.set(item.group, []);
    map.get(item.group).push(item);
  }
  return map;
}
```

Rendering — `render()` calls `metrics()`, `renderTabs()`, `renderList()`:

```js
function renderTabs() {
  const allGroups = [...groupsFor(state.items).keys()].sort();
  const visibleGroups = groupsFor(filteredItems());
  if (state.activeTab !== "all" && !allGroups.includes(state.activeTab)) state.activeTab = "all";
  el.tabBar.innerHTML = "";
  const defs = [["all", "All"], ...allGroups.map((g) => [g, prettyPath(g)])];
  for (const [key, label] of defs) {
    const items = key === "all" ? filteredItems() : (visibleGroups.get(key) || []);
    const size = items.reduce((acc, i) => acc + i.size, 0);
    const tab = document.createElement("button");
    tab.type = "button";
    tab.className = "tab" + (items.length === 0 && key !== "all" ? " faded" : "");
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(state.activeTab === key));
    tab.innerHTML = `<span></span><span class="badge"></span>`;
    tab.firstChild.textContent = label;
    tab.lastChild.textContent = `${items.length} · ${formatBytes(size)}`;
    tab.addEventListener("click", () => { state.activeTab = key; render(); });
    el.tabBar.appendChild(tab);
  }
  el.tabBar.hidden = state.items.length === 0;
}

function renderList() {
  const visible = filteredItems().filter(
    (item) => state.activeTab === "all" || item.group === state.activeTab
  );
  el.listPanel.innerHTML = "";
  el.emptyState.hidden = visible.length !== 0;
  el.emptyState.textContent = state.items.length === 0
    ? "No scan yet. Choose a scope and start a scan."
    : "Nothing in this system path matches the current filters.";

  if (state.activeTab !== "all" && visible.length) {
    const allSelected = visible.every((item) => state.selected.has(item.path));
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "btn btn-ghost tab-toggle";
    toggle.textContent = allSelected ? "Unselect all in this path" : "Select all in this path";
    toggle.addEventListener("click", () => {
      for (const item of visible) allSelected ? state.selected.delete(item.path) : state.selected.add(item.path);
      render();
    });
    el.listPanel.appendChild(toggle);
  }

  for (const item of visible) {
    const row = document.createElement("label");
    row.className = "row";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = state.selected.has(item.path);
    input.disabled = state.deleting;
    input.addEventListener("change", () => {
      input.checked ? state.selected.add(item.path) : state.selected.delete(item.path);
      render();
    });
    const body = document.createElement("div");
    body.className = "row-body";
    const title = document.createElement("p");
    title.className = "row-title";
    title.textContent = item.label;
    const badge = document.createElement("span");
    badge.className = "size-badge";
    badge.textContent = formatBytes(item.size);
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.style.cssText = chipStyle(item.category);
    chip.textContent = item.category;
    const path = document.createElement("p");
    path.className = "path";
    path.textContent = prettyPath(item.path);
    title.appendChild(badge);
    title.appendChild(chip);
    body.appendChild(title);
    body.appendChild(path);
    row.appendChild(input);
    row.appendChild(body);
    el.listPanel.appendChild(row);
  }
}
```

`metrics()` as in the old file (counts, sizes, button disabling — plus `el.stopBtn` never disabled by it). Render throttling for streaming items:

```js
let renderQueued = false;
function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  setTimeout(() => { renderQueued = false; render(); }, 150);
}
```

`startScan()` as in the old file, with: `state.activeTab = "all"`, reads `data.scan_id` from the `start` event into `state.scanId`, handles `progress` events (`state.scannedDirs`, `state.currentDir` — display wired in Task 5), uses `scheduleRender()` instead of `render()` for `item` events, and `item` handling uses `data.group`. `setBusyState()` disables `mode, scope, searchInput, categoryFilter, sortBy, scanBtn, deleteBtn, selectVisibleBtn, clearSelectionBtn` while `state.scanning || state.deleting`, and toggles `scanBtn/stopBtn` visibility (`el.scanBtn.hidden = state.scanning; el.stopBtn.hidden = !state.scanning;`). Delete keeps `window.confirm` in this task. All wiring (event listeners, init calls) as in the old file.

- [ ] **Step 4: Manual verification**

Run: `mkdir -p ~/projects/_macclean_sample/node_modules && dd if=/dev/zero of=~/projects/_macclean_sample/node_modules/blob bs=1m count=8 2>/dev/null; uv run python main.py --no-browser` and open `http://localhost:8080`.
Expected: aurora light theme, no network requests in devtools Network tab, scan produces tabs (All + `~/projects` + any cache groups), tab badges show count · size, filters/sort/search work within tabs, terminology says "system path", stats tick up during scan, delete works via native confirm.

- [ ] **Step 5: Commit**

```bash
git add ui/index.html
git commit -m "feat: aurora-themed tabbed system-paths UI"
```

---

### Task 5: Scan panel with radar animation and Stop scan

**Files:**
- Modify: `ui/index.html` (fill `#scanPanel`, scan-panel CSS, wire stop/progress)

**Interfaces:**
- Consumes: `progress` events (Task 3), `stopBtn`, `scanPanel`, `scanItems`, `scanSize`, `scanPath` (Task 4).
- Produces: `stopScan()`; scan-state UX used by Task 6's flows.

- [ ] **Step 1: Scan panel markup**

Replace the `#scanPanel` placeholder content:

```html
<section id="scanPanel" class="card scan-panel" hidden>
  <div class="radar" aria-hidden="true">
    <span class="ring r1"></span><span class="ring r2"></span><span class="ring r3"></span>
    <span class="sweep"></span><span class="core"></span>
  </div>
  <div class="scan-info">
    <p class="scan-title">Scanning your Mac…</p>
    <p class="scan-stats"><span id="scanItems">0</span> items · <span id="scanSize">0 B</span> found</p>
    <p id="scanPath" class="path">&nbsp;</p>
  </div>
</section>
```

- [ ] **Step 2: Radar CSS**

```css
.scan-panel { display: flex; align-items: center; gap: 1.5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }
.radar { position: relative; width: 92px; height: 92px; flex: 0 0 auto; }
.radar .ring, .radar .sweep, .radar .core { position: absolute; inset: 0; border-radius: 50%; }
.radar .ring { border: 2px solid rgba(99,102,241,.35); animation: radar-pulse 2.4s ease-out infinite; }
.radar .r2 { animation-delay: .8s; }
.radar .r3 { animation-delay: 1.6s; }
.radar .sweep {
  background: conic-gradient(from 0deg, rgba(139,92,246,.45), rgba(34,211,238,.18) 30%, transparent 45%);
  animation: radar-spin 1.8s linear infinite;
  -webkit-mask: radial-gradient(circle, transparent 18%, #000 19%);
  mask: radial-gradient(circle, transparent 18%, #000 19%);
}
.radar .core { inset: 38%; background: var(--grad); box-shadow: 0 0 18px rgba(139,92,246,.6); animation: core-pulse 1.2s ease-in-out infinite alternate; }
@keyframes radar-pulse { from { transform: scale(.35); opacity: 1; } to { transform: scale(1); opacity: 0; } }
@keyframes radar-spin { to { transform: rotate(360deg); } }
@keyframes core-pulse { from { transform: scale(.85); } to { transform: scale(1.1); } }
.scan-title { margin: 0; font: 700 1.1rem var(--font-display); }
.scan-stats { margin: .2rem 0; color: var(--ink-soft); }
.scan-stats span { font-family: var(--font-mono); font-weight: 700; color: var(--indigo); }
.results.dimmed { opacity: .75; }
```

(`prefers-reduced-motion` already zeroes `.radar *` animations from Task 4.)

- [ ] **Step 3: Wire the behavior**

In `startScan()`: `el.scanPanel.hidden = false;` and add `dimmed` class to the results card; reset `scanItems/scanSize/scanPath`. On `item` events also update `el.scanItems.textContent` and running-size in `el.scanSize` (direct DOM update, not full render). On `progress` events set `el.scanPath.textContent = prettyPath(data.current)`. On `done`: hide panel, remove `dimmed`, existing complete behavior; message says "Found N cleanup candidates totalling S across R system path(s)." where R = number of distinct groups.

```js
function stopScan() {
  if (!state.scanning) return;
  closeSource();
  state.scanning = false;
  el.scanPanel.hidden = true;
  document.querySelector(".results").classList.remove("dimmed");
  setBusyState();
  setStatus("Scan stopped — partial results kept", "warn");
  setMessage(`Stopped after ${state.items.length} item(s). Everything found so far stays selectable and deletable.`);
  render();
}
el.stopBtn.addEventListener("click", stopScan);
```

Also update `source.onerror` to route through the same cleanup (hide panel, remove `dimmed`).

- [ ] **Step 4: Manual verification**

Scan `Full Mac` scope (long enough to watch): radar animates, tickers count up, current path updates, every control disabled except Stop. Click Stop mid-scan: panel hides, status pill shows "Scan stopped — partial results kept", items remain selected, Delete selected works on a `~/projects/_macclean_sample` item. Confirm server console/CPU shows the walk stops shortly after.

- [ ] **Step 5: Commit**

```bash
git add ui/index.html
git commit -m "feat: animated scan panel with stop button and live progress"
```

---

### Task 6: Delete confirmation modal + celebration overlay

**Files:**
- Modify: `ui/index.html` (fill `#confirmModal` and `#celebration`, overlay CSS, replace `window.confirm`)

**Interfaces:**
- Consumes: `performDelete` flow, `formatBytes`, overlay containers from Task 4.
- Produces: `openConfirm()`, `closeConfirm()`, `celebrate(bytes, count)`, `dismissCelebration()`.

- [ ] **Step 1: Markup**

```html
<div id="confirmModal" class="overlay" hidden>
  <div class="card dialog">
    <h3 id="confirmTitle">Delete 0 items?</h3>
    <p id="confirmBody">This frees about 0 B. Files are removed permanently, not moved to the Trash.</p>
    <div class="dialog-actions">
      <button id="confirmCancel" class="btn btn-ghost">Cancel</button>
      <button id="confirmDelete" class="btn btn-danger">Delete</button>
    </div>
  </div>
</div>

<div id="celebration" class="overlay" hidden>
  <canvas id="confettiCanvas"></canvas>
  <div class="card dialog celebrate">
    <p class="celebrate-emoji">🎉</p>
    <h3>All clean!</h3>
    <p id="celebrateAmount" class="celebrate-amount">0 B</p>
    <p id="celebrateSub" class="celebrate-sub">reclaimed across 0 items</p>
    <button id="celebrateClose" class="btn btn-primary">Done</button>
  </div>
</div>
```

- [ ] **Step 2: CSS**

```css
.dialog { max-width: 24rem; width: calc(100% - 2rem); padding: 1.75rem; text-align: center; background: #fff; }
.dialog h3 { margin: 0 0 .5rem; font: 700 1.25rem var(--font-display); }
.dialog p { margin: 0 0 1.25rem; color: var(--ink-soft); }
.dialog-actions { display: flex; gap: .75rem; justify-content: center; }
#confettiCanvas { position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; }
.celebrate { animation: pop-in .45s cubic-bezier(.2, 1.4, .4, 1); }
.celebrate-emoji { font-size: 2.5rem; margin: 0; }
.celebrate-amount {
  margin: .25rem 0 0 !important; font: 800 3rem var(--font-display);
  background: var(--grad); -webkit-background-clip: text; background-clip: text; color: transparent;
}
.celebrate-sub { color: var(--ink-soft); }
@keyframes pop-in { from { transform: scale(.7); opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .celebrate { animation: none; } }
```

- [ ] **Step 3: JS — confirm modal replaces `window.confirm`**

```js
function openConfirm() {
  const selectedItems = state.items.filter((item) => state.selected.has(item.path));
  const totalBytes = selectedItems.reduce((acc, item) => acc + item.size, 0);
  el.confirmTitle.textContent = `Delete ${selectedItems.length} item${selectedItems.length === 1 ? "" : "s"}?`;
  el.confirmBody.textContent = `This frees about ${formatBytes(totalBytes)}. Files are removed permanently, not moved to the Trash.`;
  el.confirmDelete.textContent = `Delete ${selectedItems.length} item${selectedItems.length === 1 ? "" : "s"}`;
  el.confirmModal.hidden = false;
}
function closeConfirm() { el.confirmModal.hidden = true; }
```

`deleteSelected` becomes: guard (`selected.size`, `deleting`, `scanId` — same messages as before) then `openConfirm()`. `confirmDelete` click → `closeConfirm(); performDelete();` where `performDelete` is the old fetch flow. On success call `celebrate(result.deleted_bytes || 0, result.deleted_count || 0)` and keep the skipped-items message. `confirmCancel` click and clicking the overlay backdrop (`event.target === el.confirmModal`) → `closeConfirm()`.

- [ ] **Step 4: JS — celebration with confetti + count-up**

```js
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let celebrationTimer = null;
let confettiRaf = null;

function celebrate(bytes, count) {
  el.celebrateSub.textContent = `reclaimed across ${count} item${count === 1 ? "" : "s"}`;
  el.celebration.hidden = false;
  if (REDUCED_MOTION) {
    el.celebrateAmount.textContent = formatBytes(bytes);
  } else {
    const start = performance.now();
    const duration = 1600;
    (function tick(now) {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      el.celebrateAmount.textContent = formatBytes(bytes * eased);
      if (t < 1 && !el.celebration.hidden) requestAnimationFrame(tick);
    })(start);
    launchConfetti();
  }
  celebrationTimer = setTimeout(dismissCelebration, 6000);
}

function dismissCelebration() {
  clearTimeout(celebrationTimer);
  if (confettiRaf) cancelAnimationFrame(confettiRaf);
  confettiRaf = null;
  el.celebration.hidden = true;
}

function launchConfetti() {
  const canvas = el.confettiCanvas;
  const ctx = canvas.getContext("2d");
  canvas.width = canvas.clientWidth;
  canvas.height = canvas.clientHeight;
  const colors = ["#6366f1", "#8b5cf6", "#ec4899", "#22d3ee", "#10b981", "#f59e0b"];
  const parts = Array.from({ length: 180 }, () => ({
    x: canvas.width / 2 + (Math.random() - 0.5) * canvas.width * 0.3,
    y: canvas.height * 0.55,
    vx: (Math.random() - 0.5) * 14,
    vy: -6 - Math.random() * 10,
    w: 6 + Math.random() * 6,
    h: 4 + Math.random() * 4,
    rot: Math.random() * Math.PI,
    vr: (Math.random() - 0.5) * 0.3,
    color: colors[Math.floor(Math.random() * colors.length)],
    life: 1,
  }));
  const started = performance.now();
  (function frame(now) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of parts) {
      p.vy += 0.25; p.x += p.vx; p.y += p.vy; p.rot += p.vr;
      p.life = Math.max(0, 1 - (now - started) / 4000);
      ctx.save();
      ctx.globalAlpha = p.life;
      ctx.translate(p.x, p.y);
      ctx.rotate(p.rot);
      ctx.fillStyle = p.color;
      ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
      ctx.restore();
    }
    if (now - started < 4000 && !el.celebration.hidden) confettiRaf = requestAnimationFrame(frame);
    else ctx.clearRect(0, 0, canvas.width, canvas.height);
  })(started);
}

el.celebrateClose.addEventListener("click", dismissCelebration);
el.celebration.addEventListener("click", (event) => { if (event.target === el.celebration) dismissCelebration(); });
```

- [ ] **Step 5: Manual verification**

Delete the `~/projects/_macclean_sample` items: styled modal appears with exact count/size and "Delete N items" button; Cancel and backdrop-click close it; confirming shows confetti burst + amount counting up to the reclaimed size + item count; overlay auto-dismisses after ~6 s and immediately on Done; list and stats update underneath; skipped-items message still appears when relevant.

- [ ] **Step 6: Commit**

```bash
git add ui/index.html
git commit -m "feat: delete confirmation modal and confetti celebration overlay"
```

---

### Task 7: End-to-end verification pass

**Files:**
- None (verification only); fix anything found, commit fixes individually.

- [ ] **Step 1: Backend tests green**

Run: `uv run python -m unittest discover -s tests -t . -v` — all PASS.

- [ ] **Step 2: Full browser walkthrough**

With `uv run python main.py --no-browser` running and sample dirs present (`~/projects/_macclean_sample/node_modules` with an 8 MB blob, plus `__pycache__`):

1. Fresh load: idle empty state, no external network requests, no console errors.
2. Projects scan: tabs render (All first, gradient active state), badges correct, "system path" wording everywhere, no "project" strings visible.
3. Filters: search/category/sort operate within tabs; fully-filtered tabs fade; All tab aggregates.
4. Scan again → Stop mid-scan: controls disabled during scan except Stop, radar animates, ticker/current-path update; after Stop partial items remain selected and deletable.
5. Delete flow: confirm modal → celebration (count-up amount matches `deleted_human` scale) → items removed.
6. Full Mac scope (non-admin): amber admin note appears; permissions message intact.
7. Narrow window (~600 px): layout stacks, tab bar scrolls horizontally, no horizontal page scroll.

- [ ] **Step 3: Clean up sample dirs**

Run: `rm -rf ~/projects/_macclean_sample`

- [ ] **Step 4: Final commit if fixes were made**

```bash
git add -p   # only files this plan touched
git commit -m "fix: polish from end-to-end verification"
```
