# MacClean UI Overhaul — Design

Date: 2026-07-10
Status: Approved (all clarifying questions answered with recommended options; final sign-off pending user review)

## Goal

Modernize the MacClean web UI with five changes requested by the user:

1. Show cleanup candidates in per-path **tabs** instead of a vertical expandable list.
2. Rename all user-facing "project" terminology to **"system paths"**.
3. During a scan, show a **beautiful animation**, disable all controls, and provide a **Stop Scan** button.
4. After a cleanup completes, show an **eye-catching animated celebration** displaying the amount reclaimed.
5. Restyle the whole UI to be **modern, vibrant, and light** (no dark colors).

Decisions made with the user:

- **Tab grouping:** smarter granularity — paths under a user home group one level deeper (`~/projects`, `~/Library`, `~/.Trash`, …); system paths stay top-level (`/Library`, `/opt`, `/private`, …).
- **Styling:** drop the Tailwind CDN; hand-written, self-contained CSS embedded in `ui/index.html` (fully offline, zero-dependency).
- **Theme:** "Aurora" light — near-white background with soft drifting indigo/violet/pink/cyan gradients, glassy cards, gradient accents, bright category chips.
- **Cancel semantics:** stopping a scan keeps partial results, which remain deletable.

## Scope

Two files change: `main.py` (small protocol/grouping changes + dead-code cleanup) and `ui/index.html` (full rewrite of markup/CSS/JS, same overall feature set). No new dependencies, no new runtime files.

## Backend design (`main.py`)

### Grouping

`path_group(path)` returns:

- For paths under `/Users/<name>` (or `/home/<name>`): `/Users/<name>/<first-child>` — e.g. `/Users/raj/projects/foo/node_modules` → `/Users/raj/projects`. A path that *is* the home root returns the home root.
- Otherwise: `/<top-level>` as today (`/Library`, `/opt`, `/private`, `/usr`).

The SSE item field `project` is renamed to `group`. The UI displays the current user's home prefix as `~` (home root obtained from `/status`'s `home_root`).

### Cancellable scans

- `scan_id` is generated at scan start and sent in the `start` event (it remains in the `done` event too).
- The scan session is persisted in `SCAN_SESSIONS` at scan start with an empty path set; `emit_item` adds each emitted path to the session as it goes. Stopping mid-scan therefore leaves all found items deletable under the existing scan-session validation.
- Cancel mechanism: the client closes the `EventSource`. The server already stops when a write fails (`client_connected = False`); progress events (below) guarantee writes happen regularly even when no items are being found.

### Progress events

During the directory walk, every 250 directories the server emits:

```json
{"type": "progress", "scanned_dirs": 1250, "current": "/Users/raj/projects/foo"}
```

This drives the scan animation (live counters + "currently scanning" path) and bounds how long a cancelled scan keeps walking server-side.

### Targeted cleanup

`main.py` defines `TARGET_RULES` and `rules_for_mode` twice (lines ~52–200 and ~459–618); the second definitions silently shadow the first. `is_safe_path()` is dead code referencing an undefined `SEARCH_ROOT`. Remove the first (shadowed) `TARGET_RULES`/`rules_for_mode` block and delete `is_safe_path`, preserving today's *effective* rule set exactly (i.e. the second block's semantics, where `target` is aggressive-only).

## Frontend design (`ui/index.html`)

Single self-contained file: inline `<style>` and `<script>`, system font stack, no network resources.

### Layout (top to bottom)

1. **Header card** — gradient-text "MacClean" logo + tagline; Start Scan (gradient primary) and Delete Selected (warm gradient danger) buttons; Mode and Scope selects.
2. **Stats row** — four glassy stat tiles (Detected items, Selected items, Detected reclaimable, Selected reclaimable) with gradient numerals.
3. **Filters row** — Search, Category, Sort controls; Select visible / Clear selection; status pill.
4. **Cleanup Candidates card** — subtitle "Grouped by system path". Horizontal scrollable pill tab bar: **All** tab first, then one tab per system path group, each showing a prettified path (`~/projects`, `/Library`) plus an item-count and size badge. Active tab gets the gradient fill. Tab panel lists that path's items: checkbox, label, size badge, colored category chip, small monospace path. Per-tab "Select all in this path / Unselect" action.
5. Message line + admin info banner (existing behaviors preserved).

Filter behavior: search/category/sort apply to the item list within the active tab; a tab whose items are all filtered out is greyed out (still clickable, shows empty-state text). Counts/sizes on tab badges reflect filtered items. The **All** tab shows every visible item ungrouped.

### Terminology

All user-facing "project" strings become "system path(s)": section subtitle, select-all buttons, search placeholder ("Search path or label"), messages. Scope option labels ("Projects", "User home", "Full Mac") are unchanged — they describe scan scopes, not groups.

### Scan experience

On Start Scan:

- Every control is disabled except a prominent **Stop Scan** button.
- An animated scan panel appears above the results: CSS-only radar animation (pulsing concentric gradient rings + orbiting comet dot), live tickers for items found and size found, and the currently-scanned directory (from progress events) in a single-line ellipsized monospace strip.
- Results continue to stream into the tabs below, slightly dimmed but visible.

Stop Scan closes the EventSource, keeps all partial results selected/deletable, hides the scan panel, and sets the status pill to "Scan stopped — partial results". Natural completion shows "Scan complete" as today.

### Delete confirmation + celebration

- `window.confirm` is replaced by a styled in-page modal: item count, total size, Cancel / Delete buttons.
- On successful deletion, a full-screen celebration overlay plays: canvas confetti burst (self-contained particle system, ~60 lines, no library), a large number counting up from 0 to the reclaimed size ("🎉 2.4 GB reclaimed!"), an item-count subtitle, and a Done button; auto-dismisses after ~6 s or on click.
- Skipped/failed deletions keep the current message-line reporting after the overlay closes.

### Theme — Aurora light

- Background `#fafaff` with two or three large, slowly drifting radial gradients (indigo `#6366f1`, violet `#8b5cf6`, pink `#ec4899`, cyan `#22d3ee`) at low opacity, animated via CSS keyframes.
- White glassy cards (`backdrop-filter: blur`, soft colored shadows, 16–20 px radii).
- Gradient fills for primary buttons, active tab, stat numerals, and the logo.
- One bright chip color per category (deterministic hash from category name into a fixed vibrant palette), always dark-text-on-light-chip for contrast.
- No dark backgrounds anywhere. `prefers-reduced-motion: reduce` disables ambient drift, radar, and confetti animations.

### Error handling

- SSE `error` events and stream drops: warning status pill + message (existing behavior, restyled).
- Delete failure / expired scan session: existing messages preserved.
- Empty states: friendly emoji + text per tab and for "no scan yet".

## Testing / verification

No automated test suite exists in this repo. Verification is end-to-end:

1. `uv run python main.py` and open the UI.
2. Scan `~/projects` (with throwaway sample dirs like `sample/node_modules`), confirm tabs, badges, filters, terminology.
3. Start a scan and Stop mid-way; confirm partial results remain and can be deleted.
4. Delete a throwaway selection; confirm the confirmation modal, the celebration overlay with correct reclaimed amount, and list updates.
5. Confirm the server actually stops walking after cancel (progress events cease server-side).
