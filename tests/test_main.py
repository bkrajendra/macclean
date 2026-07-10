import io
import json
import os
import tempfile
import types
import unittest

import main


def parse_sse(raw):
    events = []
    for block in raw.decode().split("\n\n"):
        block = block.strip()
        if block.startswith("data: "):
            events.append(json.loads(block[len("data: "):]))
    return events


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

    def test_progress_events_emitted_during_walk(self):
        with tempfile.TemporaryDirectory() as projects, \
                tempfile.TemporaryDirectory() as fake_home:
            for i in range(300):
                os.makedirs(os.path.join(projects, f"pkg{i}", "src"))
            old_projects, old_home = main.PROJECTS_ROOT, main.HOME_ROOT
            main.PROJECTS_ROOT, main.HOME_ROOT = projects, fake_home
            try:
                handler = types.SimpleNamespace(wfile=io.BytesIO())
                main.scan_stream(handler, mode="safe", scope="projects")
            finally:
                main.PROJECTS_ROOT, main.HOME_ROOT = old_projects, old_home

            events = parse_sse(handler.wfile.getvalue())
            progress = [e for e in events if e["type"] == "progress"]
            self.assertTrue(progress)
            self.assertGreaterEqual(progress[0]["scanned_dirs"], 250)
            self.assertTrue(progress[0]["current"].startswith(os.path.realpath(projects))
                            or progress[0]["current"].startswith(projects))


if __name__ == "__main__":
    unittest.main()
