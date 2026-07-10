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
