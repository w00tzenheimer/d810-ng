"""Tests for ProjectManager construction/discovery behaviour (slice 6,
ticket d81-ebpz): ``ProjectManager.__post_init__`` calls ``load_all()`` ->
``D810Configuration.discover_projects()`` on every construction, which must
not rewrite options.json, and the UI-facing "configurations" list must
still be visible afterwards.
"""

import tempfile
import unittest
from pathlib import Path

from d810.core.config import D810Configuration, ProjectConfiguration
from d810.core.project import ProjectManager


class TestProjectManagerDiscovery(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.ida_dir = Path(self._tmp_dir.name)

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_construction_does_not_persist_options_json(self):
        config = D810Configuration(ida_user_dir=self.ida_dir)
        self.assertFalse(config.config_file.exists())

        ProjectManager(config)

        # ProjectManager.__post_init__ -> load_all() -> discover_projects()
        # must not have written options.json to disk.
        self.assertFalse(config.config_file.exists())

    def test_configurations_list_still_visible_after_construction(self):
        config = D810Configuration(ida_user_dir=self.ida_dir)
        manager = ProjectManager(config)

        self.assertGreater(len(manager), 0)
        cfg_names = config.get("configurations")
        self.assertIsNotNone(cfg_names)
        self.assertEqual(sorted(cfg_names), manager.project_names())

    def test_add_still_persists_explicitly(self):
        """ProjectManager.add() is a user-initiated change and must still
        write options.json (unlike discovery)."""
        config = D810Configuration(ida_user_dir=self.ida_dir)
        manager = ProjectManager(config)

        project_path = self.ida_dir / "cfg" / "d810" / "brand_new_project.json"
        project_path.parent.mkdir(parents=True, exist_ok=True)
        project_path.write_text('{"description": "Brand new"}')

        manager.add(ProjectConfiguration.from_file(project_path))

        self.assertTrue(config.config_file.exists())
        reloaded = D810Configuration(config.config_file, ida_user_dir=self.ida_dir)
        self.assertIn("brand_new_project.json", reloaded.get("configurations"))


if __name__ == "__main__":
    unittest.main()
