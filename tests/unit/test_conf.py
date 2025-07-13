import json
import logging
import unittest
from pathlib import Path

from .tutils import MockIdaDiskio, load_conf_classes, temp_ida_dir


class TestConfiguration(unittest.TestCase):

    def setUp(self):
        """Set up dummy files for testing."""
        self.dummy_options_file = Path("./options.json")
        self.dummy_options_file.write_text('{"api_key": "secret", "timeout": 60}')

        self.dummy_project_file = Path("./project.json")
        self.dummy_project_content = {
            "description": "My Test Project",
            "ins_rules": [
                {
                    "name": "check_string_format",
                    "is_activated": True,
                    "config": {"min_len": 5},
                }
            ],
            "blk_rules": [],
        }
        with self.dummy_project_file.open("w") as f:
            json.dump(self.dummy_project_content, f, indent=2)

    def tearDown(self):
        """Clean up dummy files after testing."""
        self.dummy_options_file.unlink(missing_ok=True)
        self.dummy_project_file.unlink(missing_ok=True)

    def test_d810_configuration(self):
        """Test D810Configuration loading and logging."""
        with temp_ida_dir() as ida_dir:
            # Place template in read-only area (simulate packaged conf)
            packaged_path = ida_dir / "cfg/d810/options.json"
            packaged_path.parent.mkdir(parents=True, exist_ok=True)
            packaged_path.write_text('{"template_key": "tmpl"}')
            with load_conf_classes() as (D810Configuration, _, _):
                # Instance with no explicit path should read template but save to user dir
                app_config = D810Configuration()
                # Value should initially be whatever is in config (template or pre-existing user copy)
                self.assertIn(app_config.get("template_key"), ("tmpl", "user"))
                # After save(), a user copy must exist
                app_config.set("template_key", "user")
                app_config.save()
                self.assertTrue(app_config.config_file.exists())
                # log_dir should use MockIdaDiskio path
                self.assertEqual(
                    str(app_config.log_dir),
                    str(Path(MockIdaDiskio.get_user_idadir(), "logs")),
                )

    def test_project_configuration(self):
        """Test ProjectConfiguration loading, modification, and saving."""
        with load_conf_classes() as (_, ProjectConfiguration, RuleConfiguration):
            project_config = ProjectConfiguration.from_file(self.dummy_project_file)
            self.assertEqual(project_config.description, "My Test Project")

            # Modify and save
            new_rule = RuleConfiguration(name="check_buffer_size", is_activated=False)
            project_config.ins_rules.append(new_rule)
            project_config.description = "My updated test project"
            project_config.save()

            # Reload and verify changes
            project_config_reloaded = ProjectConfiguration.from_file(
                self.dummy_project_file
            )
            self.assertEqual(
                project_config_reloaded.description, "My updated test project"
            )
            self.assertIn(new_rule, project_config_reloaded.ins_rules)

    def test_get_and_set_methods(self):
        """Test get() and set() methods of D810Configuration."""
        with load_conf_classes() as (D810Configuration, _, _):
            app_config = D810Configuration(self.dummy_options_file)
            # default when missing
            self.assertIsNone(app_config.get("missing_key"))
            self.assertEqual(app_config.get("missing_key", "default"), "default")
            # assign and retrieve
            app_config.set("new_key", "new_value")
            self.assertEqual(app_config.get("new_key"), "new_value")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
