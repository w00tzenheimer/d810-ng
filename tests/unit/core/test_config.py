"""Tests for D810 configuration system.

These tests require mocking ida_diskio to control the IDA user directory.
"""

import importlib
import json
import logging
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager
from pathlib import Path


class MockIdaDiskio:
    """Mock for ida_diskio module."""

    _user_idadir: Path = Path("mock_idadir")

    @classmethod
    def get_user_idadir(cls) -> Path:
        return cls._user_idadir


@contextmanager
def temp_ida_dir():
    """Context manager providing a temporary IDA user directory."""
    orig_dir = MockIdaDiskio._user_idadir
    with tempfile.TemporaryDirectory() as tmp_dir:
        MockIdaDiskio._user_idadir = Path(tmp_dir)
        try:
            yield Path(tmp_dir)
        finally:
            MockIdaDiskio._user_idadir = orig_dir


@contextmanager
def load_conf_classes():
    """Context manager that loads config classes with mocked ida_diskio."""
    orig = sys.modules.get("ida_diskio")

    dummy_mod = types.ModuleType("ida_diskio")
    setattr(dummy_mod, "get_user_idadir", MockIdaDiskio.get_user_idadir)
    sys.modules["ida_diskio"] = dummy_mod

    try:
        if "d810.core.config" in sys.modules:
            module = importlib.reload(sys.modules["d810.core.config"])
        else:
            module = importlib.import_module("d810.core.config")
        yield module.D810Configuration, module.ProjectConfiguration, module.RuleConfiguration
    finally:
        if orig is not None:
            sys.modules["ida_diskio"] = orig
        else:
            sys.modules.pop("ida_diskio", None)


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
                # Instance with explicit ida_user_dir should read template but save to user dir
                app_config = D810Configuration(ida_user_dir=ida_dir)
                # Value should initially be whatever is in config (template or pre-existing user copy)
                self.assertIn(app_config.get("template_key"), ("tmpl", "user"))
                # After save(), a user copy must exist
                app_config.set("template_key", "user")
                app_config.save()
                self.assertTrue(app_config.config_file.exists())
                # log_dir should use the provided ida_user_dir path
                self.assertEqual(
                    str(app_config.log_dir),
                    str(ida_dir / "logs"),
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

    def test_discover_projects(self):
        """Test project discovery, including user overrides and ignoring options.json."""
        with temp_ida_dir() as ida_dir:
            with load_conf_classes() as (D810Configuration, ProjectConfiguration, _):
                # 1. Setup a user directory with a new project and an overriding project
                user_conf_dir = Path(ida_dir) / "cfg" / "d810"
                user_conf_dir.mkdir(parents=True, exist_ok=True)

                # This project is unique to the user directory
                (user_conf_dir / "my_user_project.json").write_text(
                    '{"description": "My User Project"}'
                )

                # This project overrides a built-in template
                (user_conf_dir / "hodur_deobfuscation.json").write_text(
                    '{"description": "User Override for Hodur"}'
                )

                # 2. Run discovery with explicit ida_user_dir
                config = D810Configuration(ida_user_dir=ida_dir)
                projects = config.discover_projects()

                # 3. Verify results
                project_map = {p.path.name: p for p in projects}

                # Check that options.json is NOT treated as a project
                self.assertNotIn("options.json", project_map)

                # Check that the user's new project is found
                self.assertIn("my_user_project.json", project_map)
                self.assertEqual(
                    project_map["my_user_project.json"].description, "My User Project"
                )

                # Check that the user's overriding project is used
                self.assertIn("hodur_deobfuscation.json", project_map)
                self.assertEqual(
                    project_map["hodur_deobfuscation.json"].description,
                    "User Override for Hodur",
                )

                # Check that a built-in project that was NOT overridden is still loaded
                self.assertIn("default_instruction_only.json", project_map)

                # Check that the list of configurations was saved back to options.json
                config.save()
                reloaded_config = D810Configuration(config.config_file, ida_user_dir=ida_dir)
                saved_configs = reloaded_config.get("configurations")
                self.assertIn("my_user_project.json", saved_configs)
                self.assertIn("hodur_deobfuscation.json", saved_configs)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
