"""Unit tests for CythonMode functionality.

Tests the CythonMode singleton and CythonImporter helper that control
Cython-accelerated implementations at runtime.
"""
import os
import sys
import unittest
from unittest.mock import patch

from d810.core.cymode import CythonMode, CythonImporter, _get_default_cython_enabled


class TestGetDefaultCythonEnabled(unittest.TestCase):
    """Test the _get_default_cython_enabled function that reads D810_NO_CYTHON env var."""

    def test_no_env_var_defaults_to_enabled(self):
        """When D810_NO_CYTHON is not set, Cython should be enabled by default."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove D810_NO_CYTHON if it exists
            os.environ.pop("D810_NO_CYTHON", None)
            result = _get_default_cython_enabled()
            self.assertTrue(result)

    def test_env_var_1_disables_cython(self):
        """D810_NO_CYTHON=1 should disable Cython."""
        with patch.dict(os.environ, {"D810_NO_CYTHON": "1"}):
            result = _get_default_cython_enabled()
            self.assertFalse(result)

    def test_env_var_true_disables_cython(self):
        """D810_NO_CYTHON=true should disable Cython."""
        with patch.dict(os.environ, {"D810_NO_CYTHON": "true"}):
            result = _get_default_cython_enabled()
            self.assertFalse(result)

    def test_env_var_yes_disables_cython(self):
        """D810_NO_CYTHON=yes should disable Cython."""
        with patch.dict(os.environ, {"D810_NO_CYTHON": "yes"}):
            result = _get_default_cython_enabled()
            self.assertFalse(result)

    def test_env_var_case_insensitive(self):
        """D810_NO_CYTHON should be case-insensitive."""
        for value in ["TRUE", "True", "YES", "Yes", "1"]:
            with patch.dict(os.environ, {"D810_NO_CYTHON": value}):
                result = _get_default_cython_enabled()
                self.assertFalse(result, f"Failed for value: {value}")

    def test_env_var_0_enables_cython(self):
        """D810_NO_CYTHON=0 should enable Cython."""
        with patch.dict(os.environ, {"D810_NO_CYTHON": "0"}):
            result = _get_default_cython_enabled()
            self.assertTrue(result)

    def test_env_var_empty_enables_cython(self):
        """D810_NO_CYTHON='' (empty string) should enable Cython."""
        with patch.dict(os.environ, {"D810_NO_CYTHON": ""}):
            result = _get_default_cython_enabled()
            self.assertTrue(result)

    def test_env_var_arbitrary_value_enables_cython(self):
        """D810_NO_CYTHON with arbitrary value should enable Cython."""
        with patch.dict(os.environ, {"D810_NO_CYTHON": "some_random_value"}):
            result = _get_default_cython_enabled()
            self.assertTrue(result)


class TestCythonModeSingleton(unittest.TestCase):
    """Test CythonMode singleton behavior."""

    def setUp(self):
        """Set up test by getting the singleton instance."""
        self.mode = CythonMode()
        # Store original state to restore after test
        self._original_state = self.mode.is_enabled()

    def tearDown(self):
        """Restore original state after test."""
        # Restore the original state by directly setting _enabled
        self.mode._enabled = self._original_state

    def test_singleton_returns_same_instance(self):
        """Multiple CythonMode() calls should return the same instance."""
        mode1 = CythonMode()
        mode2 = CythonMode()
        self.assertIs(mode1, mode2)

    def test_state_persists_across_instances(self):
        """State changes should persist across all CythonMode instances."""
        mode1 = CythonMode()
        mode1.enable()

        mode2 = CythonMode()
        self.assertTrue(mode2.is_enabled())

        mode1.disable()
        self.assertFalse(mode2.is_enabled())


class TestCythonModeToggleMethods(unittest.TestCase):
    """Test CythonMode enable/disable/toggle methods."""

    def setUp(self):
        """Set up test by getting the singleton instance."""
        self.mode = CythonMode()
        self._original_state = self.mode.is_enabled()

    def tearDown(self):
        """Restore original state after test."""
        self.mode._enabled = self._original_state

    def test_enable_sets_enabled_to_true(self):
        """enable() should set is_enabled() to True."""
        # First disable to ensure we're testing the transition
        self.mode._enabled = False

        # Capture print output
        with patch("builtins.print") as mock_print:
            self.mode.enable()
            self.assertTrue(self.mode.is_enabled())
            mock_print.assert_called_once_with("Cython speedups ENABLED.")

    def test_enable_when_already_enabled_no_message(self):
        """enable() when already enabled should not print message."""
        self.mode._enabled = True

        with patch("builtins.print") as mock_print:
            self.mode.enable()
            self.assertTrue(self.mode.is_enabled())
            mock_print.assert_not_called()

    def test_disable_sets_enabled_to_false(self):
        """disable() should set is_enabled() to False."""
        # First enable to ensure we're testing the transition
        self.mode._enabled = True

        with patch("builtins.print") as mock_print:
            self.mode.disable()
            self.assertFalse(self.mode.is_enabled())
            mock_print.assert_called_once_with("Cython speedups DISABLED (using pure Python).")

    def test_disable_when_already_disabled_no_message(self):
        """disable() when already disabled should not print message."""
        self.mode._enabled = False

        with patch("builtins.print") as mock_print:
            self.mode.disable()
            self.assertFalse(self.mode.is_enabled())
            mock_print.assert_not_called()

    def test_toggle_from_enabled_to_disabled(self):
        """toggle() should flip state from enabled to disabled."""
        self.mode._enabled = True

        with patch("builtins.print") as mock_print:
            self.mode.toggle()
            self.assertFalse(self.mode.is_enabled())
            mock_print.assert_called_once_with("Cython speedups DISABLED (using pure Python).")

    def test_toggle_from_disabled_to_enabled(self):
        """toggle() should flip state from disabled to enabled."""
        self.mode._enabled = False

        with patch("builtins.print") as mock_print:
            self.mode.toggle()
            self.assertTrue(self.mode.is_enabled())
            mock_print.assert_called_once_with("Cython speedups ENABLED.")

    def test_multiple_toggles(self):
        """Multiple toggle() calls should alternate state."""
        initial_state = self.mode.is_enabled()

        self.mode.toggle()
        self.assertEqual(self.mode.is_enabled(), not initial_state)

        self.mode.toggle()
        self.assertEqual(self.mode.is_enabled(), initial_state)

        self.mode.toggle()
        self.assertEqual(self.mode.is_enabled(), not initial_state)


class TestCythonImporterDisabled(unittest.TestCase):
    """Test CythonImporter behavior when CythonMode is disabled."""

    def setUp(self):
        """Set up test by disabling CythonMode."""
        self.mode = CythonMode()
        self._original_state = self.mode.is_enabled()
        self.mode._enabled = False
        self.importer = CythonImporter()

    def tearDown(self):
        """Restore original state after test."""
        self.mode._enabled = self._original_state

    def test_import_module_raises_when_disabled(self):
        """import_module() should raise ImportError when CythonMode is disabled."""
        with self.assertRaises(ImportError) as cm:
            self.importer.import_module("some.module")

        self.assertIn("CythonMode disabled", str(cm.exception))
        self.assertIn("some.module", str(cm.exception))

    def test_import_attr_raises_when_disabled(self):
        """import_attr() should raise ImportError when CythonMode is disabled."""
        with self.assertRaises(ImportError) as cm:
            self.importer.import_attr("some.module", "some_attr")

        self.assertIn("CythonMode disabled", str(cm.exception))
        self.assertIn("some.module", str(cm.exception))


class TestCythonImporterEnabled(unittest.TestCase):
    """Test CythonImporter behavior when CythonMode is enabled."""

    def setUp(self):
        """Set up test by enabling CythonMode."""
        self.mode = CythonMode()
        self._original_state = self.mode.is_enabled()
        self.mode._enabled = True
        self.importer = CythonImporter()

    def tearDown(self):
        """Restore original state after test."""
        self.mode._enabled = self._original_state

    def test_import_module_succeeds_for_valid_module(self):
        """import_module() should successfully import a valid module."""
        # Import a standard library module as a test
        module = self.importer.import_module("os.path")
        self.assertIsNotNone(module)
        self.assertTrue(hasattr(module, "join"))

    def test_import_module_raises_for_invalid_module(self):
        """import_module() should raise ImportError for non-existent module."""
        with self.assertRaises(ImportError) as cm:
            self.importer.import_module("nonexistent_module_xyz_123")

        # Should NOT contain "CythonMode disabled" message
        self.assertNotIn("CythonMode disabled", str(cm.exception))

    def test_import_attr_succeeds_for_valid_attr(self):
        """import_attr() should successfully import a valid attribute."""
        # Import os.path.join as a test
        join_func = self.importer.import_attr("os.path", "join")
        self.assertIsNotNone(join_func)
        self.assertTrue(callable(join_func))

    def test_import_attr_raises_for_invalid_module(self):
        """import_attr() should raise ImportError for non-existent module."""
        with self.assertRaises(ImportError):
            self.importer.import_attr("nonexistent_module_xyz_123", "some_attr")

    def test_import_attr_raises_for_invalid_attr(self):
        """import_attr() should raise AttributeError for non-existent attribute."""
        with self.assertRaises(AttributeError):
            self.importer.import_attr("os.path", "nonexistent_attr_xyz_123")


class TestCythonModeIntegration(unittest.TestCase):
    """Integration tests for CythonMode with environment variables."""

    def test_fresh_instance_respects_env_var(self):
        """A fresh CythonMode instance should respect D810_NO_CYTHON env var.

        Note: This test is limited because the singleton survives reloads.
        We can only test that the initial creation logic is correct.
        """
        # Test the helper function directly since the singleton may already exist
        with patch.dict(os.environ, {"D810_NO_CYTHON": "1"}):
            result = _get_default_cython_enabled()
            self.assertFalse(result)

        with patch.dict(os.environ, {"D810_NO_CYTHON": "0"}):
            result = _get_default_cython_enabled()
            self.assertTrue(result)

    def test_runtime_toggle_overrides_env_var(self):
        """Runtime enable/disable should override initial env var setting."""
        mode = CythonMode()
        original_state = mode.is_enabled()

        try:
            # Regardless of initial state, we should be able to toggle
            mode.enable()
            self.assertTrue(mode.is_enabled())

            mode.disable()
            self.assertFalse(mode.is_enabled())

            mode.enable()
            self.assertTrue(mode.is_enabled())
        finally:
            # Restore original state
            mode._enabled = original_state


class TestCythonImporterUsesSharedSingleton(unittest.TestCase):
    """Test that CythonImporter uses the shared CythonMode singleton."""

    def setUp(self):
        """Set up test."""
        self.mode = CythonMode()
        self._original_state = self.mode.is_enabled()

    def tearDown(self):
        """Restore original state after test."""
        self.mode._enabled = self._original_state

    def test_importer_sees_mode_changes(self):
        """CythonImporter should see changes to the shared CythonMode singleton."""
        importer = CythonImporter()

        # Enable and verify importer can import
        self.mode._enabled = True
        module = importer.import_module("os")
        self.assertIsNotNone(module)

        # Disable and verify importer raises
        self.mode._enabled = False
        with self.assertRaises(ImportError) as cm:
            importer.import_module("os")
        self.assertIn("CythonMode disabled", str(cm.exception))

        # Re-enable and verify importer can import again
        self.mode._enabled = True
        module = importer.import_module("os")
        self.assertIsNotNone(module)


if __name__ == "__main__":
    unittest.main()
