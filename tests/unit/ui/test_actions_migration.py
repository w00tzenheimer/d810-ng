"""Tests for Phase 2 action migration.

Verifies that all 8 actions are properly migrated to the new framework
and registered in the D810ActionHandler registry.
"""
from __future__ import annotations

from d810.ui.actions import D810ActionHandler, load_builtin_actions

load_builtin_actions()


class TestActionMigration:
    """Test that all actions from Phase 2 migration are registered."""

    def test_all_actions_registered(self):
        """All core actions should be in the registry."""
        # Expected action IDs (after removing superseded actions)
        expected_actions = {
            "d810ng:deobfuscate_this",
            "d810ng:deobfuscation_stats",
            "d810ng:function_rules",
            "d810ng:mark_deobfuscated",
            "d810ng:decompile_function",
            "d810ng:export_microcode",
            "d810ng:export_to_c",
            "d810ng:export_disasm",
        }

        # Get all registered action IDs
        registered_actions = {
            cls.ACTION_ID for cls in D810ActionHandler.registry.values()
        }

        # Verify all expected actions are registered
        for action_id in expected_actions:
            assert (
                action_id in registered_actions
            ), f"Action {action_id} not found in registry"

    def test_pseudocode_actions_count(self):
        """7 actions should support pseudocode view."""
        pseudocode_actions = [
            cls
            for cls in D810ActionHandler.registry.values()
            if "pseudocode" in cls.SUPPORTED_VIEWS
        ]
        assert len(pseudocode_actions) >= 7

    def test_disasm_actions_count(self):
        """1 action should support disasm view."""
        disasm_actions = [
            cls
            for cls in D810ActionHandler.registry.values()
            if "disasm" in cls.SUPPORTED_VIEWS
        ]
        assert len(disasm_actions) >= 1

    def test_action_ids_use_d810ng_prefix(self):
        """All migrated actions should use d810ng: prefix."""
        # Check all registered actions
        migrated_action_names = {
            "DeobfuscateThisFunction",
            "DeobfuscationStats",
            "FunctionRules",
            "MarkDeobfuscated",
            "DecompileFunction",
            "ExportMicrocode",
            "ExportToC",
            "ExportDisasm",
        }

        for cls in D810ActionHandler.registry.values():
            if cls.__name__ in migrated_action_names:
                assert cls.ACTION_ID.startswith(
                    "d810ng:"
                ), f"Action {cls.__name__} uses wrong prefix: {cls.ACTION_ID}"

    def test_menu_order_set(self):
        """All migrated actions should have explicit MENU_ORDER."""
        migrated_action_names = {
            "DeobfuscateThisFunction",
            "DeobfuscationStats",
            "FunctionRules",
            "MarkDeobfuscated",
            "DecompileFunction",
            "ExportMicrocode",
            "ExportToC",
            "ExportDisasm",
        }

        for cls in D810ActionHandler.registry.values():
            if cls.__name__ in migrated_action_names:
                # Should have explicit order, not default 100
                assert (
                    cls.MENU_ORDER != 100
                ), f"Action {cls.__name__} should have explicit MENU_ORDER"

    def test_backward_compat_all_actions_list(self):
        """Legacy ALL_ACTIONS list should still work."""
        from d810.ui.pseudocode_actions import ALL_ACTIONS

        assert len(ALL_ACTIONS) == 4
        # All should have ACTION_ID
        for action_cls in ALL_ACTIONS:
            assert hasattr(action_cls, "ACTION_ID")
            assert action_cls.ACTION_ID

    def test_backward_compat_disasm_actions_list(self):
        """Legacy DISASM_ACTIONS list should still work."""
        from d810.ui.pseudocode_actions import DISASM_ACTIONS

        assert len(DISASM_ACTIONS) == 1
        # Should have ACTION_ID
        for action_cls in DISASM_ACTIONS:
            assert hasattr(action_cls, "ACTION_ID")
            assert action_cls.ACTION_ID
