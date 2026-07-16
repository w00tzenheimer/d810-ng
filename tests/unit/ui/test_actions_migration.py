"""Tests for Phase 2 action migration.

Verifies that all 8 actions are properly migrated to the new framework
and registered in the D810ActionHandler registry.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from d810.ui.actions import D810ActionHandler, load_builtin_actions
from d810.ui.actions.deobfuscation_stats import DeobfuscationStats

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


def test_stats_compatibility_action_opens_evidence_focused_workbench(
    monkeypatch,
) -> None:
    created: list[object] = []

    class FakePanel:
        def __init__(self, state) -> None:
            self.state = state
            self._closed = False
            self.function_calls: list[tuple[int | None, str | None, str | None]] = []
            self.show_calls: list[str | None] = []
            self.command_adapters: list[object] = []
            created.append(self)

        def set_function(self, func_ea, func_name, fingerprint=None) -> None:
            self.function_calls.append((func_ea, func_name, fingerprint))

        def show(self, focus_section=None) -> bool:
            self.show_calls.append(focus_section)
            return True

        def set_command_adapter(self, adapter) -> None:
            self.command_adapters.append(adapter)

    class LegacyPanel(FakePanel):
        pass

    workbench_module = ModuleType("d810.ui.workbench_panel")
    workbench_module.DeobfuscationWorkbenchPanel = FakePanel
    legacy_module = ModuleType("d810.ui.stats_dialog")
    legacy_module.DeobfuscationStatsPanel = LegacyPanel
    monkeypatch.setitem(sys.modules, "d810.ui.workbench_panel", workbench_module)
    monkeypatch.setitem(sys.modules, "d810.ui.stats_dialog", legacy_module)

    idaapi = SimpleNamespace(
        get_widget_vdui=lambda widget: SimpleNamespace(
            cfunc=SimpleNamespace(entry_ea=0x401000)
        ),
        get_func=lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 4),
        get_func_name=lambda ea: "target",
        get_bytes=lambda start, size: b"abcd",
        warning=lambda message: None,
        info=lambda message: None,
    )
    stats = SimpleNamespace(last_report=lambda: {})
    state = SimpleNamespace(manager=SimpleNamespace(stats=stats))
    action = DeobfuscationStats(state, ida_modules={"idaapi": idaapi})
    ctx = SimpleNamespace(widget=object())
    DeobfuscationStats._panel = None

    assert DeobfuscationStats.ACTION_ID == "d810ng:deobfuscation_stats"
    assert action.execute(ctx) == 1
    first = DeobfuscationStats._panel
    assert type(first) is FakePanel
    assert first.function_calls == [
        (
            0x401000,
            "target",
            "sha256:88d4266fd4e6338d13b845fcf289579d"
            "209c897823b9217da3e161936f031589",
        )
    ]
    assert first.show_calls == ["evidence"]
    assert len(first.command_adapters) == 1
    adapter = first.command_adapters[0]
    assert adapter._state is state
    assert adapter._idaapi is idaapi
    assert adapter._ctx is ctx

    first._closed = True
    assert action.execute(ctx) == 1
    second = DeobfuscationStats._panel
    assert type(second) is FakePanel
    assert second is not first
    assert len(created) == 2
    DeobfuscationStats._panel = None


def test_stats_action_teardown_closes_and_releases_workbench_panel() -> None:
    class FakePanel:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    panel = FakePanel()
    state = SimpleNamespace(manager=object())
    action = DeobfuscationStats(state, ida_modules={})
    DeobfuscationStats._panel = panel

    action.term()

    assert panel.close_calls == 1
    assert DeobfuscationStats._panel is None
    action.term()
    assert panel.close_calls == 1
