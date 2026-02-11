"""Integration tests for the D810 action framework.

Tests the full flow from action definition to registration and discovery.
"""
from __future__ import annotations

import typing
from unittest.mock import MagicMock

import pytest

from d810.ui.actions import D810ActionHandler


class TestActionFrameworkIntegration:
    """Test the complete action framework integration."""

    def test_action_registration_and_discovery(self):
        """Test that actions register and can be discovered."""
        # Start with initial registry state
        initial_count = len(D810ActionHandler.registry)

        # Define two test actions
        class PseudocodeAction(D810ActionHandler):
            ACTION_ID = "d810ng:test_pseudocode"
            ACTION_TEXT = "Test Pseudocode"
            ACTION_TOOLTIP = "Test pseudocode action"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})
            MENU_ORDER = 10

            def execute(self, ctx: typing.Any) -> int:
                return 1

        class DisasmAction(D810ActionHandler):
            ACTION_ID = "d810ng:test_disasm"
            ACTION_TEXT = "Test Disasm"
            ACTION_TOOLTIP = "Test disasm action"
            SUPPORTED_VIEWS = frozenset({"disasm"})
            MENU_ORDER = 20

            def execute(self, ctx: typing.Any) -> int:
                return 1

        # Verify registration
        assert len(D810ActionHandler.registry) == initial_count + 2

        # Filter by view type (simulating what context_menu.py does)
        all_actions = list(D810ActionHandler.registry.values())
        pseudocode_actions = [
            cls for cls in all_actions
            if "pseudocode" in cls.SUPPORTED_VIEWS
        ]
        disasm_actions = [
            cls for cls in all_actions
            if "disasm" in cls.SUPPORTED_VIEWS
        ]

        assert len(pseudocode_actions) >= 1
        assert len(disasm_actions) >= 1
        assert PseudocodeAction in pseudocode_actions
        assert DisasmAction in disasm_actions

    def test_menu_ordering(self):
        """Test that actions can be sorted by MENU_ORDER."""
        class Action1(D810ActionHandler):
            ACTION_ID = "d810ng:order1"
            ACTION_TEXT = "Order 1"
            ACTION_TOOLTIP = "First"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})
            MENU_ORDER = 30

            def execute(self, ctx: typing.Any) -> int:
                return 1

        class Action2(D810ActionHandler):
            ACTION_ID = "d810ng:order2"
            ACTION_TEXT = "Order 2"
            ACTION_TOOLTIP = "Second"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})
            MENU_ORDER = 10

            def execute(self, ctx: typing.Any) -> int:
                return 1

        class Action3(D810ActionHandler):
            ACTION_ID = "d810ng:order3"
            ACTION_TEXT = "Order 3"
            ACTION_TOOLTIP = "Third"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})
            MENU_ORDER = 20

            def execute(self, ctx: typing.Any) -> int:
                return 1

        # Get all actions and sort by MENU_ORDER
        all_actions = list(D810ActionHandler.registry.values())
        sorted_actions = sorted(all_actions, key=lambda cls: cls.MENU_ORDER)

        # Find our test actions in the sorted list
        test_actions = [Action1, Action2, Action3]
        sorted_test_actions = [
            action for action in sorted_actions
            if action in test_actions
        ]

        # Verify they're in order by MENU_ORDER (10, 20, 30)
        assert sorted_test_actions == [Action2, Action3, Action1]

    def test_multi_view_action(self):
        """Test that an action can support multiple views."""
        class MultiViewAction(D810ActionHandler):
            ACTION_ID = "d810ng:multi_view"
            ACTION_TEXT = "Multi View"
            ACTION_TOOLTIP = "Works in both views"
            SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        all_actions = list(D810ActionHandler.registry.values())

        # Should appear in both filtered lists
        pseudocode_actions = [
            cls for cls in all_actions
            if "pseudocode" in cls.SUPPORTED_VIEWS
        ]
        disasm_actions = [
            cls for cls in all_actions
            if "disasm" in cls.SUPPORTED_VIEWS
        ]

        assert MultiViewAction in pseudocode_actions
        assert MultiViewAction in disasm_actions

    def test_action_instantiation_with_state(self):
        """Test that actions can be instantiated with state."""
        class TestAction(D810ActionHandler):
            ACTION_ID = "d810ng:instantiate_test"
            ACTION_TEXT = "Instantiate Test"
            ACTION_TOOLTIP = "Test instantiation"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                # Use state
                return 1 if self._state.is_ready() else 0

        # Create mock state
        mock_state = MagicMock()
        mock_state.is_ready.return_value = True

        # Instantiate action
        action = TestAction(mock_state)
        assert action._state is mock_state

        # Execute action
        result = action.execute(MagicMock())
        assert result == 1
        mock_state.is_ready.assert_called_once()

    def test_backward_compatibility_with_old_actions(self):
        """Test that the framework doesn't break existing pseudocode_actions.py."""
        # Import the old actions module
        from d810.ui.pseudocode_actions import ALL_ACTIONS, DISASM_ACTIONS

        # Verify old actions still exist
        assert len(ALL_ACTIONS) > 0
        assert len(DISASM_ACTIONS) > 0

        # Old actions should have the required attributes
        for action_cls in ALL_ACTIONS:
            assert hasattr(action_cls, "ACTION_ID")
            assert hasattr(action_cls, "ACTION_TEXT")
            assert hasattr(action_cls, "ACTION_TOOLTIP")

    def test_action_filtering_excludes_wrong_view(self):
        """Test that view filtering excludes actions from wrong view."""
        class PseudocodeOnlyAction(D810ActionHandler):
            ACTION_ID = "d810ng:pseudo_only"
            ACTION_TEXT = "Pseudocode Only"
            ACTION_TOOLTIP = "Only in pseudocode"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        all_actions = list(D810ActionHandler.registry.values())

        # Filter for disasm - should NOT include PseudocodeOnlyAction
        disasm_actions = [
            cls for cls in all_actions
            if "disasm" in cls.SUPPORTED_VIEWS
        ]

        assert PseudocodeOnlyAction not in disasm_actions
