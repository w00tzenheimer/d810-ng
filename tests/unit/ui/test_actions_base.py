"""Unit tests for D810 action framework base classes.

Tests the D810ActionHandler base class, Registrant integration, and
the auto-discovery mechanism.
"""
from __future__ import annotations

import typing
from unittest.mock import MagicMock

import pytest

from d810.ui.actions.base import D810ActionHandler


class TestD810ActionHandlerRegistry:
    """Test auto-registration via Registrant metaclass."""

    def test_action_handler_is_registrant(self):
        """D810ActionHandler should inherit from Registrant."""
        from d810.core.registry import Registrant
        assert issubclass(D810ActionHandler, Registrant)

    def test_action_handler_has_registry(self):
        """D810ActionHandler should have a registry dict."""
        assert hasattr(D810ActionHandler, "registry")
        assert isinstance(D810ActionHandler.registry, dict)

    def test_concrete_action_auto_registers(self):
        """Concrete action subclasses should auto-register."""
        # Clear any previous registrations for this test
        initial_count = len(D810ActionHandler.registry)

        # Define a concrete action
        class TestAction(D810ActionHandler):
            ACTION_ID = "d810ng:test_action"
            ACTION_TEXT = "Test Action"
            ACTION_TOOLTIP = "Test tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        # Should be registered
        assert len(D810ActionHandler.registry) == initial_count + 1
        # Registry uses lowercase keys by default
        assert "testaction" in D810ActionHandler.registry
        assert D810ActionHandler.registry["testaction"] is TestAction

    def test_multiple_actions_register(self):
        """Multiple action subclasses should all register."""
        initial_count = len(D810ActionHandler.registry)

        class Action1(D810ActionHandler):
            ACTION_ID = "d810ng:action1"
            ACTION_TEXT = "Action 1"
            ACTION_TOOLTIP = "First action"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        class Action2(D810ActionHandler):
            ACTION_ID = "d810ng:action2"
            ACTION_TEXT = "Action 2"
            ACTION_TOOLTIP = "Second action"
            SUPPORTED_VIEWS = frozenset({"disasm"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        # Verify both actions were registered
        assert len(D810ActionHandler.registry) == initial_count + 2
        assert "action1" in D810ActionHandler.registry
        assert "action2" in D810ActionHandler.registry
        assert D810ActionHandler.registry["action1"] is Action1
        assert D810ActionHandler.registry["action2"] is Action2


class TestD810ActionHandlerAttributes:
    """Test D810ActionHandler class attributes and validation."""

    def test_action_id_required(self):
        """ACTION_ID should be required on subclasses."""
        # Base class has empty ACTION_ID
        assert D810ActionHandler.ACTION_ID == ""

        # Subclass should provide it
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert MyAction.ACTION_ID == "d810ng:my_action"

    def test_supported_views_frozenset(self):
        """SUPPORTED_VIEWS should be a frozenset."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert isinstance(MyAction.SUPPORTED_VIEWS, frozenset)
        assert "pseudocode" in MyAction.SUPPORTED_VIEWS
        assert "disasm" in MyAction.SUPPORTED_VIEWS

    def test_menu_order_default(self):
        """MENU_ORDER should default to 100."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert MyAction.MENU_ORDER == 100

    def test_menu_order_override(self):
        """MENU_ORDER can be overridden."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})
            MENU_ORDER = 50

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert MyAction.MENU_ORDER == 50

    def test_requires_started_default(self):
        """REQUIRES_STARTED should default to False."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert MyAction.REQUIRES_STARTED is False

    def test_shortcut_default(self):
        """SHORTCUT should default to None."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert MyAction.SHORTCUT is None


class TestD810ActionHandlerDependencyInjection:
    """Test dependency injection of state."""

    def test_constructor_accepts_state(self):
        """Constructor should accept state parameter."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        mock_state = MagicMock()
        action = MyAction(mock_state)
        assert action._state is mock_state

    def test_state_accessible_in_execute(self):
        """State should be accessible in execute method."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                # Access state
                self._state.some_method()
                return 1

        mock_state = MagicMock()
        action = MyAction(mock_state)

        # Execute should be able to use state
        result = action.execute(MagicMock())
        assert result == 1
        mock_state.some_method.assert_called_once()


class TestD810ActionHandlerExecution:
    """Test action execution interface."""

    def test_execute_is_abstract(self):
        """Execute method should be abstract in base class."""
        # Python's ABC won't let us instantiate a class without implementing
        # abstract methods, so we test that defining a class without execute
        # raises a TypeError when we try to instantiate it
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})
            # Deliberately not implementing execute

        mock_state = MagicMock()

        # Should raise TypeError because execute is abstract
        with pytest.raises(TypeError, match="abstract method.*execute"):
            MyAction(mock_state)

    def test_execute_returns_int(self):
        """Execute should return int (1 for success, 0 for failure)."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        mock_state = MagicMock()
        action = MyAction(mock_state)
        result = action.execute(MagicMock())
        assert isinstance(result, int)
        assert result == 1

    def test_is_available_default(self):
        """is_available should default to True."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        mock_state = MagicMock()
        action = MyAction(mock_state)
        assert action.is_available(MagicMock()) is True

    def test_is_available_override(self):
        """is_available can be overridden for conditional availability."""
        class MyAction(D810ActionHandler):
            ACTION_ID = "d810ng:my_action"
            ACTION_TEXT = "My Action"
            ACTION_TOOLTIP = "My tooltip"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

            def is_available(self, ctx: typing.Any) -> bool:
                # Custom logic
                return self._state.is_ready()

        mock_state = MagicMock()
        mock_state.is_ready.return_value = True
        action = MyAction(mock_state)

        assert action.is_available(MagicMock()) is True
        mock_state.is_ready.assert_called_once()


class TestD810ActionHandlerNamingConvention:
    """Test that action IDs follow the d810ng: prefix convention."""

    def test_action_id_should_use_d810ng_prefix(self):
        """Action IDs should use d810ng: prefix, not d810:."""
        class GoodAction(D810ActionHandler):
            ACTION_ID = "d810ng:good_action"
            ACTION_TEXT = "Good Action"
            ACTION_TOOLTIP = "Uses correct prefix"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        assert GoodAction.ACTION_ID.startswith("d810ng:")

        # Bad example (should be avoided in real code)
        class BadAction(D810ActionHandler):
            ACTION_ID = "d810:bad_action"  # Wrong prefix
            ACTION_TEXT = "Bad Action"
            ACTION_TOOLTIP = "Uses old prefix"
            SUPPORTED_VIEWS = frozenset({"pseudocode"})

            def execute(self, ctx: typing.Any) -> int:
                return 1

        # Just document that this is wrong - can't enforce at runtime
        # without adding validation logic
        assert not BadAction.ACTION_ID.startswith("d810ng:")
