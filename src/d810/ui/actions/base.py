"""Base class for D810ng context menu action handlers.

This module provides the foundation for the action framework, enabling
auto-discovery of action handlers via the Registrant metaclass.
"""
from __future__ import annotations

import typing
from abc import abstractmethod

from d810.core.registry import Registrant

if typing.TYPE_CHECKING:
    from d810.manager import D810State


class D810ActionHandler(Registrant):
    """Base class for D810ng context menu action handlers.

    All action handlers must subclass this and provide the required class
    attributes. The Registrant metaclass automatically registers subclasses
    in the `D810ActionHandler.registry` for auto-discovery.

    Deferred Execution Pattern:
        Actions that mutate plugin state (start/stop/reload) MUST use the
        deferred execution pattern to prevent state mutation while the action
        handler is still on the call stack:

            from d810.qt_shim import QTimer

            def execute(self, ctx) -> int:
                def _deferred_work():
                    # Actual state mutation happens here
                    self._state.start_d810()
                    ida_kernwin.info("Operation completed")

                # Schedule work for next event loop tick
                QTimer.singleShot(0, _deferred_work)
                return 1

        This pattern is critical for IDA stability - without it, actions that
        modify plugin state can crash IDA when triggered from context menus.

    Class Attributes (mandatory on subclasses):
        ACTION_ID: str
            Unique identifier for the action (e.g., "d810ng:deobfuscate_this")
        ACTION_TEXT: str
            Display text shown in the context menu
        ACTION_TOOLTIP: str
            Tooltip text shown on hover
        SUPPORTED_VIEWS: frozenset[str]
            Set of view types this action supports: {"pseudocode"}, {"disasm"}, or both
        MENU_ORDER: int
            Display order in menu (lower values appear first, default 100)
        REQUIRES_STARTED: bool
            Whether D810ng must be started for this action to be enabled (default False)
        SHORTCUT: str | None
            Keyboard shortcut string (e.g., "Ctrl+D"), or None for no shortcut
        SUBMENU: str | None
            Optional submenu name (e.g., "Settings") to group actions, or None for root level

    Example:
        >>> class MyAction(D810ActionHandler):
        ...     ACTION_ID = "d810ng:my_action"
        ...     ACTION_TEXT = "My Action"
        ...     ACTION_TOOLTIP = "Does something useful"
        ...     SUPPORTED_VIEWS = frozenset({"pseudocode"})
        ...     MENU_ORDER = 50
        ...
        ...     def execute(self, ctx) -> int:
        ...         # Implement action logic
        ...         return 1
    """

    # Class attributes that subclasses MUST override
    ACTION_ID: str = ""
    ACTION_TEXT: str = ""
    ACTION_TOOLTIP: str = ""
    SUPPORTED_VIEWS: frozenset[str] = frozenset()

    # Optional class attributes with defaults
    MENU_ORDER: int = 100
    REQUIRES_STARTED: bool = False
    SHORTCUT: str | None = None
    SUBMENU: str | None = None

    def __init__(self, state: "D810State") -> None:
        """Initialize action handler with dependency injection.

        Args:
            state: The D810State instance providing access to plugin state,
                manager, configuration, etc.
        """
        self._state = state

    @abstractmethod
    def execute(self, ctx: typing.Any) -> int:
        """Execute the action when triggered by the user.

        This method is called when the user selects this action from the
        context menu. Implementations should perform the action-specific
        logic and return 1 on success, 0 on failure.

        Args:
            ctx: IDA action context (ida_kernwin.action_ctx_base_t) containing
                widget information and cursor position.

        Returns:
            1 if the action was successful, 0 otherwise.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.execute() must be implemented"
        )

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if the action should be enabled in the current context.

        Subclasses can override this to implement context-specific availability
        checks. The default implementation returns True (always available).

        Args:
            ctx: IDA action context (ida_kernwin.action_ctx_base_t)

        Returns:
            True if the action should be enabled, False to grey it out.
        """
        return True
