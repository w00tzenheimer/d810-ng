"""IDA action handler adapter for D810 action handlers.

This module provides the glue between D810ActionHandler instances and IDA's
action system by creating ida_kernwin.action_handler_t wrappers.
"""
from __future__ import annotations

from d810.core import typing

from d810.core.logging import getLogger

if typing.TYPE_CHECKING:
    from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

def make_ida_handler(
    action: "D810ActionHandler",
    ida_kernwin_module: typing.Any | None = None,
) -> typing.Any:
    """Create an IDA action_handler_t wrapper for a D810ActionHandler.

    This adapter allows D810ActionHandler instances to be registered with
    IDA's action system without requiring them to directly inherit from
    ida_kernwin.action_handler_t.

    The adapter:
    - Delegates activate() to action.execute()
    - Delegates update() to action.is_available()
    - Checks REQUIRES_STARTED and prompts to start d810-ng if needed

    Args:
        action: The D810ActionHandler instance to wrap

    Returns:
        An ida_kernwin.action_handler_t instance (or a stub if IDA unavailable)

    Example:
        >>> handler = MyAction(state)
        >>> ida_handler = make_ida_handler(handler)
        >>> desc = ida_kernwin.action_desc_t(
        ...     handler.ACTION_ID,
        ...     handler.ACTION_TEXT,
        ...     ida_handler,
        ...     handler.SHORTCUT
        ... )
        >>> ida_kernwin.register_action(desc)
    """
    ida_kernwin_mod = ida_kernwin_module
    if ida_kernwin_mod is None and hasattr(action, "ida_module"):
        ida_kernwin_mod = action.ida_module("ida_kernwin")

    if ida_kernwin_mod is None:
        # Return a stub when IDA is not available (e.g., during unit tests)
        return _StubIDAHandler()

    class _IDAHandlerAdapter(ida_kernwin_mod.action_handler_t):
        """Adapter that wraps a D810ActionHandler for IDA's action system."""

        def __init__(self, handler: "D810ActionHandler") -> None:
            super().__init__()
            self._handler = handler

        def activate(self, ctx: typing.Any) -> int:
            """Handle action activation (user clicked the menu item).

            Args:
                ctx: IDA action context (action_ctx_base_t)

            Returns:
                1 if handled successfully, 0 otherwise
            """
            # Check if d810-ng needs to be started
            if self._handler.REQUIRES_STARTED:
                is_ready, error_msg = self._check_started()
                if not is_ready:
                    # Prompt user to start d810-ng
                    if self._prompt_to_start():
                        # User accepted, d810-ng is now started
                        pass
                    else:
                        # User declined or start failed
                        return 0

            # Execute the action
            try:
                return self._handler.execute(ctx)
            except Exception as exc:
                logger.error(
                    "Action %s failed: %s",
                    self._handler.ACTION_ID,
                    exc,
                    exc_info=True,
                )
                if ida_kernwin_mod is not None:
                    ida_kernwin_mod.warning(
                        f"Action failed:\n{exc}"
                    )
                return 0

        def update(self, ctx: typing.Any) -> int:
            """Update action state (enable/disable).

            Args:
                ctx: IDA action context (action_ctx_base_t)

            Returns:
                AST_ENABLE_FOR_WIDGET or AST_DISABLE
            """
            if ida_kernwin_mod is None:
                return 0

            # Check if action is available in this context
            if not self._handler.is_available(ctx):
                return ida_kernwin_mod.AST_DISABLE

            return ida_kernwin_mod.AST_ENABLE_FOR_WIDGET

        def _check_started(self) -> tuple[bool, str]:
            """Check if d810-ng is started.

            Returns:
                Tuple of (is_started, error_message)
            """
            state = self._handler._state
            if state is None:
                return False, "d810-ng is not loaded."

            if not state.is_loaded():
                return False, "d810-ng is not loaded."

            if hasattr(state, "manager") and state.manager is not None:
                if not state.manager.started:
                    return False, "d810-ng is not started."

            return True, ""

        def _prompt_to_start(self) -> bool:
            """Prompt user to start d810-ng if not already started.

            Returns:
                True if d810-ng was started (or already running), False otherwise
            """
            if ida_kernwin_mod is None:
                return False

            state = self._handler._state

            # Check if loaded but not started
            if state and state.is_loaded():
                if hasattr(state, "manager") and state.manager is not None:
                    if not state.manager.started:
                        # Prompt user
                        result = ida_kernwin_mod.ask_yn(
                            ida_kernwin_mod.ASKBTN_YES,
                            "d810-ng is not running. Start d810-ng?"
                        )
                        if result == ida_kernwin_mod.ASKBTN_YES:
                            try:
                                state.start_d810()
                                logger.info("d810-ng started by user request")
                                # Update UI status indicator if GUI is available
                                self._update_ui_after_start(state)
                                return True
                            except Exception as exc:
                                logger.error("Failed to start d810-ng: %s", exc)
                                ida_kernwin_mod.warning(f"Failed to start d810-ng:\n{exc}")
                                return False
                        else:
                            # User declined
                            return False
                    else:
                        # Already started
                        return True

            # Not loaded or manager not initialized
            is_ready, error_msg = self._check_started()
            if not is_ready:
                ida_kernwin_mod.warning(error_msg)
            return is_ready

        def _update_ui_after_start(self, state) -> None:
            """Update UI status indicator after d810-ng is started.

            Args:
                state: The D810State instance
            """
            if not hasattr(state, "gui") or state.gui is None:
                logger.debug("Cannot update status indicator: gui not available")
                return
            gui = state.gui
            if not hasattr(gui, "d810_config_form") or gui.d810_config_form is None:
                logger.debug("Cannot update status indicator: config form not available")
                return
            config_form = gui.d810_config_form
            if hasattr(config_form, "_update_status"):
                config_form._update_status(loaded=True)
            else:
                logger.debug("Cannot update status: _update_status not found on form")

    return _IDAHandlerAdapter(action)


class _StubIDAHandler:
    """Stub handler for when IDA is not available (testing)."""

    def activate(self, ctx: typing.Any) -> int:
        return 0

    def update(self, ctx: typing.Any) -> int:
        return 0
