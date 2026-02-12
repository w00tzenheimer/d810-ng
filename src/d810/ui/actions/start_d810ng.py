"""Start D810ng action.

Starts the D810ng deobfuscation engine.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

try:
    from d810.qt_shim import QTimer
except ImportError:
    QTimer = None  # type: ignore[assignment]


class StartD810ng(D810ActionHandler):
    """Start the d810-ng deobfuscation engine."""

    ACTION_ID = "d810ng:start"
    ACTION_TEXT = "Start d810-ng"
    ACTION_TOOLTIP = "Start the d810-ng deobfuscation engine"
    SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})
    MENU_ORDER = 200
    REQUIRES_STARTED = False
    SUBMENU = "Settings"

    def execute(self, ctx: typing.Any) -> int:
        """Execute the start action.

        Uses deferred execution pattern to prevent state mutation while
        the action handler is still on the call stack.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        if ida_kernwin_mod is None or QTimer is None:
            return 0

        def _deferred_start():
            """Deferred start function executed after action handler returns."""
            try:
                logger.info("Executing deferred start of d810-ng")
                self._state.start_d810()
                # Update UI status indicator to show "Loaded"
                self._update_ui_after_start()
                ida_kernwin_mod.info("d810-ng started successfully")
                logger.info("d810-ng started via context menu action")
            except Exception as e:
                ida_kernwin_mod.warning(f"Failed to start d810-ng: {e}")
                logger.error("Failed to start d810-ng: %s", e, exc_info=True)

        try:
            # Schedule start to run after this action handler returns
            # This prevents state mutation while the handler is on the stack
            logger.info("Scheduling deferred d810-ng start")
            QTimer.singleShot(0, _deferred_start)
            return 1
        except Exception as e:
            ida_kernwin_mod.warning(f"Failed to schedule start: {e}")
            logger.error("Failed to schedule start: %s", e, exc_info=True)
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            False if already started, True otherwise
        """
        # Disable if already started
        if hasattr(self._state, 'manager') and self._state.manager is not None:
            if self._state.manager.started:
                return False
        return True

    def _update_ui_after_start(self) -> None:
        """Update UI status indicator after d810-ng is started.

        Updates the status indicator circle in the config form to show green (running).
        """
        if not hasattr(self._state, "gui") or self._state.gui is None:
            logger.debug("Cannot update status: gui not available on state")
            return
        gui = self._state.gui
        if not hasattr(gui, "d810_config_form") or gui.d810_config_form is None:
            logger.debug("Cannot update status: config form not available")
            return
        config_form = gui.d810_config_form
        if hasattr(config_form, "_update_status"):
            # Update the status indicator to show "running" (green circle)
            config_form._update_status(loaded=True)
        else:
            logger.debug("Cannot update status: _update_status not found on form")
