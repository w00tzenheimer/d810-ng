"""Stop D810ng action.

Stops the D810ng deobfuscation engine.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_kernwin
    from d810.qt_shim import QTimer

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    QTimer = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


class StopD810ng(D810ActionHandler):
    """Stop the d810-ng deobfuscation engine."""

    ACTION_ID = "d810ng:stop"
    ACTION_TEXT = "Stop d810-ng"
    ACTION_TOOLTIP = "Stop the d810-ng deobfuscation engine"
    SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})
    MENU_ORDER = 210
    REQUIRES_STARTED = False
    SUBMENU = "Settings"

    def execute(self, ctx: typing.Any) -> int:
        """Execute the stop action.

        Uses deferred execution pattern to prevent state mutation while
        the action handler is still on the call stack.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if ida_kernwin is None or QTimer is None:
            return 0

        def _deferred_stop():
            """Deferred stop function executed after action handler returns."""
            try:
                logger.info("Executing deferred stop of d810-ng")
                self._state.stop_d810()
                # Update UI status indicator to show "Stopped"
                self._update_ui_after_stop()
                ida_kernwin.info("d810-ng stopped successfully")
                logger.info("d810-ng stopped via context menu action")
            except Exception as e:
                ida_kernwin.warning(f"Failed to stop d810-ng: {e}")
                logger.error("Failed to stop d810-ng: %s", e, exc_info=True)

        try:
            # Schedule stop to run after this action handler returns
            # This prevents state mutation while the handler is on the stack
            logger.info("Scheduling deferred d810-ng stop")
            QTimer.singleShot(0, _deferred_stop)
            return 1
        except Exception as e:
            ida_kernwin.warning(f"Failed to schedule stop: {e}")
            logger.error("Failed to schedule stop: %s", e, exc_info=True)
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            False if not started, True otherwise
        """
        # Disable if not started
        if hasattr(self._state, 'manager') and self._state.manager is not None:
            if not self._state.manager.started:
                return False
        return True

    def _update_ui_after_stop(self) -> None:
        """Update UI status indicator after d810-ng is stopped.

        Updates the status indicator circle in the config form to show red (stopped).
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
            # Update the status indicator to show "stopped" (red circle)
            config_form._update_status(loaded=False)
        else:
            logger.debug("Cannot update status: _update_status not found on form")
