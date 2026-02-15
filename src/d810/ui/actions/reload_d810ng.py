"""Reload D810ng action.

Hot-reloads the D810ng plugin code.
"""
from __future__ import annotations

from d810.core import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

try:
    from d810.qt_shim import QTimer
except ImportError:
    QTimer = None  # type: ignore[assignment]


class ReloadD810ng(D810ActionHandler):
    """Hot-reload the d810-ng plugin code."""

    ACTION_ID = "d810ng:reload"
    ACTION_TEXT = "Reload d810-ng"
    ACTION_TOOLTIP = "Hot-reload the d810-ng plugin code"
    SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})
    MENU_ORDER = 220
    REQUIRES_STARTED = False
    SUBMENU = "Settings"

    def execute(self, ctx: typing.Any) -> int:
        """Execute the reload action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        idaapi_mod = self.ida_module("idaapi")
        if ida_kernwin_mod is None or idaapi_mod is None or QTimer is None:
            return 0

        def _deferred_reload():
            """Deferred reload function executed after action handler returns."""
            try:
                # Try to get the plugin instance directly
                plugin = idaapi_mod.find_plugin("D810", True)
                if plugin and hasattr(plugin, 'reload'):
                    logger.info("Executing deferred reload of d810-ng plugin")
                    plugin.reload()
                    ida_kernwin_mod.info("d810-ng reloaded successfully")
                    logger.info("d810-ng reloaded via context menu action")
                else:
                    # Fallback: try to trigger via action
                    result = ida_kernwin_mod.process_ui_action("D810:reload_plugin")
                    if result:
                        ida_kernwin_mod.info("d810-ng reloaded successfully")
                        logger.info("d810-ng reloaded via action")
                    else:
                        ida_kernwin_mod.warning("Failed to trigger reload action")
                        logger.warning("Failed to trigger reload action")
            except Exception as e:
                ida_kernwin_mod.warning(f"Failed to reload d810-ng: {e}")
                logger.error("Failed to reload d810-ng: %s", e, exc_info=True)

        try:
            # Schedule reload to run after this action handler returns
            # This prevents reloading the module while it's executing
            logger.info("Scheduling deferred d810-ng plugin reload")
            QTimer.singleShot(0, _deferred_reload)
            return 1
        except Exception as e:
            ida_kernwin_mod.warning(f"Failed to schedule reload: {e}")
            logger.error("Failed to schedule reload: %s", e, exc_info=True)
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            Always True - reload is always available
        """
        return True
