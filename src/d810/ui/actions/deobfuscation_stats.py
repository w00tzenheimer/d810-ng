"""Deobfuscation statistics action.

Shows a dialog with rule-fire counts for the last decompilation.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler
from d810.ui.actions_logic import (
    format_stats_for_display,
    get_deobfuscation_stats,
)

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_funcs
    import ida_hexrays
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_funcs = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


def _get_current_func_ea(ctx: typing.Any) -> int | None:
    """Extract the entry-point EA of the function from the context.

    Args:
        ctx: IDA action context

    Returns:
        Function entry EA, or None if not in a function
    """
    if ida_hexrays is None:
        return None

    vdui = ida_hexrays.get_widget_vdui(ctx.widget)
    if vdui is not None:
        return vdui.cfunc.entry_ea

    return None


class DeobfuscationStats(D810ActionHandler):
    """Show a dialog with rule-fire counts for the last decompilation."""

    ACTION_ID = "d810ng:deobfuscation_stats"
    ACTION_TEXT = "Deobfuscation stats..."
    ACTION_TOOLTIP = "Show deobfuscation statistics for the last run"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 20

    # Singleton panel instance
    _panel: typing.Any = None

    def execute(self, ctx: typing.Any) -> int:
        """Execute the stats action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if ida_kernwin is None:
            return 0

        # Check if plugin is ready (manager initialized)
        if not hasattr(self._state, "manager") or self._state.manager is None:
            ida_kernwin.warning("d810-ng manager is not initialized.")
            return 0

        # Get the current function EA and name
        func_ea = _get_current_func_ea(ctx)
        func_name = None
        if func_ea is not None and ida_funcs is not None:
            func = ida_funcs.get_func(func_ea)
            if func is not None:
                func_name = ida_funcs.get_func_name(func_ea)

        # Get stats from manager
        stats = get_deobfuscation_stats(self._state.manager)

        # Log stats in old text format for debugging
        formatted = format_stats_for_display(
            stats, func_ea=func_ea, func_name=func_name
        )
        logger.debug("Stats:\n%s", formatted)

        # Show stats in dockable panel (singleton)
        try:
            from d810.ui.stats_dialog import DeobfuscationStatsPanel

            # If panel was closed by IDA, discard it and create fresh
            cls = DeobfuscationStats
            if cls._panel is not None and getattr(cls._panel, '_closed', False):
                cls._panel = None

            # Create panel on first use
            if cls._panel is None:
                cls._panel = DeobfuscationStatsPanel(self._state)

            # Update function context and show (CTO pattern)
            cls._panel.set_function(func_ea, func_name)
            cls._panel.show()
        except ImportError:
            # Fallback to simple message if IDA not available
            ida_kernwin.info(formatted)

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view, False otherwise
        """
        if ida_hexrays is None:
            return False

        return ida_hexrays.get_widget_vdui(ctx.widget) is not None
