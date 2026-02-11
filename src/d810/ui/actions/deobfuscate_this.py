"""Deobfuscate this function action.

Re-decompiles the current function with D810ng optimizations active.
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
    import ida_hexrays
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
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


class DeobfuscateThisFunction(D810ActionHandler):
    """Re-decompile the current function with d810-ng active."""

    ACTION_ID = "d810ng:deobfuscate_this"
    ACTION_TEXT = "Deobfuscate this function"
    ACTION_TOOLTIP = "Re-decompile the current function with d810-ng optimizations"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 10
    REQUIRES_STARTED = True

    def execute(self, ctx: typing.Any) -> int:
        """Execute the deobfuscate action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if ida_hexrays is None or ida_kernwin is None:
            return 0

        func_ea = _get_current_func_ea(ctx)
        if func_ea is None:
            logger.warning("DeobfuscateThisFunction: could not determine function EA")
            return 0

        logger.info("Triggering re-decompilation for function at %s", hex(func_ea))

        # Force a refresh of the pseudocode view, which re-runs the
        # decompiler (and therefore all installed D-810 hooks).
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if vdui is not None:
            vdui.refresh_view(True)
        else:
            ida_hexrays.decompile(func_ea)

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
