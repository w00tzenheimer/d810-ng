"""Deobfuscate this function action.

Re-decompiles the current function with D810ng optimizations active.
"""
from __future__ import annotations

from d810.core import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

def _get_current_func_ea(ctx: typing.Any, idaapi_shim: typing.Any) -> int | None:
    """Extract the entry-point EA of the function from the context.

    Args:
        ctx: IDA action context

    Returns:
        Function entry EA, or None if not in a function
    """
    vdui = idaapi_shim.get_widget_vdui(ctx.widget)
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
        idaapi_shim = self.ida_module("idaapi")
        if idaapi_shim is None:
            return 0

        func_ea = _get_current_func_ea(ctx, idaapi_shim)
        if func_ea is None:
            logger.warning("DeobfuscateThisFunction: could not determine function EA")
            return 0

        logger.info("Triggering re-decompilation for function at %s", hex(func_ea))

        # Force a refresh of the pseudocode view, which re-runs the
        # decompiler (and therefore all installed D-810 hooks).
        vdui = idaapi_shim.get_widget_vdui(ctx.widget)
        if vdui is not None:
            vdui.refresh_view(True)
        else:
            idaapi_shim.decompile(func_ea)

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view, False otherwise
        """
        idaapi_shim = self.ida_module("idaapi")
        if idaapi_shim is None:
            return False

        return idaapi_shim.get_widget_vdui(ctx.widget) is not None
