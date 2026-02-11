"""Decompile function action.

Decompile the current function with D810ng active (from disassembly view).
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
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import idaapi

    IDA_AVAILABLE = True
except ImportError:
    ida_funcs = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


class DecompileFunction(D810ActionHandler):
    """Decompile the current function with d810-ng active (from disassembly view)."""

    ACTION_ID = "d810ng:decompile_function"
    ACTION_TEXT = "Decompile function"
    ACTION_TOOLTIP = "Decompile the current function with d810-ng optimizations"
    SUPPORTED_VIEWS = frozenset({"disasm"})
    MENU_ORDER = 10

    def execute(self, ctx: typing.Any) -> int:
        """Execute the decompile function action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        # Get the current function from the disassembly cursor
        if ida_kernwin is None or ida_funcs is None or ida_hexrays is None:
            return 0

        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            logger.warning("DecompileFunction: no function at cursor (%s)", hex(ea))
            ida_kernwin.warning("No function at cursor")
            return 0

        func_ea = func.start_ea

        logger.info("Decompiling function at %s from disassembly view", hex(func_ea))

        # Trigger decompilation (D810ng hooks will run automatically)
        try:
            ida_hexrays.decompile(func_ea)
            # Open the pseudocode window
            ida_hexrays.open_pseudocode(func_ea, 0)
        except Exception as exc:
            logger.error("Failed to decompile function: %s", exc)
            ida_kernwin.warning(f"Failed to decompile function:\n{exc}")
            return 0

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Enable only in disassembly view when cursor is in a function.

        Args:
            ctx: IDA action context

        Returns:
            True if in disassembly view and cursor is in a function
        """
        if ida_kernwin is None or ida_funcs is None or idaapi is None:
            return False

        # Check if we're in a disassembly view
        widget_type = idaapi.get_widget_type(ctx.widget)
        if widget_type != idaapi.BWN_DISASM:
            return False

        # Check if cursor is in a function
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            return False

        return True
