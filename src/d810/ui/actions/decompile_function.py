"""Decompile function action.

Decompile the current function with D810ng active (from disassembly view).
"""
from __future__ import annotations

from d810.core import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

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
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        ida_funcs_mod = self.ida_module("ida_funcs")
        ida_hexrays_mod = self.ida_module("ida_hexrays")
        if ida_kernwin_mod is None or ida_funcs_mod is None or ida_hexrays_mod is None:
            return 0

        ea = ida_kernwin_mod.get_screen_ea()
        func = ida_funcs_mod.get_func(ea)
        if func is None:
            logger.warning("DecompileFunction: no function at cursor (%s)", hex(ea))
            ida_kernwin_mod.warning("No function at cursor")
            return 0

        func_ea = func.start_ea

        logger.info("Decompiling function at %s from disassembly view", hex(func_ea))

        # Trigger decompilation (D810ng hooks will run automatically)
        try:
            ida_hexrays_mod.decompile(func_ea)
            # Open the pseudocode window
            ida_hexrays_mod.open_pseudocode(func_ea, 0)
        except Exception as exc:
            logger.error("Failed to decompile function: %s", exc)
            ida_kernwin_mod.warning(f"Failed to decompile function:\n{exc}")
            return 0

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Enable only in disassembly view when cursor is in a function.

        Args:
            ctx: IDA action context

        Returns:
            True if in disassembly view and cursor is in a function
        """
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        ida_funcs_mod = self.ida_module("ida_funcs")
        idaapi_mod = self.ida_module("idaapi")
        if ida_kernwin_mod is None or ida_funcs_mod is None or idaapi_mod is None:
            return False

        # Check if we're in a disassembly view
        widget_type = idaapi_mod.get_widget_type(ctx.widget)
        if widget_type != idaapi_mod.BWN_DISASM:
            return False

        # Check if cursor is in a function
        ea = ida_kernwin_mod.get_screen_ea()
        func = ida_funcs_mod.get_func(ea)
        if func is None:
            return False

        return True
