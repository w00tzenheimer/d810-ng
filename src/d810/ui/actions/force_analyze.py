"""Force analysis action.

Re-analyzes the current function or a selected range and refreshes the
Hex-Rays decompiler output.
"""
from __future__ import annotations

from d810.core import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")


class ForceAnalyze(D810ActionHandler):
    """Force analysis of the current function or selected range."""

    ACTION_ID = "d810ng:force_analyze"
    ACTION_TEXT = "Force Analyze"
    ACTION_TOOLTIP = "Force re-analysis of the current function or selection"
    SUPPORTED_VIEWS = frozenset({"disasm"})
    MENU_ORDER = 30

    def execute(self, ctx: typing.Any) -> int:
        idaapi_mod = self.ida_module("idaapi")
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        ida_funcs_mod = self.ida_module("ida_funcs")
        ida_auto_mod = self.ida_module("ida_auto")
        ida_bytes_mod = self.ida_module("ida_bytes")
        ida_hexrays_mod = self.ida_module("ida_hexrays")
        ida_problems_mod = self.ida_module("ida_problems")

        if (
            idaapi_mod is None
            or ida_kernwin_mod is None
            or ida_funcs_mod is None
            or ida_bytes_mod is None
        ):
            return 0

        def _auto_wait() -> None:
            if ida_auto_mod is not None:
                ida_auto_mod.auto_wait()
            elif hasattr(idaapi_mod, "auto_wait"):
                idaapi_mod.auto_wait()

        def _delete_and_recreate_function(func_start: int, func_end: int) -> None:
            size = func_end - func_start
            ida_bytes_mod.del_items(func_start, 0, size)
            for offset in range(size):
                idaapi_mod.create_insn(func_start + offset)
            ida_funcs_mod.add_func(func_start, func_end)
            _auto_wait()

        def _decompile_function(func_start: int) -> None:
            if ida_hexrays_mod is None:
                return
            _auto_wait()
            try:
                ida_hexrays_mod.mark_cfunc_dirty(func_start, False)
            except Exception:  # pragma: no cover - IDA API variability
                pass
            try:
                if hasattr(ida_hexrays_mod, "hexrays_failure_t"):
                    hf = ida_hexrays_mod.hexrays_failure_t()
                    ida_hexrays_mod.decompile_func(ida_funcs_mod.get_func(func_start), hf)
                else:
                    ida_hexrays_mod.decompile(func_start)
            except Exception as exc:
                logger.warning("ForceAnalyze: decompile failed at %s: %s", hex(func_start), exc)
            _auto_wait()

        def _reset_problems(func_start: int, func_end: int) -> None:
            if ida_problems_mod is None:
                return
            current = func_start
            while current != func_end:
                ida_problems_mod.forget_problem(ida_problems_mod.PR_DISASM, current)
                current += 1

        ea = ida_kernwin_mod.get_screen_ea()
        func = ida_funcs_mod.get_func(ea)
        if func is not None:
            start_ea = func.start_ea
            end_ea = func.end_ea
        else:
            viewer = None
            if hasattr(ida_kernwin_mod, "get_current_viewer"):
                viewer = ida_kernwin_mod.get_current_viewer()
            elif hasattr(idaapi_mod, "get_current_viewer"):
                viewer = idaapi_mod.get_current_viewer()

            is_selected = False
            start_ea = idaapi_mod.BADADDR
            end_ea = idaapi_mod.BADADDR
            if viewer is not None and hasattr(idaapi_mod, "read_range_selection"):
                is_selected, start_ea, end_ea = idaapi_mod.read_range_selection(viewer)

            if is_selected and start_ea != idaapi_mod.BADADDR and end_ea != idaapi_mod.BADADDR:
                ea = start_ea
            else:
                start_ea = ea
                ida_kernwin_mod.msg("d810-ng: No range selected.\n")
                end_ea = ida_kernwin_mod.ask_addr(
                    start_ea, "Enter end address for selection:"
                )
                if end_ea is None or end_ea == idaapi_mod.BADADDR:
                    ida_kernwin_mod.msg("d810-ng: Selection cancelled.\n")
                    return 0
                if end_ea <= start_ea:
                    ida_kernwin_mod.warning("End address must be greater than start address.")
                    return 0
            ida_kernwin_mod.msg(
                "d810-ng: Selection start 0x%X, end 0x%X (user-defined)\n"
                % (start_ea, end_ea)
            )

        try:
            _delete_and_recreate_function(start_ea, end_ea)
            _decompile_function(start_ea)
            _reset_problems(start_ea, end_ea)
            logger.info(
                "ForceAnalyze: reanalyzed range 0x%X - 0x%X", start_ea, end_ea
            )
            ida_kernwin_mod.msg(
                "d810-ng: Forced analysis of range 0x%X - 0x%X\n"
                % (start_ea, end_ea)
            )
        finally:
            ida_kernwin_mod.jumpto(ea)

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        idaapi_mod = self.ida_module("idaapi")
        if idaapi_mod is None:
            return False
        return idaapi_mod.get_widget_type(ctx.widget) == idaapi_mod.BWN_DISASM
