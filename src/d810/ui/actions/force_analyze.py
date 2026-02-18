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
        idaapi_shim = self.ida_module("idaapi")

        if idaapi_shim is None:
            return 0

        def _auto_wait() -> None:
            idaapi_shim.auto_wait()

        def _delete_and_recreate_function(func_start: int, func_end: int) -> None:
            size = func_end - func_start
            idaapi_shim.del_items(func_start, 0, size)
            for offset in range(size):
                idaapi_shim.create_insn(func_start + offset)
            idaapi_shim.add_func(func_start, func_end)
            _auto_wait()

        def _decompile_function(func_start: int) -> None:
            _auto_wait()
            try:
                idaapi_shim.mark_cfunc_dirty(func_start, False)
            except Exception:  # pragma: no cover - IDA API variability
                pass
            try:
                if hasattr(idaapi_shim, "hexrays_failure_t"):
                    hf = idaapi_shim.hexrays_failure_t()
                    idaapi_shim.decompile_func(idaapi_shim.get_func(func_start), hf)
                else:
                    idaapi_shim.decompile(func_start)
            except Exception as exc:
                logger.warning("ForceAnalyze: decompile failed at %s: %s", hex(func_start), exc)
            _auto_wait()

        def _reset_problems(func_start: int, func_end: int) -> None:
            current = func_start
            while current != func_end:
                idaapi_shim.forget_problem(idaapi_shim.PR_DISASM, current)
                current += 1

        ea = idaapi_shim.get_screen_ea()
        func = idaapi_shim.get_func(ea)
        if func is not None:
            start_ea = func.start_ea
            end_ea = func.end_ea
        else:
            viewer = None
            if hasattr(idaapi_shim, "get_current_viewer"):
                viewer = idaapi_shim.get_current_viewer()

            is_selected = False
            start_ea = idaapi_shim.BADADDR
            end_ea = idaapi_shim.BADADDR
            if viewer is not None and hasattr(idaapi_shim, "read_range_selection"):
                is_selected, start_ea, end_ea = idaapi_shim.read_range_selection(viewer)

            if is_selected and start_ea != idaapi_shim.BADADDR and end_ea != idaapi_shim.BADADDR:
                ea = start_ea
            else:
                start_ea = ea
                idaapi_shim.msg("d810-ng: No range selected.\n")
                end_ea = idaapi_shim.ask_addr(
                    start_ea, "Enter end address for selection:"
                )
                if end_ea is None or end_ea == idaapi_shim.BADADDR:
                    idaapi_shim.msg("d810-ng: Selection cancelled.\n")
                    return 0
                if end_ea <= start_ea:
                    idaapi_shim.warning("End address must be greater than start address.")
                    return 0
            idaapi_shim.msg(
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
            idaapi_shim.msg(
                "d810-ng: Forced analysis of range 0x%X - 0x%X\n"
                % (start_ea, end_ea)
            )
        finally:
            idaapi_shim.jumpto(ea)

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        idaapi_shim = self.ida_module("idaapi")
        if idaapi_shim is None:
            return False
        return idaapi_shim.get_widget_type(ctx.widget) == idaapi_shim.BWN_DISASM
