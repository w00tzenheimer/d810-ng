from __future__ import annotations

import contextlib

import ida_hexrays
import idaapi

from d810.core import getLogger, typing
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager
from d810.hexrays.hooks.glbopt_diagnostics import prune_unreachable_condition_chain
from d810.hexrays.lifecycle import DecompilationEvent

main_logger = getLogger("D810")

if typing.TYPE_CHECKING:
    from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager


class HexraysDecompilationHook(ida_hexrays.Hexrays_Hooks):
    def __init__(
        self,
        callback: typing.Callable,
        ctree_optimizer_manager: CtreeOptimizerManager | None = None,
        block_optimizer: BlockOptimizerManager | None = None,
    ):
        super().__init__()
        self.callback = callback
        self.ctree_optimizer_manager = ctree_optimizer_manager
        self._block_optimizer = block_optimizer

    def flowchart(
        self,
        fc,
        mba: ida_hexrays.mbl_array_t,
        reachable_blocks,
        decomp_flags,
    ) -> "int":
        decision: dict[str, object] = {"request_redo": False}
        try:
            self.callback(
                DecompilationEvent.HEXRAYS_FLOWCHART_READY,
                function_ea=int(mba.entry_ea),
                mba=mba,
                decision=decision,
            )
        except Exception:
            main_logger.debug(
                "Hex-Rays flowchart event failed for 0x%X",
                int(getattr(mba, "entry_ea", 0) or 0),
                exc_info=True,
            )
            return 0
        if bool(decision.get("request_redo")):
            main_logger.info(
                "Hex-Rays flowchart preanalysis requested redo for 0x%X: %s",
                int(mba.entry_ea),
                decision.get("reason", "unspecified"),
            )
            return ida_hexrays.MERR_REDO
        return 0

    def prolog(
        self, mba: ida_hexrays.mbl_array_t, fc, reachable_blocks, decomp_flags
    ) -> "int":
        fn_name = ""
        with contextlib.suppress(BaseException):
            fn_name = idaapi.get_func_name(mba.entry_ea)
        prologue = f"{fn_name} @ {hex(mba.entry_ea)}"
        main_logger.info("Starting decompilation of function %s", prologue)
        try:
            from d810.core.observability import open_observability_session
            # open_observability_session opens the diag session
            # (idempotent re-installation on re-decompilation) by
            # delegating to the registered backend; nothing here
            # imports d810.core.diag.
            open_observability_session(int(mba.entry_ea))
        except Exception:
            pass  # diagnostic, never gates decompilation
        self.callback(DecompilationEvent.STARTED)
        # self.manager.start_profiling()
        # self.manager.instruction_optimizer.reset_rule_usage_statistic()
        # self.manager.block_optimizer.reset_rule_usage_statistic()
        return 0

    def maturity(self, cfunc, new_maturity: int) -> int:
        """Ctree maturity level is being changed."""
        if self.ctree_optimizer_manager is not None:
            self.ctree_optimizer_manager.on_maturity(cfunc, new_maturity)
        return 0

    def glbopt(self, mba: ida_hexrays.mbl_array_t) -> "int":
        main_logger.info("glbopt finished for function at %s", hex(mba.entry_ea))
        main_logger.reset_maturity()

        # PruneUnreachable: diagnostic-only; logs unreachable condition-chain blocks
        # but does NOT remove them (see helper for rationale).
        prune_unreachable_condition_chain(mba, self._block_optimizer)
        return 0

    def structural(self, ct: "control_graph_t") -> int:  # type: ignore
        """Structural analysis has been finished.

        @param ct: (control_graph_t *)"""
        main_logger.info("Structural analysis has been finished")
        try:
            from d810.core.observability import close_observability_session
            # close_observability_session unsubscribes event-handler
            # subscribers and closes the diag DB via the registered
            # backend; nothing here imports d810.core.diag.
            close_observability_session()
        except Exception:
            pass  # diagnostic, never gates decompilation
        self.callback(DecompilationEvent.FINISHED)
        return 0

    def func_printed(self, cfunc: "cfunc_t") -> int:
        """Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.

        @param cfunc: (cfunc_t *)"""
        main_logger.info("Function text has been generated")
        return 0
