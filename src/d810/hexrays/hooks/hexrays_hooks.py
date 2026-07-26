from __future__ import annotations

import contextlib

import ida_hexrays
import idaapi

from d810.core import getLogger, typing
from d810.core.decompilation_session import DecompilationEvent
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager
from d810.hexrays.hooks.glbopt_diagnostics import (
    apply_return_const_corruption_cleanup,
    prune_unreachable_condition_chain,
)
main_logger = getLogger("D810")

if typing.TYPE_CHECKING:
    from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager


class HexraysDecompilationHook(ida_hexrays.Hexrays_Hooks):
    def __init__(
        self,
        callback: typing.Callable,
        ctree_optimizer_manager: CtreeOptimizerManager | None = None,
        block_optimizer: BlockOptimizerManager | None = None,
        decompilation_lifecycle: typing.Any | None = None,
        database_identity: str = "",
    ):
        super().__init__()
        self.callback = callback
        self.ctree_optimizer_manager = ctree_optimizer_manager
        self._block_optimizer = block_optimizer
        self._decompilation_lifecycle = decompilation_lifecycle
        self._database_identity = str(database_identity)

    @staticmethod
    def _function_owner_ea(mba: ida_hexrays.mbl_array_t) -> int:
        """Return the IDA function that owns a callback-local MBA entry.

        Hex-Rays can invoke hooks for an internal entry while recursively
        processing one decompilation.  That entry is a live-MBA coordinate,
        not a top-level lifecycle identity: all session, diagnostic, and
        function-keyed callback routing must use the containing IDA function.
        """
        entry_ea = int(getattr(mba, "entry_ea", 0) or 0)
        try:
            function = idaapi.get_func(entry_ea)
            start_ea = None if function is None else getattr(function, "start_ea", None)
            if start_ea is not None:
                owner_ea = int(start_ea)
                if owner_ea != int(getattr(idaapi, "BADADDR", -1)):
                    return owner_ea
        except Exception:
            pass
        return entry_ea

    def _decision_for_mba(
        self,
        mba: ida_hexrays.mbl_array_t,
        *,
        bind_live_identity: bool = False,
    ) -> dict[str, object]:
        """Create an event decision with the active portable session, if any.

        The live MBA remains event-local.  Retry-capable consumers receive the
        coordinator-owned session through this decision port so they can retain
        only portable evidence across an ``MERR_REDO`` rebuild.
        """
        decision: dict[str, object] = {"request_redo": False}
        HexraysDecompilationHook._ensure_lifecycle_session(self, mba)
        lifecycle = getattr(self, "_decompilation_lifecycle", None)
        if lifecycle is None:
            return decision
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        try:
            session = lifecycle.current_session(function_ea)
        except Exception:
            main_logger.debug(
                "Failed to retrieve decompilation session for 0x%X",
                function_ea,
                exc_info=True,
            )
            return decision
        if session is None:
            return decision
        decision["session"] = session
        if not bind_live_identity:
            return decision
        build_identity_index = getattr(
            lifecycle,
            "build_current_mba_identity_index",
            None,
        )
        if callable(build_identity_index):
            index = build_identity_index(
                function_ea=function_ea,
                mba=mba,
            )
            if index is not None:
                decision["identity_index"] = index
                new_mutation_gateway = getattr(
                    lifecycle,
                    "new_current_mba_mutation_gateway",
                    None,
                )
                if callable(new_mutation_gateway):
                    gateway = new_mutation_gateway(
                        function_ea=function_ea,
                        maturity=int(getattr(mba, "maturity", 0) or 0),
                    )
                    if gateway is not None:
                        decision["mutation_gateway"] = gateway
                        new_materializer = getattr(
                            lifecycle,
                            "new_semantic_native_body_materializer",
                            None,
                        )
                        if callable(new_materializer):
                            materializer = new_materializer(
                                function_ea=function_ea,
                                mba=mba,
                            )
                            if materializer is not None:
                                decision["semantic_native_body_materializer"] = (
                                    materializer
                                )
        return decision

    def _ensure_lifecycle_session(
        self,
        mba: ida_hexrays.mbl_array_t,
        *,
        structural_callback: bool = False,
    ) -> object | None:
        """Lazily create one coordinator-owned session for any Hex-Rays hook.

        ``prolog`` normally creates the session.  This fallback covers hook
        ordering differences and rebuild paths, while the coordinator ensures
        that a ``MERR_REDO`` neither resets state nor emits duplicate lifecycle
        events.
        """
        lifecycle = getattr(self, "_decompilation_lifecycle", None)
        ensure_session = getattr(lifecycle, "ensure_hexrays_session", None)
        if not callable(ensure_session):
            return None
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        callback_entry_ea = (
            int(getattr(mba, "entry_ea", 0) or 0) if structural_callback else None
        )
        try:
            session, _created = ensure_session(
                function_ea=function_ea,
                database_identity=str(getattr(self, "_database_identity", "")),
                callback_entry_ea=callback_entry_ea,
            )
            return session
        except Exception:
            main_logger.debug(
                "Failed to ensure decompilation session for 0x%X",
                function_ea,
                exc_info=True,
            )
            return None

    def flowchart(
        self,
        fc,
        mba: ida_hexrays.mbl_array_t,
        reachable_blocks,
        decomp_flags,
    ) -> "int":
        decision = HexraysDecompilationHook._decision_for_mba(self, mba)
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        begin_generation = getattr(
            getattr(self, "_decompilation_lifecycle", None),
            "begin_current_mba_generation",
            None,
        )
        if callable(begin_generation):
            begin_generation(function_ea=function_ea)
        try:
            self.callback(
                DecompilationEvent.HEXRAYS_FLOWCHART_READY,
                function_ea=function_ea,
                mba=mba,
                decision=decision,
            )
        except Exception:
            main_logger.debug(
                "Hex-Rays flowchart event failed for 0x%X",
                function_ea,
                exc_info=True,
            )
            return 0
        if bool(decision.get("request_redo")):
            main_logger.info(
                "Hex-Rays flowchart preanalysis requested redo for 0x%X: %s",
                function_ea,
                decision.get("reason", "unspecified"),
            )
            return ida_hexrays.MERR_REDO
        return 0

    def calls_done(self, mba: ida_hexrays.mbl_array_t) -> "int":
        """Run preanalysis that requires the intact MMAT_CALLS microcode."""
        decision = HexraysDecompilationHook._decision_for_mba(self, mba)
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        try:
            self.callback(
                DecompilationEvent.HEXRAYS_CALLS_DONE,
                function_ea=function_ea,
                mba=mba,
                decision=decision,
            )
        except Exception:
            main_logger.debug(
                "Hex-Rays CALLS preanalysis event failed for 0x%X",
                function_ea,
                exc_info=True,
            )
            return 0
        if bool(decision.get("request_redo")):
            main_logger.info(
                "Hex-Rays CALLS preanalysis requested redo for 0x%X: %s",
                function_ea,
                decision.get("reason", "unspecified"),
            )
            if bool(decision.get("defer_generated_restart")):
                # hxe_calls_done has no documented microcode-error return
                # contract. The manager retains the session and initiates a
                # follow-up whose flowchart callback returns MERR_REDO.
                return 0
            # Hex-Rays documents MERR_LOOP as the required result when a
            # calls_done subscriber changes microcode inputs.  It restarts the
            # optimization pipeline at the CALLS boundary.
            return ida_hexrays.MERR_LOOP
        return 0

    def build_callinfo(self, blk, call_type):
        """Let profile-scoped providers supply a call prototype before guessing."""
        decision = HexraysDecompilationHook._decision_for_mba(self, blk.mba)
        function_ea = HexraysDecompilationHook._function_owner_ea(blk.mba)
        decision["callinfo"] = None
        try:
            self.callback(
                DecompilationEvent.HEXRAYS_BUILD_CALLINFO,
                function_ea=function_ea,
                block=blk,
                call_type=call_type,
                decision=decision,
            )
        except Exception:
            call_ea = int(blk.tail.ea) if blk.tail is not None else int(blk.start)
            main_logger.debug(
                "Hex-Rays callinfo preanalysis event failed at 0x%X",
                call_ea,
                exc_info=True,
            )
            return None
        return decision["callinfo"]

    def stkpnts(self, mba, stack_points):
        """Let profile-scoped providers amend transient stack provenance."""
        decision = HexraysDecompilationHook._decision_for_mba(self, mba)
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        try:
            self.callback(
                DecompilationEvent.HEXRAYS_STKPNTS,
                function_ea=function_ea,
                mba=mba,
                stack_points=stack_points,
                decision=decision,
            )
        except Exception:
            main_logger.debug(
                "Hex-Rays stack-point preanalysis event failed for 0x%X",
                function_ea,
                exc_info=True,
            )
        return 0

    def locopt(self, mba: ida_hexrays.mbl_array_t) -> "int":
        """Run profile-gated mutation after LOCOPT and before call analysis."""
        decision = HexraysDecompilationHook._decision_for_mba(self, mba)
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        try:
            self.callback(
                DecompilationEvent.HEXRAYS_LOCOPT_READY,
                function_ea=function_ea,
                mba=mba,
                decision=decision,
            )
        except Exception:
            main_logger.debug(
                "Hex-Rays LOCOPT preanalysis event failed for 0x%X",
                function_ea,
                exc_info=True,
            )
            return 0
        if bool(decision.get("request_redo")):
            main_logger.warning(
                "Hex-Rays LOCOPT preanalysis requested an unsupported maturity "
                "restart for 0x%X: %s; continuing into call analysis",
                function_ea,
                decision.get("reason", "unspecified"),
            )
        elif bool(decision.get("microcode_modified")):
            main_logger.info(
                "Hex-Rays LOCOPT preanalysis modified microcode for 0x%X: %s",
                function_ea,
                decision.get("details", {}),
            )
        return 0

    def prolog(
        self, mba: ida_hexrays.mbl_array_t, fc, reachable_blocks, decomp_flags
    ) -> "int":
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        fn_name = ""
        with contextlib.suppress(BaseException):
            fn_name = idaapi.get_func_name(function_ea)
        prologue = f"{fn_name} @ {hex(function_ea)}"
        main_logger.info("Starting decompilation of function %s", prologue)
        session = HexraysDecompilationHook._ensure_lifecycle_session(
            self,
            mba,
            structural_callback=True,
        )
        diagnostic_owner_ea = int(
            getattr(session, "function_ea", function_ea)
            if session is not None
            else function_ea
        )
        try:
            from d810.core.observability import open_observability_session

            # open_observability_session opens the diag session
            # (idempotent re-installation on re-decompilation) by
            # delegating to the registered backend; nothing here
            # imports d810.core.diag.
            open_observability_session(diagnostic_owner_ea)
        except Exception:
            pass  # diagnostic, never gates decompilation
        reobserve = getattr(
            getattr(self, "_decompilation_lifecycle", None),
            "reobserve_active_diagnostic_session",
            None,
        )
        if session is not None and callable(reobserve):
            reobserve(diagnostic_owner_ea)
        return 0

    def maturity(self, cfunc, new_maturity: int) -> int:
        """Ctree maturity level is being changed."""
        if self.ctree_optimizer_manager is not None:
            self.ctree_optimizer_manager.on_maturity(cfunc, new_maturity)
        return 0

    def glbopt(self, mba: ida_hexrays.mbl_array_t) -> "int":
        function_ea = HexraysDecompilationHook._function_owner_ea(mba)
        main_logger.info("glbopt finished for function at %s", hex(function_ea))
        main_logger.reset_maturity()

        # PruneUnreachable: diagnostic-only; logs unreachable condition-chain blocks
        # but does NOT remove them (see helper for rationale).
        decision = self._decision_for_mba(mba, bind_live_identity=True)
        prune_unreachable_condition_chain(
            mba,
            self._block_optimizer,
            identity_index=decision.get("identity_index"),
        )
        # v2 (d81-fzlo): the GLBOPT1 pre-fold severance snapshot is function-keyed
        # on the block optimizer (it survives the GLBOPT1->GLBOPT2 boundary, where
        # glbopt() actually fires; the per-maturity flow_context does not). Empty
        # when no block optimizer is installed -> the cleanup fails closed.
        prefold_def_eas = (
            self._block_optimizer.prefold_return_reg_consumer_def_eas_for(function_ea)
            if self._block_optimizer is not None
            else frozenset()
        )
        capture_nop_sites = getattr(
            self._block_optimizer,
            "_capture_callback_nop_sites",
            None,
        )
        report_nop_delta = getattr(
            self._block_optimizer,
            "_report_callback_nop_delta",
            None,
        )
        callback_nop_sites = (
            capture_nop_sites(mba) if callable(capture_nop_sites) else None
        )
        callback_result: int | None = None
        callback_exception_name: str | None = None
        try:
            applied = apply_return_const_corruption_cleanup(
                mba,
                prefold_def_eas=prefold_def_eas,
            )
            callback_result = ida_hexrays.MERR_LOOP if applied else 0
            return callback_result
        except Exception as error:
            callback_exception_name = type(error).__name__
            raise
        finally:
            if callable(report_nop_delta):
                try:
                    report_nop_delta(
                        mba,
                        before=callback_nop_sites,
                        callback_kind="glbopt_hook",
                        callback_name="return_const_corruption_cleanup",
                        callback_result=callback_result,
                        exception_name=callback_exception_name,
                    )
                except Exception:
                    main_logger.debug(
                        "failed to persist glbopt callback NOP delta",
                        exc_info=True,
                    )

    def structural(self, ct: ida_hexrays.control_graph_t) -> int:  # type: ignore
        """Structural analysis has been finished.

        @param ct: (control_graph_t *)"""
        main_logger.info("Structural analysis has been finished")
        lifecycle = self._decompilation_lifecycle
        if lifecycle is not None:
            lifecycle.finish_hexrays_session()
        if lifecycle is None or not lifecycle.has_active_sessions:
            try:
                from d810.core.observability import close_observability_session

                # Finish emits the terminal event while the diagnostic sink is
                # still live. A controlled redo retains both lifecycle owner
                # and database until the final structural callback.
                close_observability_session()
            except Exception:
                pass  # diagnostic, never gates decompilation
        return 0

    def func_printed(self, cfunc: ida_hexrays.cfunc_t) -> int:
        """Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.

        @param cfunc: (cfunc_t *)"""
        main_logger.info("Function text has been generated")
        return 0
