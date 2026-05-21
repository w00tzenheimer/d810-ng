"""Hodur snapshot assembly helpers.

This module keeps HodurStrategyFamily focused on detection, strategy
registration, and runtime bookkeeping. Snapshot assembly lives here so future
state-machine families can copy the same builder shape without growing their
family adapter into a lifecycle orchestrator.
"""
from __future__ import annotations

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.cleanup_live_evidence import (
    collect_live_fake_jump_fixes,
    collect_live_single_iteration_fixes,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import FamilyRunState
from d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend import (
    ConstantFixpointBackend,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    serialize_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    serialize_single_iteration_fixes,
)
from d810.recon.flow.dispatcher_detection import DispatcherCache
from d810.recon.function_priors import FunctionAnalysisPriors

__all__ = ["HodurSnapshotBuilder"]


class HodurSnapshotBuilder:
    """Build immutable AnalysisSnapshot instances for the Hodur family."""

    def __init__(
        self,
        *,
        cfg_translator: IDAIRTranslator,
        constant_fixpoint_backend: ConstantFixpointBackend,
        logger,
    ) -> None:
        self.cfg_translator = cfg_translator
        self.constant_fixpoint_backend = constant_fixpoint_backend
        self.logger = logger

    def build_snapshot(
        self,
        mba: object,
        detection: object,
        *,
        run_state: FamilyRunState,
        switch_table_map: object | None,
        fact_runtime: object | None,
        state_var_stkoff_resolver,
        dispatcher_cache_factory=DispatcherCache.get_or_create,
        transition_builder=None,
        discovery_builder=None,
        reachability_builder=None,
        attach_fake_jump_fixes=None,
        attach_single_iteration_fixes=None,
    ) -> AnalysisSnapshot:
        state_machine = detection.state_machine
        flow_graph = self.build_snapshot_flow_graph(
            mba,
            state_machine=state_machine,
            attach_fake_jump_fixes=attach_fake_jump_fixes,
            attach_single_iteration_fixes=attach_single_iteration_fixes,
        )
        dispatcher_cache = dispatcher_cache_factory(mba)
        if reachability_builder is None:
            reachability = self.compute_reachability_info(mba)
        else:
            reachability = reachability_builder(mba)
        fact_view = self.resolve_fact_view(mba, fact_runtime)
        function_priors = self.function_analysis_priors_for_mba(mba, fact_runtime)

        if state_machine is None:
            return self.build_cleanup_snapshot(
                mba,
                detection=detection,
                flow_graph=flow_graph,
                dispatcher_cache=dispatcher_cache,
                reachability=reachability,
                fact_view=fact_view,
                run_state=run_state,
            )

        bst_result, bst_dispatcher_serial = self.resolve_snapshot_bst_evidence(
            mba,
            state_machine,
            switch_table_map=switch_table_map,
            state_var_stkoff_resolver=state_var_stkoff_resolver,
        )
        self.supplement_initial_transitions(
            state_machine,
            run_state=run_state,
        )
        discovery = self.build_snapshot_discovery_context(
            mba,
            state_machine=state_machine,
            flow_graph=flow_graph,
            bst_result=bst_result,
            bst_dispatcher_serial=bst_dispatcher_serial,
            function_priors=function_priors,
            run_state=run_state,
            state_var_stkoff_resolver=state_var_stkoff_resolver,
            transition_builder=transition_builder,
            discovery_builder=discovery_builder,
        )

        return AnalysisSnapshot(
            mba=mba,
            state_machine=state_machine,
            detector=detection.detector,
            dispatcher_cache=dispatcher_cache,
            bst_result=bst_result,
            bst_dispatcher_serial=bst_dispatcher_serial,
            dispatcher_blocks=frozenset(
                int(block)
                for block in (
                    getattr(bst_result, "bst_node_blocks", set()) or set()
                )
            ),
            reachability=reachability,
            maturity=mba.maturity,
            pass_number=run_state.pass_number,
            resolved_transitions=run_state.resolved_transitions,
            initial_transitions=run_state.initial_transitions,
            flow_graph=flow_graph,
            discovery=discovery,
            diagnostic_fact_view=fact_view,
        )

    def build_snapshot_flow_graph(
        self,
        mba: object,
        *,
        state_machine: DispatcherStateMachine | None,
        attach_fake_jump_fixes=None,
        attach_single_iteration_fixes=None,
    ) -> FlowGraph:
        flow_graph = self.cfg_translator.lift(mba)
        if attach_fake_jump_fixes is None:
            flow_graph = self.attach_fake_jump_fixes_to_flow_graph(
                mba,
                flow_graph,
                state_machine=state_machine,
            )
        else:
            flow_graph = attach_fake_jump_fixes(mba, flow_graph)
        if attach_single_iteration_fixes is None:
            return self.attach_single_iteration_fixes_to_flow_graph(mba, flow_graph)
        return attach_single_iteration_fixes(mba, flow_graph)

    def build_cleanup_snapshot(
        self,
        mba: object,
        *,
        detection: object,
        flow_graph: FlowGraph,
        dispatcher_cache: object,
        reachability: ReachabilityInfo,
        fact_view: object | None,
        run_state: FamilyRunState,
    ) -> AnalysisSnapshot:
        return AnalysisSnapshot(
            mba=mba,
            detector=detection.detector,
            dispatcher_cache=dispatcher_cache,
            reachability=reachability,
            maturity=mba.maturity,
            pass_number=run_state.pass_number,
            flow_graph=flow_graph,
            diagnostic_fact_view=fact_view,
        )

    def resolve_snapshot_bst_evidence(
        self,
        mba: object,
        state_machine: DispatcherStateMachine,
        *,
        switch_table_map: object | None,
        state_var_stkoff_resolver,
    ) -> tuple[object | None, int]:
        bst_result = None
        bst_dispatcher_serial = -1
        if state_machine.handlers and switch_table_map is None:
            entry_serial = list(state_machine.handlers.values())[0].check_block
            bst_stkoff = state_var_stkoff_resolver(state_machine)
            try:
                from d810.recon.flow.bst_analysis import analyze_bst_dispatcher

                raw_bst = analyze_bst_dispatcher(
                    mba,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=bst_stkoff,
                )
                if raw_bst is not None and len(raw_bst.handler_state_map) > 0:
                    return raw_bst, entry_serial
            except Exception:
                bst_result = None

        if bst_result is None and switch_table_map is not None:
            switch_handler_map = switch_table_map.to_dispatcher_handler_map()
            bst_result = switch_handler_map.to_bst_result()
            bst_dispatcher_serial = switch_table_map.dispatcher_entry_block
            self.logger.debug(
                "Using synthetic BST from switch-table analysis: %d handlers, dispatcher=blk[%d]",
                len(bst_result.handler_state_map),
                bst_dispatcher_serial,
            )
        return bst_result, bst_dispatcher_serial

    def supplement_initial_transitions(
        self,
        state_machine: DispatcherStateMachine,
        *,
        run_state: FamilyRunState,
    ) -> None:
        if not (run_state.pass_number > 0 and run_state.initial_transitions):
            return
        detected_keys = {
            (transition.from_state, transition.to_state)
            for transition in state_machine.transitions
        }
        supplemented = 0
        for transition in run_state.initial_transitions:
            key = (transition.from_state, transition.to_state)
            if key not in run_state.resolved_transitions and key not in detected_keys:
                state_machine.transitions.append(transition)
                supplemented += 1
        if supplemented:
            self.logger.debug(
                "HodurStrategyFamily: supplemented %d transitions from initial detection "
                "(resolved=%d, re-detected=%d)",
                supplemented,
                len(run_state.resolved_transitions),
                len(detected_keys),
            )

    def build_snapshot_discovery_context(
        self,
        mba: object,
        *,
        state_machine: DispatcherStateMachine,
        flow_graph: FlowGraph,
        bst_result: object | None,
        bst_dispatcher_serial: int,
        function_priors: FunctionAnalysisPriors,
        run_state: FamilyRunState,
        state_var_stkoff_resolver,
        transition_builder,
        discovery_builder,
    ) -> object | None:
        if transition_builder is None:
            from d810.recon.flow.transition_builder import (
                build_transition_result_from_state_machine as transition_builder,
            )
        if discovery_builder is None:
            from d810.recon.flow.round_discovery_context import (
                build_round_discovery_context as discovery_builder,
            )

        state_var_stkoff = state_var_stkoff_resolver(state_machine)
        if not (
            bst_result is not None
            and bst_dispatcher_serial >= 0
            and state_var_stkoff is not None
            and flow_graph is not None
        ):
            return None
        try:
            transition_result = transition_builder(
                state_machine,
                pre_header_serial=getattr(bst_result, "pre_header_serial", None),
                strategy_name="hodur_round_discovery_context",
            )
            constant_fixpoint = self.constant_fixpoint_backend.compute(
                flow_graph,
                state_var_stkoff,
            )
            return discovery_builder(
                func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                maturity=int(mba.maturity),
                pass_number=int(run_state.pass_number),
                flow_graph=flow_graph,
                transition_result=transition_result,
                dispatcher_entry_serial=bst_dispatcher_serial,
                state_var_stkoff=state_var_stkoff,
                structured_regions=(),
                constant_fixpoint=constant_fixpoint,
                bst_result=bst_result,
                initial_state=state_machine.initial_state,
                pre_header_serial=getattr(bst_result, "pre_header_serial", None),
                handler_range_map=(
                    getattr(bst_result, "handler_range_map", {}) or {}
                ),
                bst_node_blocks=tuple(
                    sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
                ),
                diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
                dispatcher=getattr(bst_result, "dispatcher", None),
                mba=mba,
                prefer_local_corridors=True,
                return_frontier_artifact_priors=(
                    function_priors.return_frontier_artifacts
                ),
            )
        except Exception as exc:
            self.logger.debug(
                "ReconRoundDiscoveryContext build failed (phase A): %s",
                exc,
            )
            return None

    def attach_fake_jump_fixes_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
        *,
        state_machine: DispatcherStateMachine | None,
        dispatcher_cache_factory=DispatcherCache.get_or_create,
        collector=collect_live_fake_jump_fixes,
    ) -> FlowGraph:
        if mba.maturity not in (ida_hexrays.MMAT_GLBOPT1,):
            return flow_graph

        try:
            fixes = collector(
                mba,
                logger=self.logger,
                max_nb_block=100,
                max_path=100,
                allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
            )
        except Exception:
            self.logger.debug(
                "Failed to collect FakeJump fixes for FlowGraph metadata",
                exc_info=True,
            )
            return flow_graph

        if not fixes:
            return flow_graph

        try:
            dispatcher_cache = dispatcher_cache_factory(mba)
            dispatcher_analysis = dispatcher_cache.analyze()
        except Exception:
            dispatcher_cache = None
            dispatcher_analysis = None

        if (
            dispatcher_cache is not None
            and dispatcher_analysis is not None
            and dispatcher_analysis.is_conditional_chain
        ):
            original_count = len(fixes)
            fixes = tuple(
                fix
                for fix in fixes
                if not dispatcher_cache.is_dispatcher(fix.fake_block)
            )
            dropped = original_count - len(fixes)
            if dropped > 0:
                self.logger.info(
                    "Dropped %d FakeJump fixes targeting conditional-chain dispatcher blocks",
                    dropped,
                )
            if not fixes:
                return flow_graph

        if (
            state_machine is None
            and dispatcher_analysis is not None
            and tuple(getattr(dispatcher_analysis, "dispatchers", ()))
        ):
            self.logger.info(
                "Skipping FakeJump fixes during cleanup-only pass with live "
                "emulated-dispatcher candidates"
            )
            return flow_graph

        metadata = dict(flow_graph.metadata)
        metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(fixes)
        self.logger.info(
            "Attached %d FakeJump predecessor redirects to FlowGraph metadata",
            len(fixes),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def attach_single_iteration_fixes_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
        *,
        collector=collect_live_single_iteration_fixes,
    ) -> FlowGraph:
        if mba.maturity not in (ida_hexrays.MMAT_GLBOPT1,):
            return flow_graph

        try:
            fixes = collector(
                mba,
                logger=self.logger,
                allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
            )
        except Exception:
            self.logger.debug(
                "Failed to collect single-iteration fixes for FlowGraph metadata",
                exc_info=True,
            )
            return flow_graph

        if not fixes:
            return flow_graph

        metadata = dict(flow_graph.metadata)
        metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] = serialize_single_iteration_fixes(
            fixes
        )
        self.logger.info(
            "Attached %d single-iteration predecessor redirects to FlowGraph metadata",
            len(fixes),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def resolve_fact_view(self, mba: object, fact_runtime: object | None) -> object | None:
        if fact_runtime is None:
            return None
        try:
            func_ea = int(getattr(mba, "entry_ea", 0) or 0)
            maturity = getattr(mba, "maturity", 0)
            return fact_runtime.validated_fact_view(func_ea, maturity_to_string(maturity))
        except Exception:
            return None

    def function_analysis_priors_for_mba(
        self,
        mba: object,
        fact_runtime: object | None,
    ) -> FunctionAnalysisPriors:
        try:
            func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        except (TypeError, ValueError):
            return FunctionAnalysisPriors()
        if fact_runtime is None:
            return FunctionAnalysisPriors()
        provider = getattr(fact_runtime, "function_analysis_priors", None)
        if not callable(provider):
            return FunctionAnalysisPriors()
        try:
            priors = provider(func_ea)
        except Exception:
            self.logger.debug(
                "Function analysis priors lookup failed for 0x%x",
                func_ea,
                exc_info=True,
            )
            return FunctionAnalysisPriors()
        if isinstance(priors, FunctionAnalysisPriors):
            return priors
        return FunctionAnalysisPriors()

    def compute_reachability_info(self, mba: ida_hexrays.mba_t) -> ReachabilityInfo:
        qty = mba.qty
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is not None:
                for i in range(blk.nsucc()):
                    queue.append(blk.succ(i))
        return ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(visited),
            total_blocks=qty,
        )
