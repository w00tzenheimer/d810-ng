"""Reusable snapshot assembly for state-machine unflattening families."""
from __future__ import annotations

from d810.ir.flowgraph import FlowGraph
from d810.optimizers.microcode.flow.flattening.engine.runtime import FamilyRunState
from d810.transforms.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)

__all__ = ["StateMachineSnapshotBuilder"]


class StateMachineSnapshotBuilder:
    """Build immutable AnalysisSnapshot instances for state-machine families."""

    def __init__(
        self,
        *,
        cfg_translator: object,
        logger,
    ) -> None:
        self.cfg_translator = cfg_translator
        self.logger = logger

    def build_snapshot(
        self,
        mba: object,
        detection: object,
        *,
        run_state: FamilyRunState,
        flow_graph_adapter,
        dispatcher_analysis_factory,
        reachability_builder=None,
        fact_view_resolver=None,
        function_priors_resolver=None,
        bst_evidence_resolver=None,
        transition_supplementer=None,
        discovery_builder=None,
    ) -> AnalysisSnapshot:
        """Build a state-machine AnalysisSnapshot from profile providers."""
        state_machine = getattr(detection, "state_machine", None)
        flow_graph = flow_graph_adapter(
            mba,
            self.cfg_translator.lift(mba),
            state_machine,
        )
        dispatcher_analysis = dispatcher_analysis_factory(mba)
        reachability = (
            self.compute_reachability_info(flow_graph)
            if reachability_builder is None
            else reachability_builder(mba)
        )
        fact_view = None if fact_view_resolver is None else fact_view_resolver(mba)

        if state_machine is None:
            return self.build_cleanup_snapshot(
                mba,
                detection=detection,
                flow_graph=flow_graph,
                dispatcher_analysis=dispatcher_analysis,
                reachability=reachability,
                fact_view=fact_view,
                run_state=run_state,
            )

        bst_result = None
        bst_dispatcher_serial = -1
        if bst_evidence_resolver is not None:
            bst_result, bst_dispatcher_serial = bst_evidence_resolver(
                mba,
                state_machine,
            )
        if transition_supplementer is not None:
            transition_supplementer(state_machine, run_state=run_state)

        function_priors = (
            None
            if function_priors_resolver is None
            else function_priors_resolver(mba)
        )
        discovery = None
        if discovery_builder is not None:
            discovery = discovery_builder(
                mba,
                state_machine=state_machine,
                flow_graph=flow_graph,
                bst_result=bst_result,
                bst_dispatcher_serial=bst_dispatcher_serial,
                function_priors=function_priors,
                run_state=run_state,
            )

        return AnalysisSnapshot(
            mba=mba,
            state_machine=state_machine,
            detector=getattr(detection, "detector", None),
            dispatcher_analysis=dispatcher_analysis,
            bst_result=bst_result,
            bst_dispatcher_serial=bst_dispatcher_serial,
            dispatcher_blocks=frozenset(
                int(block)
                for block in (
                    getattr(bst_result, "condition_chain_blocks", set()) or set()
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

    def build_cleanup_snapshot(
        self,
        mba: object,
        *,
        detection: object,
        flow_graph: FlowGraph,
        dispatcher_analysis: object,
        reachability: ReachabilityInfo,
        fact_view: object | None,
        run_state: FamilyRunState,
    ) -> AnalysisSnapshot:
        return AnalysisSnapshot(
            mba=mba,
            detector=getattr(detection, "detector", None),
            dispatcher_analysis=dispatcher_analysis,
            reachability=reachability,
            maturity=mba.maturity,
            pass_number=run_state.pass_number,
            flow_graph=flow_graph,
            diagnostic_fact_view=fact_view,
        )

    def compute_reachability_info(self, flow_graph: FlowGraph) -> ReachabilityInfo:
        total_blocks = len(flow_graph.blocks)
        visited: set[int] = set()
        queue = [flow_graph.entry_serial]
        while queue:
            serial = queue.pop()
            if serial in visited:
                continue
            block = flow_graph.get_block(serial)
            if block is None:
                continue
            visited.add(serial)
            queue.extend(block.succs)
        return ReachabilityInfo(
            entry_serial=flow_graph.entry_serial,
            reachable_blocks=frozenset(visited),
            total_blocks=total_blocks,
        )
