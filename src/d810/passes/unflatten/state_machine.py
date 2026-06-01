"""Hodur state-machine unflattening passes — the §1a north-star, realized.

Each pass schedules a portable analysis (facts over a ``FlowGraph``) or a portable transform
(producing a ``PatchPlan``). The five imports below are the WORK-LIST: each names a portable
function extracted (or being extracted) from the entangled hodur/engine files, pushing its
live-IDA reads behind the ``MicrocodeEvidenceProvider`` seam (graph-parameter, not mba-parameter;
the backend impl makes the identical live call, byte-identical for live-mba AND FlowGraph
projection — the llr-zeyu polymorphism guard).

These passes are importable + unit-tested NOW (skeleton transforms emit empty plans); they become
the live call graph once each work-list extraction lands its real body and the driver
(``run_d810_pipeline``) replaces the ``HodurUnflattener`` orchestration. Until then this module is
additive + behavior-neutral (not wired into the maturity hook).
"""
from __future__ import annotations

from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassResult,
    PreservedAnalyses,
)

# --- WORK-LIST: portable extractions composed by the passes ---
from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
from d810.analyses.control_flow.semantic_transition import resolve_state_transitions
from d810.analyses.control_flow.transition_builder import transition_result_from_resolutions
from d810.transforms.semantic_regions import plan_semantic_regions
from d810.transforms.state_machine_unflatten import lower_to_direct_graph
from d810.transforms.dispatcher_cleanup import cleanup_residual_dispatcher


def _analysis(ctx: FunctionPipelineContext, name: str, default=None):
    """Read a prior pass's published result (LLVM AnalysisManager.getResult), or ``default``."""
    facts = ctx.facts
    if hasattr(facts, "get_analysis"):
        return facts.get_analysis(name, default)
    return default


def _publish(ctx: FunctionPipelineContext, name: str, value) -> None:
    if hasattr(ctx.facts, "put_analysis"):
        ctx.facts.put_analysis(name, value)


class RecoverDispatcher:
    name = "recover_dispatcher"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = recover_dispatcher(ctx.graph, ctx.facts)
        _publish(ctx, self.name, recovery)
        return PassResult(facts=(recovery,), preserved=PreservedAnalyses.all())


class RecoverStateTransitions:
    name = "recover_state_transitions"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(ctx, "recover_dispatcher")
        dispatch_map = getattr(recovery, "dispatch_map", None)
        resolutions = resolve_state_transitions(
            ctx.graph, ctx.facts, dispatch_map=dispatch_map
        )
        transition_result = transition_result_from_resolutions(
            resolutions, dispatch_map=dispatch_map
        )
        _publish(ctx, self.name, resolutions)
        _publish(ctx, "transition_result", transition_result)
        return PassResult(
            facts=(resolutions, transition_result), preserved=PreservedAnalyses.all()
        )


class PlanSemanticRegions:
    name = "plan_semantic_regions"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(ctx, "recover_dispatcher")
        regions = plan_semantic_regions(
            ctx.graph,
            ctx.facts,
            transition_result=_analysis(ctx, "transition_result"),
            dispatcher_entry_serial=getattr(recovery, "dispatcher_block_serial", None),
            state_var_stkoff=getattr(recovery, "state_var_stkoff", None),
        )
        _publish(ctx, self.name, regions)
        return PassResult(facts=(regions,), preserved=PreservedAnalyses.all())


class LowerStateMachine:
    name = "lower_state_machine"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(ctx, "recover_dispatcher")
        plan = lower_to_direct_graph(
            ctx.graph,
            ctx.facts,
            transition_result=_analysis(ctx, "transition_result"),
            dispatch_map=getattr(recovery, "dispatch_map", None),
            dispatcher_entry_serial=getattr(recovery, "dispatcher_block_serial", None),
            state_var_stkoff=getattr(recovery, "state_var_stkoff", None),
            regions=_analysis(ctx, "plan_semantic_regions"),
        )
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())


class CleanupResidualDispatcher:
    name = "cleanup_residual_dispatcher"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        candidates = _analysis(ctx, "cleanup_candidates", ()) or ()
        plan = cleanup_residual_dispatcher(ctx.graph, ctx.facts, candidates=candidates)
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())
