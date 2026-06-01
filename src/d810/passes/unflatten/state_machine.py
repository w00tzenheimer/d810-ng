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

# --- WORK-LIST: portable extractions (skeleton bodies until the seam lands) ---
from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
from d810.analyses.control_flow.semantic_transition import resolve_state_transitions
from d810.transforms.semantic_regions import plan_semantic_regions
from d810.transforms.state_machine_unflatten import lower_to_direct_graph
from d810.transforms.dispatcher_cleanup import cleanup_residual_dispatcher


class RecoverDispatcher:
    name = "recover_dispatcher"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = recover_dispatcher(ctx.graph, ctx.facts)
        # Publish for downstream passes (LLVM AnalysisManager.getResult edge).
        if hasattr(ctx.facts, "put_analysis"):
            ctx.facts.put_analysis(self.name, recovery)
        return PassResult(facts=(recovery,), preserved=PreservedAnalyses.all())


class RecoverStateTransitions:
    name = "recover_state_transitions"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        # Pull the dispatcher map recovered by pass #1 and resolve transitions through it.
        dispatch_map = None
        if hasattr(ctx.facts, "get_analysis"):
            recovery = ctx.facts.get_analysis("recover_dispatcher")
            dispatch_map = getattr(recovery, "dispatch_map", None)
        transitions = resolve_state_transitions(
            ctx.graph, ctx.facts, dispatch_map=dispatch_map
        )
        if hasattr(ctx.facts, "put_analysis"):
            ctx.facts.put_analysis(self.name, transitions)
        return PassResult(facts=(transitions,), preserved=PreservedAnalyses.all())


class PlanSemanticRegions:
    name = "plan_semantic_regions"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        regions = plan_semantic_regions(ctx.graph, ctx.facts)
        return PassResult(facts=(regions,), preserved=PreservedAnalyses.all())


class LowerStateMachine:
    name = "lower_state_machine"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        plan = lower_to_direct_graph(ctx.graph, ctx.facts)
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())


class CleanupResidualDispatcher:
    name = "cleanup_residual_dispatcher"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        plan = cleanup_residual_dispatcher(ctx.graph, ctx.facts)
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())
