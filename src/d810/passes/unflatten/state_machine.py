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
from d810.analyses.control_flow.comparison_dispatcher_model import (
    ComparisonDispatcherModel,
)
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.router_resolver import (
    RouterResolutionContext,
    default_resolvers,
    select_router,
)
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.semantic_transition import resolve_state_transitions
from d810.analyses.control_flow.transition_builder import (
    transition_result_from_resolutions,
)
from d810.transforms.semantic_regions import plan_semantic_regions
from d810.transforms.state_machine_unflatten import lower_to_direct_graph
from d810.transforms.minimal_unflatten_emit import emit_minimal_unflatten
from d810.transforms.dispatcher_cleanup import cleanup_residual_dispatcher
from d810.capabilities.value_range import ValRangeCapability
from d810.capabilities.use_def_safety import UseDefSafetyCapability


def _count_valrange_confirmable(valrange, dispatch_map, state_var_stkoff) -> int:
    """Count dispatcher rows whose routing the live value-range analysis independently confirms.

    For each ``state_const -> target_block`` row, query the value range of the state variable at the
    target block's start: a clean routing has the routing constant as the incoming value. A read-only
    confirmation metric -- it does not yet add transitions (the substantive enrichment is gated on the
    protected #4 emission). Proves the injected :class:`ValRangeCapability` executes end-to-end.
    """
    if state_var_stkoff is None:
        return 0
    confirmed = 0
    for row in getattr(dispatch_map, "rows", ()):
        target = getattr(row, "target_block", None)
        const = getattr(row, "state_const", None)
        if target is None or const is None:
            continue
        try:
            resolved = valrange.resolve_state_value(int(target), int(state_var_stkoff))
        except Exception:  # noqa: BLE001 — capability query is best-effort
            resolved = None
        if resolved is not None and int(resolved) == int(const):
            confirmed += 1
    return confirmed


# DispatcherType (recovery taxonomy) -> RouterKind (portable router enum). Only the
# comparison kinds get a ComparisonDispatcherModel; the §1a equality-chain detector
# (dispatcher_recovery) yields CONDITIONAL_CHAIN -> CONDITION_CHAIN.
_DISPATCHER_TYPE_TO_ROUTER_KIND = {
    DispatcherType.SWITCH_TABLE: RouterKind.SWITCH,
    DispatcherType.CONDITIONAL_CHAIN: RouterKind.CONDITION_CHAIN,
    DispatcherType.INDIRECT_JUMP: RouterKind.INDIRECT_TABLE,
    DispatcherType.UNKNOWN: RouterKind.UNKNOWN,
}

# RouterKinds whose route() is the shared comparison body (exact ∪ interval).
_COMPARISON_ROUTER_KINDS = frozenset(
    {
        RouterKind.BST,
        RouterKind.SWITCH,
        RouterKind.EQUALITY_CHAIN,
        RouterKind.CONDITION_CHAIN,
    }
)


def _build_comparison_model(recovery, bst_evidence):
    """Build a ``ComparisonDispatcherModel`` when the kind is a comparison router.

    Returns ``None`` for non-comparison kinds (INDIRECT_TABLE / UNKNOWN) or when no
    dispatch map was recovered, so the caller falls back to exact-only routing.
    """
    dispatch_map = getattr(recovery, "dispatch_map", None)
    if dispatch_map is None:
        return None
    source = getattr(dispatch_map, "source", None)
    router_kind = _DISPATCHER_TYPE_TO_ROUTER_KIND.get(source, RouterKind.UNKNOWN)
    if router_kind not in _COMPARISON_ROUTER_KINDS:
        return None
    return ComparisonDispatcherModel.from_recovery(
        dispatch_map, bst_evidence=bst_evidence
    )


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
        # S2: build the consolidated ComparisonDispatcherModel for comparison
        # router kinds, folding in the pristine BST/interval evidence so
        # interval-routed next-states resolve via WrappedInterval.contains. The
        # model is published for RecoverStateTransitions to route through; None
        # for non-comparison kinds (caller falls back to exact-only).
        model = _build_comparison_model(recovery, _analysis(ctx, "bst_evidence"))
        _publish(ctx, "dispatcher_model", model)
        return PassResult(facts=(recovery,), preserved=PreservedAnalyses.all())


class RecoverStateTransitions:
    name = "recover_state_transitions"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(ctx, "recover_dispatcher")
        dispatch_map = getattr(recovery, "dispatch_map", None)
        # S2: route through the consolidated ComparisonDispatcherModel (exact ∪
        # interval) published by RecoverDispatcher; absent it (non-comparison
        # kind), resolution falls back to exact-only inside the resolver.
        model = _analysis(ctx, "dispatcher_model")
        resolutions = resolve_state_transitions(
            ctx.graph, ctx.facts, dispatch_map=dispatch_map, model=model
        )
        transition_result = transition_result_from_resolutions(
            resolutions, dispatch_map=dispatch_map
        )
        # Consume the injected value-range capability (north-star
        # ``capabilities.optional(ValRangeCapability)``). For now this records a read-only
        # confirmation metric proving the live capability executes end-to-end; the substantive
        # transition enrichment lands once #4's protected emission can absorb the richer DAG.
        valrange = ctx.capabilities.optional(ValRangeCapability)
        if valrange is not None and dispatch_map is not None:
            _publish(
                ctx,
                "valrange_confirmable_count",
                _count_valrange_confirmable(
                    valrange,
                    dispatch_map,
                    getattr(recovery, "state_var_stkoff", None),
                ),
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
    """Lower the recovered state machine to dispatcher-bypass redirects (§1a).

    The dispatcher router is **injectable** (ticket llr-oq8v): pass a custom
    ``resolvers`` chain and/or a ``configured_kind`` to pin the router shape; both
    default to the standard range-bst + exact-map detection chain, so the argless
    factory the pass driver invokes (``spec.pass_factory()``) is unchanged. To pin a
    kind per family, register ``lambda: LowerStateMachine(configured_kind=...)``.
    """

    name = "lower_state_machine"

    def __init__(self, *, resolvers=None, configured_kind=None) -> None:
        self._resolvers = (
            tuple(resolvers) if resolvers is not None else default_resolvers()
        )
        self._configured_kind = configured_kind

    def _resolve_router(self, recovery, bst_evidence, dispatcher_entry: int | None):
        """Adapt the recovered evidence into a router via the injectable chain.

        Router kind is configured AND/OR detected: ``self._configured_kind`` pins a
        provider, else detection ranks by handler coverage (the pre-mutation
        comparison-BST is the default; the recovered exact ``state -> handler`` map
        wins only when it strictly out-covers a COLLAPSED bst, e.g. an OLLVM -fla
        equality chain degraded to ``[0,2^32)->dispatcher_entry``). The provider
        chain + ranking live in
        :mod:`d810.analyses.control_flow.router_resolver`.
        """
        dmap = getattr(recovery, "dispatch_map", None) if recovery is not None else None
        has_rows = dmap is not None and getattr(dmap, "rows", None)
        ctx = RouterResolutionContext(
            bst_router=(
                getattr(bst_evidence, "dispatcher", None)
                if bst_evidence is not None
                else None
            ),
            state_to_handler=dmap.state_to_handler() if has_rows else None,
            default_target=(
                getattr(dmap, "default_target_block", None)
                if dmap is not None
                else None
            ),
            dispatcher_entry=dispatcher_entry,
        )
        return select_router(
            self._resolvers, ctx, configured_kind=self._configured_kind
        )

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(ctx, "recover_dispatcher")
        transition_result = _analysis(ctx, "transition_result")
        dispatcher_entry = getattr(recovery, "dispatcher_block_serial", None)
        state_var_stkoff = getattr(recovery, "state_var_stkoff", None)
        live_function = getattr(ctx.source, "live_source", None)
        bst_evidence = _analysis(ctx, "bst_evidence")

        # Direct interval-set unflatten (epic d81-jfg2): the interval-set
        # dispatcher (state -> handler) + per-handler next-state recovery IS the
        # state-transition graph; walk it and emit dispatcher-bypass redirects.
        # This replaces the StateDag build (build_live_linearized_state_dag_from_graph)
        # + lower_to_direct_graph(dag=...) full-reconstruction path, which drifted
        # across shared blocks and mis-resolved conditional handlers (e.g.
        # 0x610BB4D9 collapsed to the exit). The rich StateDag metadata can be
        # re-added later if needed; the redirect output does not require it.
        dispatcher = self._resolve_router(recovery, bst_evidence, dispatcher_entry)
        if (
            dispatcher is not None
            and dispatcher_entry is not None
            and state_var_stkoff is not None
        ):
            plan = emit_minimal_unflatten(
                ctx.graph,
                dispatcher,
                state_var_stkoff=int(state_var_stkoff),
                dispatcher_entry_serial=int(dispatcher_entry),
                pre_header_serial=getattr(bst_evidence, "pre_header_serial", None),
                initial_state=getattr(bst_evidence, "initial_state", None),
            )
            return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())

        # Fallback (no interval dispatcher recovered): the committed shallow
        # redirect-only path.
        plan = lower_to_direct_graph(
            ctx.graph,
            ctx.facts,
            transition_result=transition_result,
            dispatch_map=getattr(recovery, "dispatch_map", None),
            dispatcher_entry_serial=dispatcher_entry,
            state_var_stkoff=state_var_stkoff,
            regions=_analysis(ctx, "plan_semantic_regions"),
            # Protected emission: the injected use-def safety capability vetoes redirects that would
            # orphan non-state-variable uses (north-star LowerStateMachine.require(UseDefSafety)).
            use_def_safety=ctx.capabilities.optional(UseDefSafetyCapability),
            live_function=live_function,
        )
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())


class CleanupResidualDispatcher:
    name = "cleanup_residual_dispatcher"

    def run(self, ctx: FunctionPipelineContext) -> PassResult:
        candidates = _analysis(ctx, "cleanup_candidates", ()) or ()
        plan = cleanup_residual_dispatcher(ctx.graph, ctx.facts, candidates=candidates)
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())
