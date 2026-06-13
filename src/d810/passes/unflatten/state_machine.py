"""Hodur state-machine unflattening passes — the unflatten north-star, realized.

Each pass schedules a portable analysis (facts over a ``FlowGraph``) or a portable transform
(producing a ``PatchPlan``). The five imports below are the WORK-LIST: each names a portable
function extracted (or being extracted) from the entangled hodur/engine files, pushing its
live-IDA reads behind the ``MicrocodeEvidenceProvider`` seam (graph-parameter, not mba-parameter;
the backend impl makes the identical live call, byte-identical for live-mba AND FlowGraph
projection — the llr-zeyu polymorphism guard).

These passes are importable + unit-tested NOW (skeleton transforms emit empty plans); they become
the live call graph once each work-list extraction lands its real body and the driver
(``run_d810_pipeline``) replaces the legacy state-machine orchestration. Until then this module is
additive + behavior-neutral (not wired into the maturity hook).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import ClassVar
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassResult,
    PreservedAnalyses, PipelinePass,
)

# --- WORK-LIST: portable extractions composed by the passes ---
from d810.analyses.control_flow.dispatcher_recovery import (
    DispatcherRecovery,
    min_state_constant_from_config,
    recover_dispatcher,
)
from d810.analyses.control_flow.reachability import reachable_from
from d810.analyses.machine import recover_machine
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
from d810.capabilities.machine_engines import MachineRecoveryEnginesCapability
from d810.analyses.data_flow.concolic import EmulationCapability
from d810.core import logging

logger = logging.getLogger("D810.passes.unflatten.state_machine")


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
# comparison kinds get a ComparisonDispatcherModel; the unflatten equality-chain detector
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


def _make_live_block_for(live_function):
    """Build a ``serial -> live block`` resolver over the backend mba, or ``None``.

    The reduced-product CONCRETE leg (ticket llr-xauw) steps a LIVE backend block;
    this adapts the opaque ``live_source`` (a Hex-Rays ``mba_t``) into the
    serial-keyed resolver :func:`emit_minimal_unflatten` threads to the fixpoint.
    Tolerant of API shape and best-effort: returns ``None`` (-> abstract-only) when
    no live function / ``get_mblock`` is available.
    """
    if live_function is None:
        return None
    getter = getattr(live_function, "get_mblock", None)
    if getter is None:
        return None

    def _live_block_for(serial: int):
        try:
            return getter(int(serial))
        except Exception:  # noqa: BLE001 — best-effort live-block resolution -> abstain
            return None

    return _live_block_for


def _resolve_initial_state(bst_evidence, recovery) -> int | None:
    """Resolve the dispatcher's initial state for the entry bridge.

    The recovered ``StateDispatcherMap.initial_state`` is preferred whenever it is
    present, because ``recover_dispatcher`` now threads the TRUE prologue state
    onto the map -- via the structural indirect-table recovery for INDIRECT_JUMP
    (ticket llr-m9r4) AND via entry-dominance for equality-chain / switch kinds
    (ticket llr-mra1). The latter corrects the SPURIOUS mid-chain value the live
    BST evidence supplies through the backwards ``_find_pre_header`` "fewest-npred"
    heuristic (which can pick an ``m_goto`` back-edge over the real ``m_mov``
    prologue). The BST value is only used as a fall-back when no map value was
    recovered. Address-agnostic -- every value is read from a recovered structure,
    never hardcoded. ``emit_minimal_unflatten`` still applies its own prologue-fold
    fallback when both are None.
    """
    dmap = getattr(recovery, "dispatch_map", None) if recovery is not None else None
    map_initial = getattr(dmap, "initial_state", None) if dmap is not None else None
    # Prefer the recovered map's initial_state. For INDIRECT_JUMP the BST analyzer
    # emits a spurious folded inner state; for equality-chain the BST emits a
    # spurious mid-chain state -- in both cases the map carries the structurally
    # recovered true prologue state, so it wins when present.
    if map_initial is not None:
        return int(map_initial)
    bst_initial = getattr(bst_evidence, "initial_state", None)
    if bst_initial is not None:
        return int(bst_initial)
    return None


def _recovery_from_machine(machine, graph, min_state_constant: int) -> DispatcherRecovery:
    """Adapt a P1 ``RecoveredMachine`` back into the existing ``DispatcherRecovery``.

    The reduced-product orchestrator (ticket llr-1d8u) returns the engine-neutral
    ``RecoveredMachine``; the downstream passes (``RecoverStateTransitions``,
    ``PlanSemanticRegions``, ``LowerStateMachine``, ``emit_minimal_unflatten``)
    consume a ``DispatcherRecovery`` whose ``dispatch_map`` is a
    ``StateDispatcherMap``. ``machine.to_state_dispatcher_map()`` is the EXACT
    inverse of the lift, so the projection yields the SAME map shape the emit path
    consumes -- the richer forking/context data is carried separately (published as
    ``recovered_machine``) and ignored by the emit. ``None`` machine -> an empty
    recovery (caller's downstream sees "no dispatcher", same as a clean function).
    """
    if graph is None:
        return DispatcherRecovery()
    adjacency = {serial: graph.successors(serial) for serial in graph.blocks}
    reachable = reachable_from(adjacency, graph.block_count, graph.entry_serial)
    if machine is None:
        return DispatcherRecovery(reachable_block_serials=reachable)
    dmap = machine.to_state_dispatcher_map()
    if dmap is None:
        return DispatcherRecovery(reachable_block_serials=reachable)
    return DispatcherRecovery(
        reachable_block_serials=reachable,
        dispatcher_block_serial=dmap.dispatcher_entry_block,
        bst_block_serials=tuple(sorted(dmap.dispatcher_blocks)),
        state_var_stkoff=dmap.state_var_stkoff,
        dispatch_map=dmap,
    )


class RecoverDispatcher(PipelinePass):
    name = "recover_dispatcher"

    def run(self, context: FunctionPipelineContext) -> PassResult:
        # Thread the project config's min_state_constant so recovery uses the SAME
        # threshold the family's detect did (detect/recover divergence is a known bug
        # class). Defaults to the module MIN_STATE_CONSTANT when absent.
        min_state_constant = min_state_constant_from_config(context.project_config)
        # Opt-in reduced-product engine (ticket llr-1d8u): when the project config
        # sets ``recovery_engine == "reduced_product"`` route dispatcher recovery
        # through the multi-engine orchestrator (sound AI spine + fold_exact-gated
        # concolic refinement of ⊤ cells). Absent the key, this branch is skipped
        # and ``RecoverDispatcher.run`` is byte-identical to the legacy single-engine
        # path -- no golden config sets the key, so the baseline is preserved by
        # construction (A4). The orchestrator REUSES ``recover_dispatcher`` for
        # anchoring, so even when only the StaticShape pattern resolves, the
        # projected map equals today's map.
        cfg = context.project_config
        engine = cfg.get("recovery_engine") if isinstance(cfg, dict) else None
        if logger.debug_on:
            logger.debug(
                "recover_dispatcher pass: engine=%r cfg_is_dict=%s has_engines_cap=%s",
                engine,
                isinstance(cfg, dict),
                context.capabilities.optional(MachineRecoveryEnginesCapability)
                is not None,
            )
        if engine == "reduced_product":
            # Thread the live-mba recovery engines (deffai spine + concolic) the
            # backend injected (ticket llr-iy9i). Absent the capability the
            # orchestrator composes over the static §1a candidate only (no
            # regression); present, the concolic engine (the proven old-engine
            # recovery) and the AI spine compete + refine.
            engines_cap = context.capabilities.optional(
                MachineRecoveryEnginesCapability
            )
            machine = recover_machine(
                context.graph,
                context.capabilities,
                project_config=cfg if isinstance(cfg, dict) else None,
                engines=engines_cap,
            )
            recovery = _recovery_from_machine(
                machine, context.graph, min_state_constant
            )
            _publish(context, "recovered_machine", machine)
        else:
            recovery = recover_dispatcher(
                context.graph, context.facts, min_state_constant=min_state_constant
            )
        _publish(context, self.name, recovery)
        # S2: build the consolidated ComparisonDispatcherModel for comparison
        # router kinds, folding in the pristine BST/interval evidence so
        # interval-routed next-states resolve via WrappedInterval.contains. The
        # model is published for RecoverStateTransitions to route through; None
        # for non-comparison kinds (caller falls back to exact-only).
        model = _build_comparison_model(recovery, _analysis(context, "bst_evidence"))
        _publish(context, "dispatcher_model", model)
        return PassResult(facts=(recovery,), preserved=PreservedAnalyses.all())


class RecoverStateTransitions(PipelinePass):
    name = "recover_state_transitions"

    def run(self, context: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(context, "recover_dispatcher")
        dispatch_map = getattr(recovery, "dispatch_map", None)
        # S2: route through the consolidated ComparisonDispatcherModel (exact ∪
        # interval) published by RecoverDispatcher; absent it (non-comparison
        # kind), resolution falls back to exact-only inside the resolver.
        model = _analysis(context, "dispatcher_model")
        resolutions = resolve_state_transitions(
            context.graph, context.facts, dispatch_map=dispatch_map, model=model
        )
        transition_result = transition_result_from_resolutions(
            resolutions, dispatch_map=dispatch_map
        )
        # Consume the injected value-range capability (north-star
        # ``capabilities.optional(ValRangeCapability)``). For now this records a read-only
        # confirmation metric proving the live capability executes end-to-end; the substantive
        # transition enrichment lands once #4's protected emission can absorb the richer DAG.
        valrange = context.capabilities.optional(ValRangeCapability)
        if valrange is not None and dispatch_map is not None:
            _publish(
                context,
                "valrange_confirmable_count",
                _count_valrange_confirmable(
                    valrange,
                    dispatch_map,
                    getattr(recovery, "state_var_stkoff", None),
                ),
            )
        _publish(context, self.name, resolutions)
        _publish(context, "transition_result", transition_result)
        return PassResult(
            facts=(resolutions, transition_result), preserved=PreservedAnalyses.all()
        )


class PlanSemanticRegions(PipelinePass):
    name = "plan_semantic_regions"

    def run(self, context: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(context, "recover_dispatcher")
        regions = plan_semantic_regions(
            context.graph,
            context.facts,
            transition_result=_analysis(context, "transition_result"),
            dispatcher_entry_serial=getattr(recovery, "dispatcher_block_serial", None),
            state_var_stkoff=getattr(recovery, "state_var_stkoff", None),
        )
        _publish(context, self.name, regions)
        return PassResult(facts=(regions,), preserved=PreservedAnalyses.all())

@dataclass
class LowerStateMachine(PipelinePass):
    """Lower the recovered state machine to dispatcher-bypass redirects (unflatten).

    The dispatcher router is **injectable** (ticket llr-oq8v): pass a custom
    ``resolvers`` chain and/or a ``configured_kind`` to pin the router shape; both
    default to the standard range-bst + exact-map detection chain, so the argless
    factory the pass driver invokes (``spec.pass_factory()``) is unchanged. To pin a
    kind per family, register ``lambda: LowerStateMachine(configured_kind=...)``.
    """

    name = "lower_state_machine"
    resolvers: tuple = field(default_factory=default_resolvers)
    configured_kind: RouterKind | None = None

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
            self.resolvers, ctx, configured_kind=self.configured_kind
        )

    def run(self, context: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(context, "recover_dispatcher")
        transition_result = _analysis(context, "transition_result")
        dispatcher_entry = getattr(recovery, "dispatcher_block_serial", None)
        state_var_stkoff = getattr(recovery, "state_var_stkoff", None)
        live_function = getattr(context.source, "live_source", None)
        bst_evidence = _analysis(context, "bst_evidence")

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
            # Initial state for the entry bridge: prefer the BST evidence (comparison /
            # switch kinds), fall back to the recovered StateDispatcherMap.initial_state
            # for the INDIRECT_JUMP kind where bst_evidence is None (ticket llr-16jl).
            initial_state = _resolve_initial_state(bst_evidence, recovery)
            dmap = getattr(recovery, "dispatch_map", None)
            # INDIRECT-only emit gates (ticket llr-m9r4): the terminal-tail recovery
            # and the shared-EXIT redirect veto are load-bearing for the Tigress
            # INDIRECT_JUMP shape but regress equality-chain / switch goldens
            # (hodur, approov). Thread the dispatcher kind so only the indirect
            # profile enables them.
            is_indirect = (
                getattr(dmap, "source", None) is DispatcherType.INDIRECT_JUMP
                if dmap is not None
                else False
            )
            if logger.debug_on:
                logger.debug(
                    "unflat initial_state thread: bst=%s map=%s resolved=%s kind=%s",
                    getattr(bst_evidence, "initial_state", None),
                    getattr(dmap, "initial_state", None) if dmap is not None else None,
                    initial_state,
                    getattr(dmap, "source", None) if dmap is not None else None,
                )
            # Reduced-product CONCRETE leg (ticket llr-xauw): the optional
            # prove-exact-or-abstain block emulator, consulted only where the abstract
            # fixpoint fold left a back-edge next-state at ⊥ (the opaque reg^reg writers
            # whose operands live in other blocks). ``emu is None`` -> abstract-only,
            # byte-identical with the prior behaviour; the consult NEVER overrides a
            # fixpoint-resolved transition.
            emu = context.capabilities.optional(EmulationCapability)
            # Use-def severance veto (ticket llr-wlzb): the same UseDefSafetyCapability
            # the fallback lower_to_direct_graph path consults, now threaded into the
            # PRIMARY emit path so a redirect that orphans a non-state carrier (the
            # OLLVM ``var_18 = var_378`` accumulator copies) is dropped. Gated
            # D810_USE_DEF_VETO (default OFF) inside the filter -> byte-identical default.
            plan = emit_minimal_unflatten(
                context.graph,
                dispatcher,
                state_var_stkoff=int(state_var_stkoff),
                dispatcher_entry_serial=int(dispatcher_entry),
                pre_header_serial=getattr(bst_evidence, "pre_header_serial", None),
                initial_state=initial_state,
                is_indirect=is_indirect,
                fact_view=getattr(context, "facts", None),
                emu=emu,
                live_block_for=_make_live_block_for(live_function),
                use_def_safety=context.capabilities.optional(UseDefSafetyCapability),
                live_function=live_function,
            )
            return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())

        # Fallback (no interval dispatcher recovered): the committed shallow
        # redirect-only path.
        plan = lower_to_direct_graph(
            context.graph,
            context.facts,
            transition_result=transition_result,
            dispatch_map=getattr(recovery, "dispatch_map", None),
            dispatcher_entry_serial=dispatcher_entry,
            state_var_stkoff=state_var_stkoff,
            regions=_analysis(context, "plan_semantic_regions"),
            # Protected emission: the injected use-def safety capability vetoes redirects that would
            # orphan non-state-variable uses (north-star LowerStateMachine.require(UseDefSafety)).
            use_def_safety=context.capabilities.optional(UseDefSafetyCapability),
            live_function=live_function,
        )
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())


class CleanupResidualDispatcher(PipelinePass):
    name = "cleanup_residual_dispatcher"

    def run(self, context: FunctionPipelineContext) -> PassResult:
        candidates = _analysis(context, "cleanup_candidates", ()) or ()
        plan = cleanup_residual_dispatcher(context.graph, context.facts, candidates=candidates)
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())
