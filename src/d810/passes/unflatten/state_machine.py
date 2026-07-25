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

from dataclasses import dataclass, field, replace

from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassFact,
    PassResult,
    PreservedAnalyses,
    PipelinePass,
)

# --- WORK-LIST: portable extractions composed by the passes ---
from d810.analyses.control_flow.dispatcher_recovery import (
    DispatcherRecovery,
    min_state_constant_from_config,
    recover_dispatcher,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.reachability import reachable_from
from d810.analyses.machine import recover_machine
from d810.analyses.control_flow.comparison_dispatcher_model import (
    ComparisonDispatcherModel,
)
from d810.capabilities.dispatcher import RouterKind, TableProvenance
from d810.analyses.control_flow.branch_witness_provider import (
    build_static_equality_chain_witness_map,
)
from d810.analyses.control_flow.dispatcher_discovery_facts import (
    PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE,
    collect_state_dispatcher_discovery_fact_observations,
)
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    collect_predecessor_dispatcher_target_facts,
)
from d810.analyses.control_flow.router_resolver import (
    RouterResolutionContext,
    default_resolvers,
    select_router,
)
from d810.analyses.control_flow.semantic_transition import resolve_state_transitions
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    bind_canonical_semantic_evidence,
    semantic_route_proof_reaches_consumer,
)
from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
)
from d810.analyses.control_flow.transition_builder import (
    transition_result_from_resolutions,
)
from d810.transforms.semantic_regions import plan_semantic_regions
from d810.transforms.state_machine_unflatten import lower_to_direct_graph
from d810.transforms.minimal_unflatten_emit import emit_minimal_unflatten
from d810.transforms.dispatcher_cleanup import cleanup_residual_dispatcher
from d810.transforms.canonical_semantic_fragment import (
    CanonicalSemanticFragmentRejected,
    build_canonical_semantic_fragment_plan,
    compose_canonical_semantic_boundary_fragment_plan,
    compose_canonical_semantic_fragment_plan,
)
from d810.transforms.fragment_plan import (
    FragmentPlan,
    FragmentPublicationPurpose,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
    FrontendNormalizationPlanCapability,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.capabilities.branch_witness import BranchWitnessCapability
from d810.capabilities.value_range import ValRangeCapability
from d810.capabilities.use_def_safety import UseDefSafetyCapability
from d810.capabilities.machine_engines import MachineRecoveryEnginesCapability
from d810.capabilities.semantic_routes import (
    CanonicalSemanticCandidateEvidenceCapability,
    CanonicalSemanticEvidenceCapability,
    SemanticRouteReferenceOracleCapability,
)
from d810.transforms.detached_route_oracle import (
    DetachedRouteOracleRejected,
    bind_fragment_reference_oracle,
)
from d810.analyses.data_flow.concolic import EmulationCapability
from d810.core import logging
from d810.core.observability_preanalysis import observe_state_dispatcher_rows

logger = logging.getLogger("D810.passes.unflatten.state_machine")

LOWER_STATE_MACHINE_PLAN_METADATA = "lower_state_machine_plan_metadata"
CANONICAL_SEMANTIC_EVIDENCE = "canonical_semantic_evidence"
BOUND_CANONICAL_SEMANTIC_EVIDENCE = "bound_canonical_semantic_evidence"


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


# RouterKinds whose route() is the shared comparison body (exact ∪ interval).
_COMPARISON_ROUTER_KINDS = frozenset(
    {
        RouterKind.EQUALITY_CHAIN,
        RouterKind.CONDITION_CHAIN,
    }
)

_STATIC_BRANCH_KINDS = frozenset(
    {
        "eq",
        "ne",
        "jz",
        "jnz",
        "jz_taken",
        "jz_fallthrough",
        "jnz_taken",
        "jnz_fallthrough",
    }
)


def _build_comparison_model(recovery, range_evidence):
    """Build a ``ComparisonDispatcherModel`` when the kind is a comparison router.

    Returns ``None`` for non-comparison kinds (unknown or indirect table
    provenance) or when no dispatch map was recovered, so the caller falls back
    to exact-only routing.
    """
    dispatch_map = getattr(recovery, "dispatch_map", None)
    if dispatch_map is None:
        return None
    router_kind = getattr(dispatch_map, "router_kind", RouterKind.UNKNOWN)
    table_provenance = getattr(dispatch_map, "table_provenance", None)
    is_switch_table = (
        router_kind is RouterKind.TABLE and table_provenance is TableProvenance.SWITCH
    )
    if router_kind not in _COMPARISON_ROUTER_KINDS and not is_switch_table:
        return None
    return ComparisonDispatcherModel.from_recovery(
        dispatch_map, range_evidence=range_evidence
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


def _effective_state_identity(
    recovery: DispatcherRecovery | None,
    *,
    materialized_computed_goto_profile: bool,
    materialized_state_var_reg: int | None,
) -> tuple[int | None, int | None]:
    """Select the state cell used by lowering.

    Exact resolver evidence wins only for the materialized computed-goto
    profile.  That profile can expose a stack-carried alias to dispatcher
    recovery even though native state writes and comparisons use one register.
    Replacing, rather than combining, the identities keeps stack-only scanners
    from treating the alias as the state machine cell.
    """
    recovered_stkoff = recovery.state_var_stkoff if recovery is not None else None
    recovered_reg = recovery.state_var_reg if recovery is not None else None
    if materialized_computed_goto_profile and materialized_state_var_reg is not None:
        return (None, int(materialized_state_var_reg))
    return (recovered_stkoff, recovered_reg)


def _publish_observation_evidence(ctx: FunctionPipelineContext, observations) -> None:
    put_observation_evidence = getattr(ctx.facts, "put_observation_evidence", None)
    if not callable(put_observation_evidence):
        return
    for observation in observations:
        put_observation_evidence(observation)


def _maturity_label(ctx: FunctionPipelineContext) -> str:
    maturity = getattr(ctx, "maturity", None)
    value = getattr(maturity, "value", None)
    if value is not None:
        return str(value)
    if maturity is not None:
        return str(maturity)
    return "unknown"


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


def _resolve_initial_state(range_evidence, recovery) -> int | None:
    """Resolve the dispatcher's initial state for the entry bridge.

    The recovered ``StateDispatcherMap.initial_state`` is preferred whenever it is
    present, because ``recover_dispatcher`` now threads the TRUE prologue state
    onto the map -- via the structural indirect-table recovery for
    ``TABLE`` with indirect-jump provenance (ticket llr-m9r4) AND via
    entry-dominance for equality-chain / switch-table provenance
    (ticket llr-mra1). The latter corrects the SPURIOUS mid-chain value the live
    range evidence supplies through the backwards ``_find_pre_header`` "fewest-npred"
    heuristic (which can pick an ``m_goto`` back-edge over the real ``m_mov``
    prologue). The range value is only used as a fall-back when no map value was
    recovered. Address-agnostic -- every value is read from a recovered structure,
    never hardcoded. ``emit_minimal_unflatten`` still applies its own prologue-fold
    fallback when both are None.
    """
    dmap = getattr(recovery, "dispatch_map", None) if recovery is not None else None
    map_initial = getattr(dmap, "initial_state", None) if dmap is not None else None
    # Prefer the recovered map's initial_state. For indirect table provenance the range analyzer
    # emits a spurious folded inner state; for equality-chain it emits a
    # spurious mid-chain state -- in both cases the map carries the structurally
    # recovered true prologue state, so it wins when present.
    if map_initial is not None:
        return int(map_initial)
    # Register-BST soundness: a register-resident state var reaches its
    # dispatcher through an indirect / decoy re-dispatch spine, and the live range
    # analyzer can fabricate an UNTRUSTWORTHY initial state for it by selecting a
    # range leaf while the prologue actually writes a non-leaf pivot. Bridging to
    # that wrong leaf routes the prologue to the wrong handler
    # and orphans the true chain -- the function collapses to a bare ``while(1);``.
    # Distrust the range value here and return None so ``emit_minimal_unflatten`` folds
    # the initial state from the prologue's OWN state-write (unseeded); when that fold
    # cannot confirm a state (this shared-merge prologue), its entry-bridge bail leaves
    # the function intact. Scoped to the register path -> stack goldens are untouched.
    if getattr(recovery, "state_var_reg", None) is not None:
        return None
    range_initial = getattr(range_evidence, "initial_state", None)
    if range_initial is not None:
        return int(range_initial)
    return None


def _entry_bridge_requires_witness(dmap) -> bool:
    """Return whether entry shortcutting needs an exact branch witness.

    Conditional-chain maps are the only shape with production per-compare
    witness plumbing today.  Emulated conditional-chain rows are still endpoint
    rows, not proof, so they must go through the same witness/liveness policy:
    static witness if the current CFG can prove it, otherwise the no-provider
    exit-path liveness fallback.  Other comparison shapes, including
    range/interval routing, stay on the legacy endpoint shortcut path until they
    grow explicit witness providers of their own.
    """
    if getattr(dmap, "router_kind", None) is RouterKind.CONDITION_CHAIN:
        rows = tuple(getattr(dmap, "rows", ()) or ())
        branch_kinds = {str(getattr(row, "branch_kind", "")) for row in rows}
        return bool(branch_kinds & _STATIC_BRANCH_KINDS) or "emulated" in branch_kinds
    return False


def _needs_multi_entry_back_edge_recovery(range_evidence, dmap) -> bool:
    """Whether exact dispatcher rows prove the range router dropped states."""

    if getattr(dmap, "router_kind", None) is not RouterKind.CONDITION_CHAIN:
        return False
    range_router = getattr(range_evidence, "dispatcher", None)
    lookup = getattr(range_router, "lookup", None)
    if not callable(lookup):
        return False
    state_to_handler = dmap.state_to_handler() if dmap is not None else {}
    if not state_to_handler:
        return False

    default_target = getattr(range_router, "default_target", None)
    for state, exact_target in state_to_handler.items():
        routed = lookup(int(state) & 0xFFFFFFFF)
        if routed is not None and int(routed) == int(exact_target):
            continue
        if routed is None:
            return True
        if default_target is not None and int(routed) == int(default_target):
            return True
    return False


def _has_emulated_endpoint_rows(dmap) -> bool:
    rows = tuple(getattr(dmap, "rows", ()) or ())
    return any(str(getattr(row, "branch_kind", "")) == "emulated" for row in rows)


def _recovery_from_machine(
    machine, graph, min_state_constant: int
) -> DispatcherRecovery:
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
        condition_chain_block_serials=tuple(sorted(dmap.dispatcher_blocks)),
        state_var_stkoff=dmap.state_var_stkoff,
        state_var_reg=getattr(dmap, "state_var_reg", None),
        dispatch_map=dmap,
    )


def _materialized_dispatcher_recovery(
    context: FunctionPipelineContext,
    recovery: DispatcherRecovery,
) -> DispatcherRecovery:
    """Build an exact current-snapshot dispatcher view from portable evidence.

    PREOPT import can remove the legacy comparison dispatcher while retaining
    exact state-to-native-handler routes.  The live adapter has already rebound
    those native EAs to this FlowGraph; this pass packages that ephemeral view
    into the ordinary portable dispatcher contract.  Missing, conflicting, or
    non-live identities abstain rather than inventing serials.
    """
    if recovery.dispatch_map is not None or not bool(
        _analysis(context, "materialized_computed_goto_profile", False)
    ):
        return recovery
    state_var_reg = _analysis(context, "materialized_state_var_reg")
    entry_serial = _analysis(context, "materialized_dispatcher_entry_serial")
    handlers = {
        int(state) & 0xFFFFFFFF: int(serial)
        for state, serial in (
            _analysis(context, "materialized_handler_by_state", {}) or {}
        ).items()
    }
    router_serials = frozenset(
        int(serial)
        for serial in (
            _analysis(context, "materialized_dispatcher_router_serials", ()) or ()
        )
    )
    if state_var_reg is None or entry_serial is None or not handlers:
        return recovery
    entry_serial = int(entry_serial)
    if context.graph.get_block(entry_serial) is None:
        return recovery
    if any(context.graph.get_block(serial) is None for serial in handlers.values()):
        return recovery
    dispatcher_blocks = frozenset({entry_serial, *router_serials})
    if any(context.graph.get_block(serial) is None for serial in dispatcher_blocks):
        return recovery
    rows = tuple(
        StateDispatcherRow(
            state_const=int(state),
            target_block=int(target),
            dispatcher_block=entry_serial,
            compare_block=None,
            branch_kind="materialized_exact",
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        for state, target in sorted(handlers.items())
    )
    dispatch_map = StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=entry_serial,
        dispatcher_blocks=dispatcher_blocks,
        state_var_stkoff=None,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
        state_var_reg=int(state_var_reg),
    )
    return DispatcherRecovery(
        reachable_block_serials=recovery.reachable_block_serials,
        dispatcher_block_serial=entry_serial,
        condition_chain_block_serials=tuple(sorted(dispatcher_blocks)),
        state_var_stkoff=None,
        state_var_reg=int(state_var_reg),
        dispatch_map=dispatch_map,
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
            analysis_outputs = {"recovered_machine": machine}
        else:
            recovery = recover_dispatcher(
                context.graph,
                context.facts,
                min_state_constant=min_state_constant,
                materialized_indirect_transfers=tuple(
                    _analysis(context, "materialized_indirect_transfers", ()) or ()
                ),
            )
            analysis_outputs = {}
        recovery = _materialized_dispatcher_recovery(context, recovery)
        _publish(context, self.name, recovery)
        analysis_outputs[self.name] = recovery
        dispatch_map = getattr(recovery, "dispatch_map", None)
        if dispatch_map is not None:
            # Emit before LowerStateMachine applies its rewrite plan. The pass
            # manager invalidates analyses after that mutation, but the diag
            # event handler buffers this row until the recovery-status snapshot
            # is captured, preserving the exact pre-rewrite map in SQLite.
            observe_state_dispatcher_rows(
                func_ea=int(getattr(context.graph, "func_ea", 0) or 0),
                maturity=_maturity_label(context),
                dispatcher_entry_block=int(dispatch_map.dispatcher_entry_block),
                dispatcher_kind=dispatch_map.router_kind.name,
                rows=dispatch_map.rows,
            )
            _publish_observation_evidence(
                context,
                collect_state_dispatcher_discovery_fact_observations(
                    state_dispatcher_map=dispatch_map,
                    maturity=_maturity_label(context),
                    phase=self.name,
                ),
            )
        # S2: build the consolidated ComparisonDispatcherModel for comparison
        # router kinds, folding in the pristine range/interval evidence so
        # interval-routed next-states resolve via WrappedInterval.contains. The
        # model is published for RecoverStateTransitions to route through; None
        # for non-comparison kinds (caller falls back to exact-only).
        model = _build_comparison_model(recovery, _analysis(context, "range_evidence"))
        _publish(context, "dispatcher_model", model)
        analysis_outputs["dispatcher_model"] = model
        return PassResult(
            facts=(PassFact("dispatcher_family", recovery),),
            preserved=PreservedAnalyses.all(),
            analysis_outputs=analysis_outputs,
        )


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
        range_evidence = _analysis(context, "range_evidence")
        if dispatch_map is not None:
            predecessor_target_facts = collect_predecessor_dispatcher_target_facts(
                transition_result=transition_result,
                dispatcher_entry_serial=int(dispatch_map.dispatcher_entry_block),
                state_dispatcher_map=dispatch_map,
                range_evidence=range_evidence,
                transition_resolutions=resolutions,
                state_var_stkoff=getattr(recovery, "state_var_stkoff", None),
            )
            if predecessor_target_facts:
                _publish_observation_evidence(
                    context,
                    tuple(
                        observation
                        for observation in collect_state_dispatcher_discovery_fact_observations(
                            state_dispatcher_map=dispatch_map,
                            maturity=_maturity_label(context),
                            phase=self.name,
                            predecessor_target_facts=predecessor_target_facts,
                        )
                        if observation.kind == PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE
                    ),
                )
        # Consume the injected value-range capability (north-star
        # ``capabilities.optional(ValRangeCapability)``). For now this records a read-only
        # confirmation metric proving the live capability executes end-to-end; the substantive
        # transition enrichment lands once #4's protected emission can absorb the richer DAG.
        valrange = context.capabilities.optional(ValRangeCapability)
        analysis_outputs = {
            self.name: resolutions,
            "transition_result": transition_result,
        }
        semantic_provider = context.capabilities.optional(
            CanonicalSemanticEvidenceCapability
        )
        if semantic_provider is not None:
            semantic_evidence = semantic_provider.evidence_for(
                int(context.graph.func_ea)
            )
            if semantic_evidence is not None:
                if not isinstance(
                    semantic_evidence,
                    CanonicalSemanticEvidence,
                ):
                    raise TypeError(
                        "canonical semantic capability returned non-portable evidence"
                    )
                bound_semantic_evidence = bind_canonical_semantic_evidence(
                    context.graph,
                    semantic_evidence,
                )
                _publish(
                    context,
                    CANONICAL_SEMANTIC_EVIDENCE,
                    semantic_evidence,
                )
                analysis_outputs[CANONICAL_SEMANTIC_EVIDENCE] = semantic_evidence
                if bound_semantic_evidence is not None:
                    _publish(
                        context,
                        BOUND_CANONICAL_SEMANTIC_EVIDENCE,
                        bound_semantic_evidence,
                    )
                    analysis_outputs[BOUND_CANONICAL_SEMANTIC_EVIDENCE] = (
                        bound_semantic_evidence
                    )
        if valrange is not None and dispatch_map is not None:
            confirmable_count = _count_valrange_confirmable(
                valrange,
                dispatch_map,
                getattr(recovery, "state_var_stkoff", None),
            )
            _publish(
                context,
                "valrange_confirmable_count",
                confirmable_count,
            )
            analysis_outputs["valrange_confirmable_count"] = confirmable_count
        _publish(context, self.name, resolutions)
        _publish(context, "transition_result", transition_result)
        return PassResult(
            facts=(PassFact("state_transition", transition_result),),
            preserved=PreservedAnalyses.all(),
            analysis_outputs=analysis_outputs,
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
        return PassResult(
            facts=(PassFact("semantic_region", regions),),
            preserved=PreservedAnalyses.all(),
            analysis_outputs={self.name: regions},
        )


def _connected_route_candidate(
    evidence: CanonicalSemanticEvidence,
    route_index: int,
) -> CanonicalSemanticEvidence:
    """Keep downstream semantic consumers in the same atomic work item."""
    root = evidence.route_proofs[int(route_index)]
    selected = [root]
    selected_ids = {root.proof_id}
    changed = True
    while changed:
        changed = False
        for candidate in evidence.route_proofs:
            if candidate.proof_id in selected_ids:
                continue
            if not any(
                semantic_route_proof_reaches_consumer(proof, candidate)
                for proof in selected
            ):
                continue
            selected.append(candidate)
            selected_ids.add(candidate.proof_id)
            changed = True
    if len(selected) == len(evidence.route_proofs):
        return evidence
    atomic_group_id = f"{evidence.atomic_group_id}:work-item:{root.proof_id}"
    return CanonicalSemanticEvidence(
        native_key=evidence.native_key,
        generation=evidence.generation,
        atomic_group_id=atomic_group_id,
        route_proofs=tuple(
            replace(proof, atomic_group_id=atomic_group_id) for proof in selected
        ),
    )


def _plan_candidate_normalization(
    context: FunctionPipelineContext,
    candidate: CanonicalSemanticEvidence,
    plan_provider: FrontendNormalizationPlanCapability,
) -> tuple[FragmentPlan, NormalizationWorkItemAuthority] | None:
    """Read receipt-associated PREOPT intent for one exact evidence generation."""
    first_proof = candidate.route_proofs[0] if candidate.route_proofs else None
    anchor_ea = (
        int(first_proof.source_anchor_ea)
        if first_proof is not None
        else int(context.graph.func_ea)
    )
    binding = plan_provider.plan_for(
        int(context.graph.func_ea),
        int(candidate.generation),
    )
    if binding is None:
        payload = {"evidence_generation": int(candidate.generation)}
        if first_proof is not None:
            payload["route_proof_id"] = first_proof.proof_id
        raise CanonicalSemanticFragmentRejected(
            f"candidate route 0x{anchor_ea:X} has no receipt-associated "
            "PREOPT plan intent",
            reason_code="frontend_normalization_plan_intent_missing",
            anchor_ea=anchor_ea,
            payload=payload,
        )
    if (
        not isinstance(binding, tuple)
        or len(binding) != 2
        or not isinstance(binding[0], FragmentPlan)
        or not isinstance(binding[1], NormalizationWorkItemAuthority)
    ):
        raise TypeError(
            "frontend normalization plan capability returned invalid receipt binding"
        )
    plan, authority = binding
    if (
        plan.publication_purpose
        is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        or plan.native_key != candidate.native_key
    ):
        raise CanonicalSemanticFragmentRejected(
            f"candidate route 0x{anchor_ea:X} PREOPT plan authority drifted",
            reason_code="frontend_normalization_plan_intent_drift",
            anchor_ea=anchor_ea,
            payload={
                "evidence_generation": int(candidate.generation),
                "route_proof_id": (
                    None if first_proof is None else first_proof.proof_id
                ),
            },
        )
    return plan, authority


def _semantic_predecessor_boundary_anchor(
    rejection: CanonicalSemanticFragmentRejected,
    evidence: CanonicalSemanticEvidence,
) -> int | None:
    """Recover one proof-owned source block behind a rejected boundary."""
    if (
        rejection.reason_code != "published_imported_boundary_topology_unresolved"
        or rejection.anchor_ea is None
    ):
        return None
    operation_id = rejection.payload.get("incoming_operation_id")
    source_anchor = rejection.payload.get("incoming_source_anchor_ea")
    if not isinstance(operation_id, str) or not operation_id.startswith("route:"):
        return None
    if isinstance(source_anchor, str):
        try:
            source_anchor_ea = int(source_anchor, 0)
        except ValueError:
            return None
    elif isinstance(source_anchor, int):
        source_anchor_ea = int(source_anchor)
    else:
        return None
    proof_id = operation_id.removeprefix("route:")
    proofs = tuple(
        proof for proof in evidence.route_proofs if proof.proof_id == proof_id
    )
    if len(proofs) != 1:
        return None
    (proof,) = proofs
    boundary_anchor_ea = int(rejection.anchor_ea)
    state_write = proof.state_write
    source_is_state_write_entry = bool(
        state_write is not None
        and int(state_write.instruction_ea) == source_anchor_ea
        and source_anchor_ea in state_write.identity.exact_instruction_eas
        and state_write.identity.native_ranges.contains(source_anchor_ea)
        and state_write.corridor_instruction_eas
        and int(state_write.corridor_instruction_eas[0]) == source_anchor_ea
        and int(state_write.corridor_instruction_eas[-1]) == int(proof.source_anchor_ea)
        and int(proof.source_anchor_ea) in proof.source_identity.exact_instruction_eas
    )
    source_identity_owns_entry = bool(
        (
            proof.source_identity.native_ranges.contains(source_anchor_ea)
            and source_anchor_ea in proof.source_identity.exact_instruction_eas
        )
        or source_is_state_write_entry
    )
    if not source_identity_owns_entry or not any(
        destination.target_identity.native_ranges.contains(boundary_anchor_ea)
        and int(destination.target_anchor_ea) == boundary_anchor_ea
        for destination in proof.destinations
    ):
        return None
    return source_anchor_ea


def _temporary_boundary_port_retirement_obligation(
    *,
    boundary_anchor_ea: int,
    source_anchor_ea: int,
    upstream_rejection: CanonicalSemanticFragmentRejected,
) -> str | None:
    """Name one deferred semantic entry only after live ownership is disproved."""
    boundary_anchor_ea = int(boundary_anchor_ea)
    source_anchor_ea = int(source_anchor_ea)
    if (
        boundary_anchor_ea == source_anchor_ea
        or upstream_rejection.reason_code
        != "published_boundary_current_owner_count_mismatch"
        or upstream_rejection.anchor_ea != source_anchor_ea
    ):
        return None
    owner_labels = upstream_rejection.payload.get("owner_labels")
    current_inventory = upstream_rejection.payload.get("current_identity_inventory")
    incoming_operations = upstream_rejection.payload.get(
        "normalization_incoming_operations"
    )
    if owner_labels not in ((), []) or current_inventory not in ((), []):
        return None
    if not isinstance(incoming_operations, (tuple, list)) or not incoming_operations:
        return None
    if any(
        not isinstance(operation, dict)
        or operation.get("source_owner_labels") not in ((), [])
        or operation.get("source_current_identity_inventory") not in ((), [])
        for operation in incoming_operations
    ):
        return None
    return (
        f"retire-temporary-dispatcher-entry@0x{boundary_anchor_ea:X}:"
        f"publish-semantic-predecessor@0x{source_anchor_ea:X}"
    )


def _boundary_reference_oracle_rejection(
    *,
    boundary_anchor_ea: int,
    boundary_plan: FragmentPlan,
) -> CanonicalSemanticFragmentRejected:
    route_proof_ids = tuple(
        operation.operation_id.removeprefix("route:")
        for operation in boundary_plan.operations
        if operation.operation_id.startswith("route:")
    )
    return CanonicalSemanticFragmentRejected(
        "bounded canonical boundary plan requires detached reference-oracle "
        "proof before live publication",
        reason_code="canonical_boundary_detached_oracle_required",
        anchor_ea=boundary_anchor_ea,
        payload={
            "atomic_group_id": boundary_plan.atomic_group_id,
            "block_count": len(boundary_plan.blocks),
            "boundary_anchor_ea": f"0x{boundary_anchor_ea:X}",
            "boundary_ports": tuple(
                {
                    "kind": port.kind.value,
                    "port_id": port.port_id,
                    "predecessor_block_id": port.predecessor_block_id,
                    "retirement_obligation_id": port.retirement_obligation_id,
                    "root_block_id": port.root_block_id,
                }
                for port in boundary_plan.boundary_ports
            ),
            "native_body_count": len(boundary_plan.native_bodies),
            "operation_count": len(boundary_plan.operations),
            "operation_ids": tuple(
                operation.operation_id for operation in boundary_plan.operations
            ),
            "plan_id": boundary_plan.plan_id,
            "route_proof_ids": route_proof_ids,
        },
    )


def _bind_boundary_reference_oracle(
    context: FunctionPipelineContext,
    *,
    function_ea: int,
    boundary_anchor_ea: int,
    boundary_plan: FragmentPlan,
) -> FragmentPlan:
    oracle_provider = context.capabilities.optional(
        SemanticRouteReferenceOracleCapability
    )
    rewrite_anchor_eas = tuple(
        rewrite.rewrite_anchor_ea
        for operation in boundary_plan.operations
        if (rewrite := operation.direct_transfer_rewrite) is not None
    )
    selection = (
        None
        if oracle_provider is None
        else oracle_provider.reference_oracle_for(
            int(function_ea),
            boundary_plan.native_key,
            rewrite_anchor_eas,
        )
    )
    if selection is None:
        raise _boundary_reference_oracle_rejection(
            boundary_anchor_ea=boundary_anchor_ea,
            boundary_plan=boundary_plan,
        )
    try:
        return bind_fragment_reference_oracle(boundary_plan, selection)
    except (DetachedRouteOracleRejected, TypeError) as exc:
        rejection = _boundary_reference_oracle_rejection(
            boundary_anchor_ea=boundary_anchor_ea,
            boundary_plan=boundary_plan,
        )
        raise CanonicalSemanticFragmentRejected(
            "bounded canonical boundary plan has invalid detached "
            "reference-oracle authority",
            reason_code="canonical_boundary_detached_oracle_invalid",
            anchor_ea=boundary_anchor_ea,
            payload={
                **rejection.payload,
                "cause_detail": str(exc),
            },
        ) from exc


def _rejected_canonical_composition_attempt(
    *,
    kind: str,
    rejection: CanonicalSemanticFragmentRejected,
    route_candidate: CanonicalSemanticEvidence | None = None,
    boundary_anchor_ea: int | None = None,
) -> dict[str, object]:
    """Serialize one rejected composition attempt with stable native anchors."""
    payload: dict[str, object] = {
        "kind": str(kind),
        "outcome": "rejected",
        "reason_code": rejection.reason_code,
        "rejection_anchor_ea": (
            None
            if rejection.anchor_ea is None
            else f"0x{int(rejection.anchor_ea):X}"
        ),
        "detail": str(rejection),
        "rejection_payload": dict(rejection.payload),
    }
    if route_candidate is not None:
        payload.update(
            {
                "route_proof_ids": tuple(
                    proof.proof_id for proof in route_candidate.route_proofs
                ),
                "route_source_anchor_eas": tuple(
                    f"0x{int(proof.source_anchor_ea):X}"
                    for proof in route_candidate.route_proofs
                ),
            }
        )
    if boundary_anchor_ea is not None:
        payload["boundary_anchor_ea"] = f"0x{int(boundary_anchor_ea):X}"
    return payload


def _accepted_canonical_composition_attempt(
    *,
    kind: str,
    plan: FragmentPlan,
    route_candidate: CanonicalSemanticEvidence | None = None,
    boundary_anchor_ea: int | None = None,
) -> dict[str, object]:
    """Serialize one accepted composition attempt before oracle/publication gates."""
    payload: dict[str, object] = {
        "kind": str(kind),
        "outcome": "accepted",
        "plan_id": plan.plan_id,
        "atomic_group_id": plan.atomic_group_id,
        "block_count": len(plan.blocks),
        "operation_count": len(plan.operations),
        "native_body_count": len(plan.native_bodies),
        "root_block_ids": plan.roots,
    }
    if route_candidate is not None:
        payload.update(
            {
                "route_proof_ids": tuple(
                    proof.proof_id for proof in route_candidate.route_proofs
                ),
                "route_source_anchor_eas": tuple(
                    f"0x{int(proof.source_anchor_ea):X}"
                    for proof in route_candidate.route_proofs
                ),
            }
        )
    if boundary_anchor_ea is not None:
        payload["boundary_anchor_ea"] = f"0x{int(boundary_anchor_ea):X}"
    return payload


def _with_canonical_composition_attempts(
    rejection: CanonicalSemanticFragmentRejected,
    attempts: tuple[dict[str, object], ...],
) -> CanonicalSemanticFragmentRejected:
    """Attach the complete attempt ledger without replacing the final rejection."""
    payload = dict(rejection.payload)
    payload["composition_attempts"] = tuple(dict(attempt) for attempt in attempts)
    return CanonicalSemanticFragmentRejected(
        str(rejection),
        reason_code=rejection.reason_code,
        anchor_ea=rejection.anchor_ea,
        payload=payload,
    )


def _compose_candidate_semantic_fragment(
    context: FunctionPipelineContext,
    *,
    prohibited_dispatcher_serials: tuple[int, ...],
) -> tuple[FragmentPlan, int]:
    candidate_provider = context.capabilities.optional(
        CanonicalSemanticCandidateEvidenceCapability
    )
    frontend_provider = context.capabilities.optional(
        FrontendNormalizationEvidenceCapability
    )
    plan_provider = context.capabilities.optional(FrontendNormalizationPlanCapability)
    if candidate_provider is None or frontend_provider is None or plan_provider is None:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition requires candidate evidence, normalization "
            "evidence, and receipt-associated PREOPT plan intent",
            reason_code="canonical_composition_capability_missing",
            anchor_ea=int(context.graph.func_ea),
        )
    function_ea = int(context.graph.func_ea)
    candidate = candidate_provider.candidate_evidence_for(function_ea)
    frontend_evidence = frontend_provider.evidence_for(function_ea)
    if not isinstance(candidate, CanonicalSemanticEvidence):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition has no current candidate evidence",
            reason_code="canonical_candidate_evidence_missing",
            anchor_ea=function_ea,
        )
    if not isinstance(frontend_evidence, FrontendNormalizationEvidence):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition has no current normalization evidence",
            reason_code="frontend_normalization_evidence_missing",
            anchor_ea=function_ea,
        )
    if (
        candidate.native_key != frontend_evidence.native_key
        or candidate.generation != frontend_evidence.generation
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition evidence generation drifted",
            reason_code="canonical_composition_generation_drift",
            anchor_ea=function_ea,
            payload={
                "candidate_generation": int(candidate.generation),
                "normalization_generation": int(frontend_evidence.generation),
            },
        )
    normalization_binding = _plan_candidate_normalization(
        context,
        candidate,
        plan_provider,
    )
    if normalization_binding is None:
        first_route_anchor = (
            int(candidate.route_proofs[0].source_anchor_ea)
            if candidate.route_proofs
            else function_ea
        )
        raise CanonicalSemanticFragmentRejected(
            "canonical composition has no unpublished normalization plan",
            reason_code="unpublished_normalization_plan_missing",
            anchor_ea=first_route_anchor,
        )
    normalization_plan, normalization_authority = normalization_binding
    current_identity_index = _analysis(
        context,
        "current_block_identity_index",
    )
    identity_for_serial = getattr(
        current_identity_index,
        "identity_for_serial",
        None,
    )
    if not callable(identity_for_serial):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition requires current identity authority",
            reason_code="current_identity_authority_missing",
            anchor_ea=function_ea,
        )
    current_identity_by_serial = {
        int(serial): identity
        for serial in context.graph.blocks
        if (identity := identity_for_serial(int(serial))) is not None
    }

    plans: list[FragmentPlan] = []
    composition_attempts: list[dict[str, object]] = []
    unresolved_boundary_anchors: list[int] = []
    unresolved_boundary_rejection_by_anchor: dict[
        int,
        CanonicalSemanticFragmentRejected,
    ] = {}
    first_rejection: CanonicalSemanticFragmentRejected | None = None
    first_rejected_proof = None
    for route_index, proof in enumerate(candidate.route_proofs):
        if any(
            semantic_route_proof_reaches_consumer(parent, proof)
            for parent in candidate.route_proofs
            if parent.proof_id != proof.proof_id
        ):
            continue
        route_candidate = _connected_route_candidate(candidate, route_index)
        try:
            plan = compose_canonical_semantic_fragment_plan(
                context.graph,
                normalization_plan,
                route_candidate,
                available_evidence=candidate,
                current_identity_by_serial=current_identity_by_serial,
                normalization_authority=normalization_authority,
                prohibited_dispatcher_serials=(prohibited_dispatcher_serials),
            )
        except CanonicalSemanticFragmentRejected as exc:
            composition_attempts.append(
                _rejected_canonical_composition_attempt(
                    kind="route",
                    rejection=exc,
                    route_candidate=route_candidate,
                )
            )
            if first_rejection is None:
                first_rejection = exc
                first_rejected_proof = proof
            if (
                exc.reason_code == "published_imported_boundary_topology_unresolved"
                and exc.anchor_ea is not None
            ):
                boundary_anchor_ea = int(exc.anchor_ea)
                if boundary_anchor_ea not in unresolved_boundary_anchors:
                    unresolved_boundary_anchors.append(boundary_anchor_ea)
                    unresolved_boundary_rejection_by_anchor[boundary_anchor_ea] = exc
            continue
        composition_attempts.append(
            _accepted_canonical_composition_attempt(
                kind="route",
                plan=plan,
                route_candidate=route_candidate,
            )
        )
        plans.append(plan)
    boundary_plans: list[tuple[int, FragmentPlan]] = []
    first_boundary_rejection: CanonicalSemanticFragmentRejected | None = None
    boundary_plan_rejection_by_anchor: dict[
        int,
        CanonicalSemanticFragmentRejected,
    ] = {}
    if not plans:
        for boundary_anchor_ea in unresolved_boundary_anchors:
            try:
                boundary_plan = compose_canonical_semantic_boundary_fragment_plan(
                    context.graph,
                    normalization_plan,
                    boundary_anchor_ea=boundary_anchor_ea,
                    available_evidence=candidate,
                    current_identity_by_serial=current_identity_by_serial,
                    normalization_authority=normalization_authority,
                    prohibited_dispatcher_serials=prohibited_dispatcher_serials,
                )
            except CanonicalSemanticFragmentRejected as exc:
                composition_attempts.append(
                    _rejected_canonical_composition_attempt(
                        kind="boundary",
                        rejection=exc,
                        boundary_anchor_ea=boundary_anchor_ea,
                    )
                )
                boundary_plan_rejection_by_anchor[boundary_anchor_ea] = exc
                if first_boundary_rejection is None:
                    first_boundary_rejection = exc
                continue
            composition_attempts.append(
                _accepted_canonical_composition_attempt(
                    kind="boundary",
                    plan=boundary_plan,
                    boundary_anchor_ea=boundary_anchor_ea,
                )
            )
            boundary_plans.append((boundary_anchor_ea, boundary_plan))
    if not plans and not boundary_plans:
        attempted_anchors = set(unresolved_boundary_anchors)
        first_upstream_rejection: CanonicalSemanticFragmentRejected | None = None
        for boundary_anchor_ea in unresolved_boundary_anchors:
            if (
                boundary_plan_rejection_by_anchor[boundary_anchor_ea].reason_code
                != "published_boundary_predecessor_missing"
            ):
                continue
            boundary_rejection = unresolved_boundary_rejection_by_anchor[
                boundary_anchor_ea
            ]
            source_anchor_ea = _semantic_predecessor_boundary_anchor(
                boundary_rejection,
                candidate,
            )
            if source_anchor_ea is None or source_anchor_ea in attempted_anchors:
                continue
            attempted_anchors.add(source_anchor_ea)
            try:
                boundary_plan = compose_canonical_semantic_boundary_fragment_plan(
                    context.graph,
                    normalization_plan,
                    boundary_anchor_ea=source_anchor_ea,
                    available_evidence=candidate,
                    current_identity_by_serial=current_identity_by_serial,
                    normalization_authority=normalization_authority,
                    prohibited_dispatcher_serials=prohibited_dispatcher_serials,
                )
            except CanonicalSemanticFragmentRejected as exc:
                composition_attempts.append(
                    _rejected_canonical_composition_attempt(
                        kind="semantic_predecessor_boundary",
                        rejection=exc,
                        boundary_anchor_ea=source_anchor_ea,
                    )
                )
                if first_upstream_rejection is None:
                    first_upstream_rejection = exc
                retirement_obligation_id = (
                    _temporary_boundary_port_retirement_obligation(
                        boundary_anchor_ea=boundary_anchor_ea,
                        source_anchor_ea=source_anchor_ea,
                        upstream_rejection=exc,
                    )
                )
                if retirement_obligation_id is None:
                    continue
                try:
                    boundary_plan = compose_canonical_semantic_boundary_fragment_plan(
                        context.graph,
                        normalization_plan,
                        boundary_anchor_ea=boundary_anchor_ea,
                        available_evidence=candidate,
                        current_identity_by_serial=current_identity_by_serial,
                        normalization_authority=normalization_authority,
                        prohibited_dispatcher_serials=(prohibited_dispatcher_serials),
                        temporary_dispatcher_entry_port_obligation_id=(
                            retirement_obligation_id
                        ),
                    )
                except CanonicalSemanticFragmentRejected as port_exc:
                    composition_attempts.append(
                        _rejected_canonical_composition_attempt(
                            kind="temporary_boundary_port",
                            rejection=port_exc,
                            boundary_anchor_ea=boundary_anchor_ea,
                        )
                    )
                    first_upstream_rejection = port_exc
                    continue
                composition_attempts.append(
                    _accepted_canonical_composition_attempt(
                        kind="temporary_boundary_port",
                        plan=boundary_plan,
                        boundary_anchor_ea=boundary_anchor_ea,
                    )
                )
                boundary_plans.append((boundary_anchor_ea, boundary_plan))
                continue
            composition_attempts.append(
                _accepted_canonical_composition_attempt(
                    kind="semantic_predecessor_boundary",
                    plan=boundary_plan,
                    boundary_anchor_ea=source_anchor_ea,
                )
            )
            boundary_plans.append((source_anchor_ea, boundary_plan))
        if first_upstream_rejection is not None:
            first_boundary_rejection = first_upstream_rejection
    if boundary_plans:
        boundary_anchor_ea, boundary_plan = min(
            boundary_plans,
            key=lambda item: (
                len(item[1].operations),
                len(item[1].blocks),
                int(item[0]),
                item[1].plan_id,
            ),
        )
        try:
            oracle_bound_plan = _bind_boundary_reference_oracle(
                context,
                function_ea=function_ea,
                boundary_anchor_ea=boundary_anchor_ea,
                boundary_plan=boundary_plan,
            )
        except CanonicalSemanticFragmentRejected as exc:
            raise _with_canonical_composition_attempts(
                exc,
                tuple(composition_attempts),
            ) from exc
        return oracle_bound_plan, int(candidate.generation)
    if not plans:
        if first_boundary_rejection is not None:
            first_rejection = first_boundary_rejection
        first_route_anchor = (
            int(first_rejection.anchor_ea)
            if first_rejection is not None and first_rejection.anchor_ea is not None
            else (
                int(first_rejected_proof.source_anchor_ea)
                if first_rejected_proof is not None
                else function_ea
            )
        )
        first_rejection_payload = (
            {}
            if first_rejection is None
            else {
                "cause_detail": str(first_rejection),
                "cause_payload": dict(first_rejection.payload),
            }
        )
        if first_rejected_proof is not None:
            first_rejection_payload["route_proof_id"] = first_rejected_proof.proof_id
        first_rejection_payload["composition_attempts"] = tuple(
            composition_attempts
        )
        raise CanonicalSemanticFragmentRejected(
            "canonical composition found no complete route"
            + ("" if first_rejection is None else f": {first_rejection}"),
            reason_code=(
                "canonical_route_incomplete"
                if first_rejection is None
                else first_rejection.reason_code
            ),
            anchor_ea=first_route_anchor,
            payload=first_rejection_payload,
        )
    plan = min(
        plans,
        key=lambda item: (
            len(item.operations),
            len(item.blocks),
            int(item.block(item.roots[0]).semantic_anchor_ea),
            item.plan_id,
        ),
    )
    return plan, int(candidate.generation)


class LowerCanonicalSemanticFragment(PipelinePass):
    """Lower one bound atomic evidence group through fragment publication only."""

    name = "lower_state_machine"

    def run(self, context: FunctionPipelineContext) -> PassResult:
        bound = _analysis(context, BOUND_CANONICAL_SEMANTIC_EVIDENCE)
        recovery = _analysis(context, "recover_dispatcher")
        range_evidence = _analysis(context, "range_evidence")
        dispatch_map = (
            getattr(recovery, "dispatch_map", None) if recovery is not None else None
        )
        dispatcher_serials = {
            int(serial)
            for serial in getattr(dispatch_map, "dispatcher_blocks", ()) or ()
        }
        dispatcher_serial = getattr(recovery, "dispatcher_block_serial", None)
        if dispatcher_serial is not None:
            dispatcher_serials.add(int(dispatcher_serial))
        dispatcher_serials.update(
            int(serial)
            for serial in (
                _analysis(
                    context,
                    "materialized_dispatcher_router_serials",
                    (),
                )
                or ()
            )
        )
        if range_evidence is not None:
            dispatcher_serials.update(
                int(serial)
                for serial in (
                    getattr(range_evidence, "condition_chain_blocks", ()) or ()
                )
            )
            decision_dag = getattr(range_evidence, "decision_dag", None)
            if decision_dag is not None:
                dispatcher_serials.update(
                    int(serial) for serial in getattr(decision_dag, "nodes", ()) or ()
                )
        if not dispatcher_serials:
            raise CanonicalSemanticFragmentRejected(
                "canonical semantic lowering requires residual dispatcher identity",
                reason_code="residual_dispatcher_identity_missing",
                anchor_ea=int(context.graph.func_ea),
            )

        if bound is None:
            plan, evidence_generation = _compose_candidate_semantic_fragment(
                context,
                prohibited_dispatcher_serials=tuple(sorted(dispatcher_serials)),
            )
        else:
            plan = build_canonical_semantic_fragment_plan(
                context.graph,
                bound,
                prohibited_dispatcher_serials=dispatcher_serials,
            )
            evidence_generation = int(bound.evidence.generation)
        metadata = {
            "plan_id": plan.plan_id,
            "atomic_group_id": plan.atomic_group_id,
            "evidence_generation": evidence_generation,
            "operation_count": len(plan.operations),
            "owned_original_count": len(plan.owned_originals),
            "prohibited_dispatcher_count": len(plan.prohibited_dispatcher_blocks),
        }
        _publish(context, LOWER_STATE_MACHINE_PLAN_METADATA, metadata)
        return PassResult(
            facts=(PassFact("recovered_cfg_edge", metadata),),
            fragment_plan=plan,
            preserved=PreservedAnalyses.none(),
            analysis_outputs={LOWER_STATE_MACHINE_PLAN_METADATA: metadata},
        )


@dataclass
class LowerStateMachine(PipelinePass):
    """Lower the recovered state machine to dispatcher-bypass redirects (unflatten).

    The dispatcher router is **injectable** (ticket llr-oq8v): pass a custom
    ``resolvers`` chain and/or a ``configured_kind`` to pin the router shape; both
    default to the standard condition-chain range + exact-map detection chain, so the argless
    factory the pass driver invokes (``spec.pass_factory()``) is unchanged. To pin a
    kind per family, register ``lambda: LowerStateMachine(configured_kind=...)``.
    """

    name = "lower_state_machine"
    resolvers: tuple = field(default_factory=default_resolvers)
    configured_kind: RouterKind | None = None
    configured_table_provenance: TableProvenance | None = None

    def _resolve_router(self, recovery, range_evidence, dispatcher_entry: int | None):
        """Adapt the recovered evidence into a router via the injectable chain.

        Router kind is configured AND/OR detected: ``self._configured_kind`` pins a
        provider, else detection ranks by handler coverage (the pre-mutation
        condition-chain range evidence is the default; the recovered exact ``state -> handler`` map
        wins only when it strictly out-covers a COLLAPSED range router, e.g. an OLLVM -fla
        equality chain degraded to ``[0,2^32)->dispatcher_entry``). The provider
        chain + ranking live in
        :mod:`d810.analyses.control_flow.router_resolver`.
        """
        dmap = getattr(recovery, "dispatch_map", None) if recovery is not None else None
        has_rows = dmap is not None and getattr(dmap, "rows", None)
        ctx = RouterResolutionContext(
            condition_chain_router=(
                getattr(range_evidence, "dispatcher", None)
                if range_evidence is not None
                else None
            ),
            state_to_handler=dmap.state_to_handler() if has_rows else None,
            default_target=(
                getattr(dmap, "default_target_block", None)
                if dmap is not None
                else None
            ),
            dispatcher_entry=dispatcher_entry,
            table_provenance=(
                getattr(dmap, "table_provenance", None) if dmap is not None else None
            ),
        )
        return select_router(
            self.resolvers,
            ctx,
            configured_kind=self.configured_kind,
            configured_table_provenance=self.configured_table_provenance,
        )

    def run(self, context: FunctionPipelineContext) -> PassResult:
        recovery = _analysis(context, "recover_dispatcher")
        transition_result = _analysis(context, "transition_result")
        dispatcher_entry = getattr(recovery, "dispatcher_block_serial", None)
        materialized_computed_goto_profile = bool(
            _analysis(context, "materialized_computed_goto_profile", False)
        )
        materialized_state_var_reg = _analysis(
            context,
            "materialized_state_var_reg",
        )
        state_var_stkoff, state_var_reg = _effective_state_identity(
            recovery,
            materialized_computed_goto_profile=materialized_computed_goto_profile,
            materialized_state_var_reg=materialized_state_var_reg,
        )
        # A register-resident state variable that is never stack-homed has
        # ``state_var_stkoff is None`` but a
        # recovered ``state_var_reg``. The primary emit path below opens to EITHER
        # identity; the partitioned fixpoint reads the register cell from its
        # already-computed ``out_reg_maps``.
        live_function = getattr(context.source, "live_source", None)
        range_evidence = _analysis(context, "range_evidence")
        current_block_identity_index = _analysis(
            context,
            "current_block_identity_index",
        )

        def block_serial_for_native_identity(identity) -> int | None:
            if current_block_identity_index is None:
                return None
            rebound = current_block_identity_index.rebind_identity(identity)
            return None if rebound.block is None else int(rebound.block.serial)

        # Direct interval-set unflatten (epic d81-jfg2): the interval-set
        # dispatcher (state -> handler) + per-handler next-state recovery IS the
        # state-transition graph; walk it and emit dispatcher-bypass redirects.
        # This replaces the StateDag build (build_live_linearized_state_dag_from_graph)
        # + lower_to_direct_graph(dag=...) full-reconstruction path, which drifted
        # across shared blocks and mis-resolved conditional handlers (e.g.
        # 0x610BB4D9 collapsed to the exit). The rich StateDag metadata can be
        # re-added later if needed; the redirect output does not require it.
        dispatcher = self._resolve_router(recovery, range_evidence, dispatcher_entry)
        if (
            dispatcher is not None
            and dispatcher_entry is not None
            and (state_var_stkoff is not None or state_var_reg is not None)
        ):
            # Initial state for the entry bridge: prefer the range evidence
            # for comparison / switch-table dispatchers, fall back to the
            # recovered StateDispatcherMap.initial_state for indirect table
            # provenance where range evidence is None (ticket llr-16jl).
            initial_state = _resolve_initial_state(range_evidence, recovery)
            dmap = getattr(recovery, "dispatch_map", None)
            # Indirect-table-only emit gates (ticket llr-m9r4): the terminal-tail recovery
            # and the shared-EXIT redirect veto are load-bearing for the Tigress
            # table/indirect shape but regress equality-chain / switch-table goldens
            # (hodur, approov). Thread the table provenance so only the indirect
            # profile enables them.
            is_indirect = (
                dmap is not None
                and getattr(dmap, "router_kind", None) is RouterKind.TABLE
                and getattr(dmap, "table_provenance", None)
                is TableProvenance.INDIRECT_JUMP_TABLE
            )
            if logger.debug_on:
                logger.debug(
                    "unflat initial_state thread: range=%s map=%s resolved=%s kind=%s",
                    getattr(range_evidence, "initial_state", None),
                    getattr(dmap, "initial_state", None) if dmap is not None else None,
                    initial_state,
                    getattr(dmap, "router_kind", None) if dmap is not None else None,
                )
            # Reduced-product CONCRETE leg (ticket llr-xauw): the optional
            # prove-exact-or-abstain block emulator, consulted only where the abstract
            # fixpoint fold left a back-edge next-state at ⊥ (the opaque reg^reg writers
            # whose operands live in other blocks). ``emu is None`` -> abstract-only,
            # byte-identical with the prior behaviour; the consult NEVER overrides a
            # fixpoint-resolved transition.
            emu = context.capabilities.optional(EmulationCapability)
            branch_witness_emu = context.capabilities.optional(BranchWitnessCapability)
            # Use-def severance veto (ticket llr-wlzb): the same UseDefSafetyCapability
            # the fallback lower_to_direct_graph path consults, now threaded into the
            # PRIMARY emit path so a redirect that orphans a non-state carrier (the
            # OLLVM ``var_18 = var_378`` accumulator copies) is dropped. Gated
            # D810_USE_DEF_VETO (default OFF) inside the filter -> byte-identical default.
            dmap = (
                getattr(recovery, "dispatch_map", None)
                if recovery is not None
                else None
            )
            entry_bridge_requires_witness = _entry_bridge_requires_witness(dmap)
            branch_witness_map = (
                build_static_equality_chain_witness_map(context.graph, dmap)
                if (
                    dmap is not None
                    and entry_bridge_requires_witness
                    and not _has_emulated_endpoint_rows(dmap)
                )
                else None
            )
            entry_bridge_exit_path_blocks = (
                tuple(
                    sorted(
                        int(block)
                        for block in getattr(dmap, "dispatcher_blocks", ()) or ()
                    )
                )
                if dmap is not None and entry_bridge_requires_witness
                else ()
            )
            recover_multi_entry_back_edges = _needs_multi_entry_back_edge_recovery(
                range_evidence, dmap
            )
            materialized_indirect_transfers = (
                _analysis(context, "materialized_indirect_transfers", ()) or ()
            )
            imported_direct_boundary_evidence = (
                _analysis(context, "imported_direct_boundary_evidence", ()) or ()
            )
            imported_conditional_boundary_evidence = (
                _analysis(context, "imported_conditional_boundary_evidence", ()) or ()
            )
            imported_native_eas_by_serial = (
                _analysis(context, "imported_native_eas_by_serial", {}) or {}
            )
            native_carrier_consumer_serials_by_load_ea = (
                _analysis(
                    context,
                    "native_carrier_consumer_serials_by_load_ea",
                    {},
                )
                or {}
            )
            materialized_state_routes = (
                _analysis(context, "materialized_state_routes", ()) or ()
            )
            legacy_handler_by_state = (
                _analysis(context, "legacy_handler_by_state", {}) or {}
            )
            materialized_handler_by_state = (
                _analysis(context, "materialized_handler_by_state", {}) or {}
            )
            materialized_handler_entry_eas = (
                _analysis(context, "materialized_handler_entry_eas", {}) or {}
            )
            bound_bootstrap_routes = (
                _analysis(context, "bound_bootstrap_routes", ()) or ()
            )
            materialized_computed_goto_profile = bool(
                _analysis(context, "materialized_computed_goto_profile", False)
            )
            authoritative_handler_serials = frozenset(
                int(serial)
                for serial in (
                    _analysis(context, "authoritative_handler_serials", ()) or ()
                )
            )
            missing_materialized_handler_targets = tuple(
                (int(state), int(target_ea))
                for state, target_ea in (
                    _analysis(
                        context,
                        "unmapped_materialized_handler_targets",
                        (),
                    )
                    or ()
                )
            )
            materialized_dispatcher_router_serials = frozenset(
                int(serial)
                for serial in (
                    _analysis(
                        context,
                        "materialized_dispatcher_router_serials",
                        (),
                    )
                    or ()
                )
            )
            entry_bridge_evidence = _analysis(context, "residual_entry_bridge_evidence")
            logger.info(
                "unflat computed-goto profile: active=%s transfers=%d routes=%d "
                "authoritative_handlers=%d state_reg=%s",
                materialized_computed_goto_profile,
                len(materialized_indirect_transfers),
                len(materialized_state_routes),
                len(authoritative_handler_serials),
                state_var_reg,
            )
            condition_chain_dag = (
                range_evidence.decision_dag if range_evidence is not None else None
            )
            condition_chain_handlers = (
                frozenset(int(serial) for serial in dmap.state_to_handler().values())
                if dmap is not None and condition_chain_dag is not None
                else frozenset()
            )
            carrier_vd_stkoff_candidates: dict[int, set[int]] = {}
            if live_function is not None:
                for transfer in materialized_indirect_transfers:
                    if (
                        transfer.state_carrier_store_ea is None
                        or transfer.state_carrier_ida_stkoff is None
                    ):
                        continue
                    try:
                        vd_stkoff = int(
                            live_function.stkoff_ida2vd(
                                int(transfer.state_carrier_ida_stkoff)
                            )
                        )
                    except (AttributeError, RuntimeError):
                        continue
                    carrier_vd_stkoff_candidates.setdefault(
                        int(transfer.state_carrier_store_ea),
                        set(),
                    ).add(vd_stkoff)
            state_carrier_vd_stkoffs_by_store_ea = {
                store_ea: next(iter(offsets))
                for store_ea, offsets in carrier_vd_stkoff_candidates.items()
                if len(offsets) == 1
            }
            if materialized_computed_goto_profile:
                logger.info(
                    "unflat native stack-carrier evidence: transfers=%d "
                    "bound=%d live_cells=%s consumers=%s",
                    len(materialized_indirect_transfers),
                    sum(
                        1
                        for transfer in materialized_indirect_transfers
                        if transfer.state_carrier_consumer_load_eas
                        and transfer.state_carrier_ida_stkoff is not None
                    ),
                    {
                        f"0x{int(store_ea):X}": int(vd_stkoff)
                        for store_ea, vd_stkoff in sorted(
                            state_carrier_vd_stkoffs_by_store_ea.items()
                        )
                    },
                    {
                        f"0x{int(load_ea):X}": (
                            "blk%d@0x%X"
                            % (
                                int(serial),
                                int(context.graph.get_block(serial).start_ea),
                            )
                            if context.graph.get_block(serial) is not None
                            else "missing"
                        )
                        for load_ea, serial in sorted(
                            native_carrier_consumer_serials_by_load_ea.items()
                        )
                    },
                )
            dispatcher_region_serials = (
                frozenset(int(block) for block in dmap.dispatcher_blocks)
                if dmap is not None
                else frozenset()
            )
            dispatcher_region_serials |= materialized_dispatcher_router_serials
            if range_evidence is not None:
                dispatcher_region_serials |= frozenset(
                    int(block) for block in range_evidence.condition_chain_blocks
                )
                if range_evidence.decision_dag is not None:
                    dispatcher_region_serials |= frozenset(
                        int(block) for block in range_evidence.decision_dag.nodes
                    )
            plan = emit_minimal_unflatten(
                context.graph,
                dispatcher,
                state_var_stkoff=(
                    int(state_var_stkoff) if state_var_stkoff is not None else None
                ),
                state_var_reg=state_var_reg,
                dispatcher_entry_serial=int(dispatcher_entry),
                pre_header_serial=getattr(range_evidence, "pre_header_serial", None),
                initial_state=initial_state,
                is_indirect=is_indirect,
                fact_view=getattr(context, "facts", None),
                emu=emu,
                live_block_for=_make_live_block_for(live_function),
                use_def_safety=context.capabilities.optional(UseDefSafetyCapability),
                live_function=live_function,
                branch_witness_map=branch_witness_map,
                branch_witness_emu=branch_witness_emu,
                entry_bridge_exit_path_blocks=entry_bridge_exit_path_blocks,
                entry_bridge_requires_witness=entry_bridge_requires_witness,
                exit_path_effect_recovery=(
                    isinstance(context.project_config, dict)
                    and bool(context.project_config.get("exit_path_effect_recovery"))
                ),
                recover_multi_entry_back_edges=recover_multi_entry_back_edges,
                materialized_indirect_transfers=materialized_indirect_transfers,
                imported_direct_boundary_evidence=(imported_direct_boundary_evidence),
                imported_conditional_boundary_evidence=(
                    imported_conditional_boundary_evidence
                ),
                imported_native_eas_by_serial=imported_native_eas_by_serial,
                native_carrier_consumer_serials_by_load_ea=(
                    native_carrier_consumer_serials_by_load_ea
                ),
                materialized_state_routes=materialized_state_routes,
                legacy_handler_by_state=legacy_handler_by_state,
                materialized_handler_by_state=materialized_handler_by_state,
                handler_entry_eas_by_serial=materialized_handler_entry_eas,
                state_carrier_vd_stkoffs_by_store_ea=(
                    state_carrier_vd_stkoffs_by_store_ea
                ),
                materialized_computed_goto_profile=(materialized_computed_goto_profile),
                condition_chain_dag=condition_chain_dag,
                condition_chain_handlers=condition_chain_handlers,
                authoritative_handler_serials=authoritative_handler_serials,
                missing_materialized_handler_targets=(
                    missing_materialized_handler_targets
                ),
                dispatcher_region_serials=dispatcher_region_serials,
                entry_bridge_evidence=entry_bridge_evidence,
                bound_bootstrap_routes=bound_bootstrap_routes,
                block_serial_for_native_identity=(block_serial_for_native_identity),
                native_key=(
                    None
                    if current_block_identity_index is None
                    else current_block_identity_index.native_key
                ),
            )
            plan_metadata = plan.metadata_dict()
            _publish(context, LOWER_STATE_MACHINE_PLAN_METADATA, plan_metadata)
            return PassResult(
                facts=(PassFact("recovered_cfg_edge", plan_metadata),),
                rewrite_plan=plan,
                preserved=PreservedAnalyses.none(),
                analysis_outputs={LOWER_STATE_MACHINE_PLAN_METADATA: plan_metadata},
            )

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
        _publish(context, LOWER_STATE_MACHINE_PLAN_METADATA, {})
        return PassResult(
            facts=(PassFact("recovered_cfg_edge", {}),),
            rewrite_plan=plan,
            preserved=PreservedAnalyses.none(),
            analysis_outputs={LOWER_STATE_MACHINE_PLAN_METADATA: {}},
        )


class CleanupResidualDispatcher(PipelinePass):
    name = "cleanup_residual_dispatcher"

    def run(self, context: FunctionPipelineContext) -> PassResult:
        candidates = _analysis(context, "cleanup_candidates", ()) or ()
        plan = cleanup_residual_dispatcher(
            context.graph, context.facts, candidates=candidates
        )
        return PassResult(rewrite_plan=plan, preserved=PreservedAnalyses.none())
