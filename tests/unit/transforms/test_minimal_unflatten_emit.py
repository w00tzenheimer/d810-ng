"""Unit tests for the direct interval-set unflatten emitter (epic d81-jfg2)."""

from __future__ import annotations

import inspect
import logging
import pathlib
from dataclasses import fields, replace
from types import SimpleNamespace

import pytest

import d810.analyses.control_flow.minimal_state_recovery as minimal_state_recovery_module
import d810.analyses.control_flow.semantic_route_evidence as semantic_route_evidence_module
from d810.transforms import minimal_unflatten_emit as minimal_unflatten_emit_module

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.branch_witness_provider import (
    build_static_equality_chain_witness_map,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    InitialStateWriteWitness,
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.detached_handler_island import (
    AppliedDetachedSnippetDirectBoundaryPort,
    AppliedDetachedSnippetConditionalBoundaryPort,
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetConditionalBoundaryPort,
    DetachedSnippetDirectBoundaryPort,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainHandlerEntry,
    ConditionChainRouteEndpoint,
    ConditionChainRouteEndpointKind,
    ConditionChainRouteEvidence,
    ConditionChainRouteProvenance,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    ExactU32DispatcherRouteReceipt,
    HandlerTransition,
    StateWriteTransition,
    TransitionArm,
    TransitionProof,
    _resolve_state_var_alias,
    block_has_live_carrier_write,
    recover_state_write_transitions,
    resolve_materialized_indirect_transfer_targets,
)
from d810.analyses.control_flow.semantic_transition import (
    NativeBoundRouteBindingEvidence,
    NativeBoundTransitionRoute,
)
from d810.core.runtime_identity import RuntimeJoinRejected
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidenceProductionAbstention,
    CanonicalSemanticEvidenceProductionFactCoordinate,
    CanonicalSemanticEvidenceProductionReason,
    CanonicalSemanticEvidenceProductionResult,
    CanonicalSemanticEvidenceProductionStage,
    DecisionDagComparisonWitness,
    DecisionDagRouteWitness,
    SemanticPhysicalStateWriteWitness,
    SemanticRouteFact,
    SemanticRouteFactKind,
    StatePartitionGroupWitness,
    StatePartitionMemberWitness,
    canonical_semantic_evidence_from_proofs,
    bind_canonical_semantic_evidence,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.analyses.control_flow.route_predicate import (
    DecisionDag,
    RouteComparison,
)
from d810.analyses.control_flow.route_comparison import ExactU32XduNamespaceBridge
from d810.analyses.control_flow.state_machine_analysis import (
    run_snapshot_constant_fixpoint,
)
from d810.analyses.value_flow.state_write import (
    MicrocodeEvalSeams,
    forward_eval_insn as _portable_forward_eval_insn,
)
from d810.capabilities.providers import (
    ConditionChainWalkerProvider,
    register_condition_chain_walkers,
)
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.graph_fingerprint import instruction_projection_without_block_references
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.ir.semantics import ControlTransferKind
from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    LowerConditionalStateTransition,
    NopInstructions,
    PreserveLivePredicateCondition,
    RedirectBranch,
    RedirectGoto,
    ScalarizeLocalAliasAccess,
    SyntheticRegisterNonzeroCondition,
    SyntheticStackValueEqualsCondition,
)
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.plan import compile_patch_plan
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.minimal_unflatten_emit import (
    _applied_conditional_boundary_edge_keys,
    _applied_direct_boundary_edge_keys,
    _exact_live_state_edge_keys,
    _logical_function_exit_endpoints,
    _prefer_exact_terminal_route_fragments,
    _preserve_deferred_materialized_handler_exit_paths,
    _recover_initial_state,
    _prove_bound_bootstrap_entry_routes,
    _resolver_proven_dynamic_entry_edges,
    build_conditional_arm_redirects,
    build_exact_terminal_state_route_redirects,
    build_loop_guard_exit_redirects,
    build_materialized_conditional_handler_bridges,
    build_materialized_state_entry_bridges,
    build_materialized_state_route_redirects,
    build_native_bound_state_entry_bridges,
    build_resolver_proven_indirect_call_neutralizations,
    build_stack_carried_state_selector_lowerings,
    _normalize_degenerate_branch_redirects,
    _rebind_materialized_state_route_sources,
    build_source_keyed_handler_redirects,
    build_state_write_redirects,
    enrich_native_bound_transition_routes,
    MissingSemanticRouteFactCoordinate,
    _missing_semantic_route_fact_coordinates,
    _conditional_arm_route_forecast,
    _build_conditional_arm_redirects_with_forecasts,
    _correlate_surviving_conditional_arm_forecasts,
    _complete_local_semantic_route_facts,
    _propose_partition_member_replacements,
    _final_local_semantic_route_facts,
    _final_state_route_transitions,
    _omit_nonexclusive_physical_delivery_drafts,
    _prepare_final_local_evidence_inputs,
    _hold_local_route_facts,
    _native_bound_route_fact,
    _filter_conditional_arm_pair_for_suppressed_sources,
    _omit_unreachable_local_alias_scalarizations,
    _delegate_entry_orphan_to_typed_authority,
    _preserve_entry_only_bootstrap_corridor,
    _reobserve_source_dag_comparisons,
)
from d810.transforms.unflatten_authority.producer_api import (
    ConditionalEntryBridgeForecast,
)
from d810.transforms.unflatten_authority.proposal import (
    _entry_liveness_route_proof_rejection_detail,
)
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidenceProductionContext,
)
from tests.native_preanalysis import make_native_key
from tests.typed_patch_authority import emit_minimal_unflatten, graph_modifications


def test_preserve_entry_only_bootstrap_corridor_when_direct_bridge_orphans_handlers() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 20), (1, 20)),
            10: _b(10, (), (2, 20)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    bootstrap = SimpleNamespace(
        write_block=1,
        target_handler=10,
        semantic_route_fact=SimpleNamespace(kind=SemanticRouteFactKind.BOOTSTRAP),
    )
    modifications = (
        RedirectGoto(20, 2, 10),
        RedirectGoto(1, 2, 10),
    )

    def project(items: tuple[object, ...]) -> FlowGraph:
        successors = {
            serial: list(block.succs) for serial, block in flow_graph.blocks.items()
        }
        for item in items:
            successors[item.from_serial] = [
                item.new_target if target == item.old_target else target
                for target in successors[item.from_serial]
            ]
        predecessors = {serial: [] for serial in flow_graph.blocks}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].append(source)
        return replace(
            flow_graph,
            blocks={
                serial: replace(
                    block,
                    succs=tuple(successors[serial]),
                    preds=tuple(predecessors[serial]),
                )
                for serial, block in flow_graph.blocks.items()
            },
        )

    preserved = _preserve_entry_only_bootstrap_corridor(
        flow_graph,
        modifications,
        transitions=(bootstrap,),
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset((10, 20)),
        project_modifications=project,
    )

    assert preserved == (RedirectGoto(20, 2, 10),)


def test_entry_only_bootstrap_fallback_keeps_bridge_when_handlers_remain_reachable() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    bootstrap = SimpleNamespace(
        write_block=1,
        target_handler=10,
        semantic_route_fact=SimpleNamespace(kind=SemanticRouteFactKind.BOOTSTRAP),
    )
    modifications = (RedirectGoto(1, 2, 10),)

    assert _preserve_entry_only_bootstrap_corridor(
        flow_graph,
        modifications,
        transitions=(bootstrap,),
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset((10, 20)),
        project_modifications=lambda items: flow_graph
        if items == ()
        else replace(
            flow_graph,
            blocks={
                **flow_graph.blocks,
                1: replace(flow_graph.get_block(1), succs=(10,)),
            },
        ),
    ) == modifications


def test_entry_bridge_keeps_effect_safety_despite_complete_route_partition() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 20), (1, 20)),
            10: _b(10, (), (2, 20)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    bootstrap = SimpleNamespace(
        write_block=1,
        target_handler=10,
        semantic_route_fact=SimpleNamespace(kind=SemanticRouteFactKind.BOOTSTRAP),
    )
    state = 0x12345678
    fact = SemanticRouteFact(
        kind=SemanticRouteFactKind.NATIVE_BOUND,
        owner_serial=20,
        source_serial=20,
        source_instruction_ea=0x1020,
        state_constant=state,
        target_serial=10,
        owner_anchor_ea=0x1020,
        target_anchor_ea=0x1010,
        path_serials=(20,),
        path_edges=(),
    )
    dead_component_route = StateWriteTransition(
        20,
        state,
        10,
        False,
        None,
        proof=TransitionProof("native_bound_transition_route", "native_bound_route", True),
        semantic_route_fact=fact,
    )
    modifications = (
        RedirectGoto(20, 2, 10),
        RedirectGoto(1, 2, 10),
    )

    def project(items: tuple[object, ...]) -> FlowGraph:
        successors = {
            serial: list(block.succs) for serial, block in flow_graph.blocks.items()
        }
        for item in items:
            successors[item.from_serial] = [
                item.new_target if target == item.old_target else target
                for target in successors[item.from_serial]
            ]
        predecessors = {serial: [] for serial in flow_graph.blocks}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].append(source)
        return replace(
            flow_graph,
            blocks={
                serial: replace(
                    block,
                    succs=tuple(successors[serial]),
                    preds=tuple(predecessors[serial]),
                )
                for serial, block in flow_graph.blocks.items()
            },
        )

    assert _preserve_entry_only_bootstrap_corridor(
        flow_graph,
        modifications,
        transitions=(bootstrap, dead_component_route),
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset((10, 20)),
        project_modifications=project,
    ) == (RedirectGoto(20, 2, 10),)


@pytest.mark.parametrize(
    ("closed", "withheld", "carrier", "expected"),
    (
        (True, True, False, True),
        (True, True, True, False),
        (True, False, False, False),
        (False, True, False, False),
    ),
)
def test_entry_orphan_delegation_requires_missing_live_carrier(
    closed, withheld, carrier, expected,
) -> None:
    assert _delegate_entry_orphan_to_typed_authority(
        closed_typed_route_set=closed,
        entry_route_would_be_withheld=withheld,
        has_live_entry_carrier=carrier,
    ) is expected


NATIVE_KEY = make_native_key()


def _typed_condition_chain_evidence(
    graph: FlowGraph,
    dag: DecisionDag,
    handlers: frozenset[int],
    *,
    dispatcher: object,
    state_identity: StorageIdentity | None = None,
    block_refs: dict[int, NativeBlockRef] | None = None,
    source_generation: int = 0,
) -> ConditionChainRouteEvidence:
    """Build the one immutable condition-chain bundle accepted by the emitter."""
    refs = block_refs or _entry_dispatcher_map_test_refs(graph)
    rows_owner = getattr(dispatcher, "_interval", dispatcher)
    rows = tuple(
        (int(row.lo), int(row.hi), int(row.target))
        for row in getattr(rows_owner, "_rows", ())
    )
    identity = state_identity or StorageIdentity(StorageIdentityKind.STACK, _STATE)
    handler_serials = frozenset({*handlers, *(target for _lo, _hi, target in rows)})
    entries = tuple(
        ConditionChainHandlerEntry(int(serial), refs[int(serial)].identity)
        for serial in sorted(handler_serials)
    )
    return ConditionChainRouteEvidence(
        decision_dag=dag,
        interval_rows=tuple(sorted(rows)),
        default_target_serial=getattr(dispatcher, "default_target", None),
        endpoints=tuple(
            ConditionChainRouteEndpoint(
                entry.serial, ConditionChainRouteEndpointKind.NATIVE, entry.identity,
            )
            for entry in entries
        ),
        handler_entries=entries,
        state_identity=identity,
        provenance=ConditionChainRouteProvenance.EXTRACTED,
        source_generation=source_generation,
    )


def test_typed_dispatcher_members_include_exact_retirement_forecast_candidates() -> None:
    """The proposal and retirement classifier must share one member catalogue."""

    forecast = SimpleNamespace(
        retirement_candidates=(
            SimpleNamespace(anchor=SimpleNamespace(serial=33, ea=0x180016C4D)),
        ),
        cycle_break=SimpleNamespace(
            retired_residue=(
                SimpleNamespace(serial=2, ea=0x180016C20),
                SimpleNamespace(serial=44, ea=0x180016C80),
            ),
        ),
    )

    assert minimal_unflatten_emit_module._typed_dispatcher_member_serials(
        dispatcher_entry_serial=2,
        dispatcher_region_serials=frozenset({2}),
        dispatcher_removal_forecast=forecast,
        route_delivery_serials=(17, 34),
    ) == (2, 17, 33, 34, 44)


def test_exact_dispatcher_map_route_attaches_typed_transition_fact() -> None:
    """The recovered dispatcher verdict must cross the canonical fact boundary."""

    state = 0x22
    write = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1280,
        operands=(),
        l=MopSnapshot(
            t=_T_NUM, size=4, value=state, kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(
            t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK,
        ),
        kind=InsnKind.MOV,
    )
    graph = FlowGraph(
        {
            10: _b(10, (17,), (), (write,)),
            17: _b(17, (2,), (10,)),
            2: _b(2, (20,), (17,)),
            20: _b(20, (), (2,)),
        },
        10,
        0x1000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={state: 20},
        interval_rows=(IntervalRow(state, state + 1, 20),),
    )
    transition = StateWriteTransition(10, state, 20, False, None, via_block=17)

    enriched = minimal_unflatten_emit_module._attach_dispatcher_map_route_facts(
        graph,
        dispatcher,
        (transition,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        condition_chain_handlers=frozenset(),
    )

    assert enriched is not None
    fact = enriched[0].semantic_route_fact
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.DISPATCHER_MAP
    assert fact.source_instruction_ea == 0x1280
    assert fact.target_serial == 20
    assert fact.path_serials == (10,)
    assert fact.path_edges == ()


def _entry_dispatcher_map_test_refs(graph: FlowGraph) -> dict[int, NativeBlockRef]:
    """Give the entry adapter only immutable native identities."""

    return {
        serial: NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(
                min((block.start_ea, *(instruction.ea for instruction in block.insn_snapshots))),
                max((block.start_ea + 0x20, *(instruction.ea + 1 for instruction in block.insn_snapshots))),
            ),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=tuple(
                instruction.ea for instruction in block.insn_snapshots
            ),
        ))
        for serial, block in graph.blocks.items()
    }


def _entry_dispatcher_map_test_input(
    *,
    write: InsnSnapshot | None | object = ...,
    source_successor: int = 2,
    dispatcher_target: int = 20,
    modifications: tuple[object, ...] | None = None,
):
    state = 0
    write = _mov_state(0x1004, state) if write is ... else write
    source_insns = (
        () if write is None else write if isinstance(write, tuple) else (write,)
    )
    graph = FlowGraph(
        {
            0: _b(0, (source_successor,), (), source_insns),
            2: _b(2, (dispatcher_target,), (0,)),
            20: _b(
                20,
                (),
                (2,),
                (InsnSnapshot(opcode=0, ea=0x1500, operands=(), kind=InsnKind.NOP),),
            ),
            21: _b(21, (), ()),
        },
        0,
        0x1000,
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state=state,
        entry_predecessor_serial=0,
        dispatcher_serial=2,
        replacement_serial=20,
        exit_path_serials=(),
        cut_exit_path_uses=False,
    )
    return (
        graph,
        _DualRouteDispatcher(
            exact_targets={state: dispatcher_target},
            interval_rows=(IntervalRow(state, state + 1, dispatcher_target),),
        ),
        carrier,
        _entry_dispatcher_map_test_refs(graph),
        (RedirectGoto(0, 2, 20),) if modifications is None else modifications,
    )


def test_entry_dispatcher_map_adapter_mints_exact_canonical_fact() -> None:
    """A legacy entry redirect earns authority only through an exact map fact."""

    graph, dispatcher, carrier, refs, modifications = _entry_dispatcher_map_test_input()

    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        dispatcher,
        carrier=carrier,
        final_modifications=(RedirectGoto(0, 2, 20),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
    )

    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.DISPATCHER_MAP
    assert fact.owner_serial == fact.source_serial == 0
    assert fact.source_instruction_ea == 0x1004
    assert fact.state_constant == 0
    assert fact.target_serial == 20
    assert fact.path_serials == (0,)


def test_entry_dispatcher_map_adapter_replays_a_bound_interval_leaf_catalogue() -> None:
    """An interval-backed entry route needs the same bound leaf authority as replay."""

    graph, _dispatcher, carrier, refs, modifications = _entry_dispatcher_map_test_input()
    dispatcher = IntervalDispatcher([IntervalRow(0, 1, 20)], compute_default=False)
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        dispatcher,
        exact_handler_serials=frozenset({20}),
        block_refs_by_serial=refs,
        source_generation=7,
    )

    assert catalogue is not None
    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        dispatcher,
        carrier=carrier,
        final_modifications=modifications,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
    )

    assert fact is not None
    assert fact.target_serial == 20


def test_entry_dispatcher_map_adapter_replays_catalogued_interval_default_leaf() -> None:
    """A bound range leaf remains valid when the interval derives it as default."""

    graph, _dispatcher, carrier, refs, modifications = _entry_dispatcher_map_test_input()
    dispatcher = IntervalDispatcher([IntervalRow(0, 2, 20)])
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        dispatcher,
        exact_handler_serials=frozenset({20}),
        block_refs_by_serial=refs,
        source_generation=7,
    )

    assert catalogue is not None
    assert dispatcher.default_target == 20
    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        dispatcher,
        carrier=carrier,
        final_modifications=modifications,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
    ) is not None


def test_entry_dispatcher_map_adapter_uses_sealed_interval_target_not_swapped_raw_row() -> None:
    """A raw dispatcher cannot replace a sealed interval target after binding."""

    graph, _dispatcher, _carrier, refs, _modifications = _entry_dispatcher_map_test_input()
    sealed = IntervalDispatcher([IntervalRow(0, 1, 21)], compute_default=False)
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        sealed,
        exact_handler_serials=frozenset({21}),
        block_refs_by_serial=refs,
        source_generation=7,
    )
    assert catalogue is not None
    raw_swapped = IntervalDispatcher([IntervalRow(0, 1, 20)], compute_default=False)
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state=0,
        entry_predecessor_serial=0,
        dispatcher_serial=2,
        replacement_serial=21,
        exit_path_serials=(),
        cut_exit_path_uses=False,
    )

    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        raw_swapped,
        carrier=carrier,
        final_modifications=(RedirectGoto(0, 2, 21),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
    )

    assert fact is not None
    assert fact.target_serial == 21


def test_entry_dispatcher_map_adapter_does_not_treat_range_fallback_as_exact_evidence() -> None:
    """A generic range resolver cannot veto a sealed entry interval leaf."""
    graph, _dispatcher, _carrier, refs, _modifications = _entry_dispatcher_map_test_input()
    sealed = IntervalDispatcher([IntervalRow(0, 1, 21)], compute_default=False)
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        sealed,
        exact_handler_serials=frozenset({21}),
        block_refs_by_serial=refs,
        source_generation=7,
    )
    assert catalogue is not None
    range_fallback = _RangeFallbackOnlyDispatcher((IntervalRow(0, 1, 20),))
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state=0,
        entry_predecessor_serial=0,
        dispatcher_serial=2,
        replacement_serial=21,
        exit_path_serials=(),
        cut_exit_path_uses=False,
    )

    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        range_fallback,
        carrier=carrier,
        final_modifications=(RedirectGoto(0, 2, 21),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
    )

    assert fact is not None
    assert fact.target_serial == 21


def test_entry_dispatcher_map_adapter_rejects_raw_target_when_sealed_interval_disagrees() -> None:
    """A swapped raw interval row cannot mint authority for its own target."""

    graph, _dispatcher, carrier, refs, modifications = _entry_dispatcher_map_test_input()
    sealed = IntervalDispatcher([IntervalRow(0, 1, 21)], compute_default=False)
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        sealed,
        exact_handler_serials=frozenset({21}),
        block_refs_by_serial=refs,
        source_generation=7,
    )
    assert catalogue is not None
    raw_swapped = IntervalDispatcher([IntervalRow(0, 1, 20)], compute_default=False)

    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        raw_swapped,
        carrier=carrier,
        final_modifications=modifications,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
    ) is None


def test_entry_dispatcher_map_adapter_rejects_conflicting_typed_exact_and_sealed_interval() -> None:
    """Typed exact evidence remains usable, but cannot override sealed authority."""

    graph, _dispatcher, carrier, refs, modifications = _entry_dispatcher_map_test_input()
    sealed = IntervalDispatcher([IntervalRow(0, 1, 21)], compute_default=False)
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        sealed,
        exact_handler_serials=frozenset({21}),
        block_refs_by_serial=refs,
        source_generation=7,
    )
    assert catalogue is not None
    raw_exact_conflict = _DualRouteDispatcher(
        exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
    )

    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        raw_exact_conflict,
        carrier=carrier,
        final_modifications=modifications,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
        exact_u32_route_receipt=(
            ExactU32DispatcherRouteReceipt(((0, 20),))
        ),
    ) is None


def test_interval_leaf_catalogue_seals_default_target_query() -> None:
    """The default route is part of the typed sealed route selection."""

    graph, _dispatcher, _carrier, refs, _modifications = _entry_dispatcher_map_test_input()
    sealed = IntervalDispatcher(
        [IntervalRow(1, 2, 20), IntervalRow(2, 3, 21)],
        default_target=21,
        compute_default=False,
    )
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        sealed,
        exact_handler_serials=frozenset({20, 21}),
        block_refs_by_serial=refs,
        source_generation=7,
    )

    assert catalogue is not None
    assert catalogue.resolve_exact_u32_target(1) == 20
    assert catalogue.resolve_exact_u32_target(0) == 21
    assert catalogue.resolve_exact_u32_target(-1) is None


def test_entry_dispatcher_map_adapter_uses_sealed_default_not_swapped_raw_default() -> None:
    """A default endpoint is selected from the sealed route catalogue too."""

    graph, _dispatcher, _carrier, refs, _modifications = _entry_dispatcher_map_test_input()
    sealed = IntervalDispatcher(
        [IntervalRow(1, 2, 20), IntervalRow(2, 3, 21)],
        default_target=21,
        compute_default=False,
    )
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        sealed,
        exact_handler_serials=frozenset({20, 21}),
        block_refs_by_serial=refs,
        source_generation=7,
    )
    assert catalogue is not None
    raw_swapped_default = IntervalDispatcher(
        [IntervalRow(1, 2, 20), IntervalRow(2, 3, 21)],
        default_target=20,
        compute_default=False,
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state=0,
        entry_predecessor_serial=0,
        dispatcher_serial=2,
        replacement_serial=21,
        exit_path_serials=(),
        cut_exit_path_uses=False,
    )

    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        raw_swapped_default,
        carrier=carrier,
        final_modifications=(RedirectGoto(0, 2, 21),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
    )

    assert fact is not None
    assert fact.target_serial == 21


def test_entry_carrier_adapter_mints_state_carrier_fact_from_bound_interval_leaf() -> None:
    """An entry CONST32 -> carrier -> state corridor uses the canonical proof."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    refs = _entry_dispatcher_map_test_refs(graph)
    dispatcher = IntervalDispatcher([IntervalRow(0, 0x100000000, 10)])
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        dispatcher,
        exact_handler_serials=frozenset({10}),
        block_refs_by_serial=refs,
        source_generation=7,
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state, 1, 3, 10, (), False,
    )

    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        dispatcher,
        carrier=carrier,
        final_modifications=(RedirectGoto(1, 3, 10),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
        replay_leaf_catalogue=catalogue,
        source_generation=7,
        decision_dag=dag,
    )

    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.STATE_CARRIER
    assert fact.fact_id is None
    assert fact.source_serial == 1
    assert fact.target_serial == 10
    assert fact.target_anchor_ea == minimal_unflatten_emit_module.stable_block_identity_semantic_anchor(
        refs[10].identity
    )
    assert fact.carrier_witness is not None
    assert fact.carrier_witness.feeder_serial == 3


def test_entry_carrier_adapter_rejects_catalogue_generation_and_target_ref_drift() -> None:
    """The carrier adapter cannot replay a leaf against a different binding."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    refs = _entry_dispatcher_map_test_refs(graph)
    dispatcher = IntervalDispatcher([IntervalRow(0, 0x100000000, 10)])
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph, dispatcher, exact_handler_serials=frozenset({10}),
        block_refs_by_serial=refs, source_generation=7,
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state, 1, 3, 10, (), False,
    )
    common = dict(
        carrier=carrier,
        final_modifications=(RedirectGoto(1, 3, 10),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        replay_leaf_catalogue=catalogue,
        decision_dag=dag,
    )
    foreign_target = NativeBlockRef(replace(
        refs[10].identity,
        native_key=replace(
            refs[10].identity.native_key,
            function_rva=refs[10].identity.native_key.function_rva + 1,
        ),
    ))

    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph, dispatcher, block_refs_by_serial=refs, source_generation=8, **common,
    ) is None
    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph, dispatcher,
        block_refs_by_serial={**refs, 10: foreign_target},
        source_generation=7,
        **common,
    ) is None


def test_state_carrier_target_anchor_binds_to_catalogue_identity_not_snapshot_start() -> None:
    """Recovery's target start is proposal-local; canonical anchor is identity-bound."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    refs = _entry_dispatcher_map_test_refs(graph)
    route = replace(_native_bound_route(
        source=1, state=state, target=10, fact_id="entry-carrier-bind",
    ), source_instruction_ea=0x1100)
    proposal = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )

    assert proposal is not None
    assert proposal.kind is SemanticRouteFactKind.STATE_CARRIER
    bound = minimal_unflatten_emit_module._bind_state_carrier_target_anchor(
        proposal, block_refs_by_serial=refs, native_key=NATIVE_KEY,
    )

    assert bound is not None
    assert bound.target_anchor_ea == minimal_unflatten_emit_module.stable_block_identity_semantic_anchor(
        refs[10].identity
    )

    # Selected context may have rebound this local target serial through an
    # exact live semantic-entry EA.  The carrier anchor must follow that same
    # immutable identity rather than the stale serial catalogue row.
    selected_target = minimal_unflatten_emit_module._bind_state_carrier_target_anchor(
        proposal,
        block_refs_by_serial=refs,
        native_key=NATIVE_KEY,
        target_identity=refs[15].identity,
    )
    assert selected_target is not None
    assert selected_target.target_anchor_ea == minimal_unflatten_emit_module.stable_block_identity_semantic_anchor(
        refs[15].identity
    )


def test_state_carrier_target_anchor_rejects_missing_logical_and_foreign_refs() -> None:
    """Only the live native identity catalogue can bind a carrier target."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    refs = _entry_dispatcher_map_test_refs(graph)
    route = replace(_native_bound_route(
        source=1, state=state, target=10, fact_id="entry-carrier-reject",
    ), source_instruction_ea=0x1100)
    proposal = _native_bound_route_fact(
        graph, route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )
    assert proposal is not None
    foreign_target = NativeBlockRef(replace(
        refs[10].identity,
        native_key=replace(
            refs[10].identity.native_key,
            function_rva=refs[10].identity.native_key.function_rva + 1,
        ),
    ))

    assert minimal_unflatten_emit_module._bind_state_carrier_target_anchor(
        proposal, block_refs_by_serial={k: v for k, v in refs.items() if k != 10},
        native_key=NATIVE_KEY,
    ) is None
    assert minimal_unflatten_emit_module._bind_state_carrier_target_anchor(
        proposal,
        block_refs_by_serial={
            **refs, 10: LogicalBlockRef("carrier-target", "function-exit", 0),
        },
        native_key=NATIVE_KEY,
    ) is None
    assert minimal_unflatten_emit_module._bind_state_carrier_target_anchor(
        proposal, block_refs_by_serial={**refs, 10: foreign_target},
        native_key=NATIVE_KEY,
    ) is None
    assert minimal_unflatten_emit_module._bind_state_carrier_target_anchor(
        proposal,
        block_refs_by_serial=refs,
        native_key=NATIVE_KEY,
        target_identity=foreign_target.identity,
    ) is None


def test_entry_dispatcher_map_adapter_keeps_redirect_owner_distinct_from_write() -> None:
    """P -> D may store the initial state in D without relabelling P as W."""

    state = 0
    graph = FlowGraph(
        {
            0: _b(0, (2,), (), ()),
            2: _b(2, (20,), (0,), (_mov_state(0x1024, state),)),
            20: _b(
                20,
                (),
                (2,),
                (InsnSnapshot(opcode=0, ea=0x1500, operands=(), kind=InsnKind.NOP),),
            ),
        },
        0,
        0x1000,
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        state=state,
        entry_predecessor_serial=0,
        dispatcher_serial=2,
        replacement_serial=20,
        exit_path_serials=(2,),
        cut_exit_path_uses=False,
    )
    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        _DualRouteDispatcher(
            exact_targets={state: 20},
            interval_rows=(IntervalRow(state, state + 1, 20),),
        ),
        carrier=carrier,
        final_modifications=(RedirectGoto(0, 2, 20),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
    )

    assert fact is not None
    assert fact.owner_serial == 0
    assert fact.source_serial == 2
    assert fact.source_instruction_ea == 0x1024
    assert fact.path_serials == (0, 2)
    assert fact.path_edges == ((0, 2),)


def test_entry_dispatcher_map_adapter_accepts_exact_conditional_redirect_arm() -> None:
    """A two-way P may replace only its proven D arm with the selected H."""

    branch = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1008,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (225,)),
            146: _b(146, (147, 225), (), (branch,)),
            147: _b(147, (148,), (146,)),
            148: _b(148, (), (147,)),
            225: _b(225, (8,), (146,)),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=146,
        states=(0xEC71CA67,),
        arms=(
            TransitionArm(0x2100AFDD, 59, False, 146, 225, 225, (146, 225, 8)),
            TransitionArm(None, None, True, 146, 148, 148, (146, 147, 148)),
        ),
    )
    dispatcher = IntervalDispatcher([IntervalRow(0, 1, 59)], compute_default=False)

    assert build_loop_guard_exit_redirects(
        fg, dispatcher, (handler,), dispatcher_entry_serial=8,
        infer_unmatched_returns=False,
    ) == []
    graph = FlowGraph(
        {
            0: replace(
                _b(0, (1, 2), (), (_mov_state(0x1004, 0), branch)),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            1: _b(1, (), (0,)),
            2: _b(2, (20,), (0,)),
            20: _b(
                20, (), (2,),
                (InsnSnapshot(opcode=0, ea=0x1500, operands=(), kind=InsnKind.NOP),),
            ),
        },
        0,
        0x1000,
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        0, 0, 2, 20, (2,), False,
    )

    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        _DualRouteDispatcher(
            exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
        ),
        carrier=carrier,
        final_modifications=(RedirectBranch(0, 2, 20),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
    )

    assert fact is not None
    assert fact.owner_serial == fact.source_serial == 0
    assert fact.target_serial == 20


def test_entry_dispatcher_map_adapter_accepts_selected_upstream_initial_write() -> None:
    """A recovered W before P is carried; the adapter does not rediscover it.

    This is the nested-dispatcher topology: W is the unique prologue write,
    P owns a conditional arm into D, and D maps state zero to H.  W is not a
    member of the P/D delivery pair.
    """
    branch = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1018,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            1: _b(1, (0,), (), (_mov_state(0x1004, 0),)),
            0: replace(
                _b(0, (3, 2), (1,), (branch,)),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            3: _b(3, (), (0,)),
            2: _b(2, (20,), (0,)),
            20: _b(20, (), (2,)),
        },
        1,
        0x1000,
    )
    # The recovery-selected witness is carried verbatim; no prologue search is
    # permitted at the adapter boundary.
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        0, 0, 2, 20, (2,), False,
        initial_state_write_witness=InitialStateWriteWitness(
            1,
            instruction_projection_without_block_references(_mov_state(0x1004, 0)),
            StorageIdentity(StorageIdentityKind.STACK, _STATE), 4, 0, 2, 0,
            (1, 0, 2), ((1, 0), (0, 2)),
        ),
    )
    fact = minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        _DualRouteDispatcher(
            exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
        ),
        carrier=carrier,
        final_modifications=(RedirectBranch(0, 2, 20),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
    )

    assert fact is not None
    assert fact.owner_serial == 1
    assert fact.source_serial == 1
    assert fact.source_instruction_ea == 0x1004


def test_initial_state_dag_entry_rejects_witness_namespace_different_from_current_dag() -> None:
    write = _mov_state(0x1004, 7)
    comparison = _eq_block(1, 7, 2, 3, preds=(0,))
    branch = comparison.insn_snapshots[-1]
    wrong_namespace_branch = replace(
        branch,
        l=replace(branch.l, stkoff=_STATE + 4),
    )
    graph = FlowGraph(
        {
            0: _b(0, (1,), (), (write,)),
            1: replace(comparison, insn_snapshots=(wrong_namespace_branch,)),
            2: _b(2, (), (1,)),
            3: _b(3, (), (1,)),
        },
        0,
        0x1000,
    )
    witness = InitialStateWriteWitness(
        0,
        instruction_projection_without_block_references(write),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
        4,
        7,
        1,
        0,
        (0, 1),
        ((0, 1),),
    )
    dag = DecisionDag(
        32, {1: RouteComparison(1, "jz", 7, 2, 3)}, root=1,
    )
    bound = minimal_state_recovery_module.build_current_u32_decision_forest(
        graph,
        1,
        expected_identities=frozenset({witness.state_identity}),
        reference_dag=dag,
    )
    assert bound is None

    result = minimal_unflatten_emit_module._trusted_initial_state_decision_dag_entry_route(
        graph,
        dispatcher_entry_serial=1,
        state=7,
        initial_state_write_witness=witness,
        decision_dag=dag,
        bound_current_dag=bound,
        dispatcher_region_serials=frozenset({1}),
    )

    assert result.route is None
    assert result.conflict


def test_initial_state_dag_entry_consumes_shared_namespace_bound_forest_with_semantic_leaf() -> None:
    write = _mov_state(0x1004, 7)
    comparison = _eq_block(1, 7, 2, 3, preds=(0,))
    graph = FlowGraph(
        {
            0: _b(0, (1,), (), (write,)),
            1: comparison,
            # A handler may itself have two semantic successors.  The shared
            # forest was bound with the handler-leaf catalogue; rebuilding
            # without that catalogue would incorrectly reject this leaf.
            2: _b(2, (4, 5), (1,)),
            3: _b(3, (), (1,)),
            4: _b(4, (), (2,)),
            5: _b(5, (), (2,)),
        },
        0,
        0x1000,
    )
    witness = InitialStateWriteWitness(
        0,
        instruction_projection_without_block_references(write),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
        4,
        7,
        1,
        0,
        (0, 1),
        ((0, 1),),
    )
    dag = DecisionDag(
        32, {1: RouteComparison(1, "jz", 7, 2, 3)}, root=1,
    )

    result = minimal_unflatten_emit_module._trusted_initial_state_decision_dag_entry_route(
        graph,
        dispatcher_entry_serial=1,
        state=7,
        initial_state_write_witness=witness,
        decision_dag=dag,
        bound_current_dag=dag,
        dispatcher_region_serials=frozenset({1}),
    )

    assert result.route is not None
    assert result.route.target_block == 2


def test_typed_emitter_mints_closed_entry_forecast_for_exact_conditional_arm(
    monkeypatch,
    _seam,
) -> None:
    """The emitter, not a caller, carries the selected P(two-way)->D proof."""

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    branch = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1008,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            0: replace(
                _b(0, (1, 2), (), (_mov_state(0x1004, 0), branch)),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            1: _b(1, (), (0,)),
            2: _b(2, (20,), (0,)),
            20: _b(
                20, (), (2,),
                (InsnSnapshot(opcode=0, ea=0x1500, operands=(), kind=InsnKind.NOP),),
            ),
        },
        0,
        0x1000,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )
    refs = _entry_dispatcher_map_test_refs(graph)
    plan = emit_minimal_unflatten(
        graph,
        _DualRouteDispatcher(
            exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0,
        entry_bridge_exit_path_blocks=(2,),
        entry_bridge_requires_witness=True,
        dispatcher_region_serials=frozenset({2}),
        native_key=NATIVE_KEY,
        block_refs_by_serial=refs,
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    assert RedirectBranch(0, 2, 20) in graph_modifications(plan)
    assert plan.unflatten_proposal is not None
    (allowance,) = plan.unflatten_proposal.entry_endpoint_liveness_allowances
    (proof,) = plan.unflatten_proposal.route_evidence.route_proofs
    assert allowance.route_proof_id == proof.proof_id
    assert allowance.entry_predecessor_owner_refs == (refs[0],)
    assert allowance.state_write_source_ref == refs[0]
    assert allowance.dispatcher_old_target_ref == refs[2]
    assert allowance.replacement_endpoint_ref == refs[20]


def test_unbound_optional_route_receipt_does_not_veto_switch_dispatcher(
    monkeypatch,
    _seam,
) -> None:
    """A switch map without comparison rows keeps the legacy route path."""

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    branch = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1008,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            0: replace(
                _b(0, (1, 2), (), (_mov_state(0x1004, 0), branch)),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            1: _b(1, (), (0,)),
            2: _b(2, (20,), (0,)),
            20: _b(
                20,
                (),
                (2,),
                (InsnSnapshot(opcode=0, ea=0x1500, operands=(), kind=InsnKind.NOP),),
            ),
        },
        0,
        0x1000,
    )
    switch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0,
                target_block=20,
                dispatcher_block=2,
                compare_block=None,
                branch_kind="switch",
                router_kind=RouterKind.TABLE,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=_STATE,
        state_var_lvar_idx=None,
        router_kind=RouterKind.TABLE,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        graph,
        _DualRouteDispatcher(
            exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0,
        state_dispatcher_map=switch_map,
        entry_bridge_exit_path_blocks=(2,),
        entry_bridge_requires_witness=True,
        dispatcher_region_serials=frozenset({2}),
        native_key=NATIVE_KEY,
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    assert RedirectBranch(0, 2, 20) in graph_modifications(plan)


def test_typed_emitter_entry_liveness_reuses_matching_transition_proof(
    monkeypatch,
    _seam,
) -> None:
    """One entry allowance may reference, but never co-own, its transition proof."""

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    branch = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1008,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            0: replace(
                _b(0, (1, 2), (), (_mov_state(0x1004, 0), branch)),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            1: _b(1, (), (0,)),
            2: _b(2, (20,), (0,)),
            20: _b(
                20, (), (2,),
                (InsnSnapshot(opcode=0, ea=0x1500, operands=(), kind=InsnKind.NOP),),
            ),
        },
        0,
        0x1000,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(0, 0, 20, False, None),
        ),
    )
    refs = _entry_dispatcher_map_test_refs(graph)
    plan = emit_minimal_unflatten(
        graph,
        _DualRouteDispatcher(
            exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0,
        entry_bridge_exit_path_blocks=(2,),
        entry_bridge_requires_witness=True,
        dispatcher_region_serials=frozenset({2}),
        native_key=NATIVE_KEY,
        block_refs_by_serial=refs,
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    assert RedirectBranch(0, 2, 20) in graph_modifications(plan)
    assert plan.unflatten_proposal is not None
    (allowance,) = plan.unflatten_proposal.entry_endpoint_liveness_allowances
    route_claims = tuple(
        claim for claim in plan.unflatten_proposal.claims
        if type(claim).__name__ == "EquivalentSemanticRouteClaim"
    )
    assert len(route_claims) == 1
    assert route_claims[0].route_proof_ids == (allowance.route_proof_id,)


def test_entry_dispatcher_map_adapter_rejects_two_writes_across_redirect_delivery() -> None:
    """P and D cannot jointly masquerade as one selected physical write."""

    graph = FlowGraph(
        {
            0: _b(0, (2,), (), (_mov_state(0x1004, 0),)),
            2: _b(2, (20,), (0,), (_mov_state(0x1024, 0),)),
            20: _b(20, (), (2,)),
        },
        0,
        0x1000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={0: 20}, interval_rows=(IntervalRow(0, 1, 20),),
    )
    carrier = minimal_unflatten_emit_module._PlannedEntryEndpointLiveness(
        0, 0, 2, 20, (2,), False,
    )

    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        dispatcher,
        carrier=carrier,
        final_modifications=(RedirectGoto(0, 2, 20),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
    ) is None


@pytest.mark.parametrize(
    ("write_factory", "source_successor", "dispatcher_target", "modifications"),
    (
        (lambda: _mov_state(0x1004, 1), 2, 20, None),
        (lambda: _mov_stack_const(0x1004, _STATE + 4, 0), 2, 20, None),
        (lambda: None, 2, 20, None),
        (lambda: (_mov_state(0x1004, 0), _mov_state(0x1008, 0)), 2, 20, None),
        (lambda: _mov_state(0x1004, 0), 2, 21, None),
        (lambda: _mov_state(0x1004, 0), 2, 20, (RedirectGoto(0, 2, 20), RedirectGoto(0, 2, 20))),
        (lambda: _mov_state(0x1004, 0), 2, 20, (RedirectGoto(0, 99, 20),)),
        (lambda: _mov_state(0x1004, 0), 2, 20, (RedirectGoto(0, 2, 21),)),
    ),
    ids=(
        "wrong-state-value",
        "wrong-state-storage",
        "missing-write",
        "ambiguous-state-write",
        "dispatcher-target-disagrees",
        "duplicate-source-redirect",
        "old-target-mutated",
        "new-target-mutated",
    ),
)
def test_entry_dispatcher_map_adapter_rejects_nonexact_inputs(
    write_factory,
    source_successor,
    dispatcher_target,
    modifications,
) -> None:
    """Every mutable or ambiguous part of the legacy bridge fails closed."""

    graph, dispatcher, carrier, refs, final_modifications = _entry_dispatcher_map_test_input(
        write=write_factory(),
        source_successor=source_successor,
        dispatcher_target=dispatcher_target,
        modifications=modifications,
    )

    assert minimal_unflatten_emit_module._entry_dispatcher_map_route_fact(
        graph,
        dispatcher,
        carrier=carrier,
        final_modifications=final_modifications,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        block_refs_by_serial=refs,
    ) is None


def test_shared_physical_delivery_draft_abstains_without_suppressing_safe_sibling() -> None:
    """A shared delivery GOTO cannot be globally redirected for one writer.

    The physical writer at block 10 proves one state, but delivery block 11
    also has a non-writer predecessor.  Redirecting block 11 would therefore
    impose that writer's handler on the sibling.  Proposal selection must omit
    only that draft and retain the independent direct row at block 12.
    """

    state = 0x22
    write = _mov_state(0x1280, state)
    graph = FlowGraph(
        {
            9: _b(9, (11,), ()),
            10: _b(10, (11,), (), (write,)),
            11: _b(11, (2,), (9, 10)),
            12: _b(12, (2,), ()),
            2: _b(2, (20,), (11, 12)),
            20: _b(20, (), (2,)),
        },
        9,
        0x1000,
    )
    physical = SemanticPhysicalStateWriteWitness(
        semantic_route_evidence_module._instruction_projection(write),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
        4,
        state,
        source_serial=10,
    )
    shared_delivery = StateWriteTransition(
        11,
        state,
        20,
        False,
        None,
        semantic_route_fact=SemanticRouteFact(
            kind=SemanticRouteFactKind.DECISION_DAG,
            owner_serial=10,
            source_serial=11,
            source_instruction_ea=0x1280,
            state_constant=state,
            target_serial=20,
            owner_anchor_ea=0x1280,
            target_anchor_ea=0x1500,
            path_serials=(10, 11),
            path_edges=((10, 11),),
            physical_state_write=physical,
        ),
        physical_state_write=physical,
    )
    safe_sibling = StateWriteTransition(12, 0x23, 20, False, None)

    selected = _omit_nonexclusive_physical_delivery_drafts(
        graph,
        (shared_delivery, safe_sibling),
    )

    assert selected == (safe_sibling,)
    assert build_state_write_redirects(
        graph,
        _disp({0x23: 20}, exit_block=20),
        selected,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
    ) == [RedirectGoto(from_serial=12, old_target=2, new_target=20)]


def test_unreachable_local_alias_scalarization_abstains_without_suppressing_live_sibling() -> None:
    """Projection-only dead owners cannot enter the scalarization receipt."""

    dead = ScalarizeLocalAliasAccess(
        block_serial=10,
        host_ea=0x1280,
        host_opcode=_OP_MOV,
        alias_token="%var_dead",
        base_token="%var_base",
        host_text_sha1=None,
        value_size=4,
        reason="local_alias_scalarization",
    )
    live = ScalarizeLocalAliasAccess(
        block_serial=12,
        host_ea=0x1300,
        host_opcode=_OP_MOV,
        alias_token="%var_live",
        base_token="%var_base",
        host_text_sha1=None,
        value_size=4,
        reason="local_alias_scalarization",
    )

    assert _omit_unreachable_local_alias_scalarizations(
        [dead, live],
        frozenset({12}),
    ) == [live]


def test_dispatcher_map_route_attaches_typed_fact_for_exact_address_store() -> None:
    """A recovered address-form U32 state STORE remains producer authority."""

    state = 0xB2FD8FB6
    store = InsnSnapshot(
        opcode=0,
        ea=0x1280,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(_STATE,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK,
                size=4,
                stkoff=_STATE,
                stack_refs=(_STATE,),
            ),
        ),
        kind=InsnKind.STORE,
    )
    graph = FlowGraph(
        {
            10: _b(10, (2,), (), (store,)),
            2: _b(2, (20,), (10,)),
            20: _b(20, (), (2,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(10, state, 20, False, None)

    (enriched,) = minimal_unflatten_emit_module._attach_dispatcher_map_route_facts(
        graph,
        _disp({state: 20}, exit_block=20),
        (transition,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        condition_chain_handlers=frozenset(),
    )

    assert enriched.semantic_route_fact is not None
    assert enriched.semantic_route_fact.kind is SemanticRouteFactKind.DISPATCHER_MAP
    assert enriched.semantic_route_fact.source_instruction_ea == 0x1280


def test_recovered_self_add_dispatcher_route_attaches_exact_typed_fact() -> None:
    """A recovered state increment keeps its exact source operation as authority."""

    state = 0xF6952
    write = InsnSnapshot(
        opcode=0,
        ea=0x1280,
        operands=(),
        l=MopSnapshot(
            t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM, size=4, value=1, kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(
            t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK,
        ),
        kind=InsnKind.ADD,
    )
    graph = FlowGraph(
        {
            10: _b(10, (17,), (), (write,)),
            17: _b(17, (2,), (10,)),
            2: _b(2, (20,), (17,)),
            20: _b(20, (), (2,)),
        },
        10,
        0x1000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={state: 20},
        interval_rows=(IntervalRow(state, state + 1, 20),),
    )

    enriched = minimal_unflatten_emit_module._attach_dispatcher_map_route_facts(
        graph,
        dispatcher,
        (StateWriteTransition(10, state, 20, False, None, via_block=17),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        condition_chain_handlers=frozenset(),
    )

    fact = enriched[0].semantic_route_fact
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.DISPATCHER_MAP
    assert fact.source_instruction_ea == 0x1280
    assert fact.recovered_state_write is not None
    assert fact.recovered_state_write.source_instruction.kind is InsnKind.ADD
    assert fact.recovered_state_write.recovered_state == state


def test_final_state_route_transitions_exclude_unemitted_self_route() -> None:
    """Canonical evidence follows the final operation set, not draft recovery."""

    applied = StateWriteTransition(10, 0x22, 20, False, None)
    stale_self_route = StateWriteTransition(22, 0x1C, 22, False, None)

    assert minimal_unflatten_emit_module._final_state_route_transitions(
        (applied, stale_self_route),
        (RedirectGoto(10, 2, 20),),
    ) == (applied,)


@pytest.mark.parametrize("kind", (BlockKind.ZERO_WAY, BlockKind.STOP))
def test_logical_function_exit_endpoint_export_requires_exact_logical_ref_and_sink(
    kind: BlockKind,
) -> None:
    logical_ref = LogicalBlockRef("logical-endpoint-test", "function-exit", 0)
    exact_exit = BlockSnapshot(
        serial=7,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=kind,
    )
    graph = FlowGraph({7: exact_exit}, 7, 0x1000)
    assert _logical_function_exit_endpoints(graph, {7: logical_ref}) == (
        (
            7,
            minimal_unflatten_emit_module.SemanticLogicalDagEndpoint(
                kind=minimal_unflatten_emit_module.SemanticDagEndpointKind.FUNCTION_EXIT,
                serial=7,
                session_id="logical-endpoint-test",
                proxy_token="function-exit",
                version=0,
            ),
        ),
    )
    native_looking = FlowGraph(
        {7: replace(exact_exit, start_ea=0x1700)}, 7, 0x1000,
    )
    assert _logical_function_exit_endpoints(native_looking, {7: logical_ref}) == ()


def test_typed_emitter_selects_return_dag_proof_with_logical_exit_sibling(
    monkeypatch,
    _seam,
) -> None:
    """A selected terminal redirect retains its exact logical DAG closure."""

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    state = 0x10203040
    logical_exit = 99
    write = _mov_state(0x1044, state)
    branch = InsnSnapshot(
        opcode=_OP_MOV, ea=0x1100, operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=_STATE),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=20),
        kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            10: _b(10, (2,), (), (write,)),
            2: _b(2, (4,), (10,)),
                4: replace(
                    _b(4, (20, logical_exit), (2,), (branch,)),
                    kind=BlockKind.TWO_WAY,
                    tail_kind=InsnKind.COND_JUMP,
                ),
            20: _exit_block(20, (4,)),
            logical_exit: BlockSnapshot(
                serial=logical_exit,
                block_type=1,
                succs=(),
                preds=(4,),
                flags=0,
                start_ea=0xFFFFFFFFFFFFFFFF,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(10, state, 20, True, None)
    route = minimal_state_recovery_module._DecisionDagStateRoute(
        target=20,
        certified_targets=frozenset({20}),
        entry_serial=4,
        path_serials=(4,),
        path_anchors=(graph.get_block(4).start_ea,),
        comparisons=(DecisionDagComparisonWitness(
            4,
            RouteComparison(4, "jz", state, 20, logical_exit),
            StorageIdentity(StorageIdentityKind.STACK, _STATE),
        ),),
    )
    fact = minimal_state_recovery_module._semantic_route_fact_for_transition(
        transition,
        route,
        graph,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert fact is not None
    transition = replace(transition, semantic_route_fact=fact)
    refs = {
        serial: (
            LogicalBlockRef("return-dag-logical-exit", "function-exit", 0)
            if serial == logical_exit
            else NativeBlockRef(StableBlockIdentity.from_intervals(
                (NativeEaInterval(
                    min((block.start_ea, *(instruction.ea for instruction in block.insn_snapshots))),
                    max((block.start_ea + 0x20, *(instruction.ea + 1 for instruction in block.insn_snapshots))),
                ),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=tuple(
                    instruction.ea for instruction in block.insn_snapshots
                ),
            ))
        )
        for serial, block in graph.blocks.items()
    }
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (transition,),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        lambda rows, *_args, **_kwargs: tuple(rows),
    )
    captured_discovered_handlers = []
    original_recover_handlers = minimal_unflatten_emit_module.recover_handler_transitions

    def capture_recovered_handlers(*args, **kwargs):
        captured_discovered_handlers.append(kwargs["authoritative_handler_serials"])
        return original_recover_handlers(*args, **kwargs)

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_handler_transitions",
        capture_recovered_handlers,
    )

    plan = emit_minimal_unflatten(
        graph,
        _disp({state: 20}, exit_block=20),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        # A stale *recovered* dispatcher target may still name the source's
        # structural STOP after Hex-Rays has folded its former native body.
        # It is evidence, not an explicit authoritative caller claim.
        recovered_dispatch_map_handler_serials=frozenset({20, logical_exit}),
        dispatcher_region_serials=frozenset({2, 4}),
        native_key=NATIVE_KEY,
        block_refs_by_serial=refs,
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    assert RedirectGoto(10, 2, 20) in graph_modifications(plan)
    assert plan.unflatten_proposal is not None
    claims = tuple(
        claim
        for claim in plan.unflatten_proposal.claims
        if type(claim).__name__ == "EquivalentSemanticRouteClaim"
    )
    assert len(claims) == 1
    assert claims[0].dag_endpoint_subjects[0].block_ref == refs[logical_exit]
    assert captured_discovered_handlers
    assert captured_discovered_handlers[-1] == frozenset({20})

    explicit_plan = emit_minimal_unflatten(
        graph,
        _disp({state: 20}, exit_block=20),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({logical_exit}),
        dispatcher_region_serials=frozenset({2, 4}),
        native_key=NATIVE_KEY,
        block_refs_by_serial=refs,
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    # The identical coordinate remains fail-closed when a caller explicitly
    # claims it as an authoritative handler.
    assert graph_modifications(explicit_plan) == []
    assert explicit_plan.unflatten_proposal is None


def test_return_dag_logical_exit_selection_rejects_untyped_or_malformed_endpoint() -> None:
    """Return admission is closed over the typed, zero-way logical endpoint."""

    state = 0x10203040
    logical_exit = 99
    write = _mov_state(0x1044, state)
    graph = FlowGraph(
        {
            10: _b(10, (2,), (), (write,)),
            2: _b(2, (4,), (10,)),
            4: _b(4, (20, logical_exit), (2,)),
            20: _exit_block(20, (4,)),
            logical_exit: BlockSnapshot(
                serial=logical_exit,
                block_type=1,
                succs=(),
                preds=(4,),
                flags=0,
                start_ea=0xFFFFFFFFFFFFFFFF,
                insn_snapshots=(),
                kind=BlockKind.ZERO_WAY,
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(10, state, 20, True, None)
    route = minimal_state_recovery_module._DecisionDagStateRoute(
        target=20,
        certified_targets=frozenset({20}),
        entry_serial=4,
        path_serials=(4,),
        path_anchors=(graph.get_block(4).start_ea,),
        comparisons=(DecisionDagComparisonWitness(
            4,
            RouteComparison(4, "jz", state, 20, logical_exit),
            StorageIdentity(StorageIdentityKind.STACK, _STATE),
        ),),
    )
    fact = minimal_state_recovery_module._semantic_route_fact_for_transition(
        transition,
        route,
        graph,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert fact is not None
    transition = replace(transition, semantic_route_fact=fact)
    native_refs = {
        serial: NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(
                min((block.start_ea, *(instruction.ea for instruction in block.insn_snapshots))),
                max((block.start_ea + 0x20, *(instruction.ea + 1 for instruction in block.insn_snapshots))),
            ),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=tuple(
                instruction.ea for instruction in block.insn_snapshots
            ),
        ))
        for serial, block in graph.blocks.items()
        if serial != logical_exit
    }
    typed_refs = native_refs | {
        logical_exit: LogicalBlockRef("return-dag-logical-exit", "function-exit", 0),
    }

    assert minimal_unflatten_emit_module._is_exact_return_dag_with_logical_exit(
        graph, transition, typed_refs,
    )

    witness = fact.decision_dag_witness
    assert witness is not None
    path_without_exit = DecisionDagComparisonWitness(
        4,
        RouteComparison(4, "jz", state, 20, 21),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )
    unrelated_exit = DecisionDagComparisonWitness(
        5,
        RouteComparison(5, "jz", state, 20, logical_exit),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )
    unrelated_fact = replace(
        fact,
        decision_dag_witness=replace(
            witness,
            comparisons=(path_without_exit, unrelated_exit),
        ),
    )
    assert not minimal_unflatten_emit_module._is_exact_return_dag_with_logical_exit(
        graph, replace(transition, semantic_route_fact=unrelated_fact), typed_refs,
    )

    wrong_sibling = DecisionDagComparisonWitness(
        4,
        RouteComparison(4, "jz", state, 21, logical_exit),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )
    wrong_sibling_fact = replace(
        fact,
        decision_dag_witness=replace(witness, comparisons=(wrong_sibling,)),
    )
    assert not minimal_unflatten_emit_module._is_exact_return_dag_with_logical_exit(
        graph, replace(transition, semantic_route_fact=wrong_sibling_fact), typed_refs,
    )

    assert not minimal_unflatten_emit_module._is_exact_return_dag_with_logical_exit(
        graph, replace(transition, semantic_route_fact=None), typed_refs,
    )
    malformed_graph = FlowGraph(
        graph.blocks | {
            logical_exit: replace(graph.blocks[logical_exit], kind=BlockKind.ONE_WAY),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    assert not minimal_unflatten_emit_module._is_exact_return_dag_with_logical_exit(
        malformed_graph, transition, typed_refs,
    )


def _source_generation_dag_fact(
    proposed: RouteComparison,
    *,
    proposed_identity: StorageIdentity,
) -> SemanticRouteFact:
    """One CALLS proposal whose comparison must be rebound at GLBOPT1."""

    witness = DecisionDagRouteWitness(
        state_identity=proposed_identity,
        state_constant=0x55,
        entry_serial=4,
        entry_anchor_ea=0x1100,
        path_serials=(4,),
        path_anchors=(0x1100,),
        comparisons=(DecisionDagComparisonWitness(
            4, proposed, proposed_identity,
        ),),
        aliases=(),
    )
    return SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        owner_serial=4,
        source_serial=4,
        source_instruction_ea=0x1100,
        state_constant=0x55,
        target_serial=20,
        owner_anchor_ea=0x1100,
        target_anchor_ea=0x1200,
        path_serials=(4,),
        path_edges=(),
        decision_dag_witness=witness,
    )


def _source_generation_dag_graph(*, state_offset: int = 212) -> FlowGraph:
    branch = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1100,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=state_offset),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x55),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=20),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    return FlowGraph({
        4: replace(
            _b(4, (20, 21), (), (branch,)),
            kind=BlockKind.TWO_WAY,
            tail_kind=InsnKind.COND_JUMP,
        ),
        20: _b(20, (), (4,)),
        21: _b(21, (), (4,)),
    }, entry_serial=4, func_ea=0x1100)


def test_source_generation_reobservation_rebinds_stale_calls_namespace() -> None:
    """CALLS topology may be reused, but GLBOPT1 supplies its namespace."""

    current_identity = StorageIdentity(StorageIdentityKind.STACK, 212)
    stale_calls_identity = StorageIdentity(StorageIdentityKind.STACK, 232)
    fact = _source_generation_dag_fact(
        RouteComparison(4, "jz", 0x55, 20, 21),
        proposed_identity=stale_calls_identity,
    )

    rebound = _reobserve_source_dag_comparisons(
        _source_generation_dag_graph(), (fact,), state_identity=current_identity,
    )

    assert rebound is not None
    witness = rebound[0].decision_dag_witness
    assert witness is not None
    assert witness.state_identity == current_identity
    assert witness.comparisons == (
        DecisionDagComparisonWitness(
            4, RouteComparison(4, "jz", 0x55, 20, 21), current_identity,
        ),
    )


@pytest.mark.parametrize(
    ("proposed", "state_offset"),
    (
        (RouteComparison(4, "jnz", 0x55, 20, 21), 212),
        (RouteComparison(4, "jz", 0x56, 20, 21), 212),
        (RouteComparison(4, "jz", 0x55, 21, 20), 212),
        (RouteComparison(4, "jz", 0x55, 20, 21), 232),
    ),
    ids=("operation", "constant", "successor-edge", "current-namespace"),
)
def test_source_generation_reobservation_rejects_calls_semantic_drift(
    proposed: RouteComparison,
    state_offset: int,
) -> None:
    """A stale DAG cannot mint authority when source semantics drift."""

    current_identity = StorageIdentity(StorageIdentityKind.STACK, 212)
    stale_calls_identity = StorageIdentity(StorageIdentityKind.STACK, 232)
    fact = _source_generation_dag_fact(
        proposed,
        proposed_identity=stale_calls_identity,
    )

    assert _reobserve_source_dag_comparisons(
        _source_generation_dag_graph(state_offset=state_offset),
        (fact,),
        state_identity=current_identity,
    ) is None


def _bridged_source_generation_dag_fact() -> SemanticRouteFact:
    """One source witness whose comparison follows an exact XDU handoff."""

    source_identity = StorageIdentity(StorageIdentityKind.STACK, 212)
    result_identity = StorageIdentity(StorageIdentityKind.REGISTER, 8)
    witness = DecisionDagRouteWitness(
        state_identity=source_identity,
        state_constant=0x55,
        entry_serial=4,
        entry_anchor_ea=0x1100,
        path_serials=(4, 5),
        path_anchors=(0x1100, 0x1120),
        comparisons=(DecisionDagComparisonWitness(
            5, RouteComparison(5, "jz", 0x55, 20, 21), result_identity,
        ),),
        aliases=(),
        bridges=(ExactU32XduNamespaceBridge(
            4, 0x1100, 0x1108, source_identity, result_identity, 4, 8,
        ),),
    )
    return replace(
        _source_generation_dag_fact(
            RouteComparison(4, "jz", 0x55, 20, 21),
            proposed_identity=source_identity,
        ),
        decision_dag_witness=witness,
    )


def test_source_generation_reobservation_replays_exact_xdu_namespace_bridge(
    monkeypatch,
) -> None:
    """A current DAG comparison may use only the witness's exact bridge result."""

    current_identity = StorageIdentity(StorageIdentityKind.STACK, 212)
    result_identity = StorageIdentity(StorageIdentityKind.REGISTER, 8)
    observed_bridge = ExactU32XduNamespaceBridge(
        4, 0x1100, 0x1108, current_identity, result_identity, 4, 8,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "exact_u32_xdu_namespace_bridge",
        lambda _graph, serial, *, source_identity: (
            observed_bridge if (serial, source_identity) == (4, current_identity) else None
        ),
        raising=False,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "current_u32_route_comparison",
        lambda _graph, serial, *, expected_identities: (
            (RouteComparison(5, "jz", 0x55, 20, 21), result_identity, 0x1120, 0x1128)
            if (serial, expected_identities) == (5, frozenset({result_identity}))
            else None
        ),
    )

    rebound = _reobserve_source_dag_comparisons(
        object(), (_bridged_source_generation_dag_fact(),),
        state_identity=current_identity,
    )

    assert rebound is not None
    witness = rebound[0].decision_dag_witness
    assert witness is not None
    assert witness.comparisons[0].state_identity == result_identity
    assert witness.bridges == (observed_bridge,)


@pytest.mark.parametrize(
    "bridge",
    (
        None,
        ExactU32XduNamespaceBridge(
            4, 0x1100, 0x1108,
            StorageIdentity(StorageIdentityKind.STACK, 212),
            StorageIdentity(StorageIdentityKind.REGISTER, 9), 4, 8,
        ),
        ExactU32XduNamespaceBridge(
            4, 0x1100, 0x1109,
            StorageIdentity(StorageIdentityKind.STACK, 212),
            StorageIdentity(StorageIdentityKind.REGISTER, 8), 4, 8,
        ),
        ExactU32XduNamespaceBridge(
            6, 0x1140, 0x1148,
            StorageIdentity(StorageIdentityKind.STACK, 212),
            StorageIdentity(StorageIdentityKind.REGISTER, 8), 4, 8,
        ),
    ),
    ids=(
        "missing", "changed-result-namespace", "changed-instruction-ea",
        "bridge-outside-witness-path",
    ),
)
def test_source_generation_reobservation_rejects_xdu_bridge_drift(
    monkeypatch,
    bridge: ExactU32XduNamespaceBridge | None,
) -> None:
    """Bridge availability and immutable coordinates remain authority boundaries."""

    current_identity = StorageIdentity(StorageIdentityKind.STACK, 212)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "exact_u32_xdu_namespace_bridge",
        lambda *_args, **_kwargs: bridge,
        raising=False,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "current_u32_route_comparison",
        lambda *_args, **_kwargs: None,
    )

    assert _reobserve_source_dag_comparisons(
        object(), (_bridged_source_generation_dag_fact(),),
        state_identity=current_identity,
    ) is None


def _assert_no_legacy_plan_metadata(plan) -> None:
    from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS

    assert not set(plan.metadata_dict()).intersection(LEGACY_UNFLATTEN_KEYS)


def test_conditional_arm_forecast_mints_complete_decision_dag_fact() -> None:
    """A direct arm carries its exact writer and complete DAG route witness."""

    state = 0x12345678
    write = _mov_state(0x1044, state)
    branch = InsnSnapshot(
        opcode=_OP_MOV, ea=0x1080, operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=_STATE),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph({
        0: replace(
            _b(0, (1, 5), (), (replace(branch, ea=0x1000, d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1)),)),
            kind=BlockKind.TWO_WAY, tail_kind=InsnKind.COND_JUMP,
        ),
        1: replace(_b(1, (2,), (0,), (write,)), kind=BlockKind.ONE_WAY, tail_kind=InsnKind.MOV),
        2: replace(_b(2, (3, 4), (1,), (branch,)), kind=BlockKind.TWO_WAY, tail_kind=InsnKind.COND_JUMP),
        3: _b(3, (), (2,), ()),
        4: _b(4, (), (2,), ()),
        5: _b(5, (), (0,), ()),
    }, entry_serial=0, func_ea=0x1000)
    arm = TransitionArm(state, 3, False, 0, 1, 1, (0, 1))
    assert minimal_state_recovery_module._route_state_through_decision_dag(
        StateWriteTransition(1, state, 3, False, None), graph,
        DecisionDag(32, {2: RouteComparison(2, "jz", state, 3, 4)}, root=2),
        state_var_stkoff=_STATE, state_var_reg=None,
    ) is not None
    forecast = _conditional_arm_route_forecast(
        RedirectGoto(1, 2, 3), arm, graph,
        DecisionDag(32, {2: RouteComparison(2, "jz", state, 3, 4)}, root=2),
        state_var_stkoff=_STATE, state_var_reg=None,
    )
    assert forecast is not None
    assert forecast.route_fact.kind is SemanticRouteFactKind.DECISION_DAG
    assert forecast.route_fact.owner_anchor_ea == 0x1040
    assert forecast.route_fact.source_instruction_ea == 0x1044
    assert forecast.route_fact.recovered_state_write is None
    witness = forecast.route_fact.decision_dag_witness
    assert witness is not None
    assert witness.path_serials == (2,)
    assert witness.path_anchors == (0x1080,)
    assert witness.comparisons == (
        DecisionDagComparisonWitness(
            2,
            RouteComparison(2, "jz", state, 3, 4),
            StorageIdentity(StorageIdentityKind.STACK, _STATE),
        ),
    )
    assert witness.aliases == ()
    assert witness.bridges == ()
    duplicate_write_graph = FlowGraph(
        {**graph.blocks, 1: replace(graph.blocks[1], insn_snapshots=(write, write))},
        entry_serial=0, func_ea=0x1000,
    )
    assert _conditional_arm_route_forecast(
        RedirectGoto(1, 2, 3), arm, duplicate_write_graph,
        DecisionDag(32, {2: RouteComparison(2, "jz", state, 3, 4)}, root=2),
        state_var_stkoff=_STATE, state_var_reg=None,
    ) is None
    wrong_value = _mov_state(0x1048, state + 1)
    wrong_write_graph = FlowGraph(
        {**graph.blocks, 1: replace(graph.blocks[1], insn_snapshots=(write, wrong_value))},
        entry_serial=0, func_ea=0x1000,
    )
    assert _conditional_arm_route_forecast(
        RedirectGoto(1, 2, 3), arm, wrong_write_graph,
        DecisionDag(32, {2: RouteComparison(2, "jz", state, 3, 4)}, root=2),
        state_var_stkoff=_STATE, state_var_reg=None,
    ) is None
    assert _conditional_arm_route_forecast(
        RedirectGoto(1, 99, 3), replace(arm, ordered_path=()), graph,
        DecisionDag(32, {2: RouteComparison(2, "jz", state, 3, 4)}, root=2),
        state_var_stkoff=_STATE, state_var_reg=None,
    ) is None


def test_conditional_arm_forecast_retains_exact_xdu_namespace_bridge(monkeypatch) -> None:
    """Forecast reconstruction must retain the route's typed XDU handoff."""

    state, graph, arm, dag = _direct_conditional_arm_fixture()
    route = minimal_unflatten_emit_module._route_u32_state_through_decision_dag(
        state, graph, dag, state_var_stkoff=_STATE, state_var_reg=None, via_block=None,
    )
    assert route is not None
    bridge = ExactU32XduNamespaceBridge(
        2,
        0x1080,
        0x1078,
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
        StorageIdentity(StorageIdentityKind.REGISTER, 5),
        4,
        8,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_route_u32_state_through_decision_dag",
        lambda *_args, **_kwargs: replace(route, bridges=(bridge,)),
    )

    forecast = _forecast_direct_arm(graph, arm, dag)

    assert forecast is not None
    assert forecast.route_fact.decision_dag_witness is not None
    assert forecast.route_fact.decision_dag_witness.bridges == (bridge,)


def test_conditional_arm_forecast_binds_branch_operation_to_writer_route() -> None:
    """A shared-write cut keeps its operation identity and writer DAG proof."""

    state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _conditional_arm_route_forecast(
        RedirectBranch(0, 1, 3), arm, graph, dag,
        state_var_stkoff=_STATE, state_var_reg=None,
    )

    assert forecast is not None
    assert forecast.modification == RedirectBranch(0, 1, 3)
    assert forecast.route_fact.owner_serial == arm.write_block
    assert forecast.route_fact.source_serial == arm.write_block
    # The operation is a branch cut inside the writer's proven arm path; a
    # same-target redirect from an unrelated block cannot borrow that route.
    assert _conditional_arm_route_forecast(
        RedirectGoto(5, 0, 3), arm, graph, dag,
        state_var_stkoff=_STATE, state_var_reg=None,
    ) is None
    assert _conditional_arm_route_forecast(
        RedirectBranch(0, 5, 3), arm, graph, dag,
        state_var_stkoff=_STATE, state_var_reg=None,
    ) is None


def _computed_state(ea, *, kind: InsnKind, const: int):
    """One recovered state write whose expression need not be a literal MOV."""

    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        r=MopSnapshot(t=_T_NUM, size=4, value=1, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=kind,
    )


def _direct_conditional_arm_fixture(
    *,
    selector_kind: InsnKind = InsnKind.COND_JUMP,
    selector_target: int = 1,
) -> tuple[int, FlowGraph, TransitionArm, DecisionDag]:
    state = 0x12345678
    selector = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1000,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=_STATE),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=selector_target),
        kind=selector_kind,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    route_branch = replace(
        selector,
        ea=0x1080,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.COND_JUMP,
    )
    graph = FlowGraph(
        {
            0: replace(
                _b(0, (1, 5), (), (selector,)),
                kind=BlockKind.TWO_WAY,
                tail_kind=selector_kind,
            ),
            1: replace(
                _b(1, (2,), (0,), (_mov_state(0x1044, state),)),
                kind=BlockKind.ONE_WAY,
                tail_kind=InsnKind.MOV,
            ),
            2: replace(
                _b(2, (3, 4), (1,), (route_branch,)),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            3: _b(3, (), (2,), ()),
            4: _b(4, (), (2,), ()),
            5: _b(5, (), (0,), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    return (
        state,
        graph,
        TransitionArm(state, 3, False, 0, 1, 1, (0, 1)),
        DecisionDag(32, {2: RouteComparison(2, "jz", state, 3, 4)}, root=2),
    )


def _forecast_direct_arm(graph: FlowGraph, arm: TransitionArm, dag: DecisionDag):
    return _conditional_arm_route_forecast(
        RedirectGoto(1, 2, 3),
        arm,
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )


def test_identical_arm_and_backedge_share_one_physical_route_owner() -> None:
    state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    assert forecast is not None
    transition = StateWriteTransition(1, state, 3, False, None)
    assert minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, forecast, (transition,)
    )
    assert not minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, forecast, ()
    )
    assert not minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, forecast, (transition, transition)
    )
    assert not minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, forecast, (replace(transition, next_state=state + 1),)
    )
    assert not minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, forecast, (replace(transition, target_handler=4),)
    )
    assert not minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, forecast, (replace(transition, via_block=2),)
    )


def test_arm_cannot_share_transition_owner_when_old_edge_differs() -> None:
    state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    assert forecast is not None
    transition = StateWriteTransition(1, state, 3, False, None)
    wrong_edge = replace(
        forecast,
        modification=RedirectGoto(1, 5, 3),
    )
    assert not minimal_unflatten_emit_module._conditional_arm_reuses_transition_route(
        graph, wrong_edge, (transition,)
    )


@pytest.mark.parametrize("kind", (InsnKind.VALUE, InsnKind.ADD, InsnKind.SUB))
def test_conditional_arm_forecast_accepts_recovered_non_mov_state_write(kind: InsnKind) -> None:
    """The recovered arm state, not a re-parsed expression, owns the route."""

    state, graph, arm, dag = _direct_conditional_arm_fixture()
    computed = _computed_state(0x1044, kind=kind, const=state + 1)
    graph = FlowGraph(
        {**graph.blocks, 1: replace(graph.blocks[1], insn_snapshots=(computed,))},
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    forecast = _forecast_direct_arm(graph, arm, dag)

    assert forecast is not None
    assert forecast.route_fact.state_constant == state
    assert forecast.route_fact.source_instruction_ea == 0x1044
    recovered = forecast.route_fact.recovered_state_write
    assert recovered is not None
    assert recovered.source_instruction == semantic_route_evidence_module._instruction_projection(computed)
    assert recovered.state_identity == StorageIdentity(StorageIdentityKind.STACK, _STATE)
    assert recovered.width == 4
    assert recovered.recovered_state == state


@pytest.mark.parametrize(
    "write_factory",
    (
        pytest.param(
            lambda: replace(
                _computed_state(0x1044, kind=InsnKind.VALUE, const=1),
                d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE + 4, kind=OperandKind.STACK),
            ),
            id="wrong-destination",
        ),
        pytest.param(
            lambda: replace(
                _computed_state(0x1044, kind=InsnKind.SUB, const=1),
                d=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
            ),
            id="wrong-width",
        ),
        pytest.param(
            lambda: replace(
                _computed_state(0x1044, kind=InsnKind.VALUE, const=1), native_ea=0,
            ),
            id="invalid-native-ea",
        ),
        pytest.param(
            lambda: _mov_state(0x1044, 0x12345679),
            id="contradictory-mov-immediate",
        ),
        pytest.param(
            lambda: replace(
                _computed_state(0x1044, kind=InsnKind.VALUE, const=1),
                kind=InsnKind.NOP,
            ),
            id="wrong-kind",
        ),
    ),
)
def test_conditional_arm_forecast_rejects_invalid_recovered_state_write(write_factory) -> None:
    """Relaxed expression form keeps destination, width, and MOV facts exact."""

    write = write_factory()
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    graph = FlowGraph(
        {**graph.blocks, 1: replace(graph.blocks[1], insn_snapshots=(write,))},
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    assert _forecast_direct_arm(graph, arm, dag) is None


def test_conditional_arm_forecast_rejects_multiple_recovered_state_writes() -> None:
    """One arm must still bind exactly one write to the recovered state slot."""

    state, graph, arm, dag = _direct_conditional_arm_fixture()
    graph = FlowGraph(
        {
            **graph.blocks,
            1: replace(
                graph.blocks[1],
                insn_snapshots=(
                    _computed_state(0x1044, kind=InsnKind.VALUE, const=state),
                    _computed_state(0x1048, kind=InsnKind.SUB, const=state),
                ),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    assert _forecast_direct_arm(graph, arm, dag) is None


def test_final_authority_selects_only_exact_emitted_route() -> None:
    """An unfactored recovery row is not authoritative without its redirect."""
    row = StateWriteTransition(55, 0x1E928A3B, 2, False, None)
    assert _final_state_route_transitions((row,), ()) == ()
    assert _final_state_route_transitions(
        (row,), (RedirectGoto(55, 99, 2),)
    ) == (row,)
    # A dispatcher-internal/no-op redirect never realizes the recovered target.
    assert _final_state_route_transitions(
        (row,), (RedirectGoto(55, 99, 99),)
    ) == ()


def test_conditional_arm_correlation_selects_only_unsuppressed_exact_operation() -> None:
    """A suppressed arm cannot carry authority for its surviving sibling."""

    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    survivor = RedirectGoto(1, 2, 3)
    suppressed = RedirectGoto(4, 5, 6)
    forecast = _conditional_arm_route_forecast(
        survivor, arm, graph, dag, state_var_stkoff=_STATE, state_var_reg=None,
    )
    assert forecast is not None
    suppressed_forecast = replace(
        forecast,
        modification=suppressed,
        target_serial=6,
        route_fact=replace(
            forecast.route_fact,
            owner_serial=4,
            source_serial=4,
            target_serial=6,
            path_serials=(4,),
        ),
    )
    assert _correlate_surviving_conditional_arm_forecasts(
        (survivor, suppressed), (forecast, suppressed_forecast), (survivor,)
    ) == (forecast,)


@pytest.mark.parametrize(
    ("arm_modifications", "forecasts", "final_modifications"),
    (
        pytest.param(
            lambda mod, forecast: (mod,),
            lambda mod, forecast: (forecast,),
            lambda mod, forecast: (mod, mod),
            id="duplicate-final-operation",
        ),
        pytest.param(
            lambda mod, forecast: (mod, mod),
            lambda mod, forecast: (forecast,),
            lambda mod, forecast: (mod,),
            id="duplicate-arm-operation",
        ),
        pytest.param(
            lambda mod, forecast: (mod,),
            lambda mod, forecast: (forecast, forecast),
            lambda mod, forecast: (mod,),
            id="duplicate-forecast",
        ),
        pytest.param(
            lambda mod, forecast: (mod,),
            lambda mod, forecast: (forecast,),
            lambda mod, forecast: (ConvertToGoto(1, 7),),
            id="convert-replacement-drift",
        ),
    ),
)
def test_conditional_arm_correlation_rejects_nonunique_or_drifted_occurrences(
    arm_modifications, forecasts, final_modifications,
) -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    modification = RedirectGoto(1, 2, 3)
    forecast = _conditional_arm_route_forecast(
        modification, arm, graph, dag, state_var_stkoff=_STATE, state_var_reg=None,
    )
    assert forecast is not None

    assert _correlate_surviving_conditional_arm_forecasts(
        arm_modifications(modification, forecast),
        forecasts(modification, forecast),
        final_modifications(modification, forecast),
    ) is None


def test_conditional_arm_redirect_builder_preserves_public_signature() -> None:
    parameters = inspect.signature(build_conditional_arm_redirects).parameters

    assert tuple(parameters) == (
        "flow_graph", "dispatcher", "handler_transitions",
        "dispatcher_entry_serial", "existing", "existing_sources", "is_indirect",
        "carrier_via_blocks", "infer_unmatched_returns", "state_var_stkoff",
        "state_var_reg",
    )
    assert parameters["dispatcher_entry_serial"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["existing_sources"].default is None
    assert parameters["is_indirect"].default is False
    assert parameters["carrier_via_blocks"].default is None
    assert parameters["infer_unmatched_returns"].default is True
    assert parameters["state_var_stkoff"].default is None
    assert parameters["state_var_reg"].default is None


def test_final_local_fact_join_rejects_divergent_same_id() -> None:
    backedge = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND, 1, 1, 0x1000, 0x10, 2,
        0x1000, 0x2000, (1,), (), "same",
    )
    divergent_entry = replace(backedge, target_serial=3)

    assert _complete_local_semantic_route_facts(
        (backedge,), divergent_entry, (),
    ) is None


def test_final_local_fact_join_deduplicates_only_exact_fact() -> None:
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND, 1, 1, 0x1000, 0x10, 2,
        0x1000, 0x2000, (1,), (), "same",
    )

    assert _complete_local_semantic_route_facts((fact,), fact, ()) == (fact,)


def test_final_fact_selection_proposes_typed_partition_member_replacement() -> None:
    state = StorageIdentity(StorageIdentityKind.STACK, _STATE)
    group = StatePartitionGroupWitness(
        "partition-group:final-selection",
        2,
        0x1200,
        state,
        (
            StatePartitionMemberWitness(1, 2, state, 7),
            StatePartitionMemberWitness(3, 2, state, 9),
        ),
    )
    partition = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        1, 2, 0x1200, 7, 6,
        0x1100, 0x1600, (1, 2), ((1, 2),),
        partition_witness=group,
    )
    selected = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        3, 7, 0x1700, 9, 4,
        0x1300, 0x1400, (3, 7), ((3, 7),),
    )

    proposed = _propose_partition_member_replacements((partition, selected))

    assert proposed[0] is partition
    replacement = proposed[1].partition_member_replacement
    assert replacement is not None
    assert (
        replacement.group_id,
        replacement.owner_serial,
        replacement.state_identity,
        replacement.state_constant,
        replacement.target_serial,
    ) == (group.group_id, 3, state, 9, 4)

    competing_group = replace(
        group,
        group_id="partition-group:competing-selection",
    )
    competing_partition = replace(
        partition,
        partition_witness=competing_group,
    )
    ambiguous = _propose_partition_member_replacements(
        (selected,),
        partition_table_facts=(partition, competing_partition),
    )
    assert ambiguous[0].partition_member_replacement is None


def test_entry_liveness_proof_family_rejects_bootstrap_collision_for_map_fact() -> None:
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DISPATCHER_MAP,
        1, 1, 0x1004, 0x10, 2,
        0x1000, 0x2000, (1,), (), "entry-map",
    )
    state_assignment = SimpleNamespace(
        proof_kind=semantic_route_evidence_module.SemanticRouteProofKind.STATE_ASSIGNMENT,
    )
    bootstrap = SimpleNamespace(
        proof_kind=semantic_route_evidence_module.SemanticRouteProofKind.BOOTSTRAP,
    )

    matches = minimal_unflatten_emit_module._route_proof_matches_local_fact_family
    assert matches(fact, state_assignment)
    assert not matches(fact, bootstrap)


def test_entry_liveness_proof_family_uses_guarded_physical_assignment_kind() -> None:
    """Guarded physical DAG facts share the producer's canonical kind rule."""

    from d810.analyses.control_flow.semantic_route_evidence import (
        build_canonical_semantic_evidence,
    )
    from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
        _guarded_alias_store_inputs,
    )

    _source, fact, context, _branch, _store = _guarded_alias_store_inputs()
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is None and result.evidence is not None
    (proof,) = result.evidence.route_proofs
    assert (
        proof.proof_kind
        is semantic_route_evidence_module.SemanticRouteProofKind.STATE_ASSIGNMENT
    )

    matches = minimal_unflatten_emit_module._route_proof_matches_local_fact_family
    assert matches(fact, proof)


def test_entry_liveness_exit_path_closes_over_redirected_dispatcher() -> None:
    normalize = minimal_unflatten_emit_module._entry_liveness_exit_path_blocks

    assert normalize((12, 19, 26), 6) == (6, 12, 19, 26)
    assert normalize((12, 6, 19, 6), 6) == (6, 12, 19)


def test_final_local_fact_join_keeps_distinct_none_id_arm_facts() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    first = replace(forecast.route_fact, fact_id=None)
    second = replace(first, source_instruction_ea=first.source_instruction_ea + 4)

    assert _complete_local_semantic_route_facts(
        (), None, (first, second, first),
    ) == (first, second)


def _same_snapshot_fact_anchor_fixture():
    graph = FlowGraph(
        {
            1: _b(1, (2,), (), (_mov_state(0x1044, 0x10),)),
            2: _b(2, (), (1,), ()),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    refs = _entry_dispatcher_map_test_refs(graph)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        1, 1, 0x1044, 0x10, 2,
        0x1040, 0xDEAD, (1,), (), "same-snapshot",
    )
    return graph, refs, fact


def _same_snapshot_state_transform_anchor_fixture():
    from tests.unit.preanalysis.flow.test_minimal_state_recovery import (
        _captured_nested_state_transform_fixture,
    )

    graph, dag, _transition, _dispatcher = _captured_nested_state_transform_fixture()
    source = graph.blocks[285]
    source_anchor_ea = int(source.start_ea) - 1
    graph = FlowGraph(
        {**graph.blocks, 285: replace(
            source,
            start_ea=source_anchor_ea,
            native_start_ea=source_anchor_ea,
        )},
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    witness = minimal_state_recovery_module.prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=0x64,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=0x28F25B96,
    )
    assert witness is not None
    assert witness.source_ea == source_anchor_ea
    refs = _entry_dispatcher_map_test_refs(graph)
    assert source_anchor_ea not in refs[285].identity.exact_instruction_eas
    assert refs[285].identity.native_ranges.contains(source_anchor_ea)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_TRANSFORM,
        285,
        285,
        witness.source_ea,
        witness.state,
        118,
        witness.source_ea,
        0x180016680,
        (285,),
        (),
        "state-transform:block-anchor",
        transform_witness=witness,
    )
    return graph, refs, fact


def test_same_snapshot_fact_anchor_binding_normalizes_duplicate_snapshot_target() -> None:
    graph, refs, fact = _same_snapshot_fact_anchor_fixture()
    duplicate = replace(fact, target_anchor_ea=0xBEEF)

    bound = minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (fact, duplicate), block_refs_by_serial=refs,
    )

    assert bound is not None
    assert bound[0] == bound[1]
    assert _complete_local_semantic_route_facts((bound[0],), bound[1], ()) == (
        bound[0],
    )
    assert bound[0].target_anchor_ea == (
        minimal_unflatten_emit_module.stable_block_identity_semantic_anchor(
            refs[2].identity
        )
    )


def test_same_snapshot_fact_anchor_binding_keeps_other_duplicate_mismatch_rejected() -> None:
    graph, refs, fact = _same_snapshot_fact_anchor_fixture()
    bound = minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (fact, replace(fact, state_constant=0x11)),
        block_refs_by_serial=refs,
    )

    assert bound is not None
    assert _complete_local_semantic_route_facts((bound[0],), bound[1], ()) is None


def test_same_snapshot_fact_anchor_binding_rejects_stale_native_ref_origins() -> None:
    graph, refs, fact = _same_snapshot_fact_anchor_fixture()
    stale_source = NativeBlockRef(StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1044, 0x1046),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1045,),
    ))

    assert minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (fact,), block_refs_by_serial={**refs, 1: stale_source},
    ) is None


def test_same_snapshot_fact_anchor_binding_accepts_typed_state_transform_block_anchor() -> None:
    graph, refs, fact = _same_snapshot_state_transform_anchor_fixture()

    assert minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (fact,), block_refs_by_serial=refs,
    ) is not None


def test_same_snapshot_fact_anchor_binding_rejects_state_transform_anchor_outside_owner() -> None:
    graph, refs, fact = _same_snapshot_state_transform_anchor_fixture()
    outside_ea = max(
        interval.end_ea for interval in refs[285].identity.native_ranges.intervals
    )
    stale_witness = replace(fact.transform_witness, source_ea=outside_ea)
    stale_fact = replace(
        fact,
        source_instruction_ea=outside_ea,
        owner_anchor_ea=outside_ea,
        transform_witness=stale_witness,
    )

    assert minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (stale_fact,), block_refs_by_serial=refs,
    ) is None


def test_same_snapshot_fact_anchor_binding_rejects_noninstruction_native_bound_anchor() -> None:
    graph, refs, fact = _same_snapshot_fact_anchor_fixture()
    block_anchor_fact = replace(fact, source_instruction_ea=0x1040)
    assert refs[1].identity.native_ranges.contains(0x1040)
    assert 0x1040 not in refs[1].identity.exact_instruction_eas

    assert minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (block_anchor_fact,), block_refs_by_serial=refs,
    ) is None


def test_same_snapshot_fact_anchor_binding_preserves_canonical_fact() -> None:
    graph, refs, fact = _same_snapshot_fact_anchor_fixture()
    canonical = replace(
        fact,
        target_anchor_ea=minimal_unflatten_emit_module.stable_block_identity_semantic_anchor(
            refs[2].identity
        ),
    )

    assert minimal_unflatten_emit_module._bind_same_snapshot_local_fact_anchors(
        graph, (canonical,), block_refs_by_serial=refs,
    ) == (canonical,)


def test_final_fact_stream_replaces_arm_forecast_with_bound_fact() -> None:
    _state_constant, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    raw_forecast = replace(
        forecast,
        route_fact=replace(forecast.route_fact, target_anchor_ea=0xDEAD),
    )

    result = _final_local_semantic_route_facts(
        (), None, (raw_forecast,),
        flow_graph=graph,
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert result is not None
    assert raw_forecast.route_fact != result.facts[0]
    assert result.arm_forecasts[0].route_fact is result.facts[0]
    assert result.arm_forecasts[0].route_fact.target_anchor_ea != 0xDEAD


def test_final_fact_stream_projects_one_partition_replacement_to_every_consumer() -> None:
    """The final stream carries one replacement object through all adapters."""

    state_constant, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    assert forecast is not None
    stronger = forecast.route_fact
    state_identity = StorageIdentity(StorageIdentityKind.STACK, _STATE)
    group = StatePartitionGroupWitness(
        "partition-group:final-stream-projection",
        0,
        0x1000,
        state_identity,
        (
            StatePartitionMemberWitness(0, 0, state_identity, 7),
            StatePartitionMemberWitness(
                stronger.owner_serial, 0, state_identity, state_constant,
            ),
        ),
    )
    retained_partition = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        0, 0, 0x1000, 7, 1,
        0x1000, 0x1040, (0,), (),
        partition_witness=group,
    )

    result = _final_local_semantic_route_facts(
        (retained_partition, stronger), stronger, (forecast,),
        flow_graph=graph,
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        state_identity=state_identity,
        partition_table_facts=(retained_partition,),
    )

    assert result is not None
    (annotated,) = tuple(
        fact for fact in result.facts
        if fact.partition_member_replacement is not None
    )
    replacement = annotated.partition_member_replacement
    assert replacement is not None
    assert result.backedge_facts[0].kind is SemanticRouteFactKind.STATE_PARTITION
    assert result.backedge_facts[0].partition_witness == group
    assert result.backedge_facts[1] is annotated
    assert result.entry_fact is annotated
    assert result.arm_forecasts[0].route_fact is annotated
    assert all(
        fact.partition_member_replacement is replacement
        for fact in (
            annotated,
            result.backedge_facts[1],
            result.entry_fact,
            result.arm_forecasts[0].route_fact,
        )
    )

    transition = StateWriteTransition(
        stronger.owner_serial,
        stronger.state_constant,
        stronger.target_serial,
        False,
        None,
        semantic_route_fact=stronger,
    )
    rebound = minimal_unflatten_emit_module._rebind_authority_transition_facts(
        (transition,), (stronger,), (annotated,),
    )

    assert rebound is not None
    assert rebound[0].semantic_route_fact is annotated
    assert rebound[0].semantic_route_fact.partition_member_replacement is replacement


def test_final_fact_stream_rejects_ambiguous_stripped_partition_replacements() -> None:
    """Two selected candidates for one pre-annotation subject fail closed."""

    state_constant, graph, _arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, _arm, dag)
    assert forecast is not None
    stronger = forecast.route_fact
    state_identity = StorageIdentity(StorageIdentityKind.STACK, _STATE)
    group = StatePartitionGroupWitness(
        "partition-group:final-stream-ambiguity",
        0,
        0x1000,
        state_identity,
        (
            StatePartitionMemberWitness(0, 0, state_identity, 7),
            StatePartitionMemberWitness(
                stronger.owner_serial, 0, state_identity, state_constant,
            ),
        ),
    )
    retained_partition = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        0, 0, 0x1000, 7, 1,
        0x1000, 0x1040, (0,), (),
        partition_witness=group,
    )
    preannotated = _propose_partition_member_replacements(
        (stronger,), partition_table_facts=(retained_partition,),
    )[0]
    assert preannotated.partition_member_replacement is not None

    assert _final_local_semantic_route_facts(
        (retained_partition, stronger, preannotated), None, (),
        flow_graph=graph,
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        state_identity=state_identity,
        partition_table_facts=(retained_partition,),
    ) is None


def test_final_fact_stream_rejects_a_conflicting_join(monkeypatch) -> None:
    """The typed final stream is never constructed with a rejected join."""

    _state_constant, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_complete_local_semantic_route_facts",
        lambda *_args: None,
    )

    assert _final_local_semantic_route_facts(
        (), None, (forecast,),
        flow_graph=graph,
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    ) is None


def test_authority_transitions_consume_bound_backedge_fact_stream() -> None:
    _graph, _refs, fact = _same_snapshot_fact_anchor_fixture()
    rebound = replace(fact, target_anchor_ea=0x2040)
    transition = StateWriteTransition(
        fact.owner_serial,
        fact.state_constant,
        fact.target_serial,
        False,
        None,
        semantic_route_fact=fact,
    )

    result = minimal_unflatten_emit_module._rebind_authority_transition_facts(
        (transition,), (fact,), (rebound,),
    )

    assert result is not None
    assert result[0].semantic_route_fact is rebound


def test_authority_transition_fact_rebinding_rejects_reordered_proposal_stream() -> None:
    _graph, _refs, fact = _same_snapshot_fact_anchor_fixture()
    second = replace(fact, fact_id="second", state_constant=0x11)
    transitions = (
        StateWriteTransition(1, 0x10, 2, False, None, semantic_route_fact=fact),
        StateWriteTransition(1, 0x11, 2, False, None, semantic_route_fact=second),
    )

    assert minimal_unflatten_emit_module._rebind_authority_transition_facts(
        transitions,
        (second, fact),
        (replace(second, target_anchor_ea=0x2040), replace(fact, target_anchor_ea=0x2040)),
    ) is None


def test_final_emitter_fact_join_does_not_bypass_divergent_entry_comparison() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    backedge = replace(forecast.route_fact, fact_id="shared-route")
    divergent_entry = replace(
        backedge,
        source_instruction_ea=backedge.source_instruction_ea + 4,
    )

    assert _complete_local_semantic_route_facts(
        (backedge,), divergent_entry, (),
    ) is None


def test_production_final_input_preparation_preserves_same_source_fact_identity() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    first = replace(forecast.route_fact, fact_id="one")
    second = replace(first, fact_id="two")

    local_facts, entry_fact = _prepare_final_local_evidence_inputs(
        (first, second), None,
    )

    assert (local_facts, entry_fact) == ((first, second), None)
    assert _complete_local_semantic_route_facts(local_facts, entry_fact, ()) == (
        first, second,
    )


def test_production_local_fact_hold_keeps_entry_prefix_fact() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    entry_prefix_fact = _forecast_direct_arm(graph, arm, dag).route_fact

    assert _hold_local_route_facts((entry_prefix_fact, None)) == (entry_prefix_fact,)



def test_production_final_input_preparation_rejects_same_id_anchor_drift() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    forecast = _forecast_direct_arm(graph, arm, dag)
    first = replace(forecast.route_fact, fact_id="same")
    divergent_entry = replace(first, source_instruction_ea=first.source_instruction_ea + 4)

    local_facts, entry_fact = _prepare_final_local_evidence_inputs(
        (first,), divergent_entry,
    )

    assert _complete_local_semantic_route_facts(local_facts, entry_fact, ()) is None


def test_guard_suppression_filters_arm_modifications_and_forecasts_in_lockstep() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    survivor = RedirectGoto(1, 2, 3)
    suppressed = RedirectGoto(4, 5, 6)
    forecast = _forecast_direct_arm(graph, arm, dag)
    suppressed_forecast = replace(
        forecast,
        modification=suppressed,
        target_serial=6,
        route_fact=replace(
            forecast.route_fact,
            owner_serial=4,
            source_serial=4,
            target_serial=6,
            path_serials=(4,),
        ),
    )

    filtered = _filter_conditional_arm_pair_for_suppressed_sources(
        (survivor, suppressed), (forecast, suppressed_forecast), frozenset({4}),
    )

    assert filtered == ((survivor,), (forecast,))
    assert _correlate_surviving_conditional_arm_forecasts(
        filtered[0], filtered[1], (survivor,),
    ) == (forecast,)


def test_conditional_arm_forecast_rejects_absent_intermediate_path_block() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    assert _forecast_direct_arm(
        graph,
        replace(arm, ordered_path=(0, 99, 1)),
        dag,
    ) is None


def test_conditional_arm_forecast_rejects_disconnected_path_edge() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    detached = _b(6, (5,), (0,), ())
    graph = FlowGraph(
        {
            **graph.blocks,
            0: replace(
                graph.blocks[0],
                succs=(6, 5),
                insn_snapshots=(
                    replace(
                        graph.blocks[0].tail,
                        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=6),
                    ),
                ),
            ),
            1: replace(graph.blocks[1], preds=()),
            5: replace(graph.blocks[5], preds=(0, 6)),
            6: detached,
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    assert _forecast_direct_arm(
        graph,
        replace(arm, ordered_path=(0, 6, 1)),
        dag,
    ) is None


def test_conditional_arm_forecast_rejects_selector_equal_to_writer() -> None:
    state, graph, arm, dag = _direct_conditional_arm_fixture()
    selector = replace(
        graph.blocks[0].tail,
        ea=0x1048,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
    )
    graph = FlowGraph(
        {
            **graph.blocks,
            1: replace(
                graph.blocks[1],
                kind=BlockKind.TWO_WAY,
                succs=(2, 5),
                insn_snapshots=(_mov_state(0x1044, state), selector),
                tail_kind=InsnKind.COND_JUMP,
            ),
            5: replace(graph.blocks[5], preds=(0, 1)),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    same_block = replace(
        arm,
        branch_block=1,
        write_block=1,
        exit_block=1,
        ordered_path=(1,),
    )
    assert _conditional_arm_route_forecast(
        RedirectBranch(1, 2, 3),
        same_block,
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    ) is None


def test_conditional_arm_forecast_rejects_one_way_nonselector() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture()
    graph = FlowGraph(
        {
            **graph.blocks,
            0: replace(graph.blocks[0], kind=BlockKind.ONE_WAY, succs=(1,)),
            5: replace(graph.blocks[5], preds=()),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    assert _forecast_direct_arm(graph, arm, dag) is None


def test_conditional_arm_forecast_rejects_tail_target_outside_successors() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture(selector_target=99)
    assert _forecast_direct_arm(graph, arm, dag) is None


def test_conditional_arm_forecast_accepts_equality_jump_selector() -> None:
    _state, graph, arm, dag = _direct_conditional_arm_fixture(
        selector_kind=InsnKind.EQUALITY_JUMP,
    )
    assert _forecast_direct_arm(graph, arm, dag) is not None

_OP_MOV = 4
_T_NUM, _T_STK, _T_REG = 2, 4, 1
_STATE = 0x64
_CARRIER_OFF = 0x70  # a non-state stack slot (the Approov ``v4`` carrier)


def _seams() -> MicrocodeEvalSeams:
    return MicrocodeEvalSeams(
        mop_type_name=lambda t: {_T_NUM: "mop_n", _T_STK: "mop_S", _T_REG: "mop_r"}.get(
            t
        ),
        mop_type_value=lambda n, d: {
            "mop_n": _T_NUM,
            "mop_S": _T_STK,
            "mop_r": _T_REG,
        }.get(n, d),
        opcode_value=lambda n, d: {"m_mov": _OP_MOV}.get(n, d),
        opcode_name=lambda op: {_OP_MOV: "m_mov"}.get(op),
        fetch_stable_global_value=lambda _a, _s: None,
        lvar_stkoff=lambda _m, _i: -1,
    )


@pytest.fixture
def _seam():
    from d810.capabilities import providers as _p

    s = _seams()

    def _fwd(insn, stk, reg, off, **kw):
        kw.pop("seams", None)
        return _portable_forward_eval_insn(
            insn,
            stk,
            reg,
            off,
            seams=s,
            mba=kw.pop("mba", None),
            state_var_lvar_idx=kw.pop("state_var_lvar_idx", None),
        )

    register_condition_chain_walkers(
        ConditionChainWalkerProvider(
            detect_state_var_stkoff=lambda *a, **k: None,
            dump_dispatcher_node=lambda *a, **k: None,
            find_pre_header_state=lambda *a, **k: None,
            walk_handler_chain=lambda *a, **k: None,
            forward_eval_insn=_fwd,
            resolve_via_condition_chain_walk=lambda *a, **k: None,
        )
    )
    try:
        yield
    finally:
        _p.reset_providers_for_tests()


def _mov_state(ea, const):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_stk(ea, src_off, dst_off):
    # pure stack->stack copy: dst = src (no right operand)
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=src_off, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=dst_off, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_reg(ea, const, dst_reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=dst_reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _use_nested_reg(ea, reg):
    """A nested sub-instruction use, shaped like an indirect-call operand."""
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(
            t=4,
            size=8,
            kind=OperandKind.SUBINSN,
            sub_l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        ),
        d=MopSnapshot(t=_T_REG, size=8, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _stx_reg(ea, value, ptr_reg):
    return InsnSnapshot(
        opcode=1,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        r=MopSnapshot(t=_T_REG, size=2, reg=256, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_REG, size=8, reg=ptr_reg, kind=OperandKind.REGISTER),
        kind=InsnKind.STORE,
    )


def _mov_reg_const(ea, reg, value=0x1234):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _mov_reg_from_stack(ea, reg, stkoff):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _mov_reg_from_reg(ea, source_reg, destination_reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(
            t=_T_REG,
            size=4,
            reg=source_reg,
            kind=OperandKind.REGISTER,
        ),
        d=MopSnapshot(
            t=_T_REG,
            size=4,
            reg=destination_reg,
            kind=OperandKind.REGISTER,
        ),
        kind=InsnKind.MOV,
    )


def _mov_stack_from_reg(ea, stkoff, reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_stack_const(ea, stkoff, value=0x1234):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _call_reg(ea, reg):
    return InsnSnapshot(
        opcode=0x44,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.CALL,
    )


def _nested_call_result(ea):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(
            t=4,
            size=4,
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.CALL,
        ),
        d=MopSnapshot(t=_T_REG, size=4, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _state_ne_tail(ea, const):
    return InsnSnapshot(
        opcode=0x33,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=const, kind=OperandKind.NUMBER),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _signed_ge_tail(ea, compared, taken):
    return InsnSnapshot(
        opcode=0x32,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=0x30, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=compared, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.SGE,
        is_conditional_jump=True,
    )


def _indirect_jump(ea):
    return InsnSnapshot(
        opcode=0x36,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
        kind=InsnKind.INDIRECT_JUMP,
    )


def _b(serial, succs, preds, insns=()):
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x40,
        insn_snapshots=tuple(insns),
    )


def _disp(point_targets, exit_block, hi=0x100000000):
    rows, cur = [], 0
    for st in sorted(point_targets):
        if st > cur:
            rows.append(IntervalRow(lo=cur, hi=st, target=exit_block))
        rows.append(IntervalRow(lo=st, hi=st + 1, target=point_targets[st]))
        cur = st + 1
    if cur < hi:
        rows.append(IntervalRow(lo=cur, hi=hi, target=exit_block))
    return IntervalDispatcher(rows)


class _DualRouteDispatcher:
    """Expose exact and interval route evidence independently for RED tests."""

    def __init__(
        self,
        *,
        exact_targets: dict[int, int],
        interval_rows: tuple[IntervalRow, ...],
        default_target: int | None = None,
        legacy_lookup_interval: bool = False,
    ) -> None:
        self._exact_targets = {
            int(state) & 0xFFFFFFFF: int(target)
            for state, target in exact_targets.items()
        }
        self._interval = IntervalDispatcher(list(interval_rows), compute_default=False)
        self.default_target = default_target
        self._legacy_lookup_interval = bool(legacy_lookup_interval)

    def resolve_target(self, state: int) -> int | None:
        return self._exact_targets.get(int(state) & 0xFFFFFFFF)

    def lookup_row(self, state: int) -> IntervalRow | None:
        return self._interval.lookup_row(int(state) & 0xFFFFFFFF)

    def lookup(self, state: int) -> int | None:
        # Preserve the old exact-before-range behavior as the RED baseline.
        exact = self.resolve_target(state)
        if exact is not None or not self._legacy_lookup_interval:
            return exact
        return self._interval.lookup(state)

    def all_targets(self) -> set[int]:
        return self._interval.all_targets()


class _RangeFallbackOnlyDispatcher:
    """Compatibility adapter whose generic resolver is interval-backed."""

    def __init__(self, rows: tuple[IntervalRow, ...]) -> None:
        self._interval = IntervalDispatcher(list(rows), compute_default=False)

    def resolve_target(self, state: int) -> int | None:
        return self._interval.lookup(int(state) & 0xFFFFFFFF)

    def lookup_row(self, state: int) -> IntervalRow | None:
        return self._interval.lookup_row(int(state) & 0xFFFFFFFF)

    def all_targets(self) -> set[int]:
        return self._interval.all_targets()


class _StateMapDispatcher:
    """Expose exact StateDispatcherMap rows through the route-provider shape."""

    def __init__(self, dispatch_map: StateDispatcherMap) -> None:
        self._dispatch_map = dispatch_map
        self.rows = dispatch_map.rows
        self.default_target = None

    def resolve_target(self, state: int) -> int | None:
        return self._dispatch_map.resolve_target(state)

    def all_targets(self) -> set[int]:
        return {int(row.target_block) for row in self.rows}


class _MalformedIntervalRow:
    def __init__(self, error: type[BaseException]) -> None:
        self._error = error

    @property
    def target(self):
        raise self._error("malformed interval target")


class _MalformedIntervalDispatcher:
    default_target = 99

    def __init__(self, error: type[BaseException], state: int) -> None:
        self._row = _MalformedIntervalRow(error)
        self._state = int(state) & 0xFFFFFFFF

    def resolve_target(self, _state: int) -> int | None:
        return None

    def lookup_row(self, state: int):
        if int(state) & 0xFFFFFFFF == self._state:
            return self._row
        return None

    def all_targets(self) -> set[int]:
        return set()


def _eq_block(serial, const, taken, fallthrough, preds=(), insns=()):
    """Equality-chain compare block: ``jz state == const -> taken; fallthrough``."""
    tail = InsnSnapshot(
        opcode=100,
        ea=0x1000 + serial * 0x40,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    return BlockSnapshot(
        serial=serial,
        block_type=4,
        succs=(fallthrough, taken),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(*insns, tail),
    )


def _use_stk(ea, stkoff):
    """A statement that uses a stack slot: ``return use(stkoff)`` proxy via mov."""
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_REG, size=4, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _equality_dispatcher(point_targets, entry_block, compare_blocks):
    """Build IntervalDispatcher + StateDispatcherMap for equality-chain rows."""
    rows = tuple(
        StateDispatcherRow(
            state_const=st,
            target_block=target,
            dispatcher_block=entry_block,
            compare_block=cmp_block,
            branch_kind="eq",
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        for st, target, cmp_block in zip(
            sorted(point_targets),
            [point_targets[st] for st in sorted(point_targets)],
            compare_blocks,
        )
    )
    dispatch_map = StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=entry_block,
        dispatcher_blocks=frozenset(compare_blocks),
        state_var_stkoff=_STATE,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    interval_rows = [
        IntervalRow(lo=st & 0xFFFFFFFF, hi=(st & 0xFFFFFFFF) + 1, target=target)
        for st, target in point_targets.items()
    ]
    return IntervalDispatcher(interval_rows), dispatch_map


@pytest.mark.parametrize(
    "malformation",
    ("entry", "state_identity", "stale_target", "wrong_existing_target", "empty"),
)
def test_exact_dispatcher_receipt_binds_current_candidate_or_abstains(
    malformation: str,
) -> None:
    state = 0x16AA65E9
    graph = FlowGraph(
        {
            0: _b(0, (2,), ()),
            2: _b(2, (20,), (0, 10)),
            20: _eq_block(20, state, 10, 99, preds=(2,)),
            10: _b(10, (2,), (20,)),
            99: replace(_b(99, (), (20,)), kind=BlockKind.STOP),
        },
        0,
        0x180055760,
    )
    _dispatcher, dispatch_map = _equality_dispatcher(
        {state: 10}, entry_block=2, compare_blocks=(20,)
    )
    if malformation == "entry":
        dispatch_map = replace(dispatch_map, dispatcher_entry_block=3)
    elif malformation == "state_identity":
        dispatch_map = replace(dispatch_map, state_var_stkoff=_STATE + 4)
    elif malformation == "stale_target":
        dispatch_map = replace(
            dispatch_map,
            rows=(replace(dispatch_map.rows[0], target_block=999),),
        )
    elif malformation == "wrong_existing_target":
        dispatch_map = replace(
            dispatch_map,
            rows=(replace(dispatch_map.rows[0], target_block=99),),
        )
    elif malformation == "empty":
        dispatch_map = replace(dispatch_map, rows=())
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(malformation)

    receipt = minimal_unflatten_emit_module._bind_exact_u32_dispatcher_route_receipt(
        graph,
        dispatch_map,
        dispatcher_entry_serial=2,
        state_var_stkoff=_STATE,
        state_var_reg=None,
        dispatcher_region_serials=frozenset({2, 20}),
    )

    assert receipt is None


def test_exact_dispatcher_receipt_accepts_bound_current_rows() -> None:
    state = 0x16AA65E9
    graph = FlowGraph(
        {
            0: _b(0, (2,), ()),
            2: _b(2, (20,), (0, 10)),
            20: _eq_block(20, state, 10, 99, preds=(2,)),
            10: _b(10, (2,), (20,)),
            99: replace(_b(99, (), (20,)), kind=BlockKind.STOP),
        },
        0,
        0x180055760,
    )
    _dispatcher, dispatch_map = _equality_dispatcher(
        {state: 10}, entry_block=2, compare_blocks=(20,)
    )

    receipt = minimal_unflatten_emit_module._bind_exact_u32_dispatcher_route_receipt(
        graph,
        dispatch_map,
        dispatcher_entry_serial=2,
        state_var_stkoff=_STATE,
        state_var_reg=None,
        dispatcher_region_serials=frozenset({2, 20}),
    )

    assert receipt is not None
    assert receipt.target_for_u32_state(state) == 10


def test_exact_dispatcher_receipt_filters_retired_prefix_rows() -> None:
    retired_state = 0x11111111
    current_state = 0x22222222
    graph = FlowGraph(
        {
            0: _b(0, (2,), ()),
            2: _b(2, (21,), (0, 10, 11)),
            20: _eq_block(20, retired_state, 10, 21, preds=()),
            21: _eq_block(21, current_state, 11, 99, preds=(2,)),
            10: _b(10, (2,), (20,)),
            11: _b(11, (2,), (21,)),
            99: replace(_b(99, (), (21,)), kind=BlockKind.STOP),
        },
        0,
        0x180055760,
    )
    _dispatcher, dispatch_map = _equality_dispatcher(
        {retired_state: 10, current_state: 11},
        entry_block=2,
        compare_blocks=(20, 21),
    )

    receipt = minimal_unflatten_emit_module._bind_exact_u32_dispatcher_route_receipt(
        graph,
        dispatch_map,
        dispatcher_entry_serial=2,
        state_var_stkoff=_STATE,
        state_var_reg=None,
        dispatcher_region_serials=frozenset({2, 21}),
    )

    assert receipt is not None
    assert receipt.target_for_u32_state(retired_state) is None
    assert receipt.target_for_u32_state(current_state) == 11


def test_emits_back_edge_redirect_and_entry_bridge(_seam) -> None:
    # entry blk0 -> dispatcher blk2; state-write blk10 writes 0x20 -> dispatcher;
    # route(0x10 initial)=blk10, route(0x20)=blk20.  The transition is anchored on
    # the back-edge blk10->dispatcher, re-pointed onto route(0x20)=blk20.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),  # entry -> dispatcher
            2: _b(2, (10, 20), (0, 10, 20)),  # dispatcher
            10: _b(
                10, (2,), (2,), (_mov_state(0x1000, 0x20),)
            ),  # writes 0x20 -> dispatcher
            20: _b(20, (2,), (2,)),  # target handler
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    # blk10 is the resolved state-write back-edge -> route(0x20) = blk20
    by_block = {t.write_block: t for t in transitions}
    assert by_block[10].next_state == 0x20
    assert by_block[10].target_handler == 20
    assert by_block[10].is_return is False
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=0x10,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    # back-edge blk10 re-pointed off the dispatcher onto blk20
    assert (10, 2, 20) in gotos
    # entry bridge: blk0 -> route(initial 0x10) = blk10
    assert (0, 2, 10) in gotos


def test_state_redirect_abstains_when_dispatcher_coordinate_is_not_source_edge(
    _seam,
) -> None:
    """A stale dispatcher coordinate cannot become a redirect's old edge."""

    fg = FlowGraph(
        blocks={
            6: _b(6, (14,), (174,)),
            14: _b(14, (), (6,)),
            174: _b(174, (6,), (), (_mov_state(0x18003239F, 0x22),)),
            304: _b(304, (), ()),
        },
        entry_serial=174,
        func_ea=0x180032390,
    )
    dispatcher = _disp({0x22: 14}, exit_block=99)
    transition = StateWriteTransition(174, 0x22, 14, False, None)

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        (transition,),
        # The current source topology is 174 -> 6.  A later/stale dispatcher
        # coordinate of 304 must not manufacture 174 -> 304 -> 14.
        dispatcher_entry_serial=304,
        pre_header_serial=None,
        initial_state=None,
    )

    assert not any(
        isinstance(modification, RedirectGoto)
        and modification.from_serial == 174
        for modification in modifications
    )


def test_native_cfg_persistence_keeps_exact_terminal_alias_anchor() -> None:
    """A logical STOP route must retain its current native GOTO anchor."""

    terminal_goto = InsnSnapshot(
        opcode=0x37,
        ea=0x1800021FB,
        native_ea=0x1800021FB,
        operands=(),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            2: _b(2, (8,), (8,)),
            5: BlockSnapshot(
                serial=5,
                block_type=0,
                succs=(9,),
                preds=(),
                flags=0,
                start_ea=0x1800021FB,
                native_start_ea=0x1800021FB,
                insn_snapshots=(terminal_goto,),
            ),
            8: _b(8, (2,), (2,), (_mov_state(0x180002231, 0x3C8960A9),)),
            9: BlockSnapshot(
                serial=9,
                block_type=1,
                succs=(),
                preds=(5,),
                flags=0,
                start_ea=0xFFFFFFFFFFFFFFFF,
                native_start_ea=None,
                insn_snapshots=(),
            ),
        },
        entry_serial=2,
        func_ea=0x1800021D0,
    )
    dispatcher = _disp({}, exit_block=9)
    transition = StateWriteTransition(
        write_block=8,
        next_state=0x3C8960A9,
        target_handler=9,
        is_return=True,
        branch_arm=None,
        proof=TransitionProof(
            "decision_dag_state_route_reconciliation",
            "decision_dag_reconciled",
            True,
        ),
    )

    legacy = build_state_write_redirects(
        graph,
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
    )
    assert [
        (item.from_serial, item.old_target, item.new_target)
        for item in legacy
        if isinstance(item, RedirectGoto)
    ] == [(8, 2, 9)]

    modifications = build_state_write_redirects(
        graph,
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        prefer_native_terminal_aliases=True,
        decision_dag_aliases={5: 9},
    )

    assert [
        (item.from_serial, item.old_target, item.new_target)
        for item in modifications
        if isinstance(item, RedirectGoto)
    ] == [(8, 2, 5)]

    one_sided = FlowGraph(
        {**graph.blocks, 9: replace(graph.get_block(9), preds=())},
        graph.entry_serial,
        graph.func_ea,
    )
    malformed = build_state_write_redirects(
        one_sided,
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        prefer_native_terminal_aliases=True,
        decision_dag_aliases={5: 9},
    )
    assert [
        (item.from_serial, item.old_target, item.new_target)
        for item in malformed
        if isinstance(item, RedirectGoto)
    ] == [(8, 2, 9)]


def _native_bound_route(
    *,
    source: int,
    state: int,
    target: int,
    fact_id: str = "fact",
    resolver_kind: str | None = None,
    row_kind: str | None = None,
    binding_evidence: NativeBoundRouteBindingEvidence | None = None,
) -> NativeBoundTransitionRoute:
    values = dict(
        fact_id=fact_id,
        source_instruction_ea=0x7FF855576BA0 + source,
        source_block_serial=source,
        state_constant=state,
        target_handler_serial=target,
        binding_evidence=binding_evidence,
    )
    if resolver_kind is not None:
        values["resolver_kind"] = resolver_kind
    if row_kind is not None:
        values["row_kind"] = row_kind
    return NativeBoundTransitionRoute(**values)


def _completed_decision_dag_transition(*, exact_target: int = 30) -> StateWriteTransition:
    graph = FlowGraph(
        {
            4: _b(4, (exact_target,), (), ()),
            10: _b(10, (11,), (), ()),
            11: _b(11, (), (10,), (_mov_state(0x12C0, 0x10),)),
            exact_target: _b(exact_target, (), (4,), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(
        10,
        0x10,
        exact_target,
        False,
        None,
        via_block=11,
    )
    route = minimal_state_recovery_module._DecisionDagStateRoute(
        target=exact_target,
        certified_targets=frozenset({exact_target}),
        entry_serial=4,
        path_serials=(4,),
        path_anchors=(0x1100,),
    )
    fact = minimal_state_recovery_module._semantic_route_fact_for_transition(
        transition,
        route,
        graph,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.DECISION_DAG
    assert fact.decision_dag_witness is not None
    assert fact.decision_dag_witness.path_serials == (4,)
    return replace(transition, semantic_route_fact=fact)


def test_native_bound_routes_enrich_direct_and_via_with_typed_fact_ids() -> None:
    direct = StateWriteTransition(10, 0x10, 20, False, None)
    through_via = StateWriteTransition(11, 0x20, 30, False, None, via_block=12)
    unrelated = StateWriteTransition(13, 0x30, 40, False, None, via_block=14)

    enriched = enrich_native_bound_transition_routes(
        (direct, through_via, unrelated),
        (
            _native_bound_route(source=10, state=0x10, target=20, fact_id="direct"),
            _native_bound_route(source=12, state=0x20, target=30, fact_id="via"),
        ),
    )
    assert [item.semantic_route_fact.fact_id for item in enriched[:2]] == [
        "direct",
        "via",
    ]
    assert enriched[2].semantic_route_fact is None


def test_graph_bound_native_enrichment_matches_emitter_entry_fact() -> None:
    graph = FlowGraph(
        {0: _b(0, (2,), ()), 2: _b(2, (), (0,))}, entry_serial=0, func_ea=0x1000,
    )
    route = _native_bound_route(source=0, state=0x10, target=2, fact_id="entry")
    (enriched,) = enrich_native_bound_transition_routes(
        (StateWriteTransition(0, None, None, True, None),), (route,), flow_graph=graph,
    )

    assert enriched.semantic_route_fact == _native_bound_route_fact(graph, route)


def test_graph_bound_native_enrichment_abstains_when_target_is_missing() -> None:
    graph = FlowGraph({0: _b(0, (), ())}, entry_serial=0, func_ea=0x1000)
    route = _native_bound_route(source=0, state=0x10, target=2, fact_id="entry")
    (enriched,) = enrich_native_bound_transition_routes(
        (StateWriteTransition(0, None, None, True, None),), (route,), flow_graph=graph,
    )

    assert enriched.semantic_route_fact is None


def test_graph_bound_native_anchor_drift_rejects_final_fact_join() -> None:
    route = _native_bound_route(source=0, state=0x10, target=2, fact_id="entry")
    graph = FlowGraph(
        {0: _b(0, (2,), ()), 2: _b(2, (), (0,))}, entry_serial=0, func_ea=0x1000,
    )
    drifted = FlowGraph(
        {0: _b(0, (2,), ()), 2: replace(_b(2, (), (0,)), start_ea=0x2222)},
        entry_serial=0,
        func_ea=0x1000,
    )
    (first,) = enrich_native_bound_transition_routes(
        (StateWriteTransition(0, None, None, True, None),), (route,), flow_graph=graph,
    )
    (second,) = enrich_native_bound_transition_routes(
        (StateWriteTransition(0, None, None, True, None),), (route,), flow_graph=drifted,
    )

    assert first.semantic_route_fact != second.semantic_route_fact
    assert _complete_local_semantic_route_facts(
        (first.semantic_route_fact,), second.semantic_route_fact, (),
    ) is None


def test_native_bound_enrichment_joins_resolved_transition_by_exact_route() -> None:
    transition = StateWriteTransition(10, 0x10, 20, False, None)

    (enriched,) = enrich_native_bound_transition_routes(
        (transition,),
        (
            _native_bound_route(
                source=10, state=0x10, target=20, fact_id="matching"
            ),
            _native_bound_route(
                source=10, state=0x99, target=30, fact_id="other-route"
            ),
        ),
    )

    assert enriched.semantic_route_fact is not None
    assert enriched.semantic_route_fact.fact_id == "matching"
    assert enriched.next_state == transition.next_state
    assert enriched.target_handler == transition.target_handler


def test_native_bound_enrichment_can_bind_after_route_reconciliation() -> None:
    receipt = _native_bound_route(
        source=10, state=0x30, target=40, fact_id="normalized"
    )
    provisional = StateWriteTransition(10, 0x10, 20, False, None)

    (before_reconciliation,) = enrich_native_bound_transition_routes(
        (provisional,), (receipt,)
    )
    assert before_reconciliation.semantic_route_fact is None

    normalized = replace(
        before_reconciliation,
        next_state=0x30,
        target_handler=40,
    )
    (after_reconciliation,) = enrich_native_bound_transition_routes(
        (normalized,), (receipt,)
    )

    assert after_reconciliation.semantic_route_fact is not None
    assert after_reconciliation.semantic_route_fact.fact_id == "normalized"


def test_seeded_native_bound_transition_retains_typed_route_fact() -> None:
    def block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...], ea: int) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=len(succs),
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=ea,
            insn_snapshots=(),
        )

    graph = FlowGraph(
        {
            4: block(4, (5,), (), 0x1100),
            5: block(5, (), (4,), 0x1200),
            3: block(3, (), (), 0x1300),
        },
        4,
        0x1000,
    )
    route = _native_bound_route(source=4, state=0x10, target=3, fact_id="seed")
    (transition,) = minimal_unflatten_emit_module._seed_native_bound_backedge_transitions(
        graph,
        (),
        (route,),
        dispatcher_entry_serial=2,
        dispatcher_region_serials=frozenset({2, 5}),
    )
    assert transition.semantic_route_fact is not None
    assert transition.semantic_route_fact.kind is SemanticRouteFactKind.NATIVE_BOUND
    assert transition.semantic_route_fact.source_instruction_ea == route.source_instruction_ea
    assert transition.semantic_route_fact.fact_id == "seed"


def test_native_bound_fact_shared_by_two_owners_abstains_atomically() -> None:
    transitions = (
        StateWriteTransition(10, 0x10, 20, False, None, via_block=12),
        StateWriteTransition(11, 0x10, 20, False, None, via_block=12),
    )

    enriched = enrich_native_bound_transition_routes(
        transitions,
        (_native_bound_route(source=12, state=0x10, target=20, fact_id="shared"),),
    )
    assert all(item.semantic_route_fact is None for item in enriched)


def test_ambiguous_native_fact_does_not_hide_unrelated_exact_fact() -> None:
    transitions = (
        StateWriteTransition(10, 0x10, 20, False, None, via_block=12),
        StateWriteTransition(11, 0x10, 20, False, None, via_block=12),
        StateWriteTransition(13, 0x30, 40, False, None),
    )

    enriched = enrich_native_bound_transition_routes(
        transitions,
        (
            _native_bound_route(
                source=12, state=0x10, target=20, fact_id="shared"
            ),
            _native_bound_route(
                source=13, state=0x30, target=40, fact_id="independent"
            ),
        ),
    )

    assert enriched[0].semantic_route_fact is None
    assert enriched[1].semantic_route_fact is None
    assert enriched[2].semantic_route_fact is not None
    assert enriched[2].semantic_route_fact.fact_id == "independent"


def test_native_bound_route_enriches_unresolved_entry_transition() -> None:
    transition = StateWriteTransition(10, None, None, True, 1, via_block=11)

    (enriched,) = enrich_native_bound_transition_routes(
        (transition,),
        (_native_bound_route(source=11, state=0x16AA65E9, target=20),),
    )

    assert enriched.write_block == transition.write_block
    assert enriched.next_state == 0x16AA65E9
    assert enriched.target_handler == 20
    assert enriched.branch_arm == transition.branch_arm
    assert enriched.via_block == transition.via_block
    assert enriched.is_return is False
    assert enriched.proof is not None
    assert enriched.proof.oracle_kind == "native_bound_transition_route"
    assert enriched.proof.kind == "native_bound_route"
    assert enriched.proof.trusted is True


def test_native_bound_route_enriches_unresolved_backedge_transition() -> None:
    transition = StateWriteTransition(15, None, None, True, None)

    (enriched,) = enrich_native_bound_transition_routes(
        (transition,),
        (_native_bound_route(source=15, state=0x079323F9, target=30),),
    )

    assert (enriched.next_state, enriched.target_handler) == (0x079323F9, 30)
    assert enriched.branch_arm is None
    assert enriched.via_block is None


def test_native_bound_route_never_overwrites_disagreeing_resolved_transition() -> None:
    proof = TransitionProof("existing", "resolved", True)
    transition = StateWriteTransition(10, 0x10, 20, False, 0, proof=proof)

    assert enrich_native_bound_transition_routes(
        (transition,),
        (_native_bound_route(source=10, state=0x16AA65E9, target=30),),
    ) == (transition,)


def test_native_bound_route_corroborates_matching_resolved_transition() -> None:
    proof = TransitionProof("abstract_fixpoint", "global_fold", True)
    transition = StateWriteTransition(10, 0x16AA65E9, 20, False, 0, proof=proof)
    route = _native_bound_route(
        source=10,
        state=0x16AA65E9,
        target=20,
        fact_id="transition:corroborated",
    )

    (enriched,) = enrich_native_bound_transition_routes((transition,), (route,))

    assert enriched.next_state == transition.next_state
    assert enriched.target_handler == transition.target_handler
    assert enriched.proof is not None
    assert enriched.proof.oracle_kind == "native_bound_transition_route"
    assert enriched.proof.kind == "native_bound_route"
    assert enriched.proof.reason == (
        "fact_id=transition:corroborated;native_ea=0x7FF855576BAA"
    )


def test_native_bound_normalization_preserves_richer_matching_fact() -> None:
    transition = _completed_decision_dag_transition()
    route = _native_bound_route(source=11, state=0x10, target=30, fact_id="native")
    unrelated = _native_bound_route(
        source=11, state=0x99, target=20, fact_id="other-phase"
    )

    (normalized,) = enrich_native_bound_transition_routes(
        (transition,), (route, unrelated)
    )

    assert normalized.semantic_route_fact is transition.semantic_route_fact
    assert normalized.semantic_route_fact.kind is SemanticRouteFactKind.DECISION_DAG


def test_native_bound_normalization_revokes_stale_existing_fact() -> None:
    old_route = _native_bound_route(source=10, state=0x10, target=20, fact_id="old")
    (with_old_fact,) = enrich_native_bound_transition_routes(
        (StateWriteTransition(10, 0x10, 20, False, None),), (old_route,)
    )
    stale = replace(with_old_fact, target_handler=30)

    (normalized,) = enrich_native_bound_transition_routes((stale,), (old_route,))

    assert normalized.semantic_route_fact is None


def test_native_bound_normalization_preserves_completed_decision_dag_fact_at_coarse_replay(
) -> None:
    transition = _completed_decision_dag_transition()
    coarse_dispatcher_receipt = _native_bound_route(
        source=11,
        state=0x10,
        target=20,
        fact_id="native:coarse-dispatcher",
    )

    (normalized,) = enrich_native_bound_transition_routes(
        (transition,), (coarse_dispatcher_receipt,)
    )

    assert normalized.semantic_route_fact is transition.semantic_route_fact
    assert normalized.semantic_route_fact.decision_dag_witness is not None
    assert normalized.semantic_route_fact.target_serial == 30


def test_native_enrichment_preserves_completed_bootstrap_entry_corridor_fact() -> None:
    """Native receipts must not erase an entry-writer bootstrap route fact."""

    state = 0xB2FD8FB6
    call = InsnSnapshot(
        opcode=0x38,
        ea=0x1508,
        operands=(),
        kind=InsnKind.CALL,
    )
    graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (3,), (0,), (_mov_state(0x1108, state),)),
            3: _b(3, (5,), (1,)),
            5: _b(5, (6,), (3,), (call,)),
            6: _b(6, (7,), (5,)),
            7: _b(7, (), (6,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(5, state, 7, False, None)
    route = minimal_state_recovery_module._DecisionDagStateRoute(
        target=7,
        certified_targets=frozenset({7}),
        entry_serial=6,
        path_serials=(6,),
        path_anchors=(graph.get_block(6).start_ea,),
        handoff_dispatcher_serial=6,
        handoff_dispatcher_anchor_ea=graph.get_block(6).start_ea,
    )
    fact = minimal_state_recovery_module._semantic_route_fact_for_transition(
        transition,
        route,
        graph,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.BOOTSTRAP
    assert fact.owner_serial == 5
    assert fact.source_serial == 1

    (enriched,) = minimal_unflatten_emit_module._enrich_native_routes_preserving_bootstrap_facts(
        (replace(transition, semantic_route_fact=fact),),
        (),
        flow_graph=graph,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert enriched.semantic_route_fact is fact


def test_exact_physical_native_receipt_revokes_completed_dag_route_before_enrichment() -> None:
    """A matching physical receipt owns the route over its generic DAG replay."""

    transition = _completed_decision_dag_transition()
    graph = FlowGraph(
        {
            4: _b(4, (30,), (), ()),
            10: _b(10, (11,), (), ()),
            11: _b(11, (), (10,), (_mov_state(0x12C0, 0x10),)),
            30: _b(30, (), (4,), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    receipt = _native_bound_route(
        source=11,
        state=0x10,
        target=30,
        fact_id="native:physical",
        binding_evidence=NativeBoundRouteBindingEvidence(
            target_native_ea=0x1780,
            state_var_stkoff=_STATE,
            state_var_reg=None,
        ),
    )
    receipt = replace(receipt, source_instruction_ea=0x12C0)
    revoke = getattr(
        minimal_unflatten_emit_module,
        "_revoke_completed_dag_facts_for_exact_native_receipts",
        lambda rows, *_args, **_kwargs: rows,
    )

    (reconciled,) = revoke(
        (transition,),
        (receipt,),
        flow_graph=graph,
        dispatcher_region_serials=frozenset(),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )
    (enriched,) = enrich_native_bound_transition_routes(
        (reconciled,),
        (receipt,),
        flow_graph=graph,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert enriched.proof is not None
    assert enriched.proof.oracle_kind == "native_bound_transition_route"
    assert enriched.semantic_route_fact is not None
    assert enriched.semantic_route_fact.kind is SemanticRouteFactKind.NATIVE_BOUND


@pytest.mark.parametrize(
    "variant",
    (
        "missing-physical-write",
        "divergent-receipt",
        "different-source-instruction",
        "raw-binding-evidence",
        "wrong-target-evidence",
        "wrong-identity-evidence",
    ),
)
def test_native_receipt_replay_keeps_completed_dag_fact_without_one_exact_witness(
    variant: str,
) -> None:
    """Incomplete native receipt evidence must not demote a completed DAG proof."""

    transition = _completed_decision_dag_transition()
    graph = FlowGraph(
        {
            4: _b(4, (30,), (), ()),
            10: _b(10, (11,), (), ()),
            11: _b(
                11,
                (),
                (10,),
                () if variant == "missing-physical-write" else (_mov_state(0x12C0, 0x10),),
            ),
            30: _b(30, (), (4,), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    receipt = _native_bound_route(
        source=11, state=0x10, target=30, fact_id="native:physical",
    )
    if variant != "different-source-instruction":
        receipt = replace(receipt, source_instruction_ea=0x12C0)
    if variant not in {"raw-binding-evidence", "different-source-instruction"}:
        receipt = replace(
            receipt,
            binding_evidence=NativeBoundRouteBindingEvidence(
                target_native_ea=(0x17C0 if variant == "wrong-target-evidence" else 0x1780),
                state_var_stkoff=(0x24 if variant == "wrong-identity-evidence" else _STATE),
                state_var_reg=None,
            ),
        )
    receipts = (
        (receipt, replace(receipt, source_instruction_ea=receipt.source_instruction_ea + 1))
        if variant == "divergent-receipt"
        else (receipt,)
    )

    (reconciled,) = minimal_unflatten_emit_module._revoke_completed_dag_facts_for_exact_native_receipts(
        (transition,),
        receipts,
        flow_graph=graph,
        dispatcher_region_serials=frozenset(),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert reconciled is transition
    assert reconciled.semantic_route_fact is transition.semantic_route_fact


@pytest.mark.parametrize("reverse", (False, True))
def test_strong_native_receipt_revocation_is_independent_of_raw_receipt_order(
    reverse: bool,
) -> None:
    transition = _completed_decision_dag_transition()
    graph = FlowGraph(
        {
            4: _b(4, (30,), (), ()),
            10: _b(10, (11,), (), ()),
            11: _b(11, (), (10,), (_mov_state(0x12C0, 0x10),)),
            30: _b(30, (), (4,), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    raw = _native_bound_route(source=11, state=0x10, target=30, fact_id="raw")
    strong = replace(
        raw,
        fact_id="strong",
        source_instruction_ea=0x12C0,
        binding_evidence=NativeBoundRouteBindingEvidence(0x1780, _STATE, None),
    )
    routes = (strong, raw) if reverse else (raw, strong)

    (reconciled,) = minimal_unflatten_emit_module._revoke_completed_dag_facts_for_exact_native_receipts(
        (transition,), routes, flow_graph=graph, dispatcher_region_serials=frozenset(),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert reconciled.semantic_route_fact is None


def test_divergent_replay_valid_strong_receipts_preserve_completed_dag_fact() -> None:
    transition = _completed_decision_dag_transition()
    graph = FlowGraph(
        {
            4: _b(4, (30,), (), ()),
            10: _b(10, (11,), (), ()),
            11: _b(11, (), (10,), (_mov_state(0x12C0, 0x10),)),
            30: _b(30, (), (4,), (_mov_state(0x1781, 0x99),)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    first = _native_bound_route(
        source=11,
        state=0x10,
        target=30,
        fact_id="strong:first",
        binding_evidence=NativeBoundRouteBindingEvidence(0x1780, _STATE, None),
    )
    second = replace(
        first,
        fact_id="strong:second",
        binding_evidence=NativeBoundRouteBindingEvidence(0x1781, _STATE, None),
    )
    first = replace(first, source_instruction_ea=0x12C0)
    second = replace(second, source_instruction_ea=0x12C0)

    (reconciled,) = minimal_unflatten_emit_module._revoke_completed_dag_facts_for_exact_native_receipts(
        (transition,), (first, second), flow_graph=graph, dispatcher_region_serials=frozenset(),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert reconciled is transition
    assert reconciled.semantic_route_fact is transition.semantic_route_fact


def test_native_bound_normalization_abstains_on_witnessless_decision_dag_fact() -> None:
    completed = _completed_decision_dag_transition()
    provisional = replace(
        completed,
        semantic_route_fact=replace(
            completed.semantic_route_fact,
            decision_dag_witness=None,
        ),
    )

    (normalized,) = enrich_native_bound_transition_routes(
        (provisional,),
        (_native_bound_route(source=11, state=0x10, target=20),),
    )

    assert normalized.semantic_route_fact is None
    assert normalized.proof is None


def test_native_bound_normalization_rejects_same_id_with_unequal_content() -> None:
    transition = StateWriteTransition(10, 0x10, 20, False, None)
    first = _native_bound_route(source=10, state=0x10, target=20, fact_id="same")
    routes = (
        first,
        replace(first, source_instruction_ea=0x7FF855576BAB),
    )

    (normalized,) = enrich_native_bound_transition_routes((transition,), routes)

    assert normalized.semantic_route_fact is None


def test_seed_native_bound_backedge_rejects_conflicting_receipts() -> None:
    def block(
        serial: int,
        succs: tuple[int, ...],
        preds: tuple[int, ...],
        ea: int,
    ) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=len(succs),
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=ea,
            insn_snapshots=(),
        )

    graph = FlowGraph(
        {
            4: block(4, (5,), (), 0x1100),
            5: block(5, (), (4,), 0x1200),
            3: block(3, (), (), 0x1300),
        },
        4,
        0x1000,
    )
    routes = (
        _native_bound_route(source=4, state=0x10, target=3, fact_id="first"),
        _native_bound_route(source=4, state=0x10, target=3, fact_id="second"),
    )

    seeded = minimal_unflatten_emit_module._seed_native_bound_backedge_transitions(
        graph,
        (),
        routes,
        dispatcher_entry_serial=2,
        dispatcher_region_serials=frozenset({2, 5}),
    )

    assert seeded == ()


def test_seed_native_bound_backedge_conflict_aborts_mixed_sources() -> None:
    def block(
        serial: int,
        succs: tuple[int, ...],
        preds: tuple[int, ...],
        ea: int,
    ) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=len(succs),
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=ea,
            insn_snapshots=(),
        )

    graph = FlowGraph(
        {
            4: block(4, (5,), (), 0x1100),
            6: block(6, (5,), (), 0x1140),
            5: block(5, (), (4, 6), 0x1200),
            3: block(3, (), (), 0x1300),
            9: block(9, (), (), 0x1400),
        },
        4,
        0x1000,
    )
    routes = (
        _native_bound_route(source=4, state=0x10, target=3, fact_id="conflict"),
        _native_bound_route(source=4, state=0x10, target=9, fact_id="conflict"),
        _native_bound_route(source=6, state=0x20, target=3, fact_id="valid"),
    )

    seeded = minimal_unflatten_emit_module._seed_native_bound_backedge_transitions(
        graph,
        (),
        routes,
        dispatcher_entry_serial=2,
        dispatcher_region_serials=frozenset({2, 5}),
    )

    assert seeded is None


def test_emit_aborts_fragment_on_richer_route_disagreement(monkeypatch) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
            30: _b(30, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 20}, exit_block=99)
    native = _native_bound_route(source=10, state=0x10, target=20, fact_id="rich")
    (native_transition,) = enrich_native_bound_transition_routes(
        (StateWriteTransition(10, 0x10, 20, False, 0),), (native,)
    )
    rich = replace(
        native_transition.semantic_route_fact,
        kind=SemanticRouteFactKind.DECISION_DAG,
        fact_id=None,
    )
    transition = replace(native_transition, semantic_route_fact=rich)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (transition,),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        native_key=NATIVE_KEY,
        native_bound_transition_routes=(
            _native_bound_route(source=10, state=0x10, target=30, fact_id="other"),
        ),
    )

    assert graph_modifications(plan) == []


def test_emit_aborts_fragment_on_ambiguous_native_missing_fact(monkeypatch) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (StateWriteTransition(10, None, None, False, None),),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
                state_var_stkoff=_STATE,
                dispatcher_entry_serial=2,
                initial_state=0x10,
                authoritative_handler_serials=frozenset({10, 20}),
                native_key=NATIVE_KEY,
                native_bound_transition_routes=(
            _native_bound_route(source=10, state=0x10, target=20, fact_id="one"),
            _native_bound_route(source=10, state=0x20, target=10, fact_id="two"),
        ),
    )

    assert graph_modifications(plan) == []


def test_missing_route_fact_coordinates_include_receipt_candidates() -> None:
    transitions = (
        StateWriteTransition(3, None, None, False, None, via_block=4),
        StateWriteTransition(8, None, None, False, None),
    )
    routes = (
        _native_bound_route(source=4, state=0x20, target=30, fact_id="z"),
        _native_bound_route(source=4, state=0x10, target=20, fact_id="a"),
        _native_bound_route(source=99, state=0x30, target=40, fact_id="unrelated"),
    )

    coordinates = _missing_semantic_route_fact_coordinates(transitions, routes)

    assert coordinates == (
        MissingSemanticRouteFactCoordinate(
            owner_serial=3,
            write_serial=3,
            via_serial=4,
            state=None,
            target=None,
            candidate_fact_ids=("a", "z"),
        ),
        MissingSemanticRouteFactCoordinate(
            owner_serial=8,
            write_serial=8,
            via_serial=None,
            state=None,
            target=None,
            candidate_fact_ids=(),
        ),
    )


def test_native_bound_route_mismatch_and_conflict_are_inert() -> None:
    mismatch = StateWriteTransition(10, None, None, True, 0, via_block=11)
    conflict = StateWriteTransition(15, None, None, True, 1)

    assert enrich_native_bound_transition_routes(
        (mismatch,),
        (_native_bound_route(source=99, state=0x10, target=20),),
    ) == (mismatch,)
    assert enrich_native_bound_transition_routes(
        (conflict,),
        (
            _native_bound_route(source=15, state=0x10, target=20, fact_id="a"),
            _native_bound_route(source=15, state=0x20, target=30, fact_id="b"),
        ),
    ) == (conflict,)


def test_native_bound_route_target_in_dispatcher_region_is_inert() -> None:
    transition = StateWriteTransition(15, None, None, True, 1)

    assert enrich_native_bound_transition_routes(
        (transition,),
        (_native_bound_route(source=15, state=0x10, target=2),),
        dispatcher_region_serials=frozenset({2}),
    ) == (transition,)


def test_native_bound_route_receipt_identifies_accepted_current_route(
    monkeypatch, caplog
):
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(10, None, None, True, None),
        ),
    )
    route = _native_bound_route(
        source=10,
        state=0x20,
        target=20,
        fact_id="transition:receipt",
    )

    with caplog.at_level(
        logging.INFO, logger="d810.transforms.minimal_unflatten_emit"
    ):
        plan = emit_minimal_unflatten(
            fg,
            disp,
            state_var_stkoff=_STATE,
            dispatcher_entry_serial=2,
            initial_state=0x10,
            native_bound_transition_routes=(route,),
        )

    _assert_no_legacy_plan_metadata(plan)
    assert (10, 2, 20) in {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert not any(
        "native-bound transition route receipt:" in record.getMessage()
        for record in caplog.records
    )


def test_intermediate_effect_veto_stops_later_sibling_planning(monkeypatch):
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(
                10,
                0x20,
                20,
                False,
                0,
                proof=TransitionProof("exact", "test", True),
            ),
        ),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_stage_effect_safe_intermediate_redirect_groups",
        lambda *_args, **_kwargs: None,
    )

    def fail_later_planning(*_args, **_kwargs):
        raise AssertionError("effect veto must stop later sibling planning")

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_handler_transitions",
        fail_later_planning,
    )

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
    )

    assert graph_modifications(plan) == []


def test_emitter_logs_typed_production_abstention_and_abstains_atomically(
    monkeypatch, caplog
) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (StateWriteTransition(10, None, None, True, None),),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "build_canonical_semantic_evidence",
        lambda *_args, **_kwargs: CanonicalSemanticEvidenceProductionResult(
            abstention=CanonicalSemanticEvidenceProductionAbstention(
                reason=CanonicalSemanticEvidenceProductionReason.PARTITION_GROUP_INCOMPLETE,
                stage=CanonicalSemanticEvidenceProductionStage.GROUP,
                coordinate=CanonicalSemanticEvidenceProductionFactCoordinate(
                    SemanticRouteFactKind.NATIVE_BOUND,
                    10,
                    10,
                    0x2000,
                    20,
                    0x20,
                ),
            )
        ),
    )

    with caplog.at_level(logging.INFO, logger="d810.transforms.minimal_unflatten_emit"):
        plan = emit_minimal_unflatten(
            fg,
            disp,
            state_var_stkoff=_STATE,
            dispatcher_entry_serial=2,
            initial_state=0x10,
            authoritative_handler_serials=frozenset({10, 20}),
            native_key=NATIVE_KEY,
            native_bound_transition_routes=(
                _native_bound_route(source=10, state=0x20, target=20, fact_id="typed"),
            ),
        )

    assert graph_modifications(plan) == []
    assert not any(
        "unflat canonical route evidence abstained" in record.getMessage()
        for record in caplog.records
    )


def test_native_bound_entry_route_receipt_identifies_exact_redirect(monkeypatch):
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    state = 0x16AA65E9
    disp = _disp({state: 10}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )
    route = _native_bound_route(
        source=1,
        state=state,
        target=10,
        fact_id="entry:receipt",
    )

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        native_bound_transition_routes=(route,),
    )

    assert (1, 2, 10) in {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    _assert_no_legacy_plan_metadata(plan)


def test_route_join_rejection_abstains_instead_of_escaping_the_emitter(
    monkeypatch, _seam,
) -> None:
    """A refused route join must decline the plan, never abort the pass.

    ``emit_minimal_unflatten`` converts a producer failure into "emit nothing"
    with ``except (TypeError, ValueError)``.  The route-authority joins raise
    ``RuntimeJoinRejected``, and its only production caller above the emitter
    (``state_machine``) has no handler at all, so if that exception were not a
    ``ValueError`` a proof that is merely not this bundle's own record would
    escape the emitter and abort a decompilation instead of declining it.
    """

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    state = 0x16AA65E9
    source_write = InsnSnapshot(
        0, 0x1001, (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(
            kind=OperandKind.STACK, size=4, stkoff=_STATE, stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    target_insn = InsnSnapshot(
        0, 0x2000, (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x0BADF00D),
        d=MopSnapshot(
            kind=OperandKind.STACK, size=4, stkoff=_STATE, stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    fg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (2,), (), 0, 0x1000, (source_write,)),
            2: _b(2, (20,), (0, 20)),
            20: BlockSnapshot(20, 0, (2,), (2,), 0, 0x2000, (target_insn,)),
            99: _b(99, (), ()),
        }, entry_serial=0, func_ea=0x1000,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (StateWriteTransition(0, None, None, True, None),),
    )
    entry_route = NativeBoundTransitionRoute("entry", 0x1001, 0, state, 20)
    kwargs = dict(
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        native_key=NATIVE_KEY,
        block_refs_by_serial={
            serial: NativeBlockRef(StableBlockIdentity.from_intervals(
                (NativeEaInterval(block.start_ea, block.start_ea + 0x20),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=tuple(insn.ea for insn in block.insn_snapshots),
            )) for serial, block in fg.blocks.items()
        },
        native_bound_transition_routes=(entry_route,),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({20}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )
    dispatcher = _disp({state: 20}, exit_block=99)

    accepted = emit_minimal_unflatten(fg, dispatcher, **kwargs)
    assert accepted.unflatten_proposal is not None

    reached = []

    def refuse(_evidence):
        reached.append(1)
        raise RuntimeJoinRejected(
            "canonical semantic evidence is not bound to a runtime authority arena"
        )

    monkeypatch.setattr(
        minimal_unflatten_emit_module, "route_join_binding", refuse,
    )

    declined = emit_minimal_unflatten(fg, dispatcher, **kwargs)

    assert reached, "the join under test was never reached"
    assert declined.unflatten_proposal is None
    assert graph_modifications(declined) == []
    # The reason the two asserts above hold, stated so a future edit that
    # rebases the exception cannot quietly reintroduce the escape.
    assert issubclass(RuntimeJoinRejected, ValueError)


def test_native_bound_interval_range_cannot_bypass_function_entry() -> None:
    """An interval interior is a router hint, not an exact entry bridge."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    modifications = build_native_bound_state_entry_bridges(
        fg,
        (
            _native_bound_route(
                source=1,
                state=0x3C7BAD9A,
                target=10,
                fact_id="entry:interval-range",
                resolver_kind="interval_dispatcher_row",
                row_kind="interval_range",
            ),
        ),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({10}),
    )

    assert modifications == []


def test_interval_only_entry_route_bails_without_a_singleton_proof(
    monkeypatch,
) -> None:
    """The generic interval provider cannot re-promote a rejected range row."""
    state = 0x3C7BAD9A
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(lo=state - 1, hi=state + 2, target=10),),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        native_bound_transition_routes=(
            _native_bound_route(
                source=1,
                state=state,
                target=10,
                fact_id="entry:interval-range",
                resolver_kind="interval_dispatcher_row",
                row_kind="interval_range",
            ),
        ),
        authoritative_handler_serials=frozenset({10}),
        dispatcher_region_serials=frozenset({2}),
    )

    assert graph_modifications(plan) == []


def test_native_bound_route_receipt_is_not_logged_before_entry_bridge_bail(
    monkeypatch, caplog
):
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(10, None, None, True, None),
        ),
    )
    route = _native_bound_route(
        source=10,
        state=0x20,
        target=20,
        fact_id="transition:bail",
    )

    with caplog.at_level(
        logging.INFO, logger="d810.transforms.minimal_unflatten_emit"
    ):
        plan = emit_minimal_unflatten(
            fg,
            disp,
            state_var_stkoff=_STATE,
            dispatcher_entry_serial=2,
            native_bound_transition_routes=(route,),
        )

    messages = [record.getMessage() for record in caplog.records]
    assert any("BAILED (no entry bridge" in message for message in messages)
    assert not any(
        "native-bound transition route receipt:" in message for message in messages
    )
    _assert_no_legacy_plan_metadata(plan)


def test_native_bound_route_recovers_initial_state_and_entry_bridge(monkeypatch):
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (20,), (0, 20)),
            20: _b(20, (2,), (2,)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    state = 0x16AA65E9
    disp = _disp({state: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(0, None, None, True, None),
        ),
    )
    route = _native_bound_route(source=0, state=state, target=20)
    enriched = enrich_native_bound_transition_routes(
        (StateWriteTransition(0, None, None, True, None),),
        (route,),
    )
    assert _recover_initial_state(
        fg,
        enriched,
        2,
        None,
        state_var_stkoff=_STATE,
    ) == state

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        native_bound_transition_routes=(route,),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (0, 2, 20) in gotos


@pytest.mark.parametrize("duplicate_entry_fact", (False, True))
def test_typed_entry_native_route_registers_its_canonical_proof(monkeypatch, _seam, duplicate_entry_fact):
    """An entry-only native receipt owns proposal evidence without a back edge."""

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    state = 0x16AA65E9
    source_write = InsnSnapshot(
        0, 0x1001, (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(
            kind=OperandKind.STACK, size=4, stkoff=_STATE,
            stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    target_insn = InsnSnapshot(
        0, 0x2000, (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x0BADF00D),
        d=MopSnapshot(
            kind=OperandKind.STACK, size=4, stkoff=_STATE,
            stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    fg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (2,), (), 0, 0x1000, (source_write,)),
            2: _b(2, (20,), (0, 20)),
            20: BlockSnapshot(20, 0, (2,), (2,), 0, 0x2000, (target_insn,)),
            99: _b(99, (), ()),
        }, entry_serial=0, func_ea=0x1000,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (StateWriteTransition(0, None, None, True, None),),
    )
    entry_route = NativeBoundTransitionRoute("entry", 0x1001, 0, state, 20)
    plan = emit_minimal_unflatten(
        fg, _disp({state: 20}, exit_block=99), state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        native_key=NATIVE_KEY,
        block_refs_by_serial={
            serial: NativeBlockRef(StableBlockIdentity.from_intervals(
                (NativeEaInterval(block.start_ea, block.start_ea + 0x20),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=tuple(insn.ea for insn in block.insn_snapshots),
            )) for serial, block in fg.blocks.items()
        },
        native_bound_transition_routes=(entry_route, entry_route) if duplicate_entry_fact else (entry_route,),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({20}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )
    if duplicate_entry_fact:
        assert graph_modifications(plan) == []
        assert plan.unflatten_proposal is None
    else:
        assert plan.unflatten_proposal is not None
        assert sum(bool(getattr(claim, "route_proof_ids", ())) for claim in plan.unflatten_proposal.claims) == 1


def _typed_entry_native_route_fixture(monkeypatch):
    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    state = 0x16AA65E9
    source_write = InsnSnapshot(
        0, 0x1001, (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state),
        d=MopSnapshot(
            kind=OperandKind.STACK, size=4, stkoff=_STATE,
            stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    target_insn = InsnSnapshot(
        0, 0x2000, (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x0BADF00D),
        d=MopSnapshot(
            kind=OperandKind.STACK, size=4, stkoff=_STATE,
            stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (2,), (), 0, 0x1000, (source_write,)),
            2: _b(2, (20,), (0, 20)),
            20: BlockSnapshot(20, 0, (2,), (2,), 0, 0x2000, (target_insn,)),
            99: _b(99, (), ()),
        }, entry_serial=0, func_ea=0x1000,
    )
    entry_route = NativeBoundTransitionRoute("entry", 0x1001, 0, state, 20)
    non_entry_route = NativeBoundTransitionRoute(
        "non-entry", 0x2000, 20, 0x0BADF00D, 20,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (StateWriteTransition(0, None, None, True, None),),
    )
    return graph, state, entry_route, dict(
        dispatcher=_disp({state: 20, 0x0BADF00D: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        block_refs_by_serial={
            serial: NativeBlockRef(StableBlockIdentity.from_intervals(
                (NativeEaInterval(block.start_ea, block.start_ea + 0x20),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=tuple(insn.ea for insn in block.insn_snapshots),
            )) for serial, block in graph.blocks.items()
        },
        native_bound_transition_routes=(entry_route, non_entry_route),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({20}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )


def test_complete_typed_routes_delegate_entry_without_live_carrier(
    monkeypatch, _seam,
) -> None:
    """Missing entry-carrier evidence sends the route through proposal authority."""

    include_nonentry_route = True

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    entry_state = 0x16AA65E9
    loop_state = 0x0BADF00D
    other_state = 0x13572468
    entry_write = InsnSnapshot(
        0,
        0x1001,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=entry_state),
        d=MopSnapshot(
            kind=OperandKind.STACK,
            size=4,
            stkoff=_STATE,
            stack_refs=(_STATE,),
        ),
        kind=InsnKind.MOV,
        raw_opcode=0,
    )
    loop_write = replace(entry_write, ea=0x3001, l=replace(
        entry_write.l, value=loop_state,
    ))
    target_insn = replace(entry_write, ea=0x1281, l=replace(
        entry_write.l, value=other_state,
    ))
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (2,), (), 0, 0x1000, (entry_write,)),
            2: _b(2, (10, 20), (0, 20)),
            10: _b(10, (99,), (2,), (target_insn,)),
            20: BlockSnapshot(20, 0, (2,), (2,), 0, 0x3000, (loop_write,)),
            99: _b(99, (), (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    refs = {
        serial: NativeBlockRef(
            StableBlockIdentity.from_intervals(
                (NativeEaInterval(block.start_ea, block.start_ea + 0x20),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=tuple(
                    insn.ea for insn in block.insn_snapshots
                ),
            )
        )
        for serial, block in graph.blocks.items()
    }
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            (StateWriteTransition(0, None, None, True, None),)
            + ((StateWriteTransition(
                20,
                loop_state,
                10,
                False,
                None,
                proof=TransitionProof(
                    "region_partitioned_fixpoint", "global_fold", True,
                ),
            ),) if include_nonentry_route else ())
        ),
    )
    original_attach = minimal_unflatten_emit_module._attach_dispatcher_map_route_facts

    def attach_bootstrap_fact(*args, **kwargs):
        rows = original_attach(*args, **kwargs)
        return tuple(
            replace(
                row,
                semantic_route_fact=minimal_state_recovery_module._semantic_route_fact_for_transition(
                    row,
                    minimal_state_recovery_module._DecisionDagStateRoute(
                        target=10,
                        certified_targets=frozenset({10}),
                        entry_serial=2,
                        path_serials=(2,),
                        path_anchors=(graph.get_block(2).start_ea,),
                        handoff_dispatcher_serial=2,
                        handoff_dispatcher_anchor_ea=graph.get_block(2).start_ea,
                    ),
                    graph,
                    state_var_stkoff=_STATE,
                    state_var_reg=None,
                ),
            )
            if row.write_block == 0 and row.semantic_route_fact is not None
            else row
            for row in rows
        )

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_attach_dispatcher_map_route_facts",
        attach_bootstrap_fact,
    )

    plan = emit_minimal_unflatten(
        graph,
        _disp(
            {
                entry_state: 10,
                loop_state: 10,
                other_state: 20,
            },
            exit_block=99,
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        native_key=NATIVE_KEY,
        block_refs_by_serial=refs,
        native_bound_transition_routes=(
            (NativeBoundTransitionRoute(
                "entry", 0x1001, 0, entry_state, 10,
            ),)
            + ((NativeBoundTransitionRoute(
                "loop", 0x3001, 20, loop_state, 10,
            ),) if include_nonentry_route else ())
        ),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    entry_redirect = RedirectGoto(from_serial=0, old_target=2, new_target=10)
    loop_redirect = RedirectGoto(from_serial=20, old_target=2, new_target=10)
    assert entry_redirect in graph_modifications(plan)
    assert (loop_redirect in graph_modifications(plan)) is include_nonentry_route
    assert plan.unflatten_proposal is not None


@pytest.mark.parametrize("copies", (1, 2, 3))
def test_typed_native_entry_accepts_agreeing_recovery_occurrences(
    monkeypatch, _seam, copies,
):
    """Overlapping recovery rows must reach one final entry proof without losing paths."""
    graph, state, _route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    rows = tuple(
        StateWriteTransition(
            0, state, 20, False, None,
            via_block=None if index == 0 else 2,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "global_fold" if index == 0 else "partial_predecessor_partitioned",
                True,
            ),
        )
        for index in range(copies)
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: rows,
    )
    original_select = minimal_unflatten_emit_module.build_state_write_redirects
    selected_rows = []
    selected_options = []

    def observe_selection(flow_graph, dispatcher, transitions, **options):
        selected_rows.extend(row for row in transitions if row.write_block == 0)
        selected_options.append(options)
        return original_select(flow_graph, dispatcher, transitions, **options)

    monkeypatch.setattr(
        minimal_unflatten_emit_module, "build_state_write_redirects", observe_selection,
    )
    plan = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)

    assert plan.unflatten_proposal is not None
    assert sum(bool(getattr(claim, "route_proof_ids", ()))
               for claim in plan.unflatten_proposal.claims) == 2  # entry plus loop-back
    assert sum(isinstance(mod, RedirectGoto) and mod.from_serial == 0
               for mod in graph_modifications(plan)) == 1
    assert [row.via_block for row in selected_rows] == [None, *([2] * (copies - 1))]
    assert selected_options[0]["strict_pre_header_prologue"] is True
    assert rows[0].proof.kind == "global_fold"
    assert all(row.proof.kind == "partial_predecessor_partitioned" for row in rows[1:])


@pytest.mark.parametrize("field,value", (
    ("source_serial", 20),
    ("source_instruction_ea", 0x1002),
    ("state_constant", 0x12345678),
    ("target_serial", 99),
))
def test_typed_native_entry_rejects_conflicting_recovery_occurrence(
    monkeypatch, _seam, field, value,
):
    """An agreeing first occurrence cannot hide a later conflicting entry fact."""
    graph, state, _route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(0, state, 20, False, None),
        ),
    )
    original_attach = minimal_unflatten_emit_module._attach_dispatcher_map_route_facts

    def conflicting_occurrence(*args, **options):
        rows = original_attach(*args, **options)
        entry = next(row for row in rows if row.write_block == 0)
        assert entry.semantic_route_fact is not None
        changes = {field: value}
        if field == "source_serial":
            changes.update(path_serials=(0, 20), path_edges=((0, 20),))
        if field == "state_constant":
            changes["physical_state_write"] = None
        return (*rows, replace(entry, semantic_route_fact=replace(
            entry.semantic_route_fact, **changes,
        )))

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_attach_dispatcher_map_route_facts", conflicting_occurrence,
    )
    plan = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_typed_native_entry_is_not_blocked_by_an_unselected_untyped_transition(
    monkeypatch, _seam,
):
    """Only emitted route operations, not every recovered row, close entry authority."""

    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    original_attach = minimal_unflatten_emit_module._attach_dispatcher_map_route_facts

    def add_unselected_untyped_transition(*args, **inner_kwargs):
        transitions = original_attach(*args, **inner_kwargs)
        return (*transitions, StateWriteTransition(99, None, None, False, None))

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_attach_dispatcher_map_route_facts",
        add_unselected_untyped_transition,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "build_state_write_redirects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("entry authority reached redirect selection")
        ),
    )

    with pytest.raises(RuntimeError, match="entry authority reached redirect selection"):
        emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)


def _dispatcher_removal_intent_fixture(*, candidate: bool = False):
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor,
        DispatcherCorridorCoverage,
        RetiredDispatcherInfrastructure,
    )

    dispatcher = DispatcherBlockAnchor(2, 0x1200)
    return DispatcherCorridorCoverage(
        function_ea=0x1000,
        dispatcher=dispatcher,
        covered_corridors=(),
        residual_corridors=(),
        enumeration_complete=True,
        retirement_candidates=(RetiredDispatcherInfrastructure(
            role="comparison_dispatcher", anchor=dispatcher,
        ),) if candidate else (),
    )


def test_typed_emitter_ignores_reachable_source_retirement_candidates():
    """Source-derived candidate rows are not projected removal intent."""

    graph = FlowGraph(
        blocks={0: _b(0, (2,), ()), 2: _b(2, (), (0,))},
        entry_serial=0,
        func_ea=0x1000,
    )

    status = minimal_unflatten_emit_module._dispatcher_removal_intent(
        graph, _dispatcher_removal_intent_fixture(candidate=True), 2,
    )

    assert status.exists is False
    assert status.reason == "dispatcher_reachable"


@pytest.mark.parametrize(
    ("graph", "dispatcher_entry_serial", "reason"),
    (
        (
            FlowGraph(
                blocks={
                    0: _b(0, (1,), ()),
                    1: _b(1, (), (0,)),
                    2: _b(2, (), ()),
                },
                entry_serial=0,
                func_ea=0x1000,
            ),
            2,
            "dispatcher_unreachable",
        ),
        (
            FlowGraph(
                blocks={0: _b(0, (), ())}, entry_serial=0, func_ea=0x1000,
            ),
            2,
            "dispatcher_absent",
        ),
    ),
)
def test_typed_emitter_retains_unreachable_or_absent_dispatcher_forecast(
    graph, dispatcher_entry_serial, reason,
):
    status = minimal_unflatten_emit_module._dispatcher_removal_intent(
        graph, _dispatcher_removal_intent_fixture(), dispatcher_entry_serial,
    )

    assert status.exists is True
    assert status.reason == reason


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("cycle_break", "terminal_cycle"),
        ("detached_dead_handler_component", "detached_component"),
    ),
)
def test_typed_emitter_retains_terminal_or_detached_forecast(field, reason):
    graph = FlowGraph(
        blocks={0: _b(0, (2,), ()), 2: _b(2, (), (0,))},
        entry_serial=0,
        func_ea=0x1000,
    )
    forecast = replace(_dispatcher_removal_intent_fixture(), **{field: object()})

    status = minimal_unflatten_emit_module._dispatcher_removal_intent(
        graph, forecast, 2,
    )

    assert status.exists is True
    assert status.reason == reason


def test_typed_emitter_rejects_malformed_projected_traversal():
    graph = FlowGraph(
        blocks={0: _b(0, (99,), ())}, entry_serial=0, func_ea=0x1000,
    )

    with pytest.raises(ValueError, match="successor"):
        minimal_unflatten_emit_module._dispatcher_removal_intent(
            graph, _dispatcher_removal_intent_fixture(), 2,
        )


def test_typed_emitter_abstains_when_projected_traversal_is_unresolvable(
    monkeypatch, _seam,
):
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_dispatcher_removal_intent",
        lambda *_args: (_ for _ in ()).throw(ValueError("projected traversal failed")),
    )

    plan = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)

    assert plan.unflatten_proposal is None


def test_supplied_canonical_entry_evidence_is_consumed_without_remint(monkeypatch, _seam):
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence

    supplied = emit_minimal_unflatten(
        graph, native_key=None, canonical_route_evidence=evidence, **kwargs,
    )

    assert supplied.unflatten_proposal is not None
    assert supplied.unflatten_proposal.route_evidence is evidence
    assert tuple(proof.proof_id for proof in supplied.unflatten_proposal.route_evidence.route_proofs) == tuple(
        proof.proof_id for proof in evidence.route_proofs
    )
    assert len(supplied.unflatten_proposal.route_evidence.route_proofs) == len(evidence.route_proofs)
    assert supplied.unflatten_proposal.route_evidence.generation == evidence.generation


def test_supplied_canonical_evidence_mints_exact_current_native_entry_proof(
    monkeypatch, _seam,
):
    """A rebound native entry receipt extends incomplete supplied evidence once."""
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence
    non_entry_proof = next(
        proof for proof in evidence.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x2000
    )
    missing_entry_evidence = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, evidence.generation, (non_entry_proof,),
    )

    plan = emit_minimal_unflatten(
        graph,
        native_key=None,
        canonical_route_evidence=missing_entry_evidence,
        **kwargs,
    )

    assert plan.unflatten_proposal is not None
    augmented = plan.unflatten_proposal.route_evidence
    assert augmented.native_key == missing_entry_evidence.native_key
    assert augmented.generation == missing_entry_evidence.generation
    proof_eas = {
        proof.state_write.instruction_ea
        for proof in augmented.route_proofs
        if proof.state_write is not None
    }
    assert proof_eas == {0x1001, 0x2000}
    reminted_prior = next(
        proof for proof in augmented.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x2000
    )
    supplied_prior = missing_entry_evidence.route_proofs[0]
    stable_fields = tuple(
        field.name for field in fields(supplied_prior)
        if field.name not in {"proof_id", "atomic_group_id"}
    )
    assert tuple(getattr(reminted_prior, field) for field in stable_fields) == tuple(
        getattr(supplied_prior, field) for field in stable_fields
    )
    assert reminted_prior.proof_id != supplied_prior.proof_id
    assert reminted_prior.atomic_group_id != supplied_prior.atomic_group_id
    assert canonical_semantic_evidence_from_proofs(
        missing_entry_evidence.native_key,
        missing_entry_evidence.generation,
        missing_entry_evidence.route_proofs,
    ) == missing_entry_evidence
    assert canonical_semantic_evidence_from_proofs(
        augmented.native_key,
        augmented.generation,
        augmented.route_proofs,
    ) == augmented


def test_local_authority_mints_unique_native_entry_without_scalar_consensus(
    monkeypatch, _seam,
):
    """One source-keyed operation can rebind one native entry receipt."""
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    forecast_inputs = []
    original_forecast = minimal_unflatten_emit_module.ConcreteEntryRouteForecast

    def capture_forecast(*args, **forecast_kwargs):
        forecast_inputs.append(forecast_kwargs)
        return original_forecast(*args, **forecast_kwargs)

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "ConcreteEntryRouteForecast",
        capture_forecast,
    )

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_resolve_entry_state_route_resolution",
        lambda *_args, **_kwargs: pytest.fail("scalar consensus must not run"),
    )

    plan = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)

    assert plan.unflatten_proposal is not None
    assert {
        proof.state_write.instruction_ea
        for proof in plan.unflatten_proposal.route_evidence.route_proofs
        if proof.state_write is not None
    } == {0x1001, 0x2000}
    assert [inputs["source_kinds"] for inputs in forecast_inputs] == [
        (minimal_unflatten_emit_module.NATIVE_BOUND_ENTRY_ROUTE_SOURCE_KIND,)
    ]


def test_local_authority_abstains_on_ambiguous_native_entry_correlation(
    monkeypatch, _seam,
):
    """Two receipts for one source-keyed redirect never choose an owner."""
    graph, _state, entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )

    plan = emit_minimal_unflatten(
        graph,
        native_key=NATIVE_KEY,
        native_bound_transition_routes=(
            entry_route,
            replace(entry_route, fact_id="ambiguous-entry"),
            *kwargs["native_bound_transition_routes"][1:],
        ),
        **{key: value for key, value in kwargs.items() if key != "native_bound_transition_routes"},
    )

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_local_authority_abstains_on_unmatched_native_entry_redirect(
    monkeypatch, _seam,
):
    """A source-keyed redirect cannot borrow an unrelated route receipt."""
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "build_native_bound_state_entry_bridges",
        lambda *_args, **_kwargs: [RedirectGoto(0, 2, 99)],
    )

    plan = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_local_authority_requires_scalar_consensus_when_initial_state_exists(
    monkeypatch, _seam,
):
    """A missing scalar consensus cannot fall back to operation correlation."""
    graph, state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: state,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_resolve_entry_state_route_resolution",
        lambda *_args, **_kwargs: minimal_unflatten_emit_module._EntryStateRouteResolution(
            None,
        ),
    )

    plan = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_local_authority_accepts_native_entry_receipt_at_default_target(
    monkeypatch, _seam,
):
    """A rebound native entry receipt is exact even when its target is default."""
    graph, state, entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    forecast_inputs = []
    original_forecast = minimal_unflatten_emit_module.ConcreteEntryRouteForecast

    def capture_forecast(*args, **forecast_kwargs):
        forecast_inputs.append(forecast_kwargs)
        return original_forecast(*args, **forecast_kwargs)

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "ConcreteEntryRouteForecast",
        capture_forecast,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: state,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0, 0x100000000, 20),),
        default_target=20,
    )

    plan = emit_minimal_unflatten(
        graph,
        native_key=NATIVE_KEY,
        dispatcher=dispatcher,
        **{key: value for key, value in kwargs.items() if key != "dispatcher"},
    )

    assert plan.unflatten_proposal is not None
    assert len(forecast_inputs) == 1
    forecast = forecast_inputs[0]
    assert forecast["physical_fact_id"] == entry_route.fact_id
    assert forecast["source_kinds"] == (
        minimal_unflatten_emit_module.NATIVE_BOUND_ENTRY_ROUTE_SOURCE_KIND,
    )
    assert forecast["source_anchor_ea"] == entry_route.source_instruction_ea
    assert forecast["target_handler"] == entry_route.target_handler_serial
    assert forecast["canonical_proof_id"] in {
        proof.proof_id for proof in plan.unflatten_proposal.route_evidence.route_proofs
    }


def test_supplied_canonical_evidence_abstains_on_refined_entry_write_collision(
    monkeypatch, _seam,
):
    """A different stable range cannot reopen an occupied native write EA."""
    graph, _state, entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence
    entry_proof = next(
        proof for proof in evidence.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x1001
    )
    refined_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1001, 0x1002),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1001,),
    )
    refined_entry_proof = replace(
        entry_proof,
        state_write=replace(entry_proof.state_write, identity=refined_identity),
    )
    supplied = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY,
        evidence.generation,
        (refined_entry_proof,),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        native_key=NATIVE_KEY,
        generation=supplied.generation,
        atomic_group_id="refined-entry-collision",
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        blocks=tuple(graph.blocks.values()),
        identities_by_serial=tuple(
            (int(serial), ref.identity)
            for serial, ref in kwargs["block_refs_by_serial"].items()
        ),
        entry_serial=graph.entry_serial,
    )

    assert minimal_unflatten_emit_module._augment_supplied_canonical_evidence_with_native_entry_fact(
        supplied,
        _native_bound_route_fact(graph, entry_route),
        context,
    ) is None

    plan = emit_minimal_unflatten(
        graph, native_key=None, canonical_route_evidence=supplied, **kwargs,
    )

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_supplied_canonical_evidence_abstains_on_divergent_entry_write_route(
    monkeypatch, _seam,
):
    """One native write EA cannot support a second state/target claim."""
    graph, _state, entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    entry_proof = next(
        proof for proof in produced.unflatten_proposal.route_evidence.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x1001
    )
    divergent_state = 0x0BADF00D
    original_write = entry_proof.state_write.physical_state_write
    assert original_write is not None
    assert original_write.source_instruction.l is not None
    divergent_write = replace(
        original_write,
        source_instruction=replace(
            original_write.source_instruction,
            l=replace(original_write.source_instruction.l, value=divergent_state),
        ),
        state_constant=divergent_state,
    )
    divergent = replace(
        entry_proof,
        state_write=replace(
            entry_proof.state_write,
            state_constant=divergent_state,
            physical_state_write=divergent_write,
        ),
        destinations=(replace(
            entry_proof.destinations[0],
            state_constant=divergent_state,
            target_identity=kwargs["block_refs_by_serial"][99].identity,
            target_anchor_ea=graph.get_block(99).start_ea,
        ),),
    )
    supplied = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY,
        produced.unflatten_proposal.route_evidence.generation,
        (divergent,),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        native_key=NATIVE_KEY,
        generation=supplied.generation,
        atomic_group_id="divergent-entry-collision",
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        blocks=tuple(graph.blocks.values()),
        identities_by_serial=tuple(
            (int(serial), ref.identity)
            for serial, ref in kwargs["block_refs_by_serial"].items()
        ),
        entry_serial=graph.entry_serial,
    )

    assert minimal_unflatten_emit_module._augment_supplied_canonical_evidence_with_native_entry_fact(
        supplied,
        _native_bound_route_fact(graph, entry_route),
        context,
    ) is None


def test_supplied_canonical_evidence_abstains_on_generation_mismatch(
    monkeypatch, _seam,
):
    """The source receipt cannot cross into another canonical generation."""
    graph, _state, entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence
    non_entry_proof = next(
        proof for proof in evidence.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x2000
    )
    supplied = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, evidence.generation, (non_entry_proof,),
    )
    wrong_generation_context = CanonicalSemanticEvidenceProductionContext(
        native_key=NATIVE_KEY,
        generation=supplied.generation + 1,
        atomic_group_id="generation-mismatch",
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        blocks=tuple(graph.blocks.values()),
        identities_by_serial=tuple(
            (int(serial), ref.identity)
            for serial, ref in kwargs["block_refs_by_serial"].items()
        ),
        entry_serial=graph.entry_serial,
    )

    assert minimal_unflatten_emit_module._augment_supplied_canonical_evidence_with_native_entry_fact(
        supplied,
        _native_bound_route_fact(graph, entry_route),
        wrong_generation_context,
    ) is None


def test_emitter_abstains_before_native_entry_augmentation_on_source_generation_drift(
    monkeypatch, _seam,
):
    """A caller cannot join a current native receipt to another source generation."""
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence
    non_entry_proof = next(
        proof for proof in evidence.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x2000
    )
    supplied = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, evidence.generation, (non_entry_proof,),
    )

    plan = emit_minimal_unflatten(
        graph,
        native_key=None,
        canonical_route_evidence=supplied,
        source_generation=supplied.generation + 1,
        **kwargs,
    )

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_emitter_abstains_before_native_entry_augmentation_on_block_key_drift(
    monkeypatch, _seam,
):
    """A foreign block-reference namespace cannot mint an entry proof."""
    graph, _state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence
    non_entry_proof = next(
        proof for proof in evidence.route_proofs
        if proof.state_write is not None and proof.state_write.instruction_ea == 0x2000
    )
    supplied = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, evidence.generation, (non_entry_proof,),
    )
    foreign_key = make_native_key(input_identity="sha256:foreign-entry-identity")
    foreign_refs = {
        serial: NativeBlockRef(StableBlockIdentity.from_intervals(
            ref.identity.native_ranges.intervals,
            native_key=foreign_key,
            exact_instruction_eas=ref.identity.exact_instruction_eas,
        ))
        for serial, ref in kwargs["block_refs_by_serial"].items()
    }

    plan = emit_minimal_unflatten(
        graph,
        native_key=None,
        canonical_route_evidence=supplied,
        block_refs_by_serial=foreign_refs,
        **{key: value for key, value in kwargs.items() if key != "block_refs_by_serial"},
    )

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None


def test_non_prefix_transition_competing_for_entry_proof_rejects_atomically(
    monkeypatch, caplog, _seam,
):
    graph, state, _entry_route, kwargs = _typed_entry_native_route_fixture(monkeypatch)
    produced = emit_minimal_unflatten(graph, native_key=NATIVE_KEY, **kwargs)
    evidence = produced.unflatten_proposal.route_evidence
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(20, state, 20, False, None, via_block=0),
        ),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: state,
    )

    plan = emit_minimal_unflatten(
        graph,
        native_key=None,
        canonical_route_evidence=evidence,
        initial_state=state,
        **kwargs,
    )

    assert graph_modifications(plan) == []
    assert plan.unflatten_proposal is None
    assert any(
        "concrete entry proof is already owned" in record.getMessage()
        for record in caplog.records
    )


def test_native_bound_routes_seed_missing_current_backedge_transition(
    monkeypatch,
) -> None:
    """Current native bindings can seed a direct router backedge when recovery is empty."""
    entry_state = 0x16AA65E9
    backedge_state = 0x079323F9
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 20), (1, 11)),
            10: _b(10, (11,), (2,)),
            11: _b(11, (2,), (10,)),
            20: _b(20, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({entry_state: 10, backedge_state: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=entry_state,
        native_bound_transition_routes=(
            _native_bound_route(
                source=1,
                state=entry_state,
                target=10,
                fact_id="entry",
            ),
            _native_bound_route(
                source=11,
                state=backedge_state,
                target=20,
                fact_id="backedge",
                resolver_kind="interval_dispatcher_row",
                row_kind="interval_range",
            ),
        ),
        authoritative_handler_serials=frozenset({10, 20}),
        dispatcher_region_serials=frozenset({2}),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert gotos >= {(1, 2, 10), (11, 2, 20)}
    _assert_no_legacy_plan_metadata(plan)


def test_native_bound_route_receipt_is_absent_after_use_def_veto(
    monkeypatch,
):
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(10, None, None, True, None),
        ),
    )
    monkeypatch.setenv("D810_USE_DEF_VETO", "1")

    class _UseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (SimpleNamespace(var_stkoff=_CARRIER_OFF),)

    route = _native_bound_route(
        source=10,
        state=0x20,
        target=20,
        fact_id="transition:veto",
    )
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        native_bound_transition_routes=(route,),
        use_def_safety=_UseDefSafety(),
        live_function=object(),
    )

    assert graph_modifications(plan) == []
    _assert_no_legacy_plan_metadata(plan)


def test_materialized_state_route_rebinds_to_exact_imported_handler_owner() -> None:
    """Handler-exit replay follows the exact PREOPT handler replacement."""
    native_write_ea = 0x40E207
    native_source = 10
    imported_source = 30
    cleanup_handler = 40
    owner_state = 0xD919DEB2
    selected_state = 0x85AE90D3
    fg = FlowGraph(
        blocks={
            0: _b(0, (), ()),
            native_source: _b(
                native_source,
                (20, 21),
                (),
                (_mov_state(native_write_ea, selected_state),),
            ),
            imported_source: _b(
                imported_source,
                (20, 21),
                (),
                (_mov_state(0xF1C01448, selected_state),),
            ),
            20: _b(20, (), (native_source, imported_source)),
            21: _b(21, (), (native_source, imported_source)),
            cleanup_handler: _b(cleanup_handler, (), ()),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    route = MaterializedStateRoute(
        source_block_serial=native_source,
        state_constant=selected_state,
        target_handler_serial=cleanup_handler,
        source_handler_serial=native_source,
        handler_exit_proven=True,
        proof_kind="handler_replay",
    )

    assert _rebind_materialized_state_route_sources(
        fg,
        (route,),
        legacy_handler_by_state={owner_state: native_source},
        materialized_handler_by_state={owner_state: imported_source},
        imported_native_eas_by_serial={
            imported_source: frozenset({native_write_ea}),
        },
    ) == (
        replace(
            route,
            source_block_serial=imported_source,
            source_handler_serial=imported_source,
        ),
    )


def test_resolver_proof_routes_unmatched_folded_state_to_live_handler(_seam) -> None:
    # The state value is not an equality-router key, so legacy recovery marks
    # this concrete back-edge terminal. A materialized-transfer record may
    # correct only that miss when its anchor is present in the transition source.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    # `IntervalDispatcher` represents an equality-router miss as its default
    # target. This is the production false-terminal shape, not a `None` route.
    unresolved = StateWriteTransition(10, 0xDEAD, 99, True, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),  # block 20's snapshot start EA
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (unresolved,), fg, disp, (transfer,)
    )

    assert resolved.target_handler == 20
    assert resolved.is_return is False
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_target"


def test_resolver_proof_never_overrides_exact_dispatcher_route(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x10),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    exact = StateWriteTransition(10, 0x10, 10, False, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),
    )

    assert resolve_materialized_indirect_transfer_targets(
        (exact,), fg, disp, (transfer,)
    ) == (exact,)


def test_emitter_uses_materialized_transfer_only_for_default_router_miss(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),
    )

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_indirect_transfers=(transfer,),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 20) in gotos


def test_emitter_rejects_unbound_materialized_route_for_default_router_miss(
    _seam,
) -> None:
    state = 0xA5A94B86
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, state),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_state_routes=(MaterializedStateRoute(10, state, 20),),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    # A materialized route without a bound source receipt is not final
    # transaction authority merely because it disagrees with the default arm.
    assert gotos == set()


def test_emitter_reports_reachable_dispatcher_corridors_as_partial_not_complete(
    _seam,
    monkeypatch,
) -> None:
    """`unresolved=0` cannot hide a still-reachable dispatcher feeder."""
    from d810.transforms import minimal_unflatten_emit as emit_module

    class _LogCapture:
        info_on = True

        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[object, ...]]] = []

        def info(self, message: str, *args: object) -> None:
            self.calls.append((message, args))

    log_capture = _LogCapture()
    monkeypatch.setattr(emit_module, "logger", log_capture)
    fg = FlowGraph(
        blocks={
            0: replace(_b(0, (2,), ()), start_ea=0x7FF859C06F60),
            2: replace(_b(2, (10, 20), (0, 10)), start_ea=0x7FF859C070C4),
            # No foldable state write: this is intentionally a residual
            # dispatcher feeder, not an unsafe forced redirect.
            10: replace(_b(10, (2,), (2,)), start_ea=0x7FF859C08D35),
            20: replace(_b(20, (), (2,)), start_ea=0x7FF859C08B37),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
    )

    _assert_no_legacy_plan_metadata(plan)
    assert not any(
        message.startswith("unflat dispatcher corridor coverage:")
        for message, _args in log_capture.calls
    ), log_capture.calls
    assert not any(" unresolved=%d " in message for message, _args in log_capture.calls)


def test_emitter_proof_uses_caller_authoritative_handlers_not_dispatcher_rows(
    _seam,
) -> None:
    """A materialized caller-only handler cannot disappear behind row fallback."""

    class _CleanUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return ()

    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            # The portable CFG includes imported handler blk30, but this
            # interval adapter intentionally has no row that names it.
            2: _b(2, (10, 20, 30), (0, 10, 20, 30)),
            10: _b(10, (2,), (2,), (_mov_state(0x1280, 0x20),)),
            20: _b(20, (2,), (2,), (_mov_state(0x1500, 0x10),)),
            30: _b(30, (2,), (2,), (_mov_state(0x1780, 0x10),)),
            99: _exit_block(99, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20, 30}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    _assert_no_legacy_plan_metadata(plan)
    assert len(graph_modifications(plan)) == 4


def _complete_two_handler_dispatcher_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x1280, 0x20),)),
            20: _b(20, (2,), (2,), (_mov_state(0x1500, 0x10),)),
            99: _exit_block(99, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_emitter_narrow_proof_requires_executed_whole_fragment_use_def_check(
    _seam,
) -> None:
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
    )

    _assert_no_legacy_plan_metadata(plan)


def test_emitter_narrow_proof_abstains_when_use_def_capability_raises(
    _seam,
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)

    class _FailingUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            raise LookupError("live use-def authority unavailable")

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_FailingUseDefSafety(),
        live_function=object(),
    )

    _assert_no_legacy_plan_metadata(plan)
    assert len(graph_modifications(plan)) == 3


def test_partial_use_def_audit_retains_fragment_and_reports_unavailable_safety(
    _seam,
    monkeypatch,
) -> None:
    """A partial enforced audit is not an authoritative fragment rejection."""
    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)

    class _PartialUseDefSafety:
        def __init__(self) -> None:
            self.calls = 0

        def redirect_use_def_violations(
            self, *_args: object
        ) -> tuple[object, ...]:
            if self.calls == 0:
                self.calls += 1
                return (SimpleNamespace(var_stkoff=_CARRIER_OFF),)
            self.calls += 1
            raise LookupError("live use-def authority unavailable")

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_PartialUseDefSafety(),
        live_function=object(),
    )

    assert len(graph_modifications(plan)) == 3
    _assert_no_legacy_plan_metadata(plan)


def test_emitter_keeps_siblings_for_advisory_use_def_severance(
    _seam,
    monkeypatch,
) -> None:
    """Default heuristic findings are evidence, not a redirect filter."""
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    monkeypatch.delenv("D810_S1A_SEVERANCE_BAIL", raising=False)

    class _SeveringUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (SimpleNamespace(var_stkoff=_CARRIER_OFF),)

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_SeveringUseDefSafety(),
        live_function=object(),
    )

    assert len(graph_modifications(plan)) == 3
    _assert_no_legacy_plan_metadata(plan)


def test_confirmed_use_def_severance_rejects_partial_fragment_atomically() -> None:
    """Partial dispatcher coverage never weakens the hard fragment veto."""
    from d810.transforms import minimal_unflatten_emit as emit_module

    audit = SimpleNamespace(executed=True, severance_count=1, enforced=False)

    assert not emit_module._must_reject_fragment_for_use_def_audit(audit)
    assert emit_module._must_reject_fragment_for_use_def_audit(
        audit, legacy_bail=True
    )
    audit.enforced = True
    assert emit_module._must_reject_fragment_for_use_def_audit(audit)


def test_emitter_narrow_proof_accepts_clean_executed_use_def_check(_seam) -> None:
    class _CleanUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return ()

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    _assert_no_legacy_plan_metadata(plan)


def test_emitter_scans_imported_materialized_handler_root(_seam) -> None:
    state_reg = 99
    imported_state = 0x20
    next_state = 0x30
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 40), (0, 10, 40)),
            10: _b(10, (2,), (2,), (_mov_reg(0x1100, 0x10, state_reg),)),
            30: _b(30, (31,), (), (_mov_reg(0x1300, next_state, state_reg),)),
            31: _b(31, (), (30,)),
            40: _b(40, (2,), (2,), (_mov_reg(0x1400, 0x10, state_reg),)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, next_state: 40}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_computed_goto_profile=True,
        materialized_state_routes=(
            MaterializedStateRoute(98, imported_state, 30),
            MaterializedStateRoute(
                30,
                next_state,
                40,
                source_handler_serial=30,
                handler_exit_proven=True,
            ),
        ),
    )

    assert RedirectGoto(
        from_serial=30,
        old_target=31,
        new_target=40,
    ) in graph_modifications(plan)


def test_emitter_abstains_atomically_on_incomplete_materialized_handler_map(
    monkeypatch,
) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    def fail_if_recovery_runs(*_args, **_kwargs):
        raise AssertionError("incomplete exact map must abstain before recovery")

    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        fail_if_recovery_runs,
    )
    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=99),
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_computed_goto_profile=True,
        missing_materialized_handler_targets=((0x20, 0x402000),),
    )

    assert graph_modifications(plan) == []


@pytest.mark.parametrize(
    (
        "materialized_profile",
        "has_imported_boundary_evidence",
        "state_var_reg",
        "expected_region",
    ),
    (
        (False, False, None, frozenset()),
        (False, True, None, frozenset()),
        (True, False, None, frozenset()),
        (True, True, None, frozenset({2, 3})),
        (True, False, 20, frozenset({2, 3})),
    ),
)
def test_dispatcher_predecessor_filter_requires_imported_boundary_evidence(
    _seam,
    monkeypatch,
    materialized_profile,
    has_imported_boundary_evidence,
    state_var_reg,
    expected_region,
) -> None:
    """Ordinary stack dispatchers retain semantic guard predecessors.

    A comparison block can also be the terminal stack-alias guard that owns a
    handler's source edge.  The strict router-region exclusion is justified
    only when the materialized computed-goto BST has applied PREOPT boundary
    evidence; the legacy CALLS path must retain its semantic predecessors.
    """
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (3, 10), (0, 3)),
            3: _b(3, (2,), (2,)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    captured: list[frozenset[int]] = []
    from d810.transforms import minimal_unflatten_emit as emit_module

    def _capture_region(*_args, **kwargs):
        captured.append(kwargs["dispatcher_region_serials"])
        return ()

    monkeypatch.setattr(
        emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        _capture_region,
    )
    imported_direct_boundary_evidence = ()
    if has_imported_boundary_evidence:
        imported_direct_boundary_evidence = (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=DetachedSnippetDirectBoundaryPort(
                    source_block_ea=0xDEAD,
                    source_instruction_ea=0xDEAD,
                    endpoint_block_ea=0xDEAD,
                    old_successor_eas=(),
                    target_ea=0xBEEF,
                    state_register=20,
                    state_constant=0x10,
                    source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    delivery_mode="terminal_goto",
                    resolver_kind="static_fixpoint",
                ),
                endpoint_anchor_eas=(),
                target_anchor_eas=(),
            ),
        )

    emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=99),
        state_var_stkoff=_STATE if state_var_reg is None else None,
        state_var_reg=state_var_reg,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        dispatcher_region_serials=frozenset({2, 3}),
        materialized_computed_goto_profile=materialized_profile,
        imported_direct_boundary_evidence=imported_direct_boundary_evidence,
    )

    assert captured == [expected_region]


def test_emitter_routes_materialized_midtree_entry_to_known_handler(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _b(20, (30, 99), ()),
            30: _b(30, (), (20,)),
            99: _b(99, (), (20,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0xDEAD: 30}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),
    )
    dag = DecisionDag(
        32,
        {20: RouteComparison(20, "jz", 0xDEAD, 30, 99)},
        root=20,
    )

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_indirect_transfers=(transfer,),
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            fg, dag, frozenset({30}), dispatcher=disp,
            block_refs=_entry_dispatcher_map_test_refs(fg),
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(fg),
        source_generation=0,
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 30) in gotos


def test_current_snapshot_route_rejects_nested_dispatcher_router(
    _seam, monkeypatch
) -> None:
    """A guard-chain resolver must not classify an inner router as a handler."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10,), (1, 10)),
            3: _b(3, (30, 40), (20,)),  # nested switch/router, not a handler
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _eq_block(20, 0xDEAD, 3, 99),
            30: _b(30, (), (3,)),
            40: _b(40, (), (3,)),
            99: _b(99, (), (20,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dag = DecisionDag(
        32,
        {20: RouteComparison(20, "jz", 0xDEAD, 3, 99)},
        root=20,
    )
    captured_routes: list[int | None] = []

    def _capture_route(*_args, **kwargs):
        resolver = kwargs["state_route_resolver"]
        captured_routes.append(resolver(0xDEAD) if resolver is not None else None)
        return ()

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        _capture_route,
    )

    emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            fg, dag, frozenset({30, 40}), dispatcher=_disp({0x10: 10}, exit_block=99),
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(fg),
        dispatcher_region_serials=frozenset({2, 20}),
    )

    assert captured_routes == [None]


def test_interval_backed_handler_leaf_authority_admits_only_validated_non_state_leaf(
    _seam,
) -> None:
    """A normalized interval row may authorize its exact non-state DAG leaf."""
    state = StorageIdentity(StorageIdentityKind.STACK, _STATE)
    graph = FlowGraph(
        blocks={
            1: _eq_block(1, 7, 3, 2),
            2: _b(
                2,
                (4, 5),
                (1,),
                (InsnSnapshot(
                    opcode=100,
                    ea=0x1080,
                    operands=(),
                    l=MopSnapshot(
                        t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER,
                    ),
                    r=MopSnapshot(
                        t=_T_NUM, size=4, value=1, kind=OperandKind.NUMBER,
                    ),
                    d=MopSnapshot(
                        t=0, size=0, block_ref=4, kind=OperandKind.BLOCK,
                    ),
                    kind=InsnKind.COND_JUMP,
                    branch_predicate=PredicateKind.EQ,
                    is_conditional_jump=True,
                ),),
            ),
            3: _b(3, (), (1,)),
            4: _b(4, (), (2,)),
            5: _b(5, (), (2,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    dispatcher = IntervalDispatcher(
        [IntervalRow(0, 7, 2), IntervalRow(7, 8, 3)],
        compute_default=False,
    )
    dag = DecisionDag(32, {1: RouteComparison(1, "jz", 7, 3, 2)}, root=1)
    refs = _entry_dispatcher_map_test_refs(graph)

    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        dispatcher,
        exact_handler_serials=frozenset({3}),
        block_refs_by_serial=refs,
        source_generation=7,
    )

    assert catalogue is not None
    assert tuple(item.serial for item in catalogue.bindings) == (2, 3)
    assert minimal_state_recovery_module.build_current_u32_decision_forest(
        graph,
        1,
        expected_identities=frozenset({state}),
        reference_dag=dag,
        permitted_non_state_handler_leaf_catalog=catalogue,
        block_refs_by_serial=refs,
        source_generation=7,
    ) is not None

    def _replay(**overrides):
        return minimal_state_recovery_module.build_current_u32_decision_forest(
            overrides.pop("graph", graph),
            1,
            expected_identities=frozenset({state}),
            reference_dag=dag,
            permitted_non_state_handler_leaf_catalog=overrides.pop("catalogue", catalogue),
            block_refs_by_serial=overrides.pop("refs", refs),
            source_generation=overrides.pop("generation", 7),
            **overrides,
        )

    # The replay authority is bound to the exact source generation, graph
    # topology, native identities, and normalized interval rows.  None of
    # these drifts can manufacture a semantic leaf permission.
    assert _replay(generation=8) is None
    assert _replay(catalogue=replace(
        catalogue,
        bindings=(
            replace(catalogue.bindings[0], interval_rows=((0, 6),)),
            *catalogue.bindings[1:],
        ),
    )) is None
    assert _replay(refs={**refs, 2: refs[3]}) is None
    assert _replay(graph=FlowGraph(
        {**graph.blocks, 4: replace(graph.blocks[4], start_ea=0x10A0)},
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )) is None
    assert _replay(catalogue=replace(
        catalogue,
        bindings=(replace(catalogue.bindings[0], serial=99), *catalogue.bindings[1:]),
    )) is None


@pytest.mark.parametrize("mode", ("absent", "fabricated", "stateful"))
def test_interval_backed_handler_leaf_authority_rejects_unproven_or_stateful_targets(
    _seam,
    mode: str,
) -> None:
    """Interval leaves still require normalized provenance and semantic-leaf shape."""
    state = StorageIdentity(StorageIdentityKind.STACK, _STATE)
    leaf = (
        _eq_block(2, 9, 4, 5, preds=(1,))
        if mode == "stateful"
        else _b(2, (), (1,))
    )
    graph = FlowGraph(
        {1: _eq_block(1, 7, 3, 2), 2: leaf, 3: _b(3, (), (1,)),
         4: _b(4, (), (2,)), 5: _b(5, (), (2,))},
        entry_serial=1,
        func_ea=0x1000,
    )
    dispatcher: object = (
        IntervalDispatcher([IntervalRow(0, 8, 9)], compute_default=False)
        if mode == "absent"
        else _DualRouteDispatcher(
            exact_targets={7: 3},
            interval_rows=(IntervalRow(0, 7, 2), IntervalRow(7, 8, 3)),
        )
        if mode == "fabricated"
        else IntervalDispatcher(
            [IntervalRow(0, 7, 2), IntervalRow(7, 8, 3)],
            compute_default=False,
        )
    )
    refs = _entry_dispatcher_map_test_refs(graph)
    catalogue = minimal_unflatten_emit_module._normalized_condition_chain_handler_leaves(
        graph,
        dispatcher,
        exact_handler_serials=frozenset({3}),
        block_refs_by_serial=refs,
        source_generation=7,
    )

    if mode != "stateful":
        assert catalogue is None
        return
    assert catalogue is not None
    dag = DecisionDag(32, {1: RouteComparison(1, "jz", 7, 3, 2)}, root=1)
    assert minimal_state_recovery_module.build_current_u32_decision_forest(
        graph,
        1,
        expected_identities=frozenset({state}),
        reference_dag=dag,
        permitted_non_state_handler_leaf_catalog=catalogue,
        block_refs_by_serial=refs,
        dispatcher=dispatcher,
        source_generation=7,
    ) is None


def test_strict_preheader_prologue_keeps_ring_back_edge_redirectable(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1, 3), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 20), (1, 10)),
            3: _b(3, (10,), (0,)),
            10: _b(10, (2,), (2, 3), (_mov_state(0x1000, 0x20),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = (StateWriteTransition(10, 0x20, 20, False, None),)

    loose = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
    )
    loose_gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in loose
        if isinstance(m, RedirectGoto)
    }
    assert (10, 2, 20) not in loose_gotos

    strict = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        strict_pre_header_prologue=True,
    )
    strict_gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in strict
        if isinstance(m, RedirectGoto)
    }
    assert (10, 2, 20) in strict_gotos


def test_entry_bridge_shortcuts_pure_state_only_witness_exit_path(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_state_ne_tail(0x1000, 0x10),)),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5, 6), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (7,), (4,)),
            6: _b(6, (7,), (4,)),
            7: _exit_block(7, (5, 6)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=7)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) in gotos


def test_entry_bridge_preserves_witness_exit_path_with_live_stack_def(_seam) -> None:
    non_state = 0x88
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_stack_const(0x1000, non_state), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,)),
            8: _b(8, (9,), (5,), (_mov_reg_from_stack(0x1080, 1, non_state),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) not in gotos


def test_entry_bridge_shortcuts_skipped_dead_non_state_def(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_reg_const(0x1000, 2), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,), (_mov_reg_const(0x1050, 2),)),
            8: _b(8, (9,), (5,), (_call_reg(0x1080, 2),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) in gotos


def test_entry_bridge_shortcuts_dispatcher_local_non_state_temp(_seam) -> None:
    temp_stack = 0x88
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_reg_const(0x1000, 2), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,)),
            4: _b(
                4,
                (5, 6),
                (2, 3),
                (
                    _mov_stack_from_reg(0x1010, temp_stack, 2),
                    _state_ne_tail(0x1014, 0x10),
                ),
            ),
            5: _b(5, (7,), (4,)),
            6: _b(6, (7,), (4,)),
            7: _exit_block(7, (5, 6)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=7)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) in gotos


def test_entry_bridge_preserves_witness_exit_path_with_live_call_target_reg(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_reg_const(0x1000, 0), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,), (_mov_reg_const(0x1008, 0, value=0x5555),)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,)),
            8: _b(8, (9,), (5,), (_call_reg(0x1080, 0),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) not in gotos


def test_recovers_initial_state_from_prologue(_seam) -> None:
    # prologue blk0 -> blk1(writes initial 0x10) -> dispatcher blk2.  The prologue
    # is a dispatcher predecessor too, so its folded state IS the initial state --
    # recovered without any caller-supplied initial_state / condition-chain evidence.
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),  # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),  # prologue writes 0x10
            2: _b(2, (10, 20), (1, 10, 20)),  # dispatcher
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # handler writes 0x20
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    assert _recover_initial_state(fg, transitions, 2, None) == 0x10


def test_recovers_register_initial_state_across_entry_only_glue(_seam) -> None:
    state_reg = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            # The dispatcher predecessor is shared with a handler back-edge.
            # Only blk1@0x1040 is reachable before crossing the dispatcher.
            2: _b(2, (3,), (1, 10)),
            3: _b(3, (10,), (2,)),
            10: _b(10, (2,), (3,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert (
        _recover_initial_state(
            fg,
            (),
            3,
            None,
            state_var_reg=state_reg,
        )
        == 0x10
    )


def test_emit_prefers_entry_reaching_initial_state_over_range_hint(_seam) -> None:
    state_reg = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            2: _b(2, (3,), (1, 10, 20)),
            3: _b(3, (10, 20), (2,)),
            10: _b(10, (2,), (3,), (_mov_reg(0x1400, 0x20, state_reg),)),
            20: _b(20, (2,), (3,), (_mov_reg(0x1500, 0x10, state_reg),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, 0x20: 20}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=3,
        initial_state=0x20,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in graph_modifications(plan)
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (2, 3, 10) in edges
    assert (2, 3, 20) not in edges


def test_emit_bails_when_no_entry_bridge(_seam) -> None:
    # The prologue blk1 writes NO state, so the initial state is unrecoverable and
    # the entry can't be bridged.  Removing the dispatcher would orphan every
    # handler, so emit must BAIL (empty plan) and leave the function intact rather
    # than gut it (the OLLVM current-state-shadow failure mode).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),  # NO state write
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # resolvable handler
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2
    )
    assert len(graph_modifications(plan)) == 0


def test_resolves_state_var_alias_through_header_copy(_seam) -> None:
    # Dispatcher header copies the COMPARED slot (_STATE) FROM the next-state slot
    # (0x40): handlers write 0x40, the header does ``_STATE = 0x40`` then routes on
    # _STATE.  At a back-edge _STATE is still stale, so the fold must read 0x40 --
    # _resolve_state_var_alias follows the header copy (OLLVM -fla shadow).
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(
                2, (10,), (0, 10), (_mov_stk(0x2000, 0x40, _STATE),)
            ),  # _STATE <- 0x40
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert _resolve_state_var_alias(fg, 2, _STATE) == 0x40


def test_state_var_alias_unchanged_without_header_copy(_seam) -> None:
    # No copy into the compared slot at the header -> offset unchanged (the clean
    # hodur / sub_7FFD chains must not be remapped).
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),  # no copy
            10: _b(10, (2,), (2,), (_mov_state(0x2000, 0x20),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert _resolve_state_var_alias(fg, 2, _STATE) == _STATE


def _mov_carrier(ea, src_off, dst_off=_CARRIER_OFF):
    # pure stack->stack copy to a NON-state slot: the carrier write ``v4 = src``.
    return _mov_stk(ea, src_off, dst_off)


def test_block_has_live_carrier_write_detects_non_state_write() -> None:
    # A block whose only data write is the state-var write is pure glue.
    glue = _b(10, (2,), (8, 9), (_mov_state(0x1000, 0x20),))
    assert block_has_live_carrier_write(glue, _STATE) is False
    # A block that also writes a non-state slot carries a live carrier.
    carrier = _b(
        10,
        (2,),
        (8, 9),
        (_mov_state(0x1000, 0x20), _mov_carrier(0x1004, 0x80)),
    )
    assert block_has_live_carrier_write(carrier, _STATE) is True
    # A block with only a carrier write (no state write) still counts.
    carrier_only = _b(11, (2,), (8,), (_mov_carrier(0x1008, 0x80),))
    assert block_has_live_carrier_write(carrier_only, _STATE) is True


def _exit_block(serial, preds):
    # A 0-successor STOP/exit block (the function return).
    return BlockSnapshot(
        serial=serial,
        block_type=2,
        succs=(),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(),
    )


def test_carrier_return_arm_flows_through_shared_block(_seam) -> None:
    # The Approov conditional-handler shape: a 2-way branch (blk7) selects two arms
    # that CONVERGE on a shared block (blk10) carrying a LIVE non-state write (the
    # ``v4 = a1`` carrier = the return value).  Arm A (blk8) writes a CONTINUE state
    # (0x20, a real handler that re-enters the loop and overwrites the carrier); arm
    # B (blk9) writes the EXIT state (0x30, routing to the return).  The carrier is
    # live ONLY on the exit arm, so the recovery must keep the exit arm flowing
    # THROUGH blk10 (carrier preserved -> ``return v4``) while the continue arm
    # bypasses blk10 (its carrier copy is dead).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),  # entry
            1: _b(1, (3,), (0,), (_mov_state(0x900, 0x10),)),  # prologue -> 0x10
            3: _b(3, (7, 20, 99), (1, 10), ()),  # dispatcher
            7: _b(7, (8, 9), (3,)),  # selecting 2-way
            8: _b(8, (10,), (7,), (_mov_state(0x1000, 0x20),)),  # CONTINUE arm -> 0x20
            9: _b(9, (10,), (7,), (_mov_state(0x1010, 0x30),)),  # EXIT arm -> 0x30
            10: _b(10, (3,), (8, 9), (_mov_carrier(0x1020, 0x80),)),  # shared carrier
            20: _b(20, (3,), (3,)),  # continue handler
            99: _exit_block(99, (3,)),  # return/exit
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # 0x30 has no handler row -> routes to the exit (default) = a return.
    disp = _disp({0x10: 7, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=3, initial_state=0x10
    )
    mods = graph_modifications(plan)
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    # The CONTINUE arm bypasses the carrier block: blk8 -> route(0x20)=blk20.
    assert (8, 10, 20) in gotos
    # The carrier block ITSELF is redirected onto the exit route (blk99): the exit
    # arm's edge blk9 -> blk10 stays intact, so ``blk9 -> blk10(carrier) -> exit``.
    assert (10, 3, 99) in gotos
    # The exit arm (blk9) is NOT bypassed -- it must flow through the carrier block.
    assert not [m for m in mods if isinstance(m, RedirectGoto) and m.from_serial == 9]


def test_explicit_stop_row_routes_to_stop_not_catchall(_seam) -> None:
    # OLLVM -fla EXIT shape (ticket llr-gpt3): the EXIT state (0x30) is an EXPLICIT
    # map row routing to a STOP block (blk99), while the dispatcher's catch-all
    # default (blk20) loops back to the dispatcher (NOT a STOP).  The terminal
    # handler blk10 writes the EXIT state, so its back-edge must redirect onto the
    # STOP (blk99) -- routing it to the catch-all default (blk20) strands the
    # output write in a non-returning while(1).
    # blk99 must be a real STOP (BLT_STOP); a bare 0-succ block is ZERO_WAY, not
    # STOP, and _is_stop_block keys on the STOP kind/type.
    stop99 = BlockSnapshot(
        serial=99,
        block_type=1,
        succs=(),
        preds=(2,),
        flags=0,
        start_ea=0x1000 + 99 * 0x40,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),  # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),  # prologue -> 0x10
            2: _b(2, (10, 20, 99), (1, 10, 20)),  # dispatcher
            10: _b(
                10, (2,), (2,), (_mov_state(0x1000, 0x30),)
            ),  # terminal: writes EXIT 0x30
            20: _b(20, (2,), (2,)),  # catch-all default (loops back)
            99: stop99,  # STOP / return
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # Explicit rows: 0x10 -> blk10 (terminal handler), 0x30 -> blk99 (STOP).
    # Catch-all default = blk20 (the loop-back catch-all, NOT a STOP).
    disp = _disp({0x10: 10, 0x30: 99}, exit_block=20)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    by_block = {t.write_block: t for t in transitions}
    # blk10 folds to EXIT state 0x30, routed to STOP blk99 -> classified is_return.
    assert by_block[10].next_state == 0x30
    assert by_block[10].target_handler == 99
    assert by_block[10].is_return is True
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
    )
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # FIX: the terminal back-edge redirects onto the STOP (blk99), NOT the catch-all
    # default (blk20) -- so the function actually returns.
    assert (10, 99) in gotos
    assert (10, 20) not in gotos


def test_return_redirect_falls_back_to_default_when_not_stop(_seam) -> None:
    # CONTROL (hodur / approov shape): when the return routes to the catch-all
    # default which IS the function's exit, the back-edge must still redirect onto
    # default_target exactly as before (byte-identical legacy path).  Here the EXIT
    # arm's state 0x30 has no explicit row -> routes to the catch-all default = the
    # STOP blk99; target_handler == default, so the fix returns default unchanged.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 99), (1, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x30),)),  # writes UNMAPPED 0x30
            99: _exit_block(99, (2,)),  # catch-all default = STOP
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # 0x30 has NO explicit row -> routes to default = exit_block = blk99 (STOP).
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    by_block = {t.write_block: t for t in transitions}
    assert by_block[10].is_return is True
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
    )
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # default_target IS the STOP -> redirect onto it (unchanged legacy behaviour).
    assert (10, 99) in gotos


def test_exact_static_terminal_delivery_targets_zero_successor_epilogue(_seam) -> None:
    """Resolver-proven epilogues need not be classified as portable STOP blocks."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (11,), (2,)),
            11: _b(11, (2,), (10,)),
            99: _b(99, (), ()),
            100: BlockSnapshot(
                serial=100,
                block_type=1,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x9000,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=0,
        func_ea=0x40A560,
    )
    disp = _disp({0x19A7218A: 10}, exit_block=98)
    transition = StateWriteTransition(
        write_block=10,
        next_state=0x19A7218A,
        target_handler=99,
        is_return=True,
        branch_arm=None,
        via_block=11,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "computed_goto_exact_terminal_delivery",
            True,
        ),
    )

    mods = build_state_write_redirects(
        fg,
        disp,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=None,
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 11, 100) in gotos


def test_pure_glue_via_block_still_bypassed(_seam) -> None:
    # CONTROL: when the shared back-edge block carries ONLY the state-glue (no live
    # carrier write), the predecessor-partitioned model must still BYPASS it exactly
    # as before -- the carrier-preservation must not fire (byte-identical old path).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (3,), (0,), (_mov_state(0x900, 0x10),)),
            3: _b(3, (7, 20, 99), (1, 10), ()),
            7: _b(7, (8, 9), (3,)),
            8: _b(8, (10,), (7,), (_mov_state(0x1000, 0x20),)),
            9: _b(9, (10,), (7,), (_mov_state(0x1010, 0x30),)),
            10: _b(10, (3,), (8, 9), ()),  # PURE glue
            20: _b(20, (3,), (3,)),
            99: _exit_block(99, (3,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 7, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=3, initial_state=0x10
    )
    mods = graph_modifications(plan)
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # Pure glue: blk8 bypasses to route(0x20)=blk20, blk9 bypasses to the exit
    # (blk99); the shared block is never kept on the path.
    assert (8, 20) in gotos
    assert (9, 99) in gotos
    # The carrier-return path is NOT used (no ``blk10 -> exit`` self-redirect).
    assert (10, 99) not in gotos


def test_terminal_stack_alias_via_block_keeps_carrier_guard(_seam) -> None:
    alias_definition = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1700,
        operands=(),
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(_STATE,),
            sub_l=MopSnapshot(
                t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK
            ),
        ),
        d=MopSnapshot(t=_T_REG, size=8, reg=3, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )
    terminal_store = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1800,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=0x20, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=3, kind=OperandKind.REGISTER),
        kind=InsnKind.STORE,
    )
    terminal_guard = InsnSnapshot(
        opcode=0x33,
        ea=0x1804,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=0x20, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=9, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (6,), ()),
            2: _b(2, (3, 5), (8,)),
            6: _b(6, (7, 8), (0,), (_state_ne_tail(0x1600, 0x10),)),
            7: _b(7, (8,), (6,), (alias_definition,)),
            8: _b(8, (9, 2), (6, 7), (terminal_store, terminal_guard)),
            9: _b(9, (10,), (8,)),
            10: _exit_block(10, (9,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 7, 0x20: 9}, exit_block=3)
    physical = semantic_route_evidence_module.SemanticPhysicalStateWriteWitness(
        semantic_route_evidence_module._instruction_projection(terminal_store),
        StorageIdentity(StorageIdentityKind.STACK, _STATE),
        4,
        0x20,
        source_serial=8,
        alias_definition_instruction=semantic_route_evidence_module._instruction_projection(
            alias_definition
        ),
        alias_definition_serial=7,
        physical_width=8,
    )
    guarded = semantic_route_evidence_module.prove_semantic_physical_guard_selection(
        fg,
        guard_serial=8,
        selected_target_serial=9,
        physical_state_write=physical,
    )
    assert guarded is not None
    transitions = (
        StateWriteTransition(
            7,
            0x20,
            9,
            False,
            None,
            via_block=8,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "stack_address_alias_terminal_guard_partitioned",
                True,
            ),
            physical_state_write=replace(physical, guarded_selection=guarded),
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=0x10,
        state_var_stkoff=_STATE,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    converts = {
        (m.block_serial, m.goto_target) for m in mods if isinstance(m, ConvertToGoto)
    }
    assert (7, 8, 9) not in gotos
    assert (6, 7) in converts
    assert (8, 9) in converts
    assert (6, 8, 7) not in branches
    assert (8, 2, 9) not in branches


def test_witness_entry_bridge_shortcuts_safe_exit_path(_seam) -> None:
    """Equality-chain entry bridge with a pure exit_path is shortcut."""
    # blk0 -> blk2(dispatcher entry) -> blk4(eq 0x10) -> blk10(handler)
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_preserves_live_stack_exit_path(_seam) -> None:
    """Equality-chain entry bridge with a live stack definition is preserved."""
    # blk0 -> blk2(dispatcher entry) -> blk4(eq 0x10). blk4 defines a non-state
    # stack slot 0x70. blk10(handler) uses 0x70. Shortcut blk0 -> blk10 would
    # bypass the definition, so the entry bridge must be preserved.
    _LIVE_OFF = 0x70
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_stk(0x1080, _STATE, _LIVE_OFF),),  # live def of 0x70
            ),
            10: _b(10, (99,), (2,), (_use_stk(0x10C0, _LIVE_OFF),)),  # use of 0x70
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectBranch)
    }
    # Entry bridge must NOT shortcut because blk2 defines live 0x70.
    assert (0, 2, 10) not in gotos
    # Feasibility is still useful to prove which arm is live, but unsafe
    # exit_path_effect_summaries must preserve the current CFG instead of mutating branch arms.
    assert (2, 99, 10) not in branches


def test_witness_entry_bridge_preserves_nested_register_use(_seam) -> None:
    """Nested sub-instruction uses, like ``icall rax``, keep register defs live."""
    _RAX = 8
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_reg(0x1080, 0x1234, _RAX),),
            ),
            10: _b(10, (99,), (2,), (_use_nested_reg(0x10C0, _RAX),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectBranch)
    }
    assert (0, 2, 10) not in gotos
    assert (2, 99, 10) not in branches


def test_entry_bridge_requires_witness_shortcuts_live_safe_without_provider(
    _seam,
) -> None:
    """Missing witness rows keep legacy shortcutting when the exit_path is live-safe."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_entry_bridge_requires_witness_preserves_live_no_provider_exit_path(
    _seam,
) -> None:
    """No-provider fallback preserves a live register def in the dispatcher entry."""
    _RAX = 8
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_reg(0x1080, 0x1234, _RAX),),
            ),
            10: _b(10, (99,), (2,), (_use_nested_reg(0x10C0, _RAX),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) not in gotos


def test_computed_goto_entry_bridge_ignores_router_only_scratch_liveness(_seam) -> None:
    scratch = 8
    state_reg = 20
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 99), (0,), (_mov_reg(0x1080, 0x1234, scratch),)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (100,), (2, 10), (_use_nested_reg(0x10C0, scratch),)),
            100: _exit_block(100, (99,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=100),
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_exit_path_blocks=(2, 99),
        entry_bridge_requires_witness=True,
        materialized_computed_goto_profile=True,
    )
    gotos = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_entry_bridge_requires_witness_preserves_live_no_provider_stack_exit_path(
    _seam,
) -> None:
    """No-provider fallback uses all supplied exit_path blocks, not just old target."""
    _LIVE_OFF = 0x70
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (4,), (0,)),
            4: _b(4, (10,), (2,), (_mov_stk(0x1080, _STATE, _LIVE_OFF),)),
            10: _b(10, (99,), (4,), (_use_stk(0x10C0, _LIVE_OFF),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) not in gotos


def test_conditional_entry_bridge_without_policy_uses_legacy_shortcut(_seam) -> None:
    """Conditional-looking CFG alone does not force witness-mode projection."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_shortcuts_dead_non_state_exit_path(_seam) -> None:
    """A non-state definition with no live use can be bypassed."""
    _DEAD_OFF = 0x71
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_stk(0x1080, _STATE, _DEAD_OFF),),  # dead def
            ),
            10: _b(10, (99,), (2,)),  # no use of _DEAD_OFF
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_shortcuts_state_only_exit_path(_seam) -> None:
    """State-variable definitions are intentionally severed by unflattening."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_state(0x1080, 0x10),),  # state-var def
            ),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_back_edge_preserves_unresolved_indirect_state_store(_seam) -> None:
    """Do not route a dispatcher back-edge past a pointer-indirected state store."""
    tail = InsnSnapshot(
        opcode=43,
        ea=0x1200,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=0x20, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(8,)),
            8: _b(8, (9, 2), (6, 7), (_stx_reg(0x1180, 0x20, 32), tail)),
            9: _exit_block(9, (8,)),
            10: _b(10, (8,), (2,)),
            99: _exit_block(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=8,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=1,
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
    )
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    assert (8, 2, 10) not in branches


def test_back_edge_uses_exact_witness_for_terminal_indirect_state_store(_seam) -> None:
    """A terminal indirect state store may redirect through a local branch witness."""
    terminal = 0xDD1FF05BF465445C
    tail = InsnSnapshot(
        opcode=43,
        ea=0x1200,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=terminal, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(8,)),
            8: _b(8, (9, 2), (7,), (_stx_reg(0x1180, terminal, 32), tail)),
            9: _exit_block(9, (8,)),
            10: _b(10, (8,), (2,)),
            99: _exit_block(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=8,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=1,
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        branch_witness_map=None,
    )
    converts = {
        (m.block_serial, m.goto_target) for m in mods if isinstance(m, ConvertToGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    assert (8, 9) in converts
    assert (8, 2, 9) not in branches
    assert (8, 2, 10) not in branches


def test_conditional_entry_two_arms_bridge_to_both_handlers(_seam) -> None:
    """d81-3rja: the prologue selects the initial state CONDITIONALLY -- two arms
    each write a distinct leaf state to the state var, then merge into the
    dispatcher (the Rhadamanthys sub_40A560 ``a2 ? S_a : S_b`` entry). Both arms
    must bridge PAST the dispatcher to their own handler, not funnel through a
    single ``initial_state``.

        0(entry) -> 1(cond) -> {11 writes 0x10, 12 writes 0x20} -> 2(dispatcher)
        route(0x10)=21, route(0x20)=22

    Expected 2-way entry bridge: 11 -> 21 and 12 -> 22.
    """
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (11, 12), (0,)),  # conditional split
            11: _b(11, (2,), (1,), (_mov_state(0x1100, 0x10),)),  # arm A: state=0x10
            12: _b(12, (2,), (1,), (_mov_state(0x1200, 0x20),)),  # arm B: state=0x20
            2: _b(2, (21, 22), (11, 12, 21, 22)),  # dispatcher
            21: _b(21, (2,), (2,)),  # handler A
            22: _b(22, (2,), (2,)),  # handler B
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=None,
        state_var_stkoff=_STATE,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (11, 2, 21) in gotos, f"arm A not bridged to its handler: {sorted(gotos)}"
    assert (12, 2, 22) in gotos, f"arm B not bridged to its handler: {sorted(gotos)}"


def test_conditional_handler_redirects_unique_arm_glue_before_bst_spine(_seam) -> None:
    """A register-BST arm can write its next state in a unique glue block and
    then enter one of the dispatch root's range-navigation children. Redirect
    that glue edge, preserving its writes, instead of requiring the distant
    shared write boundary to be a direct dispatcher predecessor.
    """
    fg = FlowGraph(
        blocks={
            8: _b(8, (9, 131), ()),
            9: _b(9, (8,), (230,)),
            131: _b(131, (8,), (195,)),
            194: _b(194, (195, 230), ()),
            195: _b(195, (131,), (194,), (_mov_reg(0x1195, 0x20, 20),)),
            230: _b(230, (9,), (194,), (_mov_reg(0x1230, 0x10, 20),)),
            103: _b(103, (500,), ()),
            220: _b(220, (501,), ()),
            500: _b(500, (8,), (103,)),
            501: _b(501, (8,), (220,)),
            104: _b(104, (), ()),
            221: _b(221, (), ()),
        },
        entry_serial=194,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=194,
        states=(0xA0716E5B,),
        arms=(
            TransitionArm(0x20, 221, False, 194, 220, 220, (194, 195, 131, 220)),
            TransitionArm(0x10, 104, False, 194, 103, 103, (194, 230, 9, 103)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 104, 0x20: 221}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
    )
    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, RedirectGoto)
    }
    assert gotos == {(195, 131, 221), (230, 9, 104)}


@pytest.mark.parametrize("is_indirect", (False, True))
@pytest.mark.parametrize(
    "existing, expected_sources",
    (
        ({(135, 105)}, {116}),
        ({(135, 105), (147, 116)}, set()),
        ({(104, 105)}, {105, 116}),
    ),
)
def test_conditional_arm_does_not_retarget_already_partitioned_shared_feeder(
    existing, expected_sources, is_indirect,
) -> None:
    """A writer-edge redirect owns its arm, not the shared feeder's other inputs."""
    graph = FlowGraph(
        {
            74: _b(74, (135, 147), ()),
            135: _b(135, (105,), (74,)),
            147: _b(147, (116,), (74,)),
            104: _b(104, (105,), ()),
            115: _b(115, (116,), ()),
            105: _b(105, (2,), (135, 104)),
            116: _b(116, (2,), (147, 115)),
            2: _b(2, (80, 195), (105, 116)),
            80: _b(80, (), (2,)),
            195: _b(195, (), (2,)),
            99: _b(99, (), ()),
        },
        entry_serial=74, func_ea=0x1000,
    )
    handler = HandlerTransition(
        74, (0x10,),
        (
            TransitionArm(0x20, 195, False, 74, 105, 105, (74, 135, 105)),
            TransitionArm(0x30, 80, False, 74, 116, 116, (74, 147, 116)),
        ),
    )
    modifications = build_conditional_arm_redirects(
        graph, _disp({0x20: 195, 0x30: 80}, exit_block=99), (handler,),
        dispatcher_entry_serial=2, existing=existing, is_indirect=is_indirect,
    )
    assert {mod.from_serial for mod in modifications} == expected_sources


def test_conditional_arm_forecast_abstention_logs_without_changing_redirects(
    monkeypatch, caplog, _seam,
) -> None:
    """A forecast abstention rejects only that optional arm redirect.

    ``TransitionArm`` records its handler only through ``ordered_path``.  The
    canonical pipeline cannot publish the redirect without its corresponding
    typed route fact, but the failure need not reject unrelated back-edge
    redirects.  Its INFO diagnostic uses the arm's typed path rather than a
    nonexistent ``arm.handler`` field.
    """
    fg = FlowGraph(
        blocks={
            8: _b(8, (20, 30), (101, 102)),
            20: _b(20, (), (8,)),
            30: _b(30, (), (8,)),
            100: _b(100, (101, 102), ()),
            101: _b(101, (8,), (100,)),
            102: _b(102, (8,), (100,)),
        },
        entry_serial=100,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=100,
        states=(0xA0,),
        arms=(
            TransitionArm(0x10, 20, False, 100, 101, 101, (100, 101)),
            TransitionArm(0x20, 30, False, 100, 102, 102, (100, 102)),
        ),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_conditional_arm_route_forecast",
        lambda *_args, **_kwargs: None,
    )

    with caplog.at_level(logging.INFO, logger="d810.transforms.minimal_unflatten_emit"):
        modifications, forecasts = _build_conditional_arm_redirects_with_forecasts(
            fg,
            _disp({0x10: 20, 0x20: 30}, exit_block=99),
            (handler,),
            dispatcher_entry_serial=8,
            existing={(102, 8)},
            decision_dag=DecisionDag(32, {}, root=8),
        )

    assert modifications == []
    assert forecasts == ()
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        message.startswith("UNFLAT_ARM_FORECAST_ABSTAIN source=blk[101]")
        and "handler=blk[100]" in message
        for message in messages
    )


def test_conditional_handler_shared_write_preserves_effectful_arm_corridors(
    _seam,
) -> None:
    """A shared-write conditional must not bypass work on either arm.

    The native lowering backend may insert a helper immediately after the
    selecting branch.  The arm's original path can still contain observable
    work before the shared state-write block.  Redirecting the branch edge
    directly to the next handler (the historical behavior) severs that path;
    the owned edge is the last arm-local predecessor into the shared write.
    """
    fg = FlowGraph(
        blocks={
            8: _b(8, (20, 30), (200,)),
            20: _b(20, (), (8,)),
            30: _b(30, (), (8,)),
            99: _b(99, (), ()),
            100: _b(100, (101, 103), ()),
            101: _b(101, (102,), (100,)),
            102: _b(102, (200,), (101,), (_call_reg(0x2102, 7),)),
            103: _b(103, (104,), (100,)),
            104: _b(104, (200,), (103,)),
            # The shared suffix is state plumbing only.  The arm-local cut may
            # bypass it once that fact is made explicit; it must not bypass a
            # non-state effect hidden in the same block.
            200: _b(200, (8,), (102, 104), (_mov_state(0x2200, 0x20),)),
        },
        entry_serial=100,
        func_ea=0x2000,
    )
    handler = HandlerTransition(
        handler=100,
        states=(0xA0,),
        arms=(
            TransitionArm(
                0x10,
                20,
                False,
                100,
                200,
                200,
                (100, 101, 102, 200),
            ),
            TransitionArm(
                0x20,
                30,
                False,
                100,
                200,
                200,
                (100, 103, 104, 200),
            ),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 20, 0x20: 30}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        state_var_stkoff=_STATE,
    )

    assert {
        (type(mod).__name__, mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, (RedirectGoto, RedirectBranch))
    } == {
        ("RedirectGoto", 102, 200, 20),
        ("RedirectGoto", 104, 200, 30),
    }


def test_conditional_handler_shared_write_abstains_on_unowned_cut_predecessor(
    _seam,
) -> None:
    """A cut source with an unrelated predecessor is not arm-owned."""
    fg = FlowGraph(
        blocks={
            8: _b(8, (20, 30), (200,)),
            20: _b(20, (), (8,)),
            30: _b(30, (), (8,)),
            99: _b(99, (), ()),
            100: _b(100, (101, 103), ()),
            101: _b(101, (102,), (100,)),
            # 300 is not represented by either arm's ordered_path.  A
            # redirect of 102 -> 20 would also bypass the shared write for
            # 300 -> 102 unless ownership is proved explicitly.
            102: _b(102, (200,), (101, 300), (_call_reg(0x2702, 7),)),
            103: _b(103, (104,), (100,)),
            104: _b(104, (200,), (103,)),
            200: _b(200, (8,), (102, 104), (_mov_state(0x2700, 0x20),)),
            300: _b(300, (102,), (), ()),
        },
        entry_serial=100,
        func_ea=0x2400,
    )
    handler = HandlerTransition(
        handler=100,
        states=(0xA0,),
        arms=(
            TransitionArm(0x10, 20, False, 100, 200, 200, (100, 101, 102, 200)),
            TransitionArm(0x20, 30, False, 100, 200, 200, (100, 103, 104, 200)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 20, 0x20: 30}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        state_var_stkoff=_STATE,
    )

    assert not any(
        isinstance(mod, (RedirectGoto, RedirectBranch)) for mod in mods
    )


@pytest.mark.parametrize("near_miss", ("other_successor", "stale_path"))
def test_conditional_handler_abstains_on_near_miss_shared_boundary(
    _seam,
    near_miss,
) -> None:
    """A shared cut requires current CFG/path evidence, not stale metadata."""
    shared_succs = (8, 99) if near_miss == "other_successor" else (8,)
    first_path = (100, 101, 105, 200) if near_miss == "stale_path" else (100, 101, 102, 200)
    fg = FlowGraph(
        blocks={
            8: _b(8, (20, 30), (200,)),
            20: _b(20, (), (8,)),
            30: _b(30, (), (8,)),
            99: _b(99, (), ()),
            100: _b(100, (101, 103), ()),
            101: _b(101, (102,), (100,)),
            102: _b(102, (200,), (101,), (_call_reg(0x2602, 7),)),
            103: _b(103, (104,), (100,)),
            104: _b(104, (200,), (103,)),
            200: _b(
                200,
                shared_succs,
                (102, 104),
                (_mov_state(0x2600, 0x20),),
            ),
        },
        entry_serial=100,
        func_ea=0x2300,
    )
    handler = HandlerTransition(
        handler=100,
        states=(0xA0,),
        arms=(
            TransitionArm(0x10, 20, False, 100, 200, 200, first_path),
            TransitionArm(0x20, 30, False, 100, 200, 200, (100, 103, 104, 200)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 20, 0x20: 30}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        state_var_stkoff=_STATE,
    )

    assert not any(
        isinstance(mod, (RedirectGoto, RedirectBranch))
        for mod in mods
    )


def test_conditional_handler_abstains_when_shared_suffix_has_effect(
    _seam,
) -> None:
    """Never cut around a shared block that carries a non-state effect."""
    fg = FlowGraph(
        blocks={
            8: _b(8, (20, 30), (200,)),
            20: _b(20, (), (8,)),
            30: _b(30, (), (8,)),
            99: _b(99, (), ()),
            100: _b(100, (101, 103), ()),
            101: _b(101, (102,), (100,)),
            102: _b(102, (200,), (101,), (_call_reg(0x2302, 7),)),
            103: _b(103, (104,), (100,)),
            104: _b(104, (200,), (103,)),
            # The shared state write is accompanied by a live carrier write.
            # Redirecting 102/104 past this block would silently drop it.
            200: _b(
                200,
                (8,),
                (102, 104),
                (_mov_state(0x2400, 0x20), _mov_carrier(0x2404, 0x80)),
            ),
        },
        entry_serial=100,
        func_ea=0x2100,
    )
    handler = HandlerTransition(
        handler=100,
        states=(0xA0,),
        arms=(
            TransitionArm(0x10, 20, False, 100, 200, 200, (100, 101, 102, 200)),
            TransitionArm(0x20, 30, False, 100, 200, 200, (100, 103, 104, 200)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 20, 0x20: 30}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        state_var_stkoff=_STATE,
    )

    assert not any(
        isinstance(mod, (RedirectGoto, RedirectBranch))
        for mod in mods
    )


@pytest.mark.parametrize("effect", ("memory_store", "unknown"))
def test_conditional_handler_abstains_on_unclassified_shared_suffix_effect(
    _seam,
    effect,
) -> None:
    """Unresolved/memory-shaped shared work is not treated as state glue."""
    effect_insn = (
        _stx_reg(0x2504, 0x1234, 1)
        if effect == "memory_store"
        else InsnSnapshot(
            opcode=0x99,
            ea=0x2504,
            operands=(),
            kind=InsnKind.UNKNOWN,
        )
    )
    fg = FlowGraph(
        blocks={
            8: _b(8, (20, 30), (200,)),
            20: _b(20, (), (8,)),
            30: _b(30, (), (8,)),
            99: _b(99, (), ()),
            100: _b(100, (101, 103), ()),
            101: _b(101, (102,), (100,)),
            102: _b(102, (200,), (101,), (_call_reg(0x2502, 7),)),
            103: _b(103, (104,), (100,)),
            104: _b(104, (200,), (103,)),
            200: _b(
                200,
                (8,),
                (102, 104),
                (_mov_state(0x2500, 0x20), effect_insn),
            ),
        },
        entry_serial=100,
        func_ea=0x2200,
    )
    handler = HandlerTransition(
        handler=100,
        states=(0xA0,),
        arms=(
            TransitionArm(0x10, 20, False, 100, 200, 200, (100, 101, 102, 200)),
            TransitionArm(0x20, 30, False, 100, 200, 200, (100, 103, 104, 200)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 20, 0x20: 30}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        state_var_stkoff=_STATE,
    )

    assert not any(
        isinstance(mod, (RedirectGoto, RedirectBranch))
        for mod in mods
    )


def test_conditional_handler_abstains_on_unmatched_materialized_arm(_seam) -> None:
    """An unproven computed-goto arm is not evidence of a function return."""
    fg = FlowGraph(
        blocks={
            8: _b(8, (9, 10), ()),
            9: _b(9, (8,), (146,)),
            10: _b(10, (8,), (146,)),
            59: _b(59, (), ()),
            99: _b(99, (), ()),
            146: _b(146, (9, 10), ()),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=146,
        states=(0xEC71CA67,),
        arms=(
            TransitionArm(0x2100AFDD, 59, False, 146, 9, 9, (146, 9, 8)),
            TransitionArm(None, None, True, 146, 10, 10, (146, 10, 8)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x2100AFDD: 59}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        infer_unmatched_returns=False,
    )
    redirects = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, (RedirectGoto, RedirectBranch))
    }
    assert redirects == {(9, 8, 59)}


def test_state_write_redirect_abstains_on_unmatched_materialized_return(_seam) -> None:
    """The coarse back-edge model must not infer return from an unknown state."""
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (225,)),
            146: _b(146, (147, 225), ()),
            147: _b(147, (), (146,)),
            148: _b(148, (), ()),
            225: _b(225, (8,), (146,)),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(
        146,
        None,
        148,
        True,
        None,
        via_block=225,
    )

    mods = build_state_write_redirects(
        fg,
        _disp({}, exit_block=148),
        (transition,),
        dispatcher_entry_serial=8,
        pre_header_serial=None,
        initial_state=None,
        state_var_reg=20,
        infer_unmatched_returns=False,
    )

    assert mods == []


def test_loop_guard_exit_abstains_on_unmatched_materialized_arm(_seam) -> None:
    """A detached terminal arm is not proof that its sibling should exit."""
    branch = InsnSnapshot(
        opcode=100,
        ea=0x2000,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=225),
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (225,)),
            146: _b(146, (147, 225), (), (branch,)),
            147: _b(147, (148,), (146,)),
            148: _b(148, (), (147,)),
            225: _b(225, (8,), (146,)),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=146,
        states=(0xEC71CA67,),
        arms=(
            TransitionArm(0x2100AFDD, 59, False, 146, 225, 225, (146, 225, 8)),
            TransitionArm(None, None, True, 146, 148, 148, (146, 147, 148)),
        ),
    )
    dispatcher = IntervalDispatcher([IntervalRow(0, 1, 59)], compute_default=False)

    assert build_loop_guard_exit_redirects(
        fg,
        dispatcher,
        (handler,),
        dispatcher_entry_serial=8,
        infer_unmatched_returns=False,
    ) == []


def test_loop_guard_exit_redirect_preserves_return_value_transport_prefix(_seam) -> None:
    """The outer selector chooses blk24, not its XDU successor blk25."""
    outer = 24

    def eq(ea: int, constant: int, target: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=44,
            ea=ea,
            operands=(),
            l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=outer),
            r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
            kind=InsnKind.EQUALITY_JUMP,
            branch_predicate=PredicateKind.EQ,
            is_conditional_jump=True,
            control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
            compare_width=4,
        )
    fg = FlowGraph(
        blocks={
            2: _b(2, (3, 6), (23,), (eq(0x1200, 0, 6),)),
            3: _b(3, (4, 9), (2,), (eq(0x1300, 1, 9),)),
            4: _b(4, (5, 24), (3,), (eq(0x1400, 9, 24),)),
            5: _b(5, (25,), (4,), (InsnSnapshot(
                opcode=0, ea=0x1500, operands=(), kind=InsnKind.MOV,
                l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0xFFFFFFFF),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
            ),)),
            6: _b(6, (), (2,)),
            9: _b(9, (), (3,)),
            23: _b(23, (2,), (), (_mov_state(0x2300, 9), InsnSnapshot(
                opcode=0, ea=0x2304, operands=(),
                l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=outer),
                kind=InsnKind.MOV,
            ))),
            24: _b(24, (25,), (4,), (InsnSnapshot(
                opcode=0, ea=0x2400, operands=(), kind=InsnKind.MOV,
                l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=12),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
            ),)),
            25: _b(25, (26,), (24, 5), (InsnSnapshot(
                opcode=0, ea=0x2500, operands=(), kind=InsnKind.XDU,
                l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
                d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=8),
            ),)),
            26: BlockSnapshot(26, 0, (), (25,), 0, 0xFFFFFFFFFFFFFFFF, (), BlockKind.STOP),
        },
        entry_serial=23,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=23, states=(9,),
        arms=(TransitionArm(9, 23, False, 23, 25, 25, (23, 2, 3, 4, 24, 25)),),
    )
    dispatcher = IntervalDispatcher([IntervalRow(0, 10, 23)], compute_default=False)

    forest = minimal_state_recovery_module.build_current_u32_decision_forest(
        fg,
        2,
        expected_identities=frozenset({StorageIdentity(StorageIdentityKind.STACK, outer)}),
    )
    assert forest is not None
    assert forest.route_from(2, 9) == 24

    forecasts = []
    redirects = build_loop_guard_exit_redirects(
        fg, dispatcher, (handler,), dispatcher_entry_serial=9,
        terminal_delivery_forecasts=forecasts,
    )
    assert redirects == [RedirectGoto(23, 2, 24)]
    assert len(forecasts) == 1
    forecast = forecasts[0]
    assert (forecast.source_serial, forecast.old_target, forecast.new_target) == (23, 2, 24)
    assert (forecast.exit_entry_serial, forecast.carrier_serial, forecast.logical_exit_serial) == (24, 25, 26)

    refs: dict[int, NativeBlockRef | LogicalBlockRef] = {
        serial: NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(
                min((block.start_ea, *(item.ea for item in block.insn_snapshots))),
                max((block.start_ea + 0x40, *(item.ea + 1 for item in block.insn_snapshots))),
            ),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=tuple(item.ea for item in block.insn_snapshots),
        ))
        for serial, block in fg.blocks.items() if serial != 26
    }
    refs[26] = LogicalBlockRef("loop-guard-terminal", "logical-stop", 1)
    proof = minimal_unflatten_emit_module._mint_loop_guard_terminal_delivery_proof(
        flow_graph=fg, modification=redirects[0], forecast=forecast,
        source_generation=7, block_refs_by_serial=refs,
    )
    assert proof is not None
    assert proof.proof_kind.value == "terminal_delivery"
    assert proof.state_dag is None
    assert proof.terminal_delivery is not None
    evidence = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 7, (proof,))
    assert bind_canonical_semantic_evidence(fg, evidence) is not None
    # The raw receipt cannot be reused to skip its leaf MOV or alter its DAG.
    assert minimal_unflatten_emit_module._mint_loop_guard_terminal_delivery_proof(
        flow_graph=fg, modification=RedirectGoto(23, 2, 25), forecast=forecast,
        source_generation=7, block_refs_by_serial=refs,
    ) is None
    assert minimal_unflatten_emit_module._mint_loop_guard_terminal_delivery_proof(
        flow_graph=fg, modification=redirects[0],
        forecast=replace(forecast, logical_exit_serial=25),
        source_generation=7, block_refs_by_serial=refs,
    ) is None
    nonreciprocal_blocks = dict(fg.blocks)
    nonreciprocal_blocks[25] = replace(nonreciprocal_blocks[25], preds=(5,))
    nonreciprocal = FlowGraph(nonreciprocal_blocks, fg.entry_serial, fg.func_ea)
    assert build_loop_guard_exit_redirects(
        nonreciprocal, dispatcher, (handler,), dispatcher_entry_serial=9,
    ) == []
    duplicate_move_blocks = dict(fg.blocks)
    duplicate_move_blocks[24] = replace(
        duplicate_move_blocks[24],
        insn_snapshots=(*duplicate_move_blocks[24].insn_snapshots, InsnSnapshot(
            opcode=0, ea=0x2408, operands=(), kind=InsnKind.MOV,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0),
            d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
        )),
    )
    duplicate_move = FlowGraph(duplicate_move_blocks, fg.entry_serial, fg.func_ea)
    assert build_loop_guard_exit_redirects(
        duplicate_move, dispatcher, (handler,), dispatcher_entry_serial=9,
    ) == []


def test_source_keyed_arm_overrides_existing_coarse_glue_redirect(_seam) -> None:
    fg = FlowGraph(
        blocks={
            8: _b(8, (9, 131), ()),
            131: _b(131, (8,), (129,)),
            104: _b(104, (129,), ()),
            129: _b(129, (131,), (104,)),
            212: _b(212, (), ()),
        },
        entry_serial=104,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=104,
        states=(0x13921E0E,),
        arms=(
            TransitionArm(
                0xA5540595,
                212,
                False,
                104,
                129,
                129,
                (104, 129),
                source_keyed_block=129,
            ),
            TransitionArm(0xDEF4B7E6, None, True, 104, 104, 104, (104,)),
        ),
    )

    mods = build_source_keyed_handler_redirects(
        fg,
        (handler,),
    )

    assert any(
        isinstance(mod, RedirectGoto)
        and (mod.from_serial, mod.old_target, mod.new_target) == (129, 131, 212)
        for mod in mods
    )


def test_source_keyed_handler_owner_redirects_one_branch_arm(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), ()),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                12,
                12,
                (10, 12),
                source_keyed_block=10,
            ),
        ),
    )

    mods = build_source_keyed_handler_redirects(fg, (handler,))

    assert mods == [RedirectBranch(10, 12, 20)]


def test_source_keyed_group_abstains_when_last_default_effect_route_is_lost(
    _seam,
) -> None:
    """Source-keyed shortcuts cannot collectively strand a live default arm."""

    fg = FlowGraph(
        blocks={
            0: _b(0, (77, 284, 452, 610), ()),
            77: _b(77, (78,), (0,)),
            284: _b(284, (78,), (0,)),
            452: _b(452, (78,), (0,)),
            78: _b(78, (79, 546), (77, 284, 452)),
            79: _b(79, (), (78,)),
            546: _b(546, (547,), (78,), (_call_reg(0x18002CF2E, 7),)),
            547: _b(547, (), (546,)),
            600: _b(600, (), ()),
            601: _b(601, (), ()),
            610: _b(610, (611,), (0,)),
            611: _b(611, (), (610,)),
            612: _b(612, (), ()),
        },
        entry_serial=0,
        func_ea=0x180015110,
    )
    handler = HandlerTransition(
        handler=452,
        states=(0x40131868,),
        arms=(
            TransitionArm(
                0x40131868,
                79,
                False,
                None,
                452,
                79,
                (452, 78, 79),
                source_keyed_block=452,
            ),
        ),
    )
    source_keyed = build_source_keyed_handler_redirects(fg, (handler,))
    assert source_keyed == [RedirectGoto(452, 78, 79)]
    base = [RedirectGoto(77, 78, 600), RedirectGoto(284, 78, 601)]

    def project(modifications):
        plan = compile_patch_plan(
            tuple(modifications),
            fg,
            block_refs_by_serial={
                serial: LogicalBlockRef("source-keyed-effect", f"blk-{serial}", 0)
                for serial in fg.blocks
            },
        )
        return project_patch_plan(fg, plan, snapshot_id=plan.snapshot_id).graph

    stage_intermediate_groups = getattr(
        minimal_unflatten_emit_module,
        "_stage_effect_safe_intermediate_redirect_groups",
    )
    assert stage_intermediate_groups(
        fg,
        [*base, *source_keyed],
        dispatcher_entry_serial=5,
        project_modifications=project,
    ) is None

    merge_group = getattr(
        minimal_unflatten_emit_module,
        "_merge_effect_safe_source_keyed_redirect_group",
    )
    safe = RedirectGoto(610, 611, 612)
    merged, accepted = merge_group(
        fg,
        base,
        [*source_keyed, safe],
        project_modifications=project,
    )
    assert accepted is False
    assert merged == base

    merged, accepted = merge_group(
        fg,
        base,
        [safe],
        project_modifications=project,
    )
    assert accepted is True
    assert merged == [*base, safe]

    # Attribute only effects newly lost by this optional group.  An already
    # unsafe base remains the final fragment-wide preflight gate's concern.
    already_lost = [*base, *source_keyed]
    merged, accepted = merge_group(
        fg,
        already_lost,
        [safe],
        project_modifications=project,
    )
    assert accepted is True
    assert merged == [*already_lost, safe]

    def fail_projection(_modifications):
        raise RuntimeError("projection failed")

    with pytest.raises(RuntimeError, match="projection failed"):
        merge_group(
            fg,
            base,
            source_keyed,
            project_modifications=fail_projection,
        )


def test_intermediate_stage_accounts_for_semantic_retained_route_folding(
    _seam,
) -> None:
    """Earlier corridor cuts cannot rely on a concretely selected retained arm."""

    fg = FlowGraph(
        blocks={
            0: _b(0, (10, 20, 452), ()),
            10: _b(10, (77,), (0,)),
            20: _b(20, (284,), (0,)),
            77: _b(77, (78,), (10,)),
            284: _b(284, (78,), (20,)),
            452: _b(452, (78,), (0,)),
            78: _b(78, (79, 546), (77, 284, 452)),
            79: _b(79, (), (78,)),
            546: _b(546, (), (78,), (_call_reg(0x18002CF2E, 7),)),
            600: _b(600, (), ()),
            601: _b(601, (), ()),
        },
        entry_serial=0,
        func_ea=0x180015110,
    )
    corridor_cuts = [
        RedirectGoto(10, 77, 600),
        RedirectGoto(20, 284, 601),
    ]
    exact_retained_route = RedirectGoto(452, 78, 79)

    def project(modifications):
        plan = compile_patch_plan(
            tuple(modifications),
            fg,
            block_refs_by_serial={
                serial: LogicalBlockRef("semantic-retained-effect", f"blk-{serial}", 0)
                for serial in fg.blocks
            },
        )
        return project_patch_plan(fg, plan, snapshot_id=plan.snapshot_id).graph

    stage_intermediate_groups = getattr(
        minimal_unflatten_emit_module,
        "_stage_effect_safe_intermediate_redirect_groups",
    )

    # Structurally retaining 452 -> 78 appears to preserve the default arm,
    # but the exact recovered state selects 79.  Hex-Rays folds that retained
    # comparison after the earlier corridor cuts, so staging must retain at
    # least one genuinely unresolved ingress instead of accepting both cuts.
    staged = stage_intermediate_groups(
        fg,
        [*corridor_cuts, exact_retained_route],
        dispatcher_entry_serial=5,
        project_modifications=project,
    )
    assert staged is not None
    assert staged.modifications == (corridor_cuts[0],)
    assert staged.effect_exclusions == ()
    assert not minimal_unflatten_emit_module.check_effectful_reachability_preserved(
        fg,
        post_cfg=project(tuple((*staged.modifications, exact_retained_route))),
    ).lost_block_serials


def test_intermediate_stage_carries_exact_infeasible_effect_proof(_seam) -> None:
    state = 0x40131868
    source = replace(
        _b(
            452,
            (78,),
            (361,),
            (
                _mov_state(0x18002A9E6, state),
                InsnSnapshot(
                    opcode=55,
                    ea=0x18002A9EC,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=78),
                    kind=InsnKind.GOTO,
                ),
            ),
        ),
        start_ea=0x18002A9CE,
        native_start_ea=0x18002A9CE,
    )
    predicate = replace(
        _b(
            78,
            (79, 546),
            (77, 284, 452),
            (
                InsnSnapshot(
                    opcode=43,
                    ea=0x180016416,
                    operands=(),
                    l=MopSnapshot(
                        kind=OperandKind.STACK,
                        size=4,
                        stkoff=_STATE,
                        stack_refs=(_STATE,),
                    ),
                    r=MopSnapshot(
                        kind=OperandKind.NUMBER,
                        size=4,
                        value=state,
                    ),
                    d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=546),
                    kind=InsnKind.COND_JUMP,
                    branch_predicate=PredicateKind.NE,
                    is_conditional_jump=True,
                ),
            ),
        ),
        start_ea=0x180016411,
        native_start_ea=0x180016411,
    )
    effect = replace(
        _b(546, (), (78,), (_call_reg(0x18002CF2E, 7),)),
        start_ea=0x18002CF19,
        native_start_ea=0x18002CF19,
    )
    graph = FlowGraph(
        blocks={
            0: _b(0, (361,), ()),
            361: _b(361, (452,), (0,)),
            77: _b(77, (78,), ()),
            284: _b(284, (78,), ()),
            452: source,
            78: predicate,
            79: _b(79, (), (78,)),
            546: effect,
        },
        entry_serial=0,
        func_ea=0x180015110,
    )
    exact_route = RedirectGoto(452, 78, 79)
    transition = StateWriteTransition(
        452,
        state,
        79,
        False,
        None,
        via_block=78,
        proof=TransitionProof(
            "decision_dag_state_route_reconciliation",
            "decision_dag_reconciled",
            True,
            route_source_kinds=("decision_dag", "interval"),
        ),
    )

    def project(modifications):
        plan = compile_patch_plan(
            tuple(modifications),
            graph,
            block_refs_by_serial={
                serial: LogicalBlockRef("exact-effect", f"blk-{serial}", 0)
                for serial in graph.blocks
            },
        )
        return project_patch_plan(graph, plan, snapshot_id=plan.snapshot_id).graph

    stage = minimal_unflatten_emit_module._stage_effect_safe_intermediate_redirect_groups(
        graph,
        [exact_route],
        dispatcher_entry_serial=5,
        project_modifications=project,
        transitions=(transition,),
        state_var_stkoff=_STATE,
    )

    assert stage is not None
    assert stage.modifications == ()
    (proof,) = stage.effect_exclusions
    assert proof.normalized_state == state
    assert proof.source_serial == 452
    assert proof.source_ea == 0x18002A9CE
    assert proof.source_write_ea == 0x18002A9E6
    assert proof.predicate_serial == 78
    assert proof.predicate_ea == 0x180016411
    assert proof.predicate_branch_ea == 0x180016416
    assert proof.selected_target_serial == 79
    assert proof.selected_target_ea == 0x23C0
    assert proof.discarded_effect_serial == 546
    # The exclusion binds the exact effect site; block diagnostics continue to
    # render the independently anchored blk546@0x18002CF19 identity.
    assert proof.discarded_effect_ea == 0x18002CF2E


def test_source_keyed_route_does_not_override_exact_live_edge(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (20,), ()),
            20: _b(20, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    stale_route = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x30,
                30,
                False,
                None,
                10,
                10,
                (10,),
                source_keyed_block=10,
            ),
        ),
    )

    assert (
        build_source_keyed_handler_redirects(
            fg,
            (stale_route,),
            protected_edges=frozenset({(10, 20)}),
        )
        == []
    )


def test_source_keyed_internal_owner_redirects_ordered_branch_arm(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11,), ()),
            11: _b(11, (12, 13), (10,)),
            12: _b(12, (), (11,)),
            13: _b(13, (), (11,)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                13,
                13,
                (10, 11, 13),
                source_keyed_block=11,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == [
        RedirectBranch(from_serial=11, old_target=13, new_target=20)
    ]


def test_source_keyed_terminal_handler_connects_to_proven_target(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (), ()),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                10,
                10,
                10,
                (10,),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == [
        ConvertToGoto(block_serial=10, goto_target=20)
    ]


def test_source_keyed_external_stop_never_becomes_a_goto_source(_seam) -> None:
    external_stop = BlockSnapshot(
        serial=10,
        block_type=6,
        succs=(),
        preds=(9,),
        flags=0,
        start_ea=0x40C898,
        insn_snapshots=(),
        kind=BlockKind.EXTERNAL,
    )
    fg = FlowGraph(
        blocks={
            10: external_stop,
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x19A7218A,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                10,
                10,
                10,
                (10,),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == []


def test_source_keyed_terminal_epilogue_routes_to_canonical_stop(_seam) -> None:
    stop = BlockSnapshot(
        serial=313,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            301: _b(301, (302,), ()),
            302: _b(302, (), (301,)),
            313: stop,
        },
        entry_serial=301,
        func_ea=0x40A560,
    )
    handler = HandlerTransition(
        handler=301,
        states=(0x19A7218A,),
        arms=(
            TransitionArm(
                0x19A7218A,
                302,
                True,
                None,
                301,
                301,
                (301,),
                source_keyed_block=301,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == [
        RedirectGoto(from_serial=301, old_target=302, new_target=313)
    ]


def test_exact_terminal_state_writer_routes_to_canonical_stop(_seam) -> None:
    state = 0x19A7218A
    state_reg = 20
    stop = BlockSnapshot(
        serial=313,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            261: _b(
                261,
                (262,),
                (217,),
                (_mov_reg(0x40C7E5, state, state_reg),),
            ),
            262: _b(262, (5,), (261,)),
            302: _b(302, (), ()),
            313: stop,
        },
        entry_serial=261,
        func_ea=0x40A560,
    )

    assert build_exact_terminal_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(
                261,
                state,
                302,
                proof_kind="terminal_state_route",
            ),
        ),
        state_var_reg=state_reg,
    ) == [RedirectGoto(from_serial=261, old_target=262, new_target=313)]


def test_exact_terminal_route_fragment_rejects_same_source_sibling_rewrites() -> None:
    terminal = RedirectGoto(from_serial=261, old_target=262, new_target=313)
    unrelated = RedirectGoto(from_serial=100, old_target=101, new_target=102)

    assert _prefer_exact_terminal_route_fragments(
        [
            ConvertToGoto(block_serial=261, goto_target=250),
            RedirectGoto(from_serial=261, old_target=262, new_target=250),
            unrelated,
            terminal,
        ],
        [terminal],
    ) == [unrelated, terminal]


def test_materialized_state_route_rebinds_external_handler_placeholder(
    _seam,
) -> None:
    state = 0x12345678
    state_reg = 20
    target_ea = 0x401800
    external = replace(
        _b(20, (), (10,)),
        start_ea=target_ea,
        kind=BlockKind.EXTERNAL,
    )
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (_mov_reg(0x401700, state, state_reg),),
            ),
            20: external,
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (MaterializedStateRoute(10, state, 30),),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset(),
        authoritative_handler_serials=frozenset({30}),
        handler_entry_eas_by_serial={30: target_ea},
    ) == [RedirectGoto(from_serial=10, old_target=20, new_target=30)]


def test_materialized_state_route_placeholder_rebind_abstains_without_local_write(
    _seam,
) -> None:
    state = 0x12345678
    state_reg = 20
    target_ea = 0x401800
    fg = FlowGraph(
        blocks={
            10: _b(10, (20,), ()),
            20: replace(
                _b(20, (), (10,)),
                start_ea=target_ea,
                kind=BlockKind.EXTERNAL,
            ),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (MaterializedStateRoute(10, state, 30),),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset(),
            authoritative_handler_serials=frozenset({30}),
            handler_entry_eas_by_serial={30: target_ea},
        )
        == []
    )


def test_materialized_state_route_dispatcher_rebind_requires_handler_exit_proof(
    _seam,
) -> None:
    state = 0x12345678
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (_mov_reg(0x401700, state, state_reg),),
            ),
            20: _b(20, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (MaterializedStateRoute(10, state, 30),),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({20}),
            authoritative_handler_serials=frozenset({30}),
        )
        == []
    )
    assert build_materialized_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(
                10,
                state,
                30,
                source_handler_serial=10,
                handler_exit_proven=True,
            ),
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({20}),
        authoritative_handler_serials=frozenset({30}),
    ) == [RedirectGoto(from_serial=10, old_target=20, new_target=30)]


def test_materialized_handler_exit_keeps_replayed_semantic_body_ownership(
    _seam,
) -> None:
    state = 0x4D34CF70
    state_reg = 20
    imported_clone = 30
    live_handler = 31
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (_mov_reg(0x401700, state, state_reg),),
            ),
            20: _b(20, (), (10,)),
            imported_clone: _b(imported_clone, (), ()),
            live_handler: _b(live_handler, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(
                10,
                state,
                imported_clone,
                source_handler_serial=10,
                handler_exit_proven=True,
            ),
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({20}),
        authoritative_handler_serials=frozenset({imported_clone, live_handler}),
    ) == [
        RedirectGoto(
            from_serial=10,
            old_target=20,
            new_target=imported_clone,
        )
    ]


def test_materialized_handler_local_next_state_proves_imported_exit(
    _seam,
) -> None:
    entry_state = 0x4A7ECCB8
    next_state = 0xDC71BBC5
    state_reg = 20
    handler = 10
    router = 20
    next_handler = 30
    fg = FlowGraph(
        blocks={
            handler: _b(
                handler,
                (router,),
                (),
                (_mov_reg(0x40EF7D, next_state, state_reg),),
            ),
            router: _b(router, (), (handler,)),
            next_handler: _b(next_handler, (), ()),
        },
        entry_serial=handler,
        func_ea=0x40D200,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(99, entry_state, handler),
            MaterializedStateRoute(handler, next_state, next_handler),
            MaterializedStateRoute(
                98,
                next_state,
                next_handler,
                source_handler_serial=handler,
                handler_exit_proven=True,
            ),
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({router}),
        authoritative_handler_serials=frozenset({handler, next_handler}),
    ) == [
        RedirectGoto(
            from_serial=handler,
            old_target=router,
            new_target=next_handler,
        )
    ]


def test_materialized_handler_local_entry_state_does_not_prove_exit(
    _seam,
) -> None:
    entry_state = 0x4A7ECCB8
    state_reg = 20
    handler = 10
    router = 20
    fg = FlowGraph(
        blocks={
            handler: _b(
                handler,
                (router,),
                (),
                (_mov_reg(0x40EF7D, entry_state, state_reg),),
            ),
            router: _b(router, (), (handler,)),
        },
        entry_serial=handler,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(99, entry_state, handler),
                MaterializedStateRoute(handler, entry_state, handler),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({router}),
            authoritative_handler_serials=frozenset({handler}),
        )
        == []
    )


def test_materialized_handler_ambiguous_replay_does_not_prove_clone_exit(
    _seam,
) -> None:
    next_state = 0xDC71BBC5
    state_reg = 20
    handler = 10
    router = 20
    first_target = 30
    second_target = 31
    fg = FlowGraph(
        blocks={
            handler: _b(
                handler,
                (router,),
                (),
                (_mov_reg(0x40EF7D, next_state, state_reg),),
            ),
            router: _b(router, (), (handler,)),
            first_target: _b(first_target, (), ()),
            second_target: _b(second_target, (), ()),
        },
        entry_serial=handler,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(handler, next_state, first_target),
                MaterializedStateRoute(
                    98,
                    next_state,
                    first_target,
                    source_handler_serial=handler,
                    handler_exit_proven=True,
                ),
                MaterializedStateRoute(
                    99,
                    next_state,
                    second_target,
                    source_handler_serial=handler,
                    handler_exit_proven=True,
                ),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({router}),
            authoritative_handler_serials=frozenset(
                {handler, first_target, second_target}
            ),
        )
        == []
    )


def test_materialized_handler_exit_collapses_two_way_dispatcher_port(
    _seam,
) -> None:
    state = 0x6EA4D36E
    state_reg = 20
    route = MaterializedStateRoute(
        10,
        state,
        30,
        source_handler_serial=5,
        handler_exit_proven=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (20, 21), (5,)),
            20: _b(20, (), (10,)),
            21: _b(21, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (route, route),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({20, 21}),
        authoritative_handler_serials=frozenset({30}),
    ) == [ConvertToGoto(block_serial=10, goto_target=30)]


def test_materialized_handler_exit_two_way_port_abstains_for_semantic_arm(
    _seam,
) -> None:
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(10, (20, 22), (5,)),
            20: _b(20, (), (10,)),
            22: _b(22, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(
                    10,
                    0x6EA4D36E,
                    30,
                    source_handler_serial=5,
                    handler_exit_proven=True,
                ),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({20}),
            authoritative_handler_serials=frozenset({30}),
        )
        == []
    )


def test_materialized_handler_exit_two_way_port_abstains_on_conflicting_route(
    _seam,
) -> None:
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(10, (20, 21), (5,)),
            20: _b(20, (), (10,)),
            21: _b(21, (), (10,)),
            30: _b(30, (), ()),
            31: _b(31, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(
                    10,
                    0x6EA4D36E,
                    30,
                    source_handler_serial=5,
                    handler_exit_proven=True,
                ),
                MaterializedStateRoute(
                    10,
                    0x6955B42A,
                    31,
                    source_handler_serial=5,
                    handler_exit_proven=True,
                ),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({20, 21}),
            authoritative_handler_serials=frozenset({30, 31}),
        )
        == []
    )


def test_materialized_handler_exit_rebinds_after_router_classification_is_lost(
    _seam,
) -> None:
    state = 0xB8D2E088
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(10, (11,), ()),
            11: _b(
                11,
                (20,),
                (10,),
                (),
            ),
            20: _b(20, (), (11,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )
    route = MaterializedStateRoute(
        11,
        state,
        30,
        source_handler_serial=10,
        handler_exit_proven=True,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (route,),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset(),
        authoritative_handler_serials=frozenset({30}),
    ) == [RedirectGoto(from_serial=11, old_target=20, new_target=30)]


def test_deferred_materialized_handler_exit_preserves_parent_path() -> None:
    route = MaterializedStateRoute(
        11,
        0xB8D2E088,
        30,
        source_handler_serial=10,
        handler_exit_proven=True,
    )

    assert _preserve_deferred_materialized_handler_exit_paths(
        [
            RedirectGoto(from_serial=10, old_target=11, new_target=10),
            RedirectGoto(from_serial=11, old_target=20, new_target=30),
        ],
        (route,),
    ) == [RedirectGoto(from_serial=11, old_target=20, new_target=30)]


def test_source_keyed_shared_terminal_redirects_each_owned_predecessor(
    _seam,
) -> None:
    """A shared computed-goto suffix must not be converted globally.

    Each proven handler arm owns the edge immediately preceding the shared
    zero-successor terminal.  Redirecting those predecessor edges preserves the
    sibling path while bypassing the computed-goto suffix for each exact arm.
    """
    fg = FlowGraph(
        blocks={
            10: _b(10, (12,), ()),
            11: _b(11, (13,), ()),
            12: _b(12, (14,), (10,)),
            13: _b(13, (14,), (11,)),
            14: _b(14, (), (12, 13)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    first = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                12,
                14,
                (10, 12, 14),
                source_keyed_block=10,
            ),
        ),
    )
    second = HandlerTransition(
        handler=11,
        states=(0x11,),
        arms=(
            TransitionArm(
                0x30,
                30,
                False,
                None,
                13,
                14,
                (11, 13, 14),
                source_keyed_block=11,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (first, second)) == [
        RedirectGoto(from_serial=12, old_target=14, new_target=20),
        RedirectGoto(from_serial=13, old_target=14, new_target=30),
    ]


def test_source_keyed_shared_terminal_with_call_abstains(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (12,), ()),
            12: _b(12, (14,), (10,)),
            13: _b(13, (14,), ()),
            14: _b(14, (), (12, 13), (_call_reg(0x1380, 7),)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                12,
                14,
                (10, 12, 14),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == []


def test_source_keyed_handler_owner_preserves_live_arm_to_known_handler(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), ()),
            11: _b(11, (20,), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), (11,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    stale_tail = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x30,
                30,
                False,
                None,
                11,
                11,
                (10, 11),
                source_keyed_block=10,
            ),
        ),
    )
    live_handler = HandlerTransition(handler=20, states=(0x20,), arms=())
    replacement_handler = HandlerTransition(handler=30, states=(0x30,), arms=())

    assert (
        build_source_keyed_handler_redirects(
            fg,
            (stale_tail, live_handler, replacement_handler),
        )
        == []
    )


def test_state_write_parent_preserves_fully_resolved_conditional_fork(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (13, 14)),
            10: _b(10, (11,), ()),
            11: _b(11, (12,), (10,)),
            12: _b(12, (13, 14), (11,)),
            13: _b(13, (8,), (12,)),
            14: _b(14, (8,), (12,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
            40: _b(40, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _disp(
        {0x20: 20, 0x30: 30, 0x40: 40},
        exit_block=99,
    )
    transitions = (
        StateWriteTransition(13, 0x30, 30, False, None),
        StateWriteTransition(14, 0x40, 40, False, None),
        StateWriteTransition(11, 0x20, 20, False, None, via_block=12),
    )

    assert build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=8,
        pre_header_serial=10,
        initial_state=None,
        strict_pre_header_prologue=True,
    ) == [
        RedirectGoto(from_serial=13, old_target=8, new_target=30),
        RedirectGoto(from_serial=14, old_target=8, new_target=40),
    ]


def test_materialized_conditional_handler_bridge_restores_folded_register_arm(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predicate = InsnSnapshot(opcode=55, ea=predicate_ea, operands=())
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(10, (8,), (), (predicate,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(20).start_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=0x1288,
    )

    assert build_materialized_conditional_handler_bridges(fg, (transfer,)) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=8,
            rewrite_from_ea=predicate_ea,
            condition_operand=SyntheticRegisterNonzeroCondition(44, 4),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_conditional_handler_bridge",
        )
    ]


def test_exact_live_state_edge_protects_existing_source_edge() -> None:
    fg = FlowGraph(
        blocks={
            146: _b(146, (243,), ()),
            243: _b(243, (), (146,)),
        },
        entry_serial=146,
        func_ea=0x40A560,
    )

    assert _exact_live_state_edge_keys(
        fg,
        (
            MaterializedStateRoute(
                146,
                0xA5540595,
                243,
                proof_kind="exact_live_state_edge",
            ),
            MaterializedStateRoute(146, 0xDEF4B7E6, 243),
        ),
    ) == {(146, 243)}


def test_applied_direct_boundary_anchors_protect_existing_live_edge() -> None:
    source_anchor_ea = 0x1290
    target_anchor_ea = 0x1510
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (InsnSnapshot(opcode=4, ea=source_anchor_ea, operands=()),),
            ),
            20: _b(
                20,
                (),
                (10,),
                (InsnSnapshot(opcode=4, ea=target_anchor_ea, operands=()),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x1280,
        source_instruction_ea=source_anchor_ea,
        endpoint_block_ea=0x1280,
        old_successor_eas=(),
        target_ea=0x1500,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(source_anchor_ea,),
                target_anchor_eas=(target_anchor_ea,),
            ),
        ),
    ) == {(10, 20)}


def test_applied_direct_boundary_prefers_attached_target_anchor_over_native_clone() -> (
    None
):
    endpoint_anchor_ea = 0x1290
    target_ea = 0x1500
    imported_target_anchor_ea = 0xF1C00234
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (21,),
                (),
                (InsnSnapshot(opcode=4, ea=endpoint_anchor_ea, operands=()),),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
            21: _b(
                21,
                (),
                (10,),
                (
                    InsnSnapshot(
                        opcode=4,
                        ea=imported_target_anchor_ea,
                        operands=(),
                    ),
                ),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x1280,
        source_instruction_ea=endpoint_anchor_ea,
        endpoint_block_ea=0x1280,
        old_successor_eas=(),
        target_ea=target_ea,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(endpoint_anchor_ea,),
                target_anchor_eas=(imported_target_anchor_ea,),
            ),
        ),
    ) == {(10, 21)}


def test_resolver_proven_router_port_is_a_dynamic_entry_bridge() -> None:
    endpoint_anchor_ea = 0x40D313
    router_ea = 0x40EAA7
    router_anchor_ea = 0xF1C01FD4
    fg = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            10: _b(
                10,
                (20,),
                (0,),
                (InsnSnapshot(opcode=4, ea=endpoint_anchor_ea, operands=()),),
            ),
            20: _b(
                20,
                (30, 40),
                (10,),
                (InsnSnapshot(opcode=4, ea=router_anchor_ea, operands=()),),
            ),
            30: _b(30, (), (20,)),
            40: _b(40, (), (20,)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=endpoint_anchor_ea,
        source_instruction_ea=0x40D348,
        endpoint_block_ea=endpoint_anchor_ea,
        old_successor_eas=(0x40D370,),
        target_ea=router_ea,
        state_register=28,
        state_constant=0x699BC698,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="redirect_edge",
        resolver_kind="residual_state_route_evidence",
    )
    evidence = AppliedDetachedSnippetDirectBoundaryPort(
        port=port,
        endpoint_anchor_eas=(endpoint_anchor_ea,),
        target_anchor_eas=(router_anchor_ea,),
    )
    router_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EAA5,
        source_block_ea=0x40EA9B,
        materialized_anchor_eas=(),
        target_eas=(0x40D370,),
        dispatcher_router_eas=(router_ea, 0x40D370),
    )

    assert _resolver_proven_dynamic_entry_edges(
        fg,
        (evidence,),
        (router_transfer,),
    ) == frozenset({(10, 20)})


def test_imported_router_origin_is_a_dynamic_entry_bridge() -> None:
    router_ea = 0x40EAA7
    router_anchor_ea = 0xF1C01FD4
    fg = FlowGraph(
        blocks={
            0: _b(0, (10, 50), ()),
            10: _b(
                10,
                (20,),
                (0,),
                (InsnSnapshot(opcode=4, ea=0x40D313, operands=()),),
            ),
            20: _b(
                20,
                (30, 40),
                (10,),
                (InsnSnapshot(opcode=4, ea=router_anchor_ea, operands=()),),
            ),
            30: _b(30, (), (20,)),
            40: _b(40, (), (20,)),
            50: BlockSnapshot(
                serial=50,
                block_type=0,
                succs=(60,),
                preds=(0,),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(),
            ),
            60: BlockSnapshot(
                serial=60,
                block_type=0,
                succs=(),
                preds=(50,),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0xF1C01000, operands=()),),
            ),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    router_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EAA5,
        source_block_ea=0x40EA9B,
        materialized_anchor_eas=(),
        target_eas=(0x40D370,),
        dispatcher_router_eas=(router_ea, 0x40D370, 0x40DBEA),
    )

    assert _resolver_proven_dynamic_entry_edges(
        fg,
        (),
        (router_transfer,),
        imported_native_eas_by_serial={
            20: frozenset({router_ea, 0x40EABA}),
            60: frozenset({0x40DBEA}),
        },
    ) == frozenset({(10, 20)})


def test_dynamic_entry_bridge_suppresses_scalar_entry_shortcut() -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1010, 0x20),)),
            20: _b(20, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = (StateWriteTransition(10, 0x20, 20, False, None),)

    mods = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=0x10,
        dynamic_entry_bridge_edges=frozenset({(0, 2)}),
    )

    redirects = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 20) in redirects
    assert not any(source == 0 for source, _old, _new in redirects)


def test_dynamic_entry_bridge_suppresses_materialized_scalar_route(_seam) -> None:
    state_reg = 28
    transient_state = 0x699BC698
    router_ea = 0x40EAA7
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (2,),
                (0,),
                (_mov_reg(0x1010, transient_state, state_reg),),
            ),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({transient_state: 10}, exit_block=99)
    router_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EAA5,
        source_block_ea=0x40EA9B,
        materialized_anchor_eas=(),
        target_eas=(0x1500,),
        dispatcher_router_eas=(router_ea,),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        initial_state=transient_state,
        materialized_computed_goto_profile=True,
        materialized_indirect_transfers=(router_transfer,),
        materialized_state_routes=(MaterializedStateRoute(1, transient_state, 10),),
        authoritative_handler_serials=frozenset({10}),
        dispatcher_region_serials=frozenset({2}),
        imported_native_eas_by_serial={2: frozenset({router_ea})},
    )

    assert not any(
        isinstance(modification, (RedirectGoto, RedirectBranch))
        and int(modification.from_serial) == 1
        and int(modification.old_target) == 2
        for modification in graph_modifications(plan)
    )


def test_applied_direct_boundary_tracks_folded_live_endpoint_into_predecessor() -> None:
    endpoint_ea = 0x1290
    target_ea = 0x1500
    fg = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(20,),
                preds=(),
                flags=0,
                start_ea=0x1200,
                insn_snapshots=(
                    InsnSnapshot(opcode=4, ea=0x1280, operands=()),
                    InsnSnapshot(opcode=55, ea=0x1000, operands=()),
                ),
            ),
            11: BlockSnapshot(
                serial=11,
                block_type=0,
                succs=(20,),
                preds=(),
                flags=0,
                start_ea=0x1800,
                insn_snapshots=(InsnSnapshot(opcode=55, ea=0x1000, operands=()),),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(10, 11),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
            21: BlockSnapshot(
                serial=21,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=endpoint_ea,
        source_instruction_ea=endpoint_ea,
        endpoint_block_ea=endpoint_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(0x1280, 0x1000),
                target_anchor_eas=(target_ea,),
            ),
        ),
    ) == {(10, 20)}


def test_applied_direct_boundary_ignores_stale_anchor_after_endpoint_fold() -> None:
    class EquivalentLiveOwner:
        value = DetachedSnippetBoundaryPortOwner.LIVE.value

    endpoint_ea = 0x1290
    target_ea = 0x1500
    stale_anchor_ea = 0x1270
    fg = FlowGraph(
        blocks={
            9: BlockSnapshot(
                serial=9,
                block_type=0,
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x1100,
                insn_snapshots=(
                    InsnSnapshot(opcode=4, ea=stale_anchor_ea, operands=()),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(20,),
                preds=(9,),
                flags=0,
                start_ea=0x1200,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0x1280, operands=()),),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(10, 11),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
            11: BlockSnapshot(
                serial=11,
                block_type=0,
                succs=(20,),
                preds=(),
                flags=0,
                start_ea=0x1600,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0x1600, operands=()),),
            ),
        },
        entry_serial=9,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=endpoint_ea,
        source_instruction_ea=endpoint_ea,
        endpoint_block_ea=endpoint_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=EquivalentLiveOwner(),  # type: ignore[arg-type]
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(stale_anchor_ea, 0x1280, 0x1600),
                target_anchor_eas=(target_ea,),
            ),
        ),
    ) == {(10, 20)}


def test_applied_conditional_boundary_protects_materialized_arm_corridors() -> None:
    predicate_ea = 0x1110
    taken_anchor_ea = 0x2010
    fallthrough_anchor_ea = 0x3010
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (11, 12),
                (),
                (InsnSnapshot(opcode=43, ea=predicate_ea, operands=()),),
            ),
            11: _b(11, (20,), (10,)),
            12: _b(12, (30,), (10,)),
            20: _b(
                20,
                (),
                (11,),
                (InsnSnapshot(opcode=4, ea=taken_anchor_ea, operands=()),),
            ),
            30: _b(
                30,
                (),
                (12,),
                (InsnSnapshot(opcode=4, ea=fallthrough_anchor_ea, operands=()),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x1100,
            predicate_ea=predicate_ea,
            old_taken_target_ea=0x1200,
            old_fallthrough_target_ea=0x1210,
            taken_target_ea=0x2000,
            fallthrough_target_ea=0x3000,
            state_register=20,
            taken_state=0xA0,
            fallthrough_state=0xB0,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            resolver_kind="static_fixpoint",
        ),
        taken_target_anchor_eas=(taken_anchor_ea,),
        fallthrough_target_anchor_eas=(fallthrough_anchor_ea,),
    )

    assert _applied_conditional_boundary_edge_keys(fg, (evidence,)) == {
        (10, 11),
        (11, 20),
        (10, 12),
        (12, 30),
    }


def test_state_write_redirect_does_not_override_protected_edge() -> None:
    fg = FlowGraph(
        blocks={
            2: _b(2, (), ()),
            10: _b(10, (20,), ()),
            20: _b(20, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(
        write_block=10,
        next_state=0x30,
        target_handler=30,
        is_return=False,
        branch_arm=None,
        via_block=20,
    )

    mods = build_state_write_redirects(
        fg,
        _disp({0x30: 30}, exit_block=99),
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        protected_edges=frozenset({(10, 20)}),
    )

    assert not [
        mod
        for mod in mods
        if isinstance(mod, RedirectGoto)
        and (mod.from_serial, mod.old_target) == (10, 20)
    ]


def test_materialized_conditional_handler_bridge_uses_post_predecessor_anchor(
    _seam,
) -> None:
    definition_ea = 0x1288
    merged_tail_ea = 0x1100
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(
                10,
                (8,),
                (),
                (
                    InsnSnapshot(opcode=4, ea=definition_ea, operands=()),
                    InsnSnapshot(opcode=55, ea=merged_tail_ea, operands=()),
                ),
            ),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1290,
        source_block_ea=0xDEAD,
        materialized_anchor_eas=(0x1290,),
        target_eas=(fg.get_block(20).start_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=definition_ea,
    )

    (modification,) = build_materialized_conditional_handler_bridges(fg, (transfer,))
    assert modification.rewrite_from_ea == merged_tail_ea


def test_materialized_conditional_handler_bridge_uses_current_state_route_when_target_ea_folds(
    _seam,
) -> None:
    definition_ea = 0x1288
    merged_tail_ea = 0x1100
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(
                10,
                (8,),
                (),
                (
                    InsnSnapshot(opcode=4, ea=definition_ea, operands=()),
                    InsnSnapshot(opcode=55, ea=merged_tail_ea, operands=()),
                ),
            ),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    true_state = 0x304E8694
    false_state = 0xA5A94B86
    dispatcher = _disp({true_state: 20, false_state: 30}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1290,
        source_block_ea=0xDEAD,
        materialized_anchor_eas=(0x1290,),
        target_eas=(0x40B342, 0x40B8E6),
        condition_code=5,
        true_target_ea=0x40B342,
        false_target_ea=0x40B8E6,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=definition_ea,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
    )

    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
    )
    assert modification.true_target_serial == 20
    assert modification.false_target_serial == 30


def test_materialized_conditional_handler_bridge_redirects_both_live_predicate_arms(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predecessor_ea = 0x1288
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (11, 12),
                (),
                (
                    InsnSnapshot(opcode=4, ea=predecessor_ea, operands=()),
                    predicate,
                ),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(20).start_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=predecessor_ea,
        predicate_true_is_taken=True,
    )

    assert build_materialized_conditional_handler_bridges(fg, (transfer,)) == [
        RedirectBranch(from_serial=10, old_target=12, new_target=20),
    ]


def test_materialized_conditional_handler_bridge_preserves_live_opaque_predicate(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            9: _b(9, (10,), ()),
            10: _b(
                10,
                (11, 12),
                (9,),
                (predicate,),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
            40: BlockSnapshot(
                serial=40,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x1000 + 10 * 0x40,
                insn_snapshots=(),
            ),
            41: _b(41, (42, 43), (), (predicate,)),
            42: _b(42, (), (41,)),
            43: _b(43, (), (41,)),
        },
        entry_serial=9,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40C16A, 0x40AAA2),
        condition_code=5,
        true_target_ea=0x40C16A,
        false_target_ea=0x40AAA2,
        resolver_kind="conditional_handler_bridge",
        predicate_register=None,
        # A live opaque predicate (including a memory comparison) does not
        # need a width because d810 preserves its existing microcode instead
        # of synthesizing a replacement operand.
        predicate_size=None,
        predicate_compare_constant=0x62,
        predicate_predecessor_ea=None,
        predicate_true_state=0xCCEC5DE0,
        predicate_false_state=0x742F372A,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    state_routes = (
        MaterializedStateRoute(10, 0xCCEC5DE0, 20),
        MaterializedStateRoute(10, 0x742F372A, 30),
    )
    assert (
        build_materialized_conditional_handler_bridges(
            fg,
            (transfer,),
            materialized_state_routes=state_routes[:1],
            handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
        )
        == []
    )
    assert build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        materialized_state_routes=state_routes,
        handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        ),
    ]
    assert build_materialized_conditional_handler_bridges(
        fg,
        (replace(transfer, condition_code=3),),
        materialized_state_routes=state_routes,
        handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        ),
    ]

    # PREOPT replay can publish the same live predicate twice: once under its
    # stable native EA and once under the imported synthetic instruction EA.
    # Equivalent source, polarity, and arm targets are corroborating evidence,
    # not an ambiguity that should erase the conditional.
    imported_predicate_ea = 0xF1C01008
    imported_predicate = replace(predicate, ea=imported_predicate_ea)
    imported_blocks = {
        serial: block
        for serial, block in fg.blocks.items()
        if serial not in {41, 42, 43}
    }
    imported_blocks[10] = replace(
        imported_blocks[10],
        insn_snapshots=(imported_predicate,),
    )
    imported_graph = FlowGraph(
        blocks=imported_blocks,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    synthetic_transfer = replace(
        transfer,
        source_jmp_ea=imported_predicate_ea,
        materialized_anchor_eas=(imported_predicate_ea,),
    )
    assert build_materialized_conditional_handler_bridges(
        imported_graph,
        (transfer, synthetic_transfer),
        materialized_state_routes=state_routes,
        handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
        imported_native_eas_by_serial={10: frozenset({predicate_ea})},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        ),
    ]


def test_applied_late_logical_source_owns_native_predicate_replay(
    _seam,
) -> None:
    owned_predicate_ea = 0x1290
    unrelated_predicate_ea = 0x1690

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=55,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (10, 40), ()),
            10: _b(10, (11, 12), (0,), (predicate(owned_predicate_ea, 12),)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
            40: _b(
                40,
                (41, 42),
                (0,),
                (predicate(unrelated_predicate_ea, 42),),
            ),
            41: _b(41, (), (40,)),
            42: _b(42, (), (40,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70

    def transfer(source: int, predicate_ea: int) -> MaterializedIndirectTransfer:
        return MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=flow_graph.get_block(source).start_ea,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(
                flow_graph.get_block(20).start_ea,
                flow_graph.get_block(30).start_ea,
            ),
            condition_code=5,
            true_target_ea=flow_graph.get_block(20).start_ea,
            false_target_ea=flow_graph.get_block(30).start_ea,
            resolver_kind="conditional_handler_bridge",
            predicate_size=4,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
        )

    owned_port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=flow_graph.get_block(10).start_ea,
        predicate_ea=owned_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=flow_graph.get_block(20).start_ea,
        fallthrough_target_ea=flow_graph.get_block(30).start_ea,
        state_register=20,
        taken_state=true_state,
        fallthrough_state=false_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="static_stack_carried_state_choice",
        logical_source_anchor_ea=0x1A00,
        predicate_ida_stkoff=0x44,
        predicate_stack_value=1,
        predicate_size=4,
        condition_code=5,
    )
    applied_evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=owned_port,
        taken_target_anchor_eas=(flow_graph.get_block(20).start_ea,),
        fallthrough_target_anchor_eas=(flow_graph.get_block(30).start_ea,),
    )
    modifications = build_materialized_conditional_handler_bridges(
        flow_graph,
        (
            transfer(10, owned_predicate_ea),
            transfer(40, unrelated_predicate_ea),
        ),
        materialized_state_routes=(
            MaterializedStateRoute(10, true_state, 20),
            MaterializedStateRoute(10, false_state, 30),
            MaterializedStateRoute(40, true_state, 20),
            MaterializedStateRoute(40, false_state, 30),
        ),
        handler_entry_eas_by_serial={
            20: flow_graph.get_block(20).start_ea,
            30: flow_graph.get_block(30).start_ea,
        },
        applied_conditional_boundary_evidence=(applied_evidence,),
    )

    assert [
        modification.rewrite_from_ea
        for modification in modifications
        if isinstance(modification, LowerConditionalStateTransition)
    ] == [unrelated_predicate_ea]


def test_emit_accepts_exact_materialized_conditional_entry_without_scalar_state(
    _seam,
    monkeypatch,
) -> None:
    """A live two-arm entry predicate is itself a complete entry bridge.

    Once PREOPT reconnects the entry predicate directly to two known handlers,
    walking from the function entry while merely removing the dispatcher also
    reaches those handlers' tails.  They must not be mistaken for unbridged
    prologue predecessors that require one scalar ``initial_state``.
    """
    predicate_ea = 0x1100
    true_state = 0xA0
    false_state = 0xB0
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=20, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (10, 20), (0,), (predicate,)),
            2: _b(2, (10, 20), (10, 20)),
            10: _b(10, (2,), (1, 2), (_mov_reg(0x1300, true_state, 20),)),
            20: _b(20, (2,), (1, 2), (_mov_reg(0x1400, false_state, 20),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({true_state: 20, false_state: 10}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=flow_graph.get_block(1).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(
            flow_graph.get_block(20).start_ea,
            flow_graph.get_block(10).start_ea,
        ),
        condition_code=5,
        true_target_ea=flow_graph.get_block(20).start_ea,
        false_target_ea=flow_graph.get_block(10).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        emit_module,
        "_recover_register_conditional_entry",
        lambda *_args, **_kwargs: [],
    )
    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=2,
        initial_state=None,
        materialized_indirect_transfers=(transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(1, true_state, 20),
            MaterializedStateRoute(1, false_state, 10),
        ),
        handler_entry_eas_by_serial={
            10: flow_graph.get_block(10).start_ea,
            20: flow_graph.get_block(20).start_ea,
        },
        materialized_computed_goto_profile=True,
    )
    assert any(
        isinstance(modification, LowerConditionalStateTransition)
        and modification.source_serial == 1
        and modification.false_target_serial == 10
        and modification.true_target_serial == 20
        for modification in graph_modifications(plan)
    )
    redirects = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (10, 2, 20) in redirects
    assert (20, 2, 10) in redirects


def test_bound_bootstrap_route_is_source_scoped_entry_proof() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,)),
            2: _b(2, (10,), (1, 10)),
            3: _b(3, (10,), (1,)),
            10: _b(10, (2,), (2, 3)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    source_ea = int(flow_graph.get_block(3).start_ea)
    handler_ea = int(flow_graph.get_block(10).start_ea)
    route = BootstrapRouteEvidence(
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 1),), native_key=NATIVE_KEY
        ),
        source_anchor_ea=source_ea,
        state=0x699BC698,
        handler_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_ea, handler_ea + 1),), native_key=NATIVE_KEY
        ),
        handler_anchor_ea=handler_ea,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    binding = BootstrapRouteBindingEvidence(
        route=route,
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 0x20),), native_key=NATIVE_KEY
        ),
        handler_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_ea, handler_ea + 0x20),), native_key=NATIVE_KEY
        ),
        evidence_generation=1,
    )

    proofs = _prove_bound_bootstrap_entry_routes(
        flow_graph,
        (binding,),
        dispatcher_entry_serial=2,
    )

    assert len(proofs) == 1
    assert (
        proofs[0].source_serial,
        proofs[0].handler_serial,
        proofs[0].state,
    ) == (3, 10, 0x699BC698)


def test_materialized_computed_goto_profile_recovers_multi_entry_state_writer(
    _seam,
) -> None:
    """A proven computed-goto profile owns state writes entering BST subtrees."""
    state = 0x20
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            2: _b(2, (20,), (12, 20)),
            10: _b(10, (11,), (0,), (_mov_state(0x1010, state),)),
            11: _b(11, (12,), (10,)),
            12: _b(12, (2,), (11,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        _disp({state: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        materialized_computed_goto_profile=True,
    )

    redirects = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (10, 11, 20) in redirects


def test_entry_bridge_prefers_unique_materialized_state_route_over_stale_map(
    _seam,
) -> None:
    initial_state = 0x34170401
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (20,), (1, 10, 20)),
            10: _b(10, (2,), ()),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    stale_dispatcher = _disp({0xB101A588: 20}, exit_block=99)

    modifications = build_state_write_redirects(
        flow_graph,
        stale_dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=initial_state,
        materialized_state_routes=(MaterializedStateRoute(1, initial_state, 10),),
    )

    assert modifications == [
        RedirectGoto(from_serial=1, old_target=2, new_target=10),
    ]


def test_scalar_entry_interval_target_must_be_a_known_handler() -> None:
    """An interval target outside the live handler set cannot bridge entry."""
    state = 0x16AA65E9
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 13, 20, 99), (0, 10, 13, 20)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
            20: _b(20, (2,), (2,)),
            99: replace(_b(99, (), (2,)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        # A broad interval has no independent exact/equality evidence for this
        # state; handler membership must therefore be authoritative.
        interval_rows=(IntervalRow(state, state + 2, 20),),
        default_target=99,
    )

    modifications = build_state_write_redirects(
        flow_graph,
        dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset(),
    )

    assert modifications == []


def test_materialized_state_entry_bridge_bypasses_proven_router_region() -> None:
    state = 0x34170401
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert build_materialized_state_entry_bridges(
        flow_graph,
        (MaterializedStateRoute(1, state, 10),),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({10}),
    ) == [
        RedirectGoto(from_serial=1, old_target=2, new_target=10),
    ]


def test_materialized_state_entry_bridge_abstains_on_conflicting_routes() -> None:
    state = 0x34170401
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert (
        build_materialized_state_entry_bridges(
            flow_graph,
            (
                MaterializedStateRoute(1, state, 10),
                MaterializedStateRoute(1, state, 20),
            ),
            dispatcher_region_serials=frozenset({2}),
            authoritative_handler_serials=frozenset({10, 20}),
        )
        == []
    )


def test_native_bound_state_entry_bridge_emits_exact_redirect() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert build_native_bound_state_entry_bridges(
        flow_graph,
        (_native_bound_route(source=1, state=0x10, target=10),),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({10}),
    ) == [
        RedirectGoto(from_serial=1, old_target=2, new_target=10),
    ]


def test_emit_deduplicates_agreeing_materialized_and_native_entry_routes(
    monkeypatch,
) -> None:
    """Agreeing providers emit one operation for one source edge."""
    state = 0x16AA65E9
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 13), (1, 10, 13)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x3000,
    )
    dispatcher = _disp({state: 10}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        materialized_computed_goto_profile=True,
        materialized_state_routes=(MaterializedStateRoute(1, state, 10),),
        native_bound_transition_routes=(
            _native_bound_route(source=1, state=state, target=10),
        ),
        authoritative_handler_serials=frozenset({10, 13}),
    )

    assert [
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
        and (modification.from_serial, modification.old_target)
        == (1, 2)
    ] == [RedirectGoto(from_serial=1, old_target=2, new_target=10)]


@pytest.mark.parametrize(
    "routes, blocks, routers, handlers",
    [
        (
            (_native_bound_route(source=1, state=0x10, target=11),),
            {
                0: _b(0, (1,), ()),
                1: _b(1, (2,), (0,)),
                2: _b(2, (10,), (1, 10)),
                10: _b(10, (2,), (2,)),
            },
            {2},
            {10},
        ),
        (
            (_native_bound_route(source=1, state=0x10, target=10),),
            {
                0: _b(0, (1,), ()),
                1: _b(1, (2, 3), (0,)),
                2: _b(2, (10,), (1,)),
                3: _b(3, (10,), (1,)),
                10: _b(10, (2,), (2,)),
            },
            {2},
            {10},
        ),
        (
            (
                _native_bound_route(source=1, state=0x10, target=10, fact_id="a"),
                _native_bound_route(source=1, state=0x20, target=20, fact_id="b"),
            ),
            {
                0: _b(0, (1,), ()),
                1: _b(1, (2,), (0,)),
                2: _b(2, (10, 20), (1,)),
                10: _b(10, (2,), (2,)),
                20: _b(20, (2,), (2,)),
            },
            {2},
            {10, 20},
        ),
        (
            (_native_bound_route(source=1, state=0x10, target=2),),
            {
                0: _b(0, (1,), ()),
                1: _b(1, (2,), (0,)),
                2: _b(2, (10,), (1,)),
                10: _b(10, (2,), (2,)),
            },
            {2},
            {2},
        ),
    ],
    ids=("mismatch", "fork", "conflict", "handler-in-topology"),
)
def test_native_bound_state_entry_bridge_abstains_on_ambiguous_or_topology_routes(
    routes, blocks, routers, handlers
) -> None:
    flow_graph = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)

    assert (
        build_native_bound_state_entry_bridges(
            flow_graph,
            routes,
            dispatcher_region_serials=frozenset(routers),
            authoritative_handler_serials=frozenset(handlers),
        )
        == []
    )


def test_native_bound_state_entry_bridge_preserves_existing_backedge() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert build_native_bound_state_entry_bridges(
        flow_graph,
        (_native_bound_route(source=10, state=0x10, target=20),),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({20}),
    ) == []


def test_emit_accepts_applied_preopt_conditional_port_when_one_router_row_was_pruned(
    _seam,
    monkeypatch,
) -> None:
    predicate_ea = 0x1100
    taken_state = 0xA0
    fallthrough_state = 0xB0
    taken_target_ea = 0x1500
    fallthrough_target_ea = 0x1600
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=20, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 20), (0,), (predicate,)),
            2: _b(2, (10,), (1,)),
            3: _b(3, (10, 20), (10, 20)),
            10: _b(10, (3,), (2, 3), (_mov_reg(0x1300, taken_state, 20),)),
            20: _b(20, (3,), (1, 3), (_mov_reg(0x1400, fallthrough_state, 20),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # The imported arm anchor is authoritative even when CALLS pruning removed
    # one state from the equality-router map.  This is the real-loader shape:
    # the fallthrough state remains in the map while the taken state's detached
    # handler is reachable only through the applied PREOPT boundary port.
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(
                lo=fallthrough_state,
                hi=fallthrough_state + 1,
                target=10,
            )
        ],
        compute_default=False,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x1080,
        predicate_ea=predicate_ea,
        old_taken_target_ea=0x1200,
        old_fallthrough_target_ea=0x1210,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        state_register=20,
        taken_state=taken_state,
        fallthrough_state=fallthrough_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="static_fixpoint",
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        # The taken target's PREOPT instructions were all folded away before
        # CALLS; the exact applied predicate and its surviving taken arm remain.
        taken_target_anchor_eas=(0xDEAD,),
        fallthrough_target_anchor_eas=(0x1300,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        emit_module,
        "_recover_register_conditional_entry",
        lambda *_args, **_kwargs: [],
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=3,
        initial_state=None,
        imported_conditional_boundary_evidence=(evidence,),
        handler_entry_eas_by_serial={
            10: fallthrough_target_ea,
        },
        materialized_computed_goto_profile=True,
        authoritative_handler_serials=frozenset({10}),
    )

    redirects = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (20, 3, 10) in redirects


def test_imported_conditional_entry_prefers_native_origin_over_stale_arm_anchor() -> (
    None
):
    predicate_ea = 0x1100
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=3, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (20,), (1,)),
            3: _b(3, (30,), (1,)),
            20: _b(20, (), (2,), (_mov_reg(0xF100, 0xB0, 20),)),
            30: _b(30, (), (3,), (_mov_reg(0xF200, 0xA0, 20),)),
            # A maturity-local clone retained the old arm anchor but is not the
            # block reached by the successfully applied conditional port.
            40: _b(40, (), (), (_mov_reg(0xDEAD, 0xB0, 20),)),
            50: _b(50, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x1080,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=0x1500,
        fallthrough_target_ea=0x1600,
        state_register=20,
        taken_state=0xA0,
        fallthrough_state=0xB0,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="resolver_proven_static_conditional_state_choice",
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        taken_target_anchor_eas=(0xF200,),
        fallthrough_target_anchor_eas=(0xDEAD,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({20, 30, 40}),
        state_var_reg=20,
        imported_native_eas_by_serial={
            20: frozenset({0x1600}),
            30: frozenset({0x1500}),
        },
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        forecasts=(
            ConditionalEntryBridgeForecast(
                source_serial=1,
                predicate_ea=predicate_ea,
                false_target_serial=20,
                true_target_serial=30,
            ),
        ),
        root_source_serials=(1,),
    )


def test_imported_conditional_entry_prefers_canonical_handler_for_leaf_ea() -> None:
    predicate_ea = 0x40D299
    taken_target_ea = 0x40EFDD
    fallthrough_target_ea = 0x40D668
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (30,), (1,)),
            3: _b(3, (40,), (1,)),
            # PREOPT imported ownership clones reached by the applied arms.
            30: _b(30, (50,), (2,)),
            40: _b(40, (50,), (3,)),
            # Canonical equality-router handlers for the same native EAs.
            10: _b(10, (50,), (50,)),
            20: _b(20, (50,), (50,)),
            50: _b(50, (10, 20), (10, 20, 30, 40)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D252,
            predicate_ea=predicate_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_target_ea,
            fallthrough_target_ea=fallthrough_target_ea,
            state_register=28,
            taken_state=0xB13A6E93,
            fallthrough_state=0x4D34CF70,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_conditional_state_choice",
        ),
        taken_target_anchor_eas=(),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        imported_native_eas_by_serial={
            30: frozenset({taken_target_ea}),
            40: frozenset({fallthrough_target_ea}),
        },
        handler_entry_eas_by_serial={
            10: taken_target_ea,
            20: fallthrough_target_ea,
        },
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        forecasts=(
            ConditionalEntryBridgeForecast(
                source_serial=1,
                predicate_ea=predicate_ea,
                false_target_serial=20,
                true_target_serial=10,
            ),
        ),
        root_source_serials=(1,),
    )


def test_imported_conditional_entry_abstains_on_ambiguous_leaf_handler_ea() -> None:
    predicate_ea = 0x40D299
    taken_target_ea = 0x40EFDD
    fallthrough_target_ea = 0x40D668
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (30,), (1,)),
            3: _b(3, (40,), (1,)),
            10: _b(10, (50,), (50,)),
            11: _b(11, (50,), (50,)),
            20: _b(20, (50,), (50,)),
            30: _b(30, (50,), (2,)),
            40: _b(40, (50,), (3,)),
            50: _b(50, (10, 11, 20), (10, 11, 20, 30, 40)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D252,
            predicate_ea=predicate_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_target_ea,
            fallthrough_target_ea=fallthrough_target_ea,
            state_register=28,
            taken_state=0xB13A6E93,
            fallthrough_state=0x4D34CF70,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_conditional_state_choice",
        ),
        taken_target_anchor_eas=(),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    assert (
        emit_module._plan_imported_conditional_entry_bridges(
            flow_graph,
            (evidence,),
            dispatcher_entry_serial=50,
            handler_serials=frozenset({10, 11, 20}),
            state_var_reg=28,
            imported_native_eas_by_serial={
                30: frozenset({taken_target_ea}),
                40: frozenset({fallthrough_target_ea}),
            },
            handler_entry_eas_by_serial={
                10: taken_target_ea,
                11: taken_target_ea,
                20: fallthrough_target_ea,
            },
        )
        is None
    )


def test_imported_conditional_entry_routes_both_states_to_authoritative_handlers() -> (
    None
):
    predicate_ea = 0x40D266
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (40,), (1,)),
            3: _b(3, (30,), (1,)),
            # Applied PREOPT clone targets.
            30: _b(30, (50,), (3,)),
            40: _b(40, (50,), (2,)),
            # Authoritative equality-router handlers for the two states.
            10: _b(10, (50,), ()),
            20: _b(20, (50,), ()),
            50: _b(50, (10, 20), (10, 20, 30, 40)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x40D252,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        # The live jge is the inverse of the native cmovl condition.
        taken_target_ea=0x40F20B,
        fallthrough_target_ea=0x40DABB,
        state_register=28,
        taken_state=false_state,
        fallthrough_state=true_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="resolver_proven_static_stack_carried_entry_choice",
        predicate_true_is_taken=False,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        taken_target_anchor_eas=(0xF1C02000,),
        fallthrough_target_anchor_eas=(0xF1C01000,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        materialized_state_routes=(
            MaterializedStateRoute(100, true_state, 10),
            MaterializedStateRoute(101, false_state, 20),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        forecasts=(
            ConditionalEntryBridgeForecast(
                source_serial=1,
                predicate_ea=predicate_ea,
                false_target_serial=20,
                true_target_serial=10,
                true_is_taken=False,
            ),
        ),
        root_source_serials=(1,),
    )


def test_imported_conditional_entry_binds_distinct_logical_source_owner() -> None:
    proof_predicate_ea = 0x40D221
    logical_source_ea = 0x40E9A8
    live_predicate_ea = 0xF1C02004
    true_state = 0x142718FC
    false_state = 0xF6D08EC5

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=50,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (4,), ()),
            # The original proof predicate remains elsewhere in the MBA.  It
            # is not the source where PREOPT applied the logical boundary.
            1: _b(1, (6, 7), (), (predicate(proof_predicate_ea, 6),)),
            4: _b(4, (2, 3), (0,), (predicate(live_predicate_ea, 2),)),
            2: _b(2, (10,), (4,)),
            3: _b(3, (20,), (4,)),
            6: _b(6, (50,), (1,)),
            7: _b(7, (50,), (1,)),
            10: _b(10, (50,), (2, 50)),
            20: _b(20, (50,), (3, 50)),
            50: _b(50, (10, 20), (6, 7, 10, 20)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D200,
            predicate_ea=proof_predicate_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=0x40F1C1,
            fallthrough_target_ea=0x40DDB0,
            state_register=28,
            taken_state=true_state,
            fallthrough_state=false_state,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_stack_carried_entry_choice",
            logical_source_anchor_ea=logical_source_ea,
            logical_source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            logical_source_replaces_dispatcher_envelope=True,
        ),
        taken_target_anchor_eas=(),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        imported_native_eas_by_serial={
            4: frozenset({logical_source_ea}),
        },
        materialized_state_routes=(
            MaterializedStateRoute(100, true_state, 10),
            MaterializedStateRoute(101, false_state, 20),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        forecasts=(
            ConditionalEntryBridgeForecast(
                source_serial=4,
                predicate_ea=live_predicate_ea,
                false_target_serial=20,
                true_target_serial=10,
            ),
        ),
        root_source_serials=(4,),
    )


def test_imported_conditional_entry_abstains_on_unproven_nested_boundary_sources() -> (
    None
):
    predicate_ea = 0x40D266
    false_nested_predicate_ea = 0x40D2BC
    true_nested_predicate_ea = 0x40D299
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (20,), (1,), (_mov_reg(false_nested_predicate_ea, 1, 8),)),
            3: _b(3, (10,), (1,), (_mov_reg(true_nested_predicate_ea, 1, 8),)),
            10: _b(10, (50,), (3,)),
            20: _b(20, (50,), (2,)),
            50: _b(50, (10, 20), (10, 20)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x40D200,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=false_nested_predicate_ea,
        fallthrough_target_ea=true_nested_predicate_ea,
        state_register=28,
        taken_state=false_state,
        fallthrough_state=true_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        resolver_kind="resolver_proven_static_conditional_state_choice",
        predicate_true_is_taken=False,
        taken_target_is_boundary_source=True,
        fallthrough_target_is_boundary_source=True,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        taken_target_anchor_eas=(false_nested_predicate_ea,),
        fallthrough_target_anchor_eas=(true_nested_predicate_ea,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        materialized_state_routes=(
            MaterializedStateRoute(100, true_state, 10),
            MaterializedStateRoute(101, false_state, 20),
        ),
    )

    assert plan is None


def test_imported_conditional_entry_plan_includes_complete_nested_tree() -> None:
    outer_ea = 0x40D266
    taken_nested_ea = 0x40D2BC
    fallthrough_nested_ea = 0x40D299
    state_reg = 28
    states = (0x10, 0x20, 0x30, 0x40)

    def predicate(ea: int, taken_serial: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=50,
            ea=ea,
            operands=(),
            d=MopSnapshot(
                t=0,
                size=0,
                block_ref=taken_serial,
                kind=OperandKind.BLOCK,
            ),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate(outer_ea, 2),)),
            2: _b(2, (20, 21), (1,), (predicate(taken_nested_ea, 20),)),
            3: _b(3, (30, 31), (1,), (predicate(fallthrough_nested_ea, 30),)),
            20: _b(20, (50,), (2, 50)),
            21: _b(21, (50,), (2, 50)),
            30: _b(30, (50,), (3, 50)),
            31: _b(31, (50,), (3, 50)),
            50: _b(50, (20, 21, 30, 31), (20, 21, 30, 31)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    outer = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D200,
            predicate_ea=outer_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_nested_ea,
            fallthrough_target_ea=fallthrough_nested_ea,
            state_register=state_reg,
            taken_state=states[0],
            fallthrough_state=states[1],
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            resolver_kind="resolver_proven_static_conditional_state_choice",
            taken_target_is_boundary_source=True,
            fallthrough_target_is_boundary_source=True,
        ),
        taken_target_anchor_eas=(taken_nested_ea,),
        fallthrough_target_anchor_eas=(fallthrough_nested_ea,),
    )

    def nested_evidence(
        predicate_ea: int,
        taken_state: int,
        fallthrough_state: int,
    ) -> AppliedDetachedSnippetConditionalBoundaryPort:
        return AppliedDetachedSnippetConditionalBoundaryPort(
            port=DetachedSnippetConditionalBoundaryPort(
                source_block_ea=predicate_ea,
                predicate_ea=predicate_ea,
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=0xF0000000 + taken_state,
                fallthrough_target_ea=0xF0000000 + fallthrough_state,
                state_register=state_reg,
                taken_state=taken_state,
                fallthrough_state=fallthrough_state,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                resolver_kind="resolver_proven_static_conditional_state_choice",
            ),
            taken_target_anchor_eas=(),
            fallthrough_target_anchor_eas=(),
        )

    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (
            outer,
            nested_evidence(taken_nested_ea, states[0], states[1]),
            nested_evidence(fallthrough_nested_ea, states[2], states[3]),
        ),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({20, 21, 30, 31}),
        state_var_reg=state_reg,
        materialized_state_routes=(
            MaterializedStateRoute(100, states[0], 20),
            MaterializedStateRoute(101, states[1], 21),
            MaterializedStateRoute(102, states[2], 30),
            MaterializedStateRoute(103, states[3], 31),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        forecasts=(
            ConditionalEntryBridgeForecast(1, outer_ea, 3, 2),
            ConditionalEntryBridgeForecast(2, taken_nested_ea, 21, 20),
            ConditionalEntryBridgeForecast(
                3,
                fallthrough_nested_ea,
                31,
                30,
            ),
        ),
        root_source_serials=(1,),
    )
    lowerings = emit_module._lower_conditional_entry_bridge_plan(
        flow_graph,
        plan,
    )
    assert tuple(lowering.source_serial for lowering in lowerings) == (1, 2, 3)


def test_imported_conditional_entry_plan_abstains_on_missing_nested_source() -> None:
    outer_ea = 0x40D266
    nested_ea = 0x40D2BC
    predicate = InsnSnapshot(
        opcode=50,
        ea=outer_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 20), (0,), (predicate,)),
            2: _b(2, (20,), (1,), (_mov_reg(nested_ea, 1, 8),)),
            20: _b(20, (50,), (1, 2, 50)),
            50: _b(50, (20,), (20,)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D200,
            predicate_ea=outer_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=nested_ea,
            fallthrough_target_ea=0x40D400,
            state_register=28,
            taken_state=0x10,
            fallthrough_state=0x20,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_conditional_state_choice",
            taken_target_is_boundary_source=True,
        ),
        taken_target_anchor_eas=(nested_ea,),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    assert (
        emit_module._plan_imported_conditional_entry_bridges(
            flow_graph,
            (evidence,),
            dispatcher_entry_serial=50,
            handler_serials=frozenset({20}),
            state_var_reg=28,
            materialized_state_routes=(MaterializedStateRoute(100, 0x20, 20),),
        )
        is None
    )


def test_imported_conditional_entry_plan_ignores_handler_local_ambiguity() -> None:
    entry_ea = 0x40D266
    handler_ea = 0x40D4A2
    state_reg = 28

    def predicate(ea: int, target: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=50,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=target, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (20, 21), (0,), (predicate(entry_ea, 20),)),
            20: _b(20, (21, 50), (1, 50), (predicate(handler_ea, 21),)),
            21: _b(21, (50,), (1, 20, 50)),
            50: _b(50, (20, 21), (20, 21)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    def evidence(
        predicate_ea: int,
        taken_state: int,
        fallthrough_state: int,
    ) -> AppliedDetachedSnippetConditionalBoundaryPort:
        return AppliedDetachedSnippetConditionalBoundaryPort(
            port=DetachedSnippetConditionalBoundaryPort(
                source_block_ea=predicate_ea,
                predicate_ea=predicate_ea,
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=0xF0000000 + taken_state,
                fallthrough_target_ea=0xF0000000 + fallthrough_state,
                state_register=state_reg,
                taken_state=taken_state,
                fallthrough_state=fallthrough_state,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                resolver_kind="resolver_proven_static_conditional_state_choice",
            ),
            taken_target_anchor_eas=(),
            fallthrough_target_anchor_eas=(),
        )

    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (
            evidence(entry_ea, 0x10, 0x20),
            evidence(handler_ea, 0x20, 0x10),
            evidence(handler_ea, 0x30, 0x40),
        ),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({20, 21}),
        state_var_reg=state_reg,
        materialized_state_routes=(
            MaterializedStateRoute(100, 0x10, 20),
            MaterializedStateRoute(101, 0x20, 21),
            MaterializedStateRoute(102, 0x30, 20),
            MaterializedStateRoute(103, 0x40, 21),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        forecasts=(ConditionalEntryBridgeForecast(1, entry_ea, 21, 20),),
        root_source_serials=(1,),
    )


def test_emit_does_not_accept_handler_local_conditional_as_entry_bridge(
    _seam,
    monkeypatch,
) -> None:
    predicate_ea = 0x1280
    true_state = 0xA0
    false_state = 0xB0
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=30, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            2: _b(2, (10, 20, 30), (20, 30)),
            10: _b(10, (20, 30), (0, 2), (predicate,)),
            20: _b(20, (2,), (10, 2)),
            30: _b(30, (2,), (10, 2)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({true_state: 30, false_state: 20}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=flow_graph.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(
            flow_graph.get_block(30).start_ea,
            flow_graph.get_block(20).start_ea,
        ),
        condition_code=5,
        true_target_ea=flow_graph.get_block(30).start_ea,
        false_target_ea=flow_graph.get_block(20).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        emit_module,
        "_recover_register_conditional_entry",
        lambda *_args, **_kwargs: [],
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=2,
        initial_state=None,
        materialized_indirect_transfers=(transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(10, true_state, 30),
            MaterializedStateRoute(10, false_state, 20),
        ),
        handler_entry_eas_by_serial={
            20: flow_graph.get_block(20).start_ea,
            30: flow_graph.get_block(30).start_ea,
        },
        materialized_computed_goto_profile=True,
        authoritative_handler_serials=frozenset({10, 20, 30}),
    )

    assert not graph_modifications(plan)


def test_live_predicate_keeps_exact_arm_when_state_route_precedes_it(
    _seam,
) -> None:
    predicate_ea = 0x1290
    true_state = 0x304E8694
    false_state = 0xA5A94B86
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), (21,)),
            21: _b(21, (20,), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(
            fg.get_block(20).start_ea,
            fg.get_block(30).start_ea,
        ),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(12, true_state, 21),
            MaterializedStateRoute(11, false_state, 30),
        ),
        handler_entry_eas_by_serial={
            21: fg.get_block(20).start_ea,
            30: fg.get_block(30).start_ea,
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_uses_native_anchored_dispatcher_targets(_seam) -> None:
    """Canonical dispatcher rows can prove both arms without source routes."""
    predicate_ea = 0xF1C000B8
    true_state = 0x5C46FC3C
    false_state = 0x3EEFBA76
    true_target_ea = 0x40CF38
    false_target_ea = 0x40CF01
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _disp(
        {true_state: 20, false_state: 30},
        exit_block=99,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=flow_graph.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=dispatcher,
        handler_entry_eas_by_serial={
            20: true_target_ea,
            30: false_target_ea,
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{flow_graph.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_resolves_imported_source_by_native_origin(_seam) -> None:
    native_predicate_ea = 0x40F651
    imported_predicate_ea = 0xF1C01234
    true_state = 0x53514884
    false_state = 0xF940AB9D
    true_target_ea = 0x40F453
    false_target_ea = 0x40E3F0
    predicate = InsnSnapshot(
        opcode=55,
        ea=imported_predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(11, 12),
                preds=(9,),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(predicate,),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            13: BlockSnapshot(
                serial=13,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0xF1C05678, operands=()),),
            ),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=native_predicate_ea,
        source_block_ea=0x40D200,
        materialized_anchor_eas=(native_predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=_disp({}, exit_block=99),
        handler_entry_eas_by_serial={
            20: true_target_ea,
            30: false_target_ea,
        },
        imported_native_eas_by_serial={
            10: frozenset({native_predicate_ea}),
            13: frozenset({0x40F700}),
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                "source_ea=0x40D200:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{native_predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_resolves_duplicate_imports_by_native_handler_entry(
    _seam,
) -> None:
    native_source_entry_ea = 0x40B199
    native_predicate_ea = 0x40B1B0
    imported_predicate_ea = 0xF1C00A74
    shadow_predicate_ea = 0xF1C10A74
    true_state = 0x65203D55
    false_state = 0x4DFFC906
    true_target_ea = 0x40A868
    false_target_ea = 0x40A9AE

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=55,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(11, 12),
                preds=(9,),
                flags=0,
                start_ea=0x40A560,
                insn_snapshots=(predicate(imported_predicate_ea, 12),),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            13: BlockSnapshot(
                serial=13,
                block_type=0,
                succs=(14, 15),
                preds=(),
                flags=0,
                start_ea=0x40A560,
                insn_snapshots=(predicate(shadow_predicate_ea, 15),),
            ),
            14: _b(14, (), (13,)),
            15: _b(15, (), (13,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=native_predicate_ea,
        source_block_ea=native_source_entry_ea,
        materialized_anchor_eas=(native_predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_compare_constant=0x40,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=_disp({true_state: 20, false_state: 30}, exit_block=99),
        handler_entry_eas_by_serial={
            10: native_source_entry_ea,
            20: true_target_ea,
            30: false_target_ea,
        },
        imported_native_eas_by_serial={
            10: frozenset({native_predicate_ea}),
            13: frozenset({native_predicate_ea}),
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                "source_ea=0x40A560:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{native_predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_prefers_authoritative_imported_handler_over_native_clone(
    _seam,
) -> None:
    native_source_entry_ea = 0x40B03E
    native_predecessor_ea = 0x40B04A
    native_predicate_ea = 0x40B053
    imported_predicate_ea = 0xF1C008E4
    true_state = 0x456A4274
    false_state = 0xF32B2D3A
    true_target_ea = 0x40B199
    false_target_ea = 0x40BF1B

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=55,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            9: BlockSnapshot(
                serial=9,
                block_type=0,
                succs=(11, 12),
                preds=(8,),
                flags=0,
                start_ea=0x40B032,
                insn_snapshots=(predicate(native_predicate_ea, 12),),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(13, 14),
                preds=(7,),
                flags=0,
                start_ea=0x40A560,
                insn_snapshots=(predicate(imported_predicate_ea, 14),),
            ),
            11: _b(11, (), (9,)),
            12: _b(12, (), (9,)),
            13: _b(13, (), (10,)),
            14: _b(14, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=native_predicate_ea,
        source_block_ea=native_source_entry_ea,
        materialized_anchor_eas=(native_predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=13,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="static_conditional_state_choice_bridge",
        predicate_predecessor_ea=native_predecessor_ea,
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=_disp({true_state: 20, false_state: 30}, exit_block=99),
        handler_entry_eas_by_serial={
            10: native_source_entry_ea,
            20: true_target_ea,
            30: false_target_ea,
        },
        imported_native_eas_by_serial={
            10: frozenset({native_predecessor_ea, native_predicate_ea}),
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=14,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                "source_ea=0x40A560:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{native_predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_abstains_when_state_route_does_not_match_exact_arm_ea(
    _seam,
) -> None:
    predicate_ea = 0x40B2B1
    true_state = 0xA5540595
    false_state = 0xDEF4B7E6
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            30: BlockSnapshot(
                serial=30,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40BC21,
                insn_snapshots=(),
            ),
            40: BlockSnapshot(
                serial=40,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40BFB2,
                insn_snapshots=(),
            ),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40C4F6, 0x40BC21),
        condition_code=5,
        true_target_ea=0x40C4F6,
        false_target_ea=0x40BC21,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert (
        build_materialized_conditional_handler_bridges(
            fg,
            (transfer,),
            materialized_state_routes=(
                MaterializedStateRoute(12, true_state, 40),
                MaterializedStateRoute(11, false_state, 30),
            ),
        )
        == []
    )


def test_live_predicate_accepts_exact_arm_corridor_into_mapped_handler(
    _seam,
) -> None:
    predicate_ea = 0xF1C01534
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    native_true_leaf = BlockSnapshot(
        serial=50,
        block_type=1,
        succs=(11,),
        preds=(),
        flags=0,
        start_ea=0x40B3F3,
        insn_snapshots=(
            InsnSnapshot(
                opcode=4,
                ea=0x40B40C,
                operands=(),
                kind=InsnKind.MOV,
            ),
        ),
    )
    imported_true_handler = BlockSnapshot(
        serial=20,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40A560,
        insn_snapshots=(),
    )
    false_handler = BlockSnapshot(
        serial=30,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40C1A0,
        insn_snapshots=(),
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: imported_true_handler,
            30: false_handler,
            50: native_true_leaf,
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B3F3, 0x40C1A0),
        condition_code=5,
        true_target_ea=0x40B3F3,
        false_target_ea=0x40C1A0,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(12, true_state, 20),
            MaterializedStateRoute(11, false_state, 30),
        ),
        handler_entry_eas_by_serial={20: 0x40B3FF, 30: 0x40C1A0},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_materialized_conditional_handler_bridge_prefers_source_keyed_replacement(
    _seam,
) -> None:
    predicate_ea = 0x40C5D1
    true_state = 0x78BAC34B
    false_state = 0x1F0B7687
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            9: _b(9, (10,), ()),
            10: _b(10, (11, 12), (9,), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40A7AE,
                insn_snapshots=(),
            ),
            30: _b(30, (), ()),
            40: _b(40, (), ()),
        },
        entry_serial=9,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(40).start_ea, 0x40A7AE),
        condition_code=5,
        true_target_ea=fg.get_block(40).start_ea,
        false_target_ea=0x40A7AE,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    dispatcher = _disp({true_state: 40, false_state: 20}, exit_block=99)

    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
        materialized_state_routes=(
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        handler_entry_eas_by_serial={30: 0x40A7AE},
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40


def test_materialized_conditional_handler_bridge_maps_folded_target_prefix(
    _seam,
) -> None:
    predicate_ea = 0xF1C015DC
    true_state = 0xBC6EC36C
    false_state = 0x67B7A2BD
    false_handler_entry = 0x40ED00
    false_target_ea = 0x40ED0C
    next_handler_entry = 0x40EE00
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    false_handler = BlockSnapshot(
        serial=30,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=false_handler_entry,
        insn_snapshots=(
            InsnSnapshot(opcode=4, ea=0x40ED14, operands=()),
            InsnSnapshot(opcode=55, ea=0x40ED65, operands=()),
        ),
    )
    fg = FlowGraph(
        blocks={
            9: _b(9, (10,), ()),
            10: _b(10, (11, 12), (9,), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            30: false_handler,
            31: BlockSnapshot(
                serial=31,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=next_handler_entry,
                insn_snapshots=(),
            ),
            40: _b(40, (), ()),
        },
        entry_serial=9,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(40).start_ea, false_target_ea),
        condition_code=5,
        true_target_ea=fg.get_block(40).start_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    dispatcher = _disp({true_state: 40, false_state: 30}, exit_block=99)

    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
        materialized_state_routes=(
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        # The exact live route can be outside the recovered handler registry;
        # its current block provenance must still prove the folded prefix.
        handler_entry_eas_by_serial={31: next_handler_entry},
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40

    # A route's recovered handler entry can be the only later registry label.
    # The exact branch target may still be folded between that entry and the
    # route's first surviving instruction.  The route-local bounded interval
    # must remain authoritative instead of requiring an unrelated next
    # handler entry to bound the lookup.
    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
        materialized_state_routes=(
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        handler_entry_eas_by_serial={30: false_handler_entry},
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40

    imported_shadow_serial = 32
    blocks_with_shadow = dict(fg.blocks)
    blocks_with_shadow[30] = replace(false_handler, preds=(9,))
    blocks_with_shadow[imported_shadow_serial] = replace(
        false_handler,
        serial=imported_shadow_serial,
        start_ea=fg.func_ea,
    )
    graph_with_shadow = FlowGraph(
        blocks=blocks_with_shadow,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    route_args = {
        "dispatcher": dispatcher,
        "materialized_state_routes": (
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        "handler_entry_eas_by_serial": {30: false_handler_entry},
    }
    assert (
        build_materialized_conditional_handler_bridges(
            graph_with_shadow,
            (transfer,),
            **route_args,
        )
        == []
    )
    (modification,) = build_materialized_conditional_handler_bridges(
        graph_with_shadow,
        (transfer,),
        imported_native_eas_by_serial={
            30: frozenset({0x40ED14, 0x40ED65}),
            imported_shadow_serial: frozenset({0x40ED14, 0x40ED65}),
        },
        **route_args,
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40


def test_degenerate_branch_redirect_becomes_goto(_seam) -> None:
    fg = FlowGraph(
        blocks={
            188: _b(188, (189, 232), ()),
            189: _b(189, (), (188,)),
            232: _b(232, (), (188,)),
        },
        entry_serial=188,
        func_ea=0x1000,
    )

    assert _normalize_degenerate_branch_redirects(
        fg,
        [RedirectBranch(from_serial=188, old_target=232, new_target=189)],
    ) == [ConvertToGoto(block_serial=188, goto_target=189)]


def test_materialized_conditional_handler_bridge_abstains_on_ambiguous_target(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predicate = InsnSnapshot(opcode=55, ea=predicate_ea, operands=())
    duplicate_ea = 0x2000
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(10, (8,), (), (predicate,)),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=duplicate_ea,
                insn_snapshots=(),
            ),
            21: BlockSnapshot(
                serial=21,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=duplicate_ea,
                insn_snapshots=(),
            ),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(duplicate_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=duplicate_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=0x1288,
    )

    assert build_materialized_conditional_handler_bridges(fg, (transfer,)) == []


def test_source_keyed_handler_owner_leaves_recognized_conditional_arm_alone(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), ()),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                10,
                12,
                12,
                (10, 12),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == []


def test_register_conditional_entry_bridges_leaf_arms(_seam) -> None:
    """d81-3rja step 1: the prologue selects the initial state in a NON-state
    REGISTER (the Rhadamanthys ``sub_40A560`` ``ecx = a2 ? S_a : S_b``) while the
    state var itself carries a decoy. Both leaf-valued arms must bridge past the
    dispatcher to their handlers -- even though the dispatcher compares a DIFFERENT
    variable -- because the conditional's register values still route through the
    dispatcher's leaves.

        0 -> 1(reg99=0x10; branch) -> {3 (a2!=0), 2 (a2==0: reg99=0x20)}
        2 -> 3(merge: state=decoy) -> 4(dispatcher over the state var)
        route(0x10)=21, route(0x20)=22

    Enabled by ``state_var_reg`` (the register path); the walk-back finds merge=3
    and folds each arm's register to a leaf.
    """
    REG = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1, (2, 3), (0,), (_mov_reg(0x1100, 0x10, REG),)
            ),  # reg99=0x10; a2!=0 -> 3, a2==0 -> 2
            2: _b(
                2, (3,), (1,), (_mov_reg(0x1200, 0x20, REG),)
            ),  # a2==0 arm: reg99=0x20
            3: _b(
                3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)
            ),  # merge: decoy state -> dispatcher
            4: _b(4, (21, 22), (3, 21, 22)),  # dispatcher (over the state var)
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=4
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=REG,
    )
    edges = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges, f"a2!=0 arm not bridged to its handler: {sorted(edges)}"
    assert (2, 3, 22) in edges, f"a2==0 arm not bridged to its handler: {sorted(edges)}"


def test_exact_entry_bridge_suppresses_generic_register_entry_scan(_seam) -> None:
    """An already-proven exact entry route owns entry-path mutation."""
    state_reg = 99
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, 0x20, state_reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        flow_graph,
        dispatcher,
        _STATE,
        dispatcher_entry_serial=4,
    )

    modifications = build_state_write_redirects(
        flow_graph,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=state_reg,
        exact_entry_bridge_present=True,
    )

    entry_edges = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
        and modification.from_serial in {1, 2, 3}
    }
    assert entry_edges == set()


def test_stack_carried_state_selector_lowers_at_handler_consumer(_seam) -> None:
    state_reg = 28
    carrier_reg = 7
    carrier_stkoff = 0x54
    first_state = 0x4D34CF70
    second_state = 0xB13A6E93
    predicate_ea = 0x40D266
    consumer_ea = 0x40EAA7
    router_ea = 0x40EAB1
    consumer_tail = InsnSnapshot(
        opcode=0x33,
        ea=router_ea,
        operands=(),
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM,
            size=4,
            value=0x10B85E45,
            kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            0: _b(
                0,
                (1, 2),
                (),
                (
                    _mov_reg(predicate_ea - 5, first_state, carrier_reg),
                    InsnSnapshot(
                        opcode=0x33,
                        ea=predicate_ea,
                        operands=(),
                        kind=InsnKind.COND_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            1: _b(
                1,
                (2,),
                (0,),
                (_mov_reg(predicate_ea, second_state, carrier_reg),),
            ),
            2: _b(
                2,
                (3,),
                (0, 1),
                (_mov_stack_from_reg(predicate_ea + 3, carrier_stkoff, carrier_reg),),
            ),
            3: _b(3, (4, 5), (2,)),
            4: _b(4, (21,), (3, 10)),
            5: _b(5, (22,), (3, 6)),
            6: _b(
                6,
                (5,),
                (10,),
                (
                    InsnSnapshot(
                        opcode=0x40,
                        ea=router_ea + 6,
                        operands=(),
                        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=5),
                        kind=InsnKind.GOTO,
                        is_unconditional_jump=True,
                    ),
                ),
            ),
            10: _b(
                10,
                (4, 6),
                (21,),
                (
                    _mov_reg_from_stack(consumer_ea, state_reg, carrier_stkoff),
                    consumer_tail,
                ),
            ),
            21: _b(21, (10,), (4,)),
            22: _b(22, (10,), (5,)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    expected = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=4,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=8,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=(
                "stack_carried_state_selector:source_ea=0x1280:store_ea=0x40D269"
            ),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]
    dispatcher = _disp({first_state: 21, second_state: 22}, exit_block=99)

    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    # A PREOPT-imported handler can carry a detached-MBA stack offset that does
    # not match the connected prologue store.  Stable native store/load EAs plus
    # the top-level MBA's converted offset must recover the same two-arm route
    # without requiring the producer diamond to survive in this snapshot.
    detached_stkoff = 0xDC
    detached_blocks = {
        serial: block for serial, block in fg.blocks.items() if serial not in {0, 1, 2}
    }
    detached_blocks[10] = _b(
        10,
        (4, 6),
        (21,),
        (
            _mov_reg_from_stack(0xF0000010, state_reg, detached_stkoff),
            replace(
                consumer_tail,
                l=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=detached_stkoff,
                    kind=OperandKind.STACK,
                ),
            ),
        ),
    )
    detached_graph = FlowGraph(
        blocks=detached_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    portable_choice = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40D252,
        materialized_anchor_eas=(0x40D256, predicate_ea, predicate_ea + 3),
        target_eas=(0x2100, 0x2200),
        condition_code=12,
        true_target_ea=0x2100,
        false_target_ea=0x2200,
        selector_state_var_reg=state_reg,
        resolver_kind="static_stack_carried_state_choice",
        predicate_register=20,
        predicate_size=4,
        predicate_compare_constant=0x113,
        predicate_true_state=first_state,
        predicate_false_state=second_state,
        state_carrier_store_ea=predicate_ea + 3,
        state_carrier_stack_displacement=0x44,
        state_carrier_consumer_load_eas=(consumer_ea,),
        state_carrier_ida_stkoff=84,
    )
    portable_expected = [
        replace(
            expected[0],
            condition_operand=replace(
                expected[0].condition_operand,
                stack_stkoff=carrier_stkoff,
                stack_size=4,
            ),
            proof_id=(
                "stack_carried_state_selector_native:"
                "source_ea=0x1280:store_ea=0x40D269:load_ea=0x40EAA7"
            ),
            reason="resolver_proven_native_stack_carried_state_selector",
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            detached_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == portable_expected
    )

    # Later maturities can coalesce the stack reload into a register alias
    # before copying it to the state register.  The native store/load identity
    # still owns the selector and supplies the current VD stack offset.
    coalesced_blocks = dict(detached_graph.blocks)
    coalesced_blocks[10] = _b(
        10,
        (4, 6),
        (21,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=0xF1C00180,
                operands=(),
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=state_reg,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
            replace(
                consumer_tail,
                ea=0xF1C0019C,
                l=MopSnapshot(kind=OperandKind.SUBINSN),
                r=None,
            ),
        ),
    )
    coalesced_graph = FlowGraph(
        blocks=coalesced_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    assert build_stack_carried_state_selector_lowerings(
        coalesced_graph,
        dispatcher,
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({3, 4, 5}),
        handler_serials=frozenset({10, 21, 22}),
        materialized_indirect_transfers=(portable_choice,),
        handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
        state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
        native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
    ) == [
        replace(
            portable_expected[0],
            rewrite_from_ea=0xF1C0019C,
        )
    ]

    # PREOPT can lower the terminal computed jump to an exact conditional
    # after importing the native pointer-selection envelope.  The original
    # stack selector then has two pure arms which converge on that applied
    # resolver-cut predicate instead of entering the router directly.  The
    # applied receipt plus both exact router arms must authorize bypassing the
    # redundant envelope; topology alone must not.
    cut_predicate_ea = 0x40EABA
    taken_anchor_ea = 0xF1C02028
    fallthrough_anchor_ea = 0xF1C0202C
    envelope_blocks = dict(detached_graph.blocks)
    envelope_blocks[10] = _b(
        10,
        (11, 12),
        (21,),
        (
            _mov_reg_from_stack(0xF1C02004, state_reg, detached_stkoff),
            replace(
                consumer_tail,
                ea=0xF1C02020,
                l=MopSnapshot(kind=OperandKind.SUBINSN),
                r=None,
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=12),
            ),
        ),
    )
    envelope_blocks[11] = _b(
        11,
        (12,),
        (10,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=0xF1C02024,
                operands=(),
                l=MopSnapshot(kind=OperandKind.GLOBAL, value=0x48BB98),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
        ),
    )
    envelope_blocks[12] = _b(
        12,
        (4, 5),
        (10, 11),
        (
            replace(
                consumer_tail,
                ea=cut_predicate_ea,
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
            ),
        ),
    )
    envelope_blocks[4] = _b(
        4,
        (21,),
        (12,),
        (InsnSnapshot(opcode=0, ea=taken_anchor_ea, operands=(), kind=InsnKind.NOP),),
    )
    envelope_blocks[5] = _b(
        5,
        (22,),
        (12,),
        (
            InsnSnapshot(
                opcode=0,
                ea=fallthrough_anchor_ea,
                operands=(),
                kind=InsnKind.NOP,
            ),
        ),
    )
    envelope_graph = FlowGraph(
        blocks=envelope_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    resolver_cut_conditional_evidence = (
        AppliedDetachedSnippetConditionalBoundaryPort(
            port=DetachedSnippetConditionalBoundaryPort(
                source_block_ea=consumer_ea,
                predicate_ea=cut_predicate_ea,
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=0x2100,
                fallthrough_target_ea=0x2200,
                state_register=None,
                taken_state=None,
                fallthrough_state=None,
                source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                resolver_kind="resolver_proven_register_compare_cut",
            ),
            taken_target_anchor_eas=(taken_anchor_ea,),
            fallthrough_target_anchor_eas=(fallthrough_anchor_ea,),
        ),
    )
    envelope_expected = [
        replace(
            portable_expected[0],
            old_dispatcher_serial=11,
            rewrite_from_ea=0xF1C02020,
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            envelope_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == []
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            envelope_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            imported_conditional_boundary_evidence=(resolver_cut_conditional_evidence),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == envelope_expected
    )

    side_effect_blocks = dict(envelope_blocks)
    side_effect_blocks[11] = _b(
        11,
        (12,),
        (10,),
        (
            InsnSnapshot(
                opcode=0x7F,
                ea=0xF1C02024,
                operands=(),
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                d=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=carrier_stkoff + 8,
                    kind=OperandKind.STACK,
                ),
                kind=InsnKind.STORE,
            ),
        ),
    )
    side_effect_graph = FlowGraph(
        blocks=side_effect_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            side_effect_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            imported_conditional_boundary_evidence=(resolver_cut_conditional_evidence),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == []
    )

    # Resolver-proven imported handlers must not replace a still-live
    # dispatcher frontier while the choice itself is owned by a detached
    # native consumer.  Connecting those imported regions before the carrier
    # has folded into a live source can expose their synthetic router sink.
    native_stale_leaf_serial = 20
    native_stale_blocks = dict(detached_graph.blocks)
    native_stale_blocks[native_stale_leaf_serial] = _b(
        native_stale_leaf_serial,
        (4,),
        (4,),
    )
    native_stale_graph = FlowGraph(
        blocks=native_stale_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    exact_first_target = MaterializedIndirectTransfer(
        source_jmp_ea=0x2110,
        source_block_ea=0x2100,
        materialized_anchor_eas=(),
        target_eas=(0x2100,),
        selector_state_var_reg=state_reg,
        selector_state_constant=first_state,
        resolver_kind="static_equality_candidate",
    )
    exact_second_target = MaterializedIndirectTransfer(
        source_jmp_ea=0x2210,
        source_block_ea=0x2200,
        materialized_anchor_eas=(),
        target_eas=(0x2200,),
        selector_state_var_reg=state_reg,
        selector_state_constant=second_state,
        resolver_kind="static_equality_candidate",
    )
    assert build_stack_carried_state_selector_lowerings(
        native_stale_graph,
        _disp(
            {first_state: native_stale_leaf_serial, second_state: 22},
            exit_block=99,
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({3, 4, 5}),
        handler_serials=frozenset({10, native_stale_leaf_serial, 21, 22}),
        materialized_indirect_transfers=(
            portable_choice,
            exact_first_target,
            exact_second_target,
        ),
        handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
        state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
        native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
    ) == [
        replace(
            portable_expected[0],
            true_target_serial=native_stale_leaf_serial,
        )
    ]

    # A union-imported consumer may have predecessors inside the imported
    # subgraph and may already use the top-level VD stack offset.  Its native
    # origin still identifies it as imported, so internal connectivity alone
    # must not promote it to the live folded owner.
    connected_imported_blocks = dict(native_stale_blocks)
    connected_imported_blocks[10] = replace(
        connected_imported_blocks[10],
        insn_snapshots=(
            connected_imported_blocks[10].insn_snapshots[0],
            replace(
                connected_imported_blocks[10].insn_snapshots[-1],
                l=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=carrier_stkoff,
                    kind=OperandKind.STACK,
                ),
            ),
        ),
    )
    connected_imported_graph = FlowGraph(
        blocks=connected_imported_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    assert build_stack_carried_state_selector_lowerings(
        connected_imported_graph,
        _disp(
            {first_state: native_stale_leaf_serial, second_state: 22},
            exit_block=99,
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({3, 4, 5}),
        handler_serials=frozenset({10, native_stale_leaf_serial, 21, 22}),
        materialized_indirect_transfers=(
            portable_choice,
            exact_first_target,
            exact_second_target,
        ),
        imported_native_eas_by_serial={10: frozenset({consumer_ea})},
        handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
        state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
        native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
    ) == [
        replace(
            portable_expected[0],
            true_target_serial=native_stale_leaf_serial,
        )
    ]

    # A PREOPT-imported consumer can remain as a zero-predecessor clone while
    # LOCOPT folds the same stack-carried choice into a connected live handler.
    # At CALLS-pre the live consumer can still compare the exact stack cell to
    # a BST threshold; state equality appears only after route rewrites.  The
    # unique connected two-way consumer of that exact cell must own the
    # lowering, rather than the orphan named by the native load-EA map.
    live_consumer_serial = 11
    live_tail_ea = 0x40DBD3
    live_tail = replace(
        consumer_tail,
        ea=live_tail_ea,
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM,
            size=4,
            value=0x10B85E45,
            kind=OperandKind.NUMBER,
        ),
    )
    folded_blocks = dict(detached_graph.blocks)
    folded_blocks[10] = replace(folded_blocks[10], preds=())
    folded_blocks[live_consumer_serial] = _b(
        live_consumer_serial,
        (4, 6),
        (21,),
        (live_tail,),
    )
    folded_graph = FlowGraph(
        blocks=folded_blocks,
        entry_serial=live_consumer_serial,
        func_ea=fg.func_ea,
    )
    live_expected = [
        replace(
            portable_expected[0],
            source_serial=live_consumer_serial,
            rewrite_from_ea=live_tail_ea,
            proof_id=(
                "stack_carried_state_selector_native:"
                "source_ea=0x12C0:store_ea=0x40D269:load_ea=0x40EAA7"
            ),
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            folded_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, live_consumer_serial, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == live_expected
    )

    # The live dispatcher map can still name a comparison leaf for a state
    # whose resolver-proven equality target is an imported handler.  Once the
    # selector source is connected, the exact handler must outrank that stale
    # leaf or the selected semantic region remains orphaned.
    stale_leaf_serial = 20
    stale_target_blocks = dict(folded_blocks)
    stale_target_blocks[stale_leaf_serial] = _b(
        stale_leaf_serial,
        (4,),
        (4,),
    )
    stale_target_graph = FlowGraph(
        blocks=stale_target_blocks,
        entry_serial=live_consumer_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            stale_target_graph,
            _disp(
                {first_state: stale_leaf_serial, second_state: 22},
                exit_block=99,
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset(
                {10, live_consumer_serial, stale_leaf_serial, 21, 22}
            ),
            materialized_indirect_transfers=(
                portable_choice,
                exact_first_target,
                exact_second_target,
            ),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == live_expected
    )

    # Ownership must remain fail-closed when two connected folded consumers
    # match the same stack cell and state pair.
    ambiguous_blocks = dict(folded_blocks)
    ambiguous_blocks[12] = _b(12, (4, 6), (22,), (live_tail,))
    ambiguous_graph = FlowGraph(
        blocks=ambiguous_blocks,
        entry_serial=live_consumer_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            ambiguous_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 11, 12, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == []
    )

    # LOCOPT can fold ``mov state_reg, [stack]`` into the conditional tail.
    # The storage identity remains explicit in the tail and must carry the
    # same proof as the unfused form.
    direct_blocks = dict(fg.blocks)
    direct_blocks[10] = _b(10, (4, 5), (21,), (consumer_tail,))
    direct_graph = FlowGraph(
        blocks=direct_blocks,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    direct_expected = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=4,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=4,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=(
                "stack_carried_state_selector:source_ea=0x1280:store_ea=0x40D269"
            ),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            direct_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == direct_expected
    )

    # A computed-goto equality leaf can consume the stack-carried state
    # directly.  It remains a valid selector source even when exact imported
    # handler ownership removes that router block from the handler map.
    assert (
        build_stack_carried_state_selector_lowerings(
            direct_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5, 10}),
            handler_serials=frozenset({21, 22}),
        )
        == direct_expected
    )

    imported_target_ea = 0x40DD70
    imported_candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DD6E,
        source_block_ea=0x40DD58,
        materialized_anchor_eas=(),
        target_eas=(imported_target_ea,),
        selector_state_var_reg=state_reg,
        selector_state_constant=second_state,
        resolver_kind="static_equality_candidate",
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21}),
            materialized_indirect_transfers=(imported_candidate,),
            handler_entry_eas_by_serial={22: imported_target_ea},
        )
        == expected
    )

    # PREOPT equality evidence proves the native state-to-handler identity; it
    # does not replace a handler that the current live dispatcher map already
    # owns.  Prefer the maturity-local live handler when both representations
    # are present, otherwise a detached clone can orphan the live frontier.
    imported_clone_serial = 23
    blocks_with_imported_clone = dict(fg.blocks)
    blocks_with_imported_clone[imported_clone_serial] = _b(
        imported_clone_serial,
        (),
        (),
    )
    graph_with_imported_clone = FlowGraph(
        blocks=blocks_with_imported_clone,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_imported_clone,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22, imported_clone_serial}),
            materialized_indirect_transfers=(imported_candidate,),
            handler_entry_eas_by_serial={
                imported_clone_serial: imported_target_ea,
            },
        )
        == expected
    )

    # Exact imported equality ownership outranks a stale legacy route for the
    # same state.  The stale route can still name the comparison leaf that
    # existed before detached-target import; unioning both owners would make
    # the selector ambiguous and preserve the computed goto.
    stale_route = MaterializedStateRoute(
        source_block_serial=10,
        state_constant=second_state,
        target_handler_serial=21,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21}),
            materialized_state_routes=(stale_route,),
            materialized_indirect_transfers=(imported_candidate,),
            handler_entry_eas_by_serial={22: imported_target_ea},
        )
        == expected
    )

    # PREOPT can leave a dead register-copy used only to select the native
    # computed-goto target.  Once an exact resolver edge replaces that target,
    # the copy is transparent only when its destination is not live at either
    # selected handler.
    blocks_with_dead_copy = dict(fg.blocks)
    blocks_with_dead_copy[6] = _b(
        6,
        (5,),
        (10,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=router_ea + 4,
                operands=(),
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=9,
                    kind=OperandKind.REGISTER,
                ),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
            fg.blocks[6].insn_snapshots[-1],
        ),
    )
    graph_with_dead_copy = FlowGraph(
        blocks=blocks_with_dead_copy,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_dead_copy,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    # A dead address formation feeding only the replaced router is equally
    # transparent.  Its destination remains subject to the same handler
    # liveness veto as an ordinary register copy.
    blocks_with_dead_address = dict(fg.blocks)
    blocks_with_dead_address[6] = _b(
        6,
        (5,),
        (10,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=router_ea + 4,
                operands=(),
                l=MopSnapshot(
                    size=4,
                    value=0x48B918,
                    kind=OperandKind.ADDRESS,
                ),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=12,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
            fg.blocks[6].insn_snapshots[-1],
        ),
    )
    graph_with_dead_address = FlowGraph(
        blocks=blocks_with_dead_address,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_dead_address,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    # An applied resolver-cut port can prove a larger pure address-computation
    # envelope transparent.  Loads/arithmetic remain bypassable only when each
    # instruction defines a register, the exact endpoint enters the router,
    # and no store/call/control effect is present.
    endpoint_ea = router_ea + 0x20
    target_anchor_ea = router_ea + 0x30
    endpoint_goto = InsnSnapshot(
        opcode=0x40,
        ea=endpoint_ea + 3,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=5),
        kind=InsnKind.GOTO,
        is_unconditional_jump=True,
    )
    pure_endpoint_insns = (
        InsnSnapshot(
            opcode=2,
            ea=endpoint_ea,
            operands=(),
            l=MopSnapshot(kind=OperandKind.GLOBAL, value=0x48BD50),
            d=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
            kind=InsnKind.LOAD,
        ),
        InsnSnapshot(
            opcode=12,
            ea=endpoint_ea + 2,
            operands=(),
            l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
            d=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
            kind=InsnKind.ADD,
        ),
        endpoint_goto,
    )
    blocks_with_resolver_envelope = dict(fg.blocks)
    blocks_with_resolver_envelope[5] = _b(
        5,
        (22,),
        (3, 6),
        (InsnSnapshot(opcode=0, ea=target_anchor_ea, operands=(), kind=InsnKind.NOP),),
    )
    blocks_with_resolver_envelope[6] = _b(
        6,
        (5,),
        (10,),
        pure_endpoint_insns,
    )
    graph_with_resolver_envelope = FlowGraph(
        blocks=blocks_with_resolver_envelope,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    resolver_cut_evidence = (
        AppliedDetachedSnippetDirectBoundaryPort(
            port=DetachedSnippetDirectBoundaryPort(
                source_block_ea=0x40DABB,
                source_instruction_ea=0x40DACE,
                endpoint_block_ea=0x40DABB,
                old_successor_eas=(),
                target_ea=0x40D370,
                state_register=None,
                state_constant=None,
                source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                delivery_mode="terminal_goto",
                resolver_kind="static_equality_candidate_dispatcher_cut",
            ),
            endpoint_anchor_eas=tuple(insn.ea for insn in pure_endpoint_insns),
            target_anchor_eas=(target_anchor_ea,),
        ),
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_resolver_envelope,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_resolver_envelope,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            imported_direct_boundary_evidence=resolver_cut_evidence,
        )
        == expected
    )

    # A use reached only after re-entering the dispatcher is not a semantic
    # handler use: the direct lowering replaces that traversal.  Cut liveness
    # at dispatcher entry while retaining uses in the selected handler itself.
    router_use = InsnSnapshot(
        opcode=_OP_MOV,
        ea=router_ea + 8,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_REG, size=4, reg=9, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )
    blocks_with_router_only_use = dict(blocks_with_dead_copy)
    blocks_with_router_only_use[4] = _b(4, (21,), (3, 10), (router_use,))
    graph_with_router_only_use = FlowGraph(
        blocks=blocks_with_router_only_use,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_router_only_use,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    blocks_with_handler_use = dict(blocks_with_dead_copy)
    blocks_with_handler_use[21] = _b(21, (10,), (4,), (router_use,))
    graph_with_handler_use = FlowGraph(
        blocks=blocks_with_handler_use,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_handler_use,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )

    # A one-way bridge carrying any operation beyond NOPs and its terminal
    # GOTO is not a transparent dispatcher trampoline.  Preserve it rather
    # than bypassing a potentially meaningful side effect.
    blocks_with_effect = dict(fg.blocks)
    blocks_with_effect[6] = _b(
        6,
        (5,),
        (10,),
        (
            _mov_reg(router_ea + 4, 0xDEADBEEF, carrier_reg),
            fg.blocks[6].insn_snapshots[-1],
        ),
    )
    graph_with_effect = FlowGraph(
        blocks=blocks_with_effect,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_effect,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )


def test_snapshot_fixpoint_visits_entry_before_default_budget_expires(
    _seam,
) -> None:
    carrier_reg = 28
    constant = 0x4D34CF70
    branch_ea = 0x40D266
    blocks = {
        0: _b(
            0,
            (1, 2),
            (),
            (
                _mov_reg(branch_ea - 5, constant, carrier_reg),
                InsnSnapshot(
                    opcode=0x32,
                    ea=branch_ea,
                    operands=(),
                    l=MopSnapshot(
                        t=_T_REG,
                        size=4,
                        reg=carrier_reg,
                        kind=OperandKind.REGISTER,
                    ),
                    r=MopSnapshot(
                        t=_T_NUM,
                        size=4,
                        value=0x113,
                        kind=OperandKind.NUMBER,
                    ),
                    d=MopSnapshot(
                        kind=OperandKind.BLOCK,
                        block_ref=2,
                    ),
                    kind=InsnKind.COND_JUMP,
                    branch_predicate=PredicateKind.SLT,
                    is_conditional_jump=True,
                ),
            ),
        ),
        1: _b(1, (), (0,)),
        2: _b(2, (), (0,)),
    }
    blocks.update({serial: _b(serial, (), ()) for serial in range(3, 1005)})
    graph = FlowGraph(
        blocks=blocks,
        entry_serial=0,
        func_ea=0x40D200,
    )

    result = run_snapshot_constant_fixpoint(graph, -1)

    assert result.out_reg_maps[0][carrier_reg] == constant


def test_folded_imported_stack_selector_bypasses_converged_indirect_router(
    _seam,
) -> None:
    state_reg = 28
    carrier_reg = 7
    carrier_stkoff = 0x6C
    imported_frame_stkoff = 0xF4
    first_state = 0x142718FC
    second_state = 0x1D4F9917
    predicate_ea = 0x1100
    consumer_ea = 0x2200
    router_ea = 0x2204
    imported_target_ea = 0x5000
    owner_state = 0xF6D08EC5
    consumer_tail = InsnSnapshot(
        opcode=0x33,
        ea=router_ea,
        operands=(),
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM,
            size=4,
            value=0x10B85E45,
            kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=12),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    terminal_ijmp = InsnSnapshot(
        opcode=0x36,
        ea=router_ea + 8,
        operands=(),
        kind=InsnKind.INDIRECT_JUMP,
    )
    fg = FlowGraph(
        blocks={
            0: _b(
                0,
                (1, 2),
                (),
                (
                    _mov_reg(predicate_ea - 5, first_state, carrier_reg),
                    InsnSnapshot(
                        opcode=0x33,
                        ea=predicate_ea,
                        operands=(),
                        kind=InsnKind.COND_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            1: _b(
                1,
                (2,),
                (0,),
                (_mov_reg(predicate_ea, second_state, carrier_reg),),
            ),
            2: _b(
                2,
                (10,),
                (0, 1),
                (_mov_stack_from_reg(predicate_ea + 3, carrier_stkoff, carrier_reg),),
            ),
            # Imported snippets can retain a separate frame load into the
            # state register before a folded tail that compares the actual
            # selector cell directly.  The tail operand is authoritative: the
            # lowering keeps this source block and rewrites only its targets.
            10: _b(
                10,
                (11, 12),
                (2,),
                (
                    _mov_reg_from_stack(
                        consumer_ea,
                        state_reg,
                        imported_frame_stkoff,
                    ),
                    consumer_tail,
                ),
            ),
            11: _b(
                11,
                (12,),
                (10,),
                (
                    InsnSnapshot(
                        opcode=_OP_MOV,
                        ea=router_ea + 4,
                        operands=(),
                        l=MopSnapshot(
                            t=_T_REG,
                            size=4,
                            reg=9,
                            kind=OperandKind.REGISTER,
                        ),
                        d=MopSnapshot(
                            t=_T_REG,
                            size=4,
                            reg=8,
                            kind=OperandKind.REGISTER,
                        ),
                        kind=InsnKind.MOV,
                    ),
                ),
            ),
            12: _b(12, (), (10, 11), (terminal_ijmp,)),
            21: _b(21, (), (), ()),
            22: _b(22, (), (), ()),
            30: _b(30, (), (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    imported_owner = MaterializedIndirectTransfer(
        source_jmp_ea=0x4FF0,
        source_block_ea=0x4FE0,
        materialized_anchor_eas=(),
        target_eas=(imported_target_ea,),
        selector_state_var_reg=state_reg,
        selector_state_constant=owner_state,
        resolver_kind="static_equality_candidate",
    )

    assert build_stack_carried_state_selector_lowerings(
        fg,
        _disp({first_state: 21, second_state: 22}, exit_block=99),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({30}),
        handler_serials=frozenset({21, 22}),
        materialized_indirect_transfers=(imported_owner,),
        handler_entry_eas_by_serial={10: imported_target_ea},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=11,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=4,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=("stack_carried_state_selector:source_ea=0x1280:store_ea=0x1103"),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]

    # The converged-indirect exception belongs only to an exact imported
    # equality owner.  An ordinary handler with the same folded stack tail
    # must preserve the unresolved router.
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({30}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )

    # A detached static replay of the exact live indirect endpoint supplies
    # the missing ownership proof when PREOPT assigned the equality state to
    # an imported clone rather than this original live handler.  The replay
    # authorizes the existing stack-selector proof; its router-root EAs are
    # never used as the lowering destinations.
    terminal_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=router_ea + 8,
        source_block_ea=consumer_ea,
        materialized_anchor_eas=(),
        target_eas=(0x6000, 0x7000),
        condition_code=12,
        true_target_ea=0x6000,
        false_target_ea=0x7000,
        resolver_kind="detached_static_fixpoint",
    )
    expected = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=11,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=4,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=("stack_carried_state_selector:source_ea=0x1280:store_ea=0x1103"),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]
    clone_owned_args = dict(
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({30}),
        handler_serials=frozenset({10, 21, 22}),
        handler_entry_eas_by_serial={30: imported_target_ea},
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            materialized_indirect_transfers=(imported_owner, terminal_transfer),
            **clone_owned_args,
        )
        == expected
    )

    mismatched_terminal = replace(
        terminal_transfer,
        source_jmp_ea=router_ea + 0x40,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            materialized_indirect_transfers=(imported_owner, mismatched_terminal),
            **clone_owned_args,
        )
        == []
    )
    incomplete_terminal = replace(terminal_transfer, false_target_ea=None)
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            materialized_indirect_transfers=(imported_owner, incomplete_terminal),
            **clone_owned_args,
        )
        == []
    )

    # A call at the shared endpoint is a semantic effect, not a disposable
    # computed-jump router.  Exact ownership alone must not bypass it.
    effect_blocks = dict(fg.blocks)
    effect_blocks[12] = _b(
        12,
        (),
        (10, 11),
        (
            InsnSnapshot(
                opcode=0x31,
                ea=router_ea + 8,
                operands=(),
                kind=InsnKind.CALL,
            ),
        ),
    )
    effect_graph = FlowGraph(
        blocks=effect_blocks,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            effect_graph,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({30}),
            handler_serials=frozenset({21, 22}),
            materialized_indirect_transfers=(imported_owner,),
            handler_entry_eas_by_serial={10: imported_target_ea},
        )
        == []
    )


def test_terminal_replay_endpoint_excludes_imported_clone() -> None:
    from d810.transforms import minimal_unflatten_emit as emit_module

    source_jmp_ea = 0x40DACE
    terminal_ijmp = InsnSnapshot(
        opcode=0x36,
        ea=source_jmp_ea,
        operands=(),
        kind=InsnKind.INDIRECT_JUMP,
    )
    fg = FlowGraph(
        blocks={
            12: _b(12, (), (), (terminal_ijmp,)),
            31: _b(31, (), (), (terminal_ijmp,)),
        },
        entry_serial=12,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=source_jmp_ea,
        source_block_ea=0x40DABB,
        materialized_anchor_eas=(),
        target_eas=(0x40D381, 0x40E5C0),
        condition_code=12,
        true_target_ea=0x40D381,
        false_target_ea=0x40E5C0,
        resolver_kind="detached_static_fixpoint",
    )

    helper = emit_module._resolver_proven_live_terminal_endpoint_serials
    assert (
        helper(
            fg,
            (transfer,),
            imported_endpoint_serials=frozenset(),
        )
        == frozenset()
    )
    assert helper(
        fg,
        (transfer,),
        imported_endpoint_serials=frozenset({31}),
    ) == frozenset({12})
    assert (
        helper(
            fg,
            (transfer,),
            imported_endpoint_serials=frozenset({12, 31}),
        )
        == frozenset()
    )


def test_stack_carried_state_selector_abstains_on_second_cell_write(_seam) -> None:
    state_reg = 28
    carrier_reg = 7
    carrier_stkoff = 0x54
    first_state = 0x10
    second_state = 0x20
    consumer_tail = InsnSnapshot(
        opcode=0x33,
        ea=0x2204,
        operands=(),
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(t=_T_NUM, size=4, value=0, kind=OperandKind.NUMBER),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (1, 2), (), (_mov_reg(0x1000, first_state, carrier_reg),)),
            1: _b(1, (2,), (0,), (_mov_reg(0x1040, second_state, carrier_reg),)),
            2: _b(
                2,
                (3,),
                (0, 1),
                (_mov_stack_from_reg(0x1080, carrier_stkoff, carrier_reg),),
            ),
            3: _b(3, (4, 5), (2,)),
            4: _b(4, (21,), (3, 10)),
            5: _b(5, (22,), (3, 10)),
            10: _b(
                10,
                (4, 5),
                (21,),
                (
                    _mov_reg_from_stack(0x2200, state_reg, carrier_stkoff),
                    consumer_tail,
                ),
            ),
            21: _b(21, (10,), (4,)),
            22: _b(22, (10,), (5,)),
            30: _b(
                30, (), (), (_mov_stack_const(0x3000, carrier_stkoff, first_state),)
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )


def test_scalar_initial_state_suppresses_register_conditional_entry_scan(_seam) -> None:
    state_reg = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, 0x20, state_reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=0x10,
        state_var_stkoff=None,
        state_var_reg=state_reg,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (3, 4, 21) in edges
    assert not any(source in {1, 2} for source, _old, _new in edges)


def test_register_conditional_entry_ignores_invariant_leaf_register(_seam) -> None:
    """The carrier must be one register whose value varies across both arms.

    A different register may coincidentally hold a valid dispatcher state on
    both predecessors.  Selecting the first routeable value independently on
    each predecessor collapses both arms onto that unrelated state's handler.
    """
    carrier_reg = 99
    invariant_reg = 77
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (2, 3),
                (0,),
                (
                    _mov_reg(0x1100, 0x20, invariant_reg),
                    _mov_reg(0x1104, 0x10, carrier_reg),
                ),
            ),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, 0x20, carrier_reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=carrier_reg,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_abstains_on_two_distinct_route_sets(_seam) -> None:
    carrier_reg = 99
    competing_reg = 77
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (2, 3),
                (0,),
                (
                    _mov_reg(0x1100, 0x20, competing_reg),
                    _mov_reg(0x1104, 0x10, carrier_reg),
                ),
            ),
            2: _b(
                2,
                (3,),
                (1,),
                (
                    _mov_reg(0x1200, 0x10, competing_reg),
                    _mov_reg(0x1204, 0x20, carrier_reg),
                ),
            ),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=carrier_reg,
    )

    assert not any(
        isinstance(modification, (RedirectGoto, RedirectBranch))
        and modification.from_serial in {1, 2}
        for modification in modifications
    )


def test_register_conditional_entry_uses_unique_materialized_state_route(_seam) -> None:
    reg = 99
    live_state = 0xA0716E5B
    residual_state = 0xEC71CA67
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, live_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, residual_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21,), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({live_state: 21}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=4
    )

    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_state_routes=(MaterializedStateRoute(200, residual_state, 22),),
    )

    edges = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_prefers_portable_live_handler_map(_seam) -> None:
    reg = 99
    parser_state = 0xA0716E5B
    main_state = 0xEC71CA67
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, parser_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, main_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21,), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    coarse_dispatcher = _disp(
        {parser_state: 21, main_state: 21},
        exit_block=99,
    )

    modifications = build_state_write_redirects(
        fg,
        coarse_dispatcher,
        recover_state_write_transitions(
            fg,
            coarse_dispatcher,
            _STATE,
            dispatcher_entry_serial=4,
        ),
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_handler_by_state={parser_state: 22, main_state: 21},
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 22) in edges
    assert (2, 3, 21) in edges


def test_register_conditional_entry_prefers_exact_detached_equality_target(
    _seam,
) -> None:
    reg = 99
    parser_state = 0xA0716E5B
    main_state = 0xEC71CA67
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, parser_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, main_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21,), (3, 21)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (), ()),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({parser_state: 21}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=4
    )
    exact_main = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B9A4,
        source_block_ea=0x40B98C,
        materialized_anchor_eas=(0x40B998, 0x40B99E),
        target_eas=(fg.blocks[22].start_ea, fg.blocks[99].start_ea),
        condition_code=4,
        true_target_ea=fg.blocks[22].start_ea,
        false_target_ea=fg.blocks[99].start_ea,
        selector_state_var_reg=20,
        selector_compare_constant=main_state,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
    )

    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=20,
        materialized_indirect_transfers=(exact_main,),
        materialized_state_routes=(MaterializedStateRoute(200, main_state, 21),),
    )

    edges = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_rejects_external_exact_target(_seam) -> None:
    """An XTRN placeholder must not outrank the imported dispatcher handler."""
    reg = 20
    first_state = 0x09269BD2
    second_state = 0xA4C94734
    external_target_ea = 0x40CE3C
    external = BlockSnapshot(
        serial=22,
        block_type=6,
        succs=(),
        preds=(),
        flags=0,
        start_ea=external_target_ea,
        insn_snapshots=(),
        kind=BlockKind.EXTERNAL,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, first_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, second_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 23), (3, 21, 23)),
            21: _b(21, (4,), (4,)),
            22: external,
            23: _b(23, (4,), (4,)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp(
        {first_state: 21, second_state: 23},
        exit_block=99,
    )
    exact_first = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CEC6,
        source_block_ea=0x40CEAB,
        materialized_anchor_eas=(0x40CEB0,),
        target_eas=(external_target_ea, fg.blocks[99].start_ea),
        condition_code=4,
        true_target_ea=external_target_ea,
        false_target_ea=fg.blocks[99].start_ea,
        selector_state_var_reg=reg,
        selector_compare_constant=first_state,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        recover_state_write_transitions(
            fg,
            dispatcher,
            _STATE,
            dispatcher_entry_serial=4,
        ),
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_indirect_transfers=(exact_first,),
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 23) in edges
    assert all(new_target != 22 for _source, _old, new_target in edges)


def test_register_conditional_entry_uses_evidence_store_anchor_past_false_merge(
    _seam,
) -> None:
    """A detached residual chain must not hide the true prologue state merge."""
    reg = 99
    live_state = 0xA0716E5B
    residual_state = 0xEC71CA67
    source_store_ea = 0x1300
    fg = FlowGraph(
        blocks={
            0: _b(0, (1, 6), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, live_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, residual_state, reg),)),
            3: _b(3, (5,), (1, 2), (_mov_state(source_store_ea, 0xDEAD),)),
            5: _b(5, (4,), (3, 6)),
            6: _b(6, (5,), (0,)),
            4: _b(4, (21,), (5, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (), ()),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({live_state: 21}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1000,
        condition_code=5,
        predicate_stack_identity=(4, 4),
        stack_cell_identity=(_STATE, 4),
        taken_state_constant=live_state,
        fallthrough_state_constant=residual_state,
        source_store_ea=source_store_ea,
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_state_routes=(MaterializedStateRoute(200, residual_state, 22),),
        entry_bridge_evidence=evidence,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_abstains_on_ambiguous_evidence_store_anchor(
    _seam,
) -> None:
    reg = 99
    live_state = 0x10
    residual_state = 0x20
    source_store_ea = 0x1300
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, live_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, residual_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(source_store_ea, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            6: _b(6, (), (), (_mov_state(source_store_ea, 0xBEEF),)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({live_state: 21, residual_state: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1000,
        condition_code=5,
        predicate_stack_identity=(4, 4),
        stack_cell_identity=(_STATE, 4),
        taken_state_constant=live_state,
        fallthrough_state_constant=residual_state,
        source_store_ea=source_store_ea,
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        entry_bridge_evidence=evidence,
    )

    assert not any(
        isinstance(modification, (RedirectGoto, RedirectBranch))
        and modification.from_serial in {1, 2}
        for modification in modifications
    )


def test_resolver_proven_indirect_call_neutralization_joins_planned_redirect() -> None:
    transfer_ea = 0x40AE89
    graph = FlowGraph(
        blocks={
            83: _b(
                83,
                (318,),
                (82,),
                (_nested_call_result(transfer_ea),),
            ),
            43: _b(43, (4,), ()),
            318: _b(318, (4,), (83,)),
            4: _b(4, (), (43, 318)),
        },
        entry_serial=83,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=transfer_ea,
        source_block_ea=0x40AE3E,
        materialized_anchor_eas=(),
        target_eas=(0x40A607, 0x40B6C0),
        resolver_kind="detached_static_fixpoint",
    )

    assert build_resolver_proven_indirect_call_neutralizations(
        graph,
        (transfer,),
        (RedirectGoto(from_serial=83, old_target=318, new_target=43),),
        handler_serials=frozenset({43}),
    ) == [
        NopInstructions(block_serial=83, insn_eas=(transfer_ea,)),
    ]


def test_default_use_def_findings_are_advisory_and_keep_all_sibling_redirects(
    _seam,
    monkeypatch,
) -> None:
    """Heuristic severances must not silently drop sibling redirects by default."""

    class _CleanUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return ()

    class _HeuristicUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    src_block=10,
                    new_target=20,
                    var_stkoff=_CARRIER_OFF,
                    var_size=4,
                    use_block=20,
                    use_ea=0x1000,
                ),
            )

    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    monkeypatch.delenv("D810_S1A_SEVERANCE_BAIL", raising=False)
    kwargs = {
        "state_var_stkoff": _STATE,
        "dispatcher_entry_serial": 2,
        "initial_state": 0x10,
        "authoritative_handler_serials": frozenset({10, 20}),
        "live_function": object(),
    }
    clean_plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        use_def_safety=_CleanUseDefSafety(),
        **kwargs,
    )
    heuristic_plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        use_def_safety=_HeuristicUseDefSafety(),
        **kwargs,
    )

    assert len(graph_modifications(heuristic_plan)) == len(
        graph_modifications(clean_plan)
    )
    _assert_no_legacy_plan_metadata(heuristic_plan)


def test_legacy_s1a_severance_bail_rejects_the_whole_fragment(
    _seam,
    monkeypatch,
) -> None:
    """The legacy S1A gate rejects an executed actionable audit atomically."""

    class _HeuristicUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    src_block=10,
                    new_target=20,
                    var_stkoff=_CARRIER_OFF,
                    var_size=4,
                    use_block=20,
                    use_ea=0x1000,
                ),
            )

    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_HeuristicUseDefSafety(),
        live_function=object(),
    )

    assert graph_modifications(plan) == []
    _assert_no_legacy_plan_metadata(plan)


def test_legacy_s1a_severance_bail_ignores_state_variable_findings(
    _seam,
    monkeypatch,
) -> None:
    class _StateOnlyUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (SimpleNamespace(var_stkoff=_STATE),)

    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_StateOnlyUseDefSafety(),
        live_function=object(),
    )

    assert len(graph_modifications(plan)) == 3
    _assert_no_legacy_plan_metadata(plan)


def test_explicit_use_def_veto_rejects_the_whole_fragment_atomically(
    _seam,
    monkeypatch,
) -> None:
    """An enabled veto rejects all sibling redirects, never a filtered subset."""

    class _HeuristicUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    src_block=10,
                    new_target=20,
                    var_stkoff=_CARRIER_OFF,
                    var_size=4,
                    use_block=20,
                    use_ea=0x1000,
                ),
            )

    monkeypatch.setenv("D810_USE_DEF_VETO", "1")
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_HeuristicUseDefSafety(),
        live_function=object(),
    )

    assert graph_modifications(plan) == []
    _assert_no_legacy_plan_metadata(plan)


def test_switch_retirement_breaks_unique_terminal_dispatcher_cycle() -> None:
    """Full switch retirement must explicitly break its detached cycle."""
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: replace(
                _b(2, (3, 4, 5, 6, 7), (1, 8)),
                kind=BlockKind.N_WAY,
            ),
            3: _b(3, (8,), (2,)),
            4: _b(4, (8,), (2,)),
            5: _b(5, (8,), (2,)),
            6: _b(6, (9,), (2,)),
            7: _b(7, (8,), (2,)),
            8: _b(8, (2,), (3, 4, 5, 7)),
            9: replace(_exit_block(9, (6,)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x180001670,
    )
    modifications = [
        RedirectGoto(from_serial=3, old_target=8, new_target=4),
        RedirectGoto(from_serial=4, old_target=8, new_target=5),
        RedirectGoto(from_serial=5, old_target=8, new_target=6),
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
    ]

    rewritten, cleanup_source = (
        minimal_unflatten_emit_module._break_terminal_switch_dispatcher_cycle(
            flow_graph,
            modifications,
            dispatcher_entry_serial=2,
        )
    )

    assert cleanup_source == 8
    assert [mod.from_serial for mod in rewritten if isinstance(mod, RedirectGoto)] == [
        3,
        4,
        5,
        1,
        8,
    ]
    assert rewritten[-1] == RedirectGoto(
        from_serial=8,
        old_target=2,
        new_target=6,
    )


def test_switch_retirement_abstains_when_terminal_corridor_is_ambiguous() -> None:
    """Two terminal candidates provide no authority to choose a cleanup edge."""
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: replace(_b(2, (3, 4), (0, 5, 6)), kind=BlockKind.N_WAY),
            3: _b(3, (9,), (2,)),
            4: _b(4, (9,), (2,)),
            5: _b(5, (2,), ()),
            6: _b(6, (2,), ()),
            9: replace(_exit_block(9, (3, 4)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    modifications = [
        RedirectGoto(from_serial=5, old_target=2, new_target=3),
        RedirectGoto(from_serial=6, old_target=2, new_target=4),
    ]

    rewritten, cleanup_source = (
        minimal_unflatten_emit_module._break_terminal_switch_dispatcher_cycle(
            flow_graph,
            modifications,
            dispatcher_entry_serial=2,
        )
    )

    assert rewritten == modifications
    assert cleanup_source is None


def test_switch_emitter_breaks_terminal_dispatcher_cycle_before_compiling_plan(
    _seam,
) -> None:
    """The abc-style plan must make its detached switch residue acyclic."""
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: replace(
                _b(2, (3, 4, 5, 6, 7), (0, 8)),
                kind=BlockKind.N_WAY,
            ),
            3: _b(3, (8,), (2,), (_mov_state(0x1300, 1),)),
            4: _b(4, (8,), (2,), (_mov_state(0x1400, 2),)),
            5: _b(5, (8,), (2,), (_mov_state(0x1500, 3),)),
            6: _b(6, (9,), (2,)),
            7: _b(7, (8,), (2,)),
            8: _b(8, (2,), (3, 4, 5, 7)),
            9: replace(_exit_block(9, (6,)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x180001670,
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        _disp({0: 3, 1: 4, 2: 5, 3: 6}, exit_block=7),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0,
        authoritative_handler_serials=frozenset({3, 4, 5, 6}),
    )

    modifications = graph_modifications(plan)
    assert {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    } == {
        (0, 2, 3),
        (3, 8, 4),
        (4, 8, 5),
        (5, 8, 6),
        (8, 2, 6),
    }
    _assert_no_legacy_plan_metadata(plan)


def _interval_entry_flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 13, 99), (0, 10, 13)),
            10: _b(10, (2,), (2,), ()),
            13: _b(13, (2,), (2,), ()),
            99: replace(_b(99, (), (2,)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x180055760,
    )


def _interval_rows() -> tuple[IntervalRow, ...]:
    return (
        IntervalRow(0x079323FA, 0x1888937E, 10),
        IntervalRow(0x1888937E, 0x1888937F, 13),
        IntervalRow(0x1BABC1DC, 0x1BABC1DD, 2),
    )


def test_initial_state_inside_interval_abstains_without_typed_route_authority() -> None:
    """A broad interval alone cannot authorize an entry redirect."""
    state = 0x16AA65E9
    dispatcher = _DualRouteDispatcher(
        exact_targets={}, interval_rows=_interval_rows(), default_target=99
    )
    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
    )

    assert modifications == []


def test_back_edge_state_inside_interval_abstains_without_typed_route_authority() -> None:
    """A broad interval alone cannot authorize a back-edge redirect."""
    state = 0x079323FA
    dispatcher = _DualRouteDispatcher(
        exact_targets={}, interval_rows=_interval_rows(), default_target=99
    )
    transition = StateWriteTransition(
        10,
        state,
        None,
        False,
        None,
        proof=TransitionProof("region_partitioned_fixpoint", "global_fold", True),
    )
    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
    )

    assert modifications == []


def test_uncovered_interval_state_remains_unresolved() -> None:
    """An uncovered state cannot manufacture a handler edge."""
    state = 0x19000000
    dispatcher = _DualRouteDispatcher(
        exact_targets={}, interval_rows=_interval_rows(), default_target=99
    )
    transition = StateWriteTransition(10, state, None, False, None)
    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        condition_chain_handlers=frozenset({10, 13}),
    )

    assert modifications == []


def test_conflicting_exact_and_interval_target_remains_unresolved() -> None:
    """Disagreeing route providers must not silently use exact precedence."""
    state = 0x16AA65E9
    dispatcher = _DualRouteDispatcher(
        exact_targets={state: 13},
        interval_rows=_interval_rows(),
        default_target=99,
        legacy_lookup_interval=True,
    )
    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset({10, 13}),
    )

    assert modifications == []


@pytest.mark.parametrize("route_target", [99, 2])
def test_interval_default_or_dispatcher_self_route_does_not_become_handler(
    route_target: int,
) -> None:
    """Default and dispatcher-self rows are not semantic handler routes."""
    state = 0x20000000
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 1, route_target),),
        default_target=99,
        legacy_lookup_interval=True,
    )
    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset({10, 13}),
    )

    assert modifications == []


def test_ambiguous_materialized_route_abstains_even_when_interval_agrees() -> None:
    """A materialized provider conflict cannot be erased by an interval match."""
    state = 0x16AA65E9
    dispatcher = _DualRouteDispatcher(
        exact_targets={}, interval_rows=(IntervalRow(state, state + 1, 10),),
        default_target=99,
    )
    routes = (
        MaterializedStateRoute(0, state, 10),
        MaterializedStateRoute(0, state, 13),
    )

    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        materialized_state_routes=routes,
        condition_chain_handlers=frozenset({10, 13}),
    )

    assert modifications == []


def test_outer_entry_preflight_rejects_legacy_lookup_when_consensus_abstains(
    monkeypatch,
) -> None:
    """A legacy lookup target cannot authorize unrelated back-edge mutation."""
    state = 0x16AA65E9
    next_state = 0x20
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 13, 20), (0, 10, 13, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x2050, next_state),)),
            13: _b(13, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x2000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={state: 13},
        interval_rows=(
            IntervalRow(state, state + 1, 10),
            IntervalRow(next_state, next_state + 1, 20),
        ),
        default_target=99,
        legacy_lookup_interval=True,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(10, next_state, None, False, None),
        ),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_handler_transitions",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
    )

    assert graph_modifications(plan) == []


@pytest.mark.parametrize("route_target", [99, 2])
def test_empty_handler_set_rejects_default_and_dispatcher_self_routes(
    route_target: int,
) -> None:
    """No handler membership evidence must not bless default/self routes."""
    state = 0x20000000
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 1, route_target),),
        default_target=99,
        legacy_lookup_interval=True,
    )
    transition = StateWriteTransition(10, state, None, False, None)

    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset(),
    )

    assert modifications == []


def test_native_and_materialized_entry_route_conflict_abstains_atomically(
    monkeypatch,
) -> None:
    """Contradictory entry providers must not emit two redirects for one edge."""
    state = 0x16AA65E9
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 13), (1, 10, 13)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x3000,
    )
    dispatcher = _disp({state: 10}, exit_block=99)
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )
    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        materialized_computed_goto_profile=True,
        materialized_state_routes=(
            MaterializedStateRoute(1, state, 10),
        ),
        native_bound_transition_routes=(
            _native_bound_route(source=1, state=state, target=13),
        ),
        authoritative_handler_serials=frozenset({10, 13}),
    )

    assert graph_modifications(plan) == []


def test_scalar_entry_route_conflict_with_native_bound_evidence_abstains_atomically(
    monkeypatch,
) -> None:
    """Interval and native evidence for one entry edge must agree before mutation."""
    state = 0x16AA65E9
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 13), (1, 10, 13)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x3000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 2, 10),),
        default_target=99,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        materialized_computed_goto_profile=True,
        native_bound_transition_routes=(
            _native_bound_route(source=1, state=state, target=13),
        ),
        authoritative_handler_serials=frozenset({10, 13}),
    )

    assert graph_modifications(plan) == []
    assert "concrete_state_route_provenance" not in plan.metadata_dict()
    assert plan.metadata_dict().get(
        "native_bound_transition_route_receipts", ()
    ) == ()


def test_entry_native_receipts_follow_recovered_initial_state(
    monkeypatch,
) -> None:
    """Entry candidates and receipts use recovered state over a stale hint."""
    hint_state = 0x16AA65E9
    recovered_state = hint_state + 0x100
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 13), (1, 10, 13)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x3000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(recovered_state, recovered_state + 2, 10),),
        default_target=99,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(1, recovered_state, None, False, None),
        ),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=hint_state,
        materialized_computed_goto_profile=True,
        native_bound_transition_routes=(
            _native_bound_route(
                source=1, state=hint_state, target=13, fact_id="hint"
            ),
            _native_bound_route(
                source=1, state=recovered_state, target=10, fact_id="recovered"
            ),
        ),
        authoritative_handler_serials=frozenset({10, 13}),
    )

    assert RedirectGoto(from_serial=1, old_target=2, new_target=10) in (
        graph_modifications(plan)
    )
    receipts = plan.metadata_dict().get(
        "native_bound_transition_route_receipts", ()
    )
    assert receipts == ()


def test_scalar_entry_route_agrees_with_native_bound_evidence_and_provenance(
    monkeypatch,
) -> None:
    """Agreeing native evidence is deduplicated and retained in provenance."""
    state = 0x16AA65E9
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 13), (1, 10, 13)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x3000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 2, 10),),
        default_target=99,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        materialized_computed_goto_profile=True,
        native_bound_transition_routes=(
            _native_bound_route(source=1, state=state, target=10),
        ),
        authoritative_handler_serials=frozenset({10, 13}),
    )

    assert [
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
        and (modification.from_serial, modification.old_target) == (1, 2)
    ] == [RedirectGoto(from_serial=1, old_target=2, new_target=10)]
    _assert_no_legacy_plan_metadata(plan)


def test_unrelated_native_bound_entry_route_does_not_veto_scalar_entry(
    monkeypatch,
) -> None:
    """A native transition for another state must not replace the scalar route."""
    state = 0x16AA65E9
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 13), (1, 10, 13)),
            10: _b(10, (2,), (2,)),
            13: _b(13, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x3000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 2, 10),),
        default_target=99,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            fg,
            DecisionDag(32, {}, root=2),
            frozenset({10, 13}),
            dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(fg),
        materialized_computed_goto_profile=True,
        native_bound_transition_routes=(
            _native_bound_route(source=1, state=state + 0x100, target=13),
        ),
        authoritative_handler_serials=frozenset({10, 13}),
    )
    assert [
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
        and (modification.from_serial, modification.old_target) == (1, 2)
    ] == [RedirectGoto(from_serial=1, old_target=2, new_target=10)]
    _assert_no_legacy_plan_metadata(plan)


def test_empty_handler_set_rejects_broad_interval_entry_and_back_edge() -> None:
    """Empty handler discovery does not authorize a broad interval target."""
    state = 0x16AA65E9
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state - 1, state + 2, 10),),
        default_target=99,
    )
    transition = StateWriteTransition(10, state, None, False, None)

    assert build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset(),
    ) == []


def test_empty_handler_set_accepts_matching_singleton_interval_entry() -> None:
    """A width-one interval is independent exact evidence for its target."""
    state = 0x16AA65E9
    dispatcher = IntervalDispatcher(
        [IntervalRow(state, state + 1, 10)], compute_default=False
    )

    assert build_state_write_redirects(
        _interval_entry_flow_graph(),
        dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset(),
    ) == [RedirectGoto(from_serial=0, old_target=2, new_target=10)]


def test_exact_state_dispatcher_map_handler_row_accepts_empty_handler_set() -> None:
    """An exact StateDispatcherMap row independently proves the handler."""
    state = 0x16AA65E9
    _interval_dispatcher, dispatch_map = _equality_dispatcher(
        {state: 10}, entry_block=2, compare_blocks=(20,)
    )

    assert build_state_write_redirects(
        _interval_entry_flow_graph(),
        _StateMapDispatcher(dispatch_map),
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset(),
    ) == [RedirectGoto(from_serial=0, old_target=2, new_target=10)]


def test_materialized_state_route_provider_adapter_is_removed() -> None:
    assert not hasattr(
        minimal_unflatten_emit_module, "_MaterializedStateRouteProvider"
    )


def test_interval_route_source_kinds_are_retained_in_transition_proof(_seam) -> None:
    """Accepted interval routing remains visible on the typed transition proof."""
    state = 0x16AA65E9
    fg = FlowGraph(
        blocks={
            2: _b(2, (10, 13, 99), (10,)),
            10: _b(
                10,
                (2,),
                (2,),
                (_mov_state(0x2010, state),),
            ),
            13: _b(13, (2,), (2,)),
            99: replace(_b(99, (), (2,)), kind=BlockKind.STOP),
        },
        entry_serial=2,
        func_ea=0x2000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(
            IntervalRow(0x079323FA, 0x1888937E, 10),
            IntervalRow(0x1888937E, 0x1888937F, 13),
            IntervalRow(0x1BABC1DC, 0x1BABC1DD, 2),
        ),
        default_target=99,
    )

    transitions = minimal_unflatten_emit_module.recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        dispatcher,
        _STATE,
        dispatcher_entry_serial=2,
    )
    transition = next(t for t in transitions if t.write_block == 10)

    assert transition.target_handler == 10
    assert transition.proof is not None
    assert transition.proof.route_source_kinds == ("interval",)


def test_interval_route_source_kinds_are_retained_in_accepted_entry_proof(_seam) -> None:
    """Accepted scalar entry routing exposes typed interval provenance."""
    state = 0x16AA65E9
    dispatcher = _DualRouteDispatcher(
        exact_targets={}, interval_rows=_interval_rows(), default_target=99
    )

    plan = emit_minimal_unflatten(
        _interval_entry_flow_graph(),
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            _interval_entry_flow_graph(),
            DecisionDag(32, {}, root=2),
            frozenset({10, 13}),
            dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(
            _interval_entry_flow_graph(),
        ),
    )

    _assert_no_legacy_plan_metadata(plan)


@pytest.mark.parametrize(
    "shape_error",
    [AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError],
)
def test_malformed_interval_row_target_abstains(shape_error) -> None:
    """Provider-shape failures do not authorize an entry redirect."""
    state = 0x16AA65E9
    modifications = build_state_write_redirects(
        _interval_entry_flow_graph(),
        _MalformedIntervalDispatcher(shape_error, state),
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=state,
        condition_chain_handlers=frozenset({10, 13}),
    )

    assert modifications == []


def test_runtime_error_from_interval_row_target_propagates() -> None:
    """Unexpected provider failures remain visible to callers."""
    state = 0x16AA65E9
    with pytest.raises(RuntimeError, match="malformed interval target"):
        build_state_write_redirects(
            _interval_entry_flow_graph(),
            _MalformedIntervalDispatcher(RuntimeError, state),
            (),
            dispatcher_entry_serial=2,
            pre_header_serial=0,
            initial_state=state,
            condition_chain_handlers=frozenset({10, 13}),
        )
def test_state_route_conflict_abstains_before_any_fragment_modification(
    monkeypatch,
    _seam,
) -> None:
    """A stale interval row cannot leak beside conflicting exact DAG evidence."""

    state = 0x079323F9
    carrier = MopSnapshot(
        t=_T_REG,
        size=4,
        reg=8,
        kind=OperandKind.REGISTER,
    )
    state_slot = MopSnapshot(
        t=_T_STK,
        size=4,
        stkoff=_STATE,
        kind=OperandKind.STACK,
    )
    carrier_to_state = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1300,
        operands=(),
        l=carrier,
        d=state_slot,
        kind=InsnKind.MOV,
    )
    graph = FlowGraph(
        blocks={
            3: _b(3, (4,), (2, 10, 13, 15, 16), (carrier_to_state,)),
            4: _b(4, (9, 2), (3,)),
            9: _b(9, (12, 15), (4,)),
            12: _b(12, (10, 19), (9,)),
            2: _b(2, (3,), (4,)),
            10: _b(10, (3,), (12,)),
            13: _b(13, (3,), ()),
            15: _b(15, (3,), (9,)),
            16: _b(16, (3,), ()),
            19: _exit_block(19, (12,)),
        },
        entry_serial=16,
        func_ea=0x1000,
    )
    dag = DecisionDag(
        32,
        {
            4: RouteComparison(4, "jz", 0x1BABC1DC, 2, 9),
            9: RouteComparison(9, "jz", state, 15, 12),
            12: RouteComparison(12, "jz", 0x1939CB36, 19, 10),
        },
        root=4,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(
                16,
                state,
                13,
                False,
                None,
                via_block=3,
                proof=TransitionProof(
                    "region_partitioned_fixpoint",
                    "region_seeded",
                    True,
                    route_source_kinds=("interval",),
                ),
            ),
        ),
    )

    dispatcher = _disp({}, exit_block=19)
    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=3,
        materialized_state_routes=(
            MaterializedStateRoute(16, state, 13),
        ),
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({2, 10, 13, 15, 19}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({2, 10, 13, 15, 19}),
        dispatcher_region_serials=frozenset({4, 9, 12}),
    )

    assert graph_modifications(plan) == []


def _task5_carrier_const(ea: int, value: int, reg: int = 8) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=4, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _task5_goto(ea: int, target: int = 3) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=55,
        ea=ea,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
        kind=InsnKind.GOTO,
    )


def _task5_carrier_fixture(
    *,
    initial_state: int = 0x079323F9,
) -> tuple[FlowGraph, DecisionDag]:
    carrier_to_state = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1300,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )
    graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (3,),
                (0,),
                (
                    _task5_carrier_const(0x1100, initial_state),
                    _task5_goto(0x1101),
                ),
            ),
            2: _b(2, (3,), (4,), (_task5_carrier_const(0x1200, 0x1939CB36),)),
            3: _b(3, (4,), (1, 2, 14, 15), (carrier_to_state,)),
            4: _b(4, (2, 9), (3,)),
            9: _b(9, (12, 15), (4,)),
            10: _b(10, (), (12,)),
            12: _b(12, (10, 19), (9,)),
            14: _b(
                14,
                (3,),
                (),
                (
                    _task5_carrier_const(0x1E00, 0x6CF816C1),
                    _task5_goto(0x1E01),
                ),
            ),
            15: _b(
                15,
                (3,),
                (9,),
                (
                    _task5_carrier_const(0x1F00, 0x079323F9),
                    _task5_goto(0x1F01),
                ),
            ),
            19: _b(19, (), (12,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dag = DecisionDag(
        32,
        {
            4: RouteComparison(4, "jz", 0x1BABC1DC, 2, 9),
            9: RouteComparison(9, "jz", 0x079323F9, 15, 12),
            12: RouteComparison(12, "jz", 0x1939CB36, 19, 10),
        },
        root=4,
    )
    return graph, dag


def test_native_entry_receipt_upgrades_exact_carrier_delivery_to_typed_fact() -> None:
    """A native entry receipt is provenance for the existing carrier proof."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = replace(_native_bound_route(
        source=1,
        state=state,
        target=10,
        fact_id="eid-entry-carrier",
    ), source_instruction_ea=0x1100)

    fact = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )

    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.STATE_CARRIER
    assert fact.fact_id == route.fact_id
    assert fact.owner_serial == route.source_block_serial
    assert fact.source_serial == route.source_block_serial
    assert fact.source_instruction_ea == route.source_instruction_ea
    assert fact.state_constant == route.state_constant
    assert fact.target_serial == route.target_handler_serial
    assert fact.physical_state_write is None
    assert fact.carrier_witness is not None
    assert fact.carrier_witness.source_serial == 1
    assert fact.carrier_witness.feeder_serial == 3
    assert fact.carrier_witness.comparison_entry_serial == 4

    refs = {}
    for serial, block in graph.blocks.items():
        exact_eas = tuple(
            int(insn.native_ea or insn.ea) for insn in block.insn_snapshots
        )
        anchors = (int(block.start_ea), *exact_eas)
        refs[serial] = NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(min(anchors), max(anchors) + 1),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=exact_eas,
        ))
    context = CanonicalSemanticEvidenceProductionContext(
        native_key=NATIVE_KEY,
        generation=0,
        atomic_group_id="eid-entry-carrier",
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        blocks=tuple(graph.blocks.values()),
        identities_by_serial=tuple(
            (int(serial), ref.identity) for serial, ref in refs.items()
        ),
        entry_serial=graph.entry_serial,
    )
    result = semantic_route_evidence_module.build_canonical_semantic_evidence(
        (fact,), context,
    )
    assert result.abstention is None
    assert result.evidence is not None
    catalog = minimal_unflatten_emit_module.build_source_identity_catalog(
        graph,
        refs,
        source_generation=0,
        canonical_route_evidence=result.evidence,
    )
    proof = minimal_unflatten_emit_module.adapt_native_bound_transition_route(
        route,
        source=graph,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_evidence=result.evidence,
        semantic_route_fact=fact,
    )
    assert proof.proof_kind.name == "STATE_CARRIER"
    assert proof.state_carrier is not None
    assert proof.state_carrier.source_identity == refs[1].identity
    assert proof.state_carrier.feeder_identity == refs[3].identity
    assert proof.state_carrier.comparison_entry_identity == refs[4].identity
    carrier = proof.state_carrier
    assert carrier is not None
    source_witnesses = {item.block_ref: item for item in catalog.blocks}
    exact = dict(
        source_witnesses=source_witnesses,
        replacement_ref=refs[10],
        redirect_owner_ref=refs[1],
        dispatcher_old_target_ref=refs[3],
        state_production_source_ref=refs[1],
        state_production_instruction_ea=0x1100,
        route_proof_id=proof.proof_id,
        selected_ids={proof.proof_id},
        proof=proof,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        normalized_state=state,
    )
    assert _entry_liveness_route_proof_rejection_detail(**exact) is None

    # The emitter supplies these exact source-catalogue coordinates before it
    # chooses the entry proof.  Each relation is part of the selected route,
    # rather than a descriptive carrier hint.
    missing_source = dict(source_witnesses)
    del missing_source[refs[1]]
    # Duplicate corridor identities are rejected before the entry matcher.
    with pytest.raises(semantic_route_evidence_module.SemanticRouteEvidenceRejected, match="corridor"):
        replace(
            carrier,
            comparison_entry_identity=carrier.feeder_identity,
            comparison_entry_anchor_ea=carrier.feeder_anchor_ea,
            corridor=carrier.corridor[:2] + (carrier.corridor[1],),
        )
    non_instruction_source_anchor = next(
        point
        for interval in carrier.source_identity.native_ranges.intervals
        for point in range(interval.start_ea, interval.end_ea)
        if point not in carrier.source_identity.exact_instruction_eas
    )
    source_anchor_drift = replace(
        carrier,
        source_anchor_ea=non_instruction_source_anchor,
        corridor=(
            semantic_route_evidence_module.SemanticCorridorPoint(
                carrier.source_identity, non_instruction_source_anchor,
            ),
            *carrier.corridor[1:],
        ),
    )
    proof_with_source_anchor_drift = replace(
        proof,
        source_anchor_ea=non_instruction_source_anchor,
        state_carrier=source_anchor_drift,
    )
    for label, drift in (
        ("source witness", {"source_witnesses": missing_source}),
        ("state-production source", {"state_production_source_ref": refs[3]}),
        ("redirect owner", {"redirect_owner_ref": refs[3]}),
        ("dispatcher feeder", {"dispatcher_old_target_ref": refs[4]}),
        (
            "paired carrier source proof and allowance EA",
            {
                "proof": proof_with_source_anchor_drift,
                "state_production_instruction_ea": non_instruction_source_anchor,
            },
        ),
        ("destination", {"replacement_ref": refs[3]}),
        ("selected proof", {"selected_ids": set()}),
    ):
        assert _entry_liveness_route_proof_rejection_detail(
            **(exact | drift)
        ) is not None, label


def test_native_receipt_attaches_its_fact_id_to_matching_completed_carrier() -> None:
    """A rebound native receipt remains observable through a carrier proof."""
    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = replace(
        _native_bound_route(
            source=1,
            state=state,
            target=10,
            fact_id="eid-carrier-receipt",
        ),
        source_instruction_ea=0x1100,
    )
    fact = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.STATE_CARRIER
    transition = StateWriteTransition(
        1,
        state,
        10,
        False,
        None,
        via_block=3,
        semantic_route_fact=replace(fact, fact_id=None),
    )

    (enriched,) = enrich_native_bound_transition_routes(
        (transition,),
        (route,),
        flow_graph=graph,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
    )

    assert enriched.semantic_route_fact is not None
    assert enriched.semantic_route_fact.kind is SemanticRouteFactKind.STATE_CARRIER
    assert enriched.semantic_route_fact.fact_id == route.fact_id


def test_exact_state_carrier_native_target_outranks_stale_return_sentinel(
    _seam,
) -> None:
    """A typed carrier route must never be redirected to a logical STOP."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = replace(
        _native_bound_route(
            source=1,
            state=state,
            target=10,
            fact_id="eid-entry-carrier-return-sentinel",
        ),
        source_instruction_ea=0x1100,
    )
    fact = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.STATE_CARRIER
    transition = StateWriteTransition(
        1,
        state,
        10,
        True,
        None,
        via_block=3,
        proof=TransitionProof(
            "exact_source_carrier_decision_dag_route",
            "source_carrier_decision_dag_reconciled",
            True,
            route_source_kinds=("decision_dag", "source_carrier"),
        ),
        semantic_route_fact=fact,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(),
        default_target=99,
    )

    modifications = build_state_write_redirects(
        graph,
        dispatcher,
        (transition,),
        dispatcher_entry_serial=3,
        pre_header_serial=None,
        initial_state=None,
        suppress_legacy_endpoint_bridges=True,
    )

    assert RedirectGoto(from_serial=1, old_target=3, new_target=10) in modifications
    assert not any(
        isinstance(modification, RedirectGoto)
        and modification.from_serial == 1
        and modification.new_target == 99
        for modification in modifications
    )


def test_mismatched_state_carrier_fact_cannot_fall_back_to_logical_stop(
    _seam,
) -> None:
    """A stale typed carrier fact must abstain instead of becoming a return."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = replace(
        _native_bound_route(
            source=1,
            state=state,
            target=10,
            fact_id="eid-entry-carrier-target-drift",
        ),
        source_instruction_ea=0x1100,
    )
    fact = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )
    assert fact is not None
    transition = StateWriteTransition(
        1,
        state,
        19,
        True,
        None,
        via_block=3,
        proof=TransitionProof(
            "exact_source_carrier_decision_dag_route",
            "source_carrier_decision_dag_reconciled",
            True,
            route_source_kinds=("decision_dag", "source_carrier"),
        ),
        semantic_route_fact=fact,
    )

    assert build_state_write_redirects(
        graph,
        _DualRouteDispatcher(
            exact_targets={},
            interval_rows=(),
            default_target=99,
        ),
        (transition,),
        dispatcher_entry_serial=3,
        pre_header_serial=None,
        initial_state=None,
        suppress_legacy_endpoint_bridges=True,
    ) == []


@pytest.mark.parametrize(
    "mutation",
    ("source", "feeder", "state", "target", "topology"),
)
def test_native_entry_carrier_shape_rejects_exact_coordinate_drift(
    mutation: str,
) -> None:
    """Observed carrier syntax cannot fall back to a native assignment fact."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = replace(
        _native_bound_route(
            source=1,
            state=state,
            target=10,
            fact_id="eid-entry-carrier",
        ),
        source_instruction_ea=0x1100,
    )
    if mutation == "source":
        source = graph.get_block(1)
        graph = FlowGraph(
            {
                **graph.blocks,
                1: replace(
                    source,
                    insn_snapshots=(
                        source.insn_snapshots[0],
                        _mov_reg_from_reg(0x1101, 8, 9),
                        _task5_goto(0x1102),
                    ),
                ),
            },
            graph.entry_serial,
            graph.func_ea,
        )
    elif mutation == "feeder":
        feeder = graph.get_block(3)
        graph = FlowGraph(
            {
                **graph.blocks,
                3: replace(
                    feeder,
                    insn_snapshots=(
                        replace(
                            feeder.insn_snapshots[0],
                            d=MopSnapshot(
                                t=_T_STK,
                                size=4,
                                stkoff=_STATE + 4,
                                kind=OperandKind.STACK,
                            ),
                        ),
                    ),
                ),
            },
            graph.entry_serial,
            graph.func_ea,
        )
    elif mutation == "state":
        route = replace(route, state_constant=state + 1)
    elif mutation == "target":
        route = replace(route, target_handler_serial=19)
    else:
        source = graph.get_block(1)
        second = graph.get_block(10)
        graph = FlowGraph(
            {
                **graph.blocks,
                1: replace(source, succs=(3, 10)),
                10: replace(second, preds=(*second.preds, 1)),
            },
            graph.entry_serial,
            graph.func_ea,
        )

    fact = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )

    assert fact is None


def _task5_unresolved_transitions() -> tuple[StateWriteTransition, ...]:
    return tuple(
        StateWriteTransition(
            source,
            None,
            None,
            False,
            None,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "unresolved",
                False,
            ),
        )
        for source in (1, 2, 14, 15)
    )


def test_exact_source_carriers_plan_entry_bridge_and_backedges(
    monkeypatch,
    _seam,
) -> None:
    graph, dag = _task5_carrier_fixture()
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: _task5_unresolved_transitions(),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={
            0x079323F9: 15,
            0x1939CB36: 19,
            0x6CF816C1: 10,
        },
        interval_rows=(),
    )

    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=3,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({10, 15, 19}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({10, 15, 19}),
        dispatcher_region_serials=frozenset({3, 4, 9, 12}),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (1, 3, 15) in gotos
    assert (2, 3, 19) in gotos
    assert (14, 3, 10) in gotos


def test_exact_source_carrier_dag_route_authorizes_default_entry_leaf(
    monkeypatch,
    _seam,
) -> None:
    initial_state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=initial_state)
    source_carrier_fact = minimal_unflatten_emit_module._native_bound_route_fact(
        graph,
        replace(
            _native_bound_route(
                source=1,
                state=initial_state,
                target=10,
                fact_id="typed-default-entry-carrier",
            ),
            source_instruction_ea=0x1100,
        ),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )
    assert source_carrier_fact is not None
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        # This fixture exercises the one source-carrier entry receipt only.
        # Broad default rows remain insufficient absent this exact reconciled
        # source/feeder/handler proof.
        lambda *_args, **_kwargs: (
            StateWriteTransition(
                1,
                initial_state,
                10,
                False,
                None,
                via_block=3,
                proof=TransitionProof(
                    "exact_source_carrier_decision_dag_route",
                    "source_carrier_decision_dag_reconciled",
                    True,
                    route_source_kinds=("decision_dag", "source_carrier"),
                ),
                semantic_route_fact=source_carrier_fact,
            ),
        ),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        lambda rows, *_args, **_kwargs: tuple(rows),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0, 0x100000000, 10),),
        default_target=10,
    )

    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=3,
        initial_state=initial_state,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({10, 15, 19}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({10, 15, 19}),
        dispatcher_region_serials=frozenset({3, 4, 9, 12}),
    )

    assert RedirectGoto(from_serial=1, old_target=3, new_target=10) in (
        graph_modifications(plan)
    )
    _assert_no_legacy_plan_metadata(plan)


def test_source_carrier_entry_route_accepts_complete_multi_predecessor_partition(
    _seam,
) -> None:
    state_a = 0x34BF5A81
    state_b = 0x4E6E550E
    graph = FlowGraph(
        {
            0: _b(0, (1, 2), ()),
            1: _b(1, (3,), (0,)),
            2: _b(2, (3,), (0,)),
            3: _b(3, (4,), (1, 2)),
            4: _b(4, (10, 11), (3,)),
            10: _b(10, (), (4,)),
            11: _b(11, (), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    def carrier(source: int, state: int, target: int) -> StateWriteTransition:
        return StateWriteTransition(
            source,
            state,
            target,
            False,
            None,
            via_block=3,
            proof=TransitionProof(
                "exact_source_carrier_decision_dag_route",
                "source_carrier_decision_dag_reconciled",
                True,
                route_source_kinds=("decision_dag", "source_carrier"),
            ),
        )

    complete = (carrier(1, state_a, 10), carrier(2, state_b, 11))
    resolution = minimal_unflatten_emit_module._trusted_source_carrier_entry_route(
        graph,
        dispatcher_entry_serial=3,
        state=state_a,
        state_write_transitions=complete,
        dispatcher_region_serials=frozenset({3, 4}),
    )

    assert not resolution.conflict
    assert resolution.route is not None
    assert resolution.route.normalized_state == state_a
    assert resolution.route.target_block == 10

    incomplete = minimal_unflatten_emit_module._trusted_source_carrier_entry_route(
        graph,
        dispatcher_entry_serial=3,
        state=state_a,
        state_write_transitions=complete[:1],
        dispatcher_region_serials=frozenset({3, 4}),
    )
    assert incomplete.conflict
    assert incomplete.route is None


def test_exact_state_carrier_survives_canonical_entry_liveness_selection(
    monkeypatch,
    _seam,
) -> None:
    """The current source-carrier corridor is entry state authority itself."""

    class _CleanUseDefSafety:
        def redirect_use_def_violations(self, *_args, **_kwargs):
            return ()

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = replace(
        _native_bound_route(
            source=1,
            state=state,
            target=10,
            fact_id="typed-entry-liveness-carrier",
        ),
        source_instruction_ea=0x1100,
    )
    fact = _native_bound_route_fact(
        graph,
        route,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE),
        decision_dag=dag,
    )
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.STATE_CARRIER
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(
                1,
                state,
                10,
                False,
                None,
                via_block=3,
                proof=TransitionProof(
                    "exact_source_carrier_decision_dag_route",
                    "source_carrier_decision_dag_reconciled",
                    True,
                    route_source_kinds=("decision_dag", "source_carrier"),
                ),
                semantic_route_fact=fact,
            ),
        ),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        lambda rows, *_args, **_kwargs: tuple(rows),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0, 0x100000000, 10),),
        default_target=10,
    )

    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=3,
        initial_state=state,
        entry_bridge_exit_path_blocks=(3, 4, 9, 12),
        entry_bridge_requires_witness=True,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph,
            dag,
            frozenset({10, 15, 19}),
            dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({10, 15, 19}),
        dispatcher_region_serials=frozenset({3, 4, 9, 12}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    assert RedirectGoto(from_serial=1, old_target=3, new_target=10) in (
        graph_modifications(plan)
    )


def test_native_entry_carrier_receipt_drives_typed_emitter_forecast(
    monkeypatch,
    _seam,
) -> None:
    """The public entry path consumes carrier authority, not native relabeling."""

    state = 0x16AA65E9
    graph, dag = _task5_carrier_fixture(initial_state=state)
    route = NativeBoundTransitionRoute(
        "eid-entry-carrier",
        0x1100,
        1,
        state,
        10,
    )
    refs = {}
    for serial, block in graph.blocks.items():
        exact_eas = tuple(
            int(insn.native_ea or insn.ea) for insn in block.insn_snapshots
        )
        anchors = (int(block.start_ea), *exact_eas)
        refs[serial] = NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(min(anchors), max(anchors) + 1),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=exact_eas,
        ))
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            StateWriteTransition(
                1,
                None,
                None,
                False,
                None,
                proof=TransitionProof(
                    "region_partitioned_fixpoint",
                    "unresolved",
                    False,
                ),
            ),
        ),
    )
    forecast_inputs = []
    selected_proofs = []
    original_forecast = minimal_unflatten_emit_module.ConcreteEntryRouteForecast
    original_adapter = minimal_unflatten_emit_module.adapt_native_bound_transition_route

    def capture_forecast(*args, **kwargs):
        forecast_inputs.append(kwargs)
        return original_forecast(*args, **kwargs)

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "ConcreteEntryRouteForecast",
        capture_forecast,
    )

    def capture_adapter(*args, **kwargs):
        proof = original_adapter(*args, **kwargs)
        selected_proofs.append(proof)
        return proof

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "adapt_native_bound_transition_route",
        capture_adapter,
    )

    plan = emit_minimal_unflatten(
        graph,
        _DualRouteDispatcher(
            exact_targets={},
            interval_rows=(IntervalRow(0, 0x100000000, 10),),
            default_target=10,
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=3,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({10, 15, 19}), dispatcher=_DualRouteDispatcher(
                exact_targets={}, interval_rows=(),
            ), block_refs=refs,
        ),
        authoritative_handler_serials=frozenset({10, 15, 19}),
        dispatcher_region_serials=frozenset({3, 4, 9, 12}),
        native_bound_transition_routes=(route,),
        native_key=NATIVE_KEY,
        block_refs_by_serial=refs,
    )

    assert len(forecast_inputs) == 1
    forecast = forecast_inputs[0]
    assert forecast["physical_fact_id"] == route.fact_id
    assert forecast["source_anchor_ea"] == route.source_instruction_ea
    assert forecast["state_identity"] == StorageIdentity(
        StorageIdentityKind.STACK,
        _STATE,
    )
    assert len(selected_proofs) == 1
    assert selected_proofs[0].proof_id == forecast["canonical_proof_id"]
    assert selected_proofs[0].proof_kind.name == "STATE_CARRIER"
    assert selected_proofs[0].state_carrier is not None


def _task5_trusted_entry_transition(
    *,
    state: int = 0x16AA65E9,
    target: int = 10,
    source: int = 1,
    via: int = 3,
    trusted: bool = True,
    oracle_kind: str = "exact_source_carrier_decision_dag_route",
    kind: str = "source_carrier_decision_dag_reconciled",
    route_source_kinds: tuple[str, ...] = ("decision_dag", "source_carrier"),
) -> StateWriteTransition:
    return StateWriteTransition(
        source,
        state,
        target,
        False,
        None,
        via_block=via,
        proof=TransitionProof(
            oracle_kind,
            kind,
            trusted,
            route_source_kinds=route_source_kinds,
        ),
    )


def _task5_entry_route_resolution(
    graph: FlowGraph,
    dispatcher: object,
    transitions: tuple[StateWriteTransition, ...],
    *,
    state: int = 0x16AA65E9,
):
    return minimal_unflatten_emit_module._resolve_entry_state_route_resolution(
        dispatcher,
        state,
        materialized_state_routes=(),
        condition_chain_handlers=frozenset({15, 19}),
        dispatcher_entry_serial=3,
        flow_graph=graph,
        state_write_transitions=transitions,
        dispatcher_region_serials=frozenset({3, 4, 9, 12}),
    )


def _task5_default_dispatcher(target: int = 10) -> _DualRouteDispatcher:
    return _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0, 0x100000000, target),),
        default_target=target,
    )


def _nested_source_scoped_entry_fixture() -> tuple[FlowGraph, DecisionDag]:
    state = 0x704FAFF6
    blocks = {
        0: _b(0, (2,), ()),
        2: _b(2, (3,), (0,), (_mov_state(0x1800151C6, state),)),
        222: _b(222, (3,), (100,)),
        3: _b(3, (5,), (2, 222), (_mov_state(0x1800151C9, 0),)),
        5: replace(
            _eq_block(5, state, 304, 100, preds=(3,)),
            start_ea=0x1800151E1,
        ),
        100: _b(100, (222,), (5,)),
        304: _b(304, (200,), (5,), (_mov_reg_from_stack(0x18001F0AE, 0, 0x150),)),
        200: _exit_block(200, (304,)),
    }
    return FlowGraph(blocks, 0, 0x180015110), DecisionDag(
        32,
        {5: RouteComparison(5, "jz", state, 304, 100)},
        root=5,
    )


def _nested_source_scoped_entry_transition(
    *, target: int = 304, trusted: bool = True
) -> StateWriteTransition:
    return StateWriteTransition(
        2,
        0x704FAFF6,
        target,
        False,
        None,
        via_block=3,
        proof=TransitionProof(
            "decision_dag_state_route_reconciliation",
            "decision_dag_reconciled",
            trusted,
            route_source_kinds=("decision_dag",),
        ),
    )


@pytest.mark.parametrize("default_target", (200, 304))
def test_nested_source_scoped_entry_route_uses_reconciled_transition(
    monkeypatch,
    _seam,
    default_target: int,
) -> None:
    """A shared feeder is bridged only on its exact initial source partition."""

    graph, dag = _nested_source_scoped_entry_fixture()
    transition = _nested_source_scoped_entry_transition()
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (transition,),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        lambda rows, *_args, **_kwargs: tuple(rows),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0x6FB5D126, 0x709608EC, 304),),
        default_target=default_target,
    )

    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=5,
        initial_state=0x704FAFF6,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        # The current selected-root handler set is partial and omits the exact
        # semantic leaf reached by this source-scoped DAG route.
        authoritative_handler_serials=frozenset({100, 304}),
        dispatcher_region_serials=frozenset({5}),
        materialized_computed_goto_profile=False,
    )

    redirects = tuple(
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    )
    assert RedirectGoto(2, 3, 304) in redirects
    assert not any(
        modification.from_serial == 3 and modification.old_target == 5
        for modification in graph_modifications(plan)
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    )
    assert not any(
        modification.from_serial == 222
        for modification in graph_modifications(plan)
    )
    _assert_no_legacy_plan_metadata(plan)


def test_source_scoped_entry_proof_can_route_to_default_handler(_seam) -> None:
    graph, _dag = _nested_source_scoped_entry_fixture()
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(),
        default_target=304,
    )

    resolution = minimal_unflatten_emit_module._resolve_entry_state_route_resolution(
        dispatcher,
        0x704FAFF6,
        materialized_state_routes=(),
        condition_chain_handlers=frozenset({100}),
        dispatcher_entry_serial=5,
        flow_graph=graph,
        state_write_transitions=(_nested_source_scoped_entry_transition(),),
        dispatcher_region_serials=frozenset({5}),
    )

    assert resolution.source_scoped is True
    assert resolution.route is not None
    assert resolution.route.target_block == 304


def test_untrusted_source_scoped_default_route_is_not_an_entry_proof(_seam) -> None:
    graph, _dag = _nested_source_scoped_entry_fixture()
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(),
        default_target=304,
    )

    resolution = minimal_unflatten_emit_module._resolve_entry_state_route_resolution(
        dispatcher,
        0x704FAFF6,
        materialized_state_routes=(),
        condition_chain_handlers=frozenset({100}),
        dispatcher_entry_serial=5,
        flow_graph=graph,
        state_write_transitions=(
            _nested_source_scoped_entry_transition(trusted=False),
        ),
        dispatcher_region_serials=frozenset({5}),
    )

    assert resolution.route is None


def test_nested_source_scoped_entry_route_conflict_abstains_atomically(
    monkeypatch,
    _seam,
) -> None:
    graph, dag = _nested_source_scoped_entry_fixture()
    transition = _nested_source_scoped_entry_transition()
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (transition,),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        lambda rows, *_args, **_kwargs: tuple(rows),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0x6FB5D126, 0x709608EC, 100),),
        default_target=200,
    )

    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=5,
        initial_state=0x704FAFF6,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({100, 304}),
        dispatcher_region_serials=frozenset({5}),
        materialized_computed_goto_profile=False,
    )

    assert graph_modifications(plan) == []


@pytest.mark.parametrize("variant", ("untrusted", "one_sided", "ambiguous"))
def test_nested_source_scoped_entry_route_fails_closed(variant: str) -> None:
    graph, _dag = _nested_source_scoped_entry_fixture()
    transition = _nested_source_scoped_entry_transition(
        trusted=variant != "untrusted"
    )
    transitions = (transition,)
    if variant == "one_sided":
        graph = FlowGraph(
            graph.blocks
            | {3: replace(graph.blocks[3], preds=(222,))},
            graph.entry_serial,
            graph.func_ea,
        )
    elif variant == "ambiguous":
        transitions = (
            transition,
            replace(transition, write_block=222),
        )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(0x6FB5D126, 0x709608EC, 304),),
        default_target=200,
    )

    resolution = minimal_unflatten_emit_module._resolve_entry_state_route_resolution(
        dispatcher,
        0x704FAFF6,
        materialized_state_routes=(),
        condition_chain_handlers=frozenset({100}),
        dispatcher_entry_serial=5,
        flow_graph=graph,
        state_write_transitions=transitions,
        dispatcher_region_serials=frozenset({5}),
    )

    assert resolution.route is None
    assert resolution.source_scoped is False


_PREFIX_SELECTED_STATE = 0x1DF15DAB
_PREFIX_ALTERNATE_STATE = 0x50884FCC
_PREFIX_COMPARE_STATE = 0x423C3FEB
_PREFIX_DAG_STATE = 0x0EE1BCAD


def _candidate_prefix_compare_block() -> BlockSnapshot:
    return BlockSnapshot(
        serial=4,
        block_type=4,
        succs=(20, 15),
        preds=(400, 401, 402),
        flags=0,
        start_ea=0x180037940,
        insn_snapshots=(
            InsnSnapshot(
                opcode=0x4A,
                ea=0x180037970,
                operands=(),
                l=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=_STATE,
                    kind=OperandKind.STACK,
                ),
                r=MopSnapshot(
                    t=_T_NUM,
                    size=4,
                    value=_PREFIX_COMPARE_STATE,
                    kind=OperandKind.NUMBER,
                ),
                d=MopSnapshot(
                    t=0,
                    size=0,
                    block_ref=15,
                    kind=OperandKind.BLOCK,
                ),
                kind=InsnKind.COND_JUMP,
                branch_predicate=PredicateKind.SLE,
                is_conditional_jump=True,
            ),
        ),
    )


def _candidate_prefix_emitter_fixture() -> tuple[FlowGraph, DecisionDag]:
    """Non-materialized equality-chain with one omitted current-snapshot prefix."""

    unknown_state_write = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x180046E00,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )
    graph = FlowGraph(
        blocks={
            4: _candidate_prefix_compare_block(),
            15: _eq_block(
                15,
                _PREFIX_DAG_STATE,
                100,
                101,
                preds=(4, 100, 101, 403, 490, 495),
            ),
            20: _b(20, (200,), (4,)),
            100: _b(100, (15,), (15,)),
            101: _b(101, (15,), (15,)),
            200: _exit_block(200, (20,)),
            399: _b(399, (400, 401, 402, 403, 490, 495), ()),
            400: _b(400, (4,), (399,), (unknown_state_write,)),
            401: _b(401, (4,), (399,), (_mov_state(0x180046F00, _PREFIX_ALTERNATE_STATE),)),
            402: _b(402, (4,), (399,), (_mov_state(0x180047000, _PREFIX_SELECTED_STATE),)),
            403: _b(403, (15,), (399,), (_mov_state(0x180047100, _PREFIX_SELECTED_STATE),)),
            490: _b(490, (15,), (399,), (_mov_state(0x18004A100, _PREFIX_ALTERNATE_STATE),)),
            495: _b(495, (15,), (399,), (_mov_state(0x18004A600, _PREFIX_DAG_STATE),)),
        },
        entry_serial=399,
        func_ea=0x180037880,
    )
    dag = DecisionDag(
        32,
        {
            15: RouteComparison(
                15,
                "jz",
                _PREFIX_DAG_STATE,
                100,
                101,
            ),
        },
        root=15,
    )
    return graph, dag


def _candidate_prefix_partitioned_emitter_fixture() -> tuple[FlowGraph, DecisionDag]:
    """Faithful two-hop source -> feeder -> omitted-prefix topology."""

    graph, dag = _candidate_prefix_emitter_fixture()
    blocks = dict(graph.blocks)
    blocks.pop(400)
    blocks[399] = replace(blocks[399], succs=(401, 402, 403, 490, 495))
    blocks[4] = replace(blocks[4], preds=(330,))
    blocks[330] = _b(
        330,
        (4,),
        (401, 402),
        (_mov_state(0x180042930, _PREFIX_SELECTED_STATE),),
    )
    blocks[401] = replace(blocks[401], succs=(330,))
    blocks[402] = replace(blocks[402], succs=(330,))
    return FlowGraph(blocks, graph.entry_serial, graph.func_ea), dag


def _candidate_prefix_transition(
    source: int,
    state: int,
    target: int,
    *,
    via: int,
    route_source_kinds: tuple[str, ...] = ("region_partitioned_fixpoint",),
    proof_kind: str = "global_fold",
) -> StateWriteTransition:
    return StateWriteTransition(
        source,
        state,
        target,
        False,
        None,
        via_block=via,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            proof_kind,
            True,
            route_source_kinds=route_source_kinds,
        ),
    )


def test_emitter_threads_one_candidate_prefix_authority_before_recovery(
    monkeypatch,
    _seam,
) -> None:
    """The emitter, not late reconciliation, owns prefix classification order."""

    graph, dag = _candidate_prefix_emitter_fixture()
    observation = minimal_state_recovery_module._observe_candidate_scoped_prefix(
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is not None
    authority = observation.authority
    observer_calls: list[tuple[FlowGraph, DecisionDag]] = []
    recovery_calls: list[dict[str, object]] = []
    reconciliation_calls: list[dict[str, object]] = []

    def observe_once(flow_graph, decision_dag, **_kwargs):
        observer_calls.append((flow_graph, decision_dag))
        return observation

    def recover_with_scoped_feeders(*_args, **kwargs):
        recovery_calls.append(dict(kwargs))
        if kwargs.get("candidate_prefix_authority") is not authority:
            # Current production reaches this branch: the prefix is admitted as
            # one unresolved semantic back-edge instead of being router plumbing.
            return (
                StateWriteTransition(
                    4,
                    None,
                    None,
                    True,
                    None,
                    proof=TransitionProof(
                        "region_partitioned_fixpoint",
                        "unresolved",
                        False,
                    ),
                ),
            )
        return (
            _candidate_prefix_transition(401, _PREFIX_ALTERNATE_STATE, 101, via=4),
            _candidate_prefix_transition(402, _PREFIX_SELECTED_STATE, 101, via=4),
            _candidate_prefix_transition(403, _PREFIX_SELECTED_STATE, 101, via=15),
            _candidate_prefix_transition(490, _PREFIX_ALTERNATE_STATE, 101, via=15),
            _candidate_prefix_transition(495, _PREFIX_DAG_STATE, 100, via=15),
        )

    def reconcile_with_same_authority(transitions, *_args, **kwargs):
        reconciliation_calls.append(
            {"transitions": tuple(transitions), "kwargs": dict(kwargs)}
        )
        if kwargs.get("candidate_prefix_authority") is not authority:
            return ()
        by_source = {int(row.write_block): row for row in transitions}
        selected = replace(
            by_source[402],
            proof=replace(
                by_source[402].proof,
                route_source_kinds=(
                    "candidate_scoped_prefix_arm",
                    "decision_dag",
                ),
            ),
        )
        direct = tuple(
            replace(
                by_source[source],
                proof=replace(
                    by_source[source].proof,
                    route_source_kinds=("decision_dag",),
                ),
            )
            for source in (403, 490, 495)
        )
        return (selected, *direct)

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "observe_candidate_scoped_prefix_authority",
        observe_once,
        raising=False,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        recover_with_scoped_feeders,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        reconcile_with_same_authority,
    )

    plan = emit_minimal_unflatten(
        graph,
        _disp(
            {
                _PREFIX_SELECTED_STATE: 101,
                _PREFIX_ALTERNATE_STATE: 101,
                _PREFIX_DAG_STATE: 100,
            },
            exit_block=200,
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100, 101}), dispatcher=_disp(
                {_PREFIX_SELECTED_STATE: 101, _PREFIX_ALTERNATE_STATE: 101, _PREFIX_DAG_STATE: 100},
                exit_block=200,
            ),
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({100, 101}),
        dispatcher_region_serials=frozenset({15}),
        recover_multi_entry_back_edges=False,
        materialized_computed_goto_profile=False,
    )

    assert observer_calls == [(graph, dag)]
    assert len(recovery_calls) == 1
    assert recovery_calls[0]["dispatcher_region_serials"] == frozenset({4})
    assert recovery_calls[0]["candidate_prefix_authority"] is authority
    assert len(reconciliation_calls) == 1
    assert reconciliation_calls[0]["kwargs"]["candidate_prefix_authority"] is authority
    reconciled = reconciliation_calls[0]["transitions"]
    assert tuple(int(row.write_block) for row in reconciled) == (401, 402, 403, 490, 495)

    redirects = tuple(
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    )
    assert RedirectGoto(402, 4, 101) in redirects
    assert RedirectGoto(403, 15, 101) in redirects
    assert RedirectGoto(490, 15, 101) in redirects
    assert RedirectGoto(495, 15, 100) in redirects
    assert all(modification.from_serial != 401 for modification in redirects)
    assert tuple(modification.from_serial for modification in redirects) == tuple(
        sorted(modification.from_serial for modification in redirects)
    )


def test_emitter_excludes_validated_prefix_from_seeded_back_edge_recovery(
    monkeypatch,
    _seam,
) -> None:
    """A current router prefix must never enter the semantic seeded DFS."""

    graph, dag = _candidate_prefix_emitter_fixture()
    seeded_targets: list[frozenset[int] | None] = []

    def record_seeded_targets(*_args, **kwargs):
        seeded_targets.append(kwargs.get("target_back_edges"))
        return {}

    monkeypatch.setattr(
        minimal_state_recovery_module,
        "_resolve_back_edge_states",
        record_seeded_targets,
    )
    # Stop after the real recovery result; this regression owns only the
    # recovery-classification boundary, not downstream plan construction.
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        lambda *_args, **_kwargs: (),
    )

    dispatcher = _disp(
        {
            _PREFIX_SELECTED_STATE: 101,
            _PREFIX_ALTERNATE_STATE: 101,
            _PREFIX_DAG_STATE: 100,
        },
        exit_block=200,
    )
    emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100, 101}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({100, 101}),
        dispatcher_region_serials=frozenset({15}),
        recover_multi_entry_back_edges=False,
        materialized_computed_goto_profile=False,
    )

    assert all(
        targets is None or 4 not in targets
        for targets in seeded_targets
    )


def test_candidate_prefix_recovery_merges_scoped_and_direct_sources_physically(
    _seam,
) -> None:
    graph, dag = _candidate_prefix_emitter_fixture()
    blocks = dict(graph.blocks)
    blocks.pop(400)
    blocks[399] = replace(blocks[399], succs=(401, 402, 403, 490, 495))
    blocks[4] = replace(blocks[4], preds=(401, 402))
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery_module.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is not None

    recovered = minimal_state_recovery_module.recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        _disp(
            {
                _PREFIX_SELECTED_STATE: 101,
                _PREFIX_ALTERNATE_STATE: 101,
                _PREFIX_DAG_STATE: 100,
            },
            exit_block=200,
        ),
        _STATE,
        dispatcher_entry_serial=15,
        dispatcher_region_serials=frozenset({4}),
        candidate_prefix_authority=observation.authority,
    )

    recovered_by_source = {int(row.write_block): row for row in recovered}
    assert tuple(recovered_by_source) == (100, 101, 401, 402, 403, 490, 495)
    assert all(recovered_by_source[source].via_block is None for source in (100, 101))
    assert tuple(recovered_by_source[source].via_block for source in (401, 402)) == (4, 4)
    assert tuple(
        int(recovered_by_source[source].via_block or 15)
        for source in (403, 490, 495)
    ) == (15, 15, 15)


def test_invalid_candidate_prefix_abstains_before_recovery_or_plan(
    monkeypatch,
    _seam,
) -> None:
    graph, dag = _candidate_prefix_emitter_fixture()
    malformed_prefix = replace(
        graph.blocks[4],
        insn_snapshots=(
            _call_reg(0x180037978, 8),
            *graph.blocks[4].insn_snapshots,
        ),
    )
    malformed = FlowGraph(
        blocks={**graph.blocks, 4: malformed_prefix},
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    observation = minimal_state_recovery_module._observe_candidate_scoped_prefix(
        malformed,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is None
    recovery_calls = 0

    def observe_invalid(*_args, **_kwargs):
        return observation

    def record_recovery(*_args, **_kwargs):
        nonlocal recovery_calls
        recovery_calls += 1
        return ()

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "observe_candidate_scoped_prefix_authority",
        observe_invalid,
        raising=False,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        record_recovery,
    )

    dispatcher = _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200)
    plan = emit_minimal_unflatten(
        malformed,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100, 101}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(malformed),
        authoritative_handler_serials=frozenset({100, 101}),
        materialized_computed_goto_profile=False,
    )

    assert recovery_calls == 0
    assert graph_modifications(plan) == []


@pytest.mark.parametrize(
    ("materialized_profile", "state_var_stkoff", "state_var_reg", "expected_region"),
    (
        (False, _STATE, None, frozenset()),
        (True, None, 20, frozenset({15})),
    ),
)
def test_candidate_prefix_not_applicable_preserves_legacy_recovery_region(
    monkeypatch,
    _seam,
    materialized_profile,
    state_var_stkoff,
    state_var_reg,
    expected_region,
) -> None:
    graph, dag = _candidate_prefix_emitter_fixture()
    root = graph.blocks[15]
    if state_var_reg is not None:
        comparison = root.insn_snapshots[0]
        root = replace(
            root,
            insn_snapshots=(replace(
                comparison,
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=int(state_var_reg),
                    kind=OperandKind.REGISTER,
                ),
            ),),
        )
    root = replace(root, preds=(100, 101, 403, 490, 495))
    no_prefix = FlowGraph(
        blocks={
            serial: block
            for serial, block in graph.blocks.items()
            if serial not in {4, 20, 399, 400, 401, 402}
        }
        | {
            15: root,
            200: replace(graph.blocks[200], preds=()),
            403: replace(graph.blocks[403], preds=()),
            490: replace(graph.blocks[490], preds=()),
            495: replace(graph.blocks[495], preds=()),
        },
        entry_serial=403,
        func_ea=graph.func_ea,
    )
    observation = minimal_state_recovery_module._observe_candidate_scoped_prefix(
        no_prefix,
        dag,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    assert observation.authority is None
    captured_regions: list[frozenset[int]] = []

    def capture_recovery(*_args, **kwargs):
        captured_regions.append(kwargs["dispatcher_region_serials"])
        return ()

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        capture_recovery,
    )

    dispatcher = _disp(
        {
            _PREFIX_SELECTED_STATE: 101,
            _PREFIX_ALTERNATE_STATE: 101,
            _PREFIX_DAG_STATE: 100,
        },
        exit_block=200,
    )
    emit_minimal_unflatten(
        no_prefix,
        dispatcher,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
        dispatcher_entry_serial=15,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            no_prefix,
            dag,
            frozenset({100, 101}),
            dispatcher=dispatcher,
            state_identity=(
                StorageIdentity(StorageIdentityKind.REGISTER, int(state_var_reg))
                if state_var_reg is not None
                else StorageIdentity(StorageIdentityKind.STACK, int(state_var_stkoff))
            ),
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(no_prefix),
        authoritative_handler_serials=frozenset({100, 101}),
        dispatcher_region_serials=frozenset({15}),
        recover_multi_entry_back_edges=False,
        materialized_computed_goto_profile=materialized_profile,
    )

    assert captured_regions == [expected_region]


def test_candidate_prefix_provider_conflict_is_fragment_atomic_after_threading(
    monkeypatch,
    _seam,
) -> None:
    graph, dag = _candidate_prefix_emitter_fixture()
    observation = minimal_state_recovery_module._observe_candidate_scoped_prefix(
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is not None
    authority = observation.authority
    reconciliation_authorities: list[object] = []

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "observe_candidate_scoped_prefix_authority",
        lambda *_args, **_kwargs: observation,
        raising=False,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (
            _candidate_prefix_transition(402, _PREFIX_SELECTED_STATE, 100, via=4),
        ),
    )

    def reject_conflict(_transitions, *_args, **kwargs):
        reconciliation_authorities.append(kwargs.get("candidate_prefix_authority"))
        return ()

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        reject_conflict,
    )

    dispatcher = _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200)
    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100, 101}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({100, 101}),
        materialized_computed_goto_profile=False,
    )

    assert reconciliation_authorities == [authority]
    assert graph_modifications(plan) == []


def test_supplied_candidate_prefix_is_revalidated_without_rediscovery(
    monkeypatch,
    _seam,
) -> None:
    graph, dag = _candidate_prefix_emitter_fixture()
    observation = minimal_state_recovery_module.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is not None
    monkeypatch.setattr(
        minimal_state_recovery_module,
        "_observe_candidate_scoped_prefix",
        lambda *_args, **_kwargs: pytest.fail("supplied authority was rediscovered"),
    )

    dispatcher = _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200)
    resolved = resolve_materialized_indirect_transfer_targets(
        (
            _candidate_prefix_transition(
                402,
                _PREFIX_SELECTED_STATE,
                101,
                via=4,
            ),
        ),
        graph,
        dispatcher,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE,
        candidate_prefix_authority=observation.authority,
    )

    assert len(resolved) == 1
    assert resolved[0].proof is not None
    assert "candidate_scoped_prefix_arm" in resolved[0].proof.route_source_kinds


def test_supplied_candidate_prefix_rejects_current_snapshot_drift(_seam) -> None:
    graph, dag = _candidate_prefix_emitter_fixture()
    observation = minimal_state_recovery_module.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is not None
    branch = graph.blocks[4].insn_snapshots[0]
    drifted = FlowGraph(
        blocks={
            **graph.blocks,
            4: replace(
                graph.blocks[4],
                insn_snapshots=(replace(branch, ea=int(branch.ea) + 1),),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    dispatcher = _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200)
    assert resolve_materialized_indirect_transfer_targets(
        (
            _candidate_prefix_transition(
                402,
                _PREFIX_SELECTED_STATE,
                101,
                via=4,
            ),
        ),
        drifted,
        dispatcher,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE,
        candidate_prefix_authority=observation.authority,
    ) == ()


def _partitioned_prefix_reconciled_rows() -> tuple[StateWriteTransition, ...]:
    selected = _candidate_prefix_transition(
        402,
        _PREFIX_SELECTED_STATE,
        101,
        via=330,
        route_source_kinds=(
            "candidate_scoped_prefix_arm",
            "decision_dag",
            "region_partitioned_fixpoint",
        ),
    )
    direct = (
        _candidate_prefix_transition(
            403,
            _PREFIX_SELECTED_STATE,
            101,
            via=15,
            route_source_kinds=("decision_dag", "region_partitioned_fixpoint"),
        ),
        _candidate_prefix_transition(
            490,
            _PREFIX_ALTERNATE_STATE,
            101,
            via=15,
            route_source_kinds=("decision_dag", "region_partitioned_fixpoint"),
        ),
        _candidate_prefix_transition(
            495,
            _PREFIX_DAG_STATE,
            100,
            via=15,
            route_source_kinds=("decision_dag", "region_partitioned_fixpoint"),
        ),
    )
    return (selected, *direct)


def _emit_partitioned_prefix_with_captured_routes(
    monkeypatch,
    *,
    include_selected_feeder: bool,
):
    graph, dag = _candidate_prefix_partitioned_emitter_fixture()
    observation = minimal_state_recovery_module.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE,
        state_var_reg=None,
    )
    assert observation.authority is not None
    authority = observation.authority
    recovered = (
        _candidate_prefix_transition(
            401,
            _PREFIX_ALTERNATE_STATE,
            101,
            via=330,
            proof_kind="predecessor_partitioned",
        ),
        _candidate_prefix_transition(
            402,
            _PREFIX_SELECTED_STATE,
            101,
            via=330,
            proof_kind="predecessor_partitioned",
        ),
        _candidate_prefix_transition(
            403,
            _PREFIX_SELECTED_STATE,
            101,
            via=15,
        ),
        _candidate_prefix_transition(
            490,
            _PREFIX_ALTERNATE_STATE,
            101,
            via=15,
        ),
        _candidate_prefix_transition(
            495,
            _PREFIX_DAG_STATE,
            100,
            via=15,
        ),
    )
    reconciled = _partitioned_prefix_reconciled_rows()
    if not include_selected_feeder:
        reconciled = tuple(row for row in reconciled if int(row.write_block) != 402)

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "observe_candidate_scoped_prefix_authority",
        lambda *_args, **_kwargs: observation,
    )

    def recover_once(*_args, **kwargs):
        assert kwargs["candidate_prefix_authority"] is authority
        return recovered

    def reconcile_once(_rows, *_args, **kwargs):
        assert kwargs["candidate_prefix_authority"] is authority
        return reconciled

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        recover_once,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        reconcile_once,
    )
    # Reproduce the live giant-SCC classification: every root predecessor is
    # reachable from entry without traversing root, although none is a scalar
    # entry endpoint.  Candidate-prefix authority must suppress this entire
    # LEGACY_ENDPOINT class rather than guessing one global state.
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_dispatcher_entry_preds",
        lambda *_args, **_kwargs: [4, 403, 490, 495],
    )
    plan = emit_minimal_unflatten(
        graph,
        _disp(
            {
                _PREFIX_SELECTED_STATE: 101,
                _PREFIX_ALTERNATE_STATE: 101,
                _PREFIX_DAG_STATE: 100,
            },
            exit_block=200,
        ),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        initial_state=_PREFIX_SELECTED_STATE,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100, 101}), dispatcher=_disp(
                {0x011A0881: 100, 0x33D9A310: 101, 0x2431DE88: 100, 0x1B30D140: 101,
                 0x2E160A90: 100, 0x0244FF40: 101, 0x60A0D558: 100}, exit_block=200,
            ),
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({100, 101}),
        dispatcher_region_serials=frozenset({15}),
        recover_multi_entry_back_edges=False,
        materialized_computed_goto_profile=False,
    )
    return plan


def test_candidate_prefix_plan_suppresses_all_legacy_root_entry_bridges(
    monkeypatch,
    _seam,
) -> None:
    """Only source-specific rows may cut prefix/root edges under this authority."""

    plan = _emit_partitioned_prefix_with_captured_routes(
        monkeypatch,
        include_selected_feeder=True,
    )
    redirects = tuple(
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    )

    assert set(redirects) == {
        RedirectGoto(402, 330, 101),
        RedirectGoto(403, 15, 101),
        RedirectGoto(490, 15, 101),
        RedirectGoto(495, 15, 100),
    }
    assert not any(
        modification.from_serial == 4 and modification.old_target == 15
        for modification in graph_modifications(plan)
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    )
    assert RedirectGoto(495, 15, 101) not in redirects
    _assert_no_legacy_plan_metadata(plan)


def test_candidate_prefix_preserved_feeder_uses_existing_pred_split_clone(
    _seam,
) -> None:
    """A source-specific selected route replays its semantic feeder body."""

    graph, _dag = _candidate_prefix_partitioned_emitter_fixture()
    transition = StateWriteTransition(
        402,
        _PREFIX_SELECTED_STATE,
        101,
        False,
        None,
        via_block=330,
        proof=TransitionProof(
            "decision_dag_state_route_reconciliation",
            "decision_dag_reconciled",
            True,
            route_source_kinds=(
                "candidate_scoped_prefix_arm",
                "preserved_feeder_clone",
            ),
        ),
        preserve_via_block=True,
    )

    modifications = build_state_write_redirects(
        graph,
        _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200),
        (transition,),
        dispatcher_entry_serial=15,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        suppress_legacy_endpoint_bridges=True,
    )

    assert modifications == [
        EdgeRedirectViaPredSplit(
            src_block=330,
            old_target=4,
            new_target=101,
            via_pred=402,
            clone_until=330,
        )
    ]


def test_candidate_prefix_preserved_setup_corridor_uses_multi_block_clone(
    _seam,
) -> None:
    """Retarget only after replaying feeder and post-state setup blocks."""

    graph, _dag = _candidate_prefix_partitioned_emitter_fixture()
    blocks = dict(graph.blocks)
    feeder = blocks[330]
    prefix = blocks[4]
    blocks[330] = replace(feeder, succs=(331,))
    blocks[331] = _b(331, (4,), (330,))
    blocks[4] = replace(prefix, preds=(331,))
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    transition = StateWriteTransition(
        402,
        _PREFIX_SELECTED_STATE,
        101,
        False,
        None,
        via_block=330,
        proof=TransitionProof(
            "decision_dag_state_route_reconciliation",
            "decision_dag_reconciled",
            True,
            route_source_kinds=(
                "candidate_scoped_prefix_arm",
                "preserved_feeder_clone",
            ),
        ),
        preserve_via_block=True,
        preserve_via_until=331,
    )

    modifications = build_state_write_redirects(
        graph,
        _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200),
        (transition,),
        dispatcher_entry_serial=15,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        suppress_legacy_endpoint_bridges=True,
    )

    assert modifications == [
        EdgeRedirectViaPredSplit(
            src_block=330,
            old_target=331,
            new_target=101,
            via_pred=402,
            clone_until=331,
        )
    ]


def test_candidate_prefix_incomplete_feeder_partition_stays_residual(
    monkeypatch,
    _seam,
) -> None:
    """Missing source authority cannot be hidden by one global prefix bridge."""

    plan = _emit_partitioned_prefix_with_captured_routes(
        monkeypatch,
        include_selected_feeder=False,
    )
    assert not any(
        modification.from_serial == 4 and modification.old_target == 15
        for modification in graph_modifications(plan)
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    )
    _assert_no_legacy_plan_metadata(plan)


def _candidate_prefix_captured_incomplete_emitter_fixture(
) -> tuple[FlowGraph, DecisionDag]:
    """Captured root15 shape with six direct rows and incomplete feeder3."""

    prefix = replace(_candidate_prefix_compare_block(), preds=(3,))
    root = replace(
        _eq_block(
            15,
            _PREFIX_DAG_STATE,
            100,
            101,
            preds=(4, 405, 492, 497),
        ),
        start_ea=0x180015268,
    )
    blocks = {
        4: prefix,
        15: root,
        20: _b(20, (200,), (4,)),
        200: _exit_block(200, (20,)),
        100: _b(100, (2, 351, 305, 365), (15,)),
        101: _b(101, (230, 404, 491, 496), (15,)),
        2: _b(2, (3,), (100,)),
        230: _b(230, (3,), (101,)),
        3: _b(3, (4,), (2, 230), (_mov_state(0x1800151C9, 0),)),
        351: _b(351, (405,), (100,)),
        404: _b(404, (405,), (101,)),
        405: _b(405, (15,), (351, 404), (_mov_state(0x18002672A, 0),)),
        305: _b(305, (492,), (100,)),
        491: _b(491, (492,), (101,)),
        492: _b(492, (15,), (305, 491), (_mov_state(0x18002B4D9, 0),)),
        365: _b(365, (497,), (100,)),
        496: _b(496, (497,), (101,)),
        497: _b(497, (15,), (365, 496), (_mov_state(0x18002BC5F, 0),)),
    }
    return FlowGraph(blocks, 15, 0x180015110), DecisionDag(
        32,
        {
            15: RouteComparison(
                15,
                "jz",
                _PREFIX_DAG_STATE,
                100,
                101,
            ),
        },
        root=15,
    )


def _captured_incomplete_emitter_provider_rows(
) -> dict[int, tuple[StateWriteTransition, ...]]:
    def row(
        source: int,
        via: int,
        state: int,
        target: int | None,
        *,
        trusted: bool,
    ) -> StateWriteTransition:
        return StateWriteTransition(
            source,
            state,
            target,
            target is None,
            None,
            via_block=via,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "predecessor_partitioned",
                trusted,
            ),
        )

    return {
        405: (
            row(351, 405, 0x011A0881, 100, trusted=True),
            row(404, 405, 0x33D9A310, 101, trusted=True),
        ),
        492: (
            row(305, 492, 0x2431DE88, 100, trusted=True),
            row(491, 492, 0x1B30D140, 101, trusted=True),
        ),
        497: (
            row(365, 497, 0x2E160A90, 100, trusted=True),
            row(496, 497, 0x0244FF40, 101, trusted=True),
        ),
        3: (
            row(2, 3, 0x704FAFF6, None, trusted=False),
            row(230, 3, 0x60A0D558, 100, trusted=True),
        ),
    }


def test_candidate_prefix_concrete_alternate_rows_reach_reconciliation(
    monkeypatch,
    _seam,
) -> None:
    """Concrete alternate hints are classified before selected redirects emit."""

    graph, dag = _candidate_prefix_captured_incomplete_emitter_fixture()
    provider_rows = _captured_incomplete_emitter_provider_rows()

    monkeypatch.setattr(
        minimal_state_recovery_module,
        "_resolve_next_state_before_seeded",
        lambda _ctx, pred, _block, _arm: list(provider_rows[int(pred)]),
    )

    reconcile_inputs = []

    def reconcile_direct(rows, *_args, **_kwargs):
        reconcile_inputs.append(tuple(int(row.write_block) for row in rows))
        return tuple(row for row in rows if int(row.write_block) not in {2, 230})

    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "resolve_materialized_indirect_transfer_targets",
        reconcile_direct,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_dispatcher_entry_preds",
        lambda *_args, **_kwargs: [4, 405, 492, 497],
    )

    dispatcher = _disp(
        {
            0x011A0881: 100,
            0x33D9A310: 101,
            0x2431DE88: 100,
            0x1B30D140: 101,
            0x2E160A90: 100,
            0x0244FF40: 101,
            0x60A0D558: 100,
        },
        exit_block=200,
    )
    plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        initial_state=_PREFIX_SELECTED_STATE,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            graph, dag, frozenset({100, 101}), dispatcher=dispatcher,
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(graph),
        authoritative_handler_serials=frozenset({100, 101}),
        dispatcher_region_serials=frozenset({15}),
        recover_multi_entry_back_edges=False,
        materialized_computed_goto_profile=False,
    )

    redirects = tuple(
        modification
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    )
    assert reconcile_inputs == [
        (2, 230, 351, 404, 305, 491, 365, 496)
    ]
    assert tuple(modification.from_serial for modification in redirects) == (
        351,
        404,
        305,
        491,
        365,
        496,
    )
    assert not any(
        modification.from_serial in {4, 405, 492, 497}
        and modification.old_target == 15
        for modification in graph_modifications(plan)
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    )
    _assert_no_legacy_plan_metadata(plan)


def test_candidate_prefix_not_applicable_keeps_legacy_endpoint_bridge(
    monkeypatch,
    _seam,
) -> None:
    """The bridge suppression is scoped to a VALID candidate-prefix authority."""

    graph, dag = _candidate_prefix_emitter_fixture()
    root = replace(graph.blocks[15], preds=(100, 101, 403, 490, 495))
    no_prefix = FlowGraph(
        {
            serial: block
            for serial, block in graph.blocks.items()
            if serial not in {4, 20, 399, 400, 401, 402}
        }
        | {
            15: root,
            200: replace(graph.blocks[200], preds=()),
            403: replace(graph.blocks[403], preds=()),
            490: replace(graph.blocks[490], preds=()),
            495: replace(graph.blocks[495], preds=()),
        },
        entry_serial=403,
        func_ea=graph.func_ea,
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        minimal_unflatten_emit_module,
        "_dispatcher_entry_preds",
        lambda *_args, **_kwargs: [403],
    )

    plan = emit_minimal_unflatten(
        no_prefix,
        _disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=15,
        initial_state=_PREFIX_SELECTED_STATE,
        condition_chain_route_evidence=_typed_condition_chain_evidence(
            no_prefix, dag, frozenset({100, 101}),
            dispatcher=_disp({_PREFIX_SELECTED_STATE: 101}, exit_block=200),
        ),
        block_refs_by_serial=_entry_dispatcher_map_test_refs(no_prefix),
        authoritative_handler_serials=frozenset({100, 101}),
        materialized_computed_goto_profile=False,
    )

    assert RedirectGoto(403, 15, 101) in graph_modifications(plan)


def test_emitter_does_not_expose_independent_interval_or_plumbing_route_authority() -> None:
    """Route selections must arrive through the typed authority/preflight result."""

    parameters = inspect.signature(
        minimal_unflatten_emit_module.emit_minimal_unflatten,
    ).parameters
    assert "interval_route_proofs" not in parameters
    assert "state_transition_plumbing_route_proofs" not in parameters


def test_emitter_does_not_deduplicate_family_route_authority_by_plain_set() -> None:
    """Collision evidence must remain observable until the authority binder decides."""

    implementation = inspect.getsource(minimal_unflatten_emit_module.emit_minimal_unflatten)
    assert "selected_route_proof_ids: set[str]" not in implementation


def _exact_table_multi_entry_fixture(*, slot=_STATE, width=4, reciprocal=True):
    tail = InsnSnapshot(
        opcode=0, ea=0x1080, operands=(), kind=InsnKind.TABLE_JUMP,
        l=MopSnapshot(t=0, size=width, stack_refs=(slot,), kind=OperandKind.SUBINSN),
        r=MopSnapshot(t=0, size=0, switch_cases=(((0,), 20), ((1,), 21)), kind=OperandKind.CASE_LIST),
    )
    source_succ = (9,) if reciprocal else (20,)
    return FlowGraph({
        2: _b(2, (20, 21), (9, 31), (tail,)),
        9: _b(9, (2,), (10, 11)),
        10: _b(10, source_succ, ()),
        11: _b(11, (9,), ()),
        20: _b(20, (), (2, 10) if not reciprocal else (2,)),
        21: _b(21, (), (2,)),
        30: _b(30, (31,), ()),
        31: _b(31, (2,), (30,)),
    }, 10, 0x1000)


def test_exact_table_multi_entry_policy_accepts_nested_writer_feeder() -> None:
    graph = _exact_table_multi_entry_fixture()
    assert minimal_unflatten_emit_module._exact_table_multi_entry_source_edges(
        graph, dispatcher_entry_serial=2, state_var_stkoff=_STATE, state_var_reg=None,
    ) == frozenset({(10, 9), (11, 9)})


@pytest.mark.parametrize(
    ("dispatcher", "slot", "width", "reciprocal"),
    ((3, _STATE, 4, True), (2, _STATE + 4, 4, True), (2, _STATE, 8, True), (2, _STATE, 4, False)),
    ids=("wrong_dispatcher", "wrong_stack_slot", "non_u32_width", "nonreciprocal_feeder"),
)
def test_exact_table_multi_entry_policy_rejects_unbound_delivery(
    dispatcher, slot, width, reciprocal,
) -> None:
    graph = _exact_table_multi_entry_fixture(slot=slot, width=width, reciprocal=reciprocal)
    assert not minimal_unflatten_emit_module._exact_table_multi_entry_source_edges(
        graph, dispatcher_entry_serial=dispatcher, state_var_stkoff=_STATE, state_var_reg=None,
    )


# ---------------------------------------------------------------------------
# Terminal outcome counters (ticket d81-rhu6)
# ---------------------------------------------------------------------------


def _emit_module_source() -> str:
    import d810.transforms.minimal_unflatten_emit as module

    return pathlib.Path(module.__file__).read_text()


def _calls_named(node, name: str) -> bool:
    import ast as _ast

    return any(
        isinstance(child, _ast.Call)
        and isinstance(child.func, _ast.Name)
        and child.func.id == name
        for child in _ast.walk(node)
    )


def _function_named(tree, name: str):
    import ast as _ast

    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            if node.name == name:
                return node
    raise AssertionError(f"function {name} not found")


def test_coverage_counters_are_not_sourced_from_the_info_log_helper():
    """``log_dispatcher_coverage`` runs only on the legacy, non-typed path.

    Sourcing the terminal record's coverage numbers from it would leave the
    typed-authority path with no counters at all.
    """
    import ast as _ast

    tree = _ast.parse(_emit_module_source())
    helper = _function_named(tree, "log_dispatcher_coverage")
    assert not _calls_named(helper, "note_unflat_counters")


def test_counters_are_noted_unconditionally_in_emit_minimal_unflatten():
    import ast as _ast

    tree = _ast.parse(_emit_module_source())
    emitter = _function_named(tree, "emit_minimal_unflatten")
    # Both counter notes must sit directly in the emitter body (statement
    # depth 1), not under an ``if logger.info_on`` or a path branch.
    top_level_notes = [
        stmt
        for stmt in emitter.body
        if isinstance(stmt, _ast.Try) and _calls_named(stmt, "note_unflat_counters")
    ]
    assert len(top_level_notes) == 2
