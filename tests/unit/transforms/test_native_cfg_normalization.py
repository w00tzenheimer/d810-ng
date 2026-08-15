from __future__ import annotations

import pytest

from d810.core.execution_journal import ExecutionEffectRef
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.maturity import IRMaturity
from d810.ir.native_range_projection import (
    CtreeNativeRangeProjection,
    CtreeStatementNativeRanges,
    NativeRange,
)
from d810.transforms.native_cfg_normalization import (
    NativeCfgEdgeKind,
    NativeCfgFreezeReason,
    NativeCfgPassMutationObservation,
    ObservedEdgeStateContract,
    bind_ctree_native_ranges,
    freeze_native_cfg_topology,
)

pytestmark = pytest.mark.pure_python


def _contract(proof_id: str = "state:edge") -> EdgeStateContract:
    return EdgeStateContract(
        source_stack_delta=0,
        target_stack_delta=0,
        proof_ids=(proof_id,),
    )


def _graph(
    edges: dict[int, tuple[int, ...]],
    *,
    function_ea: int = 0x1000,
    native_eas: dict[int, int] | None = None,
) -> FlowGraph:
    native_eas = native_eas or {serial: 0x1000 + serial * 0x20 for serial in edges}
    predecessors = {serial: [] for serial in edges}
    for source, targets in edges.items():
        for target in targets:
            if target in predecessors:
                predecessors[target].append(source)
    blocks = {}
    for serial, successors in edges.items():
        native_ea = native_eas[serial]
        tail_ea = native_ea + 4
        blocks[serial] = BlockSnapshot(
            serial=serial,
            block_type=1,
            succs=successors,
            preds=tuple(predecessors[serial]),
            flags=0,
            start_ea=native_ea,
            native_start_ea=native_ea,
            insn_snapshots=(
                InsnSnapshot(
                    opcode=1,
                    ea=tail_ea,
                    native_ea=tail_ea,
                    operands=(),
                    kind=InsnKind.GOTO,
                ),
            ),
        )
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=function_ea)


def _observation(
    pre_graph: FlowGraph,
    post_graph: FlowGraph,
    *,
    source: int,
    pass_id: str = "lower_state_machine",
    receipt: str = "receipt-1",
) -> NativeCfgPassMutationObservation:
    return NativeCfgPassMutationObservation(
        pass_id=pass_id,
        maturity=IRMaturity.GLOBAL_OPTIMIZED,
        pre_graph=pre_graph,
        post_graph=post_graph,
        plan_fingerprint=f"plan:{receipt}",
        receipt_ref=ExecutionEffectRef("mutation", receipt),
        edge_state_contracts=(
            ObservedEdgeStateContract(
                source_block=source,
                inherited_successors=pre_graph.blocks[source].succs,
                final_successors=post_graph.blocks[source].succs,
                contract=_contract(f"state:{receipt}"),
            ),
        ),
    )


def _freeze(
    baseline: FlowGraph,
    final: FlowGraph,
    observations: tuple[NativeCfgPassMutationObservation, ...],
):
    return freeze_native_cfg_topology(
        function_ea=baseline.func_ea,
        maturity=IRMaturity.GLOBAL_OPTIMIZED,
        baseline_graph=baseline,
        final_graph=final,
        observations=observations,
    )


def _projection(
    graph: FlowGraph,
    *,
    overrides: dict[int, tuple[CtreeStatementNativeRanges, ...]] | None = None,
) -> CtreeNativeRangeProjection:
    overrides = overrides or {}
    statements: list[CtreeStatementNativeRanges] = []
    reverse: list[tuple[int, tuple[int, ...]]] = []
    next_index = 1
    for serial, block in sorted(graph.blocks.items()):
        custom = overrides.get(serial)
        if custom is None:
            native_ea = int(block.native_start_ea)
            custom = (
                CtreeStatementNativeRanges(
                    citem_index=next_index,
                    statement_op=71,
                    representative_ea=native_ea,
                    ranges=(NativeRange(native_ea, native_ea + 0x10),),
                ),
            )
            next_index += 1
        else:
            next_index = max(
                next_index,
                max(item.citem_index for item in custom) + 1,
            )
        statements.extend(custom)
        reverse.append(
            (
                int(block.native_start_ea),
                tuple(item.citem_index for item in custom),
            )
        )
    return CtreeNativeRangeProjection(
        function_ea=graph.func_ea,
        function_ranges=(NativeRange(0x1000, 0x1100),),
        statements=tuple(statements),
        ea_to_statement_indices=tuple(reverse),
    )


def test_freezes_direct_redirect_with_exact_receipt_and_contract() -> None:
    baseline = _graph({0: (1,), 1: (), 2: ()})
    final = _graph({0: (2,), 1: (), 2: ()})

    outcome = _freeze(baseline, final, (_observation(baseline, final, source=0),))

    assert outcome.reason is None
    assert outcome.topology is not None
    edge = outcome.topology.edge_intents[0]
    assert edge.kind is NativeCfgEdgeKind.REDIRECT
    assert edge.source_native_ea == 0x1004
    assert edge.inherited_target_native_eas == (0x1020,)
    assert edge.target_native_eas == (0x1040,)
    assert edge.owner_pass_ids == ("lower_state_machine",)
    assert tuple(ref.ref_id for ref in edge.receipt_refs) == ("receipt-1",)
    assert edge.state_contract.permits_control_only_relink


@pytest.mark.parametrize(
    ("successor", "kind"),
    [(1, NativeCfgEdgeKind.FORCE_TAKEN), (2, NativeCfgEdgeKind.FORCE_FALLTHROUGH)],
)
def test_classifies_conditional_edge_selection(
    successor: int,
    kind: NativeCfgEdgeKind,
) -> None:
    baseline = _graph({0: (1, 2), 1: (), 2: ()})
    final = _graph({0: (successor,), 1: (), 2: ()})

    outcome = _freeze(baseline, final, (_observation(baseline, final, source=0),))

    assert outcome.topology is not None
    assert outcome.topology.edge_intents[0].kind is kind


def test_unchanged_graph_reports_no_changed_edges() -> None:
    graph = _graph({0: (1,), 1: ()})

    outcome = _freeze(graph, graph, ())

    assert outcome.topology is None
    assert outcome.reason is NativeCfgFreezeReason.NO_CHANGED_EDGES


def test_uncontracted_sibling_change_rejects_the_complete_topology() -> None:
    baseline = _graph({0: (1,), 1: (2,), 2: ()})
    final = _graph({0: (2,), 1: (0,), 2: ()})

    outcome = _freeze(baseline, final, (_observation(baseline, final, source=0),))

    assert outcome.topology is None
    assert outcome.reason is NativeCfgFreezeReason.EDGE_STATE_CONTRACT_REQUIRED


def test_orders_a_two_observation_graph_chain_independent_of_input_order() -> None:
    baseline = _graph({0: (1,), 1: (2,), 2: ()})
    middle = _graph({0: (2,), 1: (2,), 2: ()})
    final = _graph({0: (2,), 1: (0,), 2: ()})
    first = _observation(baseline, middle, source=0, receipt="receipt-1")
    second = _observation(middle, final, source=1, receipt="receipt-2")

    forward = _freeze(baseline, final, (first, second))
    reverse = _freeze(baseline, final, (second, first))

    assert forward.topology is not None
    assert reverse.topology is not None
    assert forward.topology.topology_hash == reverse.topology.topology_hash
    assert len(forward.topology.edge_intents) == 2


def test_added_or_reanchored_final_block_abstains() -> None:
    baseline = _graph({0: (1,), 1: ()})
    added = _graph({0: (2,), 1: (), 2: ()})
    reanchored = _graph(
        {0: (1,), 1: ()},
        native_eas={0: 0x1000, 1: 0x1080},
    )

    assert _freeze(baseline, added, ()).reason is NativeCfgFreezeReason.ADDED_BLOCK
    assert (
        _freeze(baseline, reanchored, ()).reason
        is NativeCfgFreezeReason.REANCHORED_BLOCK
    )


def test_missing_positive_contract_abstains() -> None:
    baseline = _graph({0: (1,), 1: (), 2: ()})
    final = _graph({0: (2,), 1: (), 2: ()})
    observation = _observation(baseline, final, source=0)
    observation = NativeCfgPassMutationObservation(
        pass_id=observation.pass_id,
        maturity=observation.maturity,
        pre_graph=observation.pre_graph,
        post_graph=observation.post_graph,
        plan_fingerprint=observation.plan_fingerprint,
        receipt_ref=observation.receipt_ref,
        edge_state_contracts=(),
    )

    assert (
        _freeze(baseline, final, (observation,)).reason
        is NativeCfgFreezeReason.EDGE_STATE_CONTRACT_REQUIRED
    )


def test_binds_every_surviving_block_to_ctree_ranges() -> None:
    baseline = _graph({0: (1,), 1: (), 2: ()})
    final = _graph({0: (2,), 1: (), 2: ()})
    frozen = _freeze(
        baseline,
        final,
        (_observation(baseline, final, source=0),),
    ).topology
    assert frozen is not None
    projection = _projection(final)

    outcome = bind_ctree_native_ranges(
        frozen=frozen,
        target_projection=projection,
    )

    assert outcome.reason is None
    assert outcome.intent is not None
    assert outcome.intent.target_ctree_range_fingerprint == projection.fingerprint
    assert tuple(row.block_serial for row in outcome.intent.block_range_bindings) == (
        0,
        1,
        2,
    )


def test_binding_rejects_absent_or_ambiguous_ctree_ranges() -> None:
    baseline = _graph({0: (1,), 1: (), 2: ()})
    final = _graph({0: (2,), 1: (), 2: ()})
    frozen = _freeze(
        baseline,
        final,
        (_observation(baseline, final, source=0),),
    ).topology
    assert frozen is not None

    missing = CtreeNativeRangeProjection(
        function_ea=final.func_ea,
        function_ranges=(NativeRange(0x1000, 0x1100),),
        statements=(),
        ea_to_statement_indices=(),
    )
    assert (
        bind_ctree_native_ranges(frozen=frozen, target_projection=missing).reason
        is NativeCfgFreezeReason.MISSING_CTREE_NATIVE_RANGE
    )

    first = CtreeStatementNativeRanges(
        20,
        71,
        0x1000,
        (NativeRange(0x1000, 0x1010),),
    )
    second = CtreeStatementNativeRanges(
        21,
        72,
        0x1000,
        (NativeRange(0x1000, 0x1018),),
    )
    ambiguous = _projection(final, overrides={0: (first, second)})
    assert (
        bind_ctree_native_ranges(
            frozen=frozen,
            target_projection=ambiguous,
        ).reason
        is NativeCfgFreezeReason.AMBIGUOUS_CTREE_NATIVE_RANGE
    )


def test_binding_accepts_shared_identical_range_rows() -> None:
    baseline = _graph({0: (1,), 1: (), 2: ()})
    final = _graph({0: (2,), 1: (), 2: ()})
    frozen = _freeze(
        baseline,
        final,
        (_observation(baseline, final, source=0),),
    ).topology
    assert frozen is not None
    shared_range = (NativeRange(0x1000, 0x1010),)
    projection = _projection(
        final,
        overrides={
            0: (
                CtreeStatementNativeRanges(20, 71, 0x1000, shared_range),
                CtreeStatementNativeRanges(21, 72, 0x1000, shared_range),
            )
        },
    )

    outcome = bind_ctree_native_ranges(
        frozen=frozen,
        target_projection=projection,
    )

    assert outcome.intent is not None
    assert outcome.intent.block_range_bindings[0].ctree_statement_indices == (20, 21)


def test_projection_fingerprint_is_bound_into_final_intent_hash() -> None:
    baseline = _graph({0: (1,), 1: (), 2: ()})
    final = _graph({0: (2,), 1: (), 2: ()})
    frozen = _freeze(
        baseline,
        final,
        (_observation(baseline, final, source=0),),
    ).topology
    assert frozen is not None
    first = _projection(final)
    row = first.statements[0]
    changed = _projection(
        final,
        overrides={
            0: (
                CtreeStatementNativeRanges(
                    row.citem_index,
                    row.statement_op + 1,
                    row.representative_ea,
                    row.ranges,
                ),
            )
        },
    )

    first_intent = bind_ctree_native_ranges(
        frozen=frozen,
        target_projection=first,
    ).intent
    changed_intent = bind_ctree_native_ranges(
        frozen=frozen,
        target_projection=changed,
    ).intent

    assert first_intent is not None and changed_intent is not None
    assert first_intent.intent_hash != changed_intent.intent_hash
