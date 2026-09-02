"""Entry-cut initial-state authority stays in the portable analysis layer."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.analyses.control_flow.dispatcher_resolution import (
    InitialStateWriteWitness,
    bind_initial_state_write_witness,
    initial_state_write_witness_from_entry_cut,
)
from d810.ir.graph_fingerprint import instruction_projection_without_block_references
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind


_STATE_OFF = 0x38
_INITIAL_STATE = 0x568411F6


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    instructions: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x180000000 + serial * 0x10,
        insn_snapshots=instructions,
    )


def _state_write(value: int, *, ea: int = 0x180000010) -> InsnSnapshot:
    dest = MopSnapshot(kind=OperandKind.STACK, stkoff=_STATE_OFF, size=4)
    source = MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4)
    return InsnSnapshot(
        opcode=1,
        ea=ea,
        native_ea=ea,
        operands=(dest, source),
        l=source,
        d=dest,
        kind=InsnKind.MOV,
    )


def _entry_cut_graph(write: InsnSnapshot | None = None) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1,), (), (() if write is None else (write,))),
            1: _block(1, (2,), (0,)),
            2: _block(2, (3,), (1,)),
            3: _block(3, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x180000000,
    )


def test_initial_state_entry_cut_mints_exact_write_witness() -> None:
    witness = initial_state_write_witness_from_entry_cut(
        _entry_cut_graph(_state_write(_INITIAL_STATE)), 2, _STATE_OFF, _INITIAL_STATE,
    )

    assert witness is not None
    assert witness.normalized_state == _INITIAL_STATE
    assert witness.delivery_path_serials == (0, 1, 2)
    assert witness.delivery_path_edges == ((0, 1), (1, 2))


def test_initial_state_entry_cut_preserves_zero_stack_offset() -> None:
    original = _state_write(_INITIAL_STATE)
    destination = replace(original.d, stkoff=0)
    zero_offset_write = replace(
        original, d=destination, operands=(destination, original.l),
    )

    witness = initial_state_write_witness_from_entry_cut(
        _entry_cut_graph(zero_offset_write), 2, 0, _INITIAL_STATE,
    )

    assert witness is not None
    assert witness.state_identity == StorageIdentity(StorageIdentityKind.STACK, 0)


@pytest.mark.parametrize(
    "graph,state",
    (
        (_entry_cut_graph(), _INITIAL_STATE),
        (_entry_cut_graph(_state_write(_INITIAL_STATE + 1)), _INITIAL_STATE),
        (
            FlowGraph(
                blocks={
                    **_entry_cut_graph(_state_write(_INITIAL_STATE)).blocks,
                    0: replace(
                        _entry_cut_graph(_state_write(_INITIAL_STATE)).blocks[0],
                        succs=(1, 2),
                    ),
                    2: replace(
                        _entry_cut_graph(_state_write(_INITIAL_STATE)).blocks[2],
                        preds=(0, 1),
                    ),
                },
                entry_serial=0,
                func_ea=0x180000000,
            ),
            _INITIAL_STATE,
        ),
    ),
)
def test_initial_state_entry_cut_rejects_missing_wrong_or_ambiguous_evidence(
    graph: FlowGraph,
    state: int,
) -> None:
    assert initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, state,
    ) is None


def _witness_for_entry_cut(graph: FlowGraph) -> InitialStateWriteWitness:
    write = graph.blocks[0].insn_snapshots[0]
    return InitialStateWriteWitness(
        source_block_serial=0,
        source_instruction=instruction_projection_without_block_references(write),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, _STATE_OFF),
        width=4,
        normalized_state=_INITIAL_STATE,
        dispatcher_entry_serial=2,
        redirect_predecessor_serial=1,
        delivery_path_serials=(0, 1, 2),
        delivery_path_edges=((0, 1), (1, 2)),
    )


def test_bind_initial_state_write_witness_rebinds_exact_portable_delivery() -> None:
    graph = _entry_cut_graph(_state_write(_INITIAL_STATE))

    assert bind_initial_state_write_witness(graph, _witness_for_entry_cut(graph)) == _witness_for_entry_cut(graph)


def test_bind_initial_state_write_witness_rejects_stale_instruction_projection() -> None:
    graph = _entry_cut_graph(_state_write(_INITIAL_STATE, ea=0x180000020))
    stale = _entry_cut_graph(_state_write(_INITIAL_STATE))

    assert bind_initial_state_write_witness(graph, _witness_for_entry_cut(stale)) is None


def test_bind_initial_state_write_witness_rejects_later_state_overwrite() -> None:
    first = _state_write(_INITIAL_STATE, ea=0x180000010)
    overwrite = replace(
        _state_write(_INITIAL_STATE + 1, ea=0x180000020),
        kind=InsnKind.ADD,
    )
    graph = _entry_cut_graph(first)
    graph = replace(graph, blocks={
        **graph.blocks,
        0: replace(graph.blocks[0], insn_snapshots=(first, overwrite)),
    })

    assert bind_initial_state_write_witness(graph, _witness_for_entry_cut(_entry_cut_graph(first))) is None


def test_initial_state_entry_cut_rejects_conditional_delivery_without_selector_closure() -> None:
    write = _state_write(_INITIAL_STATE)
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), (), (write,)),
            1: _block(1, (2, 3), (0,)),
            2: _block(2, (4,), (1,)),
            3: _block(3, (), (1,)),
            4: _block(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x180000000,
    )

    assert initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    ) is None


def _conditional_entry_cut_graph(
    *,
    selector_value: int = 7,
    comparison_constant: int = 7,
    predicate: PredicateKind = PredicateKind.EQ,
) -> FlowGraph:
    selector_dest = MopSnapshot(kind=OperandKind.STACK, stkoff=0x40, size=4)
    selector_source = MopSnapshot(kind=OperandKind.NUMBER, value=selector_value, size=4)
    selector = InsnSnapshot(
        opcode=1,
        ea=0x180000014,
        native_ea=0x180000014,
        operands=(selector_dest, selector_source),
        l=selector_source,
        d=selector_dest,
        kind=InsnKind.MOV,
    )
    branch = InsnSnapshot(
        opcode=2,
        ea=0x180000020,
        native_ea=0x180000020,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, stkoff=0x40, size=4),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=comparison_constant, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2, size=0),
        kind=InsnKind.COND_JUMP,
        branch_predicate=predicate,
        is_conditional_jump=True,
    )
    return FlowGraph(
        blocks={
            0: _block(0, (1,), (), (_state_write(_INITIAL_STATE), selector)),
            1: _block(1, (2, 3), (0,), (branch,)),
            2: _block(2, (4,), (1,)),
            3: _block(3, (), (1,)),
            4: _block(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x180000000,
    )


def test_initial_state_entry_cut_mints_exact_conditional_selector_closure() -> None:
    graph = _conditional_entry_cut_graph()

    witness = initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    )

    assert witness is not None
    assert witness.comparison_selected_target_serial == 2
    assert witness.selector_identity == StorageIdentity(StorageIdentityKind.STACK, 0x40)
    assert bind_initial_state_write_witness(graph, witness) == witness


def test_initial_state_entry_cut_rejects_conditional_selector_for_other_arm() -> None:
    graph = _conditional_entry_cut_graph(selector_value=6)

    assert initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    ) is None


@pytest.mark.parametrize(
    "predicate,selector_value,accepted",
    (
        (PredicateKind.NE, 8, True),
        (PredicateKind.NE, 7, False),
        (PredicateKind.UGT, 8, True),
        (PredicateKind.UGT, 6, False),
        (PredicateKind.ULE, 6, True),
        (PredicateKind.ULE, 8, False),
    ),
)
def test_initial_state_entry_cut_uses_exact_selector_predicate_semantics(
    predicate: PredicateKind,
    selector_value: int,
    accepted: bool,
) -> None:
    graph = _conditional_entry_cut_graph(
        selector_value=selector_value,
        predicate=predicate,
    )

    witness = initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    )

    assert (witness is not None) is accepted


def test_bind_initial_state_write_witness_rejects_selector_or_comparison_drift() -> None:
    graph = _conditional_entry_cut_graph()
    witness = initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    )
    assert witness is not None
    selector = graph.blocks[0].insn_snapshots[1]
    changed_selector = replace(selector, l=replace(selector.l, value=6))
    selector_graph = replace(graph, blocks={
        **graph.blocks,
        0: replace(graph.blocks[0], insn_snapshots=(graph.blocks[0].insn_snapshots[0], changed_selector)),
    })
    branch = graph.blocks[1].insn_snapshots[0]
    changed_branch = replace(branch, r=replace(branch.r, value=8))
    comparison_graph = replace(graph, blocks={
        **graph.blocks,
        1: replace(graph.blocks[1], insn_snapshots=(changed_branch,)),
    })

    assert bind_initial_state_write_witness(selector_graph, witness) is None
    assert bind_initial_state_write_witness(comparison_graph, witness) is None


def test_initial_state_entry_cut_rejects_stale_selector_before_later_same_identity_write() -> None:
    graph = _conditional_entry_cut_graph()
    selector = graph.blocks[0].insn_snapshots[1]
    later_source = replace(selector.l, value=6)
    later_selector = replace(
        selector,
        ea=0x180000018,
        native_ea=0x180000018,
        l=later_source,
        operands=(selector.d, later_source),
    )
    graph = replace(graph, blocks={
        **graph.blocks,
        0: replace(
            graph.blocks[0],
            insn_snapshots=(*graph.blocks[0].insn_snapshots, later_selector),
        ),
    })

    assert initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    ) is None


def test_bind_initial_state_write_witness_rejects_later_selector_overwrite_on_corridor() -> None:
    graph = _conditional_entry_cut_graph()
    witness = initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    )
    assert witness is not None
    selector = graph.blocks[0].insn_snapshots[1]
    overwrite_source = replace(selector.l, value=6)
    overwrite = replace(
        selector,
        ea=0x180000018,
        native_ea=0x180000018,
        l=overwrite_source,
        operands=(selector.d, overwrite_source),
    )
    drifted = replace(graph, blocks={
        **graph.blocks,
        0: replace(
            graph.blocks[0],
            insn_snapshots=(*graph.blocks[0].insn_snapshots, overwrite),
        ),
    })

    assert bind_initial_state_write_witness(drifted, witness) is None


def test_initial_state_entry_cut_rejects_selector_overwrite_in_intermediate_corridor() -> None:
    graph = _conditional_entry_cut_graph()
    selector = graph.blocks[0].insn_snapshots[1]
    overwrite_source = replace(selector.l, value=6)
    overwrite = replace(
        selector,
        ea=0x180000018,
        native_ea=0x180000018,
        l=overwrite_source,
        operands=(selector.d, overwrite_source),
    )
    graph = replace(graph, blocks={
        **graph.blocks,
        0: replace(graph.blocks[0], succs=(5,)),
        1: replace(graph.blocks[1], preds=(5,)),
        5: _block(5, (1,), (0,), (overwrite,)),
    })

    assert initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    ) is None


def test_bind_initial_state_write_witness_rejects_wrong_state_namespace() -> None:
    graph = _entry_cut_graph(_state_write(_INITIAL_STATE))
    forged = _witness_for_entry_cut(graph)
    object.__setattr__(
        forged, "state_identity", StorageIdentity(StorageIdentityKind.STACK, _STATE_OFF + 4),
    )

    assert bind_initial_state_write_witness(graph, forged) is None


def test_initial_state_entry_cut_rejects_two_candidate_writers_and_multiple_paths() -> None:
    first = _state_write(_INITIAL_STATE, ea=0x180000010)
    second = _state_write(_INITIAL_STATE, ea=0x180000020)
    two_writers = _entry_cut_graph(first)
    two_writers = replace(two_writers, blocks={
        **two_writers.blocks,
        0: replace(two_writers.blocks[0], insn_snapshots=(first, second)),
    })
    multiple_paths = FlowGraph(
        blocks={
            0: _block(0, (1, 2), (), (first,)),
            1: _block(1, (3,), (0,)),
            2: _block(2, (3,), (0,)),
            3: _block(3, (4,), (1, 2)),
            4: _block(4, (), (3,)),
        },
        entry_serial=0,
        func_ea=0x180000000,
    )

    assert initial_state_write_witness_from_entry_cut(
        two_writers, 2, _STATE_OFF, _INITIAL_STATE,
    ) is None
    assert initial_state_write_witness_from_entry_cut(
        multiple_paths, 3, _STATE_OFF, _INITIAL_STATE,
    ) is None


def test_bind_initial_state_write_witness_rejects_new_reciprocal_alternate_path() -> None:
    graph = _entry_cut_graph(_state_write(_INITIAL_STATE))
    witness = initial_state_write_witness_from_entry_cut(
        graph, 2, _STATE_OFF, _INITIAL_STATE,
    )
    assert witness is not None
    alternate = replace(graph, blocks={
        **graph.blocks,
        0: replace(graph.blocks[0], succs=(1, 4)),
        1: replace(graph.blocks[1], preds=(0, 4)),
        4: _block(4, (1,), (0,)),
    })

    assert bind_initial_state_write_witness(alternate, witness) is None
