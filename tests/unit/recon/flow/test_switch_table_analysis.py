"""Unit tests for switch-table analysis pure-logic helpers."""
from __future__ import annotations

from d810.cfg.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.switch_table_analysis import (
    analyze_switch_table_flow_graph,
    build_state_dispatcher_map_from_cases,
    find_switch_loop_guard_blocks,
)


def _mop(
    *,
    kind: OperandKind = OperandKind.UNKNOWN,
    stkoff: int | None = None,
    value: int | None = None,
    stack_refs: tuple[int, ...] = (),
    switch_cases: tuple[tuple[tuple[int, ...], int], ...] = (),
) -> MopSnapshot:
    return MopSnapshot(
        kind=kind,
        stkoff=stkoff,
        value=value,
        stack_refs=stack_refs,
        switch_cases=switch_cases,
    )


def _insn(
    *,
    kind: InsnKind,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=1,
        ea=0,
        operands=(),
        l=left,
        r=right,
        kind=kind,
    )


def _block(
    serial: int,
    *,
    preds=(),
    succs=(),
    tail: InsnSnapshot | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0,
        insn_snapshots=() if tail is None else (tail,),
    )


def _flow_graph(blocks: dict[int, BlockSnapshot]) -> FlowGraph:
    return FlowGraph(
        blocks=blocks,
        entry_serial=min(blocks),
        func_ea=0x401000,
        metadata={"maturity_name": "MMAT_CALLS"},
    )


def test_find_switch_loop_guard_blocks_finds_while_guard():
    guard_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    flow_graph = _flow_graph({
        0: _block(0, succs=(2,)),
        2: _block(2, preds=(0, 6), succs=(3, 9), tail=guard_tail),
        3: _block(3, preds=(2, 6), succs=(4, 5)),
        6: _block(6, succs=(3,)),
        9: _block(9),
    })

    assert find_switch_loop_guard_blocks(
        flow_graph,
        3,
        state_var_stkoff=0x10,
        case_values=frozenset({0, 1, 2, 3, 4, 5, 6, 7}),
    ) == frozenset({2})


def test_find_switch_loop_guard_blocks_rejects_unrelated_branch():
    branch_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x20, stack_refs=(0x20,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    flow_graph = _flow_graph({
        0: _block(0, succs=(2,)),
        2: _block(2, preds=(0, 6), succs=(3, 9), tail=branch_tail),
        3: _block(3, preds=(2, 6), succs=(4, 5)),
        6: _block(6, succs=(3,)),
        9: _block(9),
    })

    assert find_switch_loop_guard_blocks(
        flow_graph,
        3,
        state_var_stkoff=0x10,
        case_values=frozenset({0, 1, 2, 3, 4, 5, 6, 7}),
    ) == frozenset()


def test_analyze_switch_table_flow_graph_extracts_cases_and_guard_block():
    state_operand = _mop(
        kind=OperandKind.SUBINSN,
        stack_refs=(0x10,),
    )
    switch_cases = _mop(
        kind=OperandKind.CASE_LIST,
        switch_cases=(
            ((0,), 4),
            ((1, 2), 5),
            ((), 3),
        ),
    )
    guard_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    table_tail = _insn(
        kind=InsnKind.TABLE_JUMP,
        left=state_operand,
        right=switch_cases,
    )
    flow_graph = _flow_graph({
        0: _block(0, succs=(2,)),
        2: _block(2, preds=(0, 6), succs=(3, 9), tail=guard_tail),
        3: _block(3, preds=(2, 6), succs=(4, 5), tail=table_tail),
        4: _block(4),
        5: _block(5),
        6: _block(6, succs=(3,)),
        9: _block(9),
    })

    result = analyze_switch_table_flow_graph(flow_graph)

    assert result is not None
    assert result.state_var_operand is state_operand
    dispatch_map = result.state_dispatcher_map
    assert dispatch_map.dispatcher_entry_block == 3
    assert dispatch_map.dispatcher_blocks == frozenset({2, 3})
    assert dispatch_map.state_var_stkoff == 0x10
    assert dispatch_map.state_to_handler() == {0: 4, 1: 5, 2: 5}
    assert dispatch_map.default_target_block == 3
    assert dispatch_map.default_row_kind == "dispatcher_default_self_loop"


class TestBuildStateDispatcherMapFromCases:
    """Test case-list to exact StateDispatcherMap conversion."""

    def test_simple_4_state(self):
        """abc_or_dispatch shape: 4 linear cases."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10, 1: 11, 2: 12, 3: 13}
        assert m.handler_state_map() == {10: 0, 11: 1, 12: 2, 13: 3}
        assert m.dispatcher_entry_block == 5
        assert m.dispatcher_blocks == frozenset({5})
        assert m.state_var_stkoff == 0x3C
        assert m.source == DispatcherType.SWITCH_TABLE

    def test_with_initial_state(self):
        cases = [(0, 10), (1, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            initial_state=0,
        )
        assert m.initial_state == 0

    def test_preserves_aliased_targets(self):
        """Multiple case values mapping to one target stay exact rows."""
        cases = [(0, 10), (1, 10), (2, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10, 1: 10, 2: 11}
        assert m.states_by_target() == {10: (0, 1), 11: (2,)}
        assert [row.row_kind for row in m.rows] == [
            "handler_alias",
            "handler_alias",
            "handler",
        ]
        # The old handler-map view is intentionally lossy; exact aliases live
        # in StateDispatcherMap.rows.
        assert m.to_dispatcher_handler_map().handler_state_map == {10: 0, 11: 2}

    def test_preserves_self_loop_targets(self):
        """Cases targeting the dispatcher itself are exact self-loop rows."""
        cases = [(0, 10), (1, 5), (2, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(1) == 5
        assert m.rows[1].is_dispatcher_self_loop
        assert m.handler_state_map() == {10: 0, 11: 2}

    def test_empty_cases(self):
        m = build_state_dispatcher_map_from_cases(
            cases=[],
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.rows == ()
        assert m.handler_state_map() == {}

    def test_resolve_target_works(self):
        """End-to-end: build map then resolve targets."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(0) == 10
        assert m.resolve_target(2) == 12
        assert m.resolve_target(99) is None

    def test_records_default_target_separately(self):
        cases = [(0, 10), (None, 99)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10}
        assert m.default_target_block == 99
        assert m.default_row_kind == "dispatcher_default"
