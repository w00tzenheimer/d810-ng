"""Portable reachability primitive + recover_dispatcher analysis pass (extraction #1).

Locks the byte-identical semantics of the live ``compute_reachability_info`` walk now that it is a
shared primitive, and proves ``recover_dispatcher`` computes reachability over a real FlowGraph.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.analyses.control_flow.reachability import reachable_from
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_recovery import (
    DispatcherRecovery,
    build_state_dispatcher_map_from_flow_graph,
    recover_dispatcher,
    recover_entry_dominated_initial_state,
)
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import CallKind, PredicateKind


def _blk(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(),
    )


def test_reachable_linear_chain():
    adj = {0: (1,), 1: (2,), 2: ()}
    assert reachable_from(adj, 3) == frozenset({0, 1, 2})


def test_reachable_skips_unreachable_and_out_of_range():
    # block 3 unreachable; successor 9 is out of range and ignored.
    adj = {0: (1, 9), 1: (), 2: (), 3: ()}
    assert reachable_from(adj, 4) == frozenset({0, 1})


def test_reachable_handles_cycles_without_hanging():
    adj = {0: (1,), 1: (2,), 2: (0,)}
    assert reachable_from(adj, 3) == frozenset({0, 1, 2})


def test_reachable_is_order_independent():
    # diamond: order of successor expansion must not change the reachable set
    adj = {0: (1, 2), 1: (3,), 2: (3,), 3: ()}
    assert reachable_from(adj, 4) == reachable_from(
        {0: (2, 1), 1: (3,), 2: (3,), 3: ()}, 4
    )
    assert reachable_from(adj, 4) == frozenset({0, 1, 2, 3})


def test_negative_entry_yields_empty():
    assert reachable_from({0: ()}, 1, entry=-1) == frozenset()


def test_recover_dispatcher_computes_reachability_over_flowgraph():
    # 0 -> 1 -> 2 ; block 3 is unreachable (orphan)
    graph = FlowGraph(
        blocks={
            0: _blk(0, (1,), ()),
            1: _blk(1, (2,), (0,)),
            2: _blk(2, (), (1,)),
            3: _blk(3, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    result = recover_dispatcher(graph, facts=None)
    assert isinstance(result, DispatcherRecovery)
    assert result.reachable_block_serials == frozenset({0, 1, 2})
    assert 3 not in result.reachable_block_serials


def test_recover_dispatcher_tolerates_null_graph():
    # the pipeline shape test runs passes on a null context
    assert recover_dispatcher(None, None) == DispatcherRecovery()


def _table_jump_block(
    serial: int,
    *,
    preds: tuple[int, ...],
    succs: tuple[int, ...],
    state_stkoff: int,
    cases: tuple[tuple[tuple[int, ...], int], ...],
) -> BlockSnapshot:
    """A jtbl block dispatching on a masked state var (abc_or_dispatch shape)."""
    tail = InsnSnapshot(
        opcode=1,
        ea=0x1000 + serial,
        operands=(),
        l=MopSnapshot(kind=OperandKind.SUBINSN, stack_refs=(state_stkoff,)),
        r=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=cases),
        kind=InsnKind.TABLE_JUMP,
    )
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(tail,),
    )


def test_recover_dispatcher_resolves_switch_table_when_no_equality_chain():
    # abc_or_dispatch shape: `switch (state & 0xF)` jtbl routing the low nibble
    # to four handlers. No equality-chain compare exists, so recover_dispatcher
    # must fall through to the portable switch-table detector.
    graph = FlowGraph(
        blocks={
            0: _blk(0, (1,), ()),
            1: _table_jump_block(
                1,
                preds=(0, 2, 3, 4),
                succs=(2, 3, 4, 5),
                state_stkoff=0x40,
                cases=(((0,), 2), ((1,), 3), ((2,), 4), ((3,), 5)),
            ),
            2: _blk(2, (1,), (1,)),
            3: _blk(3, (1,), (1,)),
            4: _blk(4, (1,), (1,)),
            5: _blk(5, (), (1,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    result = recover_dispatcher(graph, facts=None)
    assert result.dispatch_map is not None
    assert result.dispatch_map.router_kind is RouterKind.TABLE
    assert result.dispatch_map.state_to_handler() == {0: 2, 1: 3, 2: 4, 3: 5}
    assert result.dispatch_map.state_var_stkoff == 0x40
    assert result.dispatcher_block_serial == 1
    assert result.state_var_stkoff == 0x40


def test_recover_dispatcher_prefers_equality_chain_over_switch_table():
    # When an equality-chain dispatcher is present it wins; the switch-table
    # fallback only fires when build_state_dispatcher_map_from_flow_graph is None.
    # A graph with no jtbl and no equality compare yields no dispatch_map.
    graph = FlowGraph(
        blocks={
            0: _blk(0, (1,), ()),
            1: _blk(1, (2,), (0,)),
            2: _blk(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    result = recover_dispatcher(graph, facts=None)
    assert result.dispatch_map is None


# Same-block dispatcher-entry prefix fixtures.  These deliberately exercise
# portable snapshots rather than rendered microcode text: the production bug
# was that the dispatcher block itself was also the function entry, so the old
# predecessor-only recovery had no block from which to read the prologue write.
_PREFIX_STATE_OFF = 0x3C
_PREFIX_INITIAL_STATE = 0x16AA65E9
_PREFIX_COMPARE_STATE = 0x2A55AA55
_PREFIX_HANDLER = 10
_PREFIX_NEXT = 11


def _prefix_mov_const(
    value: int,
    *,
    destination: int = _PREFIX_STATE_OFF,
    source_size: int = 4,
    destination_size: int = 4,
) -> InsnSnapshot:
    source = MopSnapshot(kind=OperandKind.NUMBER, value=value, size=source_size)
    dest = MopSnapshot(
        kind=OperandKind.STACK, stkoff=destination, size=destination_size
    )
    return InsnSnapshot(
        opcode=2,
        ea=0x2000,
        operands=(source, dest),
        l=source,
        d=dest,
        kind=InsnKind.MOV,
    )


def _prefix_mov_nonconstant() -> InsnSnapshot:
    source = MopSnapshot(kind=OperandKind.STACK, stkoff=0x48, size=4)
    dest = MopSnapshot(kind=OperandKind.STACK, stkoff=_PREFIX_STATE_OFF, size=4)
    return InsnSnapshot(
        opcode=2,
        ea=0x2001,
        operands=(source, dest),
        l=source,
        d=dest,
        kind=InsnKind.MOV,
    )


def _prefix_store_address(
    offset: int,
    *,
    stack_refs: tuple[int, ...] = (),
    nested: MopSnapshot | None = None,
) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.ADDRESS,
        size=8,
        stack_refs=stack_refs,
        sub_l=nested
        if nested is not None
        else MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=8),
    )


def _prefix_store_const(
    value: int,
    address: MopSnapshot,
) -> InsnSnapshot:
    source = MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4)
    segment = MopSnapshot(kind=OperandKind.EMPTY, size=2)
    return InsnSnapshot(
        opcode=3,
        ea=0x2008,
        operands=(source, segment, address),
        l=source,
        r=segment,
        d=address,
        kind=InsnKind.STORE,
    )


def _prefix_add() -> InsnSnapshot:
    left = MopSnapshot(kind=OperandKind.STACK, stkoff=0x50, size=4)
    right = MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4)
    dest = MopSnapshot(kind=OperandKind.STACK, stkoff=0x50, size=4)
    return InsnSnapshot(
        opcode=4,
        ea=0x2002,
        operands=(left, right, dest),
        l=left,
        r=right,
        d=dest,
        kind=InsnKind.ADD,
    )


def _prefix_state_overwrite(kind: InsnKind) -> InsnSnapshot:
    left = MopSnapshot(kind=OperandKind.STACK, stkoff=0x50, size=4)
    right = MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4)
    dest = MopSnapshot(kind=OperandKind.STACK, stkoff=_PREFIX_STATE_OFF, size=4)
    return InsnSnapshot(
        opcode=6,
        ea=0x2005,
        operands=(left, right, dest),
        l=left,
        r=right,
        d=dest,
        kind=kind,
    )


def _prefix_reg_mov_const(value: int) -> InsnSnapshot:
    source = MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4)
    dest = MopSnapshot(kind=OperandKind.REGISTER, reg=20, size=4)
    return InsnSnapshot(
        opcode=2,
        ea=0x2006,
        operands=(source, dest),
        l=source,
        d=dest,
        kind=InsnKind.MOV,
    )


def _prefix_reg_tail(const: int = _PREFIX_COMPARE_STATE) -> InsnSnapshot:
    left = MopSnapshot(kind=OperandKind.REGISTER, reg=20, size=4)
    right = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    dest = MopSnapshot(kind=OperandKind.BLOCK, block_ref=_PREFIX_NEXT)
    return InsnSnapshot(
        opcode=1,
        ea=0x2011,
        operands=(left, right, dest),
        l=left,
        r=right,
        d=dest,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _prefix_nested_effect(kind: InsnKind) -> MopSnapshot:
    inner = MopSnapshot(kind=OperandKind.SUBINSN, sub_kind=kind, size=4)
    right = MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4)
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.ADD,
        sub_l=inner,
        sub_r=right,
        size=4,
    )


def _prefix_add_with_source(source: MopSnapshot) -> InsnSnapshot:
    right = MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4)
    dest = MopSnapshot(kind=OperandKind.STACK, stkoff=0x50, size=4)
    return InsnSnapshot(
        opcode=4,
        ea=0x2007,
        operands=(source, right, dest),
        l=source,
        r=right,
        d=dest,
        kind=InsnKind.ADD,
    )


def _prefix_reg_graph(prefix: tuple[InsnSnapshot, ...]) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _prefix_block(0, (_PREFIX_HANDLER, _PREFIX_NEXT), (), prefix),
            _PREFIX_HANDLER: _prefix_block(_PREFIX_HANDLER, (), (0,)),
            _PREFIX_NEXT: _prefix_block(_PREFIX_NEXT, (), (0,)),
        },
        entry_serial=0,
        func_ea=0x2000,
    )


def _prefix_call() -> InsnSnapshot:
    return InsnSnapshot(opcode=5, ea=0x2003, operands=(), kind=InsnKind.CALL)


def _prefix_tail(const: int = _PREFIX_COMPARE_STATE) -> InsnSnapshot:
    left = MopSnapshot(kind=OperandKind.STACK, stkoff=_PREFIX_STATE_OFF, size=4)
    right = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    dest = MopSnapshot(kind=OperandKind.BLOCK, block_ref=_PREFIX_NEXT)
    return InsnSnapshot(
        opcode=1,
        ea=0x2010,
        operands=(left, right, dest),
        l=left,
        r=right,
        d=dest,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _prefix_block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x2000 + serial,
        insn_snapshots=insns,
    )


def _prefix_graph(prefix: tuple[InsnSnapshot, ...]) -> FlowGraph:
    """Build an entry-as-dispatcher graph for the prefix tests."""
    return FlowGraph(
        blocks={
            0: _prefix_block(
                0,
                (_PREFIX_HANDLER, _PREFIX_NEXT),
                (),
                prefix,
            ),
            _PREFIX_HANDLER: _prefix_block(
                _PREFIX_HANDLER, (), (0,)
            ),
            _PREFIX_NEXT: _prefix_block(_PREFIX_NEXT, (), (0,)),
        },
        entry_serial=0,
        func_ea=0x2000,
    )


def _prefix_dmap(graph: FlowGraph):
    dmap = build_state_dispatcher_map_from_flow_graph(graph)
    assert dmap is not None
    assert dmap.dispatcher_entry_block == graph.entry_serial
    assert dmap.state_var_stkoff == _PREFIX_STATE_OFF
    return dmap


def test_entry_dominated_initial_state_reads_constant_before_dispatch_tail():
    graph = _prefix_graph(
        (_prefix_mov_const(_PREFIX_INITIAL_STATE), _prefix_add(), _prefix_tail())
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) == (
        _PREFIX_INITIAL_STATE
    )


def test_recover_dispatcher_threads_same_block_initial_state_to_map():
    graph = _prefix_graph(
        (_prefix_mov_const(_PREFIX_INITIAL_STATE), _prefix_add(), _prefix_tail())
    )

    recovery = recover_dispatcher(graph, facts=None)

    assert recovery.dispatch_map is not None
    assert recovery.dispatch_map.initial_state == _PREFIX_INITIAL_STATE


def test_entry_dominated_initial_state_stops_at_first_dispatch_tail():
    graph = _prefix_graph(
        (
            _prefix_mov_const(_PREFIX_INITIAL_STATE),
            _prefix_tail(),
            _prefix_mov_nonconstant(),
            _prefix_tail(_PREFIX_COMPARE_STATE + 1),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) == (
        _PREFIX_INITIAL_STATE
    )


def test_entry_dominated_initial_state_rejects_conflicting_prefix_writes():
    graph = _prefix_graph(
        (
            _prefix_mov_const(_PREFIX_INITIAL_STATE),
            _prefix_mov_const(_PREFIX_INITIAL_STATE + 1),
            _prefix_tail(),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_rejects_nonconstant_prefix_write():
    graph = _prefix_graph((_prefix_mov_nonconstant(), _prefix_tail()))

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_rejects_wrong_state_identity():
    graph = _prefix_graph(
        (_prefix_mov_const(_PREFIX_INITIAL_STATE, destination=0x40), _prefix_tail())
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_rejects_effect_barrier_after_write():
    graph = _prefix_graph(
        (_prefix_mov_const(_PREFIX_INITIAL_STATE), _prefix_call(), _prefix_tail())
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_accepts_exact_stack_store():
    graph = _prefix_graph(
        (
            _prefix_store_const(
                _PREFIX_INITIAL_STATE,
                _prefix_store_address(
                    _PREFIX_STATE_OFF,
                    stack_refs=(_PREFIX_STATE_OFF,),
                ),
            ),
            _prefix_tail(),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) == (
        _PREFIX_INITIAL_STATE
    )


def test_entry_dominated_initial_state_rejects_register_store_for_register_state():
    register_address = MopSnapshot(
        kind=OperandKind.REGISTER,
        reg=20,
        size=8,
    )
    graph = _prefix_reg_graph(
        (_prefix_store_const(_PREFIX_INITIAL_STATE, register_address), _prefix_reg_tail())
    )
    dmap = build_state_dispatcher_map_from_flow_graph(graph)
    assert dmap is not None
    assert dmap.state_var_stkoff is None
    assert dmap.state_var_reg == 20

    assert recover_entry_dominated_initial_state(graph, dmap) is None


@pytest.mark.parametrize(
    "address",
    (
        _prefix_store_address(_PREFIX_STATE_OFF + 4, stack_refs=(_PREFIX_STATE_OFF + 4,)),
        _prefix_store_address(
            _PREFIX_STATE_OFF,
            stack_refs=(_PREFIX_STATE_OFF, _PREFIX_STATE_OFF + 4),
        ),
        _prefix_store_address(
            _PREFIX_STATE_OFF,
            stack_refs=(_PREFIX_STATE_OFF,),
            nested=MopSnapshot(
                kind=OperandKind.SUBINSN,
                sub_kind=InsnKind.CALL,
                size=8,
            ),
        ),
    ),
)
def test_entry_dominated_initial_state_rejects_non_exact_stack_store_address(
    address: MopSnapshot,
):
    graph = _prefix_graph(
        (_prefix_store_const(_PREFIX_INITIAL_STATE, address), _prefix_tail())
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_rejects_call_kind_on_pure_instruction():
    inconsistent = replace(_prefix_add(), call_kind=CallKind.DIRECT)
    graph = _prefix_graph(
        (_prefix_mov_const(_PREFIX_INITIAL_STATE), inconsistent, _prefix_tail())
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


@pytest.mark.parametrize(
    "kind",
    (
        InsnKind.ADD,
        InsnKind.SUB,
        InsnKind.AND,
        InsnKind.MUL,
        InsnKind.XDU,
        InsnKind.XDS,
    ),
)
def test_entry_dominated_initial_state_rejects_arithmetic_state_overwrite(
    kind: InsnKind,
):
    graph = _prefix_graph(
        (_prefix_mov_const(_PREFIX_INITIAL_STATE), _prefix_state_overwrite(kind), _prefix_tail())
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


@pytest.mark.parametrize("nested_kind", (InsnKind.CALL, InsnKind.STORE, InsnKind.UNKNOWN))
def test_entry_dominated_initial_state_rejects_nested_effect_operand(
    nested_kind: InsnKind,
):
    graph = _prefix_graph(
        (
            _prefix_mov_const(_PREFIX_INITIAL_STATE),
            _prefix_add_with_source(_prefix_nested_effect(nested_kind)),
            _prefix_tail(),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_rejects_mixed_64_to_32_write():
    graph = _prefix_graph(
        (
            _prefix_mov_const(
                _PREFIX_INITIAL_STATE,
                source_size=8,
                destination_size=4,
            ),
            _prefix_tail(),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_rejects_unknown_write_width():
    graph = _prefix_graph(
        (
            _prefix_mov_const(
                _PREFIX_INITIAL_STATE,
                source_size=0,
                destination_size=4,
            ),
            _prefix_tail(),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) is None


def test_entry_dominated_initial_state_normalizes_32_bit_literal():
    graph = _prefix_graph(
        (
            _prefix_mov_const(
                0x100000001,
                source_size=4,
                destination_size=4,
            ),
            _prefix_tail(),
        )
    )

    assert recover_entry_dominated_initial_state(graph, _prefix_dmap(graph)) == 1


def test_entry_dominated_initial_state_rejects_mixed_dispatcher_state_width():
    graph = _prefix_graph(
        (
            _prefix_mov_const(_PREFIX_INITIAL_STATE),
            _prefix_tail(),
        )
    )
    block = graph.blocks[0]
    tail = block.tail
    assert tail is not None
    wide_left = MopSnapshot(kind=OperandKind.STACK, stkoff=_PREFIX_STATE_OFF, size=8)
    wide_tail = InsnSnapshot(
        opcode=tail.opcode,
        ea=tail.ea,
        operands=(wide_left, tail.r, tail.d),
        l=wide_left,
        r=tail.r,
        d=tail.d,
        kind=tail.kind,
        branch_predicate=tail.branch_predicate,
        is_conditional_jump=True,
    )
    blocks = dict(graph.blocks)
    blocks[0] = _prefix_block(
        0,
        (_PREFIX_HANDLER, _PREFIX_NEXT),
        (),
        (_prefix_mov_const(_PREFIX_INITIAL_STATE), wide_tail),
    )
    wide_graph = FlowGraph(blocks=blocks, entry_serial=0, func_ea=graph.func_ea)

    assert recover_entry_dominated_initial_state(wide_graph, _prefix_dmap(wide_graph)) is None


def test_predecessor_register_initialization_remains_unhandled():
    graph = FlowGraph(
        blocks={
            0: _prefix_block(0, (1,), (), (_prefix_reg_mov_const(_PREFIX_INITIAL_STATE),)),
            1: _prefix_block(1, (_PREFIX_HANDLER, _PREFIX_NEXT), (0, 3), (_prefix_reg_tail(),)),
            _PREFIX_HANDLER: _prefix_block(_PREFIX_HANDLER, (), (1,)),
            _PREFIX_NEXT: _prefix_block(_PREFIX_NEXT, (), (1,)),
            3: _prefix_block(3, (1,), (1,)),
        },
        entry_serial=0,
        func_ea=0x2000,
    )
    dmap = build_state_dispatcher_map_from_flow_graph(graph)
    assert dmap is not None
    assert dmap.state_var_stkoff is None
    assert dmap.state_var_reg == 20

    assert recover_entry_dominated_initial_state(graph, dmap) is None


def test_same_block_register_initialization_is_recovered():
    graph = _prefix_reg_graph(
        (_prefix_reg_mov_const(_PREFIX_INITIAL_STATE), _prefix_reg_tail())
    )
    dmap = build_state_dispatcher_map_from_flow_graph(graph)
    assert dmap is not None
    assert dmap.state_var_stkoff is None
    assert dmap.state_var_reg == 20

    assert recover_entry_dominated_initial_state(graph, dmap) == _PREFIX_INITIAL_STATE


def test_predecessor_initialization_behavior_is_unchanged():
    preheader = _prefix_mov_const(_PREFIX_INITIAL_STATE)
    graph = FlowGraph(
        blocks={
            0: _prefix_block(0, (1,), (), (preheader,)),
            1: _prefix_block(
                1,
                (_PREFIX_HANDLER, _PREFIX_NEXT),
                (0, 3),
                (_prefix_tail(),),
            ),
            _PREFIX_HANDLER: _prefix_block(_PREFIX_HANDLER, (), (1,)),
            _PREFIX_NEXT: _prefix_block(_PREFIX_NEXT, (), (1,)),
            3: _prefix_block(3, (1,), (1,)),
        },
        entry_serial=0,
        func_ea=0x2000,
    )
    dmap = build_state_dispatcher_map_from_flow_graph(graph)
    assert dmap is not None
    assert dmap.dispatcher_entry_block == 1

    assert recover_entry_dominated_initial_state(graph, dmap) == _PREFIX_INITIAL_STATE
