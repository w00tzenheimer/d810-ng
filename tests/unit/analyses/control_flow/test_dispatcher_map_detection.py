"""unflatten pass #1: portable equality-chain dispatcher detection over a FlowGraph.

Hand-port of HodurStateMachineDetector — verifies state_const -> handler routing (EQ -> jump
target, NE -> fall-through), dominant-state-variable selection, and the StateDispatcherMap the
downstream passes consume.
"""
from __future__ import annotations

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.dispatcher_recovery import (
    build_state_dispatcher_map_from_flow_graph,
    recover_dispatcher,
)

C1 = 0x10000001
C2 = 0x10000002
STATE_OFF = 0x3C


def _ne_check(const: int, target: int) -> InsnSnapshot:
    """jnz state, const, target  (NE: jump when state != const)."""
    l = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(
        opcode=1, ea=0x1000, operands=(l, r, d), l=l, r=r, d=d,
        kind=InsnKind.EQUALITY_JUMP, branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _blk(serial, succs, preds, tail=None) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial, block_type=1, succs=succs, preds=preds, flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(tail,) if tail is not None else (),
        tail_opcode=tail.opcode if tail is not None else None,
    )


def _chain_graph() -> FlowGraph:
    # 0: jnz state,C1,2  (state==C1 -> fallthrough 1=handler; else -> 2)
    # 2: jnz state,C2,4  (state==C2 -> fallthrough 3=handler; else -> 4=exit)
    # 1,3 handlers ; 4 exit
    return FlowGraph(
        blocks={
            0: _blk(0, (1, 2), (), _ne_check(C1, 2)),
            1: _blk(1, (), (0,)),
            2: _blk(2, (3, 4), (0,), _ne_check(C2, 4)),
            3: _blk(3, (), (2,)),
            4: _blk(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_detects_equality_chain_and_routes_states_to_handlers():
    dmap = build_state_dispatcher_map_from_flow_graph(_chain_graph())
    assert dmap is not None
    assert dmap.resolve_target(C1) == 1   # NE: state==C1 -> fall-through handler
    assert dmap.resolve_target(C2) == 3
    assert dmap.resolve_target(0xDEAD) is None
    assert dmap.state_var_stkoff == STATE_OFF
    assert dmap.state_to_handler() == {C1: 1, C2: 3}


def test_small_constants_are_not_state_checks():
    # a conditional jump against a tiny constant must not be treated as a dispatcher row
    blk0 = _blk(0, (1, 2), (), _ne_check(3, 2))  # const 3 << MIN_STATE_CONSTANT
    g = FlowGraph(
        blocks={0: blk0, 1: _blk(1, (), (0,)), 2: _blk(2, (), (0,))},
        entry_serial=0, func_ea=0x1000,
    )
    assert build_state_dispatcher_map_from_flow_graph(g) is None


def _chain_with_loop_head_graph() -> FlowGraph:
    # Mirror the live OLLVM shape: a dispatcher LOOP HEAD (blk 10) the handler tails back-edge to,
    # followed by the equality-comparator chain (11 -> 12). The comparators each have in-degree 1
    # (reached only from the previous link); blk 10 has the high fan-in (entry + every handler).
    #   0 entry -> 10
    #   10 loop head -> 11               preds = {0, 1, 3}   (handlers loop back here)
    #   11 jnz state,C1,12  -> (1, 12)   handler 1 / next comparator 12
    #   12 jnz state,C2,13  -> (3, 13)   handler 3 / exit 13
    #   1,3 handlers -> 10               (back-edge to the loop head)
    #   13 exit
    return FlowGraph(
        blocks={
            0: _blk(0, (10,), ()),
            10: _blk(10, (11,), (0, 1, 3)),
            11: _blk(11, (1, 12), (10,), _ne_check(C1, 12)),
            12: _blk(12, (3, 13), (11,), _ne_check(C2, 13)),
            1: _blk(1, (10,), (11,)),
            3: _blk(3, (10,), (12,)),
            13: _blk(13, (), (12,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_dispatcher_entry_is_loop_head_not_midchain_comparator():
    # Regression: the entry must be the loop head the handlers converge on (blk 10, in-degree 3),
    # NOT an arbitrary low-in-degree mid-chain comparator (11/12). Ranking only ``chain_blocks`` by
    # in-degree picks a comparator; the dominator-walk from the function entry recovers the true head.
    dmap = build_state_dispatcher_map_from_flow_graph(_chain_with_loop_head_graph())
    assert dmap is not None
    assert dmap.resolve_target(C1) == 1
    assert dmap.resolve_target(C2) == 3
    assert dmap.dispatcher_entry_block == 10
    assert 10 not in dmap.dispatcher_blocks  # the head is not itself a state-comparison block


def test_recover_dispatcher_surfaces_map_and_state_var():
    result = recover_dispatcher(_chain_graph(), facts=None)
    assert result.dispatch_map is not None
    assert result.state_var_stkoff == STATE_OFF
    assert result.dispatch_map.resolve_target(C1) == 1
    # reachability still computed alongside
    assert {0, 1, 2, 3, 4} == set(result.reachable_block_serials)
