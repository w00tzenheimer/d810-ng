"""Unit tests for slicing + prune-block insertion (DEFFAI Step 4).

Covers: the conservative condvar slice (drops pure pass-through blocks, keeps
condvar defs / branches / merges, contracts edges), the condvar-cell discovery,
prune-block insertion giving each multi-pred handler a single-pred entry, the
original->synthesized serial map, and idempotence of both passes.  No IDA.
"""
from __future__ import annotations

import pytest

from d810.ir.flowgraph import BlockKind
from d810.ir.semantics import PredicateKind
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.preprocess import (
    PRUNE_BLOCK_META_KEY,
    condvar_cells_of,
    insert_prune_blocks,
    slice_on_condvars,
)

from tests.unit.analyses.control_flow.deffai._helpers import (
    block,
    goto,
    jcc,
    make_graph,
    mov,
    num,
    ret,
    stk,
)

STATE_OFF = 0x10
STATE = LocationRef.stack(STATE_OFF, 8)
COND = LocationRef.stack(0x20, 8)


def test_condvar_cells_of_collects_compared_cells():
    # block 0 branches on COND; the state cell is added when supplied.
    b0 = block(0, (jcc(stk(0x20), num(0), taken=2),), (1, 2))
    b1 = block(1, (ret(),), ())
    b2 = block(2, (ret(),), ())
    graph = make_graph([b0, b1, b2])
    cells = condvar_cells_of(graph, state_cell=STATE)
    assert COND in cells
    assert STATE in cells


def test_slice_drops_passthrough_keeps_branch_and_defs():
    # 0: def state (mov) -> 1 ; 1: pure passthrough goto -> 2 ; 2: branch -> 3,4
    b0 = block(0, (mov(num(5), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (goto(2),), (2,))  # pure passthrough, no condvar touch
    b2 = block(2, (jcc(stk(STATE_OFF), num(5), taken=3),), (3, 4))
    b3 = block(3, (ret(),), ())
    b4 = block(4, (ret(),), ())
    graph = make_graph([b0, b1, b2, b3, b4])

    sliced, condvars = slice_on_condvars(graph, state_cell=STATE)
    # The pure-passthrough block 1 is dropped; the def block 0 and branch 2 stay.
    assert 1 not in sliced.blocks
    assert 0 in sliced.blocks  # defines the state cell -> kept
    assert 2 in sliced.blocks  # branch -> kept
    assert 3 in sliced.blocks and 4 in sliced.blocks
    # Edge contraction: block 0 now points directly at block 2.
    assert sliced.blocks[0].succs == (2,)
    assert STATE in condvars


def test_slice_keeps_merge_blocks():
    # A merge (npred > 1) is kept even with no condvar touch.
    b0 = block(0, (jcc(stk(0x20), num(0), taken=2),), (1, 2))
    b1 = block(1, (goto(3),), (3,))
    b2 = block(2, (goto(3),), (3,))
    b3 = block(3, (ret(),), ())  # merge, npred=2
    graph = make_graph([b0, b1, b2, b3])
    sliced, _ = slice_on_condvars(graph, state_cell=STATE)
    assert 3 in sliced.blocks  # merge kept
    assert 0 in sliced.blocks  # branch kept


def test_slice_is_idempotent():
    b0 = block(0, (mov(num(5), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (goto(2),), (2,))
    b2 = block(2, (jcc(stk(STATE_OFF), num(5), taken=3),), (3, 4))
    b3 = block(3, (ret(),), ())
    b4 = block(4, (ret(),), ())
    graph = make_graph([b0, b1, b2, b3, b4])

    once, _ = slice_on_condvars(graph, state_cell=STATE)
    twice, _ = slice_on_condvars(once, state_cell=STATE)
    assert set(once.blocks) == set(twice.blocks)
    assert {s: b.succs for s, b in once.blocks.items()} == {
        s: b.succs for s, b in twice.blocks.items()
    }


def test_slice_preserves_entry():
    # Even a passthrough entry block is kept (it is the entry).
    b0 = block(0, (goto(1),), (1,))
    b1 = block(1, (jcc(stk(STATE_OFF), num(5), taken=2),), (2, 3))
    b2 = block(2, (ret(),), ())
    b3 = block(3, (ret(),), ())
    graph = make_graph([b0, b1, b2, b3], entry=0)
    sliced, _ = slice_on_condvars(graph, state_cell=STATE)
    assert 0 in sliced.blocks
    assert sliced.entry_serial == 0


def _dispatcher_graph():
    # Dispatcher (0) routes to two handlers (1, 2), each of which is ALSO entered
    # from a back-edge block (3, 4) -> handlers have npred > 1.
    #   0: if (state == 10) goto 1 else 2
    #   1: handler-10 -> 3
    #   2: handler-20 -> 4
    #   3: back-edge -> 1   (makes handler 1 multi-pred)
    #   4: back-edge -> 2   (makes handler 2 multi-pred)
    b0 = block(0, (jcc(stk(STATE_OFF), num(10), taken=1),), (1, 2))
    b1 = block(1, (goto(3),), (3,))
    b2 = block(2, (goto(4),), (4,))
    b3 = block(3, (goto(1),), (1,))
    b4 = block(4, (goto(2),), (2,))
    return make_graph([b0, b1, b2, b3, b4])


def test_insert_prune_blocks_gives_single_pred_entry():
    graph = _dispatcher_graph()
    assert graph.blocks[1].npred == 2  # dispatcher + back-edge
    pruned = insert_prune_blocks(
        graph, dispatcher_entry=0, handler_entries=[1, 2]
    )
    # The dispatcher no longer points directly at handler 1/2.
    assert 1 not in pruned.blocks[0].succs
    assert 2 not in pruned.blocks[0].succs
    # Each prune block is single-pred (only the dispatcher) -> single-succ handler.
    origin = dict(pruned.metadata[PRUNE_BLOCK_META_KEY])
    assert set(origin.values()) == {1, 2}
    for prune_serial, handler in origin.items():
        pblk = pruned.blocks[prune_serial]
        assert pblk.preds == (0,)
        assert pblk.succs == (handler,)
        assert pblk.insn_snapshots == ()  # empty prune block


def test_insert_prune_blocks_serial_map_round_trips():
    graph = _dispatcher_graph()
    pruned = insert_prune_blocks(
        graph, dispatcher_entry=0, handler_entries=[1, 2]
    )
    origin = dict(pruned.metadata[PRUNE_BLOCK_META_KEY])
    # Every synthesized serial maps back to its original handler, and the handler
    # is reachable from the prune block.
    for prune_serial, handler in origin.items():
        assert pruned.blocks[prune_serial].succs == (handler,)
        assert handler in graph.blocks


def test_insert_prune_blocks_idempotent_on_single_pred():
    # A handler that already has a single predecessor is left untouched.
    b0 = block(0, (jcc(stk(STATE_OFF), num(10), taken=1),), (1, 2))
    b1 = block(1, (ret(),), ())  # npred=1 (only dispatcher)
    b2 = block(2, (ret(),), ())  # npred=1
    graph = make_graph([b0, b1, b2])
    pruned = insert_prune_blocks(
        graph, dispatcher_entry=0, handler_entries=[1, 2]
    )
    # No prune blocks inserted (handlers already single-pred).
    assert not pruned.metadata.get(PRUNE_BLOCK_META_KEY)
    assert set(pruned.blocks) == set(graph.blocks)


def test_insert_prune_blocks_rerun_is_noop():
    graph = _dispatcher_graph()
    once = insert_prune_blocks(graph, dispatcher_entry=0, handler_entries=[1, 2])
    # After inserting, the dispatcher's successors are the prune blocks (single-
    # pred); re-running over the new handler set inserts nothing more for them.
    origin = dict(once.metadata[PRUNE_BLOCK_META_KEY])
    prune_serials = set(origin)
    twice = insert_prune_blocks(
        once, dispatcher_entry=0, handler_entries=sorted(once.blocks[0].succs)
    )
    # The prune blocks are single-pred already -> no new synthesized blocks.
    new_origin = dict(twice.metadata[PRUNE_BLOCK_META_KEY])
    assert set(new_origin) == prune_serials


def test_insert_prune_blocks_no_dispatcher_is_safe():
    graph = _dispatcher_graph()
    pruned = insert_prune_blocks(
        graph, dispatcher_entry=999, handler_entries=[1, 2]
    )
    assert set(pruned.blocks) == set(graph.blocks)  # no-op rebuild
