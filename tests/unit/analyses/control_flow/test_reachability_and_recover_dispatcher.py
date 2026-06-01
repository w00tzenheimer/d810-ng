"""Portable reachability primitive + recover_dispatcher analysis pass (extraction #1).

Locks the byte-identical semantics of the live ``compute_reachability_info`` walk now that it is a
shared primitive, and proves ``recover_dispatcher`` computes reachability over a real FlowGraph.
"""
from __future__ import annotations

from d810.analyses.control_flow.reachability import reachable_from
from d810.analyses.control_flow.dispatcher_recovery import (
    DispatcherRecovery,
    recover_dispatcher,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _blk(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial, block_type=1, succs=succs, preds=preds,
        flags=0, start_ea=0x1000 + serial, insn_snapshots=(),
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
    assert reachable_from(adj, 4) == reachable_from({0: (2, 1), 1: (3,), 2: (3,), 3: ()}, 4)
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
