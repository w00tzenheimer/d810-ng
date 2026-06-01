"""Tests for read_dag_from: the portable LinearizedStateDag node read-off.

``read_dag_from`` projects one canonical ``StateDagNode`` per handler as a
read-off of two fixpoints -- the dispatcher discovery (``DispatcherView``:
key/kind) x the block-ownership fixpoint (owned/exclusive/shared_suffix) --
reusing the canonical types.  It is the portable replacement for the live
``build_live_linearized_state_dag_from_graph`` node construction.

This first increment pins the node projection; local segment/edge structure and
outer transition edges land next.
"""
from __future__ import annotations

from d810.analyses.control_flow.block_ownership_domain import analyze_block_ownership
from d810.analyses.control_flow.dispatcher_discovery_fixpoint import DispatcherView
from d810.analyses.control_flow.linearized_state_dag import (
    LocalEdgeKind,
    LocalSegmentKind,
    StateNodeKind,
)
from d810.analyses.control_flow.read_dag import read_dag_from

K1, K2, K3 = 0x10000001, 0x10000002, 0x10000003

# h1=10 (exact K1); h_range=20 (range {K2,K3}); shared suffix 30; head=1, compare=2
_SUCC = {1: [2], 2: [10, 20], 10: [30], 20: [30], 30: [1]}
_PRED: dict[int, list[int]] = {n: [] for n in _SUCC}
for _p, _ss in _SUCC.items():
    for _s in _ss:
        _PRED[_s].append(_p)


def _owner_result():
    return analyze_block_ownership(
        nodes=list(_SUCC),
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
        handler_entries={10, 20},
        dispatcher_region={1, 2},
    )


def _view():
    return DispatcherView(
        handler_entry_by_state={K1: 10, K2: 20},
        handler_range_map={20: (K2, K3)},
        bst_node_blocks=frozenset({2}),
        dispatcher_entry=1,
        result=None,
    )


def _dag():
    return read_dag_from(
        view=_view(), owner_result=_owner_result(), dispatcher_entry_serial=1
    )


def test_one_node_per_handler():
    assert {n.handler_serial for n in _dag().nodes} == {10, 20}


def test_exact_handler_node_key_and_kind():
    node = next(n for n in _dag().nodes if n.handler_serial == 10)
    assert node.kind is StateNodeKind.EXACT
    assert node.key.state_const == K1
    assert node.key.range_lo is None and node.key.range_hi is None


def test_range_handler_node_key_and_kind():
    node = next(n for n in _dag().nodes if n.handler_serial == 20)
    assert node.kind is StateNodeKind.RANGE_BACKED
    assert node.key.range_lo == K2 and node.key.range_hi == K3


def test_owner_set_fields_are_read_off():
    nodes = {n.handler_serial: n for n in _dag().nodes}
    # block 30 is the shared epilogue (owned by both 10 and 20).
    assert nodes[10].owned_blocks == (10, 30)
    assert nodes[10].exclusive_blocks == (10,)
    assert nodes[10].shared_suffix_blocks == (30,)
    assert nodes[20].owned_blocks == (20, 30)
    assert nodes[20].exclusive_blocks == (20,)
    assert nodes[20].shared_suffix_blocks == (30,)


def test_nodes_sorted_by_handler_serial():
    serials = [n.handler_serial for n in _dag().nodes]
    assert serials == sorted(serials)


def test_container_carries_dispatcher_and_bst_blocks():
    dag = _dag()
    assert dag.dispatcher_entry_serial == 1
    assert dag.bst_node_blocks == (2,)


def test_local_structure_populated_when_topology_provided():
    dag = read_dag_from(
        view=_view(),
        owner_result=_owner_result(),
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
        dispatcher_entry_serial=1,
    )
    node10 = next(n for n in dag.nodes if n.handler_serial == 10)
    # owned = (10, 30); 30 is the shared epilogue.
    assert {s.segment_id for s in node10.local_segments} == {"blk[10]", "blk[30]"}
    kinds = {s.segment_id: s.kind for s in node10.local_segments}
    assert kinds["blk[30]"] is LocalSegmentKind.SHARED_SUFFIX
    e = {(x.source_segment_id, x.target_segment_id, x.kind) for x in node10.local_edges}
    assert ("blk[10]", "blk[30]", LocalEdgeKind.SHARED_SUFFIX) in e
