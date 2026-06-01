"""Tests for build_local_structure: per-block local segments + classified edges.

The canonical intra-node structure (``StateLocalSegment`` / ``StateLocalEdge``)
is per-block: one segment ``blk[N]`` per owned block, kind-classified, with one
classified edge per intra-region CFG edge.  ``build_local_structure`` is the
portable read-off producer -- a translation of the legacy ``_build_local_edges``
/ ``_classify_local_edge_kind`` that reads off the region topology + the
owner-set shared/terminal sets, emitting the CANONICAL types.
"""
from __future__ import annotations

from d810.analyses.control_flow.linearized_state_dag import (
    LocalEdgeKind,
    LocalSegmentKind,
)
from d810.analyses.control_flow.local_structure import build_local_structure


def _topo(succ):
    pred = {n: [] for n in succ}
    for src, dsts in succ.items():
        for dst in dsts:
            pred.setdefault(dst, [])
            pred[dst].append(src)
    return (lambda n: succ.get(int(n), ())), (lambda n: pred.get(int(n), ()))


def test_one_segment_per_owned_block_with_segment_id():
    succ = {10: [11], 11: []}
    s_of, p_of = _topo(succ)
    segs, _ = build_local_structure(
        (10, 11), successors_of=s_of, predecessors_of=p_of
    )
    assert [(s.segment_id, s.blocks) for s in segs] == [
        ("blk[10]", (10,)),
        ("blk[11]", (11,)),
    ]


def test_branch_segment_and_fallthrough_taken_edges():
    # 10 forks to 11 (arm 0 = fallthrough) and 12 (arm 1 = taken).
    succ = {10: [11, 12], 11: [], 12: []}
    s_of, p_of = _topo(succ)
    segs, edges = build_local_structure(
        (10, 11, 12), successors_of=s_of, predecessors_of=p_of
    )
    kind_by_id = {s.segment_id: s.kind for s in segs}
    assert kind_by_id["blk[10]"] is LocalSegmentKind.BRANCH
    e = {(x.source_segment_id, x.target_segment_id, x.kind, x.branch_arm) for x in edges}
    assert ("blk[10]", "blk[11]", LocalEdgeKind.FALLTHROUGH, 0) in e
    assert ("blk[10]", "blk[12]", LocalEdgeKind.TAKEN, 1) in e


def test_join_segment_and_edge():
    # 11 and 12 both flow into 13 -> 13 is a JOIN (2 preds).
    succ = {10: [11, 12], 11: [13], 12: [13], 13: []}
    s_of, p_of = _topo(succ)
    segs, edges = build_local_structure(
        (10, 11, 12, 13), successors_of=s_of, predecessors_of=p_of
    )
    kind_by_id = {s.segment_id: s.kind for s in segs}
    assert kind_by_id["blk[13]"] is LocalSegmentKind.JOIN
    e = {(x.source_segment_id, x.target_segment_id, x.kind) for x in edges}
    assert ("blk[11]", "blk[13]", LocalEdgeKind.JOIN) in e


def test_shared_suffix_takes_precedence():
    # block 30 is the shared epilogue (owner-set shared) -> SHARED_SUFFIX wins.
    succ = {10: [30], 30: []}
    s_of, p_of = _topo(succ)
    segs, edges = build_local_structure(
        (10, 30),
        successors_of=s_of,
        predecessors_of=p_of,
        shared_blocks=frozenset({30}),
    )
    kind_by_id = {s.segment_id: s.kind for s in segs}
    assert kind_by_id["blk[30]"] is LocalSegmentKind.SHARED_SUFFIX
    e = {(x.source_segment_id, x.target_segment_id, x.kind) for x in edges}
    assert ("blk[10]", "blk[30]", LocalEdgeKind.SHARED_SUFFIX) in e


def test_terminal_exit_classification():
    succ = {10: [99], 99: []}
    s_of, p_of = _topo(succ)
    segs, edges = build_local_structure(
        (10, 99),
        successors_of=s_of,
        predecessors_of=p_of,
        terminal_exit_blocks=frozenset({99}),
    )
    kind_by_id = {s.segment_id: s.kind for s in segs}
    assert kind_by_id["blk[99]"] is LocalSegmentKind.TERMINAL_SUFFIX
    e = {(x.source_segment_id, x.target_segment_id, x.kind) for x in edges}
    assert ("blk[10]", "blk[99]", LocalEdgeKind.TERMINAL) in e


def test_edges_only_within_owned_blocks():
    # 10 -> 20 leaves the owned set (back to dispatcher) -> no local edge for it.
    succ = {10: [11, 20], 11: []}
    s_of, p_of = _topo(succ)
    _, edges = build_local_structure(
        (10, 11), successors_of=s_of, predecessors_of=p_of
    )
    targets = {x.target_segment_id for x in edges}
    assert "blk[20]" not in targets


def test_deterministic_and_deduped():
    succ = {10: [11, 12], 11: [13], 12: [13], 13: []}
    s_of, p_of = _topo(succ)
    segs1, edges1 = build_local_structure((13, 12, 11, 10), successors_of=s_of, predecessors_of=p_of)
    segs2, edges2 = build_local_structure((10, 11, 12, 13), successors_of=s_of, predecessors_of=p_of)
    assert [s.segment_id for s in segs1] == [s.segment_id for s in segs2]
    assert edges1 == edges2
