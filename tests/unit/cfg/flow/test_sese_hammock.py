from __future__ import annotations

from d810.analyses.control_flow.sese_hammock import (
    classify_exact_conditional_shape,
    conditional_distance_to_return,
    compute_postdominator_tree,
    flow_graph_exit_blocks,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _graph(blocks: dict[int, tuple[tuple[int, ...], tuple[int, ...]]], entry: int) -> FlowGraph:
    return FlowGraph(
        blocks={
            serial: BlockSnapshot(
                serial,
                0,
                succs,
                preds,
                0,
                0,
                (),
            )
            for serial, (succs, preds) in blocks.items()
        },
        entry_serial=entry,
        func_ea=0x401000,
    )


def test_conditional_distance_to_return_counts_branch_hops() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((21,), (10,)),
            12: ((13, 15), (10,)),
            13: ((21,), (12,)),
            15: ((21,), (12,)),
            21: ((), (11, 13, 15)),
        },
        entry=10,
    )

    distances = conditional_distance_to_return(flow_graph)

    assert flow_graph_exit_blocks(flow_graph) == frozenset({21})
    assert distances[21] == 0
    assert distances[11] == 0
    assert distances[12] == 1
    assert distances[13] == 0
    assert distances[15] == 0


def test_compute_postdominator_tree_reports_follow_block() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((14,), (10,)),
            12: ((21,), (10,)),
            14: ((15, 21), (11,)),
            15: ((21,), (14,)),
            21: ((), (12, 14, 15)),
        },
        entry=10,
    )

    tree = compute_postdominator_tree(flow_graph)

    assert tree is not None
    assert tree.postdominates(21, 10)
    assert tree.idom[10] == 21
    assert tree.idom[11] == 14


def test_classify_exact_conditional_shape_accepts_local_hammock() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((14,), (10,)),
            12: ((21,), (10,)),
            14: ((15, 21), (11,)),
            15: ((21,), (14,)),
            21: ((), (12, 14, 15)),
        },
        entry=10,
    )
    transition_edge = type(
        "Edge",
        (),
        {
            "ordered_path": (10, 11, 14, 21),
            "kind": type("Kind", (), {"name": "CONDITIONAL_TRANSITION"})(),
            "source_key": type("SourceKey", (), {"state_const": 0x11111111})(),
            "source_anchor": type("Anchor", (), {"block_serial": 10})(),
        },
    )()
    sibling_return_edge = type(
        "Edge",
        (),
        {
            "ordered_path": (10, 12, 21),
            "kind": type("Kind", (), {"name": "CONDITIONAL_RETURN"})(),
            "source_key": type("SourceKey", (), {"state_const": 0x11111111})(),
            "source_anchor": type("Anchor", (), {"block_serial": 10})(),
        },
    )()

    shape = classify_exact_conditional_shape(
        flow_graph=flow_graph,
        source_block=10,
        transition_edge=transition_edge,
        sibling_return_edge=sibling_return_edge,
        postdom_tree=compute_postdominator_tree(flow_graph),
        return_distance=conditional_distance_to_return(flow_graph),
    )

    assert shape is not None
    assert shape.taken_successor == 11
    assert shape.fallback_successor == 12
    assert shape.follow_block == 21
    assert shape.taken_return_distance == 1
    assert shape.fallback_return_distance == 0


def test_classify_exact_conditional_shape_rejects_when_fallback_is_farther() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((21,), (10,)),
            12: ((13, 15), (10,)),
            13: ((21,), (12,)),
            15: ((21,), (12,)),
            21: ((), (11, 13, 15)),
        },
        entry=10,
    )
    transition_edge = type(
        "Edge",
        (),
        {
            "ordered_path": (10, 11, 21),
            "kind": type("Kind", (), {"name": "CONDITIONAL_TRANSITION"})(),
            "source_key": type("SourceKey", (), {"state_const": 0x11111111})(),
            "source_anchor": type("Anchor", (), {"block_serial": 10})(),
        },
    )()
    sibling_return_edge = type(
        "Edge",
        (),
        {
            "ordered_path": (10, 12, 13, 21),
            "kind": type("Kind", (), {"name": "CONDITIONAL_RETURN"})(),
            "source_key": type("SourceKey", (), {"state_const": 0x11111111})(),
            "source_anchor": type("Anchor", (), {"block_serial": 10})(),
        },
    )()

    shape = classify_exact_conditional_shape(
        flow_graph=flow_graph,
        source_block=10,
        transition_edge=transition_edge,
        sibling_return_edge=sibling_return_edge,
        postdom_tree=compute_postdominator_tree(flow_graph),
        return_distance=conditional_distance_to_return(flow_graph),
    )

    assert shape is None
