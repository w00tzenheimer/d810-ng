"""SESE / hammock helpers for exact-node lowering heuristics."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from d810.analyses.control_flow.postdominator import PostdomTree, compute_postdom_tree

__all__ = [
    "ExactConditionalNodeShape",
    "classify_exact_conditional_shape",
    "conditional_distance_to_return",
    "compute_postdominator_tree",
    "flow_graph_exit_blocks",
]


@dataclass(frozen=True, slots=True)
class ExactConditionalNodeShape:
    """SESE-ish shape facts for an exact conditional source site."""

    taken_successor: int
    fallback_successor: int
    follow_block: int | None
    taken_return_distance: int | None
    fallback_return_distance: int | None


def _edge_kind_name(edge: object) -> str:
    kind = getattr(getattr(edge, "kind", None), "name", None)
    return str(kind) if kind is not None else ""


def _site_key(edge: object) -> tuple[int, int] | None:
    source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
    source_block = getattr(getattr(edge, "source_anchor", None), "block_serial", None)
    if source_state is None or source_block is None:
        return None
    return (int(source_state) & 0xFFFFFFFF, int(source_block))


def flow_graph_exit_blocks(flow_graph: object) -> frozenset[int]:
    """Return blocks with no CFG successors."""

    return frozenset(
        int(serial)
        for serial, block in getattr(flow_graph, "blocks", {}).items()
        if int(getattr(block, "nsucc", 0)) == 0
    )


def conditional_distance_to_return(flow_graph: object) -> dict[int, int]:
    """Return a 0/1 BFS distance to any exit, charging only branch hops."""

    exits = flow_graph_exit_blocks(flow_graph)
    if not exits:
        return {}

    distance: dict[int, int] = {int(exit_serial): 0 for exit_serial in exits}
    worklist: deque[int] = deque(int(exit_serial) for exit_serial in exits)
    while worklist:
        current = worklist.popleft()
        current_distance = distance[current]
        current_block = flow_graph.get_block(current)
        if current_block is None:
            continue
        for pred_serial in tuple(int(pred) for pred in getattr(current_block, "preds", ())):
            pred_block = flow_graph.get_block(pred_serial)
            if pred_block is None:
                continue
            step_cost = 1 if int(getattr(pred_block, "nsucc", 0)) > 1 else 0
            candidate = current_distance + step_cost
            previous = distance.get(pred_serial)
            if previous is None or candidate < previous:
                distance[pred_serial] = candidate
                if step_cost == 0:
                    worklist.appendleft(pred_serial)
                else:
                    worklist.append(pred_serial)
    return distance


def compute_postdominator_tree(flow_graph: object) -> PostdomTree | None:
    """Build a postdominator tree for a flow-graph snapshot."""

    exits = flow_graph_exit_blocks(flow_graph)
    if not exits:
        return None
    successors = {
        int(serial): tuple(int(succ) for succ in getattr(block, "succs", ()))
        for serial, block in getattr(flow_graph, "blocks", {}).items()
    }
    return compute_postdom_tree(
        successors,
        int(getattr(flow_graph, "entry_serial", 0)),
        exits,
    )


def _return_path_first_hop(edge: object, source_block: int) -> int | None:
    ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
    if not ordered_path:
        return None
    if ordered_path[0] == source_block:
        return ordered_path[1] if len(ordered_path) >= 2 else None
    return ordered_path[0]


def classify_exact_conditional_shape(
    *,
    flow_graph: object,
    source_block: int,
    transition_edge: object,
    sibling_return_edge: object,
    postdom_tree: PostdomTree | None,
    return_distance: dict[int, int],
) -> ExactConditionalNodeShape | None:
    """Classify the shape of an exact conditional site."""

    source_snapshot = flow_graph.get_block(source_block)
    if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 2:
        return None

    succs = tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))
    ordered_path = tuple(int(node) for node in getattr(transition_edge, "ordered_path", ()) or ())
    if len(ordered_path) < 2:
        return None

    taken_successor = int(ordered_path[1])
    if taken_successor not in succs:
        return None

    fallback_candidates = tuple(succ for succ in succs if succ != taken_successor)
    if len(fallback_candidates) != 1:
        return None
    fallback_successor = fallback_candidates[0]

    return_first_hop = _return_path_first_hop(sibling_return_edge, source_block)
    if return_first_hop is not None and return_first_hop != fallback_successor:
        return None

    taken_distance = return_distance.get(taken_successor)
    fallback_distance = return_distance.get(fallback_successor)
    if fallback_distance is None:
        return None
    if taken_distance is not None and fallback_distance > taken_distance:
        return None

    follow_block = None
    if postdom_tree is not None:
        follow_block = getattr(postdom_tree, "idom", {}).get(source_block)

    return ExactConditionalNodeShape(
        taken_successor=taken_successor,
        fallback_successor=fallback_successor,
        follow_block=follow_block,
        taken_return_distance=taken_distance,
        fallback_return_distance=fallback_distance,
    )
