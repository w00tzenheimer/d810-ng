"""Pure discovery helpers for DAG redirect selection."""

from __future__ import annotations

from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
)


def _edge_priority(edge: StateDagEdge) -> int:
    if edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH:
        return 0
    if edge.source_anchor.kind == RedirectSourceKind.EXIT_BLOCK:
        return 1
    return 2


def select_plannable_dag_edges(
    dag: LinearizedStateDag,
) -> tuple[StateDagEdge, ...]:
    return tuple(
        sorted(
            (
                edge
                for edge in dag.edges
                if edge.kind
                in (
                    SemanticEdgeKind.TRANSITION,
                    SemanticEdgeKind.CONDITIONAL_TRANSITION,
                )
                and edge.target_entry_anchor is not None
            ),
            key=lambda edge: (
                0 if edge.kind == SemanticEdgeKind.TRANSITION else 1,
                -(len(edge.ordered_path)),
                edge.source_anchor.block_serial,
                -1 if edge.source_anchor.branch_arm is None else edge.source_anchor.branch_arm,
                edge.kind.value,
                edge.target_entry_anchor if edge.target_entry_anchor is not None else -1,
                _edge_priority(edge),
            ),
        )
    )


def find_foreign_exact_entry_owner(
    dag: LinearizedStateDag,
    *,
    source_key: StateDagNodeKey,
    source_block: int,
) -> StateDagNode | None:
    for node in dag.nodes:
        if node.kind is not StateNodeKind.EXACT:
            continue
        if node.entry_anchor != source_block:
            continue
        if node.key == source_key:
            return None
        return node
    return None


__all__ = [
    "find_foreign_exact_entry_owner",
    "select_plannable_dag_edges",
]
