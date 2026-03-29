from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.dag_redirect_discovery import (
    find_foreign_exact_entry_owner,
    select_plannable_dag_edges,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
)


def _node(*, entry: int, handler: int, state: int) -> StateDagNode:
    return StateDagNode(
        key=StateDagNodeKey(handler_serial=handler, state_const=state),
        kind=StateNodeKind.EXACT,
        state_label=hex(state),
        handler_serial=handler,
        entry_anchor=entry,
        owned_blocks=(),
        exclusive_blocks=(),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )


def _edge(
    *,
    kind: SemanticEdgeKind,
    source_block: int,
    source_kind: RedirectSourceKind,
    source_state: int,
    target_entry: int | None,
    ordered_path: tuple[int, ...],
    branch_arm: int | None = None,
) -> StateDagEdge:
    return StateDagEdge(
        kind=kind,
        source_key=StateDagNodeKey(handler_serial=source_block, state_const=source_state),
        target_key=StateDagNodeKey(handler_serial=target_entry or -1, state_const=0x55) if target_entry is not None else None,
        target_state=0x55,
        target_entry_anchor=target_entry,
        target_label="0x55",
        source_anchor=StateRedirectAnchor(
            kind=source_kind,
            block_serial=source_block,
            branch_arm=branch_arm,
        ),
        ordered_path=ordered_path,
    )


def _dag(*, nodes: tuple[StateDagNode, ...], edges: tuple[StateDagEdge, ...]) -> LinearizedStateDag:
    return LinearizedStateDag(
        dispatcher_entry_serial=6,
        state_var_stkoff=60,
        pre_header_serial=None,
        initial_state=0x10,
        bst_node_blocks=(),
        nodes=nodes,
        edges=edges,
        diagnostics=(),
    )


class TestSelectPlannableDagEdges:
    def test_orders_transition_before_conditional_and_longer_paths_first(self) -> None:
        conditional = _edge(
            kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
            source_block=20,
            source_kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            source_state=0x20,
            target_entry=44,
            ordered_path=(20, 22),
            branch_arm=1,
        )
        long_transition = _edge(
            kind=SemanticEdgeKind.TRANSITION,
            source_block=10,
            source_kind=RedirectSourceKind.EXIT_BLOCK,
            source_state=0x10,
            target_entry=30,
            ordered_path=(10, 12, 14),
        )
        short_transition = _edge(
            kind=SemanticEdgeKind.TRANSITION,
            source_block=11,
            source_kind=RedirectSourceKind.UNCONDITIONAL,
            source_state=0x11,
            target_entry=31,
            ordered_path=(11, 13),
        )
        dag = _dag(nodes=(), edges=(conditional, short_transition, long_transition))

        ordered = select_plannable_dag_edges(dag)

        assert ordered == (long_transition, short_transition, conditional)


class TestFindForeignExactEntryOwner:
    def test_returns_first_other_exact_owner_for_same_entry(self) -> None:
        source_node = _node(entry=24, handler=24, state=0x33)
        foreign_node = _node(entry=24, handler=30, state=0x44)
        dag = _dag(nodes=(foreign_node, source_node), edges=())

        owner = find_foreign_exact_entry_owner(
            dag,
            source_key=source_node.key,
            source_block=24,
        )

        assert owner == foreign_node

    def test_ignores_matching_source_key(self) -> None:
        source_node = _node(entry=24, handler=24, state=0x33)
        dag = _dag(nodes=(source_node,), edges=())

        owner = find_foreign_exact_entry_owner(
            dag,
            source_key=source_node.key,
            source_block=24,
        )

        assert owner is None
