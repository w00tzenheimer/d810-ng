from __future__ import annotations

from d810.analyses.control_flow.recon_dag_index import (
    build_dag_node_maps,
    incoming_edges_by_target_entry,
    resolve_target_node,
    semantic_entry_anchors,
)
from d810.analyses.control_flow.linearized_state_dag import (
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
        owned_blocks=(entry,),
        exclusive_blocks=(entry,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )


def _edge(*, source: int, target_entry: int, target_state: int) -> StateDagEdge:
    source_key = StateDagNodeKey(handler_serial=source, state_const=source)
    target_key = StateDagNodeKey(handler_serial=target_entry, state_const=target_state)
    return StateDagEdge(
        source_key=source_key,
        target_key=target_key,
        target_label=hex(target_state),
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=source,
            branch_arm=None,
        ),
        ordered_path=(source, target_entry),
        target_entry_anchor=target_entry,
        kind=SemanticEdgeKind.TRANSITION,
        target_state=target_state,
        last_write_site=None,
    )


class TestDagIndex:
    def test_semantic_entry_anchors_collects_entries(self):
        dag = LinearizedStateDag(
            dispatcher_entry_serial=2,
            state_var_stkoff=0x3C,
            pre_header_serial=None,
            initial_state=None,
            bst_node_blocks=(),
            nodes=(
                _node(entry=24, handler=24, state=0x11),
                _node(entry=30, handler=30, state=0x22),
            ),
            edges=(),
            diagnostics=(),
        )
        assert semantic_entry_anchors(dag) == {24, 30}

    def test_incoming_edges_by_target_entry_groups_edges(self):
        edge_a = _edge(source=10, target_entry=24, target_state=0x11)
        edge_b = _edge(source=12, target_entry=24, target_state=0x11)
        edge_c = _edge(source=14, target_entry=30, target_state=0x22)
        dag = LinearizedStateDag(
            dispatcher_entry_serial=2,
            state_var_stkoff=0x3C,
            pre_header_serial=None,
            initial_state=None,
            bst_node_blocks=(),
            nodes=(),
            edges=(edge_a, edge_b, edge_c),
            diagnostics=(),
        )
        grouped = incoming_edges_by_target_entry(dag)
        assert grouped[24] == (edge_a, edge_b)
        assert grouped[30] == (edge_c,)

    def test_build_dag_node_maps_indexes_nodes_edges_and_entries(self):
        node_a = _node(entry=24, handler=24, state=0x11)
        node_b = _node(entry=30, handler=30, state=0x22)
        edge = _edge(source=24, target_entry=30, target_state=0x22)
        dag = LinearizedStateDag(
            dispatcher_entry_serial=2,
            state_var_stkoff=0x3C,
            pre_header_serial=None,
            initial_state=None,
            bst_node_blocks=(),
            nodes=(node_a, node_b),
            edges=(edge,),
            diagnostics=(),
        )

        maps = build_dag_node_maps(dag)

        assert maps.node_by_key[node_a.key] == node_a
        assert maps.outgoing_by_key[edge.source_key] == (edge,)
        assert maps.nodes_by_entry_anchor[30] == (node_b,)

    def test_resolve_target_node_prefers_explicit_key_then_unique_entry_anchor(self):
        node_a = _node(entry=24, handler=24, state=0x11)
        node_b = _node(entry=30, handler=30, state=0x22)
        dag = LinearizedStateDag(
            dispatcher_entry_serial=2,
            state_var_stkoff=0x3C,
            pre_header_serial=None,
            initial_state=None,
            bst_node_blocks=(),
            nodes=(node_a, node_b),
            edges=(),
            diagnostics=(),
        )
        maps = build_dag_node_maps(dag)

        explicit = _edge(source=24, target_entry=30, target_state=0x22)
        assert (
            resolve_target_node(
                explicit,
                node_by_key=maps.node_by_key,
                nodes_by_entry_anchor=maps.nodes_by_entry_anchor,
            )
            == node_b
        )

        fallback = StateDagEdge(
            kind=SemanticEdgeKind.TRANSITION,
            source_key=node_a.key,
            target_key=None,
            target_state=0x22,
            target_entry_anchor=30,
            target_label=hex(0x22),
            source_anchor=StateRedirectAnchor(
                kind=RedirectSourceKind.EXIT_BLOCK,
                block_serial=24,
                branch_arm=None,
            ),
            ordered_path=(24, 30),
            last_write_site=None,
        )
        assert (
            resolve_target_node(
                fallback,
                node_by_key=maps.node_by_key,
                nodes_by_entry_anchor=maps.nodes_by_entry_anchor,
            )
            == node_b
        )
