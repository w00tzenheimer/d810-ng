from __future__ import annotations

from d810.recon.flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.recon.flow.target_entry_resolution import (
    resolve_edge_target_entry,
    resolve_exact_dag_entry_for_state,
    resolve_semantic_reference_entry_for_state,
)


def _node(
    *,
    entry: int,
    handler: int,
    state: int,
    owned: tuple[int, ...] = (),
    exclusive: tuple[int, ...] = (),
    shared_suffix: tuple[int, ...] = (),
) -> StateDagNode:
    return StateDagNode(
        key=StateDagNodeKey(handler_serial=handler, state_const=state),
        kind=StateNodeKind.EXACT,
        state_label=hex(state),
        handler_serial=handler,
        entry_anchor=entry,
        owned_blocks=owned,
        exclusive_blocks=exclusive,
        shared_suffix_blocks=shared_suffix,
        local_segments=(),
        local_edges=(),
    )


def _edge(
    *,
    source_handler: int,
    target_key: StateDagNodeKey | None,
    target_entry: int | None,
    target_state: int | None,
) -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=source_handler, state_const=source_handler),
        target_key=target_key,
        target_state=target_state,
        target_entry_anchor=target_entry,
        target_label=hex(target_state) if target_state is not None else "unknown",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=source_handler,
            branch_arm=None,
        ),
        ordered_path=(source_handler,),
        last_write_site=None,
    )


class TestResolveEdgeTargetEntry:
    def test_keeps_non_dispatcher_target_entry(self):
        node = _node(entry=24, handler=24, state=0x11)
        edge = _edge(
            source_handler=10,
            target_key=node.key,
            target_entry=24,
            target_state=0x11,
        )

        result = resolve_edge_target_entry(
            edge,
            node_by_key={node.key: node},
            dispatcher_region={2, 6},
        )

        assert result.target_entry == 24
        assert result.rejection_reason is None
        assert result.original_dispatcher_entry is None

    def test_prefers_same_state_head_over_interior_non_dispatcher_target(self):
        semantic_head = _node(entry=24, handler=24, state=0x11)
        interior_target = _node(entry=30, handler=30, state=0x11)
        edge = _edge(
            source_handler=10,
            target_key=interior_target.key,
            target_entry=30,
            target_state=0x11,
        )

        result = resolve_edge_target_entry(
            edge,
            node_by_key={
                semantic_head.key: semantic_head,
                interior_target.key: interior_target,
            },
            dispatcher_region={2, 6},
        )

        assert result.target_entry == 24
        assert result.rejection_reason is None
        assert result.original_dispatcher_entry is None

    def test_resolves_dispatcher_target_to_non_bst_block_from_target_node(self):
        node = _node(entry=2, handler=2, state=0x11, exclusive=(24,))
        edge = _edge(
            source_handler=10,
            target_key=node.key,
            target_entry=2,
            target_state=0x11,
        )

        result = resolve_edge_target_entry(
            edge,
            node_by_key={node.key: node},
            dispatcher_region={2, 6},
        )

        assert result.target_entry == 24
        assert result.original_dispatcher_entry == 2

    def test_prefers_same_state_non_dispatcher_head_over_interior_owned_block(self):
        dispatcher_node = _node(entry=2, handler=2, state=0x11, exclusive=(30,))
        semantic_head = _node(entry=24, handler=24, state=0x11)
        edge = _edge(
            source_handler=10,
            target_key=dispatcher_node.key,
            target_entry=2,
            target_state=0x11,
        )

        result = resolve_edge_target_entry(
            edge,
            node_by_key={
                dispatcher_node.key: dispatcher_node,
                semantic_head.key: semantic_head,
            },
            dispatcher_region={2, 6},
        )

        assert result.target_entry == 24
        assert result.original_dispatcher_entry == 2

    def test_resolves_dispatcher_target_by_same_state_fallback_node(self):
        dispatcher_node = _node(entry=2, handler=2, state=0x11)
        fallback_node = _node(entry=24, handler=24, state=0x11)
        edge = _edge(
            source_handler=10,
            target_key=dispatcher_node.key,
            target_entry=2,
            target_state=0x11,
        )

        result = resolve_edge_target_entry(
            edge,
            node_by_key={
                dispatcher_node.key: dispatcher_node,
                fallback_node.key: fallback_node,
            },
            dispatcher_region={2, 6},
        )

        assert result.target_entry == 24
        assert result.original_dispatcher_entry == 2

    def test_rejects_missing_or_unresolved_dispatcher_target(self):
        edge = _edge(
            source_handler=10,
            target_key=None,
            target_entry=None,
            target_state=None,
        )
        missing = resolve_edge_target_entry(
            edge,
            node_by_key={},
            dispatcher_region={2, 6},
        )
        assert missing.target_entry is None
        assert missing.rejection_reason == "missing_target_entry"

        dispatcher_only = _node(entry=2, handler=2, state=0x11)
        unresolved = resolve_edge_target_entry(
            _edge(
                source_handler=10,
                target_key=dispatcher_only.key,
                target_entry=2,
                target_state=0x11,
            ),
            node_by_key={dispatcher_only.key: dispatcher_only},
            dispatcher_region={2, 6},
        )
        assert unresolved.target_entry is None
        assert unresolved.rejection_reason == "dispatcher_target_entry"


def test_resolve_exact_dag_entry_for_state_prefers_exact_non_dispatcher_head():
    fallback_node = _node(entry=71, handler=71, state=0x4C77464F)
    exact_node = _node(entry=66, handler=66, state=0x4C77464F)
    dag = type("Dag", (), {"nodes": (fallback_node, exact_node)})()

    entry = resolve_exact_dag_entry_for_state(
        dag,
        0x4C77464F,
        dispatcher_region={2, 71},
    )

    assert entry == 66


def test_resolve_semantic_reference_entry_for_state_resolves_direct_state_label():
    semantic_reference_program = type(
        "SemanticReferenceProgram",
        (),
        {
            "nodes": (
                type(
                    "Node",
                    (),
                    {
                        "label_text": "STATE_4C77464F",
                        "entry_anchor": 66,
                    },
                )(),
            )
        },
    )()

    entry = resolve_semantic_reference_entry_for_state(
        0x4C77464F,
        semantic_reference_program=semantic_reference_program,
        dispatcher_region={2, 71},
    )

    assert entry == 66


def test_resolve_semantic_reference_entry_for_state_allows_dispatcher_exact_head():
    semantic_reference_program = type(
        "SemanticReferenceProgram",
        (),
        {
            "nodes": (
                type(
                    "Node",
                    (),
                    {
                        "label_text": "STATE_4E69F350",
                        "entry_anchor": 72,
                        "node_kind": "state_family",
                    },
                )(),
            )
        },
    )()

    denied = resolve_semantic_reference_entry_for_state(
        0x4E69F350,
        semantic_reference_program=semantic_reference_program,
        dispatcher_region={66, 71, 72},
    )
    allowed = resolve_semantic_reference_entry_for_state(
        0x4E69F350,
        semantic_reference_program=semantic_reference_program,
        dispatcher_region={66, 71, 72},
        allow_dispatcher_exact_head=True,
    )

    assert denied is None
    assert allowed == 72
