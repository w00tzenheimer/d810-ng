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
from d810.recon.flow.target_entry_resolution import resolve_edge_target_entry


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
