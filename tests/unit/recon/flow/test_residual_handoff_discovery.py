from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.recon.flow.residual_handoff_discovery import (
    dispatcher_exact_state_target,
    dispatcher_has_exact_state_row,
    resolve_nonexact_dispatch_target,
    resolve_path_lead_entry_from_node,
    resolve_projected_path_tail_target,
    resolve_redirect_safe_entry_from_node,
    resolve_redirect_safe_target_entry,
)


def _node(
    *,
    entry: int,
    handler: int,
    state: int,
    owned: tuple[int, ...] = (),
    exclusive: tuple[int, ...] = (),
) -> StateDagNode:
    return StateDagNode(
        key=StateDagNodeKey(handler_serial=handler, state_const=state),
        kind=StateNodeKind.EXACT,
        state_label=hex(state),
        handler_serial=handler,
        entry_anchor=entry,
        owned_blocks=owned,
        exclusive_blocks=exclusive,
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )


def _edge(
    *,
    source_handler: int,
    source_state: int | None = None,
    target_key: StateDagNodeKey | None,
    target_entry: int | None,
    target_state: int | None,
    target_label: str | None = None,
    ordered_path: tuple[int, ...] = (),
) -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(
            handler_serial=source_handler,
            state_const=source_handler if source_state is None else source_state,
        ),
        target_key=target_key,
        target_state=target_state,
        target_entry_anchor=target_entry,
        target_label=target_label or (hex(target_state) if target_state is not None else "unknown"),
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=source_handler,
            branch_arm=None,
        ),
        ordered_path=ordered_path or (source_handler,),
        last_write_site=None,
    )


def _dag(nodes: tuple[StateDagNode, ...], edges: tuple[StateDagEdge, ...]):
    return SimpleNamespace(nodes=nodes, edges=edges)


class TestDispatcherExactRows:
    def test_detects_exact_row(self) -> None:
        dispatcher = SimpleNamespace(
            _rows=(
                SimpleNamespace(lo=0x10, hi=0x11, target=24),
                SimpleNamespace(lo=0x20, hi=0x30, target=30),
            )
        )

        assert dispatcher_has_exact_state_row(0x10, dispatcher=dispatcher) is True
        assert dispatcher_has_exact_state_row(0x20, dispatcher=dispatcher) is False
        assert dispatcher_exact_state_target(0x10, dispatcher=dispatcher) == 24
        assert dispatcher_exact_state_target(0x21, dispatcher=dispatcher) is None


class TestRedirectSafeEntryResolution:
    def test_uses_unique_path_lead_when_entry_is_dispatcher(self) -> None:
        node = _node(entry=2, handler=10, state=0x11, exclusive=(24,))
        edge = _edge(
            source_handler=10,
            source_state=0x11,
            target_key=node.key,
            target_entry=2,
            target_state=0x11,
            ordered_path=(24, 40),
        )
        dag = _dag((node,), (edge,))

        assert resolve_path_lead_entry_from_node(dag, node, bst_node_blocks={2, 6}) == 24
        assert (
            resolve_redirect_safe_entry_from_node(
                node,
                dag=dag,
                bst_node_blocks={2, 6},
            )
            == 24
        )

    def test_prefers_labeled_fallback_entry(self) -> None:
        exact_node = _node(entry=2, handler=2, state=0x11)
        fallback_node = StateDagNode(
            key=StateDagNodeKey(handler_serial=24, state_const=0x11),
            kind=StateNodeKind.EXACT,
            state_label="0x00000011_fallback",
            handler_serial=24,
            entry_anchor=24,
            owned_blocks=(),
            exclusive_blocks=(),
            shared_suffix_blocks=(),
            local_segments=(),
            local_edges=(),
        )
        edge = _edge(
            source_handler=40,
            target_key=exact_node.key,
            target_entry=2,
            target_state=0x11,
            target_label="0x00000011_fallback",
            ordered_path=(40,),
        )
        dag = _dag((exact_node, fallback_node), (edge,))

        assert (
            resolve_redirect_safe_target_entry(
                dag,
                edge,
                bst_node_blocks={2, 6},
            )
            == 24
        )

    def test_keeps_explicit_non_path_target_when_safe(self) -> None:
        target_node = _node(entry=30, handler=30, state=0x22, exclusive=(31,))
        edge = _edge(
            source_handler=40,
            target_key=target_node.key,
            target_entry=32,
            target_state=0x22,
            ordered_path=(40, 41),
        )
        dag = _dag((target_node,), (edge,))

        assert (
            resolve_redirect_safe_target_entry(
                dag,
                edge,
                bst_node_blocks={2, 6},
            )
            == 32
        )

    def test_switches_from_stale_path_entry_to_safe_target(self) -> None:
        target_node = _node(entry=30, handler=30, state=0x22, exclusive=(31,))
        edge = _edge(
            source_handler=40,
            target_key=target_node.key,
            target_entry=41,
            target_state=0x22,
            ordered_path=(40, 41),
        )
        dag = _dag((target_node,), (edge,))

        assert (
            resolve_redirect_safe_target_entry(
                dag,
                edge,
                bst_node_blocks={2, 6},
            )
            == 30
        )


class TestResidualTargetDiscovery:
    def test_resolves_nonexact_dispatch_target_via_dispatcher_lookup(self) -> None:
        edge_node = _node(entry=24, handler=24, state=0x33)
        dag = _dag((edge_node,), ())
        dispatcher = SimpleNamespace(
            _rows=(SimpleNamespace(lo=0x30, hi=0x40, target=2),),
            lookup=lambda state: 24 if state == 0x33 else None,
        )

        assert (
            resolve_nonexact_dispatch_target(
                dag,
                0x33,
                source_block=10,
                bst_node_blocks={2, 6},
                dispatcher=dispatcher,
            )
            == 24
        )

    def test_resolves_projected_path_tail_target(self) -> None:
        target = _node(entry=24, handler=24, state=0x33)
        edge = _edge(
            source_handler=10,
            target_key=target.key,
            target_entry=24,
            target_state=0x33,
            ordered_path=(8, 10),
        )
        dag = _dag((target,), (edge,))

        assert (
            resolve_projected_path_tail_target(
                dag,
                source_block=10,
                bst_node_blocks={2, 6},
                predecessor_hints=(8,),
            )
            == (0x33, 24)
        )
