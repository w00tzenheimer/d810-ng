from __future__ import annotations

import ida_hexrays

from types import SimpleNamespace
from unittest.mock import patch

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
    collect_residual_source_handoff_facts,
    dispatcher_exact_state_target,
    dispatcher_has_exact_state_row,
    resolve_effective_target_entry,
    resolve_assignment_map_handoff_target,
    resolve_immediate_handoff_target,
    resolve_nonexact_dispatch_target,
    resolve_path_lead_entry_from_node,
    resolve_projected_snapshot_handoff_target,
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


class _DummyMblock:
    def __init__(self, head: object | None):
        self.head = head


class _DummyMba:
    def __init__(self, blocks: dict[int, _DummyMblock]):
        self._blocks = blocks

    def get_mblock(self, serial: int):
        return self._blocks.get(int(serial))


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

    def test_resolves_assignment_map_handoff_target(self) -> None:
        target = _node(entry=24, handler=24, state=0x33)
        dag = _dag((target,), ())
        state_machine = SimpleNamespace(
            assignment_map={
                10: (
                    SimpleNamespace(
                        opcode=ida_hexrays.m_mov,
                        l=SimpleNamespace(
                            t=ida_hexrays.mop_n,
                            nnn=SimpleNamespace(value=0x33),
                        ),
                    ),
                )
            }
        )
        dispatcher = SimpleNamespace(
            _rows=(SimpleNamespace(lo=0x33, hi=0x34, target=2),),
        )

        assert (
            resolve_assignment_map_handoff_target(
                dag,
                state_machine,
                10,
                bst_node_blocks={2, 6},
                dispatcher=dispatcher,
            )
            == (0x33, 24)
        )

    def test_effective_target_prefers_normalized_nonexact_over_same_corridor_handoff(self) -> None:
        target = _node(entry=30, handler=30, state=0x33)
        edge = _edge(
            source_handler=10,
            target_key=target.key,
            target_entry=30,
            target_state=0x33,
            target_label="0x00000033",
            ordered_path=(8, 10),
        )
        dag = _dag((target,), (edge,))
        dispatcher = SimpleNamespace(
            _rows=(SimpleNamespace(lo=0x30, hi=0x40, target=2),),
        )

        with (
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_redirect_safe_target_entry",
                return_value=30,
            ),
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_nonexact_dispatch_target",
                return_value=40,
            ),
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_immediate_handoff_target",
                return_value=(0x55, 8),
            ),
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_cover_fallback_entry_for_state",
                return_value=None,
            ),
        ):
            resolution = resolve_effective_target_entry(
                dag,
                edge,
                bst_node_blocks={2, 6},
                state_var_stkoff=0x20,
                dispatcher_lookup=None,
                dispatcher=dispatcher,
                mba=object(),
            )

        assert resolution.target_entry == 40

    def test_effective_target_preserves_dag_target_for_nonexact_state_conflict(self) -> None:
        target = _node(entry=30, handler=30, state=0x33)
        edge = _edge(
            source_handler=10,
            target_key=target.key,
            target_entry=30,
            target_state=0x33,
            target_label="0x00000033",
            ordered_path=(8, 10),
        )
        dag = _dag((target,), (edge,))
        dispatcher = SimpleNamespace(
            _rows=(SimpleNamespace(lo=0x30, hi=0x40, target=2),),
        )

        with (
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_redirect_safe_target_entry",
                return_value=30,
            ),
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_nonexact_dispatch_target",
                return_value=None,
            ),
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_immediate_handoff_target",
                return_value=(0x33, 40),
            ),
            patch(
                "d810.recon.flow.residual_handoff_discovery.resolve_dag_entry_for_state",
                return_value=31,
            ),
        ):
            resolution = resolve_effective_target_entry(
                dag,
                edge,
                bst_node_blocks={2, 6},
                state_var_stkoff=0x20,
                dispatcher_lookup=None,
                dispatcher=dispatcher,
                mba=object(),
            )

        assert resolution.target_entry == 30

    def test_resolves_immediate_and_projected_snapshot_handoff_targets(self) -> None:
        target = _node(entry=24, handler=24, state=0x33)
        dag = _dag((target,), ())
        dispatcher = SimpleNamespace(
            _rows=(SimpleNamespace(lo=0x33, hi=0x34, target=2),),
        )
        insn = SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            d=SimpleNamespace(t=ida_hexrays.mop_S, stkoff=0x88),
            l=SimpleNamespace(
                t=ida_hexrays.mop_n,
                nnn=SimpleNamespace(value=0x33),
            ),
            next=None,
        )
        mba = _DummyMba({10: _DummyMblock(insn)})
        flow_graph = SimpleNamespace(
            get_block=lambda serial: SimpleNamespace(insn_snapshots=(insn,)) if serial == 10 else None
        )

        assert (
            resolve_immediate_handoff_target(
                dag,
                mba,
                10,
                state_var_stkoff=0x88,
                bst_node_blocks={2, 6},
                dispatcher_lookup=None,
                dispatcher=dispatcher,
            )
            == (0x33, 24)
        )
        assert (
            resolve_projected_snapshot_handoff_target(
                dag,
                flow_graph,
                10,
                state_var_stkoff=0x88,
                bst_node_blocks={2, 6},
                dispatcher=dispatcher,
            )
            == (0x33, 24)
        )

    def test_collects_residual_source_handoff_facts(self, monkeypatch) -> None:
        dag = _dag((), ())

        monkeypatch.setattr(
            "d810.recon.flow.residual_handoff_discovery.block_has_state_var_write",
            lambda mba, block_serial, **kwargs: mba == "analysis",
        )
        monkeypatch.setattr(
            "d810.recon.flow.residual_handoff_discovery.resolve_assignment_map_handoff_target",
            lambda *args, **kwargs: (0x11, 24),
        )
        monkeypatch.setattr(
            "d810.recon.flow.residual_handoff_discovery.resolve_projected_snapshot_handoff_target",
            lambda *args, **kwargs: (0x22, 25),
        )
        monkeypatch.setattr(
            "d810.recon.flow.residual_handoff_discovery.resolve_immediate_handoff_target",
            lambda dag, mba, source_block, **kwargs: (
                (0x33, 26) if mba == "analysis" else (0x44, 27)
            ),
        )
        monkeypatch.setattr(
            "d810.recon.flow.residual_handoff_discovery.resolve_synthesized_handoff_target",
            lambda *args, **kwargs: None,
        )
        monkeypatch.setattr(
            "d810.recon.flow.residual_handoff_discovery.resolve_projected_path_tail_target",
            lambda *args, **kwargs: (0x55, 28),
        )

        facts = collect_residual_source_handoff_facts(
            dag,
            state_machine=object(),
            projected_flow_graph=object(),
            source_block=10,
            current_preds=(7,),
            state_var_stkoff=0x88,
            bst_node_blocks={2, 6},
            dispatcher_lookup=None,
            dispatcher=object(),
            analysis_mba="analysis",
            live_mba="live",
        )

        assert facts.source_block == 10
        assert facts.current_preds == (7,)
        assert facts.source_has_state_write is True
        assert facts.assignment_map_handoff == (0x11, 24)
        assert facts.projected_snapshot_handoff == (0x22, 25)
        assert facts.immediate_handoff == (0x33, 26)
        assert facts.live_immediate_handoff == (0x44, 27)
        assert facts.source_level_handoff == (0x33, 26)
        assert facts.projected_path_handoff == (0x55, 28)
        assert facts.handoff == (0x11, 24)
