from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from d810.recon.flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNodeKey,
    StateRedirectAnchor,
)
from d810.recon.flow.residual_handoff_resolution import (
    has_live_exact_residual_handoff_with_valranges,
    is_semantic_handoff_redirect,
    resolve_effective_target_entry,
    resolve_singleton_state_write_value,
    resolve_synthesized_handoff_target,
)


def _edge(*, source_block: int = 40, target_entry: int = 99) -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=source_block, state_const=0x11),
        target_key=StateDagNodeKey(handler_serial=target_entry, state_const=0x22),
        target_state=0x22,
        target_entry_anchor=target_entry,
        target_label="0x22",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=source_block,
            branch_arm=None,
        ),
        ordered_path=(12, source_block),
        last_write_site=None,
    )


class TestResidualHandoffResolution:
    def test_has_live_exact_residual_handoff_injects_valrange_hook(self) -> None:
        resolver = object()
        with (
            patch(
                "d810.recon.flow.residual_handoff_resolution._resolve_state_via_valranges",
                return_value=resolver,
            ),
            patch(
                "d810.recon.flow.residual_handoff_resolution.discover_has_live_exact_residual_handoff",
                return_value=True,
            ) as discover,
        ):
            assert has_live_exact_residual_handoff_with_valranges(
                object(),
                (7, 8),
                state_var_stkoff=0x30,
                dispatcher=object(),
            )
        assert discover.call_args.kwargs["resolve_state_via_valranges"] is resolver

    def test_singleton_resolution_injects_valrange_hook(self) -> None:
        resolver = object()
        with (
            patch(
                "d810.recon.flow.residual_handoff_resolution._resolve_state_via_valranges",
                return_value=resolver,
            ),
            patch(
                "d810.recon.flow.residual_handoff_resolution.discover_singleton_state_write_value",
                return_value=0x44,
            ) as discover,
        ):
            assert (
                resolve_singleton_state_write_value(
                    object(),
                    12,
                    state_var_stkoff=0x38,
                )
                == 0x44
            )
        assert discover.call_args.kwargs["resolve_state_via_valranges"] is resolver

    def test_synthesized_resolution_injects_valrange_hook(self) -> None:
        resolver = object()
        dag = SimpleNamespace()
        with (
            patch(
                "d810.recon.flow.residual_handoff_resolution._resolve_state_via_valranges",
                return_value=resolver,
            ),
            patch(
                "d810.recon.flow.residual_handoff_resolution.discover_synthesized_handoff_target",
                return_value=(0x11, 24),
            ) as discover,
        ):
            assert resolve_synthesized_handoff_target(
                dag,
                object(),
                12,
                state_var_stkoff=0x38,
                bst_node_blocks={1, 2},
                dispatcher=object(),
                via_pred=7,
            ) == (0x11, 24)
        assert discover.call_args.kwargs["resolve_state_via_valranges"] is resolver

    def test_effective_target_resolution_injects_valrange_hook(self) -> None:
        resolver = object()
        dag = SimpleNamespace()
        edge = _edge()
        with (
            patch(
                "d810.recon.flow.residual_handoff_resolution._resolve_state_via_valranges",
                return_value=resolver,
            ),
            patch(
                "d810.recon.flow.residual_handoff_resolution.discover_effective_target_entry",
                return_value=SimpleNamespace(target_entry=24),
            ) as discover,
        ):
            assert (
                resolve_effective_target_entry(
                    dag,
                    edge,
                    bst_node_blocks={1, 2},
                    state_var_stkoff=0x40,
                    dispatcher_lookup=None,
                    dispatcher=object(),
                    mba=object(),
                )
                == 24
            )
        assert discover.call_args.kwargs["resolve_state_via_valranges"] is resolver

    def test_semantic_handoff_redirect_prefers_immediate_handoff(self) -> None:
        dag = SimpleNamespace()
        edge = _edge(source_block=40, target_entry=24)
        with (
            patch(
                "d810.recon.flow.residual_handoff_resolution.resolve_immediate_handoff_target",
                return_value=(0x11, 24),
            ),
            patch(
                "d810.recon.flow.residual_handoff_resolution.resolve_synthesized_handoff_target",
                return_value=None,
            ) as synth,
        ):
            assert is_semantic_handoff_redirect(
                dag,
                edge,
                source_block=40,
                target_entry=24,
                state_var_stkoff=0x40,
                dispatcher_lookup=None,
                dispatcher=object(),
                mba=object(),
            )
        synth.assert_not_called()
