from __future__ import annotations

from types import SimpleNamespace

import d810.recon.flow.path_horizon as path_horizon
from d810.recon.flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNodeKey,
    StateRedirectAnchor,
)
from d810.recon.flow.state_machine_analysis import StateWriteSite


class _DummyFlowGraph:
    def __init__(self, blocks: dict[int, object]):
        self._blocks = {int(k): v for k, v in blocks.items()}

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))


def _edge(
    *,
    kind: SemanticEdgeKind,
    target_state: int,
    last_write_site: tuple[int, int] | None = None,
) -> StateDagEdge:
    return StateDagEdge(
        kind=kind,
        source_key=StateDagNodeKey(handler_serial=10, state_const=0x10),
        target_key=StateDagNodeKey(handler_serial=20, state_const=target_state),
        target_state=target_state,
        target_entry_anchor=20,
        target_label=hex(target_state),
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=10,
            branch_arm=None,
        ),
        ordered_path=(10, 20),
        last_write_site=last_write_site,
    )


def _constant_result():
    return SimpleNamespace(in_stk_maps={}, in_reg_maps={})


class TestResolveTransitionPathHorizon:
    def test_prefers_dfs_proven_write_site(self):
        edge = _edge(
            kind=SemanticEdgeKind.TRANSITION,
            target_state=0x22,
            last_write_site=(20, 0x1234),
        )

        resolved = path_horizon.resolve_transition_path_horizon(
            edge,
            flow_graph=_DummyFlowGraph({}),
            ordered_path=(10, 20),
            state_var_stkoff=0x3C,
            constant_result=_constant_result(),
        )

        assert resolved is not None
        block_serial, site = resolved
        assert block_serial == 20
        assert site.insn_ea == 0x1234
        assert site.state_value == 0x22

    def test_uses_snapshot_path_result_when_available(self, monkeypatch):
        edge = _edge(kind=SemanticEdgeKind.TRANSITION, target_state=0x22)
        expected = StateWriteSite(
            block_serial=20,
            state_value=0x22,
            insn_ea=0x1111,
            insn_index=3,
        )
        monkeypatch.setattr(
            path_horizon,
            "find_last_state_write_site_on_path_snapshot",
            lambda *args, **kwargs: (20, expected),
        )

        resolved = path_horizon.resolve_transition_path_horizon(
            edge,
            flow_graph=_DummyFlowGraph({}),
            ordered_path=(10, 20),
            state_var_stkoff=0x3C,
            constant_result=_constant_result(),
        )

        assert resolved == (20, expected)

    def test_conditional_fallback_uses_per_block_sites_and_overrides_state(self, monkeypatch):
        edge = _edge(kind=SemanticEdgeKind.CONDITIONAL_TRANSITION, target_state=0x44)
        stale_site = StateWriteSite(
            block_serial=20,
            state_value=0x33,
            insn_ea=0x2222,
            insn_index=1,
        )
        monkeypatch.setattr(
            path_horizon,
            "find_last_state_write_site_on_path_snapshot",
            lambda *args, **kwargs: None,
        )
        monkeypatch.setattr(
            path_horizon,
            "find_state_write_sites_snapshot",
            lambda *args, **kwargs: [stale_site] if args[1] == 20 else [],
        )

        resolved = path_horizon.resolve_transition_path_horizon(
            edge,
            flow_graph=_DummyFlowGraph({20: SimpleNamespace(insn_snapshots=())}),
            ordered_path=(10, 20),
            state_var_stkoff=0x3C,
            constant_result=_constant_result(),
        )

        assert resolved is not None
        block_serial, site = resolved
        assert block_serial == 20
        assert site.state_value == 0x44
        assert site.insn_ea == 0x2222

    def test_conditional_raw_dest_scan_is_last_resort(self, monkeypatch):
        edge = _edge(kind=SemanticEdgeKind.CONDITIONAL_TRANSITION, target_state=0x55)
        monkeypatch.setattr(
            path_horizon,
            "find_last_state_write_site_on_path_snapshot",
            lambda *args, **kwargs: None,
        )
        monkeypatch.setattr(
            path_horizon,
            "find_state_write_sites_snapshot",
            lambda *args, **kwargs: [],
        )

        insn = SimpleNamespace(
            ea=0x3333,
            d=SimpleNamespace(t=3, stkoff=0x3C),
        )
        block = SimpleNamespace(insn_snapshots=(insn,))

        resolved = path_horizon.resolve_transition_path_horizon(
            edge,
            flow_graph=_DummyFlowGraph({20: block}),
            ordered_path=(10, 20),
            state_var_stkoff=0x3C,
            constant_result=_constant_result(),
        )

        assert resolved is not None
        block_serial, site = resolved
        assert block_serial == 20
        assert site.insn_ea == 0x3333
        assert site.state_value == 0x55
