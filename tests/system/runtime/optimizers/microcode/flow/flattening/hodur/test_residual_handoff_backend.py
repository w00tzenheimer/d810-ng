from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.state_variable import StateVariableRef
from d810.optimizers.microcode.flow.flattening.hodur import (
    residual_handoff_backend as backend_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.residual_handoff_backend import (
    HexRaysEffectiveTargetEvidenceBackend,
    HexRaysResidualFrontierEvidenceBackend,
)


def test_resolve_effective_target_entry_delegates_with_state_stkoff(monkeypatch):
    backend = HexRaysEffectiveTargetEvidenceBackend()
    dag = SimpleNamespace()
    edge = SimpleNamespace(
        source_anchor=SimpleNamespace(block_serial=15),
        target_state=0x4C77464F,
    )
    mba = SimpleNamespace()
    dispatcher = SimpleNamespace()
    dispatcher_lookup = lambda _state: 99
    captured = {}

    def fake_resolve_effective_target(_dag, _edge, **kwargs):
        captured["dag"] = _dag
        captured["edge"] = _edge
        captured["kwargs"] = kwargs
        return 117

    monkeypatch.setattr(
        backend_module,
        "resolve_live_effective_target_entry",
        fake_resolve_effective_target,
    )

    evidence = backend.resolve_effective_target_entry(
        dag,
        edge,
        bst_node_blocks={2},
        state_variable=StateVariableRef(0x7BC, 4),
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        mba=mba,
    )

    assert evidence.source_block == 15
    assert evidence.target_state == 0x4C77464F
    assert evidence.target_entry == 117
    assert evidence.reason == "effective_target_resolved"
    assert captured["dag"] is dag
    assert captured["edge"] is edge
    assert captured["kwargs"]["bst_node_blocks"] == {2}
    assert captured["kwargs"]["state_var_stkoff"] == 0x7BC
    assert captured["kwargs"]["dispatcher_lookup"] is dispatcher_lookup
    assert captured["kwargs"]["dispatcher"] is dispatcher
    assert captured["kwargs"]["mba"] is mba


def test_resolve_effective_target_entry_missing_live_context_returns_none() -> None:
    backend = HexRaysEffectiveTargetEvidenceBackend()
    edge = SimpleNamespace(
        source_anchor=SimpleNamespace(block_serial=15),
        target_state=0x4C77464F,
    )

    evidence = backend.resolve_effective_target_entry(
        SimpleNamespace(),
        edge,
        bst_node_blocks={2},
        state_variable=None,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=None,
    )

    assert evidence.source_block == 15
    assert evidence.target_state == 0x4C77464F
    assert evidence.target_entry is None
    assert evidence.reason == "missing_live_context"


def test_resolve_state_variable_returns_neutral_ref() -> None:
    backend = HexRaysResidualFrontierEvidenceBackend()
    state_machine = SimpleNamespace(
        state_var=SimpleNamespace(
            t=ida_hexrays.mop_S,
            s=SimpleNamespace(off=0x7BC, size=8),
        ),
    )

    assert backend.resolve_state_variable(state_machine=state_machine) == (
        StateVariableRef(0x7BC, 8)
    )


def test_resolve_singleton_state_write_delegates_with_state_stkoff(monkeypatch) -> None:
    backend = HexRaysResidualFrontierEvidenceBackend()
    mba = SimpleNamespace()
    captured = {}

    def fake_resolve_singleton_state_write(_mba, block_serial, **kwargs):
        captured["mba"] = _mba
        captured["block_serial"] = block_serial
        captured["kwargs"] = kwargs
        return 0x4C77464F

    monkeypatch.setattr(
        backend_module,
        "resolve_singleton_state_write_value",
        fake_resolve_singleton_state_write,
    )

    evidence = backend.resolve_singleton_state_write(
        mba,
        16,
        state_variable=StateVariableRef(0x7BC, 4),
    )

    assert evidence is not None
    assert evidence.block_serial == 16
    assert evidence.state_value == 0x4C77464F
    assert evidence.reason == "singleton_state_write"
    assert captured["mba"] is mba
    assert captured["block_serial"] == 16
    assert captured["kwargs"] == {"state_var_stkoff": 0x7BC}


def test_resolve_residual_effective_target_builds_synthetic_edge(monkeypatch) -> None:
    backend = HexRaysResidualFrontierEvidenceBackend()
    dag = SimpleNamespace(nodes=(), edges=())
    dispatcher = SimpleNamespace(lookup=lambda _state: 99)
    mba = SimpleNamespace()
    captured = {}

    monkeypatch.setattr(
        backend_module,
        "supplemental_selected_entry_for_state",
        lambda _dag, _state: 14,
    )

    def fake_resolve_effective_target(_dag, edge, **kwargs):
        captured["dag"] = _dag
        captured["edge"] = edge
        captured["kwargs"] = kwargs
        return 117

    monkeypatch.setattr(
        backend_module,
        "resolve_live_effective_target_entry",
        fake_resolve_effective_target,
    )

    evidence = backend.resolve_residual_effective_target(
        dag,
        pred_serial=16,
        state_value=0x4C77464F,
        dispatcher_model=dispatcher,
        bst_node_blocks={2},
        state_variable=StateVariableRef(0x7BC, 4),
        mba=mba,
    )

    edge = captured["edge"]
    kwargs = captured["kwargs"]
    assert evidence.target_entry == 117
    assert evidence.source_block == 16
    assert evidence.state_value == 0x4C77464F
    assert evidence.reason == "effective_target_resolved"
    assert captured["dag"] is dag
    assert edge.source_anchor.block_serial == 16
    assert edge.source_anchor.branch_arm is None
    assert edge.source_key.state_const is None
    assert edge.target_state == 0x4C77464F
    assert edge.target_label == "STATE_4C77464F"
    assert edge.target_entry_anchor == 14
    assert edge.ordered_path == (16,)
    assert kwargs["bst_node_blocks"] == {2}
    assert kwargs["state_var_stkoff"] == 0x7BC
    assert kwargs["dispatcher"] is dispatcher
    assert kwargs["dispatcher_lookup"] is dispatcher.lookup
    assert kwargs["mba"] is mba
