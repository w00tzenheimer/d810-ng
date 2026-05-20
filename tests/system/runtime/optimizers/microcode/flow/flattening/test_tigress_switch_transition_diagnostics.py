from __future__ import annotations

import inspect
from types import SimpleNamespace

import d810.hexrays.observability as hexrays_observability
import d810.recon.flow.switch_case_transition_analysis as switch_case_transition_analysis
import d810.recon.flow.switch_table_analysis as switch_table_analysis
import d810.recon.observability as recon_observability
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherUnflatteningRule,
)
from d810.optimizers.microcode.flow.flattening.unflattener_switch_case import (
    UnflattenerSwitchCase,
)


def test_tigress_switch_rule_observes_live_transition_facts(monkeypatch) -> None:
    rule = object.__new__(UnflattenerSwitchCase)
    rule.mba = SimpleNamespace(entry_ea=0x401000, maturity=4)
    rule.dispatcher_list = ()
    rule._transition_diag_emitted = set()
    dispatch_map = SimpleNamespace(dispatcher_entry_block=7)
    observed: list[tuple[object, tuple[object, ...]]] = []

    monkeypatch.setattr(
        GenericDispatcherUnflatteningRule,
        "retrieve_all_dispatchers",
        lambda self: setattr(self, "dispatcher_list", (object(),)),
    )
    monkeypatch.setattr(
        switch_table_analysis,
        "analyze_switch_table_dispatcher",
        lambda _mba: SimpleNamespace(state_dispatcher_map=dispatch_map),
    )
    monkeypatch.setattr(
        switch_case_transition_analysis,
        "collect_switch_case_transition_facts_from_mba",
        lambda **_kwargs: ("fact",),
    )
    monkeypatch.setattr(
        hexrays_observability,
        "mba_to_block_snapshots",
        lambda _mba: ("block",),
    )
    monkeypatch.setattr(
        hexrays_observability,
        "request_capture_mba_snapshot",
        lambda **_kwargs: "snap",
    )
    monkeypatch.setattr(
        recon_observability,
        "observe_switch_case_transition_facts",
        lambda snap, facts: observed.append((snap, tuple(facts))),
    )

    rule.retrieve_all_dispatchers()

    assert observed == [("snap", ("fact",))]
    source = inspect.getsource(UnflattenerSwitchCase._observe_switch_case_transition_facts)
    assert "GraphModification" not in source
    assert "ModificationBuilder" not in source
