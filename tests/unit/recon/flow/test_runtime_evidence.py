from __future__ import annotations

from d810.recon.facts.model import FactObservation, ValidatedFactView
from d810.recon.flow.runtime_evidence import ensure_terminal_byte_fact_view


def test_ensure_terminal_byte_fact_view_keeps_existing_terminal_view(monkeypatch):
    obs = FactObservation(
        fact_id="f1",
        kind="TerminalByteEmitterFact",
        semantic_key="terminal:1",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.8,
        source_block=10,
        payload={"corridor_role": "terminal_tail", "byte_index": 1},
    )
    view = ValidatedFactView(maturity="MMAT_GLBOPT1", observations=(obs,))

    assert ensure_terminal_byte_fact_view(
        object(),
        func_ea=0x1000,
        maturity=4,
        fact_view=view,
    ) is view


def test_ensure_terminal_byte_fact_view_collects_when_view_is_empty(monkeypatch):
    collected = FactObservation(
        fact_id="f2",
        kind="TerminalByteEmitterFact",
        semantic_key="terminal:2",
        maturity="MMAT_GLBOPT1",
        phase="runtime",
        confidence=0.8,
        source_block=20,
        payload={"corridor_role": "terminal_tail", "byte_index": 2},
    )

    class _Collector:
        def collect(self, target, *, func_ea, maturity, phase):
            assert target == "mba"
            assert func_ea == 0x2000
            assert maturity == 4
            assert phase == "post_bundle_stabilize"
            return (collected,)

    import d810.recon.facts.collectors.terminal_byte_emitter as collector_module

    monkeypatch.setattr(
        collector_module,
        "TerminalByteEmitterFactCollector",
        lambda: _Collector(),
    )

    view = ensure_terminal_byte_fact_view(
        "mba",
        func_ea=0x2000,
        maturity=4,
        fact_view=ValidatedFactView(maturity="MMAT_GLBOPT1"),
        phase="post_bundle_stabilize",
    )

    assert view is not None
    assert view.active_observations == (collected,)
