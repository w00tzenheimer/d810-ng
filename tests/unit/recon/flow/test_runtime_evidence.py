from __future__ import annotations

from d810.recon.facts.model import (
    FactMapping,
    FactObservation,
    FactStatus,
    ValidatedFactView,
)
from d810.recon.flow.runtime_evidence import (
    ensure_terminal_byte_fact_view,
    summarize_fact_view,
)


def _terminal_obs(*, maturity: str, block: int, byte_index: int) -> FactObservation:
    return FactObservation(
        fact_id=f"byte{byte_index}:blk={block}",
        kind="TerminalByteEmitterFact",
        semantic_key=f"byte{byte_index}",
        maturity=maturity,
        phase="pre_d810",
        confidence=0.9,
        source_block=block,
        payload={
            "destination_block": block,
            "block_serial": block,
            "byte_index": byte_index,
            "corridor_role": "terminal_tail",
        },
    )


def _state_write_obs(
    *,
    fact_id: str,
    maturity: str,
    block_serial: int,
) -> FactObservation:
    return FactObservation(
        fact_id=fact_id,
        kind="StateWriteAnchorFact",
        semantic_key=fact_id,
        maturity=maturity,
        phase="pre_d810",
        confidence=0.9,
        source_block=block_serial,
        payload={"block_serial": block_serial, "opcode": "m_mov"},
    )


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


def test_summarize_fact_view_counts_active_evidence():
    terminal = _terminal_obs(maturity="MMAT_GLBOPT1", block=217, byte_index=6)
    state_write = _state_write_obs(
        fact_id="state:100",
        maturity="MMAT_GLBOPT1",
        block_serial=100,
    )
    mapping = FactMapping(
        source_fact_id="state:100",
        source_maturity="MMAT_LOCOPT",
        target_maturity="MMAT_GLBOPT1",
        status=FactStatus.STATE_CONST_REWRITTEN,
        confidence=0.9,
        payload={"block_serial": 100},
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(terminal, state_write),
        mappings=(mapping,),
    )

    summary = summarize_fact_view(
        view,
        func_ea=0x401000,
        phase="selected_alternate_override",
    )

    assert summary.func_ea == 0x401000
    assert summary.maturity == "MMAT_GLBOPT1"
    assert summary.phase == "selected_alternate_override"
    assert summary.terminal_byte_facts == 1
    assert summary.state_write_facts == 1
    assert summary.rewritten_mappings == 1
    assert summary.observation_count == 2
    assert summary.mapping_count == 1
