"""Tests for the executor terminal-byte-emit fact guard."""
from __future__ import annotations

from d810.cfg.graph_modification import RedirectBranch, RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine import (
    terminal_byte_emit_fact_guard,
)
from d810.optimizers.microcode.flow.flattening.engine.terminal_byte_emit_fact_guard import (
    filter_terminal_byte_emit_fact_redirects,
)
from d810.recon.facts import FactObservation, ValidatedFactView


def _terminal_byte_emit_fact(
    fact_id: str,
    *,
    destination_block: int = 143,
    byte_index: int = 1,
    source_ea: int = 0x180015906,
) -> FactObservation:
    return FactObservation(
        fact_id=fact_id,
        kind="TerminalByteEmitterFact",
        semantic_key=f"{fact_id}:semantic",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=source_ea,
        payload={
            "corridor_role": "terminal_tail",
            "byte_index": byte_index,
            "destination_block": destination_block,
            "block_serial": destination_block,
        },
    )


def _patch_state_const_refs(monkeypatch, refs: frozenset[str]) -> None:
    monkeypatch.setattr(
        terminal_byte_emit_fact_guard,
        "collect_const_var_refs_in_block",
        lambda _mba, _block_serial: refs,
    )


def test_state_flow_source_into_terminal_byte_emit_target_rejects(monkeypatch) -> None:
    """Source block 108 has ``mov #0x393685BA, %var_7BC`` -- the byte-emit
    target 143 is a known ``terminal_tail`` with byte_index=1.  The
    redirect must be filtered out and recorded."""
    _patch_state_const_refs(monkeypatch, frozenset({"7bc"}))
    fact = _terminal_byte_emit_fact("byte_emit:active", destination_block=143)
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    redirect_goto = RedirectGoto(from_serial=39, old_target=2, new_target=161)
    fact_target_161 = _terminal_byte_emit_fact(
        "byte_emit:byte3", destination_block=161, byte_index=3
    )
    view_with_both = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(fact, fact_target_161),
    )

    redirect_branch_108 = RedirectBranch(
        from_serial=108, old_target=110, new_target=143
    )
    redirect_branch_129 = RedirectBranch(
        from_serial=129, old_target=131, new_target=143
    )

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect_goto, redirect_branch_108, redirect_branch_129],
        mba=object(),
        fact_view=view_with_both,
        dispatcher_serial=2,
    )

    assert filtered == []
    assert len(rejections) == 3
    rejected_targets = {r.target_block for r in rejections}
    assert rejected_targets == {143, 161}
    rejected_sources = {r.source_block for r in rejections}
    assert rejected_sources == {39, 108, 129}
    assert all("7bc" in r.state_const_writes for r in rejections)


def test_non_state_flow_source_permits_redirect(monkeypatch) -> None:
    """Source has only data-var writes (no ``%var_7BC`` constant write)
    -- the redirect must pass through unchanged because the source is
    not state-flow scaffolding."""
    _patch_state_const_refs(monkeypatch, frozenset({"650", "228"}))
    fact = _terminal_byte_emit_fact("byte_emit:active", destination_block=143)
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    redirect = RedirectGoto(from_serial=42, old_target=2, new_target=143)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_no_fact_view_is_noop(monkeypatch) -> None:
    """When the validated fact view is absent, the guard must be a no-op
    even for sources that do contain ``%var_7BC`` writes."""
    _patch_state_const_refs(monkeypatch, frozenset({"7bc"}))
    redirects: list = [
        RedirectGoto(from_serial=39, old_target=2, new_target=161),
        RedirectBranch(from_serial=108, old_target=110, new_target=143),
    ]

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        list(redirects),
        mba=object(),
        fact_view=None,
        dispatcher_serial=2,
    )

    assert filtered == redirects
    assert rejections == ()
