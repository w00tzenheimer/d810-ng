"""Behavior-equivalence cover for the E5 history owner (step 2).

Covers cross-maturity promotion through the explicit owner
(``DispatcherHistoryStore`` + ``analyze_dispatcher_live``), proving the
history path preserves dispatcher type and initial state across maturity
transitions.

System/runtime because ``dispatcher_history`` imports ``lift`` (hence
``ida_hexrays``) at module top; ``lift`` / ``analyze_dispatcher`` are
stubbed so no real decompilation runs.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.backends.hexrays.evidence.dispatcher import dispatcher_history as dh_mod
from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
    DispatcherHistory,
    DispatcherHistoryStore,
    analyze_dispatcher_live,
    is_dispatcher_block,
)
from d810.analyses.control_flow.dispatcher_kind import DispatcherType

MMAT_CALLS = 4
MMAT_GLBOPT1 = 8
MMAT_GLBOPT2 = 9


class _FakeMba:
    def __init__(self, entry_ea: int, maturity: int) -> None:
        self.entry_ea = entry_ea
        self.maturity = maturity


def _install_stubs(monkeypatch, analyses):
    """Stub lift + analyze_dispatcher; record observed history kwargs."""
    calls: list[tuple[object, object]] = []
    seq = iter(analyses)

    def fake_lift(mba):
        return SimpleNamespace(blocks={})

    def fake_analyze(flow_graph, *, previous_dispatcher_type=None,
                     persisted_initial_state=None):
        calls.append((previous_dispatcher_type, persisted_initial_state))
        dtype, istate = next(seq)
        return SimpleNamespace(dispatcher_type=dtype, initial_state=istate, blocks={})

    monkeypatch.setattr(dh_mod, "lift", fake_lift)
    monkeypatch.setattr(dh_mod, "analyze_dispatcher", fake_analyze)
    return calls


def test_advanced_with_promotes_type_and_keeps_state_when_none() -> None:
    """Pure promotion rule: type advances; initial_state only overwrites
    when not None."""
    h0 = DispatcherHistory()
    h1 = h0.advanced_with(
        SimpleNamespace(dispatcher_type=DispatcherType.CONDITIONAL_CHAIN,
                        initial_state=0x1234)
    )
    assert h1 == DispatcherHistory(DispatcherType.CONDITIONAL_CHAIN, 0x1234)

    h2 = h1.advanced_with(
        SimpleNamespace(dispatcher_type=DispatcherType.SWITCH_TABLE,
                        initial_state=None)
    )
    assert h2 == DispatcherHistory(DispatcherType.SWITCH_TABLE, 0x1234)


def test_first_analysis_has_no_history(monkeypatch) -> None:
    calls = _install_stubs(monkeypatch, [(DispatcherType.CONDITIONAL_CHAIN, 0x1234)])
    store = DispatcherHistoryStore()
    analyze_dispatcher_live(_FakeMba(0x401000, MMAT_CALLS), store=store)
    assert calls == [(None, None)]


def test_history_threaded_across_maturity(monkeypatch) -> None:
    calls = _install_stubs(
        monkeypatch,
        [
            (DispatcherType.CONDITIONAL_CHAIN, 0x1234),
            (DispatcherType.SWITCH_TABLE, None),
            (DispatcherType.SWITCH_TABLE, None),
        ],
    )
    store = DispatcherHistoryStore()
    mba = _FakeMba(0x401000, MMAT_CALLS)
    analyze_dispatcher_live(mba, store=store)
    mba.maturity = MMAT_GLBOPT1
    analyze_dispatcher_live(mba, store=store)
    mba.maturity = MMAT_GLBOPT2
    analyze_dispatcher_live(mba, store=store)

    assert calls[0] == (None, None)
    assert calls[1] == (DispatcherType.CONDITIONAL_CHAIN, 0x1234)
    # GLBOPT1's None initial_state must NOT clobber the persisted 0x1234.
    assert calls[2] == (DispatcherType.SWITCH_TABLE, 0x1234)


def test_same_maturity_uses_memo(monkeypatch) -> None:
    calls = _install_stubs(monkeypatch, [(DispatcherType.CONDITIONAL_CHAIN, 0x1234)])
    store = DispatcherHistoryStore()
    mba = _FakeMba(0x401000, MMAT_CALLS)
    a1 = analyze_dispatcher_live(mba, store=store)
    a2 = analyze_dispatcher_live(mba, store=store)
    assert len(calls) == 1
    assert a1 is a2


def test_clear_resets_history(monkeypatch) -> None:
    calls = _install_stubs(
        monkeypatch,
        [
            (DispatcherType.CONDITIONAL_CHAIN, 0x1234),
            (DispatcherType.SWITCH_TABLE, 0x5678),
        ],
    )
    store = DispatcherHistoryStore()
    mba = _FakeMba(0x401000, MMAT_CALLS)
    analyze_dispatcher_live(mba, store=store)
    store.clear(mba.entry_ea)
    mba.maturity = MMAT_GLBOPT1
    analyze_dispatcher_live(mba, store=store)
    assert calls[1] == (None, None)


def test_is_dispatcher_block_reads_analysis() -> None:
    analysis = SimpleNamespace(
        blocks={
            5: SimpleNamespace(is_dispatcher=True),
            6: SimpleNamespace(is_dispatcher=False),
        }
    )
    assert is_dispatcher_block(analysis, 5) is True
    assert is_dispatcher_block(analysis, 6) is False
    assert is_dispatcher_block(analysis, 99) is False  # unknown serial
