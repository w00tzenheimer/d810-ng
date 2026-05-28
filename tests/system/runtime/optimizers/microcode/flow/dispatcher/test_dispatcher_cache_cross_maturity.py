"""Regression cover for DispatcherCache cross-maturity history (E5 step 1).

Pins the two load-bearing facts the cache threads across maturity
transitions, BEFORE the planned retirement refactor moves their
ownership out of the class:

* ``_previous_type``            <- prior analysis ``dispatcher_type``
* ``_persisted_initial_state``  <- prior analysis ``initial_state``
                                   (ONLY when not None -- a later None
                                   must NOT clobber a known value)

These are promoted on a cache-hit at a new maturity and fed into the
pure ``analyze_dispatcher(...)`` on the next ``analyze()``.  If a
refactor silently drops this threading, dispatcher detection degrades
across maturities in ways the golden e2e cases may not surface -- so
this test asserts the exact kwargs the pure analyzer receives.

Lives in ``tests/system/runtime`` because ``dispatcher_cache`` imports
``ida_hexrays`` at module top (``unit-tests-no-optimizers`` /
``-no-hexrays`` forbid importing it from ``tests/unit``).  No real
decompilation: ``lift`` and ``analyze_dispatcher`` are stubbed, so the
test is fast and deterministic and exercises ONLY the cache's
history-threading logic.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.optimizers.microcode.flow.dispatcher import dispatcher_cache as dc_mod
from d810.optimizers.microcode.flow.dispatcher.dispatcher_cache import (
    DispatcherCache,
)
from d810.recon.flow.dispatcher_kind import DispatcherType

# Hex-Rays maturity ints (values irrelevant; only distinctness matters).
MMAT_CALLS = 4
MMAT_GLBOPT1 = 8
MMAT_GLBOPT2 = 9


class _FakeMba:
    def __init__(self, entry_ea: int, maturity: int) -> None:
        self.entry_ea = entry_ea
        self.maturity = maturity


@pytest.fixture(autouse=True)
def _isolate_cache():
    DispatcherCache.clear_cache()
    yield
    DispatcherCache.clear_cache()


def _install_stubs(monkeypatch, analyses):
    """Stub lift + analyze_dispatcher.

    ``analyses`` is an ordered list of ``(dispatcher_type, initial_state)``
    returned by successive ``analyze_dispatcher`` calls.  Returns the
    ``calls`` list, each entry the ``(previous_dispatcher_type,
    persisted_initial_state)`` that call observed.
    """
    calls: list[tuple[object, object]] = []
    seq = iter(analyses)

    def fake_lift(mba):
        return SimpleNamespace(blocks={})

    def fake_analyze(flow_graph, *, previous_dispatcher_type=None,
                     persisted_initial_state=None):
        calls.append((previous_dispatcher_type, persisted_initial_state))
        dtype, istate = next(seq)
        return SimpleNamespace(
            dispatcher_type=dtype,
            initial_state=istate,
            blocks={},
        )

    monkeypatch.setattr(dc_mod, "lift", fake_lift)
    monkeypatch.setattr(dc_mod, "analyze_dispatcher", fake_analyze)
    return calls


def test_first_analysis_has_no_history(monkeypatch) -> None:
    calls = _install_stubs(monkeypatch, [(DispatcherType.CONDITIONAL_CHAIN, 0x1234)])
    mba = _FakeMba(0x401000, MMAT_CALLS)

    DispatcherCache.get_or_create(mba).analyze()

    assert calls == [(None, None)]


def test_history_threaded_across_maturity(monkeypatch) -> None:
    calls = _install_stubs(
        monkeypatch,
        [
            (DispatcherType.CONDITIONAL_CHAIN, 0x1234),  # MMAT_CALLS
            (DispatcherType.CONDITIONAL_CHAIN, 0x1234),  # MMAT_GLBOPT1
        ],
    )
    mba = _FakeMba(0x401000, MMAT_CALLS)

    first = DispatcherCache.get_or_create(mba)
    first.analyze()

    # Same function, next maturity -> same cached instance, history seeded.
    mba.maturity = MMAT_GLBOPT1
    second = DispatcherCache.get_or_create(mba)
    assert second is first  # keyed by func_ea
    second.analyze()

    assert calls[0] == (None, None)
    assert calls[1] == (DispatcherType.CONDITIONAL_CHAIN, 0x1234)


def test_persisted_initial_state_not_clobbered_by_none(monkeypatch) -> None:
    """A later analysis with ``initial_state is None`` must NOT erase a
    previously persisted concrete initial state -- the cache only
    promotes ``initial_state`` when it is not None."""
    calls = _install_stubs(
        monkeypatch,
        [
            (DispatcherType.CONDITIONAL_CHAIN, 0x1234),  # CALLS: real state
            (DispatcherType.SWITCH_TABLE, None),         # GLBOPT1: state lost
            (DispatcherType.SWITCH_TABLE, None),         # GLBOPT2
        ],
    )
    mba = _FakeMba(0x401000, MMAT_CALLS)
    cache = DispatcherCache.get_or_create(mba)
    cache.analyze()

    mba.maturity = MMAT_GLBOPT1
    DispatcherCache.get_or_create(mba).analyze()

    mba.maturity = MMAT_GLBOPT2
    DispatcherCache.get_or_create(mba).analyze()

    assert calls[0] == (None, None)
    # GLBOPT1 sees CALLS history.
    assert calls[1] == (DispatcherType.CONDITIONAL_CHAIN, 0x1234)
    # GLBOPT2: previous_type advances to SWITCH_TABLE, but the persisted
    # initial state stays 0x1234 (GLBOPT1's None did NOT clobber it).
    assert calls[2] == (DispatcherType.SWITCH_TABLE, 0x1234)


def test_same_maturity_does_not_reanalyze(monkeypatch) -> None:
    calls = _install_stubs(monkeypatch, [(DispatcherType.CONDITIONAL_CHAIN, 0x1234)])
    mba = _FakeMba(0x401000, MMAT_CALLS)

    cache = DispatcherCache.get_or_create(mba)
    cache.analyze()
    cache.analyze()  # same maturity -> cached, no second analyze_dispatcher

    assert len(calls) == 1


def test_clear_cache_resets_history(monkeypatch) -> None:
    calls = _install_stubs(
        monkeypatch,
        [
            (DispatcherType.CONDITIONAL_CHAIN, 0x1234),
            (DispatcherType.SWITCH_TABLE, 0x5678),
        ],
    )
    mba = _FakeMba(0x401000, MMAT_CALLS)
    DispatcherCache.get_or_create(mba).analyze()

    DispatcherCache.clear_cache(mba.entry_ea)

    # Fresh instance after clear -> no carried-over history.
    mba.maturity = MMAT_GLBOPT1
    DispatcherCache.get_or_create(mba).analyze()

    assert calls[1] == (None, None)
