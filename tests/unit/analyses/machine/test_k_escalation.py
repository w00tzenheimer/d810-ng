"""k-escalation policy tests (P4, llr-1d8u; design §6.5/§11)."""
from __future__ import annotations

import pytest

from d810.analyses.machine.k_escalation import (
    TOP_DENSITY_THRESHOLD,
    KBudget,
    should_escalate,
    should_escalate_density,
)


def test_should_escalate_density_fires_above_threshold():
    assert should_escalate_density(TOP_DENSITY_THRESHOLD + 0.01) is True
    assert should_escalate_density(TOP_DENSITY_THRESHOLD) is False
    assert should_escalate_density(0.0) is False


class _M:
    def __init__(self, top_density=None, transitions=()):
        self.top_density = top_density
        self.transitions = transitions


class _T:
    def __init__(self, next_states):
        self.next_states = next_states


def test_should_escalate_reads_top_density():
    assert should_escalate(_M(top_density=0.5)) is True
    assert should_escalate(_M(top_density=0.05)) is False


def test_should_escalate_estimates_from_transitions():
    # 1 of 2 transitions unresolved -> 0.5 density -> escalate
    m = _M(top_density=None, transitions=(_T(()), _T((1, 2))))
    assert should_escalate(m) is True
    # all resolved -> no escalation
    m2 = _M(top_density=None, transitions=(_T((1,)), _T((2,))))
    assert should_escalate(m2) is False


def test_should_escalate_empty_machine_false():
    assert should_escalate(_M(top_density=None, transitions=())) is False


def test_kbudget_schedule_from_start():
    assert KBudget(schedule=(2, 4, 6), start=2).schedule_from_start() == (2, 4, 6)
    assert KBudget(schedule=(2, 4, 6), start=4).schedule_from_start() == (4, 6)
    # start above schedule -> at least the start
    assert KBudget(schedule=(2, 4), start=8).schedule_from_start() == (8,)


def test_kbudget_exhausted_at_last_schedule_entry():
    b = KBudget(schedule=(2, 4, 6), start=2, time_budget_s=1e9)
    b.reset_clock()
    assert b.exhausted(2) is False
    assert b.exhausted(4) is False
    assert b.exhausted(6) is True  # last ladder entry


def test_kbudget_exhausted_on_wallclock():
    b = KBudget(schedule=(2, 4, 6), start=2, time_budget_s=0.0)
    b.reset_clock()
    # zero budget -> exhausted immediately regardless of k
    assert b.exhausted(2) is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
