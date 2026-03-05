"""Unit tests for ReachabilityInfo and AnalysisSnapshot (pure Python, no IDA)."""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)


# ---------------------------------------------------------------------------
# ReachabilityInfo tests
# ---------------------------------------------------------------------------


class TestReachabilityInfo:
    def test_coverage_normal(self) -> None:
        ri = ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset({0, 1, 2, 3}),
            total_blocks=8,
        )
        assert ri.coverage == pytest.approx(0.5)

    def test_coverage_full(self) -> None:
        ri = ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset({0, 1, 2}),
            total_blocks=3,
        )
        assert ri.coverage == pytest.approx(1.0)

    def test_coverage_zero_total(self) -> None:
        ri = ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(),
            total_blocks=0,
        )
        assert ri.coverage == 0.0

    def test_frozen(self) -> None:
        ri = ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset({0}),
            total_blocks=1,
        )
        with pytest.raises((AttributeError, TypeError)):
            ri.entry_serial = 99  # type: ignore[misc]

    def test_reachable_blocks_is_frozenset(self) -> None:
        ri = ReachabilityInfo(
            entry_serial=5,
            reachable_blocks=frozenset({5, 6, 7}),
            total_blocks=10,
        )
        assert isinstance(ri.reachable_blocks, frozenset)


# ---------------------------------------------------------------------------
# AnalysisSnapshot tests
# ---------------------------------------------------------------------------


class _FakeStateMachine:
    """Minimal stand-in for HodurStateMachine in tests."""

    def __init__(self, state_constants: set, handlers: dict, transitions: list) -> None:
        self.state_constants = state_constants
        self.handlers = handlers
        self.transitions = transitions


class TestAnalysisSnapshot:
    def _make_snapshot(self, **kwargs) -> AnalysisSnapshot:
        defaults = dict(
            mba=object(),
            state_machine=None,
            detector=object(),
        )
        defaults.update(kwargs)
        return AnalysisSnapshot(**defaults)

    def test_state_constants_no_state_machine(self) -> None:
        snap = self._make_snapshot(state_machine=None)
        assert snap.state_constants == set()

    def test_state_constants_with_state_machine(self) -> None:
        sm = _FakeStateMachine(
            state_constants={0xDEAD, 0xBEEF},
            handlers={},
            transitions=[],
        )
        snap = self._make_snapshot(state_machine=sm)
        assert snap.state_constants == {0xDEAD, 0xBEEF}

    def test_handler_count_none(self) -> None:
        snap = self._make_snapshot(state_machine=None)
        assert snap.handler_count == 0

    def test_handler_count_with_state_machine(self) -> None:
        sm = _FakeStateMachine(
            state_constants=set(),
            handlers={1: "h1", 2: "h2", 3: "h3"},
            transitions=[],
        )
        snap = self._make_snapshot(state_machine=sm)
        assert snap.handler_count == 3

    def test_transition_count_none(self) -> None:
        snap = self._make_snapshot(state_machine=None)
        assert snap.transition_count == 0

    def test_transition_count_with_state_machine(self) -> None:
        sm = _FakeStateMachine(
            state_constants=set(),
            handlers={},
            transitions=["t1", "t2"],
        )
        snap = self._make_snapshot(state_machine=sm)
        assert snap.transition_count == 2

    def test_unresolved_transition_count(self) -> None:
        sm = _FakeStateMachine(
            state_constants=set(),
            handlers={},
            transitions=["t1", "t2", "t3", "t4"],
        )
        snap = self._make_snapshot(
            state_machine=sm,
            resolved_transitions=frozenset({(1, 2), (3, 4)}),
        )
        assert snap.unresolved_transition_count == 2

    def test_defaults(self) -> None:
        snap = self._make_snapshot()
        assert snap.bst_result is None
        assert snap.bst_dispatcher_serial == -1
        assert snap.handler_graph == {}
        assert snap.reachability is None
        assert snap.maturity == 0
        assert snap.pass_number == 0
        assert snap.resolved_transitions == frozenset()
        assert snap.initial_transitions == ()
        assert snap.dispatcher_cache is None
        assert snap.flow_graph is None

    def test_frozen(self) -> None:
        snap = self._make_snapshot()
        with pytest.raises((AttributeError, TypeError)):
            snap.maturity = 99  # type: ignore[misc]

    def test_reachability_integration(self) -> None:
        ri = ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset({0, 1, 2}),
            total_blocks=6,
        )
        snap = self._make_snapshot(reachability=ri)
        assert snap.reachability is ri
        assert snap.reachability.coverage == pytest.approx(0.5)
