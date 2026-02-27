"""Unit tests for TransitionBuilder and _convert_bst_to_result.

These tests exercise pure logic only — no IDA imports, no mocking of IDA APIs.
The module under test uses try/except ImportError stubs for StateTransition and
StateHandler, so everything works without IDA present.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import Optional

import pytest

from d810.hexrays.bst_analysis import BSTAnalysisResult
from d810.optimizers.microcode.flow.flattening.transition_builder import (
    TransitionBuilder,
    TransitionResult,
    _convert_bst_to_result,
)


# ---------------------------------------------------------------------------
# _convert_bst_to_result — unconditional transitions
# ---------------------------------------------------------------------------


class TestConvertBstToResultUnconditional:
    def _make_bst(self) -> BSTAnalysisResult:
        return BSTAnalysisResult(
            handler_state_map={10: 100, 20: 200, 30: 300},
            handler_range_map={10: (0, 50), 20: (50, 100), 30: (100, 150)},
            transitions={100: 200, 200: 300, 300: None},
            conditional_transitions={},
            exits={300},
            pre_header_serial=5,
            initial_state=100,
        )

    def test_returns_transition_result(self):
        result = _convert_bst_to_result(self._make_bst())
        assert isinstance(result, TransitionResult)

    def test_strategy_name_is_bst_walker(self):
        result = _convert_bst_to_result(self._make_bst())
        assert result.strategy_name == "bst_walker"

    def test_pre_header_serial_passed_through(self):
        result = _convert_bst_to_result(self._make_bst())
        assert result.pre_header_serial == 5

    def test_initial_state_passed_through(self):
        result = _convert_bst_to_result(self._make_bst())
        assert result.initial_state == 100

    def test_none_transition_skipped(self):
        # state 300 -> None, should not produce a StateTransition
        result = _convert_bst_to_result(self._make_bst())
        to_states = {t.to_state for t in result.transitions}
        assert None not in to_states

    def test_resolved_count_excludes_none(self):
        # 100->200 and 200->300 are resolved; 300->None is skipped → 2
        result = _convert_bst_to_result(self._make_bst())
        assert result.resolved_count == 2

    def test_transitions_correct_from_state_and_to_state(self):
        result = _convert_bst_to_result(self._make_bst())
        pairs = {(t.from_state, t.to_state) for t in result.transitions}
        assert (100, 200) in pairs
        assert (200, 300) in pairs

    def test_transition_from_block_is_handler_serial(self):
        result = _convert_bst_to_result(self._make_bst())
        t100 = next(t for t in result.transitions if t.from_state == 100)
        # handler_state_map: blk 10 -> state 100, so from_block should be 10
        assert t100.from_block == 10

    def test_unconditional_transitions_not_flagged(self):
        result = _convert_bst_to_result(self._make_bst())
        for t in result.transitions:
            assert t.is_conditional is False

    def test_handlers_keyed_by_state(self):
        result = _convert_bst_to_result(self._make_bst())
        assert set(result.handlers.keys()) == {100, 200, 300}

    def test_handler_state_value(self):
        result = _convert_bst_to_result(self._make_bst())
        assert result.handlers[100].state_value == 100
        assert result.handlers[200].state_value == 200

    def test_handler_blocks_contains_serial(self):
        result = _convert_bst_to_result(self._make_bst())
        # blk 10 maps to state 100
        assert result.handlers[100].handler_blocks == [10]

    def test_handler_transitions_populated(self):
        result = _convert_bst_to_result(self._make_bst())
        # handler 100 has one outgoing transition: 100->200
        assert len(result.handlers[100].transitions) == 1
        assert result.handlers[100].transitions[0].to_state == 200

    def test_assignment_map_is_empty(self):
        result = _convert_bst_to_result(self._make_bst())
        assert result.assignment_map == {}


# ---------------------------------------------------------------------------
# _convert_bst_to_result — conditional transitions
# ---------------------------------------------------------------------------


class TestConvertBstToResultConditional:
    def _make_bst(self) -> BSTAnalysisResult:
        return BSTAnalysisResult(
            handler_state_map={10: 100, 20: 200, 30: 300},
            handler_range_map={},
            transitions={100: None},  # unconditional unknown
            conditional_transitions={100: {200, 300}},
            exits=set(),
            pre_header_serial=5,
            initial_state=100,
        )

    def test_produces_two_conditional_transitions(self):
        result = _convert_bst_to_result(self._make_bst())
        # 100->None (skipped), 100->200 (conditional), 100->300 (conditional)
        assert len(result.transitions) == 2

    def test_all_transitions_marked_conditional(self):
        result = _convert_bst_to_result(self._make_bst())
        for t in result.transitions:
            assert t.is_conditional is True

    def test_both_from_state_100(self):
        result = _convert_bst_to_result(self._make_bst())
        assert all(t.from_state == 100 for t in result.transitions)

    def test_to_states_are_200_and_300(self):
        result = _convert_bst_to_result(self._make_bst())
        to_states = {t.to_state for t in result.transitions}
        assert to_states == {200, 300}

    def test_condition_block_equals_from_block(self):
        result = _convert_bst_to_result(self._make_bst())
        for t in result.transitions:
            assert t.condition_block == t.from_block

    def test_handler_100_has_two_transitions(self):
        result = _convert_bst_to_result(self._make_bst())
        assert len(result.handlers[100].transitions) == 2

    def test_resolved_count_counts_conditional(self):
        result = _convert_bst_to_result(self._make_bst())
        assert result.resolved_count == 2


# ---------------------------------------------------------------------------
# _convert_bst_to_result — edge / empty cases
# ---------------------------------------------------------------------------


class TestConvertBstToResultEdgeCases:
    def test_empty_bst(self):
        bst = BSTAnalysisResult(
            handler_state_map={},
            handler_range_map={},
            transitions={},
            conditional_transitions={},
            exits=set(),
            pre_header_serial=None,
            initial_state=None,
        )
        result = _convert_bst_to_result(bst)
        assert result.transitions == []
        assert result.handlers == {}
        assert result.resolved_count == 0
        assert result.initial_state is None
        assert result.pre_header_serial is None

    def test_single_handler_no_transitions(self):
        bst = BSTAnalysisResult(
            handler_state_map={7: 42},
            handler_range_map={},
            transitions={},
            conditional_transitions={},
            exits=set(),
            pre_header_serial=None,
            initial_state=42,
        )
        result = _convert_bst_to_result(bst)
        assert result.handlers == {42: result.handlers[42]}
        assert result.handlers[42].state_value == 42
        assert result.handlers[42].handler_blocks == [7]
        assert result.transitions == []
        assert result.resolved_count == 0

    def test_all_transitions_none(self):
        bst = BSTAnalysisResult(
            handler_state_map={10: 100, 20: 200},
            handler_range_map={},
            transitions={100: None, 200: None},
            conditional_transitions={},
            exits=set(),
            pre_header_serial=3,
            initial_state=100,
        )
        result = _convert_bst_to_result(bst)
        assert result.transitions == []
        assert result.resolved_count == 0

    def test_transition_from_state_missing_in_handler_map_skipped(self):
        # from_state 999 has no matching blk in handler_state_map
        bst = BSTAnalysisResult(
            handler_state_map={10: 100},
            handler_range_map={},
            transitions={999: 100},  # 999 not in handler_state_map
            conditional_transitions={},
            exits=set(),
            pre_header_serial=None,
            initial_state=None,
        )
        result = _convert_bst_to_result(bst)
        assert result.transitions == []
        assert result.resolved_count == 0


# ---------------------------------------------------------------------------
# TransitionBuilder selection logic
# ---------------------------------------------------------------------------


class _StubStrategy:
    """Simple strategy stub for testing TransitionBuilder selection."""

    def __init__(self, name: str, result: Optional[TransitionResult]) -> None:
        self._name = name
        self._result = result
        self.build_call_count = 0

    @property
    def name(self) -> str:
        return self._name

    def build(self, mba, detector):
        self.build_call_count += 1
        return self._result


class TestTransitionBuilderSelection:
    def _make_strategy(self, name: str, result: Optional[TransitionResult]):
        """Create a minimal stub strategy."""
        return _StubStrategy(name=name, result=result)

    def test_picks_strategy_with_highest_resolved_count(self):
        low = TransitionResult(resolved_count=3, strategy_name="low")
        high = TransitionResult(resolved_count=7, strategy_name="high")
        s1 = self._make_strategy("s1", low)
        s2 = self._make_strategy("s2", high)
        builder = TransitionBuilder(strategies=[s1, s2])
        result = builder.build(mba=None, detector=None)
        assert result.resolved_count == 7

    def test_skips_none_returning_strategy(self):
        good = TransitionResult(resolved_count=5, strategy_name="good")
        s_none = self._make_strategy("none_strategy", None)
        s_good = self._make_strategy("good_strategy", good)
        builder = TransitionBuilder(strategies=[s_none, s_good])
        result = builder.build(mba=None, detector=None)
        assert result is not None
        assert result.resolved_count == 5

    def test_returns_none_when_all_strategies_return_none(self):
        s1 = self._make_strategy("s1", None)
        s2 = self._make_strategy("s2", None)
        builder = TransitionBuilder(strategies=[s1, s2])
        result = builder.build(mba=None, detector=None)
        assert result is None

    def test_returns_none_when_all_single_strategy_returns_none(self):
        # TransitionBuilder(strategies=[]) uses the default list (falsy empty
        # list triggers the `or` fallback), so test "all None" via one strategy.
        s = self._make_strategy("only_none", None)
        builder = TransitionBuilder(strategies=[s])
        result = builder.build(mba=None, detector=None)
        assert result is None

    def test_single_strategy_returned_directly(self):
        only = TransitionResult(resolved_count=1, strategy_name="only")
        s = self._make_strategy("s", only)
        builder = TransitionBuilder(strategies=[s])
        result = builder.build(mba=None, detector=None)
        assert result is only

    def test_tie_returns_one_of_them(self):
        r1 = TransitionResult(resolved_count=4, strategy_name="r1")
        r2 = TransitionResult(resolved_count=4, strategy_name="r2")
        s1 = self._make_strategy("s1", r1)
        s2 = self._make_strategy("s2", r2)
        builder = TransitionBuilder(strategies=[s1, s2])
        result = builder.build(mba=None, detector=None)
        # Either is acceptable; just confirm we got one of them with count==4
        assert result.resolved_count == 4

    def test_all_strategies_are_called(self):
        r1 = TransitionResult(resolved_count=1, strategy_name="r1")
        r2 = TransitionResult(resolved_count=2, strategy_name="r2")
        s1 = self._make_strategy("s1", r1)
        s2 = self._make_strategy("s2", r2)
        builder = TransitionBuilder(strategies=[s1, s2])
        builder.build(mba=None, detector=None)
        assert s1.build_call_count == 1
        assert s2.build_call_count == 1

    def test_default_strategies_instantiated(self):
        from d810.optimizers.microcode.flow.flattening.transition_builder import (
            BFSWithMopTrackerStrategy,
            BSTWalkerStrategy,
        )

        builder = TransitionBuilder()
        assert len(builder.strategies) == 2
        assert isinstance(builder.strategies[0], BSTWalkerStrategy)
        assert isinstance(builder.strategies[1], BFSWithMopTrackerStrategy)
