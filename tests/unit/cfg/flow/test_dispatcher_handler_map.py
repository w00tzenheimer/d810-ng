"""Unit tests for DispatcherHandlerMap shared IR type."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.dispatcher_handler_map import DispatcherHandlerMap
from d810.analyses.control_flow.dispatcher_kind import DispatcherType


class TestDispatcherHandlerMap:
    """Construction and field invariants."""

    def _make_simple_map(self) -> DispatcherHandlerMap:
        """4-state OR-mask switch dispatcher (abc_or_dispatch shape)."""
        return DispatcherHandlerMap(
            handler_state_map={10: 0, 11: 1, 12: 2, 13: 3},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            source=DispatcherType.SWITCH_TABLE,
            initial_state=0,
        )

    def test_frozen(self):
        m = self._make_simple_map()
        with pytest.raises(AttributeError):
            m.dispatcher_serial = 99  # type: ignore[misc]

    def test_handler_state_map_contents(self):
        m = self._make_simple_map()
        assert m.handler_state_map == {10: 0, 11: 1, 12: 2, 13: 3}
        assert m.source == DispatcherType.SWITCH_TABLE

    def test_initial_state(self):
        m = self._make_simple_map()
        assert m.initial_state == 0


class TestResolveTarget:
    """Target resolution from state values."""

    def _make_map(self) -> DispatcherHandlerMap:
        return DispatcherHandlerMap(
            handler_state_map={10: 0, 11: 1, 12: 2, 13: 3},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            source=DispatcherType.SWITCH_TABLE,
        )

    def test_exact_match(self):
        m = self._make_map()
        assert m.resolve_target(0) == 10
        assert m.resolve_target(1) == 11
        assert m.resolve_target(3) == 13

    def test_no_match_returns_none(self):
        m = self._make_map()
        assert m.resolve_target(99) is None

    def test_range_fallback(self):
        m = DispatcherHandlerMap(
            handler_state_map={10: 0x100, 11: 0x200},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            source=DispatcherType.CONDITIONAL_CHAIN,
            handler_range_map={12: (0x300, 0x400)},
        )
        assert m.resolve_target(0x350) == 12

    def test_range_skips_exact_match_serials(self):
        """Range entries for serials that also have exact matches are skipped."""
        m = DispatcherHandlerMap(
            handler_state_map={10: 0x100},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            source=DispatcherType.CONDITIONAL_CHAIN,
            handler_range_map={10: (0, 0xFFFFFFFF)},
        )
        assert m.resolve_target(0x100) == 10
        assert m.resolve_target(0x200) is None

    def test_catch_all_range_skipped(self):
        """Ranges spanning >= 0xFFFF0000 are treated as catch-all and skipped."""
        m = DispatcherHandlerMap(
            handler_state_map={10: 0x100},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            source=DispatcherType.CONDITIONAL_CHAIN,
            handler_range_map={11: (0, 0xFFFFFFFF)},
        )
        assert m.resolve_target(0x500) is None


class TestFromBstResult:
    """Bridge from BSTAnalysisResult."""

    def test_round_trip_fields(self):
        from d810.analyses.control_flow.bst_model import BSTAnalysisResult, BSTNodeMap

        node_map = BSTNodeMap()
        node_map.add(5)
        node_map.add(6)
        bst = BSTAnalysisResult(
            handler_state_map={10: 0xAABB, 11: 0xCCDD},
            handler_range_map={12: (0x1000, 0x2000)},
            bst_node_blocks=node_map,
            initial_state=0xAABB,
        )
        m = DispatcherHandlerMap.from_bst_result(
            bst, dispatcher_serial=5, state_var_stkoff=0x3C,
        )
        assert m.handler_state_map == {10: 0xAABB, 11: 0xCCDD}
        assert m.handler_range_map == {12: (0x1000, 0x2000)}
        assert m.dispatcher_serial == 5
        assert m.dispatcher_blocks == frozenset({5, 6})
        assert m.state_var_stkoff == 0x3C
        assert m.source == DispatcherType.CONDITIONAL_CHAIN
        assert m.initial_state == 0xAABB


class TestToBstResult:
    """Synthesize BSTAnalysisResult for downstream consumers."""

    def test_synthetic_bst_has_handler_state_map(self):
        from d810.analyses.control_flow.bst_model import BSTAnalysisResult

        m = DispatcherHandlerMap(
            handler_state_map={10: 0, 11: 1, 12: 2},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5, 6}),
            state_var_stkoff=0x3C,
            source=DispatcherType.SWITCH_TABLE,
            initial_state=0,
        )
        bst = m.to_bst_result()
        assert isinstance(bst, BSTAnalysisResult)
        assert bst.handler_state_map == {10: 0, 11: 1, 12: 2}
        assert bst.initial_state == 0

    def test_synthetic_bst_node_blocks_iterable(self):
        m = DispatcherHandlerMap(
            handler_state_map={10: 0},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5, 6}),
            state_var_stkoff=0x3C,
            source=DispatcherType.SWITCH_TABLE,
        )
        bst = m.to_bst_result()
        assert set(bst.bst_node_blocks) == {5, 6}

    def test_synthetic_bst_defaults(self):
        m = DispatcherHandlerMap(
            handler_state_map={10: 0},
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            source=DispatcherType.SWITCH_TABLE,
        )
        bst = m.to_bst_result()
        assert bst.transitions == {}
        assert bst.conditional_transitions == {}
        assert bst.exits == set()
        assert bst.dispatcher is None
