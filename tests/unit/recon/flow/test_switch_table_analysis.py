"""Unit tests for switch-table analysis pure-logic helpers."""
from __future__ import annotations

from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.switch_table_analysis import (
    build_state_dispatcher_map_from_cases,
)


class TestBuildStateDispatcherMapFromCases:
    """Test case-list to exact StateDispatcherMap conversion."""

    def test_simple_4_state(self):
        """abc_or_dispatch shape: 4 linear cases."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10, 1: 11, 2: 12, 3: 13}
        assert m.handler_state_map() == {10: 0, 11: 1, 12: 2, 13: 3}
        assert m.dispatcher_entry_block == 5
        assert m.dispatcher_blocks == frozenset({5})
        assert m.state_var_stkoff == 0x3C
        assert m.source == DispatcherType.SWITCH_TABLE

    def test_with_initial_state(self):
        cases = [(0, 10), (1, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            initial_state=0,
        )
        assert m.initial_state == 0

    def test_preserves_aliased_targets(self):
        """Multiple case values mapping to one target stay exact rows."""
        cases = [(0, 10), (1, 10), (2, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10, 1: 10, 2: 11}
        assert m.states_by_target() == {10: (0, 1), 11: (2,)}
        assert [row.row_kind for row in m.rows] == [
            "handler_alias",
            "handler_alias",
            "handler",
        ]
        # The old handler-map view is intentionally lossy; exact aliases live
        # in StateDispatcherMap.rows.
        assert m.to_dispatcher_handler_map().handler_state_map == {10: 0, 11: 2}

    def test_preserves_self_loop_targets(self):
        """Cases targeting the dispatcher itself are exact self-loop rows."""
        cases = [(0, 10), (1, 5), (2, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(1) == 5
        assert m.rows[1].is_dispatcher_self_loop
        assert m.handler_state_map() == {10: 0, 11: 2}

    def test_empty_cases(self):
        m = build_state_dispatcher_map_from_cases(
            cases=[],
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.rows == ()
        assert m.handler_state_map() == {}

    def test_resolve_target_works(self):
        """End-to-end: build map then resolve targets."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(0) == 10
        assert m.resolve_target(2) == 12
        assert m.resolve_target(99) is None

    def test_records_default_target_separately(self):
        cases = [(0, 10), (None, 99)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10}
        assert m.default_target_block == 99
        assert m.default_row_kind == "dispatcher_default"
