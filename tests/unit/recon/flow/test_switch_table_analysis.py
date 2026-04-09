"""Unit tests for switch-table analysis pure-logic helpers."""
from __future__ import annotations

import pytest

from d810.recon.flow.switch_table_analysis import build_handler_map_from_cases
from d810.recon.flow.dispatcher_detection import DispatcherType


class TestBuildHandlerMapFromCases:
    """Test case-list to DispatcherHandlerMap conversion."""

    def test_simple_4_state(self):
        """abc_or_dispatch shape: 4 linear cases."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_handler_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.handler_state_map == {10: 0, 11: 1, 12: 2, 13: 3}
        assert m.dispatcher_serial == 5
        assert m.dispatcher_blocks == frozenset({5})
        assert m.state_var_stkoff == 0x3C
        assert m.source == DispatcherType.SWITCH_TABLE

    def test_with_initial_state(self):
        cases = [(0, 10), (1, 11)]
        m = build_handler_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            initial_state=0,
        )
        assert m.initial_state == 0

    def test_rejects_aliased_targets(self):
        """Multiple case values mapping to same target are rejected (Phase 2)."""
        cases = [(0, 10), (1, 10), (2, 11)]
        m = build_handler_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m is None

    def test_skips_self_loop_targets(self):
        """Cases targeting the dispatcher itself are self-loops and skipped."""
        cases = [(0, 10), (1, 5), (2, 11)]
        m = build_handler_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert 5 not in m.handler_state_map
        assert m.handler_state_map == {10: 0, 11: 2}

    def test_empty_cases(self):
        m = build_handler_map_from_cases(
            cases=[],
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.handler_state_map == {}

    def test_resolve_target_works(self):
        """End-to-end: build map then resolve targets."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_handler_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(0) == 10
        assert m.resolve_target(2) == 12
        assert m.resolve_target(99) is None
