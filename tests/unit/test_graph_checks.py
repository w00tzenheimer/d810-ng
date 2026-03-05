"""Unit tests for semantic graph checks (no IDA dependency)."""
from types import SimpleNamespace

import pytest

from d810.cfg.flow.graph_checks import (
    TerminalCycle,
    detect_terminal_cycles,
    SemanticCheckResult,
    SemanticGate,
)


def _make_adj(edges: list[tuple[int, int]]) -> dict[int, list[int]]:
    """Build adjacency list from edge tuples."""
    adj: dict[int, list[int]] = {}
    for u, v in edges:
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, [])  # ensure all nodes present
    return adj


class TestDetectTerminalCycles:
    def test_clean_linear_no_cycle(self):
        # 0 -> 1 -> 2 -> 3(terminal exit) -> 4(m_ret, 0 succs)
        adj = _make_adj([(0, 1), (1, 2), (2, 3), (3, 4)])
        handler_entries = {1, 2, 3}
        terminal_exits = {4}  # block 4 has 0 successors — true terminal
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert result.passed
        assert result.cycles == []

    def test_terminal_reenter_dispatcher(self):
        # 0 -> 1 -> 2 -> 3(terminal) -> 0  (cycle back to dispatcher)
        adj = _make_adj([(0, 1), (1, 2), (2, 3), (3, 0)])
        handler_entries = {1, 2, 3}
        terminal_exits = {3}
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert not result.passed
        assert len(result.cycles) == 1
        assert result.cycles[0].terminal_block == 3
        assert result.cycles[0].reentry_target == 0

    def test_terminal_reenter_handler(self):
        # Terminal block loops back to a handler entry
        adj = _make_adj([(0, 1), (1, 2), (2, 3), (3, 1)])
        handler_entries = {1, 2, 3}
        terminal_exits = {3}
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert not result.passed
        assert result.cycles[0].reentry_target == 1

    def test_true_terminal_zero_succs_ignored(self):
        # Block 4 has 0 successors — NOT in adj as source. Should pass.
        adj = _make_adj([(0, 1), (1, 2), (2, 3), (3, 4)])
        # 4 has no outgoing edges
        handler_entries = {1, 2, 3}
        terminal_exits = {4}
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert result.passed

    def test_multiple_terminals_mixed(self):
        # Terminal A is clean, terminal B cycles
        adj = _make_adj([(0, 1), (1, 2), (2, 5), (0, 3), (3, 4), (4, 0)])
        handler_entries = {1, 2, 3, 4}
        terminal_exits = {5, 4}  # 5 clean (no succs), 4 cycles
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert not result.passed
        assert len(result.cycles) == 1


def _fake_result(**kwargs):
    """Build a duck-typed StageResult for SemanticGate testing."""
    defaults = {
        "strategy_name": "test",
        "edits_applied": 10,
        "terminal_cycles": [],
        "conflict_count_after": 0,
        "reachability_after": 1.0,
        "handler_reachability": 1.0,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestSemanticGate:
    def test_passes_clean_graph(self):
        gate = SemanticGate()
        result = _fake_result()
        assert gate.check(result)

    def test_fails_on_terminal_cycle(self):
        gate = SemanticGate()
        cycle = TerminalCycle(terminal_block=5, reentry_target=0)
        result = _fake_result(terminal_cycles=[cycle])
        assert not gate.check(result)

    def test_fails_on_excessive_conflicts(self):
        gate = SemanticGate(max_conflict_count=5)
        result = _fake_result(conflict_count_after=6)
        assert not gate.check(result)

    def test_ignores_low_block_reachability(self):
        """Block reachability is diagnostic only -- does NOT fail gate."""
        gate = SemanticGate()
        result = _fake_result(reachability_after=0.1)
        assert gate.check(result)
