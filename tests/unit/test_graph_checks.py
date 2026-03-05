"""Unit tests for semantic graph checks (no IDA dependency)."""
import pytest

from d810.cfg.flow.graph_checks import (
    TerminalCycle,
    detect_terminal_cycles,
    SemanticCheckResult,
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
