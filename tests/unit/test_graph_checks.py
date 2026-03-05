"""Unit tests for semantic graph checks (no IDA dependency)."""
from types import SimpleNamespace

import pytest

from d810.cfg.flow.edit_simulator import SimulatedEdit, simulate_edits
from d810.cfg.flow.graph_checks import (
    TerminalCycle,
    TerminalSinkResult,
    detect_terminal_cycles,
    prove_terminal_sink,
    SemanticCheckResult,
    SemanticGate,
    check_edge_split_structural_legality,
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

    def test_terminal_target_with_preexisting_backedge(self):
        """Terminal redirect target has pre-existing edge to handler entry."""
        # Handler exit (blk[5]) redirected to terminal target (blk[219])
        # blk[219] has pre-existing edge back to handler entry (blk[180])
        adj = _make_adj([
            (0, 1), (1, 2), (2, 5),  # handler chain
            (5, 219),   # terminal redirect
            (219, 180),  # pre-existing back-edge to handler entry
            (180, 181),  # handler 180's body
        ])
        handler_entries = {1, 2, 5, 180}
        # terminal_exits must include BOTH source (5) AND target (219)
        terminal_exits = {5, 219}
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert not result.passed
        assert any(c.terminal_block == 219 and c.reentry_target == 180 for c in result.cycles)

    def test_multiple_terminals_mixed(self):
        # Terminal A is clean, terminal B cycles
        adj = _make_adj([(0, 1), (1, 2), (2, 5), (0, 3), (3, 4), (4, 0)])
        handler_entries = {1, 2, 3, 4}
        terminal_exits = {5, 4}  # 5 clean (no succs), 4 cycles
        dispatcher = 0
        result = detect_terminal_cycles(adj, terminal_exits, handler_entries, dispatcher)
        assert not result.passed
        assert len(result.cycles) == 1


class TestProveTerminalSink:
    def test_clean_sink(self):
        # start -> intermediate -> exit (0 succs). PASS.
        adj = _make_adj([(10, 11), (11, 12)])
        # 12 has no outgoing edges — it's an exit
        exits = {12}
        forbidden = {0, 1, 2}
        result = prove_terminal_sink(10, adj, exits, forbidden)
        assert result.ok
        assert result.reaches_exit
        assert not result.reaches_forbidden
        assert not result.has_nonexit_cycle

    def test_reaches_forbidden(self):
        # start -> handler_entry. FAIL, reaches_forbidden=True.
        adj = _make_adj([(10, 1)])
        exits = {99}
        forbidden = {1, 2, 3}
        result = prove_terminal_sink(10, adj, exits, forbidden)
        assert not result.ok
        assert result.reaches_forbidden
        assert result.reason == "reaches forbidden block"
        assert 1 in result.witness_path

    def test_no_exit(self):
        # start -> A -> B (no exit reachable). FAIL, reaches_exit=False.
        adj = _make_adj([(10, 11), (11, 12)])
        exits = {99}  # unreachable exit
        forbidden = set()
        result = prove_terminal_sink(10, adj, exits, forbidden)
        assert not result.ok
        assert not result.reaches_exit
        assert result.reason == "no exit reachable"

    def test_cycle_in_subgraph(self):
        # start -> A -> B -> A (cycle, no exit). FAIL.
        adj: dict[int, list[int]] = {10: [11], 11: [12], 12: [11, 99]}
        exits = {99}
        forbidden = set()
        result = prove_terminal_sink(10, adj, exits, forbidden)
        assert not result.ok
        assert result.has_nonexit_cycle
        assert result.reason == "cycle in non-exit subgraph"

    def test_mixed_paths_forbidden_priority(self):
        # start -> exit AND start -> forbidden. FAIL (forbidden takes priority).
        adj: dict[int, list[int]] = {10: [99, 1], 99: [], 1: []}
        exits = {99}
        forbidden = {1}
        result = prove_terminal_sink(10, adj, exits, forbidden)
        assert not result.ok
        assert result.reaches_forbidden

    def test_start_is_forbidden(self):
        # start itself is in forbidden set. FAIL immediately.
        adj: dict[int, list[int]] = {180: [219], 219: []}
        exits = {219}
        forbidden = {180}
        result = prove_terminal_sink(180, adj, exits, forbidden)
        assert not result.ok
        assert result.reaches_forbidden
        assert result.reason == "start block is forbidden"


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


class TestPreflightCycleRejection:
    """End-to-end preflight: simulate_edits + detect_terminal_cycles catches cycles."""

    def test_redirect_creates_cycle_detected(self):
        # Handler entries: 10, 20. Dispatcher: 0. Terminal exit: 30.
        # Graph: 0->10, 10->20, 20->30, 30->99 (exit).
        # Bad edit: redirect 30->10 (terminal re-enters handler).
        adj = _make_adj([(0, 10), (10, 20), (20, 30), (30, 99)])
        bad_edit = SimulatedEdit(
            kind="goto_redirect", source=30, old_target=99, new_target=10,
        )
        sim_adj = simulate_edits(adj, [bad_edit]).adj
        result = detect_terminal_cycles(
            sim_adj,
            terminal_exits={30},
            handler_entries={10, 20},
            dispatcher=0,
        )
        assert not result.passed
        assert any(c.reentry_target == 10 for c in result.cycles)

    def test_clean_redirect_no_cycle(self):
        # Redirect terminal to a true exit — no cycle.
        adj = _make_adj([(0, 10), (10, 20), (20, 30), (30, 0)])
        adj[99] = []  # true exit node with 0 successors
        good_edit = SimulatedEdit(
            kind="goto_redirect", source=30, old_target=0, new_target=99,
        )
        sim_adj = simulate_edits(adj, [good_edit]).adj
        result = detect_terminal_cycles(
            sim_adj,
            terminal_exits={30},
            handler_entries={10, 20},
            dispatcher=0,
        )
        assert result.passed


class TestEdgeSplitStructuralLegality:
    def test_valid_edge_split_passes(self):
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=2,
                new_target=5,
                via_pred=0,
            )
        ]
        result = check_edge_split_structural_legality(adj, edits)
        assert result.passed

    def test_via_pred_must_be_one_way(self):
        adj = {0: [1, 9], 1: [2], 2: [], 9: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=2,
                new_target=5,
                via_pred=0,
            )
        ]
        result = check_edge_split_structural_legality(adj, edits)
        assert not result.passed
        assert "predecessor must be 1-way" in result.reason

    def test_old_target_must_match_source_successor(self):
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=99,
                new_target=5,
                via_pred=0,
            )
        ]
        result = check_edge_split_structural_legality(adj, edits)
        assert not result.passed
        assert "old_target mismatch" in result.reason
