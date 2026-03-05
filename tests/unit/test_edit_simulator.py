"""Unit tests for edit simulator (no IDA dependency)."""
import pytest

from d810.cfg.flow.edit_simulator import SimulatedEdit, simulate_edits


class TestSimulateEdits:
    def test_goto_redirect(self):
        """Single edge replacement via goto_redirect."""
        adj = {0: [1], 1: [2], 2: []}
        edits = [SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2)]
        result = simulate_edits(adj, edits)
        assert result[0] == [2]
        assert result[1] == [2]  # unchanged

    def test_conditional_redirect(self):
        """One of two edges replaced via conditional_redirect."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [SimulatedEdit(kind="conditional_redirect", source=0, old_target=2, new_target=3)]
        result = simulate_edits(adj, edits)
        assert result[0] == [1, 3]

    def test_convert_to_goto(self):
        """Both edges become single target via convert_to_goto."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [SimulatedEdit(kind="convert_to_goto", source=0, old_target=1, new_target=3)]
        result = simulate_edits(adj, edits)
        assert result[0] == [3]

    def test_no_mutation(self):
        """Original adj unchanged after simulate."""
        adj = {0: [1], 1: [2], 2: []}
        original_copy = {0: [1], 1: [2], 2: []}
        edits = [SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2)]
        simulate_edits(adj, edits)
        assert adj == original_copy

    def test_chained_edits(self):
        """Two edits applied sequentially."""
        adj = {0: [1], 1: [2], 2: [3], 3: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2),
            SimulatedEdit(kind="goto_redirect", source=1, old_target=2, new_target=3),
        ]
        result = simulate_edits(adj, edits)
        assert result[0] == [2]
        assert result[1] == [3]

    def test_edge_split_redirect_no_via_pred(self):
        """edge_split_redirect without via_pred uses conservative fallback (append)."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [SimulatedEdit(kind="edge_split_redirect", source=0, old_target=1, new_target=3)]
        result = simulate_edits(adj, edits)
        assert 3 in result[0]
        # Original successors preserved, new_target appended
        assert 1 in result[0]

    def test_edge_split_redirect_no_via_pred_dedup(self):
        """edge_split_redirect fallback does not duplicate existing target."""
        adj = {0: [1, 3], 1: [], 3: []}
        edits = [SimulatedEdit(kind="edge_split_redirect", source=0, old_target=1, new_target=3)]
        result = simulate_edits(adj, edits)
        assert result[0].count(3) == 1  # no duplicate

    def test_edge_split_with_clone(self):
        """Edge split creates virtual clone node."""
        # Original: 0->1->2, via_pred=0
        adj = {0: [1], 1: [2], 2: []}
        edits = [SimulatedEdit(
            kind="edge_split_redirect",
            source=1, old_target=2, new_target=5,
            via_pred=0,
        )]
        result = simulate_edits(adj, edits)
        # Clone node created (serial 3 = max(2)+1)
        clone = max(result.keys())
        assert clone > 2  # new node
        assert result[clone] == [5]  # clone -> new_target
        assert clone in result[0]  # via_pred rewired to clone
        assert result[1] == [2]  # original source unchanged

    def test_edge_split_clone_via_pred_partial_rewire(self):
        """Edge split only rewires the source edge in via_pred, not others."""
        # via_pred 0 has two successors: [1, 3]
        adj = {0: [1, 3], 1: [2], 2: [], 3: []}
        edits = [SimulatedEdit(
            kind="edge_split_redirect",
            source=1, old_target=2, new_target=5,
            via_pred=0,
        )]
        result = simulate_edits(adj, edits)
        clone = max(result.keys())
        # via_pred[0] should have [clone, 3] — only source=1 replaced
        assert clone in result[0]
        assert 3 in result[0]
        assert 1 not in result[0]

    def test_edge_split_clone_cycle_detection(self):
        """Edge split clone that creates cycle is detectable."""
        # 0(disp)->1(handler)->2(exit)->3(stop, nsucc=0)
        # Edge split: src=2, via_pred=1, old=3, new=1 (back to handler!)
        adj = {0: [1], 1: [2], 2: [3], 3: []}
        edits = [SimulatedEdit(
            kind="edge_split_redirect",
            source=2, old_target=3, new_target=1,
            via_pred=1,
        )]
        result = simulate_edits(adj, edits)
        clone = max(result.keys())
        # Clone -> 1 (handler), creating cycle
        assert result[clone] == [1]
        # detect_terminal_cycles should find this
        from d810.cfg.flow.graph_checks import detect_terminal_cycles
        cycle_result = detect_terminal_cycles(
            result, terminal_exits={clone}, handler_entries={1}, dispatcher=0
        )
        assert not cycle_result.passed
