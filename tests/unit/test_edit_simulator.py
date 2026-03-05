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

    def test_edge_split_redirect(self):
        """edge_split_redirect replaces old_target with new_target."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [SimulatedEdit(kind="edge_split_redirect", source=0, old_target=1, new_target=3)]
        result = simulate_edits(adj, edits)
        assert result[0] == [3, 2]

    def test_edge_split_redirect_missing_old_target(self):
        """edge_split_redirect appends when old_target not in successors."""
        adj = {0: [1], 1: []}
        edits = [SimulatedEdit(kind="edge_split_redirect", source=0, old_target=99, new_target=3)]
        result = simulate_edits(adj, edits)
        assert 3 in result[0]
