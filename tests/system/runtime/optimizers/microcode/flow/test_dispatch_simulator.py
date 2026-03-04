"""Unit tests for dispatch table simulation and transition graph reconstruction.

Tests the DispatchSimulator service with synthetic dispatch tables and state
writes representing OLLVM-style control-flow flattening patterns.

No IDA runtime required - operates on abstract types.
"""

from __future__ import annotations

import pytest

from d810.cfg.flow.compare_chain import (
    CompareEntry,
    DispatchTable,
)
from d810.cfg.flow.dispatch_simulator import (
    CaseTransition,
    DispatchSimulator,
    TransitionGraph,
)


class TestCaseTransition:
    """Test CaseTransition dataclass validation and representation."""

    def test_valid_transition(self) -> None:
        """Valid transition should construct without errors."""
        trans = CaseTransition(10, 0x42, 20)
        assert trans.from_serial == 10
        assert trans.assigned_value == 0x42
        assert trans.to_serial == 20

    def test_transition_repr_hex_formatting(self) -> None:
        """Repr should format assigned_value in hex."""
        trans = CaseTransition(10, 0x42, 20)
        repr_str = repr(trans)
        assert "0x42" in repr_str
        assert "10" in repr_str
        assert "20" in repr_str

    def test_negative_from_serial_raises(self) -> None:
        """Negative from_serial should raise ValueError."""
        with pytest.raises(ValueError, match="from_serial must be non-negative"):
            CaseTransition(-1, 0x42, 20)

    def test_negative_to_serial_raises(self) -> None:
        """Negative to_serial should raise ValueError."""
        with pytest.raises(ValueError, match="to_serial must be non-negative"):
            CaseTransition(10, 0x42, -1)

    def test_zero_serials_allowed(self) -> None:
        """Zero serials should be allowed (valid block numbers)."""
        trans = CaseTransition(0, 0x42, 0)
        assert trans.from_serial == 0
        assert trans.to_serial == 0

    def test_transition_is_immutable(self) -> None:
        """CaseTransition should be immutable (frozen dataclass)."""
        trans = CaseTransition(10, 0x42, 20)
        with pytest.raises(AttributeError):
            trans.from_serial = 99


class TestTransitionGraph:
    """Test TransitionGraph dataclass validation and methods."""

    def test_valid_graph(self) -> None:
        """Valid graph should construct without errors."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
        )
        graph = TransitionGraph(transitions, unresolved=())
        assert len(graph) == 2
        assert len(graph.unresolved) == 0

    def test_graph_with_unresolved(self) -> None:
        """Graph with unresolved writes should track them."""
        transitions = (CaseTransition(10, 0x42, 20),)
        unresolved = ((10, 0x999), (20, 0xAAA))
        graph = TransitionGraph(transitions, unresolved)
        assert len(graph) == 1
        assert len(graph.unresolved) == 2
        assert (10, 0x999) in graph.unresolved

    def test_as_edge_dict_simple(self) -> None:
        """as_edge_dict should produce adjacency dictionary."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
        )
        graph = TransitionGraph(transitions, ())
        edges = graph.as_edge_dict()
        assert edges[10] == {20}
        assert edges[20] == {30}

    def test_as_edge_dict_multiple_targets(self) -> None:
        """as_edge_dict should collect multiple targets per source."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(10, 0x100, 30),
            CaseTransition(10, 0x200, 40),
        )
        graph = TransitionGraph(transitions, ())
        edges = graph.as_edge_dict()
        assert edges[10] == {20, 30, 40}

    def test_as_edge_dict_empty(self) -> None:
        """as_edge_dict on empty graph should return empty dict."""
        graph = TransitionGraph((), ())
        edges = graph.as_edge_dict()
        assert edges == {}

    def test_for_case_filters_correctly(self) -> None:
        """for_case should return only transitions from specified case."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(10, 0x100, 30),
            CaseTransition(20, 0x200, 40),
        )
        graph = TransitionGraph(transitions, ())
        case_10_trans = graph.for_case(10)
        assert len(case_10_trans) == 2
        assert all(t.from_serial == 10 for t in case_10_trans)

    def test_for_case_no_matches(self) -> None:
        """for_case with no matches should return empty tuple."""
        transitions = (CaseTransition(10, 0x42, 20),)
        graph = TransitionGraph(transitions, ())
        assert graph.for_case(99) == ()

    def test_len_returns_transition_count(self) -> None:
        """len() should return number of transitions."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
            CaseTransition(30, 0x200, 40),
        )
        graph = TransitionGraph(transitions, ())
        assert len(graph) == 3

    def test_len_empty_graph(self) -> None:
        """len() on empty graph should return 0."""
        graph = TransitionGraph((), ())
        assert len(graph) == 0

    def test_invalid_transition_raises(self) -> None:
        """Non-CaseTransition in transitions should raise ValueError."""
        with pytest.raises(ValueError, match="All transitions must be CaseTransition"):
            TransitionGraph((10, 20, 30), ())  # type: ignore

    def test_graph_is_immutable(self) -> None:
        """TransitionGraph should be immutable (frozen dataclass)."""
        graph = TransitionGraph((), ())
        with pytest.raises(AttributeError):
            graph.transitions = ()


class TestSimulateHappyPath:
    """Test simulate() with valid inputs (happy path scenarios)."""

    def test_simple_linear_chain(self) -> None:
        """Simulate simple linear chain: A->B->C->A."""
        # Dispatch table: 0x42->20, 0x100->30, 0x200->10
        entries = (
            CompareEntry(0x42, 20, 1),
            CompareEntry(0x100, 30, 2),
            CompareEntry(0x200, 10, 3),
        )
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x42], 20: [0x100], 30: [0x200]}
        case_blocks = frozenset([10, 20, 30])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 3
        assert len(graph.unresolved) == 0
        edges = graph.as_edge_dict()
        assert edges[10] == {20}
        assert edges[20] == {30}
        assert edges[30] == {10}

    def test_single_case_single_write(self) -> None:
        """Simulate single case with single state write."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x42]}
        case_blocks = frozenset([10, 20])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 1
        assert graph.transitions[0] == CaseTransition(10, 0x42, 20)

    def test_case_with_multiple_writes(self) -> None:
        """Simulate case block that writes multiple state values."""
        entries = (
            CompareEntry(0x42, 20, 1),
            CompareEntry(0x100, 30, 2),
            CompareEntry(0x200, 40, 3),
        )
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x42, 0x100, 0x200]}  # Three writes from one case
        case_blocks = frozenset([10, 20, 30, 40])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 3
        case_10_trans = graph.for_case(10)
        assert len(case_10_trans) == 3
        targets = {t.to_serial for t in case_10_trans}
        assert targets == {20, 30, 40}

    def test_empty_case_blocks(self) -> None:
        """Simulate with empty case_blocks should produce empty graph."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x42]}
        case_blocks = frozenset()

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0
        assert len(graph.unresolved) == 0

    def test_case_with_no_writes(self) -> None:
        """Simulate case block with no state writes should produce no transitions."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {}  # No writes
        case_blocks = frozenset([10])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0


class TestSimulateWithUnresolved:
    """Test simulate() with unresolved state writes."""

    def test_unresolved_no_default(self) -> None:
        """State value not in table and no default should be unresolved."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x999]}  # 0x999 not in table
        case_blocks = frozenset([10])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0
        assert len(graph.unresolved) == 1
        assert graph.unresolved[0] == (10, 0x999)

    def test_mixed_resolved_and_unresolved(self) -> None:
        """Mix of resolved and unresolved writes."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x42, 0x999]}  # One resolved, one unresolved
        case_blocks = frozenset([10, 20])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 1
        assert graph.transitions[0].assigned_value == 0x42
        assert len(graph.unresolved) == 1
        assert graph.unresolved[0] == (10, 0x999)

    def test_multiple_cases_with_unresolved(self) -> None:
        """Multiple cases with unresolved writes."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x999], 20: [0xAAA]}
        case_blocks = frozenset([10, 20])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0
        assert len(graph.unresolved) == 2
        unresolved_set = set(graph.unresolved)
        assert (10, 0x999) in unresolved_set
        assert (20, 0xAAA) in unresolved_set


class TestSimulateWithDefault:
    """Test simulate() with default_serial fallback."""

    def test_fallback_to_default(self) -> None:
        """Unresolved value should fall back to default_serial."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=99)
        state_writes = {10: [0x999]}  # Not in table
        case_blocks = frozenset([10, 99])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 1
        assert graph.transitions[0] == CaseTransition(10, 0x999, 99)
        assert len(graph.unresolved) == 0

    def test_explicit_and_default_targets(self) -> None:
        """Mix of explicit dispatch and default fallback."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=99)
        state_writes = {10: [0x42, 0x999]}  # One explicit, one default
        case_blocks = frozenset([10, 20, 99])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 2
        trans_map = {t.assigned_value: t.to_serial for t in graph.transitions}
        assert trans_map[0x42] == 20
        assert trans_map[0x999] == 99




class TestSimulateEmptyInputs:
    """Test simulate() with various empty input combinations."""

    def test_empty_dispatch_table(self) -> None:
        """Empty dispatch table should produce no transitions."""
        table = DispatchTable((), default_serial=None)
        state_writes = {10: [0x42]}
        case_blocks = frozenset([10])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0
        assert len(graph.unresolved) == 1

    def test_empty_state_writes(self) -> None:
        """Empty state_writes should produce no transitions."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {}
        case_blocks = frozenset([10])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0
        assert len(graph.unresolved) == 0

    def test_all_empty_inputs(self) -> None:
        """All empty inputs should produce empty graph."""
        table = DispatchTable((), default_serial=None)
        state_writes = {}
        case_blocks = frozenset()

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 0
        assert len(graph.unresolved) == 0


class TestResolveTarget:
    """Test resolve_target() standalone function."""

    def test_simple_lookup(self) -> None:
        """Simple table lookup should return target."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)

        target = DispatchSimulator.resolve_target(table, 0x42)

        assert target == 20

    def test_lookup_not_found_no_default(self) -> None:
        """Value not in table with no default should return None."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)

        target = DispatchSimulator.resolve_target(table, 0x999)

        assert target is None

    def test_lookup_not_found_with_default(self) -> None:
        """Value not in table with default should return default."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=99)

        target = DispatchSimulator.resolve_target(table, 0x999)

        assert target == 99

    def test_empty_dispatch_table_no_default(self) -> None:
        """Empty dispatch table with no default should return None."""
        table = DispatchTable((), default_serial=None)

        target = DispatchSimulator.resolve_target(table, 0x42)

        assert target is None

    def test_empty_dispatch_table_with_default(self) -> None:
        """Empty dispatch table with default should return default."""
        table = DispatchTable((), default_serial=99)

        target = DispatchSimulator.resolve_target(table, 0x42)

        assert target == 99

    def test_zero_state_value_lookup(self) -> None:
        """State value of 0 should be handled correctly."""
        entries = (CompareEntry(0, 20, 1),)
        table = DispatchTable(entries, default_serial=None)

        target = DispatchSimulator.resolve_target(table, 0)

        assert target == 20


class TestFindSelfLoops:
    """Test find_self_loops() utility function."""

    def test_no_self_loops(self) -> None:
        """Graph with no self-loops should return empty set."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
        )
        graph = TransitionGraph(transitions, ())

        self_loops = DispatchSimulator.find_self_loops(graph)

        assert len(self_loops) == 0

    def test_single_self_loop(self) -> None:
        """Graph with one self-loop should detect it."""
        transitions = (
            CaseTransition(10, 0x42, 10),  # Self-loop
            CaseTransition(20, 0x100, 30),
        )
        graph = TransitionGraph(transitions, ())

        self_loops = DispatchSimulator.find_self_loops(graph)

        assert self_loops == frozenset({10})

    def test_multiple_self_loops(self) -> None:
        """Graph with multiple self-loops should detect all."""
        transitions = (
            CaseTransition(10, 0x42, 10),  # Self-loop
            CaseTransition(20, 0x100, 30),
            CaseTransition(30, 0x200, 30),  # Self-loop
        )
        graph = TransitionGraph(transitions, ())

        self_loops = DispatchSimulator.find_self_loops(graph)

        assert self_loops == frozenset({10, 30})

    def test_empty_graph_no_self_loops(self) -> None:
        """Empty graph should return empty set."""
        graph = TransitionGraph((), ())

        self_loops = DispatchSimulator.find_self_loops(graph)

        assert len(self_loops) == 0


class TestFindUnreachableCases:
    """Test find_unreachable_cases() reachability analysis."""

    def test_all_reachable_linear(self) -> None:
        """Linear chain from entry should have no unreachable cases."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
        )
        graph = TransitionGraph(transitions, ())

        unreachable = DispatchSimulator.find_unreachable_cases(graph, entry_serial=10)

        assert len(unreachable) == 0

    def test_unreachable_island(self) -> None:
        """Disconnected component should be unreachable."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
            CaseTransition(40, 0x200, 50),  # Unreachable island
        )
        graph = TransitionGraph(transitions, ())

        unreachable = DispatchSimulator.find_unreachable_cases(graph, entry_serial=10)

        assert unreachable == frozenset({40, 50})

    def test_all_reachable_cyclic(self) -> None:
        """Cyclic graph should have all nodes reachable from entry."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
            CaseTransition(30, 0x200, 10),  # Cycle back
        )
        graph = TransitionGraph(transitions, ())

        unreachable = DispatchSimulator.find_unreachable_cases(graph, entry_serial=10)

        assert len(unreachable) == 0

    def test_entry_not_in_graph(self) -> None:
        """Entry point not in graph should mark all as unreachable."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(20, 0x100, 30),
        )
        graph = TransitionGraph(transitions, ())

        unreachable = DispatchSimulator.find_unreachable_cases(graph, entry_serial=99)

        assert 10 in unreachable
        assert 20 in unreachable
        assert 30 in unreachable

    def test_empty_graph_no_unreachable(self) -> None:
        """Empty graph should return empty set."""
        graph = TransitionGraph((), ())

        unreachable = DispatchSimulator.find_unreachable_cases(graph, entry_serial=10)

        assert len(unreachable) == 0

    def test_complex_reachability(self) -> None:
        """Complex graph with multiple paths and unreachable nodes."""
        transitions = (
            CaseTransition(10, 0x42, 20),
            CaseTransition(10, 0x100, 30),
            CaseTransition(20, 0x200, 40),
            CaseTransition(30, 0x300, 40),
            CaseTransition(50, 0x400, 60),  # Unreachable
            CaseTransition(60, 0x500, 70),  # Unreachable
        )
        graph = TransitionGraph(transitions, ())

        unreachable = DispatchSimulator.find_unreachable_cases(graph, entry_serial=10)

        assert unreachable == frozenset({50, 60, 70})


class TestImmutabilityContract:
    """Test immutability of frozen dataclasses."""

    def test_case_transition_frozen(self) -> None:
        """CaseTransition should be frozen."""
        trans = CaseTransition(10, 0x42, 20)
        with pytest.raises(AttributeError):
            trans.from_serial = 99
        with pytest.raises(AttributeError):
            trans.assigned_value = 0x999
        with pytest.raises(AttributeError):
            trans.to_serial = 99

    def test_transition_graph_frozen(self) -> None:
        """TransitionGraph should be frozen."""
        graph = TransitionGraph((), ())
        with pytest.raises(AttributeError):
            graph.transitions = ()
        with pytest.raises(AttributeError):
            graph.unresolved = ()

    def test_nested_immutability(self) -> None:
        """Transitions tuple should be immutable."""
        transitions = (CaseTransition(10, 0x42, 20),)
        graph = TransitionGraph(transitions, ())

        # Cannot reassign transitions attribute
        with pytest.raises(AttributeError):
            graph.transitions = ()

        # Tuple itself is immutable
        with pytest.raises(TypeError):
            graph.transitions[0] = CaseTransition(99, 0x999, 99)  # type: ignore


class TestLargeGraphs:
    """Test simulation with large dispatch tables and many cases."""

    def test_large_linear_chain(self) -> None:
        """Simulate large linear chain (50 cases)."""
        # Create chain with distinct state values: case i writes value (i*100)
        # Dispatch table: 0->1, 100->2, 200->3, ..., 4900->50
        entries = tuple(CompareEntry(i * 100, i + 1, i) for i in range(50))
        table = DispatchTable(entries, default_serial=None)
        state_writes = {i: [i * 100] for i in range(50)}
        case_blocks = frozenset(range(51))

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 50
        edges = graph.as_edge_dict()
        for i in range(50):
            assert edges[i] == {i + 1}

    def test_large_fan_out(self) -> None:
        """Simulate case with many outgoing transitions (20+ writes)."""
        entries = tuple(CompareEntry(i * 10, i, i) for i in range(1, 26))
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [i * 10 for i in range(1, 26)]}  # 25 writes
        case_blocks = frozenset([10] + list(range(1, 26)))

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 25
        case_10_trans = graph.for_case(10)
        assert len(case_10_trans) == 25


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_value_state_write(self) -> None:
        """State value of 0 should be handled correctly."""
        entries = (CompareEntry(0, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0]}
        case_blocks = frozenset([10, 20])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 1
        assert graph.transitions[0].assigned_value == 0
        assert graph.transitions[0].to_serial == 20

    def test_large_state_values(self) -> None:
        """Very large state values should be handled."""
        large_val = 0xFFFFFFFF
        entries = (CompareEntry(large_val, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [large_val]}
        case_blocks = frozenset([10, 20])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        assert len(graph) == 1
        assert graph.transitions[0].assigned_value == large_val

    def test_case_writes_same_value_multiple_times(self) -> None:
        """Case writing same value multiple times should create multiple transitions."""
        entries = (CompareEntry(0x42, 20, 1),)
        table = DispatchTable(entries, default_serial=None)
        state_writes = {10: [0x42, 0x42, 0x42]}  # Duplicate writes
        case_blocks = frozenset([10, 20])

        graph = DispatchSimulator.simulate(table, state_writes, case_blocks)

        # Should have 3 transitions (one per write, even if duplicate)
        assert len(graph) == 3
        assert all(t.to_serial == 20 for t in graph.transitions)
