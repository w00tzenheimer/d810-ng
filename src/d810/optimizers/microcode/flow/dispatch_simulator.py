"""Dispatch table simulation for state machine transition reconstruction.

This module implements the final Phase 2 algorithm: combining dispatch tables
(Phase 2.3) with case block state writes (Phase 2.2) to produce a complete
transition graph — the recovered CFG edges.

The DispatchSimulator simulates state machine transitions by following the
logic: "When case block A writes state value V, the dispatcher routes to
case block B" where B is looked up in the dispatch table.

Key insight from cadecff integration:
    State machine transitions = case writes + dispatch table lookups
        Case block A: state = 0x100
        Dispatcher: if (state == 0x100) goto case_B
        → Transition: A → B

Usage:
    from d810.optimizers.microcode.flow.compare_chain import DispatchTable

    dispatch_table = DispatchTable(entries, default_serial=99)
    state_writes = {10: [0x42, 0x100], 20: [0x200]}
    case_blocks = frozenset([10, 20, 30])

    graph = DispatchSimulator.simulate(
        dispatch_table, state_writes, case_blocks
    )
    # graph.transitions = (
    #     CaseTransition(10, 0x42, target),
    #     CaseTransition(10, 0x100, target),
    #     ...
    # )

References:
    - CaDeCFF algorithm: ~/src/idapro/cadecff/src/cadecff/analysis.py
    - CaDeCFF integration plan: docs/plans/CaDeCFF-Integration.md section 3.5
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from d810.optimizers.microcode.flow.compare_chain import DispatchTable

__all__ = [
    "CaseTransition",
    "TransitionGraph",
    "DispatchSimulator",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CaseTransition:
    """A single state machine transition.

    Represents one control-flow edge in the recovered CFG:
    "Case block X writes value V, dispatcher routes to case block Y"

    Attributes:
        from_serial: Source case block serial
        assigned_value: State variable value written by source case
        to_serial: Target case block serial (resolved via dispatch table)

    Examples:
        >>> # Case 10 writes 0x42, dispatcher routes to case 20
        >>> CaseTransition(10, 0x42, 20)
    """

    from_serial: int
    assigned_value: int
    to_serial: int

    def __post_init__(self) -> None:
        """Validate transition invariants."""
        if self.from_serial < 0:
            raise ValueError(f"from_serial must be non-negative, got {self.from_serial}")
        if self.to_serial < 0:
            raise ValueError(f"to_serial must be non-negative, got {self.to_serial}")

    def __repr__(self) -> str:
        """Return a human-readable representation with hex formatting."""
        return (
            f"CaseTransition(blk={self.from_serial} → blk={self.to_serial}, "
            f"via 0x{self.assigned_value:x})"
        )


@dataclass(frozen=True)
class TransitionGraph:
    """Complete set of resolved state machine transitions.

    Represents the full recovered CFG as a set of case-to-case edges,
    plus any unresolved transitions (state writes with no dispatch target).

    Attributes:
        transitions: All resolved transitions (from → to via value)
        unresolved: State writes that couldn't be resolved to a target
                   (from_serial, assigned_value) pairs

    Examples:
        >>> transitions = (
        ...     CaseTransition(10, 0x42, 20),
        ...     CaseTransition(20, 0x100, 30),
        ... )
        >>> graph = TransitionGraph(transitions, unresolved=())
        >>> graph.as_edge_dict()
        {10: {20}, 20: {30}}
    """

    transitions: tuple[CaseTransition, ...]
    unresolved: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        """Validate graph invariants."""
        if not all(isinstance(t, CaseTransition) for t in self.transitions):
            raise ValueError("All transitions must be CaseTransition instances")

    def as_edge_dict(self) -> dict[int, set[int]]:
        """Return adjacency dictionary representation.

        Returns:
            Dictionary mapping from_serial → set of to_serials.
            Only includes resolved transitions.

        Examples:
            >>> transitions = (
            ...     CaseTransition(10, 0x42, 20),
            ...     CaseTransition(10, 0x100, 30),
            ...     CaseTransition(20, 0x200, 10),
            ... )
            >>> graph = TransitionGraph(transitions, ())
            >>> graph.as_edge_dict()
            {10: {20, 30}, 20: {10}}
        """
        edges: dict[int, set[int]] = {}
        for trans in self.transitions:
            if trans.from_serial not in edges:
                edges[trans.from_serial] = set()
            edges[trans.from_serial].add(trans.to_serial)
        return edges

    def for_case(self, serial: int) -> tuple[CaseTransition, ...]:
        """Filter transitions originating from a specific case block.

        Parameters:
            serial: Source case block serial to filter by

        Returns:
            Tuple of transitions with from_serial == serial

        Examples:
            >>> transitions = (
            ...     CaseTransition(10, 0x42, 20),
            ...     CaseTransition(10, 0x100, 30),
            ...     CaseTransition(20, 0x200, 10),
            ... )
            >>> graph = TransitionGraph(transitions, ())
            >>> graph.for_case(10)
            (CaseTransition(10, 0x42, 20), CaseTransition(10, 0x100, 30))
        """
        return tuple(t for t in self.transitions if t.from_serial == serial)

    def __len__(self) -> int:
        """Return the number of resolved transitions."""
        return len(self.transitions)


class DispatchSimulator:
    """Simulate state machine transitions through dispatch table lookups.

    This service combines dispatch tables (Phase 2.3) with case block state
    writes (Phase 2.2) to produce the complete transition graph — the recovered
    CFG edges between case blocks.

    All methods are static (no instance state required).

    Algorithm:
        For each case block:
            For each state value it writes:
                Look up target in dispatch table
                If found → create transition
                If not found → add to unresolved

    Example:
        >>> from d810.optimizers.microcode.flow.compare_chain import (
        ...     DispatchTable, CompareEntry
        ... )
        >>> # Dispatch table: 0x42 → case 20, 0x100 → case 30
        >>> entries = (CompareEntry(0x42, 20, 1), CompareEntry(0x100, 30, 2))
        >>> table = DispatchTable(entries, default_serial=99)
        >>> # Case 10 writes 0x42 and 0x100
        >>> state_writes = {10: [0x42, 0x100]}
        >>> case_blocks = frozenset([10, 20, 30])
        >>> graph = DispatchSimulator.simulate(table, state_writes, case_blocks)
        >>> len(graph)
        2
        >>> graph.as_edge_dict()
        {10: {20, 30}}
    """

    @staticmethod
    def simulate(
        dispatch_table: DispatchTable,
        state_writes: dict[int, list[int]],
        case_blocks: frozenset[int],
        max_depth: int = 10,
    ) -> TransitionGraph:
        """Simulate state machine transitions through the dispatcher.

        Combines dispatch table lookups with case block state writes to produce
        the complete transition graph.

        Parameters
        ----------
        dispatch_table : DispatchTable from Phase 2.3
            Maps state values to target case blocks
        state_writes : dict mapping case serial → list of state values
            State variable assignments from Phase 2.2
        case_blocks : set of case block serials to simulate
            Usually all non-dispatcher blocks in the function
        max_depth : maximum recursion depth for multi-level dispatch
            Prevents infinite loops in malformed dispatch tables

        Returns
        -------
        TransitionGraph with all resolved transitions and unresolved writes

        Notes
        -----
        Multi-level dispatch: If a state value maps to another dispatcher
        block (one that's in the dispatch table as a target), we recursively
        resolve through that dispatcher up to max_depth levels.

        Unresolved writes occur when:
        - State value not in dispatch table and no default_serial
        - Max depth exceeded (cycle detection)
        - Target is not a valid case block

        Examples
        --------
        >>> # Simple linear chain
        >>> from d810.optimizers.microcode.flow.compare_chain import (
        ...     DispatchTable, CompareEntry
        ... )
        >>> entries = (
        ...     CompareEntry(0x42, 20, 1),
        ...     CompareEntry(0x100, 30, 2),
        ... )
        >>> table = DispatchTable(entries, default_serial=99)
        >>> state_writes = {10: [0x42], 20: [0x100]}
        >>> case_blocks = frozenset([10, 20, 30, 99])
        >>> graph = DispatchSimulator.simulate(table, state_writes, case_blocks)
        >>> graph.as_edge_dict()
        {10: {20}, 20: {30}}

        >>> # With unresolved values
        >>> state_writes = {10: [0x999]}  # 0x999 not in table
        >>> case_blocks = frozenset([10])
        >>> graph = DispatchSimulator.simulate(table, state_writes, case_blocks)
        >>> len(graph)
        0
        >>> graph.unresolved
        ((10, 2457),)
        """
        transitions: list[CaseTransition] = []
        unresolved: list[tuple[int, int]] = []

        for case_serial in case_blocks:
            # Get state writes for this case block (default to empty list)
            writes = state_writes.get(case_serial, [])

            for assigned_value in writes:
                # Resolve target through dispatch table
                target_serial = DispatchSimulator.resolve_target(
                    dispatch_table, assigned_value, max_depth
                )

                if target_serial is not None:
                    # Resolved: create transition
                    transition = CaseTransition(case_serial, assigned_value, target_serial)
                    transitions.append(transition)
                else:
                    # Unresolved: track for diagnostics
                    unresolved.append((case_serial, assigned_value))

        return TransitionGraph(tuple(transitions), tuple(unresolved))

    @staticmethod
    def resolve_target(
        dispatch_table: DispatchTable,
        state_value: int,
        max_depth: int = 10,
    ) -> int | None:
        """Resolve a state value to its target case block serial.

        Performs dispatch table lookup with support for multi-level dispatch
        (where a target itself is another dispatcher) and cycle detection.

        Parameters
        ----------
        dispatch_table : DispatchTable to look up in
        state_value : State variable value to resolve
        max_depth : Maximum recursion depth (prevents infinite loops)

        Returns
        -------
        Target case block serial, or None if unresolved

        Notes
        -----
        Resolution algorithm:
        1. Look up state_value in dispatch table
        2. If found and target is in table (multi-level), recurse
        3. If not found, return default_serial if available
        4. Track visited values to detect cycles

        Examples
        --------
        >>> # Simple lookup
        >>> from d810.optimizers.microcode.flow.compare_chain import (
        ...     DispatchTable, CompareEntry
        ... )
        >>> entries = (CompareEntry(0x42, 20, 1),)
        >>> table = DispatchTable(entries, default_serial=99)
        >>> DispatchSimulator.resolve_target(table, 0x42)
        20

        >>> # Fallback to default
        >>> DispatchSimulator.resolve_target(table, 0x999)
        99

        >>> # No default, unresolved
        >>> table_no_default = DispatchTable(entries, default_serial=None)
        >>> DispatchSimulator.resolve_target(table_no_default, 0x999) is None
        True
        """
        lookup = dispatch_table.as_dict()
        visited: set[int] = set()
        current_value = state_value
        depth = 0

        while depth < max_depth:
            # Cycle detection
            if current_value in visited:
                if logger.isEnabledFor(logging.WARNING):
                    logger.warning(
                        "Cycle detected in dispatch table resolution for value 0x%x",
                        state_value,
                    )
                return None

            visited.add(current_value)

            # Look up current value
            if current_value in lookup:
                target = lookup[current_value]

                # Check if target is itself a dispatcher (multi-level dispatch)
                if target in lookup:
                    # Multi-level: recurse through the next dispatcher
                    current_value = target
                    depth += 1
                    continue
                else:
                    # Terminal target found
                    return target
            else:
                # Not in table: use default if available
                return dispatch_table.default_serial

        # Max depth exceeded (likely a cycle or very deep nesting)
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(
                "Max depth (%d) exceeded resolving value 0x%x",
                max_depth,
                state_value,
            )
        return None

    @staticmethod
    def find_self_loops(graph: TransitionGraph) -> frozenset[int]:
        """Find case blocks that transition to themselves.

        Self-loops can indicate infinite loops in the original obfuscated code
        or special control flow patterns (busy-wait, retry logic).

        Parameters:
            graph: Transition graph to analyze

        Returns:
            Set of case block serials with self-transitions

        Examples:
            >>> transitions = (
            ...     CaseTransition(10, 0x42, 10),  # Self-loop
            ...     CaseTransition(20, 0x100, 30),
            ...     CaseTransition(30, 0x200, 30),  # Self-loop
            ... )
            >>> graph = TransitionGraph(transitions, ())
            >>> DispatchSimulator.find_self_loops(graph)
            frozenset({10, 30})
        """
        self_loops: set[int] = set()
        for trans in graph.transitions:
            if trans.from_serial == trans.to_serial:
                self_loops.add(trans.from_serial)
        return frozenset(self_loops)

    @staticmethod
    def find_unreachable_cases(
        graph: TransitionGraph, entry_serial: int
    ) -> frozenset[int]:
        """Find case blocks with no incoming transitions from reachable cases.

        Performs reachability analysis from the entry point to identify dead
        case blocks that can never be reached in normal execution.

        Parameters:
            graph: Transition graph to analyze
            entry_serial: Entry point case block serial

        Returns:
            Set of case block serials that are unreachable from entry

        Notes:
            This is a simple reachability check, not sophisticated dead code
            analysis. Cases may be "unreachable" due to incomplete state write
            tracking, not necessarily dead code.

        Examples:
            >>> transitions = (
            ...     CaseTransition(10, 0x42, 20),
            ...     CaseTransition(20, 0x100, 30),
            ...     CaseTransition(40, 0x200, 50),  # Unreachable island
            ... )
            >>> graph = TransitionGraph(transitions, ())
            >>> DispatchSimulator.find_unreachable_cases(graph, 10)
            frozenset({40, 50})
        """
        # Build adjacency for forward reachability
        edges = graph.as_edge_dict()

        # BFS from entry
        reachable: set[int] = {entry_serial}
        queue: list[int] = [entry_serial]

        while queue:
            current = queue.pop(0)
            for successor in edges.get(current, set()):
                if successor not in reachable:
                    reachable.add(successor)
                    queue.append(successor)

        # All cases in graph minus reachable = unreachable
        all_cases: set[int] = set()
        for trans in graph.transitions:
            all_cases.add(trans.from_serial)
            all_cases.add(trans.to_serial)

        unreachable = all_cases - reachable
        return frozenset(unreachable)
