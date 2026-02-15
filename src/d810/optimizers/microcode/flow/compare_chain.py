"""Compare-chain dispatch table reconstruction.

This module implements dispatch table extraction from compare chains in
control-flow flattened code. Based on cadecff's analysis.py algorithm,
it identifies dispatch patterns where a state variable is compared against
constants in a chain of conditional branches.

Key insight from cadecff integration plan:
    Flattened control flow uses compare chains for dispatch decisions:
        if (state_var == 0x42) goto case_A
        if (state_var == 0x100) goto case_B
        if (state_var == 0x200) goto case_C

    By extracting these comparisons, we reconstruct the dispatch table
    mapping state values to case block targets.

Usage:
    comparisons = [
        BlockComparison(1, VarRef("reg", 0, 8), 0x42, 10, 2),
        BlockComparison(2, VarRef("reg", 0, 8), 0x100, 20, 3),
    ]
    aliases = frozenset([VarRef("reg", 0, 8)])
    table = CompareChainResolver.resolve(comparisons, aliases)
    # table.as_dict() = {0x42: 10, 0x100: 20}

References:
    - CaDeCFF algorithm: ~/src/idapro/cadecff/src/cadecff/analysis.py
    - CaDeCFF integration plan: docs/plans/CaDeCFF-Integration.md section 3.4
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from d810.optimizers.microcode.flow.state_var_alias import VarRef

__all__ = [
    "VarRef",
    "BlockComparison",
    "CompareEntry",
    "DispatchTable",
    "CompareChainResolver",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BlockComparison:
    """Abstract representation of a conditional comparison in a block.

    Represents a single conditional branch: if (lhs == rhs) goto true_target
    else goto false_target. This is the input format for the resolver.

    Attributes:
        block_serial: Which block contains this comparison
        lhs: Left-hand side (variable or constant)
        rhs: Right-hand side (variable or constant)
        true_target: Block serial on match (condition true)
        false_target: Block serial on no match (fallthrough)

    Examples:
        >>> # if (reg0 == 0x42) goto 10 else goto 2
        >>> BlockComparison(1, VarRef("reg", 0, 8), 0x42, 10, 2)
        >>> # if (0x100 == reg0) goto 20 else goto 3  (reversed order)
        >>> BlockComparison(2, 0x100, VarRef("reg", 0, 8), 20, 3)
    """

    block_serial: int
    lhs: VarRef | int
    rhs: VarRef | int
    true_target: int
    false_target: int

    def __repr__(self) -> str:
        """Return a human-readable representation."""
        lhs_str = f"0x{self.lhs:x}" if isinstance(self.lhs, int) else str(self.lhs)
        rhs_str = f"0x{self.rhs:x}" if isinstance(self.rhs, int) else str(self.rhs)
        return (
            f"BlockComparison(blk={self.block_serial}, "
            f"if {lhs_str} == {rhs_str} goto {self.true_target} "
            f"else {self.false_target})"
        )


@dataclass(frozen=True)
class CompareEntry:
    """A single dispatch table entry discovered from a compare chain.

    Represents one constant → target mapping extracted from a comparison.

    Attributes:
        constant: The state value being compared
        target_serial: Block serial jumped to on match
        source_serial: Block serial containing the comparison

    Examples:
        >>> # From "if (state == 0x42) goto 10", in block 1
        >>> CompareEntry(0x42, 10, 1)
    """

    constant: int
    target_serial: int
    source_serial: int

    def __repr__(self) -> str:
        """Return a human-readable representation."""
        return (
            f"CompareEntry(0x{self.constant:x} → blk={self.target_serial}, "
            f"from blk={self.source_serial})"
        )


@dataclass(frozen=True)
class DispatchTable:
    """Complete dispatch table extracted from compare chains.

    Represents the mapping from state variable values to target blocks,
    plus an optional default/fallthrough target.

    Attributes:
        entries: Tuple of all dispatch entries (constant → target)
        default_serial: Fallthrough/default target (if any)

    Examples:
        >>> entries = (
        ...     CompareEntry(0x42, 10, 1),
        ...     CompareEntry(0x100, 20, 2),
        ... )
        >>> table = DispatchTable(entries, default_serial=99)
        >>> table.as_dict()
        {66: 10, 256: 20}
    """

    entries: tuple[CompareEntry, ...]
    default_serial: int | None

    def as_dict(self) -> dict[int, int]:
        """Return {constant: target_serial} mapping.

        Returns:
            Dictionary mapping state constants to target block serials.
            Does NOT include the default_serial (that's a fallthrough, not
            a constant-based dispatch).

        Examples:
            >>> entries = (CompareEntry(0x42, 10, 1), CompareEntry(0x100, 20, 2))
            >>> table = DispatchTable(entries, default_serial=99)
            >>> table.as_dict()
            {66: 10, 256: 20}
        """
        return {e.constant: e.target_serial for e in self.entries}

    def __repr__(self) -> str:
        """Return a human-readable representation."""
        entries_str = ", ".join(f"0x{c:x}→{t}" for c, t in self.as_dict().items())
        default_str = f", default→{self.default_serial}" if self.default_serial is not None else ""
        return f"DispatchTable([{entries_str}]{default_str})"


class CompareChainResolver:
    """Extract dispatch tables from compare chains in flattened control flow.

    This service implements the cadecff algorithm for reconstructing dispatch
    tables from equality comparisons. It operates on abstract types (no IDA
    dependency) to enable unit testing with synthetic data.

    The algorithm:
    1. Filters comparisons where one side is a state alias and the other is constant
    2. Extracts the constant and the target block serial
    3. Handles both orderings (state == const, const == state)
    4. Detects duplicate/conflicting entries
    5. Determines the default target (final fallthrough)

    Example:
        >>> comparisons = [
        ...     BlockComparison(1, VarRef("reg", 0, 8), 0x42, 10, 2),
        ...     BlockComparison(2, VarRef("reg", 0, 8), 0x100, 20, 99),
        ... ]
        >>> aliases = frozenset([VarRef("reg", 0, 8)])
        >>> table = CompareChainResolver.resolve(comparisons, aliases)
        >>> table.as_dict()
        {66: 10, 256: 20}
        >>> table.default_serial
        99
    """

    @staticmethod
    def resolve(
        comparisons: Sequence[BlockComparison],
        state_aliases: frozenset[VarRef],
    ) -> DispatchTable:
        """Build dispatch table from block comparisons and known state aliases.

        Analyzes a sequence of comparisons and extracts those that compare
        a state variable alias against a constant. Returns the complete
        dispatch table with optional default target.

        Parameters
        ----------
        comparisons : sequence of conditional comparisons from all blocks
        state_aliases : known aliases of the state variable (from alias expansion)

        Returns
        -------
        DispatchTable with entries and default_serial. If no comparisons
        match the state aliases, returns an empty table.

        Notes
        -----
        The default_serial is determined as the false_target of the last
        comparison in the chain (the final fallthrough).

        If duplicate constants map to the same target, this is accepted
        (redundant comparisons are OK). If duplicate constants map to
        different targets, a warning is logged and the first mapping wins.

        Examples
        --------
        >>> # Simple linear chain
        >>> comparisons = [
        ...     BlockComparison(1, VarRef("reg", 0, 8), 0x42, 10, 2),
        ...     BlockComparison(2, VarRef("reg", 0, 8), 0x100, 20, 99),
        ... ]
        >>> aliases = frozenset([VarRef("reg", 0, 8)])
        >>> table = CompareChainResolver.resolve(comparisons, aliases)
        >>> len(table.entries)
        2
        >>> table.default_serial
        99

        >>> # Reversed ordering (const == var)
        >>> comparisons = [BlockComparison(1, 0x42, VarRef("reg", 0, 8), 10, 2)]
        >>> aliases = frozenset([VarRef("reg", 0, 8)])
        >>> table = CompareChainResolver.resolve(comparisons, aliases)
        >>> table.as_dict()
        {66: 10}

        >>> # No state-related comparisons
        >>> comparisons = [BlockComparison(1, VarRef("reg", 1, 8), 0x42, 10, 2)]
        >>> aliases = frozenset([VarRef("reg", 0, 8)])
        >>> table = CompareChainResolver.resolve(comparisons, aliases)
        >>> len(table.entries)
        0
        """
        entries: list[CompareEntry] = []
        seen_constants: dict[int, int] = {}  # constant → target_serial
        last_false_target: int | None = None

        for comp in comparisons:
            # Extract constant and variable (handle both orderings)
            constant: int | None = None
            var: VarRef | None = None

            if isinstance(comp.lhs, VarRef) and isinstance(comp.rhs, int):
                # Pattern: state_var == constant
                var = comp.lhs
                constant = comp.rhs
            elif isinstance(comp.lhs, int) and isinstance(comp.rhs, VarRef):
                # Pattern: constant == state_var
                constant = comp.lhs
                var = comp.rhs
            else:
                # Neither pattern matches (var-to-var or const-to-const comparison)
                continue

            # Filter: only accept comparisons involving state aliases
            if var not in state_aliases:
                continue

            # Check for duplicate/conflicting constants
            if constant in seen_constants:
                existing_target = seen_constants[constant]
                if existing_target != comp.true_target:
                    # Conflicting mapping: same constant, different targets
                    if logger.isEnabledFor(logging.WARNING):
                        logger.warning(
                            "Conflicting dispatch entry: 0x%x maps to both %d and %d. "
                            "Keeping first mapping.",
                            constant,
                            existing_target,
                            comp.true_target,
                        )
                    # Keep the first mapping (don't add duplicate entry)
                    continue
                # else: duplicate with same target, redundant but harmless (skip)
                continue

            # Valid entry: add to table
            entry = CompareEntry(constant, comp.true_target, comp.block_serial)
            entries.append(entry)
            seen_constants[constant] = comp.true_target

            # Track the last false_target as the default
            last_false_target = comp.false_target

        # Determine default_serial: the final fallthrough in the chain
        default_serial = last_false_target if entries else None

        return DispatchTable(tuple(entries), default_serial)

    @staticmethod
    def merge_tables(*tables: DispatchTable) -> DispatchTable:
        """Merge multiple partial dispatch tables (e.g., from different regions).

        Combines dispatch tables from multiple sources. Handles overlapping
        entries and conflicting mappings.

        Parameters
        ----------
        *tables : variable number of DispatchTable instances to merge

        Returns
        -------
        DispatchTable containing all entries from input tables. If multiple
        tables have the same constant mapping to the same target, only one
        entry is kept (deduplication). If multiple tables have the same
        constant mapping to different targets, a warning is logged and the
        first mapping wins.

        The default_serial is taken from the last non-None default in the
        input tables.

        Examples
        --------
        >>> # Merge two non-overlapping tables
        >>> t1 = DispatchTable((CompareEntry(0x42, 10, 1),), None)
        >>> t2 = DispatchTable((CompareEntry(0x100, 20, 2),), 99)
        >>> merged = CompareChainResolver.merge_tables(t1, t2)
        >>> len(merged.entries)
        2
        >>> merged.default_serial
        99

        >>> # Merge with overlapping entries (same constant, same target)
        >>> t1 = DispatchTable((CompareEntry(0x42, 10, 1),), None)
        >>> t2 = DispatchTable((CompareEntry(0x42, 10, 2),), None)
        >>> merged = CompareChainResolver.merge_tables(t1, t2)
        >>> len(merged.entries)
        1

        >>> # Merge with conflicting entries (same constant, different targets)
        >>> t1 = DispatchTable((CompareEntry(0x42, 10, 1),), None)
        >>> t2 = DispatchTable((CompareEntry(0x42, 99, 2),), None)
        >>> merged = CompareChainResolver.merge_tables(t1, t2)
        >>> merged.as_dict()
        {66: 10}
        """
        all_entries: list[CompareEntry] = []
        seen_constants: dict[int, int] = {}  # constant → target_serial
        last_default: int | None = None

        for table in tables:
            # Collect entries, checking for conflicts
            for entry in table.entries:
                if entry.constant in seen_constants:
                    existing_target = seen_constants[entry.constant]
                    if existing_target != entry.target_serial:
                        # Conflicting mapping
                        if logger.isEnabledFor(logging.WARNING):
                            logger.warning(
                                "Conflicting dispatch entry during merge: 0x%x maps to "
                                "both %d and %d. Keeping first mapping.",
                                entry.constant,
                                existing_target,
                                entry.target_serial,
                            )
                        # Keep the first mapping
                        continue
                    # else: duplicate with same target, redundant (skip)
                    continue

                # Valid entry: add to merged table
                all_entries.append(entry)
                seen_constants[entry.constant] = entry.target_serial

            # Track the last non-None default
            if table.default_serial is not None:
                last_default = table.default_serial

        return DispatchTable(tuple(all_entries), last_default)
