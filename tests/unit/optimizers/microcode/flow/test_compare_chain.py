"""Unit tests for compare-chain dispatch table reconstruction.

Tests the CompareChainResolver service with synthetic comparison patterns
representing OLLVM-style control-flow flattening dispatch chains.

No IDA runtime required - operates on abstract BlockComparison types.
"""

from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.compare_chain import (
    BlockComparison,
    CompareChainResolver,
    CompareEntry,
    DispatchTable,
    VarRef,
)


class TestCompareChainResolver:
    """Test dispatch table extraction from compare chains."""

    def test_simple_linear_chain(self) -> None:
        """Extract dispatch table from simple linear compare chain."""
        # Dispatcher pattern: if (state == 0x42) goto 10 else 2
        #                     if (state == 0x100) goto 20 else 3
        #                     if (state == 0x200) goto 30 else 99
        state_var = VarRef("reg", 0, 8)
        comparisons = [
            BlockComparison(1, state_var, 0x42, 10, 2),
            BlockComparison(2, state_var, 0x100, 20, 3),
            BlockComparison(3, state_var, 0x200, 30, 99),
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Should have 3 dispatch entries
        assert len(table.entries) == 3
        mapping = table.as_dict()
        assert mapping[0x42] == 10
        assert mapping[0x100] == 20
        assert mapping[0x200] == 30

        # Default should be the last false_target
        assert table.default_serial == 99

    def test_single_comparison(self) -> None:
        """Degenerate case: single comparison creates one-entry table."""
        state_var = VarRef("reg", 0, 8)
        comparisons = [BlockComparison(1, state_var, 0x42, 10, 99)]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        assert len(table.entries) == 1
        assert table.as_dict()[0x42] == 10
        assert table.default_serial == 99

    def test_empty_comparisons(self) -> None:
        """Empty comparison list produces empty table."""
        aliases = frozenset([VarRef("reg", 0, 8)])
        table = CompareChainResolver.resolve([], aliases)

        assert len(table.entries) == 0
        assert table.as_dict() == {}
        assert table.default_serial is None

    def test_reversed_ordering_const_eq_var(self) -> None:
        """Handle both var==const and const==var orderings."""
        state_var = VarRef("reg", 0, 8)
        comparisons = [
            # Pattern: if (0x42 == state_var) goto 10 else 2
            BlockComparison(1, 0x42, state_var, 10, 2),
            # Pattern: if (state_var == 0x100) goto 20 else 99
            BlockComparison(2, state_var, 0x100, 20, 99),
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        assert len(table.entries) == 2
        mapping = table.as_dict()
        assert mapping[0x42] == 10
        assert mapping[0x100] == 20

    def test_duplicate_constants_same_target(self) -> None:
        """Duplicate constants mapping to same target are deduplicated."""
        state_var = VarRef("reg", 0, 8)
        comparisons = [
            BlockComparison(1, state_var, 0x42, 10, 2),
            BlockComparison(2, state_var, 0x42, 10, 99),  # Same const, same target
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Should only have one entry (first one wins)
        assert len(table.entries) == 1
        assert table.as_dict()[0x42] == 10

    def test_conflicting_constants_different_targets(self) -> None:
        """Conflicting constants (same value, different targets) keep first."""
        state_var = VarRef("reg", 0, 8)
        comparisons = [
            BlockComparison(1, state_var, 0x42, 10, 2),
            BlockComparison(2, state_var, 0x42, 99, 3),  # Same const, different target
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Should only have one entry, first mapping wins
        assert len(table.entries) == 1
        assert table.as_dict()[0x42] == 10

    def test_mixed_comparisons_filters_non_state(self) -> None:
        """Filter out comparisons not involving state variable."""
        state_var = VarRef("reg", 0, 8)
        other_var = VarRef("reg", 1, 8)
        comparisons = [
            BlockComparison(1, state_var, 0x42, 10, 2),  # State-related
            BlockComparison(2, other_var, 0x100, 20, 3),  # NOT state-related
            BlockComparison(3, state_var, 0x200, 30, 99),  # State-related
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Should only have 2 entries (block 2 filtered out)
        assert len(table.entries) == 2
        mapping = table.as_dict()
        assert 0x42 in mapping
        assert 0x200 in mapping
        assert 0x100 not in mapping  # Filtered out

    def test_default_target_detection(self) -> None:
        """Default target is the last false_target in the chain."""
        state_var = VarRef("reg", 0, 8)
        comparisons = [
            BlockComparison(1, state_var, 0x42, 10, 2),
            BlockComparison(2, state_var, 0x100, 20, 3),
            BlockComparison(3, state_var, 0x200, 30, 999),  # Last false_target
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Default should be the final false_target (999)
        assert table.default_serial == 999

    def test_merge_non_overlapping_tables(self) -> None:
        """Merge two tables with no overlapping entries."""
        t1 = DispatchTable(
            (CompareEntry(0x42, 10, 1), CompareEntry(0x100, 20, 2)),
            None,
        )
        t2 = DispatchTable(
            (CompareEntry(0x200, 30, 3), CompareEntry(0x300, 40, 4)),
            99,
        )

        merged = CompareChainResolver.merge_tables(t1, t2)

        # Should have all 4 entries
        assert len(merged.entries) == 4
        mapping = merged.as_dict()
        assert mapping[0x42] == 10
        assert mapping[0x100] == 20
        assert mapping[0x200] == 30
        assert mapping[0x300] == 40

        # Default should be from t2 (last non-None)
        assert merged.default_serial == 99

    def test_merge_overlapping_entries_same_target(self) -> None:
        """Merge tables with overlapping entries (same const, same target)."""
        t1 = DispatchTable((CompareEntry(0x42, 10, 1),), None)
        t2 = DispatchTable((CompareEntry(0x42, 10, 2),), None)

        merged = CompareChainResolver.merge_tables(t1, t2)

        # Should deduplicate: only one entry
        assert len(merged.entries) == 1
        assert merged.as_dict()[0x42] == 10

    def test_merge_conflicting_entries(self) -> None:
        """Merge tables with conflicting entries (same const, different target)."""
        t1 = DispatchTable((CompareEntry(0x42, 10, 1),), None)
        t2 = DispatchTable((CompareEntry(0x42, 99, 2),), None)

        merged = CompareChainResolver.merge_tables(t1, t2)

        # Should keep first mapping (from t1)
        assert len(merged.entries) == 1
        assert merged.as_dict()[0x42] == 10

    def test_large_dispatch_table(self) -> None:
        """Handle large dispatch tables (20+ entries)."""
        state_var = VarRef("reg", 0, 8)
        # Generate 25 comparisons
        comparisons = [
            BlockComparison(i, state_var, i * 0x10, i * 100, i + 1)
            for i in range(1, 26)
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        assert len(table.entries) == 25
        mapping = table.as_dict()

        # Verify all entries are present
        for i in range(1, 26):
            expected_const = i * 0x10
            expected_target = i * 100
            assert mapping[expected_const] == expected_target

    def test_no_state_related_comparisons(self) -> None:
        """All comparisons involve non-state variables → empty table."""
        state_var = VarRef("reg", 0, 8)
        other_var1 = VarRef("reg", 1, 8)
        other_var2 = VarRef("reg", 2, 8)

        comparisons = [
            BlockComparison(1, other_var1, 0x42, 10, 2),
            BlockComparison(2, other_var2, 0x100, 20, 99),
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # No entries should be extracted
        assert len(table.entries) == 0
        assert table.as_dict() == {}
        assert table.default_serial is None

    def test_multiple_aliases_any_match(self) -> None:
        """Comparisons match if they involve any alias in the set."""
        state_var = VarRef("reg", 0, 8)
        alias1 = VarRef("reg", 1, 8)
        alias2 = VarRef("stack", -16, 8)

        comparisons = [
            BlockComparison(1, state_var, 0x42, 10, 2),  # Matches state_var
            BlockComparison(2, alias1, 0x100, 20, 3),  # Matches alias1
            BlockComparison(3, alias2, 0x200, 30, 99),  # Matches alias2
        ]
        aliases = frozenset([state_var, alias1, alias2])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # All 3 comparisons should match
        assert len(table.entries) == 3
        mapping = table.as_dict()
        assert mapping[0x42] == 10
        assert mapping[0x100] == 20
        assert mapping[0x200] == 30

    def test_var_to_var_comparison_ignored(self) -> None:
        """Variable-to-variable comparisons are ignored (not state dispatch)."""
        state_var = VarRef("reg", 0, 8)
        other_var = VarRef("reg", 1, 8)

        comparisons = [
            BlockComparison(1, state_var, other_var, 10, 2),  # var-to-var
            BlockComparison(2, state_var, 0x42, 20, 99),  # var-to-const (valid)
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Only the second comparison should be extracted
        assert len(table.entries) == 1
        assert table.as_dict()[0x42] == 20

    def test_const_to_const_comparison_ignored(self) -> None:
        """Constant-to-constant comparisons are ignored (degenerate)."""
        state_var = VarRef("reg", 0, 8)

        comparisons = [
            BlockComparison(1, 0x42, 0x100, 10, 2),  # const-to-const
            BlockComparison(2, state_var, 0x200, 20, 99),  # var-to-const (valid)
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Only the second comparison should be extracted
        assert len(table.entries) == 1
        assert table.as_dict()[0x200] == 20

    def test_dispatch_table_repr(self) -> None:
        """DispatchTable repr shows constants and targets."""
        entries = (CompareEntry(0x42, 10, 1), CompareEntry(0x100, 20, 2))
        table = DispatchTable(entries, default_serial=99)

        repr_str = repr(table)
        assert "0x42" in repr_str
        assert "0x100" in repr_str
        assert "10" in repr_str
        assert "20" in repr_str
        assert "99" in repr_str

    def test_compare_entry_repr(self) -> None:
        """CompareEntry repr shows constant, target, and source."""
        entry = CompareEntry(0x42, 10, 1)
        repr_str = repr(entry)
        assert "0x42" in repr_str
        assert "10" in repr_str
        assert "1" in repr_str

    def test_block_comparison_repr(self) -> None:
        """BlockComparison repr shows lhs, rhs, and targets."""
        comp = BlockComparison(1, VarRef("reg", 0, 8), 0x42, 10, 2)
        repr_str = repr(comp)
        assert "0x42" in repr_str
        assert "10" in repr_str
        assert "2" in repr_str

    def test_merge_empty_tables(self) -> None:
        """Merging empty tables produces empty table."""
        t1 = DispatchTable((), None)
        t2 = DispatchTable((), None)

        merged = CompareChainResolver.merge_tables(t1, t2)

        assert len(merged.entries) == 0
        assert merged.default_serial is None

    def test_merge_single_table(self) -> None:
        """Merging a single table returns equivalent table."""
        t1 = DispatchTable((CompareEntry(0x42, 10, 1),), 99)

        merged = CompareChainResolver.merge_tables(t1)

        assert len(merged.entries) == 1
        assert merged.as_dict()[0x42] == 10
        assert merged.default_serial == 99

    def test_merge_preserves_last_default(self) -> None:
        """Merge takes last non-None default."""
        t1 = DispatchTable((CompareEntry(0x42, 10, 1),), 50)
        t2 = DispatchTable((CompareEntry(0x100, 20, 2),), None)
        t3 = DispatchTable((CompareEntry(0x200, 30, 3),), 99)

        merged = CompareChainResolver.merge_tables(t1, t2, t3)

        # Last non-None default is 99 (from t3)
        assert merged.default_serial == 99

    def test_entry_source_serial_preserved(self) -> None:
        """CompareEntry preserves source block serial."""
        state_var = VarRef("reg", 0, 8)
        comparisons = [
            BlockComparison(100, state_var, 0x42, 10, 2),
            BlockComparison(200, state_var, 0x100, 20, 99),
        ]
        aliases = frozenset([state_var])

        table = CompareChainResolver.resolve(comparisons, aliases)

        # Check that source serials are preserved
        entry_map = {e.constant: e for e in table.entries}
        assert entry_map[0x42].source_serial == 100
        assert entry_map[0x100].source_serial == 200
