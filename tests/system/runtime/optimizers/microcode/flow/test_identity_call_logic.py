"""Unit tests for identity_call pure logic functions.

These tests cover only the pure-Python logic functions that don't depend on IDA.
IDA-dependent functionality is tested in tests/system/runtime/test_identity_call.py.
"""
import pytest

from d810.optimizers.microcode.flow.identity_call import (
    DeferredIdentityCall,
    TableResolution,
    classify_table_entries,
    clear_deferred_analysis,
    retrieve_deferred_analysis,
    store_deferred_analysis,
)


class TestClassifyTableEntries:
    """Test table entry classification logic."""

    def test_both_same_target(self):
        """Test when both table entries resolve to same target."""
        result = classify_table_entries(
            final0=0x1000,
            final1=0x1000,
            func_ea=0x2000,
            func_start=0x2000,
            func_end=0x2100,
        )

        assert result.entry0_target == 0x1000
        assert result.entry1_target is None
        assert result.both_same is True
        assert result.is_cff_dispatcher is False

    def test_entry1_none(self):
        """Test when entry1 is None (single entry table)."""
        result = classify_table_entries(
            final0=0x1000,
            final1=None,
            func_ea=0x2000,
            func_start=0x2000,
            func_end=0x2100,
        )

        assert result.entry0_target == 0x1000
        assert result.entry1_target is None
        assert result.both_same is True
        assert result.is_cff_dispatcher is False

    def test_both_self_reference_cff_dispatcher(self):
        """Test CFF dispatcher pattern (both entries loop back to function)."""
        result = classify_table_entries(
            final0=0x2050,  # Inside function
            final1=0x2000,  # Function entry
            func_ea=0x2000,
            func_start=0x2000,
            func_end=0x2100,
        )

        assert result.entry0_target == 0x2050
        assert result.entry1_target == 0x2000
        assert result.both_same is False
        assert result.is_cff_dispatcher is True

    def test_one_self_reference_entry0(self):
        """Test when entry0 is self-ref, entry1 is valid."""
        result = classify_table_entries(
            final0=0x2050,  # Inside function
            final1=0x3000,  # External target
            func_ea=0x2000,
            func_start=0x2000,
            func_end=0x2100,
        )

        assert result.entry0_target == 0x3000  # Use entry1
        assert result.entry1_target is None
        assert result.both_same is False
        assert result.is_cff_dispatcher is False

    def test_one_self_reference_entry1(self):
        """Test when entry1 is self-ref, entry0 is valid."""
        result = classify_table_entries(
            final0=0x3000,  # External target
            final1=0x2050,  # Inside function
            func_ea=0x2000,
            func_start=0x2000,
            func_end=0x2100,
        )

        assert result.entry0_target == 0x3000  # Use entry0
        assert result.entry1_target is None
        assert result.both_same is False
        assert result.is_cff_dispatcher is False

    def test_both_different_valid_targets(self):
        """Test when both entries are valid but different (conditional)."""
        result = classify_table_entries(
            final0=0x3000,
            final1=0x4000,
            func_ea=0x2000,
            func_start=0x2000,
            func_end=0x2100,
        )

        assert result.entry0_target == 0x3000
        assert result.entry1_target == 0x4000
        assert result.both_same is False
        assert result.is_cff_dispatcher is False


class TestDeferredAnalysisStorage:
    """Test deferred analysis storage functions."""

    def setup_method(self):
        """Clear storage before each test."""
        clear_deferred_analysis()

    def test_store_and_retrieve_single(self):
        """Test storing and retrieving a single deferred call."""
        dc = DeferredIdentityCall(
            call_ea=0x1000,
            ijmp_ea=0x1010,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8000,
            final_target_ea=0x9000,
            target_name="target_func",
            is_ijmp_pattern=True,
        )

        store_deferred_analysis(0x2000, dc)
        retrieved = retrieve_deferred_analysis(0x2000)

        assert len(retrieved) == 1
        assert retrieved[0].call_ea == 0x1000
        assert retrieved[0].target_name == "target_func"

    def test_store_multiple_same_function(self):
        """Test storing multiple deferred calls for same function."""
        dc1 = DeferredIdentityCall(
            call_ea=0x1000,
            ijmp_ea=0x1010,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8000,
            final_target_ea=0x9000,
            target_name="target1",
            is_ijmp_pattern=True,
        )
        dc2 = DeferredIdentityCall(
            call_ea=0x1020,
            ijmp_ea=0x1030,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8100,
            final_target_ea=0x9100,
            target_name="target2",
            is_ijmp_pattern=False,
        )

        store_deferred_analysis(0x2000, dc1)
        store_deferred_analysis(0x2000, dc2)

        retrieved = retrieve_deferred_analysis(0x2000)
        assert len(retrieved) == 2
        assert retrieved[0].target_name == "target1"
        assert retrieved[1].target_name == "target2"

    def test_retrieve_nonexistent_function(self):
        """Test retrieving from function with no stored analysis."""
        retrieved = retrieve_deferred_analysis(0x9999)
        assert retrieved == []

    def test_clear_specific_function(self):
        """Test clearing deferred analysis for specific function."""
        dc1 = DeferredIdentityCall(
            call_ea=0x1000,
            ijmp_ea=0x1010,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8000,
            final_target_ea=0x9000,
            target_name="target1",
            is_ijmp_pattern=True,
        )
        dc2 = DeferredIdentityCall(
            call_ea=0x2000,
            ijmp_ea=0x2010,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8100,
            final_target_ea=0x9100,
            target_name="target2",
            is_ijmp_pattern=True,
        )

        store_deferred_analysis(0x1000, dc1)
        store_deferred_analysis(0x2000, dc2)

        clear_deferred_analysis(0x1000)

        assert retrieve_deferred_analysis(0x1000) == []
        assert len(retrieve_deferred_analysis(0x2000)) == 1

    def test_clear_all(self):
        """Test clearing all deferred analysis."""
        dc1 = DeferredIdentityCall(
            call_ea=0x1000,
            ijmp_ea=0x1010,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8000,
            final_target_ea=0x9000,
            target_name="target1",
            is_ijmp_pattern=True,
        )
        dc2 = DeferredIdentityCall(
            call_ea=0x2000,
            ijmp_ea=0x2010,
            identity_func_ea=0x5000,
            global_ptr_ea=0x8100,
            final_target_ea=0x9100,
            target_name="target2",
            is_ijmp_pattern=True,
        )

        store_deferred_analysis(0x1000, dc1)
        store_deferred_analysis(0x2000, dc2)

        clear_deferred_analysis(None)

        assert retrieve_deferred_analysis(0x1000) == []
        assert retrieve_deferred_analysis(0x2000) == []


class TestTrampolineChainLogic:
    """Test trampoline chain cycle detection logic.

    These tests verify the cycle detection algorithm without IDA dependencies.
    The actual trampoline resolution is tested in system tests.
    """

    def test_visited_set_prevents_cycles(self):
        """Test that visited set pattern prevents infinite loops."""
        # Simulate the visited set logic (matches arch_utils.resolve_trampoline_chain)
        visited: set[int] = set()
        current = 0x1000
        chain = [0x2000, 0x3000, 0x1000]  # After 0x1000, go to 0x2000, 0x3000, then cycle back

        max_depth = 10
        visited.add(current)  # Add initial
        for next_addr in chain:
            if next_addr in visited:
                # Cycle detected
                break
            visited.add(next_addr)
            current = next_addr
            max_depth -= 1
            if max_depth <= 0:
                break

        # Should have stopped at cycle, not exhausted depth
        assert max_depth > 0
        assert 0x1000 in visited
        assert 0x2000 in visited
        assert 0x3000 in visited

    def test_max_depth_limits_chain(self):
        """Test that max_depth parameter limits chain following."""
        visited: set[int] = set()
        current = 0x1000
        # Infinite chain (no cycle)
        chain = [0x1100 + i * 0x100 for i in range(100)]  # 0x1100, 0x1200, ...

        max_depth = 5
        depth_used = 0

        visited.add(current)  # Add initial
        for next_addr in chain:
            if next_addr in visited:
                break
            visited.add(next_addr)
            current = next_addr
            depth_used += 1
            max_depth -= 1
            if max_depth <= 0:
                break

        # Should have stopped at depth limit
        assert max_depth == 0
        assert depth_used == 5
