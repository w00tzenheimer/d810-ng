"""Unit tests for tracker_components.py - extracted hot path components."""

import pytest
from d810.hexrays.tracker_components import (
    ImmutableBlockInfo,
    CachedBlockPath,
    MopSet,
    benchmark_block_info_copy,
    benchmark_cached_path,
)


class TestImmutableBlockInfo:
    """Tests for ImmutableBlockInfo."""

    def test_creation(self):
        """Test basic creation."""
        info = ImmutableBlockInfo(blk_serial=5, ins_list=(100, 200, 300))
        assert info.blk_serial == 5
        assert info.ins_list == (100, 200, 300)

    def test_frozen(self):
        """Test that frozen dataclass prevents mutation."""
        info = ImmutableBlockInfo(blk_serial=5, ins_list=(100,))
        with pytest.raises(AttributeError):
            info.blk_serial = 10  # type: ignore

    def test_hashable(self):
        """Test that ImmutableBlockInfo is hashable."""
        info1 = ImmutableBlockInfo(blk_serial=5, ins_list=(100, 200))
        info2 = ImmutableBlockInfo(blk_serial=5, ins_list=(100, 200))
        info3 = ImmutableBlockInfo(blk_serial=6, ins_list=(100, 200))

        # Equal objects should have same hash
        assert hash(info1) == hash(info2)
        # Can be used in sets
        s = {info1, info2, info3}
        assert len(s) == 2

    def test_with_prepended_ins(self):
        """Test prepending instruction creates new object."""
        original = ImmutableBlockInfo(blk_serial=5, ins_list=(200, 300))
        new = original.with_prepended_ins(100)

        assert original.ins_list == (200, 300)  # Original unchanged
        assert new.ins_list == (100, 200, 300)  # New has prepended
        assert new.blk_serial == 5

    def test_with_appended_ins(self):
        """Test appending instruction creates new object."""
        original = ImmutableBlockInfo(blk_serial=5, ins_list=(100, 200))
        new = original.with_appended_ins(300)

        assert original.ins_list == (100, 200)  # Original unchanged
        assert new.ins_list == (100, 200, 300)  # New has appended


class TestCachedBlockPath:
    """Tests for CachedBlockPath."""

    def test_empty_path(self):
        """Test empty path."""
        path = CachedBlockPath()
        assert len(path) == 0
        assert path.serials == ()
        assert path.serial_set == frozenset()

    def test_serials_caching(self):
        """Test that serials are cached."""
        blocks = [
            ImmutableBlockInfo(blk_serial=i, ins_list=())
            for i in [5, 10, 15]
        ]
        path = CachedBlockPath(blocks)

        # First access computes
        serials1 = path.serials
        assert serials1 == (5, 10, 15)

        # Second access should use cache (same object)
        serials2 = path.serials
        assert serials1 is serials2

    def test_cache_invalidation_on_prepend(self):
        """Test cache invalidated on prepend."""
        blocks = [ImmutableBlockInfo(blk_serial=5, ins_list=())]
        path = CachedBlockPath(blocks)

        _ = path.serials  # Populate cache
        assert path._serial_cache_valid

        path.prepend(ImmutableBlockInfo(blk_serial=1, ins_list=()))
        assert not path._serial_cache_valid

        assert path.serials == (1, 5)

    def test_cache_invalidation_on_insert(self):
        """Test cache invalidated on insert."""
        blocks = [
            ImmutableBlockInfo(blk_serial=1, ins_list=()),
            ImmutableBlockInfo(blk_serial=5, ins_list=()),
        ]
        path = CachedBlockPath(blocks)

        _ = path.serials  # Populate cache
        path.insert(1, ImmutableBlockInfo(blk_serial=3, ins_list=()))

        assert path.serials == (1, 3, 5)

    def test_contains_serial(self):
        """Test O(1) serial membership check."""
        blocks = [
            ImmutableBlockInfo(blk_serial=i, ins_list=())
            for i in [5, 10, 15, 20]
        ]
        path = CachedBlockPath(blocks)

        assert path.contains_serial(5)
        assert path.contains_serial(10)
        assert path.contains_serial(15)
        assert path.contains_serial(20)
        assert not path.contains_serial(1)
        assert not path.contains_serial(100)

    def test_copy_preserves_cache(self):
        """Test that copy preserves valid cache."""
        blocks = [ImmutableBlockInfo(blk_serial=i, ins_list=()) for i in range(5)]
        path = CachedBlockPath(blocks)

        _ = path.serials  # Populate cache
        path_copy = path.copy()

        # Copy should have valid cache
        assert path_copy._serial_cache_valid
        assert path_copy.serials == path.serials

    def test_copy_independence(self):
        """Test that copy is independent of original."""
        blocks = [ImmutableBlockInfo(blk_serial=i, ins_list=()) for i in range(3)]
        path = CachedBlockPath(blocks)
        path_copy = path.copy()

        # Modify copy
        path_copy.prepend(ImmutableBlockInfo(blk_serial=100, ins_list=()))

        # Original unchanged
        assert path.serials == (0, 1, 2)
        assert path_copy.serials == (100, 0, 1, 2)


class TestMopSet:
    """Tests for MopSet - requires mocking since we can't create real mop_t."""

    def test_empty_set(self):
        """Test empty set."""
        s = MopSet()
        assert len(s) == 0

    def test_copy(self):
        """Test copy creates independent set."""
        s1 = MopSet()
        s2 = s1.copy()

        assert len(s1) == len(s2)
        # Both should be independent (can't test fully without mop_t)


class TestBenchmarks:
    """Tests for benchmark functions."""

    def test_benchmark_block_info_copy_runs(self):
        """Test benchmark function runs without error."""
        result = benchmark_block_info_copy(n_iterations=100)
        assert "iterations" in result
        assert "immutable_ref_time" in result
        assert "shallow_copy_time" in result
        assert "speedup_vs_shallow" in result

    def test_benchmark_cached_path_runs(self):
        """Test benchmark function runs without error."""
        result = benchmark_cached_path(n_iterations=100)
        assert "iterations" in result
        assert "cached_time" in result
        assert "uncached_time" in result
        assert "speedup" in result

    def test_benchmark_shows_speedup(self):
        """Test that benchmarks show expected speedup."""
        # Caching should always be faster
        result = benchmark_cached_path(n_iterations=1000)
        assert result["speedup"] > 1.0, "Caching should provide speedup"

        # Immutable reference should be faster than shallow copy
        result = benchmark_block_info_copy(n_iterations=1000)
        assert result["speedup_vs_shallow"] > 1.0, "Immutable ref should be faster than copy"
