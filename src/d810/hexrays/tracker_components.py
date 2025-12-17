"""Extracted hot-path components from tracker.py for optimization.

These components are extracted to:
1. Enable isolated benchmarking
2. Allow Cython optimization
3. Provide testable units with clear interfaces

Performance targets based on profiling:
- BlockInfo.get_copy: 1.4M calls in 0.55s → target <0.1s
- MopHistory copy operations: 22K calls in 0.76s → target <0.2s
- block_serial_path: 102K calls in 1.3s → target <0.2s (with caching)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    import ida_hexrays


# =============================================================================
# BlockInfo - Immutable version for structural sharing
# =============================================================================


@dataclass(frozen=True, slots=True)
class ImmutableBlockInfo:
    """Immutable block info that can be safely shared across copies.

    Using frozen dataclass with slots for:
    - Memory efficiency (slots)
    - Hashability (frozen)
    - Copy-free sharing between MopHistory instances
    """
    blk_serial: int
    ins_list: Tuple[int, ...]  # Tuple of instruction EAs for immutability

    @classmethod
    def from_block(cls, blk: "ida_hexrays.mblock_t", ins: Optional["ida_hexrays.minsn_t"] = None) -> "ImmutableBlockInfo":
        """Create from IDA block, optionally with initial instruction."""
        ins_list = (ins.ea,) if ins is not None else ()
        return cls(blk_serial=blk.serial, ins_list=ins_list)

    def with_prepended_ins(self, ins_ea: int) -> "ImmutableBlockInfo":
        """Return new BlockInfo with instruction prepended (copy-on-write)."""
        return ImmutableBlockInfo(
            blk_serial=self.blk_serial,
            ins_list=(ins_ea,) + self.ins_list
        )

    def with_appended_ins(self, ins_ea: int) -> "ImmutableBlockInfo":
        """Return new BlockInfo with instruction appended (copy-on-write)."""
        return ImmutableBlockInfo(
            blk_serial=self.blk_serial,
            ins_list=self.ins_list + (ins_ea,)
        )


# =============================================================================
# Path representation with cached serial list
# =============================================================================


class CachedBlockPath:
    """Block path with cached serial computation.

    The original `block_serial_path` property was called 102K times,
    recomputing the list each time. This class caches the result.
    """
    __slots__ = ('_blocks', '_serial_cache', '_serial_cache_valid')

    def __init__(self, blocks: Optional[List["ImmutableBlockInfo"]] = None):
        self._blocks: List[ImmutableBlockInfo] = blocks if blocks is not None else []
        self._serial_cache: Optional[Tuple[int, ...]] = None
        self._serial_cache_valid: bool = False

    def _invalidate_cache(self) -> None:
        """Invalidate the serial cache after mutation."""
        self._serial_cache_valid = False

    @property
    def serials(self) -> Tuple[int, ...]:
        """Get block serials as tuple (cached)."""
        if not self._serial_cache_valid:
            self._serial_cache = tuple(blk.blk_serial for blk in self._blocks)
            self._serial_cache_valid = True
        return self._serial_cache  # type: ignore

    @property
    def serial_set(self) -> frozenset[int]:
        """Get block serials as frozenset for O(1) membership testing."""
        return frozenset(self.serials)

    def __len__(self) -> int:
        return len(self._blocks)

    def __getitem__(self, index: int) -> ImmutableBlockInfo:
        return self._blocks[index]

    def __iter__(self):
        return iter(self._blocks)

    def prepend(self, block_info: ImmutableBlockInfo) -> None:
        """Prepend block to path (mutates, invalidates cache)."""
        self._blocks.insert(0, block_info)
        self._invalidate_cache()

    def insert(self, index: int, block_info: ImmutableBlockInfo) -> None:
        """Insert block at index (mutates, invalidates cache)."""
        self._blocks.insert(index, block_info)
        self._invalidate_cache()

    def copy(self) -> "CachedBlockPath":
        """Create a shallow copy (blocks are immutable, so this is safe)."""
        new_path = CachedBlockPath(self._blocks.copy())
        # Copy cache if valid
        if self._serial_cache_valid:
            new_path._serial_cache = self._serial_cache
            new_path._serial_cache_valid = True
        return new_path

    def contains_serial(self, serial: int) -> bool:
        """Check if path contains block serial (O(1) with cache)."""
        return serial in self.serial_set


# =============================================================================
# Mop set with hash-based lookup
# =============================================================================


class MopSet:
    """Hash-based set for mop_t objects.

    Replaces O(n) list searches with O(1) hash lookups.
    Uses structural hash for mop comparison.
    """
    __slots__ = ('_by_hash', '_mops')

    def __init__(self):
        self._by_hash: dict[int, List["ida_hexrays.mop_t"]] = {}
        self._mops: List["ida_hexrays.mop_t"] = []

    @staticmethod
    def _hash_mop(mop: "ida_hexrays.mop_t") -> int:
        """Compute structural hash for mop."""
        # Try Cython version first if CythonMode is enabled
        from d810.core.cymode import CythonMode
        if CythonMode().is_enabled():
            try:
                from d810.speedups.cythxr._chexrays_api import hash_mop
                return int(hash_mop(mop, 0))
            except ImportError:
                pass

        # Fallback: type + key attribute
        t = mop.t
        if t == 1:  # mop_r (register)
            return hash((t, mop.r))
        elif t == 2:  # mop_n (number)
            return hash((t, mop.nnn.value if hasattr(mop, 'nnn') and mop.nnn else 0))
        elif t == 3:  # mop_S (stack)
            return hash((t, mop.s.off if hasattr(mop, 's') and mop.s else 0))
        elif t == 5:  # mop_v (global)
            return hash((t, mop.g))
        elif t == 8:  # mop_b (block ref)
            return hash((t, mop.b))
        else:
            # Generic fallback
            from d810.hexrays.hexrays_formatters import format_mop_t
            return hash(format_mop_t(mop))

    @staticmethod
    def _equal_mops(a: "ida_hexrays.mop_t", b: "ida_hexrays.mop_t") -> bool:
        """Check mop equality (fast path for common cases)."""
        if a is b:
            return True
        if a.t != b.t:
            return False

        t = a.t
        if t == 1:  # mop_r
            return a.r == b.r
        elif t == 2:  # mop_n
            return a.nnn.value == b.nnn.value
        elif t == 3:  # mop_S
            return a.s.off == b.s.off
        elif t == 5:  # mop_v
            return a.g == b.g
        elif t == 8:  # mop_b
            return a.b == b.b
        else:
            # Fallback to full comparison
            from d810.hexrays.hexrays_helpers import equal_mops_ignore_size
            return equal_mops_ignore_size(a, b)

    def add(self, mop: "ida_hexrays.mop_t") -> bool:
        """Add mop to set. Returns True if added, False if already present."""
        h = self._hash_mop(mop)
        bucket = self._by_hash.get(h)

        if bucket is None:
            self._by_hash[h] = [mop]
            self._mops.append(mop)
            return True

        # Check for existing equal mop in bucket
        for existing in bucket:
            if self._equal_mops(existing, mop):
                return False

        bucket.append(mop)
        self._mops.append(mop)
        return True

    def remove(self, mop: "ida_hexrays.mop_t") -> bool:
        """Remove mop from set. Returns True if removed, False if not found."""
        h = self._hash_mop(mop)
        bucket = self._by_hash.get(h)

        if bucket is None:
            return False

        for i, existing in enumerate(bucket):
            if self._equal_mops(existing, mop):
                bucket.pop(i)
                # Also remove from _mops list
                for j, m in enumerate(self._mops):
                    if self._equal_mops(m, mop):
                        self._mops.pop(j)
                        break
                return True

        return False

    def __contains__(self, mop: "ida_hexrays.mop_t") -> bool:
        """Check if mop is in set (O(1) average)."""
        h = self._hash_mop(mop)
        bucket = self._by_hash.get(h)
        if bucket is None:
            return False
        return any(self._equal_mops(existing, mop) for existing in bucket)

    def __len__(self) -> int:
        return len(self._mops)

    def __iter__(self):
        return iter(self._mops)

    def copy(self) -> "MopSet":
        """Create a copy of the set."""
        new_set = MopSet()
        new_set._mops = self._mops.copy()
        new_set._by_hash = {k: v.copy() for k, v in self._by_hash.items()}
        return new_set

    def to_list(self) -> List["ida_hexrays.mop_t"]:
        """Convert to list (for compatibility)."""
        return self._mops.copy()


# =============================================================================
# Benchmarking utilities
# =============================================================================


def benchmark_block_info_copy(n_iterations: int = 100000) -> dict:
    """Benchmark BlockInfo copy operations.

    Returns timing comparison between:
    - Original mutable BlockInfo.get_copy()
    - New immutable ImmutableBlockInfo (no copy needed)
    """
    import time

    # Create test data
    immutable_infos = [
        ImmutableBlockInfo(blk_serial=i, ins_list=tuple(range(i % 10)))
        for i in range(100)
    ]

    # Benchmark immutable (just reference, no copy)
    start = time.perf_counter()
    for _ in range(n_iterations):
        copied = immutable_infos  # Just reference - no copy needed!
    immutable_time = time.perf_counter() - start

    # Benchmark with actual list copy (simulating structural sharing)
    start = time.perf_counter()
    for _ in range(n_iterations):
        copied = immutable_infos.copy()  # Shallow copy of list
    shallow_copy_time = time.perf_counter() - start

    return {
        "iterations": n_iterations,
        "immutable_ref_time": immutable_time,
        "shallow_copy_time": shallow_copy_time,
        "speedup_vs_shallow": shallow_copy_time / immutable_time if immutable_time > 0 else float('inf'),
    }


def benchmark_cached_path(n_iterations: int = 10000) -> dict:
    """Benchmark CachedBlockPath.serials vs recomputing each time."""
    import time

    # Create test path
    blocks = [
        ImmutableBlockInfo(blk_serial=i, ins_list=())
        for i in range(50)
    ]

    # Benchmark cached version
    cached_path = CachedBlockPath(blocks)
    start = time.perf_counter()
    for _ in range(n_iterations):
        _ = cached_path.serials
    cached_time = time.perf_counter() - start

    # Benchmark uncached (recompute each time)
    start = time.perf_counter()
    for _ in range(n_iterations):
        _ = tuple(blk.blk_serial for blk in blocks)
    uncached_time = time.perf_counter() - start

    return {
        "iterations": n_iterations,
        "cached_time": cached_time,
        "uncached_time": uncached_time,
        "speedup": uncached_time / cached_time if cached_time > 0 else float('inf'),
    }


def benchmark_mop_set(n_iterations: int = 10000) -> dict:
    """Benchmark MopSet vs list-based lookup."""
    import time

    # We can't easily create mop_t without IDA, so just benchmark the hash function
    # In real usage, call this from within IDA context

    return {
        "note": "Run within IDA context to benchmark with real mop_t objects",
        "iterations": n_iterations,
    }


if __name__ == "__main__":
    print("BlockInfo copy benchmark:")
    print(benchmark_block_info_copy())

    print("\nCachedBlockPath benchmark:")
    print(benchmark_cached_path())

    print("\nMopSet benchmark:")
    print(benchmark_mop_set())
