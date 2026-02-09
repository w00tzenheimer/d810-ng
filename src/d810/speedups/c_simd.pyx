# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Cython wrappers for d810_simd.h portable SIMD utilities.

Exposes: simd_best_level, tzcnt32, mem_eq_16, mem_eq_32, hash_u64, hash_combine
"""

from d810.speedups.c_simd cimport (
    D810SimdLevel, d810_simd_best_level, d810_tzcnt32,
    mem_eq_16 as c_mem_eq_16, mem_eq_32 as c_mem_eq_32,
    hash_u64 as c_hash_u64, hash_combine as c_hash_combine,
)


# Re-export enum values as module-level constants
SIMD_BEST_SUPPORTED = D810_SIMD_BEST_SUPPORTED
SIMD_SCALAR = D810_SIMD_SCALAR
SIMD_SSE2 = D810_SIMD_SSE2
SIMD_AVX2 = D810_SIMD_AVX2
SIMD_NEON = D810_SIMD_NEON


def simd_best_level() -> int:
    """Return the best SIMD level supported by the current CPU.

    Returns one of: SIMD_SCALAR, SIMD_SSE2, SIMD_AVX2, SIMD_NEON.
    """
    return <int>d810_simd_best_level()


def tzcnt32(unsigned int x) -> int:
    """Count trailing zeros in a 32-bit integer.

    Returns 32 if x == 0.
    """
    return d810_tzcnt32(x)


def cy_mem_eq_16(bytes a, bytes b) -> bool:
    """Compare 16 bytes for equality using SIMD (SSE2/NEON/scalar).

    Both arguments must be exactly 16 bytes.
    """
    if len(a) < 16 or len(b) < 16:
        raise ValueError(f"mem_eq_16 requires 16 bytes each, got {len(a)} and {len(b)}")
    return c_mem_eq_16(<const char *>a, <const char *>b)


def cy_mem_eq_32(bytes a, bytes b) -> bool:
    """Compare 32 bytes for equality using SIMD (AVX2/2xSSE2/scalar).

    Both arguments must be exactly 32 bytes.
    """
    if len(a) < 32 or len(b) < 32:
        raise ValueError(f"mem_eq_32 requires 32 bytes each, got {len(a)} and {len(b)}")
    return c_mem_eq_32(<const char *>a, <const char *>b)


def cy_hash_u64(unsigned long long x) -> int:
    """Murmur3 finalizer for 64-bit integers."""
    return c_hash_u64(x)


def cy_hash_combine(unsigned long long h1, unsigned long long h2) -> int:
    """Boost-style hash combine with golden ratio constant."""
    return c_hash_combine(h1, h2)
