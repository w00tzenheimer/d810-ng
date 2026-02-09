"""Unit tests for d810.speedups.c_simd -- Cython SIMD utilities."""

import pytest

# Try importing Cython version
try:
    from d810.speedups.c_simd import (
        simd_best_level,
        tzcnt32,
        cy_mem_eq_16,
        cy_mem_eq_32,
        cy_hash_u64,
        cy_hash_combine,
        SIMD_SCALAR,
        SIMD_SSE2,
        SIMD_AVX2,
        SIMD_NEON,
    )
    HAS_CYTHON = True
except ImportError:
    HAS_CYTHON = False

pytestmark = pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")


class TestSimdBestLevel:
    """Test simd_best_level()."""

    def test_returns_valid_level(self):
        level = simd_best_level()
        assert level in (SIMD_SCALAR, SIMD_SSE2, SIMD_AVX2, SIMD_NEON)


class TestTzcnt32:
    """Test tzcnt32()."""

    @pytest.mark.parametrize("x, expected", [
        (0, 32),
        (1, 0),
        (2, 1),
        (4, 2),
        (8, 3),
        (0x80000000, 31),
        (0b10100, 2),
        (0x10, 4),
        (0xFF00, 8),
    ])
    def test_tzcnt32(self, x, expected):
        assert tzcnt32(x) == expected


class TestMemEq:
    """Test cy_mem_eq_16 and cy_mem_eq_32."""

    def test_mem_eq_16_equal(self):
        data = b"\x42" * 16
        assert cy_mem_eq_16(data, data) is True

    def test_mem_eq_16_not_equal(self):
        a = b"\x42" * 16
        b = b"\x42" * 15 + b"\x43"
        assert cy_mem_eq_16(a, b) is False

    def test_mem_eq_16_too_short(self):
        with pytest.raises(ValueError, match="16 bytes"):
            cy_mem_eq_16(b"\x00" * 15, b"\x00" * 16)

    def test_mem_eq_32_equal(self):
        data = b"\xAB" * 32
        assert cy_mem_eq_32(data, data) is True

    def test_mem_eq_32_not_equal(self):
        a = b"\xAB" * 32
        b = b"\xAB" * 31 + b"\xCD"
        assert cy_mem_eq_32(a, b) is False

    def test_mem_eq_32_too_short(self):
        with pytest.raises(ValueError, match="32 bytes"):
            cy_mem_eq_32(b"\x00" * 31, b"\x00" * 32)

    def test_mem_eq_16_longer_buffers(self):
        """Only first 16 bytes matter."""
        a = b"\x42" * 16 + b"\xFF" * 16
        b = b"\x42" * 16 + b"\x00" * 16
        assert cy_mem_eq_16(a, b) is True


class TestHashU64:
    """Test cy_hash_u64 Murmur3 finalizer."""

    def test_zero(self):
        result = cy_hash_u64(0)
        assert isinstance(result, int)
        assert 0 <= result < 2**64

    def test_deterministic(self):
        assert cy_hash_u64(42) == cy_hash_u64(42)

    def test_avalanche(self):
        """Different inputs should produce very different hashes."""
        h1 = cy_hash_u64(0)
        h2 = cy_hash_u64(1)
        # Hamming distance should be roughly 32 for good avalanche
        diff = bin(h1 ^ h2).count("1")
        assert diff > 16, f"Poor avalanche: only {diff} bits differ"


class TestHashCombine:
    """Test cy_hash_combine (boost-style)."""

    def test_deterministic(self):
        assert cy_hash_combine(1, 2) == cy_hash_combine(1, 2)

    def test_non_commutative(self):
        """hash_combine(a, b) != hash_combine(b, a) for most inputs."""
        assert cy_hash_combine(1, 2) != cy_hash_combine(2, 1)

    def test_range(self):
        result = cy_hash_combine(0xDEAD, 0xBEEF)
        assert 0 <= result < 2**64
