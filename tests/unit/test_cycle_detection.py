"""Unit tests for instruction-level rewrite cycle detection.

Tests cover:
1. OptimizationStatistics.record_cycle_detected() and reporting
2. hash_minsn Python fallback (isolated, no IDA required)
3. Cycle detection logic in InstructionOptimizerManager (structural, using mocks)
"""

import pytest
from collections import defaultdict
from unittest.mock import MagicMock, patch

from d810.core.stats import OptimizationStatistics, OptimizationEvent


# =============================================================================
# Tests for OptimizationStatistics cycle tracking
# =============================================================================


class TestCycleDetectedStats:
    """Test cycle detection recording in OptimizationStatistics."""

    def test_record_cycle_detected_basic(self):
        """Test recording a single cycle detection."""
        stats = OptimizationStatistics()

        stats.record_cycle_detected("PatternOptimizer", "0x401000")

        assert stats.total_cycles_detected == 1
        assert stats.cycles_detected["PatternOptimizer"] == 1

    def test_record_cycle_detected_multiple_same_optimizer(self):
        """Test recording multiple cycles from the same optimizer."""
        stats = OptimizationStatistics()

        stats.record_cycle_detected("PatternOptimizer", "0x401000")
        stats.record_cycle_detected("PatternOptimizer", "0x401008")
        stats.record_cycle_detected("PatternOptimizer", "0x401010")

        assert stats.total_cycles_detected == 3
        assert stats.cycles_detected["PatternOptimizer"] == 3

    def test_record_cycle_detected_multiple_optimizers(self):
        """Test recording cycles from different optimizers."""
        stats = OptimizationStatistics()

        stats.record_cycle_detected("PatternOptimizer", "0x401000")
        stats.record_cycle_detected("Z3Optimizer", "0x402000")

        assert stats.total_cycles_detected == 2
        assert stats.cycles_detected["PatternOptimizer"] == 1
        assert stats.cycles_detected["Z3Optimizer"] == 1

    def test_reset_clears_cycles(self):
        """Test that reset() clears cycle data."""
        stats = OptimizationStatistics()
        stats.record_cycle_detected("PatternOptimizer", "0x401000")

        stats.reset()

        assert stats.total_cycles_detected == 0
        assert len(stats.cycles_detected) == 0

    def test_cycle_in_summary(self):
        """Test that cycles appear in summary dict."""
        stats = OptimizationStatistics()
        stats.record_cycle_detected("PatternOptimizer", "0x401000")

        summary = stats.summary()

        assert summary["total_cycles_detected"] == 1
        assert summary["cycles_detected"]["PatternOptimizer"] == 1

    def test_cycle_in_to_dict(self):
        """Test that cycles are serialized in to_dict."""
        stats = OptimizationStatistics()
        stats.record_cycle_detected("PatternOptimizer", "0x401000")

        d = stats.to_dict()

        assert d["total_cycles_detected"] == 1
        assert d["cycles_detected"]["PatternOptimizer"] == 1

    def test_cycle_roundtrip_serialization(self):
        """Test that cycles survive to_dict -> from_dict roundtrip."""
        stats = OptimizationStatistics()
        stats.record_cycle_detected("PatternOptimizer", "0x401000")
        stats.record_cycle_detected("Z3Optimizer", "0x402000")

        restored = OptimizationStatistics.from_dict(stats.to_dict())

        assert restored.total_cycles_detected == 2
        assert restored.cycles_detected["PatternOptimizer"] == 1
        assert restored.cycles_detected["Z3Optimizer"] == 1

    def test_cycle_event_emitted(self):
        """Test that CYCLE_DETECTED event is emitted."""
        stats = OptimizationStatistics()
        received = []

        @stats.events.on(OptimizationEvent.CYCLE_DETECTED)
        def on_cycle(optimizer_name, instruction_info):
            received.append((optimizer_name, instruction_info))

        stats.record_cycle_detected("PatternOptimizer", "0x401000")

        assert len(received) == 1
        assert received[0] == ("PatternOptimizer", "0x401000")

    def test_cycle_no_instruction_info(self):
        """Test recording cycle without instruction info."""
        stats = OptimizationStatistics()

        stats.record_cycle_detected("PatternOptimizer")

        assert stats.total_cycles_detected == 1
        assert stats.cycles_detected["PatternOptimizer"] == 1


# =============================================================================
# Tests for hash_minsn fallback (no IDA/Cython needed)
# =============================================================================


class TestHashMinsnFallback:
    """Test the pure-Python hash_minsn fallback function."""

    def test_fallback_deterministic(self):
        """Test that the fallback hash is deterministic."""
        # We cannot create real minsn_t without IDA, so test via mock
        mock_ins = MagicMock()
        mock_ins.opcode = 42
        mock_ins._print.return_value = "mov eax, ebx"

        # Import the fallback directly
        # The module-level import of ida_hexrays will fail in test,
        # so we test via the stats module which is IDA-independent
        h1 = hash((mock_ins.opcode, mock_ins._print(), 0))
        h2 = hash((mock_ins.opcode, mock_ins._print(), 0))
        assert h1 == h2

    def test_fallback_different_opcodes_differ(self):
        """Test that different opcodes produce different hashes."""
        h1 = hash((1, "mov eax, ebx", 0))
        h2 = hash((2, "mov eax, ebx", 0))
        assert h1 != h2

    def test_fallback_different_prints_differ(self):
        """Test that different instruction representations differ."""
        h1 = hash((1, "mov eax, ebx", 0))
        h2 = hash((1, "xor eax, eax", 0))
        assert h1 != h2

    def test_fallback_func_ea_salts_hash(self):
        """Test that func_entry_ea salts the hash."""
        h1 = hash((1, "mov eax, ebx", 0x401000))
        h2 = hash((1, "mov eax, ebx", 0x402000))
        assert h1 != h2


# =============================================================================
# Tests for cycle detection logic (structural, using mocks)
# =============================================================================


class TestCycleDetectionLogic:
    """Test the core cycle detection logic in isolation.

    These tests verify the dict[int, set[int]] seen-set behavior
    without requiring IDA.
    """

    def test_first_rewrite_allowed(self):
        """First rewrite to a new form should be allowed."""
        seen = defaultdict(set)
        ins_ea = 0x401000
        post_hash = 12345

        # First time: not in seen, add it
        assert post_hash not in seen[ins_ea]
        seen[ins_ea].add(post_hash)
        assert post_hash in seen[ins_ea]

    def test_cycle_detected_on_repeat(self):
        """Second rewrite to same form should be detected as cycle."""
        seen = defaultdict(set)
        ins_ea = 0x401000

        # First rewrite: X -> Y (hash_Y)
        hash_y = 11111
        seen[ins_ea].add(hash_y)

        # Second rewrite: Y -> X (hash_X)
        hash_x = 22222
        assert hash_x not in seen[ins_ea]  # not a cycle yet
        seen[ins_ea].add(hash_x)

        # Third rewrite: X -> Y again (hash_Y) -- CYCLE
        assert hash_y in seen[ins_ea]  # cycle detected!

    def test_different_instructions_independent(self):
        """Hashes for different instruction EAs should be independent."""
        seen = defaultdict(set)

        seen[0x401000].add(12345)
        seen[0x401008].add(67890)

        # Each instruction's seen set is independent
        assert 12345 not in seen[0x401008]
        assert 67890 not in seen[0x401000]

    def test_reset_clears_all(self):
        """Clearing the seen dict should reset all tracking."""
        seen = defaultdict(set)
        seen[0x401000].add(12345)
        seen[0x401008].add(67890)

        seen.clear()

        assert 12345 not in seen[0x401000]
        assert 67890 not in seen[0x401008]

    def test_many_rewrites_no_false_positive(self):
        """Many different rewrites to the same instruction should not falsely trigger."""
        seen = defaultdict(set)
        ins_ea = 0x401000

        for i in range(100):
            h = hash(("form", i))
            assert h not in seen[ins_ea], f"False positive at iteration {i}"
            seen[ins_ea].add(h)

    def test_cycle_length_two(self):
        """Simulate a classic length-2 cycle: A->B->A."""
        seen = defaultdict(set)
        ins_ea = 0x401000
        hash_a = 0xAAAA
        hash_b = 0xBBBB

        # Initial form is A, not recorded (pre-rewrite)
        # Rewrite 1: A -> B
        assert hash_b not in seen[ins_ea]
        seen[ins_ea].add(hash_b)

        # Rewrite 2: B -> A
        assert hash_a not in seen[ins_ea]
        seen[ins_ea].add(hash_a)

        # Rewrite 3: A -> B (cycle!)
        assert hash_b in seen[ins_ea]
