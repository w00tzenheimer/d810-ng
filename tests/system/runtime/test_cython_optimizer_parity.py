"""PR5: Cython/Python backend parity validation for full optimizer stack.

Validates that the Cython and Python backends produce identical results when
running through the complete PatternOptimizer hot path. This is the integration
test for the copycat acceleration project (PR1-PR4).

All tests require IDA Pro with Hex-Rays decompiler.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

import pytest

import ida_hexrays

sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import timed_run

# =========================================================================
# Helpers
# =========================================================================


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


# =========================================================================
# Test: Engine Info & Backend Detection
# =========================================================================


class TestEngineBackendDetection:
    """Verify engine dispatcher correctly reports active backend."""

    @pytest.mark.ida_required
    def test_engine_info_reports_backend(self):
        """get_engine_info() correctly reports which backend is active."""
        from d810.optimizers.microcode.instructions.pattern_matching.engine import get_engine_info

        info = get_engine_info()
        assert "backend" in info
        assert info["backend"] in ("python", "cython")
        assert "cython_mode_enabled" in info
        assert "storage_class" in info
        assert "match_function" in info

        print(f"\n  Active backend: {info['backend']}")
        print(f"  CythonMode enabled: {info['cython_mode_enabled']}")
        print(f"  Storage class: {info['storage_class']}")

    @pytest.mark.ida_required
    def test_using_cython_flag_matches_backend(self):
        """_USING_CYTHON flag matches get_engine_info() backend."""
        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            get_engine_info,
            _USING_CYTHON,
        )

        info = get_engine_info()
        if _USING_CYTHON:
            assert info["backend"] == "cython"
        else:
            assert info["backend"] == "python"


# =========================================================================
# Test: Match-Level Parity (Engine Dispatch)
# =========================================================================


class TestMatchParity:
    """Verify Cython and Python backends produce identical match results."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_match_results_identical_across_backends(self, real_asts, populated_storages):
        """Engine-dispatched match vs forced-Python match produces same results."""
        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            match_pattern_nomut,
            MatchBindings,
        )
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            match_pattern_nomut as py_match_nomut,
            MatchBindings as PyMatchBindings,
        )

        storage = populated_storages["new"]
        bindings = MatchBindings()
        py_bindings = PyMatchBindings()

        mismatches = 0
        total = 0

        for ast, _ in real_asts[:20]:
            if not ast.is_node():
                continue

            candidates = storage.get_candidates(ast)
            for entry in candidates[:5]:
                total += 1
                # Engine-dispatched match (may be Cython or Python)
                engine_result = match_pattern_nomut(entry.pattern, ast, bindings)
                # Forced Python match
                py_result = py_match_nomut(entry.pattern, ast, py_bindings)

                if engine_result != py_result:
                    mismatches += 1
                elif engine_result:
                    # Both matched — verify bindings are equivalent
                    engine_leafs = bindings.get_leafs_by_name()
                    py_leafs = py_bindings.get_leafs_by_name()
                    assert set(engine_leafs.keys()) == set(py_leafs.keys()), (
                        f"Binding name mismatch: {set(engine_leafs.keys())} vs {set(py_leafs.keys())}"
                    )

        assert total > 0, "No match attempts were made"
        assert mismatches == 0, f"{mismatches}/{total} match results differ between backends"

        print(f"\n  Match parity verified: {total} comparisons, 0 mismatches")


# =========================================================================
# Test: Storage-Level Parity
# =========================================================================


class TestStorageParity:
    """Verify OpcodeIndexedStorage produces identical candidates across backends."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_storage_candidates_identical_across_backends(self, real_asts):
        """Engine-dispatched storage vs forced-Python storage returns same candidates."""
        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            OpcodeIndexedStorage,
        )
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            OpcodeIndexedStorage as PyOpcodeIndexedStorage,
        )

        # Collect unique patterns
        unique_patterns = []
        seen_sigs = set()

        for ast, _ in real_asts[:50]:
            if ast.is_node():
                sig = ast.get_pattern()
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    unique_patterns.append(ast)
                    if len(unique_patterns) >= 20:
                        break

        if len(unique_patterns) < 5:
            pytest.skip("Not enough unique patterns for storage parity test")

        # Populate both storages identically
        engine_storage = OpcodeIndexedStorage()
        py_storage = PyOpcodeIndexedStorage()

        rules = []
        for i, pattern in enumerate(unique_patterns):
            class MockRule:
                pass

            rule = MockRule()
            rule.name = f"rule_{i}"
            rules.append(rule)

            engine_storage.add_pattern(pattern, rule)
            py_storage.add_pattern(pattern, rule)

        # Compare candidate sets for all test ASTs
        mismatches = 0
        total = 0

        for ast, _ in real_asts[:50]:
            if not ast.is_node():
                continue

            total += 1
            engine_results = {r.rule.name for r in engine_storage.get_candidates(ast)}
            py_results = {r.rule.name for r in py_storage.get_candidates(ast)}

            if engine_results != py_results:
                mismatches += 1

        assert total > 0, "No ASTs tested"
        assert mismatches == 0, f"{mismatches}/{total} candidate sets differ between backends"

        print(f"\n  Storage parity verified: {total} ASTs, 0 mismatches")


# =========================================================================
# Test: Post-Optimization Performance Capture (for PR0 comparison)
# =========================================================================


class TestPostOptimizationBenchmark:
    """Capture post-PR1-PR4 performance numbers for comparison with PR0 baseline."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_capture_post_optimization_stats(self, real_asts, populated_storages):
        """Measure match performance to compare with PR0 baseline."""
        import time

        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            match_pattern_nomut,
            MatchBindings,
            get_engine_info,
        )

        storage = populated_storages["new"]
        bindings = MatchBindings()
        info = get_engine_info()

        # Measure nomut match throughput
        match_count = 0
        start = time.perf_counter()

        for ast, _ in real_asts[:50]:
            if not ast.is_node():
                continue

            candidates = storage.get_candidates(ast)
            for entry in candidates:
                match_pattern_nomut(entry.pattern, ast, bindings)
                match_count += 1

        elapsed = time.perf_counter() - start

        if match_count > 0:
            us_per_match = (elapsed / match_count) * 1_000_000
            matches_per_sec = match_count / elapsed

            print(f"\n  Post-PR1-PR4 Performance:")
            print(f"    Backend: {info['backend']}")
            print(f"    Match attempts: {match_count}")
            print(f"    us/match: {us_per_match:.4f}")
            print(f"    Matches/sec: {matches_per_sec:.0f}")

            # Verify reasonable performance (not regressed to unusable)
            assert us_per_match < 1000, "Match performance unexpectedly slow (>1ms/match)"
        else:
            pytest.skip("No matches performed, cannot measure performance")

    @pytest.mark.ida_required
    def test_capture_hot_path_throughput(self, real_asts, libobfuscated_setup):
        """Measure full optimizer hot path throughput."""
        import time

        from d810.optimizers.microcode.instructions.pattern_matching.handler import PatternOptimizer
        from d810.optimizers.microcode.instructions.pattern_matching.engine import get_engine_info
        from d810.core import OptimizationStatistics

        stats = OptimizationStatistics()
        optimizer = PatternOptimizer(
            maturities=[ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT],
            stats=stats,
        )

        instructions = [ins for _, ins in real_asts if ins is not None][:100]

        if len(instructions) < 10:
            pytest.skip("Not enough instructions for hot path benchmark")

        class MockBlock:
            def __init__(self):
                class MockMBA:
                    maturity = ida_hexrays.MMAT_PREOPTIMIZED
                self.mba = MockMBA()

        mock_blk = MockBlock()
        info = get_engine_info()

        # Warmup
        for ins in instructions[:5]:
            optimizer.get_optimized_instruction(mock_blk, ins)

        # Measure
        start = time.perf_counter()
        for ins in instructions:
            optimizer.get_optimized_instruction(mock_blk, ins)
        elapsed = time.perf_counter() - start

        us_per_instruction = (elapsed / len(instructions)) * 1_000_000
        throughput = len(instructions) / elapsed

        print(f"\n  Hot Path Performance:")
        print(f"    Backend: {info['backend']}")
        print(f"    Instructions: {len(instructions)}")
        print(f"    us/instruction: {us_per_instruction:.4f}")
        print(f"    Throughput: {throughput:.0f} insns/sec")

        # Sanity check: should be able to process thousands of instructions per second
        assert throughput > 100, "Throughput unexpectedly low (<100 insns/sec)"
