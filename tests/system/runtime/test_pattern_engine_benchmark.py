"""Benchmark tests for pattern matching engine performance.

Measures baseline performance of pattern storage, lookup, matching, and
full hot path optimization. Uses real microcode ASTs from test binaries.

All tests require IDA Pro with Hex-Rays decompiler.
"""

from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.expr.p_ast import AstLeaf, AstNode, minsn_to_ast
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternStorage,
)
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    OpcodeIndexedStorage,
    compute_fingerprint,
    match_pattern_nomut,
    MatchBindings,
)

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import timed_run, save_baseline


# =========================================================================
# Helpers (reused from test_pattern_speedups.py)
# =========================================================================


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int):
    """Generate microcode at a specific maturity level."""
    func = idaapi.get_func(func_ea)
    if func is None:
        return None

    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
    )
    return mba


def collect_real_asts_from_mba(mba) -> list:
    """Walk all blocks in an mba_t and convert each minsn_t to an AST."""
    results = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ins = blk.head
        while ins is not None:
            try:
                ast = minsn_to_ast(ins)
                if ast is not None:
                    results.append((ast, ins))
            except Exception:
                pass
            ins = ins.next
    return results


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


@pytest.fixture(scope="class")
def real_asts(libobfuscated_setup):
    """Class-scoped fixture providing real AST trees from microcode."""
    test_functions = [
        "test_cst_simplification",
        "test_xor",
        "test_mba_guessing",
        "test_chained_add",
        "test_opaque_predicate",
    ]

    all_asts = []
    for func_name in test_functions:
        func_ea = get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            continue

        for maturity in [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
        ]:
            mba = gen_microcode_at_maturity(func_ea, maturity)
            if mba is None:
                continue

            asts = collect_real_asts_from_mba(mba)
            all_asts.extend(asts)

    if len(all_asts) < 10:
        pytest.skip("Could not collect enough ASTs from test functions")

    print(f"\n  Collected {len(all_asts)} total ASTs from {len(test_functions)} functions")
    return all_asts


# =========================================================================
# Test: Storage Parity Oracle
# =========================================================================


class TestStorageParity:
    """Verify PatternStorage and OpcodeIndexedStorage return identical candidates."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def populated_storages(self, real_asts):
        """Create PatternStorage and OpcodeIndexedStorage with same patterns."""
        unique_patterns = []
        seen_sigs = set()

        for ast, _ in real_asts:
            if ast.is_node():
                sig = ast.get_pattern()
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    unique_patterns.append(ast)
                    if len(unique_patterns) >= 20:
                        break

        if len(unique_patterns) < 5:
            pytest.skip("Not enough unique patterns found in real ASTs")

        legacy_storage = PatternStorage(depth=1)
        new_storage = OpcodeIndexedStorage()

        rules = []
        for i, pattern in enumerate(unique_patterns):
            class MockRule:
                pass

            rule = MockRule()
            rule.name = f"test_rule_{i}"
            rules.append(rule)

            legacy_storage.add_pattern_for_rule(pattern, rule)
            new_storage.add_pattern(pattern, rule)

        print(f"\n  Registered {len(unique_patterns)} patterns in both storages")
        return legacy_storage, new_storage, unique_patterns

    @pytest.mark.ida_required
    def test_candidate_sets_identical(self, real_asts, populated_storages):
        """For every real AST, both storages return the same rule set."""
        legacy_storage, new_storage, _ = populated_storages

        tested = 0
        for ast, _ in real_asts[:50]:
            if not ast.is_node():
                continue

            legacy_results = legacy_storage.get_matching_rule_pattern_info(ast)
            legacy_rule_names = {rpi.rule.name for rpi in legacy_results}

            new_results = new_storage.get_candidates(ast)
            new_rule_names = {entry.rule.name for entry in new_results}

            assert legacy_rule_names == new_rule_names, (
                f"Mismatch for AST {ast.get_pattern()}: "
                f"legacy={legacy_rule_names}, new={new_rule_names}"
            )
            tested += 1

        assert tested > 0, "Expected to test at least one AST node"
        print(f"\n  Parity verified for {tested} AST candidates")

    @pytest.mark.ida_required
    def test_candidate_ordering_consistent(self, real_asts, populated_storages):
        """Verify ordering is deterministic across repeated calls."""
        legacy_storage, new_storage, _ = populated_storages

        test_ast = None
        for ast, _ in real_asts:
            if ast.is_node():
                results = new_storage.get_candidates(ast)
                if len(results) >= 2:
                    test_ast = ast
                    break

        if test_ast is None:
            pytest.skip("No AST with multiple matches found")

        call1 = new_storage.get_candidates(test_ast)
        call2 = new_storage.get_candidates(test_ast)

        names1 = [e.rule.name for e in call1]
        names2 = [e.rule.name for e in call2]

        assert names1 == names2, "Ordering must be deterministic"


# =========================================================================
# Test: Cython/Python Parity
# =========================================================================


# Detect whether the Cython extension is available
try:
    from d810.speedups.optimizers.c_pattern_match import (
        compute_fingerprint_py as cython_compute_fingerprint,
        match_pattern_nomut as cython_match_pattern_nomut,
        COpcodeIndexedStorage,
    )
    HAS_CYTHON = True
except ImportError:
    HAS_CYTHON = False


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonPythonParity:
    """Verify Cython implementations match pure-Python outputs exactly."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_fingerprint_parity(self, real_asts):
        """compute_fingerprint results match between Cython and Python."""
        tested = 0
        for ast, _ in real_asts[:20]:
            if not ast.is_node():
                continue

            py_fp = compute_fingerprint(ast)
            cy_fp = cython_compute_fingerprint(ast)

            assert py_fp.depth == cy_fp["depth"], "depth mismatch"
            assert py_fp.node_count == cy_fp["node_count"], "node_count mismatch"
            assert py_fp.leaf_count == cy_fp["leaf_count"], "leaf_count mismatch"
            assert py_fp.const_count == cy_fp["const_count"], "const_count mismatch"
            assert py_fp.opcode_hash == cy_fp["opcode_hash"], "opcode_hash mismatch"
            tested += 1

        assert tested > 0
        print(f"\n  Fingerprint parity verified for {tested} ASTs")

    @pytest.mark.ida_required
    def test_match_parity(self, real_asts):
        """match_pattern_nomut results match between Cython and Python."""
        tested = 0
        for ast, _ in real_asts[:20]:
            if not ast.is_node():
                continue

            pattern = AstNode(ast.opcode, AstLeaf("x_0"), AstLeaf("y_0"))

            py_result = match_pattern_nomut(pattern, ast)
            cy_result = cython_match_pattern_nomut(pattern, ast)

            assert py_result == cy_result, (
                f"Match result differs for opcode {ast.opcode}: "
                f"Python={py_result}, Cython={cy_result}"
            )
            tested += 1

        assert tested > 0
        print(f"\n  Match parity verified for {tested} ASTs")

    @pytest.mark.ida_required
    def test_storage_parity(self, real_asts):
        """OpcodeIndexedStorage results match between Cython and Python."""
        py_storage = OpcodeIndexedStorage()
        cy_storage = COpcodeIndexedStorage()

        patterns = []
        for i, (ast, _) in enumerate(real_asts[:10]):
            if ast.is_node():
                class MockRule:
                    pass

                rule = MockRule()
                rule.name = f"rule_{i}"
                py_storage.add_pattern(ast, rule)
                cy_storage.add_pattern(ast, rule)
                patterns.append(ast)

        for ast in patterns:
            py_results = {r.rule.name for r in py_storage.get_candidates(ast)}
            cy_results = {r.rule.name for r in cy_storage.get_candidates(ast)}

            assert py_results == cy_results, (
                f"Storage results differ: Python={py_results}, Cython={cy_results}"
            )

        print(f"\n  Storage parity verified for {len(patterns)} patterns")


# =========================================================================
# Test: Registration Benchmark
# =========================================================================


class TestRegistrationBenchmark:
    """Benchmark pattern storage registration performance."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_registration_performance(self, real_asts):
        """Benchmark populating storage from patterns."""
        unique_patterns = []
        seen_sigs = set()

        for ast, _ in real_asts[:200]:
            if ast.is_node():
                sig = ast.get_pattern()
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    unique_patterns.append(ast)
                    if len(unique_patterns) >= 100:
                        break

        if len(unique_patterns) < 20:
            pytest.skip("Not enough unique patterns for benchmarking")

        rules = []
        for i in range(len(unique_patterns)):
            class MockRule:
                pass
            rule = MockRule()
            rule.name = f"rule_{i}"
            rules.append(rule)

        def populate_legacy():
            storage = PatternStorage(depth=1)
            for pattern, rule in zip(unique_patterns, rules):
                storage.add_pattern_for_rule(pattern, rule)
            return storage

        legacy_time = timed_run(populate_legacy, iterations=10, warmup=2)

        def populate_new():
            storage = OpcodeIndexedStorage()
            for pattern, rule in zip(unique_patterns, rules):
                storage.add_pattern(pattern, rule)
            return storage

        new_time = timed_run(populate_new, iterations=10, warmup=2)

        print(f"\n  Registration ({len(unique_patterns)} patterns):")
        print(f"    Legacy: {legacy_time * 1000:.2f} ms")
        print(f"    New:    {new_time * 1000:.2f} ms")
        print(f"    Speedup: {legacy_time / new_time:.2f}x")


# =========================================================================
# Test: Lookup Benchmarks (Hit + Miss)
# =========================================================================


class TestLookupBenchmark:
    """Benchmark pattern lookup performance (hit and miss cases)."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def lookup_fixtures(self, real_asts):
        """Prepare storages and test ASTs for lookup benchmarks."""
        unique_patterns = []
        seen_sigs = set()

        for ast, _ in real_asts[:200]:
            if ast.is_node():
                sig = ast.get_pattern()
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    unique_patterns.append(ast)
                    if len(unique_patterns) >= 50:
                        break

        if len(unique_patterns) < 10:
            pytest.skip("Not enough patterns for lookup benchmark")

        legacy_storage = PatternStorage(depth=1)
        new_storage = OpcodeIndexedStorage()

        for i, pattern in enumerate(unique_patterns):
            class MockRule:
                pass
            rule = MockRule()
            rule.name = f"rule_{i}"
            legacy_storage.add_pattern_for_rule(pattern, rule)
            new_storage.add_pattern(pattern, rule)

        hit_asts = unique_patterns[:10]

        pattern_opcodes = {p.opcode for p in unique_patterns if p.is_node()}
        miss_asts = []
        for ast, _ in real_asts:
            if ast.is_node() and ast.opcode not in pattern_opcodes:
                miss_asts.append(ast)
                if len(miss_asts) >= 10:
                    break

        return legacy_storage, new_storage, hit_asts, miss_asts

    @pytest.mark.ida_required
    def test_lookup_hit_legacy(self, lookup_fixtures):
        """Benchmark PatternStorage lookups for matching ASTs."""
        legacy_storage, _, hit_asts, _ = lookup_fixtures

        if not hit_asts:
            pytest.skip("No hit ASTs available")

        def lookup_all():
            for ast in hit_asts:
                _ = legacy_storage.get_matching_rule_pattern_info(ast)

        elapsed = timed_run(lookup_all, iterations=100, warmup=10)
        per_lookup = (elapsed / 100 / len(hit_asts)) * 1_000_000

        print(f"\n  Lookup (hit, legacy): {per_lookup:.2f} us/lookup")

    @pytest.mark.ida_required
    def test_lookup_miss_legacy(self, lookup_fixtures):
        """Benchmark PatternStorage lookups for non-matching ASTs."""
        legacy_storage, _, _, miss_asts = lookup_fixtures

        if not miss_asts:
            pytest.skip("No miss ASTs available")

        def lookup_all():
            for ast in miss_asts:
                _ = legacy_storage.get_matching_rule_pattern_info(ast)

        elapsed = timed_run(lookup_all, iterations=100, warmup=10)
        per_lookup = (elapsed / 100 / len(miss_asts)) * 1_000_000

        print(f"\n  Lookup (miss, legacy): {per_lookup:.2f} us/lookup")

    @pytest.mark.ida_required
    def test_lookup_hit_new(self, lookup_fixtures):
        """Benchmark OpcodeIndexedStorage lookups for matching ASTs."""
        _, new_storage, hit_asts, _ = lookup_fixtures

        if not hit_asts:
            pytest.skip("No hit ASTs available")

        def lookup_all():
            for ast in hit_asts:
                _ = new_storage.get_candidates(ast)

        elapsed = timed_run(lookup_all, iterations=100, warmup=10)
        per_lookup = (elapsed / 100 / len(hit_asts)) * 1_000_000

        print(f"\n  Lookup (hit, new):    {per_lookup:.2f} us/lookup")

    @pytest.mark.ida_required
    def test_lookup_miss_new(self, lookup_fixtures):
        """Benchmark OpcodeIndexedStorage lookups for non-matching ASTs."""
        _, new_storage, _, miss_asts = lookup_fixtures

        if not miss_asts:
            pytest.skip("No miss ASTs available")

        def lookup_all():
            for ast in miss_asts:
                _ = new_storage.get_candidates(ast)

        elapsed = timed_run(lookup_all, iterations=100, warmup=10)
        per_lookup = (elapsed / 100 / len(miss_asts)) * 1_000_000

        print(f"\n  Lookup (miss, new):   {per_lookup:.2f} us/lookup")


# =========================================================================
# Test: Match Benchmark
# =========================================================================


class TestMatchBenchmark:
    """Benchmark pattern matching performance."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def match_fixtures(self, real_asts):
        """Prepare patterns and candidates for match benchmarks."""
        candidates = []
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                right = getattr(ast, "right", None)
                if left is not None and right is not None:
                    candidates.append(ast)
                    if len(candidates) >= 20:
                        break

        if len(candidates) < 5:
            pytest.skip("Not enough candidate ASTs for match benchmark")

        patterns = []
        for candidate in candidates:
            pattern = AstNode(candidate.opcode, AstLeaf("x_0"), AstLeaf("y_0"))
            pattern.freeze()
            patterns.append(pattern)

        return patterns, candidates

    @pytest.mark.ida_required
    def test_match_clone_based(self, match_fixtures):
        """Benchmark check_pattern_and_copy_mops (clone-based match)."""
        patterns, candidates = match_fixtures

        def match_all():
            for pattern, candidate in zip(patterns, candidates):
                pattern_clone = pattern.clone()
                _ = pattern_clone.check_pattern_and_copy_mops(candidate)

        elapsed = timed_run(match_all, iterations=100, warmup=10)
        per_match = (elapsed / 100 / len(patterns)) * 1_000_000

        print(f"\n  Match (clone-based): {per_match:.2f} us/match")

    @pytest.mark.ida_required
    def test_match_nomut(self, match_fixtures):
        """Benchmark match_pattern_nomut (non-mutating match)."""
        patterns, candidates = match_fixtures

        bindings = MatchBindings()

        def match_all():
            for pattern, candidate in zip(patterns, candidates):
                _ = match_pattern_nomut(pattern, candidate, bindings)

        elapsed = timed_run(match_all, iterations=100, warmup=10)
        per_match = (elapsed / 100 / len(patterns)) * 1_000_000

        print(f"\n  Match (nomut):       {per_match:.2f} us/match")

    @pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
    @pytest.mark.ida_required
    def test_match_cython_nomut(self, match_fixtures):
        """Benchmark Cython match_pattern_nomut."""
        patterns, candidates = match_fixtures

        from d810.speedups.optimizers.c_pattern_match import CMatchBindings

        bindings = CMatchBindings()

        def match_all():
            for pattern, candidate in zip(patterns, candidates):
                _ = cython_match_pattern_nomut(pattern, candidate, bindings)

        elapsed = timed_run(match_all, iterations=100, warmup=10)
        per_match = (elapsed / 100 / len(patterns)) * 1_000_000

        print(f"\n  Match (Cython):      {per_match:.2f} us/match")


# =========================================================================
# Test: Hot Path Benchmark
# =========================================================================


class TestHotPathBenchmark:
    """Benchmark the full pattern matching hot path (end-to-end)."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_full_optimization_pass(self, real_asts, libobfuscated_setup):
        """Benchmark full get_optimized_instruction() across all test instructions."""
        from d810.optimizers.microcode.instructions.pattern_matching.handler import PatternOptimizer
        from d810.core import OptimizationStatistics

        stats = OptimizationStatistics()
        optimizer = PatternOptimizer(
            maturities=[ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT],
            stats=stats,
        )

        instructions = [ins for _, ins in real_asts if ins is not None]

        if len(instructions) < 10:
            pytest.skip("Not enough instructions for hot path benchmark")

        class MockBlock:
            def __init__(self):
                class MockMBA:
                    maturity = ida_hexrays.MMAT_PREOPTIMIZED
                self.mba = MockMBA()

        mock_blk = MockBlock()

        def run_optimization_pass():
            matched = 0
            for ins in instructions:
                result = optimizer.get_optimized_instruction(mock_blk, ins)
                if result is not None:
                    matched += 1
            return matched

        elapsed = timed_run(run_optimization_pass, iterations=10, warmup=2)
        per_instruction = (elapsed / 10 / len(instructions)) * 1_000_000

        print(f"\n  Hot path (no rules):")
        print(f"    Total instructions: {len(instructions)}")
        print(f"    Time per instruction: {per_instruction:.2f} us")
        print(f"    Throughput: {len(instructions) / (elapsed / 10):.0f} insns/sec")


# =========================================================================
# Test: Capture Baseline
# =========================================================================


class TestCaptureBaseline:
    """Capture all benchmark results and save as baseline."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_capture_baseline(self, real_asts, libobfuscated_setup):
        """Run all benchmarks and save baseline results."""
        from pathlib import Path

        results = {}

        # Registration benchmark
        unique_patterns = []
        seen_sigs = set()
        for ast, _ in real_asts[:200]:
            if ast.is_node():
                sig = ast.get_pattern()
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    unique_patterns.append(ast)
                    if len(unique_patterns) >= 100:
                        break

        if len(unique_patterns) >= 20:
            rules = []
            for i in range(len(unique_patterns)):
                class MockRule:
                    pass
                rule = MockRule()
                rule.name = f"rule_{i}"
                rules.append(rule)

            def populate_legacy():
                storage = PatternStorage(depth=1)
                for pattern, rule in zip(unique_patterns, rules):
                    storage.add_pattern_for_rule(pattern, rule)
                return storage

            def populate_new():
                storage = OpcodeIndexedStorage()
                for pattern, rule in zip(unique_patterns, rules):
                    storage.add_pattern(pattern, rule)
                return storage

            legacy_reg_time = timed_run(populate_legacy, iterations=10, warmup=2)
            new_reg_time = timed_run(populate_new, iterations=10, warmup=2)

            results["registration"] = {
                "pattern_count": len(unique_patterns),
                "legacy_time_ms": legacy_reg_time * 1000,
                "new_time_ms": new_reg_time * 1000,
                "speedup": legacy_reg_time / new_reg_time if new_reg_time > 0 else 0,
            }

        # Lookup benchmarks
        if len(unique_patterns) >= 10:
            legacy_storage = PatternStorage(depth=1)
            new_storage = OpcodeIndexedStorage()

            for i, pattern in enumerate(unique_patterns[:50]):
                class MockRule:
                    pass
                rule = MockRule()
                rule.name = f"rule_{i}"
                legacy_storage.add_pattern_for_rule(pattern, rule)
                new_storage.add_pattern(pattern, rule)

            hit_asts = unique_patterns[:10]
            pattern_opcodes = {p.opcode for p in unique_patterns if p.is_node()}
            miss_asts = [ast for ast, _ in real_asts if ast.is_node() and ast.opcode not in pattern_opcodes][:10]

            if hit_asts:
                def lookup_hit_legacy():
                    for ast in hit_asts:
                        _ = legacy_storage.get_matching_rule_pattern_info(ast)

                def lookup_hit_new():
                    for ast in hit_asts:
                        _ = new_storage.get_candidates(ast)

                legacy_hit_time = timed_run(lookup_hit_legacy, iterations=100, warmup=10)
                new_hit_time = timed_run(lookup_hit_new, iterations=100, warmup=10)

                results["lookup_hit"] = {
                    "candidate_count": len(hit_asts),
                    "legacy_us_per_lookup": (legacy_hit_time / 100 / len(hit_asts)) * 1_000_000,
                    "new_us_per_lookup": (new_hit_time / 100 / len(hit_asts)) * 1_000_000,
                    "speedup": legacy_hit_time / new_hit_time if new_hit_time > 0 else 0,
                }

            if miss_asts:
                def lookup_miss_legacy():
                    for ast in miss_asts:
                        _ = legacy_storage.get_matching_rule_pattern_info(ast)

                def lookup_miss_new():
                    for ast in miss_asts:
                        _ = new_storage.get_candidates(ast)

                legacy_miss_time = timed_run(lookup_miss_legacy, iterations=100, warmup=10)
                new_miss_time = timed_run(lookup_miss_new, iterations=100, warmup=10)

                results["lookup_miss"] = {
                    "candidate_count": len(miss_asts),
                    "legacy_us_per_lookup": (legacy_miss_time / 100 / len(miss_asts)) * 1_000_000,
                    "new_us_per_lookup": (new_miss_time / 100 / len(miss_asts)) * 1_000_000,
                    "speedup": legacy_miss_time / new_miss_time if new_miss_time > 0 else 0,
                }

        # Match benchmarks
        candidates = []
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                right = getattr(ast, "right", None)
                if left is not None and right is not None:
                    candidates.append(ast)
                    if len(candidates) >= 20:
                        break

        if len(candidates) >= 5:
            patterns = []
            for candidate in candidates:
                pattern = AstNode(candidate.opcode, AstLeaf("x_0"), AstLeaf("y_0"))
                pattern.freeze()
                patterns.append(pattern)

            def match_clone():
                for pattern, candidate in zip(patterns, candidates):
                    pattern_clone = pattern.clone()
                    _ = pattern_clone.check_pattern_and_copy_mops(candidate)

            def match_nomut():
                bindings = MatchBindings()
                for pattern, candidate in zip(patterns, candidates):
                    _ = match_pattern_nomut(pattern, candidate, bindings)

            clone_time = timed_run(match_clone, iterations=100, warmup=10)
            nomut_time = timed_run(match_nomut, iterations=100, warmup=10)

            results["match"] = {
                "pattern_count": len(patterns),
                "clone_us_per_match": (clone_time / 100 / len(patterns)) * 1_000_000,
                "nomut_us_per_match": (nomut_time / 100 / len(patterns)) * 1_000_000,
                "speedup": clone_time / nomut_time if nomut_time > 0 else 0,
            }

        # Hot path benchmark
        from d810.optimizers.microcode.instructions.pattern_matching.handler import PatternOptimizer
        from d810.core import OptimizationStatistics

        stats = OptimizationStatistics()
        optimizer = PatternOptimizer(
            maturities=[ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT],
            stats=stats,
        )

        instructions = [ins for _, ins in real_asts if ins is not None][:100]

        if len(instructions) >= 10:
            class MockBlock:
                def __init__(self):
                    class MockMBA:
                        maturity = ida_hexrays.MMAT_PREOPTIMIZED
                    self.mba = MockMBA()

            mock_blk = MockBlock()

            def run_optimization_pass():
                for ins in instructions:
                    _ = optimizer.get_optimized_instruction(mock_blk, ins)

            hot_path_time = timed_run(run_optimization_pass, iterations=10, warmup=2)

            results["hot_path"] = {
                "instruction_count": len(instructions),
                "us_per_instruction": (hot_path_time / 10 / len(instructions)) * 1_000_000,
                "throughput_insns_per_sec": len(instructions) / (hot_path_time / 10),
            }

        # Save results
        baseline_path = Path(__file__).resolve().parents[3] / "docs" / "copycat" / "benchmarks" / "baseline_pattern_engine.json"
        save_baseline(results, baseline_path, "Pattern Engine Baseline (PR0)")

        print(f"\n  Baseline saved to: {baseline_path}")
        print(f"  Summary saved to: {baseline_path.with_suffix('.md')}")

        assert baseline_path.exists(), "JSON baseline file not created"
        assert baseline_path.with_suffix('.md').exists(), "Markdown summary not created"
