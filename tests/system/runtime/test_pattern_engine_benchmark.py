"""Benchmark tests for pattern matching engine performance.

Measures baseline performance of pattern storage, lookup, matching, and
full hot path optimization. Uses real microcode ASTs from test binaries.

All tests require IDA Pro with Hex-Rays decompiler.
"""

from __future__ import annotations

import os
import platform
import hashlib
import cProfile
import gc
import io
import json
import pstats
import statistics
import time
import tracemalloc
from types import SimpleNamespace

import pytest

import ida_hexrays
import idaapi
import idc

from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.core.typing import NamedTuple
from d810.core.cymode import CythonMode
from d810.hexrays.expr.p_ast import AstLeaf, AstNode
from d810.hexrays.ir import minsn_utils
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.mba.provider_outcome import RawMatcherWorkReceipt
from tests.runtime_provenance import runtime_provenance
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternStorage,
    optimizer_logger,
)
from d810.optimizers.microcode.instructions.pattern_matching.engine import get_engine_info
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
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


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
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity)
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


class _CompilerShapeSample(NamedTuple):
    """Callback-local native objects retained with one compiler-shape AST."""

    ast: object
    instruction: object
    block: object
    top_instruction: object
    mba: object
    path: tuple[str, ...]


def _iter_nested_minsns(instruction, path: tuple[str, ...] = ()):
    """Yield an instruction and every nested ``mop_d`` instruction below it."""

    yield instruction, path
    for operand_name in ("l", "r", "d"):
        operand = getattr(instruction, operand_name, None)
        if operand is None or getattr(operand, "t", None) != ida_hexrays.mop_d:
            continue
        nested = getattr(operand, "d", None)
        if nested is None:
            continue
        yield from _iter_nested_minsns(
            nested,
            path + (operand_name,),
        )


def collect_compiler_shape_callback_samples(mba) -> list[_CompilerShapeSample]:
    """Collect stable top-level and nested callback candidates from an MBA.

    ``minsn_t.for_all_insns`` visits nested instructions, while the generic
    benchmark collector intentionally only records top-level instructions.
    Retain the original candidate and owner objects together: production
    bind/evaluator logic may require the candidate to belong to the real
    block, and the MBA held by each sample keeps those native pointers alive
    for the class-scoped benchmark.
    """

    results: list[_CompilerShapeSample] = []
    for block_index in range(mba.qty):
        block = mba.get_mblock(block_index)
        if block is None:
            continue
        top_instruction = block.head
        while top_instruction is not None:
            for instruction, path in _iter_nested_minsns(top_instruction):
                try:
                    ast = minsn_to_ast(instruction)
                    if ast is not None:
                        results.append(
                            _CompilerShapeSample(
                                ast=ast,
                                instruction=instruction,
                                block=block,
                                top_instruction=top_instruction,
                                mba=mba,
                                path=path,
                            )
                        )
                except Exception:
                    pass
            top_instruction = top_instruction.next
    return results


@pytest.fixture(scope="class")
def compiler_shape_real_asts(ida_database, configure_hexrays):
    """Collect real AST/minsn pairs from the pinned compiler-shape witness."""
    asts = []
    function_ea = get_func_ea("mba_shape_catalogue_08")
    if function_ea != idaapi.BADADDR:
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
        if mba is not None:
            asts.extend(collect_compiler_shape_callback_samples(mba))
    if not asts:
        pytest.skip("compiler-shape raw witnesses have no convertible ASTs")
    return asts


def _collect_real_shadow_evidence(
    d810_state, pseudocode_to_string, monkeypatch
) -> tuple[object, object, dict[str, object]]:
    """Collect complete-manifest legacy-shadow evidence for authorization."""

    from tests.system.e2e.test_mba_compiler_shape_corpus import (
        _CATALOGUE_CASES,
        _MANIFEST,
        _persist_task13_native_capture,
    )

    observed: dict[str, object] = {}
    monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
    monkeypatch.setenv("D810_SHADOW_DSL_MATCHING", "1")
    monkeypatch.delenv("D810_CANONICAL_MATCH_FALLBACK", raising=False)

    runtime_mode = "cython" if get_engine_info()["backend"] == "cython" else "python"
    capture_path = (
        Path(__file__).resolve().parents[3]
        / ".tmp"
        / f"task7-production-shadow-capture-{runtime_mode}.json"
    )
    capture = _persist_task13_native_capture(
        capture_path,
        d810_state=d810_state,
        pseudocode_to_string=pseudocode_to_string,
        shadow_evidence=observed,
    )
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    manifest_ids = {case["case_id"] for case in manifest["cases"]}
    captured_cases = capture.get("cases", [])
    assert isinstance(captured_cases, list)
    assert {case["case_id"] for case in captured_cases} == manifest_ids
    assert len(captured_cases) == len(manifest_ids)
    capture_metadata = capture.get("capture_metadata", {})
    assert capture_metadata["corpus_digest"] == hashlib.sha256(
        _MANIFEST.read_bytes()
    ).hexdigest()

    snapshot = observed.get("snapshot")
    ledger = observed.get("ledger")
    assert snapshot is not None
    assert ledger is not None
    assert ledger.legacy_match_count > 0
    assert ledger.legacy_rule_mismatches == 0
    assert ledger.legacy_binding_mismatches == 0
    assert ledger.legacy_binding_unknown == 0
    assert ledger.new_safe_coverage_pending == 0
    return snapshot, ledger, {
        "capture_path": capture_path,
        "manifest_case_count": len(manifest_ids),
        "catalogue_case_count": len(_CATALOGUE_CASES),
        "manifest_digest": capture_metadata["corpus_digest"],
    }


def _mop_projection(mop) -> tuple[object, ...] | None:
    if mop is None:
        return None
    return (
        int(getattr(mop, "t", -1)),
        int(getattr(mop, "size", 0)),
        str(mop.dstr()) if hasattr(mop, "dstr") else repr(mop),
    )


def _ast_projection(ast) -> tuple[object, ...] | None:
    """Project the behavior-bearing AST shape without object identity."""
    if ast is None:
        return None
    if ast.is_node():
        return (
            "node",
            int(ast.opcode),
            int(getattr(ast, "dest_size", 0) or 0),
            _ast_projection(getattr(ast, "left", None)),
            _ast_projection(getattr(ast, "right", None)),
            _mop_projection(getattr(ast, "dst_mop", None)),
        )
    if ast.is_constant():
        return (
            "constant",
            int(getattr(ast, "dest_size", 0) or 0),
            getattr(ast, "value", None),
            getattr(ast, "expected_value", None),
            _mop_projection(getattr(ast, "mop", None)),
        )
    return (
        "leaf",
        int(getattr(ast, "dest_size", 0) or 0),
        _mop_projection(getattr(ast, "mop", None)),
    )


def _benchmark_ast_shape(ast) -> tuple[object, ...] | None:
    """Return a backend-independent shape identity for benchmark evidence."""
    if ast is None:
        return None
    if ast.is_node():
        return (
            "node",
            int(ast.opcode),
            int(getattr(ast, "dest_size", 0) or 0),
            _benchmark_ast_shape(getattr(ast, "left", None)),
            _benchmark_ast_shape(getattr(ast, "right", None)),
        )
    if ast.is_constant():
        return (
            "constant",
            int(getattr(ast, "dest_size", 0) or 0),
            getattr(ast, "value", None),
        )
    return ("leaf", int(getattr(ast, "dest_size", 0) or 0))


def _resolver_projection(ast) -> tuple[object, ...] | None:
    """Project resolver semantics without relying on mutable AST indexes."""
    if ast is None:
        return None
    if ast.is_node():
        return (
            "node",
            int(ast.opcode),
            int(getattr(ast, "dest_size", 0) or 0),
            _resolver_projection(getattr(ast, "left", None)),
            _resolver_projection(getattr(ast, "right", None)),
        )
    mop = getattr(ast, "mop", None)
    return (
        "constant" if ast.is_constant() else "leaf",
        int(getattr(ast, "dest_size", 0) or 0),
        getattr(ast, "value", None),
        int(getattr(mop, "t", -1)) if mop is not None else -1,
        int(getattr(mop, "size", 0)) if mop is not None else 0,
        getattr(mop, "reg", getattr(mop, "r", None)) if mop is not None else None,
        getattr(mop, "stkoff", None) if mop is not None else None,
    )


def _assert_ast_owns_operand_snapshots(ast) -> None:
    if ast is None:
        return
    mop = getattr(ast, "mop", None)
    if mop is not None and not ast.is_constant():
        assert isinstance(mop, MopSnapshot), type(mop)
    if ast.is_node():
        _assert_ast_owns_operand_snapshots(getattr(ast, "left", None))
        _assert_ast_owns_operand_snapshots(getattr(ast, "right", None))
        _assert_ast_owns_operand_snapshots(getattr(ast, "dst", None))


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

    print(
        f"\n  Collected {len(all_asts)} total ASTs from {len(test_functions)} functions"
    )
    return all_asts


# =========================================================================
# Test: Storage Parity Oracle
# =========================================================================


class TestStorageParity:
    """Verify PatternStorage and OpcodeIndexedStorage return identical candidates."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_legacy_lookup_reuses_candidate_set_for_same_frozen_shape(
        self,
        real_asts,
        monkeypatch,
    ):
        candidate = next(ast for ast, _ in real_asts if ast.is_node())
        storage = PatternStorage(depth=1)

        class MockRule:
            name = "shape_cache_rule"

        storage.add_pattern_for_rule(candidate, MockRule())
        original_explore = storage.explore_one_level
        traversals = 0

        def counted_explore(searched_pattern, cur_level):
            nonlocal traversals
            traversals += 1
            return original_explore(searched_pattern, cur_level)

        monkeypatch.setattr(storage, "explore_one_level", counted_explore)

        first = storage.get_matching_rule_pattern_info(candidate)
        second = storage.get_matching_rule_pattern_info(candidate.clone())

        assert [entry.rule.name for entry in first] == ["shape_cache_rule"]
        assert [entry.rule.name for entry in second] == ["shape_cache_rule"]
        assert traversals == 1

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


@pytest.mark.skipif(
    not HAS_CYTHON or not CythonMode().is_enabled(),
    reason="Cython extensions are unavailable or disabled for this runtime",
)
class TestCythonPythonParity:
    """Verify Cython implementations match pure-Python outputs exactly."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_unified_minsn_gateway_selects_compiled_builder(self, real_asts):
        """Production Cython mode must not route the hot AST gateway to Python."""
        assert CythonMode().is_enabled()
        assert minsn_utils.get_minsn_to_ast_backend() == "cython"

    @pytest.mark.ida_required
    def test_recursive_def_resolver_gateway_selects_compiled_backend(self):
        """Production mode must not recurse over every AST node in Python."""
        from d810.evaluator.hexrays_microcode import def_search

        assert CythonMode().is_enabled()
        assert def_search.get_recursive_resolver_backend() == "cython"

    @pytest.mark.ida_required
    def test_recursive_def_resolver_budget_cutoff_matches_python(
        self, monkeypatch
    ):
        """Both resolver backends consume before rebuilding replacement nodes."""
        from types import SimpleNamespace

        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )
        from d810.evaluator.hexrays_microcode import def_search
        from d810.hexrays.expr.ast import AstLeaf as RuntimeAstLeaf
        from d810.hexrays.expr.ast import AstNode as RuntimeAstNode

        replacement = RuntimeAstLeaf("resolved")
        replacement.dest_size = 4

        def _resolve(
            _mop,
            _blk,
            _ins,
            *,
            node_budget=None,
            call_result_refiner=None,
        ):
            assert node_budget is budget_under_test
            assert call_result_refiner is None
            return replacement

        monkeypatch.setattr(def_search, "resolve_mop_to_ast", _resolve)
        block = SimpleNamespace(serial=1)
        instruction = SimpleNamespace(this=1)

        budget_under_test = None

        def _run(resolver):
            nonlocal budget_under_test
            leaf = RuntimeAstLeaf("register")
            leaf.mop = SimpleNamespace(
                t=ida_hexrays.mop_r,
                size=4,
                r=1,
                valnum=0,
            )
            root = RuntimeAstNode(ida_hexrays.m_add, leaf, None)
            budget = Z3ExpressionNodeBudget(
                Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
            )
            budget_under_test = budget
            budget.consume()
            with pytest.raises(Z3NodeLimitExceeded):
                resolver(
                    root,
                    block,
                    instruction,
                    cache={},
                    node_budget=budget,
                )
            return budget.observed_nodes

        python_observed = _run(def_search._py_slow_recursively_resolve_ast)
        compiled_observed = _run(def_search.recursively_resolve_ast)

        assert python_observed == compiled_observed == 1

    @pytest.mark.ida_required
    def test_recursive_def_resolver_matches_python_on_live_microcode(
        self,
        libobfuscated_setup,
    ):
        """The compiled tree walk must preserve Python resolver behavior."""
        from d810.evaluator.hexrays_microcode import def_search

        function_ea = get_func_ea("test_cst_simplification")
        assert function_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_PREOPTIMIZED)
        assert mba is not None

        compared = 0
        for block_index in range(mba.qty):
            block = mba.get_mblock(block_index)
            instruction = block.head
            while instruction is not None and compared < 16:
                if instruction.opcode not in {ida_hexrays.m_add, ida_hexrays.m_sub}:
                    instruction = instruction.next
                    continue
                MOP_TO_AST_CACHE.clear()
                python_source = minsn_to_ast(instruction)
                MOP_TO_AST_CACHE.clear()
                compiled_source = minsn_to_ast(instruction)
                if python_source is None or compiled_source is None:
                    instruction = instruction.next
                    continue

                python_result = def_search._py_slow_recursively_resolve_ast(
                    python_source, block, instruction, max_depth=6, cache={}
                )
                compiled_result = def_search.recursively_resolve_ast(
                    compiled_source, block, instruction, max_depth=6, cache={}
                )

                assert _resolver_projection(compiled_result) == _resolver_projection(
                    python_result
                )
                assert compiled_result.get_pattern() == python_result.get_pattern()
                compared += 1
                instruction = instruction.next

        assert compared >= 4

    @pytest.mark.ida_required
    def test_minsn_builder_parity_on_live_microcode(self, libobfuscated_setup):
        """The compiled builder must preserve the Python builder's live ASTs."""
        from d810.speedups.expr import c_ast

        function_ea = get_func_ea("test_cst_simplification")
        assert function_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_PREOPTIMIZED)
        assert mba is not None

        compared = 0
        for block_index in range(mba.qty):
            instruction = mba.get_mblock(block_index).head
            while instruction is not None and compared < 50:
                MOP_CONSTANT_CACHE.clear()
                MOP_TO_AST_CACHE.clear()
                python_ast = minsn_utils._py_slow_minsn_to_ast(instruction)
                python_projection = _ast_projection(python_ast)

                MOP_CONSTANT_CACHE.clear()
                MOP_TO_AST_CACHE.clear()
                cython_ast = c_ast.minsn_to_ast(instruction)
                cython_projection = _ast_projection(cython_ast)

                assert cython_projection == python_projection, instruction.dstr()
                _assert_ast_owns_operand_snapshots(cython_ast)
                if python_ast is not None and cython_ast is not None:
                    assert cython_ast.get_pattern() == python_ast.get_pattern()
                    py_leafs, py_constants, py_opcodes = python_ast.get_information()
                    cy_leafs, cy_constants, cy_opcodes = cython_ast.get_information()
                    assert len(cy_leafs) == len(py_leafs)
                    assert cy_constants == py_constants
                    assert cy_opcodes == py_opcodes
                compared += 1
                instruction = instruction.next

        assert compared >= 10

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


class TestCanonicalFallbackWorkBounds:
    """Exercise the handler's raw-first/fallback work accounting contract."""

    # Use the independently generated compiler-shape corpus so the production
    # catalogue adapters have genuine raw-hit candidates.  The remaining
    # pattern-engine benchmarks continue to use libobfuscated below.
    binary_name = "mba_compiler_shapes.dylib"

    @staticmethod
    def generated_binary_factory(output_path):
        from tests.system.e2e.test_mba_compiler_shape_corpus import (
            _build_native_corpus_binary,
        )

        _build_native_corpus_binary(output_path)

    @staticmethod
    def _term_and_shape():
        from d810.mba.certified_catalogue import root_shape_for_term
        from d810.mba.typed_term import TypedBvTerm

        term = TypedBvTerm(
            "add",
            32,
            children=(
                TypedBvTerm(None, 32, leaf_key=("register", 0)),
                TypedBvTerm(None, 32, leaf_key=("register", 1)),
            ),
        )
        return term, root_shape_for_term(term)

    @staticmethod
    def _make_rule(name, *, raw_result=None, fallback_result=None, shape=None):
        calls = {
            "raw": 0,
            "fallback": 0,
            "prepare": 0,
            "last_lowering": None,
            "receipt_count": 0,
            "last_receipt": None,
        }
        term, _actual_shape = TestCanonicalFallbackWorkBounds._term_and_shape()
        pattern = AstNode(ida_hexrays.m_add, AstLeaf("x"), AstLeaf("y"))
        pattern.freeze()

        class Rule:
            maturities = (ida_hexrays.MMAT_PREOPTIMIZED,)
            canonical_fallback_enabled = True
            canonical_fallback_declaration_index = 0

            def check_pattern_and_replace(self, _pattern, _candidate):
                calls["raw"] += 1
                return raw_result

            def prepare_structural_candidate(self, _candidate, **_kwargs):
                calls["prepare"] += 1
                lowering = SimpleNamespace(term=term)
                calls["last_lowering"] = lowering
                return lowering

            def match_structural_and_replace(self, _candidate, **_kwargs):
                calls["fallback"] += 1
                return fallback_result

            def clear_match_context(self):
                return None

            def bind_match_context(self, _blk, _ins):
                return None

            def record_raw_match_receipt(self, _receipt):
                calls["receipt_count"] += 1
                calls["last_receipt"] = _receipt

        rule = Rule()
        rule.name = name
        rule.canonical_fallback_root_shapes = (shape,) if shape is not None else ()
        rule.pattern_candidates = (pattern,)
        return rule, pattern, calls

    def _optimizer_for(self, raw_rule, fallback_rules):
        from d810.core import OptimizationStatistics
        from d810.mba.certified_catalogue import root_shape_for_term
        from d810.optimizers.microcode.instructions.pattern_matching.handler import (
            PatternOptimizer,
        )

        optimizer = PatternOptimizer(
            maturities=[ida_hexrays.MMAT_PREOPTIMIZED],
            stats=OptimizationStatistics(),
        )
        optimizer.cur_maturity = ida_hexrays.MMAT_PREOPTIMIZED
        optimizer._get_candidates = lambda _ast: (
            SimpleNamespace(rule=raw_rule, pattern=raw_rule.pattern_candidates[0]),
        )
        term, shape = self._term_and_shape()
        assert root_shape_for_term(term) == shape
        optimizer._canonical_fallback_rules_by_root_shape = {shape: list(fallback_rules)}
        return optimizer

    @pytest.mark.ida_required
    def test_raw_hit_does_not_prepare_or_enter_canonical_fallback(self):
        """A raw hit returns before any canonical lowering or comparison work."""
        raw_rule, pattern, raw_calls = self._make_rule(
            "raw",
            raw_result=SimpleNamespace(
                ea=0x1001, _print=lambda: "replacement"
            ),
        )
        optimizer = self._optimizer_for(raw_rule, ())

        result = optimizer._try_matches(
            SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)),
            SimpleNamespace(
                d=SimpleNamespace(size=4), ea=0x1000, _print=lambda: "raw-hit"
            ),
            pattern,
            allowed_rule_names=None,
            scheduled_rule_names=frozenset(),
            source_label="task7-raw-hit",
        )

        assert result is not None
        assert raw_calls["raw"] == 1
        assert raw_calls["receipt_count"] == 1
        assert isinstance(raw_calls["last_receipt"], RawMatcherWorkReceipt)
        assert raw_calls["prepare"] == 0
        assert raw_calls["fallback"] == 0

    @pytest.mark.ida_required
    def test_clean_miss_lowers_once_for_all_eligible_fallback_rules(self):
        """A clean miss shares one lowering across the entire fallback bucket."""
        term, shape = self._term_and_shape()
        raw_rule, pattern, _raw_calls = self._make_rule("raw", shape=shape)
        fallback_rules = [
            self._make_rule(f"fallback-{index}", shape=shape)[0]
            for index in range(3)
        ]
        # Count at the shared root-bucket owner, not on each rule adapter.
        prepare_calls = []

        def prepare(_candidate, **_kwargs):
            prepare_calls.append(True)
            return SimpleNamespace(term=term)

        raw_rule.prepare_structural_candidate = prepare
        fallback_rules[0].prepare_structural_candidate = prepare
        optimizer = self._optimizer_for(raw_rule, fallback_rules)
        optimizer._canonical_fallback_rules_by_root_shape[shape] = fallback_rules
        result = optimizer._try_matches(
            SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)),
            SimpleNamespace(d=SimpleNamespace(size=4), _print=lambda: "clean-miss"),
            pattern,
            allowed_rule_names=None,
            scheduled_rule_names=frozenset(),
            source_label="task7-clean-miss",
        )

        assert result is None
        assert len(prepare_calls) == 1
        assert [rule.name for rule in fallback_rules] == [
            "fallback-0",
            "fallback-1",
            "fallback-2",
        ]
        assert all(getattr(rule, "_last_provider_outcome", None) is None for rule in fallback_rules)

    @staticmethod
    def _callback_instruction():
        return SimpleNamespace(
            d=SimpleNamespace(size=4),
            ea=0x1000,
            _print=lambda: "task7-callback",
        )

    def _discover_production_sample(
        self, real_samples, d810_state, monkeypatch
    ) -> _CompilerShapeSample:
        """Pin one native callback sample before either A/B mode runs."""
        from d810.core import OptimizationStatistics
        from d810.optimizers.microcode.instructions.pattern_matching.handler import (
            PatternOptimizer,
        )

        monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
        # Keep snapshot attachment enabled in both arms.  Shadow observation
        # is read-only here; the canonical rollout flag remains the sole A/B
        # dimension and is still explicitly 0 versus 1.
        monkeypatch.setenv("D810_SHADOW_DSL_MATCHING", "1")
        monkeypatch.setenv("D810_CANONICAL_MATCH_FALLBACK", "0")
        with d810_state() as state:
            assert state.load_project(
                state.project_manager.index("mba_compiler_shape_catalogue.json")
            ) is not None
            adapters = tuple(state.current_ins_rules)
            adapter = next(
                rule for rule in adapters if rule.name == "Add_HackersDelightRule_4"
            )
            optimizer = PatternOptimizer(
                maturities=[ida_hexrays.MMAT_CALLS],
                stats=OptimizationStatistics(),
                verifiable_rules=list(adapters),
            )
            allowed = frozenset({adapter.name})
            for sample in real_samples:
                optimizer.last_matched_rule_name = None
                result = optimizer._try_matches(
                    sample.block,
                    sample.instruction,
                    sample.ast,
                    allowed_rule_names=allowed,
                    scheduled_rule_names=frozenset(),
                    source_label="task7-production-benchmark-discovery",
                )
                if (
                    result is not None
                    and optimizer.last_matched_rule_name == adapter.name
                ):
                    return sample
        pytest.fail(
            "pinned Add_HackersDelightRule_4 has no raw-hit AST in the "
            f"MMAT_CALLS compiler-shape witness (asts={len(real_samples)})"
        )

    def _sample_production_raw_hit(
        self,
        sample,
        d810_state,
        monkeypatch,
        activation_path,
        *,
        fallback_enabled: bool,
        fallback_probe: bool = False,
    ) -> tuple[list[float], dict]:
        """Sample a real certified adapter through the production handler.

        The small synthetic helpers above intentionally isolate work-count
        invariants.  Timing must exercise the adapter registration and
        rollout flag, however, so this helper loads the catalogue through
        ``D810State`` and invokes ``PatternOptimizer._try_matches`` with the
        exact same live AST/minsn pair selected before the A/B modes.
        """
        from d810.core import OptimizationStatistics
        from d810.core.config import ProjectConfiguration
        from d810.optimizers.microcode.instructions.pattern_matching.handler import (
            PatternOptimizer,
        )

        monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
        # Request read-only snapshot attachment in both A/B arms.  The
        # canonical rollout flag remains the only experimental dimension.
        monkeypatch.setenv("D810_SHADOW_DSL_MATCHING", "1")
        monkeypatch.setenv(
            "D810_CANONICAL_MATCH_FALLBACK", "1" if fallback_enabled else "0"
        )
        calls = {"fallback_enabled": fallback_enabled}

        with d810_state() as state:
            project_index = state.project_manager.index(
                "mba_compiler_shape_catalogue.json"
            )
            assert state.load_project(project_index) is not None
            adapters = tuple(state.current_ins_rules)
            assert adapters

            # Activate through the same D810State project/configuration path
            # used by production, rather than attaching a snapshot directly.
            state.add_project(ProjectConfiguration.from_file(activation_path))
            assert state.load_project(
                state.project_manager.index(activation_path.name)
            ) is not None
            adapters = tuple(state.current_ins_rules)
            assert state.current_certified_catalogue_snapshot is not None

            adapter = next(
                (
                    adapter
                    for adapter in adapters
                    if adapter.name == "Add_HackersDelightRule_4"
                ),
                None,
            )
            assert adapter is not None
            assert adapter.canonical_fallback_enabled is fallback_enabled
            fallback_records: list[dict[str, int]] = []
            active_record: dict[str, int] | None = None
            if fallback_probe:
                monkeypatch.setattr(
                    adapter,
                    "check_pattern_and_replace",
                    lambda *_args, **_kwargs: None,
                )
                from d810.backends.mba import hexrays_island
                from d810.backends.mba import ida as ida_backend
                from d810.mba import ac_matching

                def record_lowering(*args, **kwargs):
                    if active_record is not None:
                        active_record["lowerings"] += 1
                    return original_lowering(*args, **kwargs)

                def record_canonical_match(*args, **kwargs):
                    if active_record is not None:
                        active_record["canonical_matches"] += 1
                    return original_canonical_match(*args, **kwargs)

                def record_proof(*args, **kwargs):
                    if active_record is not None:
                        active_record["proofs"] += 1
                    return original_proof(*args, **kwargs)

                original_lowering = hexrays_island.lower_hexrays_island
                original_canonical_match = ac_matching.match_canonical_term_pattern
                original_proof = ida_backend.prove_native_ast_equivalence
                original_emitter = adapter._get_shadow_replacement

                def record_emitter(*args, **kwargs):
                    if active_record is not None:
                        active_record["emitters"] += 1
                    return original_emitter(*args, **kwargs)

                monkeypatch.setattr(hexrays_island, "lower_hexrays_island", record_lowering)
                monkeypatch.setattr(
                    ac_matching,
                    "match_canonical_term_pattern",
                    record_canonical_match,
                )
                monkeypatch.setattr(
                    ida_backend,
                    "prove_native_ast_equivalence",
                    record_proof,
                )
                monkeypatch.setattr(adapter, "_get_shadow_replacement", record_emitter)
            optimizer = PatternOptimizer(
                maturities=[ida_hexrays.MMAT_CALLS],
                stats=OptimizationStatistics(),
                verifiable_rules=list(adapters),
            )
            allowed = frozenset({adapter.name})
            scheduled = frozenset()
            candidate_ast = sample.ast
            candidate_ins = sample.instruction
            block = sample.block
            assert sample.mba.entry_ea == block.mba.entry_ea
            assert block.mba.maturity == ida_hexrays.MMAT_CALLS

            ordered_schedule = tuple(rule.name for rule in adapters)
            project_document = state.current_project.to_document()
            authorization = {
                "snapshot_fingerprint": state.current_certified_catalogue_snapshot.fingerprint,
                "expectation": project_document["additional_configuration"][
                    "structural_matcher_parity_expectation"
                ],
                "ledger": {
                    field: getattr(state.current_shadow_matcher_parity_ledger, field)
                    for field in (
                        "observation_count",
                        "legacy_match_count",
                        "legacy_rule_mismatches",
                        "legacy_binding_mismatches",
                        "legacy_binding_unknown",
                    )
                },
            }
            runtime_settings = {
                "canonical_fallback_env": "1" if fallback_enabled else "0",
                "shadow_matching_env": os.environ.get("D810_SHADOW_DSL_MATCHING"),
                "legacy_dsl_permutations_env": os.environ.get(
                    "D810_LEGACY_DSL_PERMUTATIONS"
                ),
                "legacy_storage_env": os.environ.get("D810_LEGACY_STORAGE", "0"),
                "indexed_legacy_fallback_env": os.environ.get(
                    "D810_INDEXED_LEGACY_FALLBACK", "1"
                ),
            }
            cache_policy = {
                "use_legacy_storage": optimizer._use_legacy_storage,
                "use_indexed_legacy_fallback": optimizer._use_indexed_legacy_fallback,
                "use_nomut_matching": optimizer._use_nomut_matching,
                "generation": optimizer._generation,
                "compiled_generation": getattr(
                    getattr(optimizer, "_compiled_view", None), "generation", None
                ),
                "indexed_pattern_count": optimizer._indexed_storage.total_patterns,
                "adapter_replacement_cached": tuple(
                    rule._replacement_pattern_cache is not None for rule in adapters
                ),
            }

            def callback() -> None:
                nonlocal active_record
                if fallback_probe:
                    active_record = {
                        "lowerings": 0,
                        "canonical_matches": 0,
                        "proofs": 0,
                        "emitters": 0,
                    }
                    callback_ast = minsn_to_ast(candidate_ins)
                else:
                    callback_ast = candidate_ast
                result = optimizer._try_matches(
                    block,
                    candidate_ins,
                    callback_ast,
                    allowed_rule_names=allowed,
                    scheduled_rule_names=scheduled,
                    source_label="task7-production-benchmark-raw-hit",
                )
                if fallback_probe:
                    record = active_record
                    active_record = None
                    assert record is not None
                    assert result is not None, (
                        "fallback callback failed after "
                        f"{len(fallback_records)} successful callbacks; "
                        f"candidate_ea={getattr(candidate_ins, 'ea', None)!r}; "
                        f"provider_outcome={adapter._last_provider_outcome!r}"
                    )
                    outcome = adapter._last_provider_outcome
                    assert outcome is not None and outcome.matcher is not None
                    assert outcome.matcher.selection.value == "canonical_fallback"
                    assert 1 <= outcome.matcher.fallback_comparisons <= 64
                    assert record["lowerings"] == 1
                    assert record["canonical_matches"] >= 1
                    assert record["proofs"] == 1
                    assert record["emitters"] == 1
                    fallback_records.append(record)
                else:
                    assert result is not None

            if fallback_probe:
                # This is a semantic witness, not a repeated benchmark.  The
                # fallback emitter replaces native state, so invoking it over
                # and over on one live minsn_t is not a valid way to measure
                # callback cost and eventually retires the witness itself.
                profiler = cProfile.Profile()
                profiler.enable()
                tracemalloc.start()
                allocation_before = tracemalloc.get_traced_memory()[0]
                started = time.perf_counter()
                callback()
                elapsed = time.perf_counter() - started
                gc.collect()
                allocation_current, allocation_peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                profiler.disable()
                profile_stream = io.StringIO()
                pstats.Stats(profiler, stream=profile_stream).strip_dirs().sort_stats(
                    "cumulative"
                ).print_stats()
                calls.update(
                    {
                        "fallback_records": fallback_records,
                        "profile_iterations": 1,
                        "profile": profile_stream.getvalue(),
                        "allocation_before_bytes": allocation_before,
                        "allocation_current_bytes": allocation_current,
                        "allocation_peak_bytes": allocation_peak,
                        "allocation_second_current_bytes": allocation_current,
                        "allocation_second_peak_bytes": allocation_peak,
                    }
                )
                calls["sample_batches"] = 1
                calls["batch_iterations"] = 1
                return [elapsed], calls
            for _ in range(10):
                callback()
            # The production adapter/emitter path is deliberately sampled in
            # short batches: a 5,000-callback batch is useful for the
            # synthetic work-bound probe below, but makes ten fresh native
            # mode setup calls needlessly take several minutes.  Twenty
            # independent 1,000-callback samples provide stable batch means
            # for the p95 while keeping each paired mode comparison bounded.
            sample_batches = 20
            batch_iterations = 1000
            samples: list[float] = []
            for _ in range(sample_batches):
                started = time.perf_counter()
                for _ in range(batch_iterations):
                    callback()
                samples.append((time.perf_counter() - started) / batch_iterations)
            calls.update(
                {
                    "adapter": adapter.name,
                    "candidate_ea": getattr(candidate_ins, "ea", None),
                    "candidate_path": sample.path,
                    "owner_ea": getattr(sample.top_instruction, "ea", None),
                    "function_ea": getattr(sample.mba, "entry_ea", None),
                    "candidate_digest": hashlib.sha256(
                        repr(_benchmark_ast_shape(candidate_ast)).encode()
                    ).hexdigest(),
                    "pattern_candidates": len(adapter.pattern_candidates),
                    "canonical_fallback_enabled": adapter.canonical_fallback_enabled,
                    "certificate_authorized": (
                        state.current_certified_catalogue_snapshot is not None
                    ),
                    "adapter_receipt": tuple(
                        (
                            rule.name,
                            getattr(rule, "canonical_fallback_declaration_index", None),
                            len(rule.pattern_candidates),
                            bool(rule.canonical_fallback_enabled),
                            tuple(rule.maturities),
                            bool(rule.uses_structural_matching),
                        )
                        for rule in adapters
                    ),
                    "adapter_identity": tuple(id(rule) for rule in adapters),
                    # Keep the fresh native adapter proxies alive until the
                    # paired arm has recorded its identity.  Otherwise SWIG
                    # may recycle a proxy address after the state context
                    # closes and make a genuinely fresh set look aliased.
                    "_adapter_objects": adapters,
                    "sample_identity": (
                        id(sample.mba),
                        id(sample.block),
                        id(sample.top_instruction),
                        id(sample.instruction),
                        id(sample.ast),
                    ),
                    "sample_batches": sample_batches,
                    "batch_iterations": batch_iterations,
                    "ordered_rule_schedule": ordered_schedule,
                    "allowed_rule_names": tuple(sorted(allowed)),
                    "scheduled_rule_names": tuple(sorted(scheduled)),
                    "project_document": project_document,
                    "authorization": authorization,
                    "runtime_settings": runtime_settings,
                    "cache_policy": cache_policy,
                }
            )
            return samples, calls

    @staticmethod
    def _p95(samples: list[float]) -> float:
        return statistics.quantiles(samples, n=20, method="inclusive")[18]

    @staticmethod
    def _append_performance_receipt(content: str) -> None:
        from pathlib import Path

        path = Path(__file__).resolve().parents[3] / ".tmp" / "canonical-fallback-performance.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        previous = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(previous + content, encoding="utf-8")

    @pytest.mark.ida_required
    def test_bounded_callback_performance(
        self, compiler_shape_real_asts, d810_state, monkeypatch, pseudocode_to_string
    ):
        """Record stable raw-hit and bounded fallback callback cost samples."""
        # Logging is not part of the callback budget and would dominate the
        # sub-millisecond samples below.
        monkeypatch.setattr(optimizer_logger, "disabled", True)
        # ``info_on`` is a cached LevelFlag.  Invalidate it after changing the
        # logger so discovery/timing cannot dereference a native instruction
        # merely to format a disabled diagnostic message.
        info_flag = optimizer_logger.info_on
        info_flag._last_version = -1
        from d810.mba import canonical_pattern

        catalogue_compilations = 0
        native_compile = canonical_pattern.compile_canonical_pattern

        def count_catalogue_compile(*args, **kwargs):
            nonlocal catalogue_compilations
            catalogue_compilations += 1
            return native_compile(*args, **kwargs)

        monkeypatch.setattr(
            canonical_pattern,
            "compile_canonical_pattern",
            count_catalogue_compile,
        )
        evidence = _collect_real_shadow_evidence(
            d810_state,
            pseudocode_to_string,
            monkeypatch,
        )
        evidence_snapshot, evidence_ledger, evidence_receipt = evidence
        runtime_mode = "cython" if get_engine_info()["backend"] == "cython" else "python"
        from tests.system.e2e.test_mba_compiler_shape_corpus import (
            build_real_shadow_activation,
        )

        certificate_path = (
            Path(__file__).resolve().parents[3]
            / ".tmp"
            / f"task7-production-benchmark-{runtime_mode}.certificate.json"
        )
        activation_path, expectation = build_real_shadow_activation(
            snapshot=evidence_snapshot,
            ledger=evidence_ledger,
            runtime_mode=runtime_mode,
            output_path=certificate_path,
        )
        assert expectation.observation_count == evidence_ledger.observation_count
        assert expectation.legacy_observation_count == evidence_ledger.legacy_match_count
        assert evidence_receipt["manifest_case_count"] == 76
        pinned_sample = self._discover_production_sample(
            compiler_shape_real_asts, d810_state, monkeypatch
        )
        benchmark_commit = os.environ.get("D810_BENCHMARK_COMMIT", "not supplied")
        fallback, fallback_calls = self._sample_production_raw_hit(
            pinned_sample,
            d810_state,
            monkeypatch,
            activation_path,
            fallback_enabled=True,
            fallback_probe=True,
        )
        rounds = []
        for round_index in range(5):
            if round_index % 2 == 0:
                baseline, baseline_calls = self._sample_production_raw_hit(
                    pinned_sample,
                    d810_state,
                    monkeypatch,
                    activation_path,
                    fallback_enabled=False,
                )
                candidate, candidate_calls = self._sample_production_raw_hit(
                    pinned_sample,
                    d810_state,
                    monkeypatch,
                    activation_path,
                    fallback_enabled=True,
                )
            else:
                candidate, candidate_calls = self._sample_production_raw_hit(
                    pinned_sample,
                    d810_state,
                    monkeypatch,
                    activation_path,
                    fallback_enabled=True,
                )
                baseline, baseline_calls = self._sample_production_raw_hit(
                    pinned_sample,
                    d810_state,
                    monkeypatch,
                    activation_path,
                    fallback_enabled=False,
                )
            assert baseline_calls["adapter"] == "Add_HackersDelightRule_4"
            assert candidate_calls["adapter"] == baseline_calls["adapter"]
            assert candidate_calls["candidate_ea"] == baseline_calls["candidate_ea"]
            assert candidate_calls["candidate_path"] == baseline_calls["candidate_path"]
            assert candidate_calls["owner_ea"] == baseline_calls["owner_ea"]
            assert candidate_calls["function_ea"] == baseline_calls["function_ea"]
            assert candidate_calls["candidate_digest"] == baseline_calls[
                "candidate_digest"
            ]
            baseline_receipt = baseline_calls["adapter_receipt"]
            candidate_receipt = candidate_calls["adapter_receipt"]
            # The ordered certified rule set and runtime configuration are
            # identical; only the candidate representation/rollout bit is
            # intentionally different (legacy permutations vs one canonical
            # candidate). ``uses_structural_matching`` is a derived view of
            # that same rollout bit, so assert it explicitly below rather
            # than treating it as an independent configuration difference.
            assert tuple(
                (row[0], row[1], row[4]) for row in candidate_receipt
            ) == tuple(
                (row[0], row[1], row[4]) for row in baseline_receipt
            )
            assert tuple(row[3] for row in baseline_receipt) == tuple(
                False for _ in baseline_receipt
            )
            assert tuple(row[3] for row in candidate_receipt) == tuple(
                True for _ in candidate_receipt
            )
            assert tuple(row[5] for row in baseline_receipt) == tuple(
                False for _ in baseline_receipt
            )
            assert tuple(row[5] for row in candidate_receipt) == tuple(
                True for _ in candidate_receipt
            )
            assert set(id(rule) for rule in baseline_calls["_adapter_objects"]).isdisjoint(
                id(rule) for rule in candidate_calls["_adapter_objects"]
            )
            assert baseline_calls["sample_identity"] == candidate_calls[
                "sample_identity"
            ]
            assert baseline_calls["ordered_rule_schedule"] == candidate_calls[
                "ordered_rule_schedule"
            ]
            assert baseline_calls["allowed_rule_names"] == candidate_calls[
                "allowed_rule_names"
            ]
            assert baseline_calls["scheduled_rule_names"] == candidate_calls[
                "scheduled_rule_names"
            ]
            assert baseline_calls["project_document"] == candidate_calls[
                "project_document"
            ]
            assert baseline_calls["authorization"] == candidate_calls[
                "authorization"
            ]
            baseline_runtime = dict(baseline_calls["runtime_settings"])
            candidate_runtime = dict(candidate_calls["runtime_settings"])
            baseline_runtime.pop("canonical_fallback_env")
            candidate_runtime.pop("canonical_fallback_env")
            assert baseline_runtime == candidate_runtime
            baseline_cache = dict(baseline_calls["cache_policy"])
            candidate_cache = dict(candidate_calls["cache_policy"])
            baseline_cache.pop("indexed_pattern_count")
            candidate_cache.pop("indexed_pattern_count")
            assert baseline_cache == candidate_cache
            rounds.append(
                {
                    "baseline_median": statistics.median(baseline),
                    "candidate_median": statistics.median(candidate),
                    "baseline_p95": self._p95(baseline),
                    "candidate_p95": self._p95(candidate),
                    "median_delta": statistics.median(candidate)
                    / statistics.median(baseline)
                    - 1.0,
                    "p95_delta": self._p95(candidate) / self._p95(baseline) - 1.0,
                }
            )
        baseline_median = statistics.median(
            [round_result["baseline_median"] for round_result in rounds]
        )
        candidate_median = statistics.median(
            [round_result["candidate_median"] for round_result in rounds]
        )
        candidate_p95 = statistics.median(
            [round_result["candidate_p95"] for round_result in rounds]
        )
        baseline_p95 = statistics.median(
            [round_result["baseline_p95"] for round_result in rounds]
        )
        raw_regression = candidate_median / baseline_median - 1.0
        raw_p95_regression = candidate_p95 / baseline_p95 - 1.0
        digest = baseline_calls["candidate_digest"]
        assert raw_regression <= 0.05, raw_regression
        assert raw_p95_regression <= 0.10, raw_p95_regression
        assert baseline_calls["canonical_fallback_enabled"] is False
        assert candidate_calls["canonical_fallback_enabled"] is True
        assert baseline_calls["certificate_authorized"] is True
        assert candidate_calls["certificate_authorized"] is True
        assert fallback_calls["fallback_records"]
        assert all(
            record["lowerings"] == 1
            and record["canonical_matches"] >= 1
            and record["proofs"] == 1
            and record["emitters"] == 1
            for record in fallback_calls["fallback_records"]
        )
        assert len(fallback_calls["fallback_records"]) == 1
        assert fallback_calls["allocation_peak_bytes"] < 10 * 1024 * 1024
        assert fallback_calls["profile"]
        fallback_p95 = fallback[0] if len(fallback) == 1 else self._p95(fallback)
        _provenance = runtime_provenance()
        self._append_performance_receipt(
            "\n## Task 7 callback benchmark\n\n"
            f"- Host worktree commit: `{benchmark_commit}`\n"
            f"- Docker image: `{_provenance['runtime_image']}` (`{_provenance['runtime_image_id']}`)\n"
            f"- Engine clock offset: `{_provenance['engine_clock_offset_seconds']}` s\n"
            f"- Runtime backend: `{get_engine_info()['backend']}`; `D810_NO_CYTHON={os.environ.get('D810_NO_CYTHON', '1')}`\n"
            "- Commands: Python `D810_BENCHMARK_COMMIT=$(git -C .worktrees/canonical-mba-matcher-fallback rev-parse HEAD) ./tools/scripts/run_system_tests_docker.sh test -w canonical-mba-matcher-fallback -o task7-production-benchmark-real-python-final.txt -- tests/system/runtime/test_pattern_engine_benchmark.py::TestCanonicalFallbackWorkBounds::test_bounded_callback_performance -q -s -rs`; Cython `D810_BENCHMARK_COMMIT=$(git -C .worktrees/canonical-mba-matcher-fallback rev-parse HEAD) D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh test -w canonical-mba-matcher-fallback -o task7-production-benchmark-real-cython-final.txt -- tests/system/runtime/test_pattern_engine_benchmark.py::TestCanonicalFallbackWorkBounds::test_bounded_callback_performance -q -s -rs`\n"
            "- Mode comparison: fresh production `Add_HackersDelightRule_4` adapter set with `D810_CANONICAL_MATCH_FALLBACK=0` (baseline) versus `=1` (candidate); identical full catalogue rules, cache policy, pinned compiler-shape function, candidate EA, and AST digest.\n"
            f"- Evidence: complete `{evidence_receipt['manifest_case_count']}`-case native shadow capture, manifest digest `{evidence_receipt['manifest_digest']}`; pinned AST digest `{digest}` (candidate EA `{baseline_calls['candidate_ea']}`, owner EA `{baseline_calls['owner_ea']}`, path `{baseline_calls['candidate_path']}`, function EA `{baseline_calls['function_ea']}`)\n"
            "- Production samples: 5 paired fresh-state rounds, each 20 x 1000 callback iterations after 10 warmups; aggregate values are medians of per-round medians/p95s in seconds/callback\n"
            f"- Raw-hit baseline: median `{baseline_median:.9g}`, p95 `{baseline_p95:.9g}`\n"
            f"- Raw-hit fallback-enabled: median `{candidate_median:.9g}`, p95 `{candidate_p95:.9g}`, median delta `{raw_regression:.2%}`, p95 delta `{raw_p95_regression:.2%}`\n"
            + "- Per-round deltas (baseline/candidate order alternated): "
            + "; ".join(
                f"r{index + 1} median {round_result['median_delta']:.2%}, p95 {round_result['p95_delta']:.2%}"
                for index, round_result in enumerate(rounds)
            )
            + "\n"
            f"- Controlled live raw-miss/fallback-hit probe: median `{statistics.median(fallback):.9g}`, p95 `{fallback_p95:.9g}` across one callback; the callback had one shared lowering, 1..64 canonical comparisons, one native proof, and one emitter\n"
            f"- Callback counts: catalogue compilation during benchmark setup `{catalogue_compilations}`; live fallback callbacks `{len(fallback_calls['fallback_records'])}`; per-rule extra lowering `0`\n"
            f"- Allocation observation: one traced callback, peak `{fallback_calls['allocation_peak_bytes']}` bytes, retained current `{fallback_calls['allocation_current_bytes']}` bytes after GC (bound 10485760)\n"
            "- Work counts: raw-hit canonical lowering/comparisons `0/0`; controlled live fallback is separately bounded and uses the production lowerer -> canonical matcher -> native proof -> emitter path\n"
            "- Dominant callback paths (cProfile, cumulative):\n"
            + "\n".join(f"  {line}" for line in fallback_calls["profile"].strip().splitlines())
            + "\n"
            "- Cache contract: callback-owned canonical lowering/report/path/binding state is asserted cleared by the compiler-shape corpus gate.\n"
        )


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
        from d810.optimizers.microcode.instructions.pattern_matching.handler import (
            PatternOptimizer,
        )
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

        print("\n  Hot path (no rules):")
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
            miss_asts = [
                ast
                for ast, _ in real_asts
                if ast.is_node() and ast.opcode not in pattern_opcodes
            ][:10]

            if hit_asts:

                def lookup_hit_legacy():
                    for ast in hit_asts:
                        _ = legacy_storage.get_matching_rule_pattern_info(ast)

                def lookup_hit_new():
                    for ast in hit_asts:
                        _ = new_storage.get_candidates(ast)

                legacy_hit_time = timed_run(
                    lookup_hit_legacy, iterations=100, warmup=10
                )
                new_hit_time = timed_run(lookup_hit_new, iterations=100, warmup=10)

                results["lookup_hit"] = {
                    "candidate_count": len(hit_asts),
                    "legacy_us_per_lookup": (legacy_hit_time / 100 / len(hit_asts))
                    * 1_000_000,
                    "new_us_per_lookup": (new_hit_time / 100 / len(hit_asts))
                    * 1_000_000,
                    "speedup": legacy_hit_time / new_hit_time
                    if new_hit_time > 0
                    else 0,
                }

            if miss_asts:

                def lookup_miss_legacy():
                    for ast in miss_asts:
                        _ = legacy_storage.get_matching_rule_pattern_info(ast)

                def lookup_miss_new():
                    for ast in miss_asts:
                        _ = new_storage.get_candidates(ast)

                legacy_miss_time = timed_run(
                    lookup_miss_legacy, iterations=100, warmup=10
                )
                new_miss_time = timed_run(lookup_miss_new, iterations=100, warmup=10)

                results["lookup_miss"] = {
                    "candidate_count": len(miss_asts),
                    "legacy_us_per_lookup": (legacy_miss_time / 100 / len(miss_asts))
                    * 1_000_000,
                    "new_us_per_lookup": (new_miss_time / 100 / len(miss_asts))
                    * 1_000_000,
                    "speedup": legacy_miss_time / new_miss_time
                    if new_miss_time > 0
                    else 0,
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
        from d810.optimizers.microcode.instructions.pattern_matching.handler import (
            PatternOptimizer,
        )
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
                "us_per_instruction": (hot_path_time / 10 / len(instructions))
                * 1_000_000,
                "throughput_insns_per_sec": len(instructions) / (hot_path_time / 10),
            }

        # Save results
        baseline_path = (
            Path(__file__).resolve().parents[3]
            / "docs"
            / "copycat"
            / "benchmarks"
            / "baseline_pattern_engine.json"
        )
        save_baseline(results, baseline_path, "Pattern Engine Baseline (PR0)")

        print(f"\n  Baseline saved to: {baseline_path}")
        print(f"  Summary saved to: {baseline_path.with_suffix('.md')}")

        assert baseline_path.exists(), "JSON baseline file not created"
        assert baseline_path.with_suffix(".md").exists(), "Markdown summary not created"
