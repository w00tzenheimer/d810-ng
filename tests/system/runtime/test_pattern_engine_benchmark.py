"""Benchmark tests for pattern matching engine performance.

Measures baseline performance of pattern storage, lookup, matching, and
full hot path optimization. Uses real microcode ASTs from test binaries.

All tests require IDA Pro with Hex-Rays decompiler.
"""

from __future__ import annotations

import os
import platform
import hashlib
import statistics
import subprocess
import time
from types import SimpleNamespace

import pytest

import ida_hexrays
import idaapi
import idc

from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.core.cymode import CythonMode
from d810.hexrays.expr.p_ast import AstLeaf, AstNode
from d810.hexrays.ir import minsn_utils
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.mba.provider_outcome import RawMatcherWorkReceipt
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

        def _resolve(_mop, _blk, _ins, *, node_budget=None):
            assert node_budget is budget_under_test
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

    binary_name = _get_default_binary()

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
            "lowerings": [],
            "receipts": [],
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
                calls["lowerings"].append(lowering)
                return lowering

            def match_structural_and_replace(self, _candidate, **_kwargs):
                calls["fallback"] += 1
                return fallback_result

            def clear_match_context(self):
                return None

            def bind_match_context(self, _blk, _ins):
                return None

            def record_raw_match_receipt(self, _receipt):
                calls["receipts"].append(_receipt)

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
        assert len(raw_calls["receipts"]) == 1
        assert isinstance(raw_calls["receipts"][0], RawMatcherWorkReceipt)
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

    def _sample_raw_hit(self, ast, *, fallback_enabled: bool) -> tuple[list[float], dict]:
        """Sample the real handler callback with an unchanged raw-hit fixture."""
        raw_rule, pattern, calls = self._make_rule(
            "raw-benchmark",
            raw_result=self._callback_instruction(),
        )
        fallback_rules = ()
        if fallback_enabled:
            term, shape = self._term_and_shape()
            fallback_rules = (self._make_rule("fallback-benchmark", shape=shape)[0],)
            raw_rule.canonical_fallback_root_shapes = (shape,)
            raw_rule._task7_fallback_term = term
        optimizer = self._optimizer_for(raw_rule, fallback_rules)
        samples: list[float] = []
        block = SimpleNamespace(
            mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)
        )
        instruction = self._callback_instruction()

        def callback() -> None:
            result = optimizer._try_matches(
                block,
                instruction,
                ast,
                allowed_rule_names=None,
                scheduled_rule_names=frozenset(),
                source_label="task7-benchmark-raw-hit",
            )
            assert result is not None

        for _ in range(10):
            callback()
        for _ in range(40):
            started = time.perf_counter()
            for _ in range(5000):
                callback()
            samples.append((time.perf_counter() - started) / 5000.0)
        return samples, calls

    def _sample_fallback_hit(self, ast) -> tuple[list[float], dict]:
        """Sample the controlled clean-miss/fallback-hit callback."""
        term, shape = self._term_and_shape()
        raw_rule, pattern, _raw_calls = self._make_rule("raw-benchmark", shape=shape)
        fallback_rule, _fallback_pattern, calls = self._make_rule(
            "fallback-benchmark",
            shape=shape,
            fallback_result=self._callback_instruction(),
        )
        optimizer = self._optimizer_for(raw_rule, (fallback_rule,))
        block = SimpleNamespace(
            mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)
        )
        instruction = self._callback_instruction()

        def callback() -> None:
            result = optimizer._try_matches(
                block,
                instruction,
                ast,
                allowed_rule_names=None,
                scheduled_rule_names=frozenset(),
                source_label="task7-benchmark-fallback-hit",
            )
            assert result is not None

        for _ in range(10):
            callback()
        samples: list[float] = []
        for _ in range(40):
            started = time.perf_counter()
            for _ in range(5000):
                callback()
            samples.append((time.perf_counter() - started) / 5000.0)
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
    def test_bounded_callback_performance(self, real_asts, monkeypatch):
        """Record stable raw-hit and bounded fallback callback cost samples."""
        # Logging is not part of the callback budget and would dominate the
        # sub-millisecond samples below.
        monkeypatch.setattr(optimizer_logger, "disabled", True)
        ast = next(ast for ast, _ins in real_asts if ast.is_node())
        digest = hashlib.sha256(repr(_ast_projection(ast)).encode()).hexdigest()
        baseline, baseline_calls = self._sample_raw_hit(ast, fallback_enabled=False)
        candidate, candidate_calls = self._sample_raw_hit(ast, fallback_enabled=True)
        fallback, fallback_calls = self._sample_fallback_hit(ast)
        baseline_median = statistics.median(baseline)
        candidate_median = statistics.median(candidate)
        candidate_p95 = self._p95(candidate)
        baseline_p95 = self._p95(baseline)
        raw_regression = candidate_median / baseline_median - 1.0
        raw_p95_regression = candidate_p95 / baseline_p95 - 1.0
        assert raw_regression <= 0.05, raw_regression
        assert raw_p95_regression <= 0.10, raw_p95_regression
        assert baseline_calls["fallback"] == 0
        assert candidate_calls["fallback"] == 0
        assert fallback_calls["fallback"] == 40 * 5000 + 10
        self._append_performance_receipt(
            "\n## Task 7 callback benchmark\n\n"
            f"- Commit: `{subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}`\n"
            f"- Docker image: `{os.environ.get('D810_TEST_RUNTIME_IMAGE', 'unknown')}` (`{os.environ.get('D810_TEST_RUNTIME_IMAGE_ID', 'unknown')}`)\n"
            f"- Runtime backend: `{get_engine_info()['backend']}`; `D810_NO_CYTHON={os.environ.get('D810_NO_CYTHON', '1')}`\n"
            "- Commands: `./tools/scripts/run_system_tests_docker.sh test -w canonical-mba-matcher-fallback -o task7-benchmark-python.txt -- tests/system/runtime/test_pattern_engine_benchmark.py -k CanonicalFallbackWorkBounds -q`; Cython: `D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh test -w canonical-mba-matcher-fallback -o task7-benchmark-cython.txt -- tests/system/runtime/test_pattern_engine_benchmark.py -k CanonicalFallbackWorkBounds -q`\n"
            "- Mode comparison: fallback registry absent (baseline) versus present (candidate); identical pytest fixture/rules/cache policy\n"
            f"- Corpus digest: `{digest}` (one live `real_asts` AST)\n"
            "- Samples: 40 x 5000 callback iterations after 10 warmups; values are seconds/callback\n"
            f"- Raw-hit baseline: median `{baseline_median:.9g}`, p95 `{baseline_p95:.9g}`\n"
            f"- Raw-hit fallback-enabled: median `{candidate_median:.9g}`, p95 `{candidate_p95:.9g}`, median delta `{raw_regression:.2%}`, p95 delta `{raw_p95_regression:.2%}`\n"
            f"- Controlled raw-miss/fallback-hit: median `{statistics.median(fallback):.9g}`, p95 `{self._p95(fallback):.9g}`; fallback calls `{fallback_calls['fallback']}`; max comparisons `64` (verified independently by the live compiler-shape receipt, not this callback stub)\n"
            "- Work counts: raw-hit canonical lowering/comparisons `0/0`; clean-miss lowering `1` shared by eligible bucket; fallback budget separate from raw budget\n"
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
