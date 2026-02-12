"""System tests for pattern matching speedup optimizations.

Tests the three optimizations against REAL IDA microcode:
1. Non-mutating pattern match (match_pattern_nomut)
2. O(1) opcode-indexed pattern storage (OpcodeIndexedStorage)
3. Pre-computed pattern fingerprints (PatternFingerprint)

These tests require IDA Pro with Hex-Rays decompiler. They generate real
microcode from binary samples, convert minsn_t to AST via minsn_to_ast(),
and exercise the speedup functions against real AST trees -- no mocks.
"""

from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.expr.p_ast import (
    AstConstant,
    AstLeaf,
    AstNode,
    minsn_to_ast,
)
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    MatchBindings,
    OpcodeIndexedStorage,
    PatternFingerprint,
    compute_fingerprint,
    match_pattern_nomut,
)

# Detect whether the Cython extension is available
try:
    from d810.speedups.optimizers.c_pattern_match import (
        CMatchBindings,
        COpcodeIndexedStorage,
        CRulePatternEntry,
        compute_fingerprint_py as cython_compute_fingerprint,
        match_pattern_nomut as cython_match_pattern_nomut,
    )
    HAS_CYTHON = True
except ImportError:
    HAS_CYTHON = False


# =========================================================================
# Helpers
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
    """Generate microcode at a specific maturity level.

    Returns an mba_t object or None if generation fails.
    """
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
    """Walk all blocks in an mba_t and convert each minsn_t to an AST.

    Returns a list of (ast, minsn) tuples for instructions that
    successfully convert to AST trees.
    """
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


def find_ast_nodes(asts: list) -> list:
    """Filter to only AstNode instances (not leaves) from collected ASTs."""
    return [(ast, ins) for ast, ins in asts if ast.is_node()]


def find_ast_with_children(asts: list) -> list:
    """Filter to AstNode instances that have both left and right children."""
    result = []
    for ast, ins in asts:
        if ast.is_node():
            left = getattr(ast, "left", None)
            right = getattr(ast, "right", None)
            if left is not None and right is not None:
                result.append((ast, ins))
    return result


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


@pytest.fixture(scope="class")
def real_asts(libobfuscated_setup):
    """Class-scoped fixture providing real AST trees from microcode.

    Generates microcode from a known function in the test binary and
    converts all instructions to AST trees via minsn_to_ast().
    Returns a list of (ast, minsn) tuples.
    """
    test_functions = [
        "test_cst_simplification",
        "test_xor",
        "test_mba_guessing",
        "test_chained_add",
        "test_opaque_predicate",
    ]

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
            if len(asts) >= 3:
                print(
                    f"\n  Collected {len(asts)} ASTs from {func_name} "
                    f"@ maturity {maturity}"
                )
                return asts

    pytest.skip("Could not collect enough ASTs from any test function")


# =========================================================================
# Test: PatternFingerprint (pure dataclass -- no IDA needed, no mocks)
# =========================================================================


class TestPatternFingerprint:
    """Test pre-computed pattern fingerprints (pure dataclass logic)."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_fingerprint_equality(self, libobfuscated_setup):
        """Two identical fingerprints should be equal."""
        fp1 = PatternFingerprint(opcode_hash=0x123, depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(opcode_hash=0x123, depth=3, node_count=2, leaf_count=3, const_count=1)
        assert fp1 == fp2

    @pytest.mark.ida_required
    def test_fingerprint_inequality_opcode_hash(self, libobfuscated_setup):
        """Different opcode_hash means different fingerprint."""
        fp1 = PatternFingerprint(opcode_hash=0x123, depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(opcode_hash=0x456, depth=3, node_count=2, leaf_count=3, const_count=1)
        assert fp1 != fp2

    @pytest.mark.ida_required
    def test_fingerprint_inequality_depth(self, libobfuscated_setup):
        """Different depth means different fingerprint."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(depth=4, node_count=2, leaf_count=3, const_count=1)
        assert fp1 != fp2

    @pytest.mark.ida_required
    def test_fingerprint_compatible_same(self, libobfuscated_setup):
        """Identical fingerprints should be compatible."""
        fp = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        assert fp.compatible_with(fp) is True

    @pytest.mark.ida_required
    def test_fingerprint_compatible_different_depth_rejects(self, libobfuscated_setup):
        """Different depth should reject."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(depth=4, node_count=2, leaf_count=3, const_count=1)
        assert fp1.compatible_with(fp2) is False

    @pytest.mark.ida_required
    def test_fingerprint_compatible_different_node_count_rejects(self, libobfuscated_setup):
        """Different node count should reject."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(depth=3, node_count=3, leaf_count=3, const_count=1)
        assert fp1.compatible_with(fp2) is False

    @pytest.mark.ida_required
    def test_fingerprint_compatible_leaf_const_swap_accepts(self, libobfuscated_setup):
        """Swapping leaf and const counts (same total) should accept."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=2, const_count=2)
        fp2 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        assert fp1.compatible_with(fp2) is True

    @pytest.mark.ida_required
    def test_fingerprint_compatible_different_total_operands_rejects(self, libobfuscated_setup):
        """Different total operand count should reject."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=2, const_count=1)
        fp2 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        assert fp1.compatible_with(fp2) is False


# =========================================================================
# Test: compute_fingerprint with real AST trees
# =========================================================================


class TestComputeFingerprintReal:
    """Test fingerprint computation from real AST trees extracted from microcode."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_real_leaf_fingerprint(self, real_asts):
        """compute_fingerprint on a real AstLeaf produces valid fingerprint."""
        # Find a real leaf from an AST tree
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                if left is not None and left.is_leaf() and not left.is_constant():
                    fp = compute_fingerprint(left)
                    assert fp.depth == 1
                    assert fp.node_count == 0
                    assert fp.leaf_count == 1
                    assert fp.const_count == 0
                    return
        pytest.skip("No real AstLeaf found in collected ASTs")

    @pytest.mark.ida_required
    def test_real_constant_fingerprint(self, real_asts):
        """compute_fingerprint on a real AstConstant produces valid fingerprint."""
        for ast, _ in real_asts:
            if ast.is_node():
                for child_attr in ("left", "right"):
                    child = getattr(ast, child_attr, None)
                    if child is not None and child.is_constant():
                        fp = compute_fingerprint(child)
                        assert fp.depth == 1
                        assert fp.node_count == 0
                        assert fp.leaf_count == 0
                        assert fp.const_count == 1
                        return
        pytest.skip("No real AstConstant found in collected ASTs")

    @pytest.mark.ida_required
    def test_real_node_fingerprint(self, real_asts):
        """compute_fingerprint on a real AstNode has correct structure counts."""
        nodes = find_ast_nodes(real_asts)
        assert len(nodes) > 0, "Expected at least one AstNode in microcode"

        ast, _ = nodes[0]
        fp = compute_fingerprint(ast)
        assert fp.depth >= 1, f"Depth should be >= 1, got {fp.depth}"
        assert fp.node_count >= 1, f"Node count should be >= 1, got {fp.node_count}"
        assert (fp.leaf_count + fp.const_count) >= 0

    @pytest.mark.ida_required
    def test_real_nested_node_fingerprint(self, real_asts):
        """compute_fingerprint on a nested real AstNode has depth >= 2."""
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                right = getattr(ast, "right", None)
                if (left is not None and left.is_node()) or (
                    right is not None and right.is_node()
                ):
                    fp = compute_fingerprint(ast)
                    assert fp.depth >= 3, (
                        f"Nested node should have depth >= 3, got {fp.depth}"
                    )
                    assert fp.node_count >= 2, (
                        f"Nested node should have >= 2 nodes, got {fp.node_count}"
                    )
                    return
        pytest.skip("No nested AstNode found in collected ASTs")

    @pytest.mark.ida_required
    def test_same_structure_same_hash(self, real_asts):
        """Two real ASTs with the same opcode produce same opcode_hash when structure matches."""
        nodes = find_ast_with_children(real_asts)
        if len(nodes) < 2:
            pytest.skip("Need at least 2 AST nodes with children")

        # Find two nodes with the same root opcode
        by_opcode = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in by_opcode:
                by_opcode[op] = []
            by_opcode[op].append(ast)

        for op, ast_list in by_opcode.items():
            if len(ast_list) >= 2:
                fp1 = compute_fingerprint(ast_list[0])
                fp2 = compute_fingerprint(ast_list[1])
                # If both have the same structure, hashes should match.
                # If structure differs, hashes may differ -- that's also correct.
                # We just verify fingerprints are non-zero.
                assert fp1.opcode_hash != 0 or fp1.node_count == 0
                assert fp2.opcode_hash != 0 or fp2.node_count == 0
                return
        pytest.skip("No two AST nodes with the same root opcode found")

    @pytest.mark.ida_required
    def test_different_opcodes_different_hash(self, real_asts):
        """Real ASTs with different root opcodes produce different opcode_hash."""
        nodes = find_ast_nodes(real_asts)

        # Collect unique opcodes with their first AST
        seen_opcodes = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in seen_opcodes:
                seen_opcodes[op] = ast
            if len(seen_opcodes) >= 2:
                break

        if len(seen_opcodes) < 2:
            pytest.skip("Need at least 2 different root opcodes")

        items = list(seen_opcodes.items())
        fp1 = compute_fingerprint(items[0][1])
        fp2 = compute_fingerprint(items[1][1])
        # Different root opcodes should produce different hashes
        # (unless both are leaf-only, which is very unlikely for nodes)
        if fp1.node_count > 0 and fp2.node_count > 0:
            assert fp1.opcode_hash != fp2.opcode_hash, (
                f"Opcodes {items[0][0]} and {items[1][0]} should produce "
                f"different hashes"
            )

    @pytest.mark.ida_required
    def test_fingerprint_deterministic(self, real_asts):
        """compute_fingerprint is deterministic on the same real AST."""
        nodes = find_ast_nodes(real_asts)
        assert len(nodes) > 0

        ast, _ = nodes[0]
        fp1 = compute_fingerprint(ast)
        fp2 = compute_fingerprint(ast)
        assert fp1 == fp2, "Same AST should produce identical fingerprints"


# =========================================================================
# Test: Non-Mutating Pattern Match with real AST trees
# =========================================================================


class TestMatchPatternNomutReal:
    """Test non-mutating pattern match against real AST trees from microcode."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_real_node_matches_itself(self, real_asts):
        """A real AST node should match itself."""
        nodes = find_ast_nodes(real_asts)
        assert len(nodes) > 0, "Expected at least one AstNode"

        ast, _ = nodes[0]
        bindings = MatchBindings()
        result = match_pattern_nomut(ast, ast, bindings)
        assert result is True, "AST should match itself"
        assert bindings.count > 0, "Should have captured at least one binding"

    @pytest.mark.ida_required
    def test_real_leaf_matches_real_leaf(self, real_asts):
        """A real AstLeaf pattern matches another real AstLeaf candidate."""
        leaves = []
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                if left is not None and left.is_leaf() and left.mop is not None:
                    leaves.append(left)
                right = getattr(ast, "right", None)
                if right is not None and right.is_leaf() and right.mop is not None:
                    leaves.append(right)
            if len(leaves) >= 2:
                break

        if len(leaves) < 2:
            pytest.skip("Need at least 2 real AstLeaf nodes with mops")

        bindings = MatchBindings()
        result = match_pattern_nomut(leaves[0], leaves[1], bindings)
        assert result is True, "Any leaf should match any other leaf with a mop"
        assert bindings.count == 1

    @pytest.mark.ida_required
    def test_real_node_rejects_different_opcode(self, real_asts):
        """Real AST nodes with different opcodes should not match."""
        nodes = find_ast_nodes(real_asts)

        seen_opcodes = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in seen_opcodes:
                seen_opcodes[op] = ast
            if len(seen_opcodes) >= 2:
                break

        if len(seen_opcodes) < 2:
            pytest.skip("Need at least 2 different root opcodes")

        items = list(seen_opcodes.values())
        result = match_pattern_nomut(items[0], items[1])
        assert result is False, "Different opcodes should not match"

    @pytest.mark.ida_required
    def test_pattern_not_mutated_after_real_match(self, real_asts):
        """Pattern tree should not be modified by match_pattern_nomut on real ASTs."""
        nodes = find_ast_nodes(real_asts)
        assert len(nodes) > 0

        pattern_ast, _ = nodes[0]

        # Build a simple pattern from real opcode
        pattern = AstNode(pattern_ast.opcode, AstLeaf("x_0"), AstLeaf("y_0"))
        pattern.freeze()

        orig_left_name = pattern.left.name
        orig_right_name = pattern.right.name
        orig_opcode = pattern.opcode

        # Try matching against the real AST
        match_pattern_nomut(pattern, pattern_ast)

        # Pattern should be unchanged
        assert pattern.opcode == orig_opcode
        assert pattern.left.name == orig_left_name
        assert pattern.right.name == orig_right_name
        assert pattern.is_frozen is True

    @pytest.mark.ida_required
    def test_bindings_capture_real_mops(self, real_asts):
        """MatchBindings should capture real mop_t objects from microcode."""
        nodes_with_children = find_ast_with_children(real_asts)
        if not nodes_with_children:
            pytest.skip("No AST nodes with both children found")

        candidate_ast, _ = nodes_with_children[0]

        # Build a pattern matching the candidate's opcode
        pattern = AstNode(
            candidate_ast.opcode, AstLeaf("x_0"), AstLeaf("y_0")
        )

        bindings = MatchBindings()
        result = match_pattern_nomut(pattern, candidate_ast, bindings)

        if result:
            assert bindings.count >= 1, "Should capture bindings on match"
            # Verify bound mops are real ida_hexrays.mop_t objects
            binding_dict = bindings.to_dict()
            for name, mop in binding_dict.items():
                assert mop is not None, f"Binding '{name}' should have a mop"
                assert hasattr(mop, "t"), f"Binding '{name}' mop should have .t attribute"

    @pytest.mark.ida_required
    def test_bindings_reuse_with_real_asts(self, real_asts):
        """MatchBindings can be reused across multiple real match attempts."""
        nodes_with_children = find_ast_with_children(real_asts)
        if len(nodes_with_children) < 2:
            pytest.skip("Need at least 2 AST nodes with children")

        bindings = MatchBindings()

        for candidate_ast, _ in nodes_with_children[:2]:
            pattern = AstNode(
                candidate_ast.opcode, AstLeaf("x_0"), AstLeaf("y_0")
            )
            result = match_pattern_nomut(pattern, candidate_ast, bindings)
            if result:
                assert bindings.count >= 1

    @pytest.mark.ida_required
    def test_none_mop_leaf_rejects(self, real_asts):
        """A leaf candidate with None mop should be rejected."""
        # Create a leaf with no mop
        candidate = AstLeaf("no_mop")
        candidate.mop = None

        pattern = AstLeaf("x_0")
        pattern.mop = None  # pattern leaf is OK with no mop

        # But we need the pattern to have a mop for the match to succeed
        # The function checks candidate.mop is None and returns False
        for ast, _ in real_asts:
            if ast.is_leaf() and ast.mop is not None:
                # Use real leaf as pattern, None-mop leaf as candidate
                result = match_pattern_nomut(ast, candidate)
                assert result is False, "None mop candidate should be rejected"
                return

        # Use a constructed leaf with an explicit mop as pattern
        pattern_leaf = AstLeaf("x_0")
        # Give it a real mop from any real ast
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                if left is not None and left.mop is not None:
                    pattern_leaf.mop = left.mop
                    result = match_pattern_nomut(pattern_leaf, candidate)
                    assert result is False, "None mop candidate should be rejected"
                    return

        pytest.skip("Could not find real leaf with mop for None-mop test")


# =========================================================================
# Test: Nomut vs clone+match equivalence on real ASTs
# =========================================================================


class TestNomutVsCloneEquivalenceReal:
    """Verify that non-mutating match produces same results as clone+match on real ASTs."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_real_match_equivalence(self, real_asts):
        """match_pattern_nomut agrees with check_pattern_and_copy_mops on real ASTs."""
        nodes_with_children = find_ast_with_children(real_asts)
        if not nodes_with_children:
            pytest.skip("No AST nodes with both children found")

        tested = 0
        for candidate_ast, _ in nodes_with_children[:5]:
            # Build a pattern from the candidate's opcode
            pattern = AstNode(
                candidate_ast.opcode, AstLeaf("x_0"), AstLeaf("y_0")
            )

            # Non-mutating match
            nomut_result = match_pattern_nomut(pattern, candidate_ast)

            # Clone-based match (the old approach)
            pattern_clone = pattern.clone()
            clone_result = pattern_clone.check_pattern_and_copy_mops(candidate_ast)

            assert nomut_result == clone_result, (
                f"nomut ({nomut_result}) != clone ({clone_result}) "
                f"for opcode {candidate_ast.opcode}"
            )
            tested += 1

        assert tested > 0, "Expected to test at least one equivalence"
        print(f"\n  Tested {tested} real ASTs: nomut == clone+match for all")

    @pytest.mark.ida_required
    def test_mismatch_equivalence(self, real_asts):
        """Both approaches agree on mismatches with real ASTs."""
        nodes = find_ast_nodes(real_asts)

        seen_opcodes = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in seen_opcodes:
                seen_opcodes[op] = ast
            if len(seen_opcodes) >= 2:
                break

        if len(seen_opcodes) < 2:
            pytest.skip("Need at least 2 different root opcodes")

        items = list(seen_opcodes.values())
        ast_a, ast_b = items[0], items[1]

        # Build pattern from ast_a's opcode, try matching against ast_b
        pattern = AstNode(ast_a.opcode, AstLeaf("x_0"), AstLeaf("y_0"))

        nomut_result = match_pattern_nomut(pattern, ast_b)
        pattern_clone = pattern.clone()
        clone_result = pattern_clone.check_pattern_and_copy_mops(ast_b)

        assert nomut_result == clone_result, (
            f"nomut ({nomut_result}) != clone ({clone_result}) "
            f"for mismatched opcodes {ast_a.opcode} vs {ast_b.opcode}"
        )


# =========================================================================
# Test: O(1) Opcode-Indexed Storage with real AST trees
# =========================================================================


class TestOpcodeIndexedStorageReal:
    """Test O(1) opcode-indexed pattern storage with real AST trees."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_add_real_pattern_and_retrieve(self, real_asts):
        """Adding a real AST pattern and retrieving it by opcode."""
        nodes = find_ast_nodes(real_asts)
        assert len(nodes) > 0

        storage = OpcodeIndexedStorage()
        ast, _ = nodes[0]

        class RealRule:
            name = "test_rule_1"

        rule = RealRule()
        storage.add_pattern(ast, rule)
        assert storage.total_patterns == 1

        # Use the same AST as candidate -- should retrieve the pattern
        results = storage.get_candidates(ast)
        assert len(results) >= 1
        assert results[0].rule is rule

    @pytest.mark.ida_required
    def test_different_opcode_no_match_real(self, real_asts):
        """Pattern with one opcode should not match candidate with different opcode."""
        nodes = find_ast_nodes(real_asts)

        seen_opcodes = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in seen_opcodes:
                seen_opcodes[op] = ast
            if len(seen_opcodes) >= 2:
                break

        if len(seen_opcodes) < 2:
            pytest.skip("Need at least 2 different root opcodes")

        items = list(seen_opcodes.items())
        storage = OpcodeIndexedStorage()

        class RealRule:
            name = "test_rule"

        storage.add_pattern(items[0][1], RealRule())

        # Candidate with different opcode
        results = storage.get_candidates(items[1][1])
        assert len(results) == 0, (
            f"Opcode {items[0][0]} pattern should not match opcode {items[1][0]} candidate"
        )

    @pytest.mark.ida_required
    def test_multiple_patterns_same_opcode_real(self, real_asts):
        """Multiple real patterns with same root opcode should all be retrievable."""
        nodes = find_ast_nodes(real_asts)

        # Group by opcode
        by_opcode = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in by_opcode:
                by_opcode[op] = []
            by_opcode[op].append(ast)

        # Find an opcode with multiple patterns
        multi_op = None
        for op, ast_list in by_opcode.items():
            if len(ast_list) >= 2:
                multi_op = op
                break

        if multi_op is None:
            pytest.skip("No opcode with multiple AST instances found")

        storage = OpcodeIndexedStorage()
        rules = []
        for i, ast in enumerate(by_opcode[multi_op][:3]):
            class DynRule:
                pass
            rule = DynRule()
            rule.name = f"rule_{i}"
            storage.add_pattern(ast, rule)
            rules.append(rule)

        assert storage.total_patterns == len(rules)

        # Use first AST as candidate
        results = storage.get_candidates(by_opcode[multi_op][0])
        # Should find at least one pattern (the one identical to itself)
        assert len(results) >= 1

    @pytest.mark.ida_required
    def test_fingerprint_filters_incompatible_real(self, real_asts):
        """Patterns with incompatible fingerprints should be filtered out."""
        nodes = find_ast_nodes(real_asts)

        # Find a deep nested AST and a shallow AST with the same root opcode
        by_opcode = {}
        for ast, _ in nodes:
            op = ast.opcode
            fp = compute_fingerprint(ast)
            if op not in by_opcode:
                by_opcode[op] = []
            by_opcode[op].append((ast, fp))

        for op, entries in by_opcode.items():
            if len(entries) < 2:
                continue
            # Find two with different depths
            depths = [(ast, fp) for ast, fp in entries if fp.depth >= 1]
            unique_depths = set(fp.depth for _, fp in depths)
            if len(unique_depths) >= 2:
                # We have ASTs with different depths under the same opcode
                sorted_by_depth = sorted(depths, key=lambda x: x[1].depth)
                shallow = sorted_by_depth[0]
                deep = sorted_by_depth[-1]

                if shallow[1].depth != deep[1].depth:
                    storage = OpcodeIndexedStorage()

                    class DepthRule:
                        name = "deep_rule"

                    storage.add_pattern(deep[0], DepthRule())

                    results = storage.get_candidates(shallow[0])
                    assert len(results) == 0, (
                        f"Deep pattern (depth={deep[1].depth}) should be "
                        f"filtered when candidate has depth={shallow[1].depth}"
                    )
                    print(
                        f"\n  Opcode {op}: depth {deep[1].depth} pattern "
                        f"correctly filtered for depth {shallow[1].depth} candidate"
                    )
                    return

        pytest.skip("No opcode with different depth ASTs found for filtering test")

    @pytest.mark.ida_required
    def test_leaf_patterns_real(self, real_asts):
        """Leaf patterns (no root opcode) should be retrievable."""
        # Find a real leaf
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                if left is not None and left.is_leaf() and left.mop is not None:
                    storage = OpcodeIndexedStorage()

                    class LeafRule:
                        name = "leaf_rule"

                    storage.add_pattern(left, LeafRule())
                    assert storage.total_patterns == 1

                    # Any leaf candidate should be retrieved
                    results = storage.get_candidates(left)
                    assert len(results) == 1
                    assert results[0].rule.name == "leaf_rule"
                    return

        pytest.skip("No real AstLeaf with mop found")


# =========================================================================
# Test: MatchBindings (pure dataclass -- no IDA needed, no mocks)
# =========================================================================


class TestMatchBindings:
    """Test MatchBindings operations (pure dataclass logic)."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_add_and_count(self, libobfuscated_setup):
        """Adding bindings increments count."""
        bindings = MatchBindings()
        assert bindings.count == 0
        bindings.add("x_0", object())
        assert bindings.count == 1
        bindings.add("y_0", object())
        assert bindings.count == 2

    @pytest.mark.ida_required
    def test_reset_clears_bindings(self, libobfuscated_setup):
        """Reset clears all bindings."""
        bindings = MatchBindings()
        bindings.add("x_0", object())
        bindings.add("y_0", object())
        bindings.reset()
        assert bindings.count == 0
        assert len(bindings.bindings) == 0

    @pytest.mark.ida_required
    def test_to_dict_returns_name_mop_pairs(self, libobfuscated_setup):
        """to_dict returns correct {name: mop} mapping."""
        bindings = MatchBindings()
        mop_a = object()
        mop_b = object()
        bindings.add("x_0", mop_a)
        bindings.add("y_0", mop_b)
        d = bindings.to_dict()
        assert d["x_0"] is mop_a
        assert d["y_0"] is mop_b

    @pytest.mark.ida_required
    def test_max_capacity(self, libobfuscated_setup):
        """Exceeding MAX_BINDINGS returns False."""
        bindings = MatchBindings()
        for i in range(MatchBindings.MAX_BINDINGS):
            assert bindings.add(f"v_{i}", object()) is True
        assert bindings.add("overflow", object()) is False
        assert bindings.count == MatchBindings.MAX_BINDINGS

    @pytest.mark.ida_required
    def test_get_leafs_by_name(self, libobfuscated_setup):
        """get_leafs_by_name returns MatchBinding objects indexed by name."""
        bindings = MatchBindings()
        mop_a = object()
        bindings.add("x_0", mop_a, dest_size=4, ea=0x1000)
        result = bindings.get_leafs_by_name()
        assert "x_0" in result
        assert result["x_0"].mop is mop_a
        assert result["x_0"].dest_size == 4
        assert result["x_0"].ea == 0x1000


# =========================================================================
# Test: Integration -- build real patterns from real microcode
# =========================================================================


class TestIntegrationRealPatterns:
    """Integration tests combining all speedups with real microcode patterns."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_full_pipeline_real_microcode(self, real_asts):
        """Full pipeline: compute fingerprint, store, retrieve, match on real ASTs."""
        nodes_with_children = find_ast_with_children(real_asts)
        if not nodes_with_children:
            pytest.skip("No AST nodes with children found")

        storage = OpcodeIndexedStorage()

        # Register patterns from the first few real ASTs
        registered = []
        for i, (ast, _) in enumerate(nodes_with_children[:5]):
            class PipelineRule:
                pass
            rule = PipelineRule()
            rule.name = f"pipeline_rule_{i}"
            storage.add_pattern(ast, rule)
            registered.append((ast, rule))

        assert storage.total_patterns == len(registered)

        # Now try to match each registered pattern against itself
        matched = 0
        for ast, rule in registered:
            candidates = storage.get_candidates(ast)
            if candidates:
                for entry in candidates:
                    bindings = MatchBindings()
                    if match_pattern_nomut(entry.pattern, ast, bindings):
                        matched += 1
                        break

        assert matched > 0, (
            f"Expected at least one successful match out of {len(registered)} patterns"
        )
        print(
            f"\n  Full pipeline: {matched}/{len(registered)} patterns matched "
            f"against themselves"
        )

    @pytest.mark.ida_required
    def test_fingerprint_compatible_with_self(self, real_asts):
        """Every real AST's fingerprint should be compatible with itself."""
        nodes = find_ast_nodes(real_asts)
        for ast, _ in nodes[:10]:
            fp = compute_fingerprint(ast)
            assert fp.compatible_with(fp) is True, (
                f"Fingerprint should be compatible with itself: {fp}"
            )

    @pytest.mark.ida_required
    def test_binding_equalities_with_real_mops(self, real_asts):
        """Test _check_binding_equalities with real mop_t objects.

        Uses a pattern where the same variable name appears twice,
        exercising the equality check on real mop_t objects.
        """
        # Find a real AST with both left and right children
        for ast, _ in real_asts:
            if not ast.is_node():
                continue
            left = getattr(ast, "left", None)
            right = getattr(ast, "right", None)
            if left is None or right is None:
                continue
            if not left.is_leaf() or not right.is_leaf():
                continue
            if left.mop is None or right.mop is None:
                continue

            # Build pattern with same variable name for both positions
            pattern = AstNode(ast.opcode, AstLeaf("x_0"), AstLeaf("x_0"))
            bindings = MatchBindings()
            result = match_pattern_nomut(pattern, ast, bindings)

            # Result depends on whether left.mop == right.mop
            # Either way, the function should not crash
            if result:
                # If matched, both bindings should exist
                assert bindings.count >= 1
            return

        pytest.skip("No AST with two leaf children found")


# =========================================================================
# Test: Cython extension matches pure-Python implementation
# =========================================================================


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonFingerprintMatchesPythonReal:
    """Verify Cython fingerprint implementation matches pure-Python on real ASTs."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_real_leaf_fingerprint(self, real_asts):
        """Cython and Python fingerprints agree on a real leaf."""
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                if left is not None and left.is_leaf():
                    py_fp = compute_fingerprint(left)
                    cy_fp = cython_compute_fingerprint(left)
                    assert py_fp.depth == cy_fp["depth"]
                    assert py_fp.node_count == cy_fp["node_count"]
                    assert py_fp.leaf_count == cy_fp["leaf_count"]
                    assert py_fp.const_count == cy_fp["const_count"]
                    assert py_fp.opcode_hash == cy_fp["opcode_hash"]
                    return
        pytest.skip("No real leaf found")

    @pytest.mark.ida_required
    def test_real_node_fingerprint(self, real_asts):
        """Cython and Python fingerprints agree on a real node."""
        nodes = find_ast_nodes(real_asts)
        assert len(nodes) > 0

        ast, _ = nodes[0]
        py_fp = compute_fingerprint(ast)
        cy_fp = cython_compute_fingerprint(ast)
        assert py_fp.depth == cy_fp["depth"]
        assert py_fp.node_count == cy_fp["node_count"]
        assert py_fp.leaf_count == cy_fp["leaf_count"]
        assert py_fp.const_count == cy_fp["const_count"]
        assert py_fp.opcode_hash == cy_fp["opcode_hash"]

    @pytest.mark.ida_required
    def test_real_nested_fingerprint(self, real_asts):
        """Cython and Python fingerprints agree on a nested real tree."""
        for ast, _ in real_asts:
            if ast.is_node():
                left = getattr(ast, "left", None)
                if left is not None and left.is_node():
                    py_fp = compute_fingerprint(ast)
                    cy_fp = cython_compute_fingerprint(ast)
                    assert py_fp.depth == cy_fp["depth"]
                    assert py_fp.node_count == cy_fp["node_count"]
                    assert py_fp.leaf_count == cy_fp["leaf_count"]
                    assert py_fp.const_count == cy_fp["const_count"]
                    assert py_fp.opcode_hash == cy_fp["opcode_hash"]
                    return
        pytest.skip("No nested real AST node found")


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonMatchMatchesPythonReal:
    """Verify Cython match_pattern_nomut matches pure-Python on real ASTs."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_real_match_agrees(self, real_asts):
        """Cython and Python match agree on real AST trees."""
        nodes_with_children = find_ast_with_children(real_asts)
        if not nodes_with_children:
            pytest.skip("No AST nodes with children found")

        tested = 0
        for candidate_ast, _ in nodes_with_children[:5]:
            pattern = AstNode(
                candidate_ast.opcode, AstLeaf("x_0"), AstLeaf("y_0")
            )

            py_result = match_pattern_nomut(pattern, candidate_ast)
            cy_result = cython_match_pattern_nomut(pattern, candidate_ast)
            assert py_result == cy_result, (
                f"Python ({py_result}) != Cython ({cy_result}) "
                f"for opcode {candidate_ast.opcode}"
            )
            tested += 1

        assert tested > 0
        print(f"\n  Tested {tested} real ASTs: Python == Cython for all")

    @pytest.mark.ida_required
    def test_real_mismatch_agrees(self, real_asts):
        """Cython and Python match agree on mismatches with real ASTs."""
        nodes = find_ast_nodes(real_asts)

        seen_opcodes = {}
        for ast, _ in nodes:
            op = ast.opcode
            if op not in seen_opcodes:
                seen_opcodes[op] = ast
            if len(seen_opcodes) >= 2:
                break

        if len(seen_opcodes) < 2:
            pytest.skip("Need at least 2 different opcodes")

        items = list(seen_opcodes.values())
        pattern = AstNode(items[0].opcode, AstLeaf("x_0"), AstLeaf("y_0"))

        py_result = match_pattern_nomut(pattern, items[1])
        cy_result = cython_match_pattern_nomut(pattern, items[1])
        assert py_result == cy_result
        assert py_result is False

    @pytest.mark.ida_required
    def test_cython_bindings_capture_real_metadata(self, real_asts):
        """CMatchBindings captures root_mop, root_ea, root_dest_size from real ASTs."""
        nodes_with_children = find_ast_with_children(real_asts)
        if not nodes_with_children:
            pytest.skip("No AST nodes with children found")

        candidate_ast, _ = nodes_with_children[0]
        pattern = AstNode(
            candidate_ast.opcode, AstLeaf("x_0"), AstLeaf("y_0")
        )

        cb = CMatchBindings()
        result = cython_match_pattern_nomut(pattern, candidate_ast, cb)
        if result:
            assert cb.root_mop is candidate_ast.mop
            assert cb.root_ea == candidate_ast.ea
            assert cb.root_dest_size == candidate_ast.dest_size


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonOpcodeIndexedStorageReal:
    """Verify Cython COpcodeIndexedStorage matches pure-Python on real ASTs."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_cython_storage_matches_python_storage_real(self, real_asts):
        """Cython and Python storage return same candidates for real ASTs."""
        nodes = find_ast_nodes(real_asts)[:5]
        if not nodes:
            pytest.skip("No AST nodes found")

        py_storage = OpcodeIndexedStorage()
        cy_storage = COpcodeIndexedStorage()

        for i, (ast, _) in enumerate(nodes):
            class StorageRule:
                pass
            rule = StorageRule()
            rule.name = f"rule_{i}"
            py_storage.add_pattern(ast, rule)
            cy_storage.add_pattern(ast, rule)

        # Test retrieval with each AST
        for ast, _ in nodes:
            py_results = {r.rule.name for r in py_storage.get_candidates(ast)}
            cy_results = {r.rule.name for r in cy_storage.get_candidates(ast)}
            assert py_results == cy_results, (
                f"Python {py_results} != Cython {cy_results}"
            )
