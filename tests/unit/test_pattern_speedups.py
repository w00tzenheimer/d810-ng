"""Unit tests for pattern matching speedup optimizations.

Tests the three optimizations:
1. Non-mutating pattern match (match_pattern_nomut)
2. O(1) opcode-indexed pattern storage (OpcodeIndexedStorage)
3. Pre-computed pattern fingerprints (PatternFingerprint)

These tests use minimal standalone AST classes and do NOT require IDA Pro.
"""

import unittest

import pytest

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
# Minimal standalone AST classes for testing (no IDA dependency)
# =========================================================================


class MockMop:
    """Minimal mop_t substitute for testing."""

    def __init__(self, value=None, mop_type=1, size=4):
        self.t = mop_type
        self.size = size
        self._value = value
        if value is not None:
            self.nnn = type("nnn", (), {"value": value})()

    def __eq__(self, other):
        if not isinstance(other, MockMop):
            return NotImplemented
        return self._value == other._value and self.t == other.t

    def __repr__(self):
        return f"MockMop(value={self._value}, t={self.t})"


class MockAstBase:
    """Minimal AstBase for testing."""

    mop = None
    dest_size = None
    ea = None
    ast_index = None

    def is_node(self) -> bool:
        return False

    def is_leaf(self) -> bool:
        return False

    def is_constant(self) -> bool:
        return False

    @property
    def is_frozen(self) -> bool:
        return getattr(self, "_is_frozen", False)

    def clone(self):
        raise NotImplementedError

    def freeze(self):
        self._is_frozen = True


class MockAstLeaf(MockAstBase):
    """Minimal AstLeaf for testing pattern matching."""

    def __init__(self, name: str, mop: MockMop | None = None):
        self.name = name
        self.mop = mop
        self.dest_size = 4
        self.ea = 0x1000
        self.ast_index = None
        self._is_frozen = False

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return False

    def clone(self):
        new = MockAstLeaf(self.name, self.mop)
        new.ast_index = self.ast_index
        new.dest_size = self.dest_size
        new.ea = self.ea
        return new

    def __repr__(self):
        return f"MockAstLeaf('{self.name}')"


class MockAstConstant(MockAstLeaf):
    """Minimal AstConstant for testing."""

    def __init__(self, name: str, value: int, size: int = 4):
        mop = MockMop(value=value, mop_type=1, size=size)
        super().__init__(name, mop)
        self.expected_value = value
        self.expected_size = size

    def is_constant(self) -> bool:
        return True

    def clone(self):
        new = MockAstConstant(self.name, self.expected_value, self.expected_size)
        new.ast_index = self.ast_index
        return new

    def __repr__(self):
        return f"MockAstConstant('{self.name}', {self.expected_value})"


class MockAstNode(MockAstBase):
    """Minimal AstNode for testing pattern matching."""

    def __init__(self, opcode: int, left=None, right=None):
        self.opcode = opcode
        self.left = left
        self.right = right
        self.mop = MockMop(value=None, mop_type=0)
        self.dst_mop = None
        self.dest_size = 4
        self.ea = 0x1000
        self.ast_index = None
        self._is_frozen = False

    def is_node(self) -> bool:
        return True

    def is_leaf(self) -> bool:
        return False

    def is_constant(self) -> bool:
        return False

    def clone(self):
        new = MockAstNode(
            self.opcode,
            self.left.clone() if self.left else None,
            self.right.clone() if self.right else None,
        )
        new.mop = self.mop
        new.dst_mop = self.dst_mop
        new.dest_size = self.dest_size
        new.ea = self.ea
        new.ast_index = self.ast_index
        return new

    def __repr__(self):
        return f"MockAstNode(op={self.opcode}, left={self.left}, right={self.right})"


# Use opcode constants that don't depend on ida_hexrays
OP_ADD = 3
OP_SUB = 4
OP_XOR = 21
OP_AND = 20
OP_OR = 19
OP_MOV = 1
OP_NEG = 2


# =========================================================================
# Import the pure-Python implementations
# =========================================================================
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    MatchBindings,
    OpcodeIndexedStorage,
    PatternFingerprint,
    compute_fingerprint,
    match_pattern_nomut,
)


# =========================================================================
# Test: PatternFingerprint
# =========================================================================


class TestPatternFingerprint(unittest.TestCase):
    """Test pre-computed pattern fingerprints."""

    def test_fingerprint_equality(self):
        """Two identical fingerprints should be equal."""
        fp1 = PatternFingerprint(opcode_hash=0x123, depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(opcode_hash=0x123, depth=3, node_count=2, leaf_count=3, const_count=1)
        self.assertEqual(fp1, fp2)

    def test_fingerprint_inequality_opcode_hash(self):
        """Different opcode_hash means different fingerprint."""
        fp1 = PatternFingerprint(opcode_hash=0x123, depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(opcode_hash=0x456, depth=3, node_count=2, leaf_count=3, const_count=1)
        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_inequality_depth(self):
        """Different depth means different fingerprint."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(depth=4, node_count=2, leaf_count=3, const_count=1)
        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_compatible_same(self):
        """Identical fingerprints should be compatible."""
        fp = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        self.assertTrue(fp.compatible_with(fp))

    def test_fingerprint_compatible_different_depth_rejects(self):
        """Different depth should reject."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(depth=4, node_count=2, leaf_count=3, const_count=1)
        self.assertFalse(fp1.compatible_with(fp2))

    def test_fingerprint_compatible_different_node_count_rejects(self):
        """Different node count should reject."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        fp2 = PatternFingerprint(depth=3, node_count=3, leaf_count=3, const_count=1)
        self.assertFalse(fp1.compatible_with(fp2))

    def test_fingerprint_compatible_leaf_const_swap_accepts(self):
        """Swapping leaf and const counts (same total) should accept."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=2, const_count=2)
        fp2 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        self.assertTrue(fp1.compatible_with(fp2))

    def test_fingerprint_compatible_different_total_operands_rejects(self):
        """Different total operand count should reject."""
        fp1 = PatternFingerprint(depth=3, node_count=2, leaf_count=2, const_count=1)
        fp2 = PatternFingerprint(depth=3, node_count=2, leaf_count=3, const_count=1)
        self.assertFalse(fp1.compatible_with(fp2))


class TestComputeFingerprint(unittest.TestCase):
    """Test fingerprint computation from AST trees."""

    def test_single_leaf(self):
        """Single leaf node."""
        leaf = MockAstLeaf("x_0")
        fp = compute_fingerprint(leaf)
        self.assertEqual(fp.depth, 1)
        self.assertEqual(fp.node_count, 0)
        self.assertEqual(fp.leaf_count, 1)
        self.assertEqual(fp.const_count, 0)

    def test_single_constant(self):
        """Single constant node."""
        const = MockAstConstant("c_0", 42)
        fp = compute_fingerprint(const)
        self.assertEqual(fp.depth, 1)
        self.assertEqual(fp.node_count, 0)
        self.assertEqual(fp.leaf_count, 0)
        self.assertEqual(fp.const_count, 1)

    def test_binary_node(self):
        """Binary node with two leaves: op(x, y)."""
        node = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        fp = compute_fingerprint(node)
        self.assertEqual(fp.depth, 2)
        self.assertEqual(fp.node_count, 1)
        self.assertEqual(fp.leaf_count, 2)
        self.assertEqual(fp.const_count, 0)

    def test_nested_tree(self):
        """Nested tree: op1(op2(x, y), z)."""
        inner = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        outer = MockAstNode(OP_ADD, inner, MockAstLeaf("z"))
        fp = compute_fingerprint(outer)
        self.assertEqual(fp.depth, 3)
        self.assertEqual(fp.node_count, 2)
        self.assertEqual(fp.leaf_count, 3)
        self.assertEqual(fp.const_count, 0)

    def test_same_structure_same_hash(self):
        """Trees with same structure and opcodes should have same opcode_hash."""
        tree1 = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        tree2 = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        fp1 = compute_fingerprint(tree1)
        fp2 = compute_fingerprint(tree2)
        self.assertEqual(fp1.opcode_hash, fp2.opcode_hash)

    def test_different_opcodes_different_hash(self):
        """Trees with different opcodes should have different opcode_hash."""
        tree1 = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        tree2 = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        fp1 = compute_fingerprint(tree1)
        fp2 = compute_fingerprint(tree2)
        self.assertNotEqual(fp1.opcode_hash, fp2.opcode_hash)

    def test_mixed_leaves_and_constants(self):
        """Tree with both leaves and constants."""
        node = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        fp = compute_fingerprint(node)
        self.assertEqual(fp.depth, 2)
        self.assertEqual(fp.node_count, 1)
        self.assertEqual(fp.leaf_count, 1)
        self.assertEqual(fp.const_count, 1)


# =========================================================================
# Test: Non-Mutating Pattern Match
# =========================================================================


class TestMatchPatternNomut(unittest.TestCase):
    """Test non-mutating pattern match."""

    def test_leaf_matches_leaf(self):
        """A leaf pattern should match any leaf candidate."""
        pattern = MockAstLeaf("x_0", mop=MockMop(value=10))
        candidate = MockAstLeaf("anything", mop=MockMop(value=42))
        bindings = MatchBindings()
        result = match_pattern_nomut(pattern, candidate, bindings)
        self.assertTrue(result)
        self.assertEqual(bindings.count, 1)

    def test_node_matches_same_opcode(self):
        """A node pattern matches candidate with same opcode."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        bindings = MatchBindings()
        result = match_pattern_nomut(pattern, candidate, bindings)
        self.assertTrue(result)
        self.assertEqual(bindings.count, 2)

    def test_node_rejects_different_opcode(self):
        """A node pattern rejects candidate with different opcode."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        result = match_pattern_nomut(pattern, candidate)
        self.assertFalse(result)

    def test_constant_pattern_matches_same_value(self):
        """AstConstant with expected value matches same value."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        pattern.left.mop = MockMop(value=1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c", 0xFF))
        candidate.left.mop = MockMop(value=10)

        bindings = MatchBindings()
        result = match_pattern_nomut(pattern, candidate, bindings)
        self.assertTrue(result)

    def test_constant_pattern_rejects_different_value(self):
        """AstConstant with expected value rejects different value."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        pattern.left.mop = MockMop(value=1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c2", 0xAA))
        candidate.left.mop = MockMop(value=10)

        result = match_pattern_nomut(pattern, candidate)
        self.assertFalse(result)

    def test_nested_tree_match(self):
        """Nested pattern matches nested candidate."""
        # Pattern: ADD(XOR(x, y), z)
        p_inner = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        p_inner.left.mop = MockMop(value=1)
        p_inner.right.mop = MockMop(value=2)
        pattern = MockAstNode(OP_ADD, p_inner, MockAstLeaf("z"))
        pattern.right.mop = MockMop(value=3)

        # Candidate: ADD(XOR(a, b), c)
        c_inner = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        c_inner.left.mop = MockMop(value=10)
        c_inner.right.mop = MockMop(value=20)
        candidate = MockAstNode(OP_ADD, c_inner, MockAstLeaf("c"))
        candidate.right.mop = MockMop(value=30)

        bindings = MatchBindings()
        result = match_pattern_nomut(pattern, candidate, bindings)
        self.assertTrue(result)
        self.assertEqual(bindings.count, 3)

    def test_pattern_not_mutated_after_match(self):
        """Pattern tree should not be modified by match_pattern_nomut."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)
        pattern.freeze()

        # Remember original mop values
        orig_left_mop = pattern.left.mop
        orig_right_mop = pattern.right.mop

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        match_pattern_nomut(pattern, candidate)

        # Pattern should be unchanged
        self.assertIs(pattern.left.mop, orig_left_mop)
        self.assertIs(pattern.right.mop, orig_right_mop)

    def test_implicit_equality_accepted(self):
        """Same variable name used twice with same mop should match."""
        mop = MockMop(value=42)
        pattern = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("x"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=1)

        candidate = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = mop
        candidate.right.mop = mop  # Same mop object

        bindings = MatchBindings()
        result = match_pattern_nomut(pattern, candidate, bindings)
        self.assertTrue(result)

    def test_bindings_reuse(self):
        """MatchBindings can be reused across multiple match attempts."""
        bindings = MatchBindings()

        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        # First match
        result1 = match_pattern_nomut(pattern, candidate, bindings)
        self.assertTrue(result1)
        self.assertEqual(bindings.count, 2)

        # Second match (reuses bindings)
        candidate2 = MockAstNode(OP_ADD, MockAstLeaf("c"), MockAstLeaf("d"))
        candidate2.left.mop = MockMop(value=30)
        candidate2.right.mop = MockMop(value=40)

        result2 = match_pattern_nomut(pattern, candidate2, bindings)
        self.assertTrue(result2)
        self.assertEqual(bindings.count, 2)  # Reset and refilled

    def test_none_candidate_mop_rejects(self):
        """Leaf candidate with None mop should be rejected."""
        pattern = MockAstLeaf("x", mop=MockMop(value=1))
        candidate = MockAstLeaf("a", mop=None)

        result = match_pattern_nomut(pattern, candidate)
        self.assertFalse(result)


# =========================================================================
# Test: O(1) Opcode-Indexed Storage
# =========================================================================


class MockRule:
    """Minimal rule for testing storage."""

    def __init__(self, name: str):
        self.name = name

    def __repr__(self):
        return f"MockRule('{self.name}')"


class TestOpcodeIndexedStorage(unittest.TestCase):
    """Test O(1) opcode-indexed pattern storage."""

    def test_add_and_retrieve(self):
        """Adding a pattern and retrieving it by opcode."""
        storage = OpcodeIndexedStorage()
        rule = MockRule("rule1")
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))

        storage.add_pattern(pattern, rule)
        self.assertEqual(storage.total_patterns, 1)

        # Candidate with same structure
        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        results = storage.get_candidates(candidate)
        self.assertEqual(len(results), 1)
        self.assertIs(results[0].rule, rule)

    def test_different_opcode_no_match(self):
        """Pattern with opcode A should not match candidate with opcode B."""
        storage = OpcodeIndexedStorage()
        rule = MockRule("rule1")
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))

        storage.add_pattern(pattern, rule)

        candidate = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        results = storage.get_candidates(candidate)
        self.assertEqual(len(results), 0)

    def test_multiple_patterns_same_opcode(self):
        """Multiple patterns with same root opcode should all be returned."""
        storage = OpcodeIndexedStorage()
        rule1 = MockRule("rule1")
        rule2 = MockRule("rule2")

        # Two different patterns with same root opcode
        pattern1 = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern2 = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c", 0xFF))

        storage.add_pattern(pattern1, rule1)
        storage.add_pattern(pattern2, rule2)
        self.assertEqual(storage.total_patterns, 2)

        # Candidate with same structure as pattern1
        candidate = MockAstNode(OP_ADD, MockAstLeaf("p"), MockAstLeaf("q"))
        results = storage.get_candidates(candidate)
        # Both should be returned (fingerprint compatible because same depth/nodes)
        self.assertGreaterEqual(len(results), 1)

    def test_fingerprint_filters_incompatible(self):
        """Patterns with incompatible fingerprints should be filtered out."""
        storage = OpcodeIndexedStorage()
        rule = MockRule("rule1")

        # Pattern: ADD(XOR(x, y), z) -- depth=3, 2 nodes, 3 leaves
        inner = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        deep_pattern = MockAstNode(OP_ADD, inner, MockAstLeaf("z"))
        storage.add_pattern(deep_pattern, rule)

        # Candidate: ADD(a, b) -- depth=2, 1 node, 2 leaves (different structure)
        shallow_candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        results = storage.get_candidates(shallow_candidate)
        self.assertEqual(len(results), 0)

    def test_leaf_patterns(self):
        """Leaf patterns (no root opcode) should be retrievable."""
        storage = OpcodeIndexedStorage()
        rule = MockRule("leaf_rule")
        pattern = MockAstLeaf("x")
        pattern.mop = MockMop(value=1)

        storage.add_pattern(pattern, rule)
        self.assertEqual(storage.total_patterns, 1)

        # Candidate leaf
        candidate = MockAstLeaf("a")
        candidate.mop = MockMop(value=42)
        results = storage.get_candidates(candidate)
        self.assertEqual(len(results), 1)

    def test_returns_same_rules_as_sequential_search(self):
        """OpcodeIndexedStorage should return same rules as linear scan."""
        storage = OpcodeIndexedStorage()
        rules = [MockRule(f"rule_{i}") for i in range(5)]
        patterns = [
            MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y")),
            MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y")),
            MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c", 1)),
            MockAstNode(OP_OR, MockAstLeaf("x"), MockAstLeaf("y")),
            MockAstNode(OP_AND, MockAstLeaf("x"), MockAstLeaf("y")),
        ]

        for rule, pattern in zip(rules, patterns):
            storage.add_pattern(pattern, rule)

        # Candidate matching ADD patterns
        candidate = MockAstNode(OP_ADD, MockAstLeaf("p"), MockAstLeaf("q"))
        results = storage.get_candidates(candidate)

        # Should find the ADD patterns (rule_0 and potentially rule_2)
        result_rules = {r.rule.name for r in results}
        self.assertIn("rule_0", result_rules)

        # Should NOT find XOR, OR, AND patterns
        self.assertNotIn("rule_1", result_rules)
        self.assertNotIn("rule_3", result_rules)
        self.assertNotIn("rule_4", result_rules)


# =========================================================================
# Test: Integration - nomut match produces same results as clone+match
# =========================================================================


class TestNomutVsCloneEquivalence(unittest.TestCase):
    """Verify that non-mutating match produces same results as clone+match."""

    def _clone_and_match(self, pattern, candidate):
        """Simulate the old clone+match approach."""
        cloned = pattern.clone()
        # Simulate check_pattern_and_copy_mops: walk tree, copy mops
        return self._recursive_clone_match(cloned, candidate)

    def _recursive_clone_match(self, pattern, candidate):
        """Simplified clone-based match for comparison."""
        if pattern is None and candidate is None:
            return True
        if pattern is None or candidate is None:
            return False

        if pattern.is_leaf():
            if pattern.is_constant():
                if candidate.mop is None:
                    return False
                expected = getattr(pattern, "expected_value", None)
                if expected is not None:
                    if candidate.mop is None or not hasattr(candidate.mop, 'nnn'):
                        return False
                    return expected == candidate.mop.nnn.value
                return True
            else:
                return candidate.mop is not None

        if not pattern.is_node() or not candidate.is_node():
            return False

        if pattern.opcode != candidate.opcode:
            return False

        p_left = getattr(pattern, "left", None)
        p_right = getattr(pattern, "right", None)
        c_left = getattr(candidate, "left", None)
        c_right = getattr(candidate, "right", None)

        if p_left is not None and c_left is not None:
            if not self._recursive_clone_match(p_left, c_left):
                return False
        elif p_left is not None:
            return False

        if p_right is not None and c_right is not None:
            if not self._recursive_clone_match(p_right, c_right):
                return False
        elif p_right is not None:
            return False

        return True

    def test_simple_match_equivalence(self):
        """Simple ADD(x, y) match should give same result."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        clone_result = self._clone_and_match(pattern, candidate)
        nomut_result = match_pattern_nomut(pattern, candidate)
        self.assertEqual(clone_result, nomut_result)

    def test_mismatch_equivalence(self):
        """Mismatch should give same result."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        clone_result = self._clone_and_match(pattern, candidate)
        nomut_result = match_pattern_nomut(pattern, candidate)
        self.assertEqual(clone_result, nomut_result)

    def test_constant_match_equivalence(self):
        """Constant match should give same result."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        pattern.left.mop = MockMop(value=1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c2", 0xFF))
        candidate.left.mop = MockMop(value=10)

        clone_result = self._clone_and_match(pattern, candidate)
        nomut_result = match_pattern_nomut(pattern, candidate)
        self.assertEqual(clone_result, nomut_result)

    def test_constant_mismatch_equivalence(self):
        """Constant value mismatch should give same result."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        pattern.left.mop = MockMop(value=1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c2", 0xAA))
        candidate.left.mop = MockMop(value=10)

        clone_result = self._clone_and_match(pattern, candidate)
        nomut_result = match_pattern_nomut(pattern, candidate)
        self.assertEqual(clone_result, nomut_result)

    def test_deep_tree_equivalence(self):
        """Deep nested tree match should give same result."""
        # Pattern: ADD(XOR(x, y), SUB(z, w))
        p_inner1 = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        p_inner1.left.mop = MockMop(value=1)
        p_inner1.right.mop = MockMop(value=2)
        p_inner2 = MockAstNode(OP_SUB, MockAstLeaf("z"), MockAstLeaf("w"))
        p_inner2.left.mop = MockMop(value=3)
        p_inner2.right.mop = MockMop(value=4)
        pattern = MockAstNode(OP_ADD, p_inner1, p_inner2)

        # Matching candidate
        c_inner1 = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        c_inner1.left.mop = MockMop(value=10)
        c_inner1.right.mop = MockMop(value=20)
        c_inner2 = MockAstNode(OP_SUB, MockAstLeaf("c"), MockAstLeaf("d"))
        c_inner2.left.mop = MockMop(value=30)
        c_inner2.right.mop = MockMop(value=40)
        candidate = MockAstNode(OP_ADD, c_inner1, c_inner2)

        clone_result = self._clone_and_match(pattern, candidate)
        nomut_result = match_pattern_nomut(pattern, candidate)
        self.assertEqual(clone_result, nomut_result)
        self.assertTrue(nomut_result)


# =========================================================================
# Test: Cython extension matches pure-Python implementation
# =========================================================================


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonFingerprintMatchesPython(unittest.TestCase):
    """Verify Cython fingerprint implementation matches pure-Python."""

    def test_single_leaf_fingerprint(self):
        """Cython and Python fingerprints agree on a single leaf."""
        leaf = MockAstLeaf("x_0")
        py_fp = compute_fingerprint(leaf)
        cy_fp = cython_compute_fingerprint(leaf)

        self.assertEqual(py_fp.depth, cy_fp["depth"])
        self.assertEqual(py_fp.node_count, cy_fp["node_count"])
        self.assertEqual(py_fp.leaf_count, cy_fp["leaf_count"])
        self.assertEqual(py_fp.const_count, cy_fp["const_count"])
        self.assertEqual(py_fp.opcode_hash, cy_fp["opcode_hash"])

    def test_single_constant_fingerprint(self):
        """Cython and Python fingerprints agree on a constant."""
        const = MockAstConstant("c_0", 42)
        py_fp = compute_fingerprint(const)
        cy_fp = cython_compute_fingerprint(const)

        self.assertEqual(py_fp.depth, cy_fp["depth"])
        self.assertEqual(py_fp.node_count, cy_fp["node_count"])
        self.assertEqual(py_fp.leaf_count, cy_fp["leaf_count"])
        self.assertEqual(py_fp.const_count, cy_fp["const_count"])
        self.assertEqual(py_fp.opcode_hash, cy_fp["opcode_hash"])

    def test_binary_node_fingerprint(self):
        """Cython and Python fingerprints agree on binary node."""
        node = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        py_fp = compute_fingerprint(node)
        cy_fp = cython_compute_fingerprint(node)

        self.assertEqual(py_fp.depth, cy_fp["depth"])
        self.assertEqual(py_fp.node_count, cy_fp["node_count"])
        self.assertEqual(py_fp.leaf_count, cy_fp["leaf_count"])
        self.assertEqual(py_fp.const_count, cy_fp["const_count"])
        self.assertEqual(py_fp.opcode_hash, cy_fp["opcode_hash"])

    def test_nested_tree_fingerprint(self):
        """Cython and Python fingerprints agree on nested tree."""
        inner = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        outer = MockAstNode(OP_ADD, inner, MockAstLeaf("z"))
        py_fp = compute_fingerprint(outer)
        cy_fp = cython_compute_fingerprint(outer)

        self.assertEqual(py_fp.depth, cy_fp["depth"])
        self.assertEqual(py_fp.node_count, cy_fp["node_count"])
        self.assertEqual(py_fp.leaf_count, cy_fp["leaf_count"])
        self.assertEqual(py_fp.const_count, cy_fp["const_count"])
        self.assertEqual(py_fp.opcode_hash, cy_fp["opcode_hash"])

    def test_mixed_tree_fingerprint(self):
        """Cython and Python fingerprints agree on tree with leaves and constants."""
        node = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        py_fp = compute_fingerprint(node)
        cy_fp = cython_compute_fingerprint(node)

        self.assertEqual(py_fp.depth, cy_fp["depth"])
        self.assertEqual(py_fp.node_count, cy_fp["node_count"])
        self.assertEqual(py_fp.leaf_count, cy_fp["leaf_count"])
        self.assertEqual(py_fp.const_count, cy_fp["const_count"])
        self.assertEqual(py_fp.opcode_hash, cy_fp["opcode_hash"])


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonMatchMatchesPython(unittest.TestCase):
    """Verify Cython match_pattern_nomut matches pure-Python on same inputs."""

    def test_simple_match_agrees(self):
        """Cython and Python match agree on simple ADD(x, y)."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        py_result = match_pattern_nomut(pattern, candidate)
        cy_result = cython_match_pattern_nomut(pattern, candidate)
        self.assertEqual(py_result, cy_result)
        self.assertTrue(cy_result)

    def test_mismatch_agrees(self):
        """Cython and Python match agree on opcode mismatch."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        py_result = match_pattern_nomut(pattern, candidate)
        cy_result = cython_match_pattern_nomut(pattern, candidate)
        self.assertEqual(py_result, cy_result)
        self.assertFalse(cy_result)

    def test_constant_match_agrees(self):
        """Cython and Python match agree on constant value match."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        pattern.left.mop = MockMop(value=1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c2", 0xFF))
        candidate.left.mop = MockMop(value=10)

        py_result = match_pattern_nomut(pattern, candidate)
        cy_result = cython_match_pattern_nomut(pattern, candidate)
        self.assertEqual(py_result, cy_result)
        self.assertTrue(cy_result)

    def test_constant_mismatch_agrees(self):
        """Cython and Python match agree on constant value mismatch."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstConstant("c", 0xFF))
        pattern.left.mop = MockMop(value=1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c2", 0xAA))
        candidate.left.mop = MockMop(value=10)

        py_result = match_pattern_nomut(pattern, candidate)
        cy_result = cython_match_pattern_nomut(pattern, candidate)
        self.assertEqual(py_result, cy_result)
        self.assertFalse(cy_result)

    def test_nested_tree_match_agrees(self):
        """Cython and Python match agree on deeply nested tree."""
        p_inner1 = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        p_inner1.left.mop = MockMop(value=1)
        p_inner1.right.mop = MockMop(value=2)
        p_inner2 = MockAstNode(OP_SUB, MockAstLeaf("z"), MockAstLeaf("w"))
        p_inner2.left.mop = MockMop(value=3)
        p_inner2.right.mop = MockMop(value=4)
        pattern = MockAstNode(OP_ADD, p_inner1, p_inner2)

        c_inner1 = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        c_inner1.left.mop = MockMop(value=10)
        c_inner1.right.mop = MockMop(value=20)
        c_inner2 = MockAstNode(OP_SUB, MockAstLeaf("c"), MockAstLeaf("d"))
        c_inner2.left.mop = MockMop(value=30)
        c_inner2.right.mop = MockMop(value=40)
        candidate = MockAstNode(OP_ADD, c_inner1, c_inner2)

        py_result = match_pattern_nomut(pattern, candidate)
        cy_result = cython_match_pattern_nomut(pattern, candidate)
        self.assertEqual(py_result, cy_result)
        self.assertTrue(cy_result)

    def test_cython_bindings_capture_root_metadata(self):
        """CMatchBindings captures root_mop, root_ea, root_dest_size."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)
        candidate.ea = 0x4000
        candidate.dest_size = 8

        cb = CMatchBindings()
        result = cython_match_pattern_nomut(pattern, candidate, cb)
        self.assertTrue(result)
        self.assertIs(cb.root_mop, candidate.mop)
        self.assertEqual(cb.root_ea, 0x4000)
        self.assertEqual(cb.root_dest_size, 8)

    def test_cython_bindings_to_dict(self):
        """CMatchBindings.to_dict() returns correct {name: mop} map."""
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        pattern.left.mop = MockMop(value=1)
        pattern.right.mop = MockMop(value=2)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        candidate.left.mop = MockMop(value=10)
        candidate.right.mop = MockMop(value=20)

        cb = CMatchBindings()
        result = cython_match_pattern_nomut(pattern, candidate, cb)
        self.assertTrue(result)

        d = cb.to_dict()
        self.assertIn("x", d)
        self.assertIn("y", d)
        self.assertIs(d["x"], candidate.left.mop)
        self.assertIs(d["y"], candidate.right.mop)


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython extensions not built")
class TestCythonOpcodeIndexedStorage(unittest.TestCase):
    """Verify Cython COpcodeIndexedStorage matches pure-Python behavior."""

    def test_add_and_retrieve(self):
        """Adding a pattern and retrieving by opcode works."""
        storage = COpcodeIndexedStorage()
        rule = MockRule("rule1")
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))

        storage.add_pattern(pattern, rule)
        self.assertEqual(storage.total_patterns, 1)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        results = storage.get_candidates(candidate)
        self.assertEqual(len(results), 1)
        self.assertIs(results[0].rule, rule)

    def test_different_opcode_no_match(self):
        """Pattern with opcode A does not match candidate with opcode B."""
        storage = COpcodeIndexedStorage()
        rule = MockRule("rule1")
        pattern = MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y"))
        storage.add_pattern(pattern, rule)

        candidate = MockAstNode(OP_XOR, MockAstLeaf("a"), MockAstLeaf("b"))
        results = storage.get_candidates(candidate)
        self.assertEqual(len(results), 0)

    def test_fingerprint_filters_incompatible(self):
        """Incompatible fingerprints are filtered out."""
        storage = COpcodeIndexedStorage()
        rule = MockRule("rule1")
        inner = MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y"))
        deep_pattern = MockAstNode(OP_ADD, inner, MockAstLeaf("z"))
        storage.add_pattern(deep_pattern, rule)

        shallow_candidate = MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstLeaf("b"))
        results = storage.get_candidates(shallow_candidate)
        self.assertEqual(len(results), 0)

    def test_cython_storage_matches_python_storage(self):
        """Cython and Python storage return same candidates for same input."""
        py_storage = OpcodeIndexedStorage()
        cy_storage = COpcodeIndexedStorage()

        rules = [MockRule(f"rule_{i}") for i in range(5)]
        patterns = [
            MockAstNode(OP_ADD, MockAstLeaf("x"), MockAstLeaf("y")),
            MockAstNode(OP_XOR, MockAstLeaf("x"), MockAstLeaf("y")),
            MockAstNode(OP_ADD, MockAstLeaf("a"), MockAstConstant("c", 1)),
            MockAstNode(OP_OR, MockAstLeaf("x"), MockAstLeaf("y")),
            MockAstNode(OP_AND, MockAstLeaf("x"), MockAstLeaf("y")),
        ]

        for rule, pattern in zip(rules, patterns):
            py_storage.add_pattern(pattern, rule)
            cy_storage.add_pattern(pattern, rule)

        candidate = MockAstNode(OP_ADD, MockAstLeaf("p"), MockAstLeaf("q"))
        py_results = {r.rule.name for r in py_storage.get_candidates(candidate)}
        cy_results = {r.rule.name for r in cy_storage.get_candidates(candidate)}

        self.assertEqual(py_results, cy_results)


if __name__ == "__main__":
    unittest.main()
