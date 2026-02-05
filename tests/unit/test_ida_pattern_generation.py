"""Test egglog-based pattern generation for VerifiableRule.

This tests the pattern generation logic WITHOUT importing the full IDA backend.
The actual IDA integration is tested in system tests.
"""

import pytest
import itertools
from typing import List

from d810.mba.dsl import Var, SymbolicExpression


# =============================================================================
# Copy the helper functions from ida.py for testing (to avoid IDA dependency)
# =============================================================================

# Note: DSL uses "and", "or" (not "and_", "or_")
_COMMUTATIVE_OPS = {"add", "mul", "and", "or", "xor"}


def _generate_commutative_permutations(expr: SymbolicExpression) -> List[SymbolicExpression]:
    """Generate all commutative permutations of a SymbolicExpression."""
    # Note: is_variable() and is_constant() are methods, not properties
    if expr.is_variable() or expr.is_constant():
        return [expr]

    # Unary operations
    if expr.right is None:
        left_perms = _generate_commutative_permutations(expr.left)
        return [
            SymbolicExpression(expr.operation, left=lp, right=None)
            for lp in left_perms
        ]

    # Binary operations
    left_perms = _generate_commutative_permutations(expr.left)
    right_perms = _generate_commutative_permutations(expr.right)

    results = []
    for lp, rp in itertools.product(left_perms, right_perms):
        # Original order
        results.append(SymbolicExpression(expr.operation, left=lp, right=rp))

        # Swapped order (if commutative)
        if expr.operation in _COMMUTATIVE_OPS:
            results.append(SymbolicExpression(expr.operation, left=rp, right=lp))

    return results


# =============================================================================
# Tests
# =============================================================================


def test_permutation_simple_add():
    """Test permutation generation for simple x + y."""
    x = Var("x")
    y = Var("y")

    pattern = x + y  # add is commutative
    perms = _generate_commutative_permutations(pattern)

    # x + y can become: x + y, y + x = 2 permutations
    assert len(perms) == 2


def test_permutation_simple_sub():
    """Test permutation generation for non-commutative x - y."""
    x = Var("x")
    y = Var("y")

    pattern = x - y  # sub is NOT commutative
    perms = _generate_commutative_permutations(pattern)

    # x - y stays as x - y = 1 permutation
    assert len(perms) == 1


def test_permutation_nested():
    """Test permutation generation for (x & y) + (x ^ y)."""
    x = Var("x")
    y = Var("y")

    # This pattern has 3 commutative ops: &, +, ^
    pattern = (x & y) + (x ^ y)
    perms = _generate_commutative_permutations(pattern)

    # 2^3 = 8 permutations
    assert len(perms) == 8, f"Expected 8 permutations, got {len(perms)}"

    print(f"\nGenerated {len(perms)} permutations for (x & y) + (x ^ y):")
    for i, p in enumerate(perms):
        print(f"  {i+1}. {p}")


def test_permutation_deeply_nested():
    """Test permutation generation for ((x & y) + (x ^ y)) | z."""
    x = Var("x")
    y = Var("y")
    z = Var("z")

    # 4 commutative ops: &, +, ^, |
    pattern = ((x & y) + (x ^ y)) | z
    perms = _generate_commutative_permutations(pattern)

    # 2^4 = 16 permutations
    assert len(perms) == 16, f"Expected 16 permutations, got {len(perms)}"


def test_egglog_verification():
    """Test egglog equivalence verification of patterns."""
    try:
        from d810.mba.backends.egglog_backend import (
            EGGLOG_AVAILABLE,
            PatternExpr,
            verify_pattern_equivalence,
        )
    except ImportError:
        pytest.skip("egglog_backend not available")

    if not EGGLOG_AVAILABLE:
        pytest.skip("egglog not installed")

    x = PatternExpr.var("x")
    y = PatternExpr.var("y")

    # Commutative equivalences should be verified
    assert verify_pattern_equivalence(x + y, y + x)
    assert verify_pattern_equivalence(x & y, y & x)
    assert verify_pattern_equivalence(x | y, y | x)
    assert verify_pattern_equivalence(x ^ y, y ^ x)

    # Nested commutative equivalences
    assert verify_pattern_equivalence(
        (x & y) + (x ^ y),
        (x ^ y) + (x & y)  # top-level + commuted
    )
    assert verify_pattern_equivalence(
        (x & y) + (x ^ y),
        (y & x) + (x ^ y)  # inner & commuted
    )
    assert verify_pattern_equivalence(
        (x & y) + (x ^ y),
        (y ^ x) + (y & x)  # fully commuted
    )

    print("\nAll egglog equivalences verified!")


def test_egglog_nonequivalence():
    """Test that egglog correctly identifies non-equivalent patterns."""
    try:
        from d810.mba.backends.egglog_backend import (
            EGGLOG_AVAILABLE,
            PatternExpr,
            verify_pattern_equivalence,
        )
    except ImportError:
        pytest.skip("egglog_backend not available")

    if not EGGLOG_AVAILABLE:
        pytest.skip("egglog not installed")

    x = PatternExpr.var("x")
    y = PatternExpr.var("y")

    # These should NOT be equivalent (different operations)
    assert not verify_pattern_equivalence(x + y, x - y)
    assert not verify_pattern_equivalence(x & y, x | y)
    assert not verify_pattern_equivalence(x ^ y, x & y)

    print("\nNon-equivalences correctly detected!")


def test_symbolic_to_pattern_conversion():
    """Test conversion from SymbolicExpression to PatternExpr."""
    try:
        from d810.mba.backends.egglog_backend import (
            EGGLOG_AVAILABLE,
            PatternExpr,
            verify_pattern_equivalence,
        )
    except ImportError:
        pytest.skip("egglog_backend not available")

    if not EGGLOG_AVAILABLE:
        pytest.skip("egglog not installed")

    # This is the conversion function (copied from ida.py to avoid IDA dependency)
    def _symbolic_to_pattern_expr(expr: SymbolicExpression) -> PatternExpr:
        if expr.is_variable():
            return PatternExpr.var(expr.name)
        if expr.is_constant():
            return PatternExpr.var(f"const_{expr.value}")

        op = expr.operation
        left = _symbolic_to_pattern_expr(expr.left)
        right = _symbolic_to_pattern_expr(expr.right) if expr.right else None

        if op == "add":
            return left + right
        elif op == "sub":
            return left - right
        elif op == "and":
            return left & right
        elif op == "or":
            return left | right
        elif op == "xor":
            return left ^ right
        elif op == "neg":
            return -left
        elif op == "bnot":
            return ~left
        else:
            raise ValueError(f"Unknown operation: {op}")

    x = Var("x")
    y = Var("y")

    # Convert SymbolicExpression to PatternExpr
    sym_pattern = (x & y) + (x ^ y)
    pattern_expr = _symbolic_to_pattern_expr(sym_pattern)

    # Also create equivalent using commuted form
    sym_commuted = (x ^ y) + (x & y)
    commuted_expr = _symbolic_to_pattern_expr(sym_commuted)

    # They should be equivalent
    assert verify_pattern_equivalence(pattern_expr, commuted_expr)
    print("\nSymbolicExpression to PatternExpr conversion verified!")


def test_full_pattern_generation_pipeline():
    """Test the full pipeline: generate permutations, filter with egglog."""
    try:
        from d810.mba.backends.egglog_backend import (
            EGGLOG_AVAILABLE,
            PatternExpr,
            verify_pattern_equivalence,
        )
    except ImportError:
        pytest.skip("egglog_backend not available")

    if not EGGLOG_AVAILABLE:
        pytest.skip("egglog not installed")

    def _symbolic_to_pattern_expr(expr: SymbolicExpression) -> PatternExpr:
        if expr.is_variable():
            return PatternExpr.var(expr.name)
        if expr.is_constant():
            return PatternExpr.var(f"const_{expr.value}")

        op = expr.operation
        left = _symbolic_to_pattern_expr(expr.left)
        right = _symbolic_to_pattern_expr(expr.right) if expr.right else None

        if op == "add":
            return left + right
        elif op == "sub":
            return left - right
        elif op == "and":
            return left & right
        elif op == "or":
            return left | right
        elif op == "xor":
            return left ^ right
        elif op == "neg":
            return -left
        elif op == "bnot":
            return ~left
        else:
            raise ValueError(f"Unknown operation: {op}")

    x = Var("x")
    y = Var("y")

    # Step 1: Generate permutations
    base_pattern = (x & y) + (x ^ y)
    permutations = _generate_commutative_permutations(base_pattern)
    assert len(permutations) == 8

    # Step 2: Convert to PatternExpr
    base_pattern_expr = _symbolic_to_pattern_expr(base_pattern)

    # Step 3: Filter with egglog
    verified = [base_pattern]
    for perm in permutations[1:]:  # Skip first (base itself)
        perm_expr = _symbolic_to_pattern_expr(perm)
        if verify_pattern_equivalence(base_pattern_expr, perm_expr):
            verified.append(perm)

    # All 8 should be equivalent (just commutative swaps)
    assert len(verified) == 8, f"Expected 8 verified, got {len(verified)}"

    print(f"\nFull pipeline: {len(verified)} patterns verified equivalent")
    for i, p in enumerate(verified):
        print(f"  {i+1}. {p}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
