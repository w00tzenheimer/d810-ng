"""Test commutative pattern generation for SymbolicExpression.

This tests the pattern generation logic WITHOUT importing the full IDA backend.
The actual IDA integration is tested in system tests.
"""

import pytest
import itertools
from d810.core.typing import List

from d810.mba.dsl import Var, SymbolicExpression

# =============================================================================
# Copy the helper functions from ida.py for testing (to avoid IDA dependency)
# =============================================================================

# Note: DSL uses "and", "or" (not "and_", "or_")
_COMMUTATIVE_OPS = {"add", "mul", "and", "or", "xor"}


def _generate_commutative_permutations(
    expr: SymbolicExpression,
) -> List[SymbolicExpression]:
    """Generate all commutative permutations of a SymbolicExpression."""
    # Note: is_variable() and is_constant() are methods, not properties
    if expr.is_variable() or expr.is_constant():
        return [expr]

    # Unary operations
    if expr.right is None:
        left_perms = _generate_commutative_permutations(expr.left)
        return [
            SymbolicExpression(expr.operation, left=lp, right=None) for lp in left_perms
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
        print(f"  {i + 1}. {p}")


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



if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
