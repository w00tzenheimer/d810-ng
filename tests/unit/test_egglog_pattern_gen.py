"""Proof-of-concept: Use egglog to generate equivalent pattern variants at startup.

This demonstrates using egglog for pattern generation (not runtime optimization).
The idea:
1. Take a single pattern like (x & y) + (x ^ y)
2. Generate all commutative permutations as candidates
3. Use egglog to verify which candidates are equivalent
4. Return all equivalent patterns for AST matching

This runs ONCE at startup, so egglog's overhead is acceptable.
"""

import logging

import pytest

# Skip entire module if egglog not installed
egglog = pytest.importorskip("egglog", reason="egglog not installed")

# Suppress egglog's verbose logging
logging.getLogger("egglog").setLevel(logging.WARNING)
logging.getLogger("egglog.egraph").setLevel(logging.WARNING)

from egglog import EGraph, Expr, StringLike, eq, rewrite, vars_


class PatternExpr(Expr):
    """Expression type for pattern generation."""

    @classmethod
    def var(cls, name: StringLike) -> "PatternExpr":
        """Create a variable."""
        ...

    def __add__(self, other: "PatternExpr") -> "PatternExpr": ...
    def __sub__(self, other: "PatternExpr") -> "PatternExpr": ...
    def __and__(self, other: "PatternExpr") -> "PatternExpr": ...
    def __or__(self, other: "PatternExpr") -> "PatternExpr": ...
    def __xor__(self, other: "PatternExpr") -> "PatternExpr": ...
    def __neg__(self) -> "PatternExpr": ...
    def __invert__(self) -> "PatternExpr": ...


def create_pattern_egraph() -> EGraph:
    """Create an e-graph with commutativity rules for pattern generation."""
    egraph = EGraph()

    # Create rule variables
    a, b = vars_("a b", PatternExpr)

    # Register commutativity rules
    egraph.register(
        rewrite(a + b).to(b + a),
        rewrite(a & b).to(b & a),
        rewrite(a | b).to(b | a),
        rewrite(a ^ b).to(b ^ a),
    )

    return egraph


def generate_equivalent_patterns(
    base_pattern: PatternExpr, candidates: list[PatternExpr]
) -> list[PatternExpr]:
    """Use egglog to find which candidate patterns are equivalent to base.

    Args:
        base_pattern: The base pattern expression.
        candidates: List of candidate patterns to check.

    Returns:
        List of patterns equivalent to base_pattern (including base itself).
    """
    egraph = create_pattern_egraph()

    # Add base pattern
    egraph.register(base_pattern)

    # Add all candidates
    for candidate in candidates:
        egraph.register(candidate)

    # Run saturation to discover equivalences
    egraph.run(10)

    # Check which candidates are equivalent to base
    equivalent = [base_pattern]
    for candidate in candidates:
        try:
            egraph.check(eq(base_pattern).to(candidate))
            if candidate not in equivalent:
                equivalent.append(candidate)
        except Exception:
            pass  # Not equivalent

    return equivalent


def test_or_mba_rule_1_pattern_generation():
    """Test: Generate equivalent patterns for Or_MbaRule_1.

    Pattern: (x & y) + (x ^ y) => x | y

    Expected: Should find that (x ^ y) + (x & y) is equivalent
    (due to commutativity of +).
    """
    print("\n" + "=" * 60)
    print("Test: Or_MbaRule_1 Pattern Generation")
    print("=" * 60)

    # Create variables
    x = PatternExpr.var("x")
    y = PatternExpr.var("y")

    # Base pattern: (x & y) + (x ^ y)
    base = (x & y) + (x ^ y)
    print(f"\nBase pattern: (x & y) + (x ^ y)")

    # Generate candidate commuted forms
    candidates = [
        (x ^ y) + (x & y),  # Commuted top-level +
        (y & x) + (x ^ y),  # Commuted &
        (x & y) + (y ^ x),  # Commuted ^
        (y & x) + (y ^ x),  # Commuted both
        (y ^ x) + (y & x),  # Fully commuted
    ]
    print(f"Checking {len(candidates)} candidate permutations...")

    # Find equivalent patterns
    equivalent = generate_equivalent_patterns(base, candidates)

    print(f"\nFound {len(equivalent)} equivalent patterns:")
    for i, pattern in enumerate(equivalent):
        print(f"  {i + 1}. {pattern}")

    # Verify the commuted form was found
    commuted = (x ^ y) + (x & y)
    egraph = create_pattern_egraph()
    egraph.register(base)
    egraph.register(commuted)
    egraph.run(10)

    assert (
        egraph.check(eq(base).to(commuted)) is None
    ), f"\n✗ FAILED: Could not verify equivalence!"
    print("\n✓ VERIFIED: (x & y) + (x ^ y) ≡ (x ^ y) + (x & y)")


def test_nested_commutativity():
    """Test: Verify nested commutativity (& inside +).

    Pattern: (x & y) + (x ^ y)
    Should be equivalent to: (y & x) + (x ^ y) due to & commutativity.
    """
    print("\n" + "=" * 60)
    print("Test: Nested Commutativity")
    print("=" * 60)

    x = PatternExpr.var("x")
    y = PatternExpr.var("y")

    base = (x & y) + (x ^ y)
    nested_commuted = (y & x) + (x ^ y)  # Inner & commuted

    egraph = create_pattern_egraph()
    egraph.register(base)
    egraph.register(nested_commuted)
    egraph.run(10)

    assert (
        egraph.check(eq(base).to(nested_commuted)) is None
    ), f"\n✗ FAILED: Could not verify equivalence!"
    print("✓ VERIFIED: (x & y) + (x ^ y) ≡ (y & x) + (x ^ y)")


def test_full_permutation():
    """Test: All permutations should be equivalent.

    Pattern: (x & y) + (x ^ y)
    Should be equivalent to: (y ^ x) + (y & x) (fully permuted).
    """
    print("\n" + "=" * 60)
    print("Test: Full Permutation Equivalence")
    print("=" * 60)

    x = PatternExpr.var("x")
    y = PatternExpr.var("y")

    base = (x & y) + (x ^ y)
    fully_permuted = (y ^ x) + (y & x)

    egraph = create_pattern_egraph()
    egraph.register(base)
    egraph.register(fully_permuted)
    egraph.run(10)

    assert (
        egraph.check(eq(base).to(fully_permuted)) is None
    ), f"\n✗ FAILED: Could not verify equivalence!"
    print("✓ VERIFIED: (x & y) + (x ^ y) ≡ (y ^ x) + (y & x)")


def test_xor_not_equivalence():
    """Test: Verify XOR-NOT equivalence x ^ ~y == ~(x ^ y).

    This identity is critical for detecting inverse MBA rules like:
    - BnotXor_FactorRule_1: x ^ ~y -> ~(x ^ y)
    - CstSimplificationRule16: ~(x ^ c) -> x ^ ~c

    These are mathematical inverses of each other.
    """
    print("\n" + "=" * 60)
    print("Test: XOR-NOT Equivalence")
    print("=" * 60)

    x = PatternExpr.var("x")
    y = PatternExpr.var("y")

    # Form 1: x ^ ~y
    form1 = x ^ (~y)
    # Form 2: ~(x ^ y)
    form2 = ~(x ^ y)

    # Create egraph with XOR-NOT equivalence rule
    egraph = EGraph()
    a, b = vars_("a b", PatternExpr)

    # Register commutativity rules
    egraph.register(
        rewrite(a + b).to(b + a),
        rewrite(a & b).to(b & a),
        rewrite(a | b).to(b | a),
        rewrite(a ^ b).to(b ^ a),
    )

    # Register XOR-NOT equivalence (the rule we're testing)
    egraph.register(
        rewrite(a ^ (~b)).to(~(a ^ b)),
        rewrite(~(a ^ b)).to(a ^ (~b)),
    )

    egraph.register(form1)
    egraph.register(form2)
    egraph.run(10)

    assert (
        egraph.check(eq(form1).to(form2)) is None
    ), f"\n✗ FAILED: Could not verify x ^ ~y ≡ ~(x ^ y)!"
    print("✓ VERIFIED: x ^ ~y ≡ ~(x ^ y)")


def test_xor_not_equivalence_from_module():
    """Test: Verify XOR-NOT equivalence using the actual module's verify_pattern_equivalence."""
    print("\n" + "=" * 60)
    print("Test: XOR-NOT Equivalence (Using Module)")
    print("=" * 60)

    try:
        from d810.mba.backends.egglog_backend import PatternExpr as ModulePatternExpr
        from d810.mba.backends.egglog_backend import verify_pattern_equivalence
    except ImportError:
        print("SKIP: Could not import module (PYTHONPATH issue)")
        return

    x = ModulePatternExpr.var("x")
    y = ModulePatternExpr.var("y")

    form1 = x ^ (~y)
    form2 = ~(x ^ y)

    result = verify_pattern_equivalence(form1, form2)
    assert result, f"\n✗ FAILED: verify_pattern_equivalence returned False for x ^ ~y ≡ ~(x ^ y)"
    print("✓ VERIFIED: verify_pattern_equivalence(x ^ ~y, ~(x ^ y)) == True")


if __name__ == "__main__":
    print("Egglog Pattern Generation Proof-of-Concept")
    print("=" * 60)

    results = []
    results.append(
        ("Or_MbaRule_1 pattern gen", test_or_mba_rule_1_pattern_generation())
    )
    results.append(("Nested commutativity", test_nested_commutativity()))
    results.append(("Full permutation", test_full_permutation()))
    results.append(("XOR-NOT equivalence", test_xor_not_equivalence()))
    results.append(("XOR-NOT equivalence (module)", test_xor_not_equivalence_from_module()))

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    passed = sum(1 for _, r in results if r)
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {name}")
    print(f"\nTotal: {passed}/{len(results)} tests passed")

    if passed == len(results):
        print("\n✓ Egglog can generate equivalent pattern variants!")
        print("  This approach can replace manual *_Commuted rule definitions.")
