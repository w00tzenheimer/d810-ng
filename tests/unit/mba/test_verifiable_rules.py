"""Unit tests for VerifiableRule Z3 verification - NO IDA REQUIRED.

This is the unit test version of tests/system/optimizers/test_verifiable_rules.py.
It demonstrates that optimization rules can be verified mathematically without IDA.

Key differences from system test:
1. Rules are defined directly in this file using the pure DSL
2. No global RULE_REGISTRY - we create a local registry
3. No IDA imports - verification uses Z3VerificationVisitor directly
4. Rules are verified via prove_equivalence(), not rule.verify()

This enables:
- Fast CI feedback (no IDA license needed)
- TDD for new rules (write rule, verify, then integrate with IDA)
- Mathematical correctness checking separate from IDA integration
"""

import pytest

from d810.mba.dsl import (
    NEGATIVE_ONE,
    ONE,
    TWO,
    ZERO,
    Const,
    Var,
)
from d810.mba.rules import VerifiableRule
from d810.mba.backends.z3 import prove_equivalence

# =============================================================================
# Test Rule Definitions (Pure DSL - No IDA)
# =============================================================================
# These mirror the actual rules in pattern_matching/rewrite_*.py but are
# defined here using pure SymbolicExpression DSL.

# Common variables used across rules
x = Var("x")
y = Var("y")
c1 = Const("c_1")  # Pattern-matching constant (binds to any constant)
c2 = Const("c_2")


class Xor_HackersDelight_AddSubAnd(VerifiableRule):
    """XOR via addition, subtraction, and AND: x + y - 2*(x & y) = x ^ y."""

    DESCRIPTION = "Hacker's Delight XOR identity using add/sub/and"
    PATTERN = x + y - TWO * (x & y)
    REPLACEMENT = x ^ y


class Xor_HackersDelight_OrSubAnd(VerifiableRule):
    """XOR via OR and AND: (x | y) - (x & y) = x ^ y."""

    DESCRIPTION = "Hacker's Delight XOR identity using or/sub/and"
    PATTERN = (x | y) - (x & y)
    REPLACEMENT = x ^ y


class Xor_HackersDelight_OrXorAnd(VerifiableRule):
    """XOR via OR and AND with XOR: (x | y) ^ (x & y) = x ^ y."""

    DESCRIPTION = "XOR identity using or/xor/and"
    PATTERN = (x | y) ^ (x & y)
    REPLACEMENT = x ^ y


class And_DeMorgan(VerifiableRule):
    """De Morgan's law for AND: ~(~x | ~y) = x & y."""

    DESCRIPTION = "De Morgan's law: NOT(NOT x OR NOT y) = x AND y"
    PATTERN = ~(~x | ~y)
    REPLACEMENT = x & y


class Or_DeMorgan(VerifiableRule):
    """De Morgan's law for OR: ~(~x & ~y) = x | y."""

    DESCRIPTION = "De Morgan's law: NOT(NOT x AND NOT y) = x OR y"
    PATTERN = ~(~x & ~y)
    REPLACEMENT = x | y


class Bnot_NegMinusOne(VerifiableRule):
    """Bitwise NOT identity: ~x = -x - 1."""

    DESCRIPTION = "Bitwise NOT as negation minus one"
    PATTERN = ~x
    REPLACEMENT = -x - ONE


class Bnot_NegMinusOne_Alt(VerifiableRule):
    """Bitwise NOT identity (alternative): -x - 1 = ~x."""

    DESCRIPTION = "Negation minus one as bitwise NOT"
    PATTERN = -x - ONE
    REPLACEMENT = ~x


class Add_NegToSub(VerifiableRule):
    """Addition of negation: x + (-y) = x - y."""

    DESCRIPTION = "Convert add-neg to subtraction"
    PATTERN = x + (-y)
    REPLACEMENT = x - y


class Sub_DoubleNeg(VerifiableRule):
    """Subtraction of negation: x - (-y) = x + y."""

    DESCRIPTION = "Convert sub-neg to addition"
    PATTERN = x - (-y)
    REPLACEMENT = x + y


class Xor_SelfZero(VerifiableRule):
    """XOR self identity: x ^ x = 0."""

    DESCRIPTION = "XOR with self is zero"
    PATTERN = x ^ x
    REPLACEMENT = ZERO


class And_SelfIdentity(VerifiableRule):
    """AND self identity: x & x = x."""

    DESCRIPTION = "AND with self is identity"
    PATTERN = x & x
    REPLACEMENT = x


class Or_SelfIdentity(VerifiableRule):
    """OR self identity: x | x = x."""

    DESCRIPTION = "OR with self is identity"
    PATTERN = x | x
    REPLACEMENT = x


class Add_Zero(VerifiableRule):
    """Addition identity: x + 0 = x."""

    DESCRIPTION = "Adding zero is identity"
    PATTERN = x + ZERO
    REPLACEMENT = x


class Sub_Zero(VerifiableRule):
    """Subtraction identity: x - 0 = x."""

    DESCRIPTION = "Subtracting zero is identity"
    PATTERN = x - ZERO
    REPLACEMENT = x


class Mul_One(VerifiableRule):
    """Multiplication identity: x * 1 = x."""

    DESCRIPTION = "Multiplying by one is identity"
    PATTERN = x * ONE
    REPLACEMENT = x


class Mul_Zero(VerifiableRule):
    """Multiplication by zero: x * 0 = 0."""

    DESCRIPTION = "Multiplying by zero is zero"
    PATTERN = x * ZERO
    REPLACEMENT = ZERO


class Xor_Zero(VerifiableRule):
    """XOR with zero: x ^ 0 = x."""

    DESCRIPTION = "XOR with zero is identity"
    PATTERN = x ^ ZERO
    REPLACEMENT = x


class And_Zero(VerifiableRule):
    """AND with zero: x & 0 = 0."""

    DESCRIPTION = "AND with zero is zero"
    PATTERN = x & ZERO
    REPLACEMENT = ZERO


class Or_Zero(VerifiableRule):
    """OR with zero: x | 0 = x."""

    DESCRIPTION = "OR with zero is identity"
    PATTERN = x | ZERO
    REPLACEMENT = x


class And_NegOne(VerifiableRule):
    """AND with -1 (all bits set): x & (-1) = x."""

    DESCRIPTION = "AND with all-ones is identity"
    PATTERN = x & NEGATIVE_ONE
    REPLACEMENT = x


class Or_NegOne(VerifiableRule):
    """OR with -1 (all bits set): x | (-1) = -1."""

    DESCRIPTION = "OR with all-ones is all-ones"
    PATTERN = x | NEGATIVE_ONE
    REPLACEMENT = NEGATIVE_ONE


class DoubleNeg(VerifiableRule):
    """Double negation: -(-x) = x."""

    DESCRIPTION = "Double negation cancels"
    PATTERN = -(-x)
    REPLACEMENT = x


class DoubleBnot(VerifiableRule):
    """Double bitwise NOT: ~~x = x."""

    DESCRIPTION = "Double bitwise NOT cancels"
    PATTERN = ~~x
    REPLACEMENT = x


class Sub_Self(VerifiableRule):
    """Subtraction of self: x - x = 0."""

    DESCRIPTION = "Subtracting self is zero"
    PATTERN = x - x
    REPLACEMENT = ZERO


# =============================================================================
# Local Rule Registry (No IDA dependency)
# =============================================================================

# Collect all rules defined in this module
# This replaces the global RULE_REGISTRY which requires IDA
LOCAL_RULE_REGISTRY = [
    Xor_HackersDelight_AddSubAnd,
    Xor_HackersDelight_OrSubAnd,
    Xor_HackersDelight_OrXorAnd,
    And_DeMorgan,
    Or_DeMorgan,
    Bnot_NegMinusOne,
    Bnot_NegMinusOne_Alt,
    Add_NegToSub,
    Sub_DoubleNeg,
    Xor_SelfZero,
    And_SelfIdentity,
    Or_SelfIdentity,
    Add_Zero,
    Sub_Zero,
    Mul_One,
    Mul_Zero,
    Xor_Zero,
    And_Zero,
    Or_Zero,
    And_NegOne,
    Or_NegOne,
    DoubleNeg,
    DoubleBnot,
    Sub_Self,
]


# =============================================================================
# Tests
# =============================================================================


def test_registry_is_populated():
    """Sanity check: ensure rules were defined and collected."""
    assert len(LOCAL_RULE_REGISTRY) > 0, "No rules in local registry"
    assert len(LOCAL_RULE_REGISTRY) >= 20, f"Expected 20+ rules, got {len(LOCAL_RULE_REGISTRY)}"


@pytest.mark.parametrize(
    "rule_cls",
    LOCAL_RULE_REGISTRY,
    ids=lambda r: r.__name__,
)
def test_rule_is_correct(rule_cls):
    """Verify mathematical correctness of each rule using Z3.

    This test:
    1. Accesses the DSL pattern and replacement directly (no .node)
    2. Uses prove_equivalence() which is IDA-free
    3. Provides counterexample on failure

    Args:
        rule_cls: A VerifiableRule class (not instance - avoids .node access)
    """
    pattern = rule_cls._dsl_pattern
    replacement = rule_cls._dsl_replacement

    assert pattern is not None, f"Rule {rule_cls.__name__} has no pattern"
    assert replacement is not None, f"Rule {rule_cls.__name__} has no replacement"

    is_equiv, counterexample = prove_equivalence(pattern, replacement)

    if not is_equiv:
        msg = (
            f"\n--- VERIFICATION FAILED ---\n"
            f"Rule:        {rule_cls.__name__}\n"
            f"Description: {getattr(rule_cls, 'DESCRIPTION', 'No description')}\n"
            f"Pattern:     {pattern}\n"
            f"Replacement: {replacement}\n"
        )
        if counterexample:
            msg += f"Counterexample: {counterexample}\n"
        msg += "This rule does NOT preserve semantics!"
        pytest.fail(msg)


def test_rule_names_are_unique():
    """Ensure all rules have unique names."""
    names = [rule.__name__ for rule in LOCAL_RULE_REGISTRY]
    duplicates = [name for name in names if names.count(name) > 1]

    assert len(duplicates) == 0, f"Found rules with duplicate names: {set(duplicates)}"


def test_all_rules_have_descriptions():
    """Ensure all rules have meaningful descriptions."""
    unnamed = [
        rule.__name__
        for rule in LOCAL_RULE_REGISTRY
        if getattr(rule, "DESCRIPTION", "No description") == "No description"
    ]

    assert len(unnamed) == 0, f"Found rules without descriptions: {unnamed}"


def test_xor_identity_variations():
    """Test multiple equivalent XOR representations."""
    # All these should be equivalent to x ^ y
    xor_result = x ^ y

    # (x | y) - (x & y) = x ^ y
    is_equiv1, _ = prove_equivalence((x | y) - (x & y), xor_result)
    assert is_equiv1, "XOR identity 1 failed"

    # x + y - 2*(x & y) = x ^ y
    is_equiv2, _ = prove_equivalence(x + y - TWO * (x & y), xor_result)
    assert is_equiv2, "XOR identity 2 failed"

    # (x | y) ^ (x & y) = x ^ y
    is_equiv3, _ = prove_equivalence((x | y) ^ (x & y), xor_result)
    assert is_equiv3, "XOR identity 3 failed"

    # (x & ~y) | (~x & y) = x ^ y
    is_equiv4, _ = prove_equivalence((x & ~y) | (~x & y), xor_result)
    assert is_equiv4, "XOR identity 4 failed"


def test_demorgan_laws():
    """Test De Morgan's laws."""
    # ~(x | y) = ~x & ~y
    is_equiv1, _ = prove_equivalence(~(x | y), ~x & ~y)
    assert is_equiv1, "De Morgan 1 failed"

    # ~(x & y) = ~x | ~y
    is_equiv2, _ = prove_equivalence(~(x & y), ~x | ~y)
    assert is_equiv2, "De Morgan 2 failed"


def test_incorrect_rule_detected():
    """Verify that incorrect rules are detected."""

    class IncorrectRule(VerifiableRule):
        """This rule is WRONG - x + y != x - y."""

        DESCRIPTION = "Intentionally incorrect for testing"
        PATTERN = x + y
        REPLACEMENT = x - y

    is_equiv, counterexample = prove_equivalence(
        IncorrectRule._dsl_pattern, IncorrectRule._dsl_replacement
    )

    assert is_equiv is False, "Incorrect rule should be detected as non-equivalent"
    assert counterexample is not None, "Should provide counterexample"


# =============================================================================
# Usage Example
# =============================================================================
#
# To add a new rule:
# 1. Define the rule class using pure DSL (Var, Const, operators)
# 2. Add it to LOCAL_RULE_REGISTRY
# 3. Run: PYTHONPATH="src" python -m pytest tests/unit/mba/test_verifiable_rules.py -v
# 4. If verification passes, the rule is mathematically correct!
# 5. Then add IDA integration in pattern_matching/rewrite_*.py
#
# This TDD workflow ensures rules are correct BEFORE IDA integration.
