"""Automated verification tests for all VerifiableRule subclasses.

This test module demonstrates the power of the refactored rule system:
- No manual test cases needed for individual rules
- Rules are verified using Z3 via the z3 backend
- Adding a new rule automatically adds it to the test suite
- Failed verification provides detailed counterexamples

The single test function below replaces what would have been dozens of manual
test cases in the old system.

WHY THIS IS IN system/ TESTS:
    These tests don't use IDA functionality directly - they only need Z3 and
    Python. However, they're in system/ because the registry is populated
    when rule modules are imported, and those modules have top-level imports
    like `from ida_hexrays import *`. Therefore, `idapro` must be imported
    first (done in system/conftest.py) before the rule modules can load.

NOTE: Rules are automatically discovered and loaded by the conftest.py
      using reload_package(d810). No manual imports needed!
"""

import pytest

from d810.mba.rules import VerifiableRule
from d810.mba.backends.z3 import verify_rule


def get_all_rules():
    """Get all registered VerifiableRule instances for parametrization."""
    return VerifiableRule.instantiate_all()


@pytest.mark.slow  # Z3 verification takes ~12 seconds
def test_registry_is_populated():
    """Sanity check: ensure at least some rules were discovered and registered.

    If this fails, it means either:
    1. No refactored rule modules were imported
    2. The auto-registration mechanism is broken
    3. All rule classes are abstract (have unimplemented abstract methods)
    """
    assert len(VerifiableRule.registry) > 0, (
        "No rules were discovered and registered. "
        "Make sure refactored rule modules are imported in this test file."
    )


def _get_correct_rules():
    """Get rules that are expected to be mathematically correct."""
    return [
        r for r in get_all_rules()
        if not getattr(r, "KNOWN_INCORRECT", False)
        and not getattr(r, "SKIP_VERIFICATION", False)
    ]


def _get_known_incorrect_rules():
    """Get rules that are marked as KNOWN_INCORRECT."""
    return [r for r in get_all_rules() if getattr(r, "KNOWN_INCORRECT", False)]


def _get_skip_verification_rules():
    """Get rules that are marked as SKIP_VERIFICATION (too slow for Z3)."""
    return [r for r in get_all_rules() if getattr(r, "SKIP_VERIFICATION", False)]


@pytest.mark.slow
@pytest.mark.parametrize("rule", _get_correct_rules(), ids=lambda r: r.name)
def test_rule_is_correct(rule: VerifiableRule):
    """Verify the mathematical correctness of every registered correct rule.

    This single, generic test verifies every rule that inherits from
    VerifiableRule by calling verify_rule() from the Z3 backend, which
    proves semantic equivalence.

    If this test fails for a rule, it means:
    - The pattern and replacement are NOT semantically equivalent
    - The rule would introduce bugs if used
    - The rule definition needs to be fixed

    The failure message will include:
    - Rule name and description
    - The incorrect identity being claimed
    - A concrete counterexample showing inputs where pattern != replacement

    Args:
        rule: A VerifiableRule instance (provided by pytest parametrization).

    Raises:
        AssertionError: If the rule's pattern and replacement are not equivalent.
    """
    # Use the Z3 backend to verify rule correctness
    # All Z3 logic is encapsulated in the backend
    verify_rule(rule)


@pytest.mark.slow
@pytest.mark.parametrize("rule", _get_known_incorrect_rules(), ids=lambda r: r.name)
def test_known_incorrect_rule_fails_verification(rule: VerifiableRule):
    """Confirm that KNOWN_INCORRECT rules actually fail Z3 verification.

    This test runs Z3 verification on rules marked KNOWN_INCORRECT and asserts
    that verification FAILS (i.e., Z3 finds a counterexample). This serves two
    purposes:

    1. Documents that the incorrectness is real and verifiable
    2. Acts as a canary: if this test starts FAILING (meaning Z3 says the rule
       is now correct), it means someone fixed the rule and KNOWN_INCORRECT
       should be removed

    The test uses strict=True xfail semantics implemented manually:
    - If verify_rule raises AssertionError -> test PASSES (expected failure)
    - If verify_rule succeeds -> test FAILS (rule was fixed, remove KNOWN_INCORRECT)

    Args:
        rule: A VerifiableRule instance marked KNOWN_INCORRECT.
    """
    try:
        verify_rule(rule)
    except AssertionError:
        # Expected: Z3 found a counterexample proving the rule is incorrect
        return

    pytest.fail(
        f"Rule {rule.name} is marked KNOWN_INCORRECT but Z3 verification PASSED. "
        f"The rule appears to be correct now. Remove KNOWN_INCORRECT = True from "
        f"the rule definition."
    )


@pytest.mark.slow
@pytest.mark.parametrize("rule", _get_skip_verification_rules(), ids=lambda r: r.name)
def test_skip_verification_rule_is_documented(rule: VerifiableRule):
    """Confirm that SKIP_VERIFICATION rules are properly documented.

    These rules are skipped because Z3 verification is too slow (e.g.,
    rules with multiple multiplications like Mul_MBA_1 and Mul_MBA_4 take
    6+ minutes each) or because the rule involves size-changing operations
    that cannot be expressed in fixed-width bitvector arithmetic (e.g.,
    ReplaceMovHighContext).

    This test verifies the rule exists and has documentation, but does NOT
    run Z3 verification.
    """
    assert rule.name, f"SKIP_VERIFICATION rule has no name"
    assert rule.description and rule.description != "No description", (
        f"SKIP_VERIFICATION rule {rule.name} should have a description "
        f"explaining why verification is skipped"
    )


@pytest.mark.slow
def test_rule_names_are_unique():
    """Ensure all rules have unique names.

    Duplicate names would cause confusion in logging and debugging.
    """
    all_rules = get_all_rules()
    names = [rule.name for rule in all_rules]
    duplicates = [name for name in names if names.count(name) > 1]

    assert len(duplicates) == 0, (
        f"Found rules with duplicate names: {set(duplicates)}\n"
        f"Each rule must have a unique name for identification."
    )


@pytest.mark.slow
def test_all_rules_have_descriptions():
    """Ensure all rules have meaningful descriptions.

    Rules should document what they do and why. A description is required
    for maintainability.
    """
    all_rules = get_all_rules()
    unnamed_rules = [
        rule for rule in all_rules if rule.description in ["No description", ""]
    ]

    assert len(unnamed_rules) == 0, (
        f"Found rules without descriptions: {[r.name for r in unnamed_rules]}\n"
        f"Every rule should have a description explaining what it does."
    )


# When a developer adds a new VerifiableRule subclass:
# 1. Create the rule class in a module under pattern_matching/
# 2. The scanner automatically discovers and loads it (via conftest.py)
# 3. The rule is automatically added to VerifiableRule.registry via __init_subclass__
# 4. All three tests above automatically apply to it
# 5. No additional test code or imports needed!
#
# This is the power of the refactored architecture:
# - Rules are verified by the Z3 backend (proves correctness)
# - Tests are generic and comprehensive
# - Scanner automatically discovers new rules
# - Adding rules is trivial and safe (no manual test updates)
