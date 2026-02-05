"""Test cases for libobfuscated binary.

This module defines deobfuscation test cases as data using DeobfuscationCase.
These cases are consumed by test_libdeobfuscated_dsl.py.

Example usage::

    from tests.system.cases.libobfuscated import LIBOBFUSCATED_CASES

    @pytest.mark.parametrize("case", LIBOBFUSCATED_CASES, ids=lambda c: c.test_id)
    def test_deobfuscation(case, d810_state, ...):
        run_deobfuscation_test(case, d810_state, ...)
"""

from d810.testing import DeobfuscationCase, BinaryOverride


# =============================================================================
# Test Cases
# =============================================================================

LIBOBFUSCATED_CASES = [
    # -------------------------------------------------------------------------
    # test_simplify_chained_add
    # -------------------------------------------------------------------------
    DeobfuscationCase(
        function="test_chained_add",
        description="Test simplification of chained addition expressions",
        project="default_instruction_only.json",
        # Before: obfuscated code contains magic constants
        obfuscated_contains=["0xFFFFFFEF"],
        # After: simplified to readable form
        expected_code="""
            __int64 __fastcall test_chained_add(__int64 a1)
            {
                return 2 * a1[1] + 0x33;
            }
        """,
        # Alternative acceptable patterns
        acceptable_patterns=["2 * a1[1]", "a1[1] + a1[1]", "0x33", "0x34"],
        # Rules that should fire
        required_rules=["ArithmeticChain"],
    ),
    # -------------------------------------------------------------------------
    # test_cst_simplification
    # -------------------------------------------------------------------------
    DeobfuscationCase(
        function="test_cst_simplification",
        description="Test constant simplification with Z3",
        project="default_instruction_only.json",
        # Before: complex constant expressions
        obfuscated_contains=["0x222E69C2", "0x50211120"],
        # After: folded constants
        expected_code="""
            __int64 __fastcall test_cst_simplification(__int64 a1)
            {
                *a1 = 0x222E69C0;
                a1[1] = 0xD32B5931;
                a1[2] = 0x222E69C0;
                a1[3] = 0xD32B5931;
                a1[4] = 0xA29;
                return 0;
            }
        """,
        # Acceptable: specific constants are folded
        acceptable_patterns=["0x222E69C0", "0xD32B5931", "0xA29"],
        # Note: No required_rules - Z3 rules can vary by platform
    ),
    # -------------------------------------------------------------------------
    # test_or_mba_rule (example with binary-specific override)
    # -------------------------------------------------------------------------
    DeobfuscationCase(
        function="test_or_mba_rule",
        description="Test OR MBA rule simplification",
        project="default_instruction_only.json",
        obfuscated_contains=["0x5FEF5FEF"],
        deobfuscated_contains=["0x5FEF5FEF", "|"],
        # DLL may have slightly different patterns
        dll_override=BinaryOverride(
            # Adjust expected patterns for Windows binary
            deobfuscated_contains=["0x5FEF5FEF"],
        ),
    ),
]


# =============================================================================
# Subsets for focused testing
# =============================================================================

# Quick smoke tests (fastest subset)
SMOKE_TEST_CASES = [
    case for case in LIBOBFUSCATED_CASES
    if case.function in {"test_chained_add"}
]

# Z3-dependent tests
Z3_TEST_CASES = [
    case for case in LIBOBFUSCATED_CASES
    if case.function in {"test_cst_simplification"}
]
