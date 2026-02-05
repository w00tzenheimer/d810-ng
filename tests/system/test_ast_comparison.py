"""Demonstration of AST-based code comparison for d810 tests.

This module shows how to use libclang for robust code comparison
that ignores formatting differences.
"""

import textwrap

import pytest


def test_identical_code(require_clang, code_comparator):
    """Test that identical code is recognized as equivalent."""
    code = textwrap.dedent(
        """\
        __int64 __fastcall test_func(int a1, int a2)
        {
            return a1 + a2;
        }"""
    )
    code_comparator.check_equivalence(code, code)


def test_whitespace_differences(require_clang, code_comparator):
    """Test that whitespace differences are ignored."""
    code1 = textwrap.dedent(
        """\
        __int64 __fastcall test_func(int a1, int a2)
        {
            return a1 + a2;
        }"""
    )

    code2 = textwrap.dedent(
        """\
        __int64 __fastcall test_func(int a1, int a2)
        {
                return a1 + a2;
        }"""
    )

    code_comparator.check_equivalence(code1, code2)


def test_comment_differences(require_clang, code_comparator):
    """Test that comments are ignored."""
    code1 = textwrap.dedent(
        """\
        __int64 __fastcall test_func(int a1, int a2)
        {
            return a1 + a2;
        }"""
    )

    code2 = textwrap.dedent(
        """\
        __int64 __fastcall test_func(int a1, int a2)
        {
            // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

            return a1 + a2;
        }"""
    )

    code_comparator.check_equivalence(code1, code2)


def test_semantic_difference_detected(require_clang, code_comparator):
    """Test that semantic differences are detected."""
    code1 = "void func() { int a = 1 + 2; }"
    code2 = "void func() { int a = 1 - 2; }"  # Different operator

    with pytest.raises(AssertionError):
        code_comparator.check_equivalence(code1, code2)


def test_xor_simplification_example(require_clang, code_comparator):
    """Example: XOR pattern simplification."""
    # Before d810 optimization (obfuscated XOR)
    before = textwrap.dedent(
        """\
        __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
        {
            *a4 = a2 + a1 - 2 * (a2 & a1);
            a4[1] = a2 - 3 + a3 * a1 - 2 * ((a2 - 3) & (a3 * a1));
            return (unsigned int)(a4[1] + *a4);
        }"""
    )

    # After d810 optimization (simplified XOR)
    after = textwrap.dedent(
        """\
        __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
        {
            // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

            *a4 = a2 ^ a1;
            a4[1] = (a2 - 3) ^ (a3 * a1);
            return (unsigned int)(a4[1] + *a4);
        }"""
    )

    # These are semantically DIFFERENT - the XOR is optimized
    # So this should FAIL (demonstrating that AST comparison detects real changes)
    with pytest.raises(AssertionError):
        code_comparator.check_equivalence(before, after)


def test_type_cast_variations(require_clang, code_comparator):
    """Test that C-style and functional casts are detected as structurally different.

    While (int)5 and int(5) are semantically equivalent, they parse to different
    AST nodes in Clang (CStyleCastExpr vs CXXFunctionalCastExpr). The CodeComparator
    does structural comparison, so it correctly identifies them as different.
    """
    code1 = "void func() { int a = (int)5; }"
    code2 = "void func() { int a = int(5); }"

    # These are structurally different (CStyleCastExpr vs CXXFunctionalCastExpr)
    with pytest.raises(AssertionError):
        code_comparator.check_equivalence(code1, code2)

    # Same cast syntax should be equivalent
    code3 = "void func() { int a = (int)5; }"
    code4 = "void func() { int a =   (int)5; }"  # Just whitespace difference
    code_comparator.check_equivalence(code3, code4)


def test_are_equivalent_true(require_clang, code_comparator):
    """Test that are_equivalent returns True for equivalent code."""
    code = "void func() { int a = 1; }"
    assert code_comparator.are_equivalent(code, code) is True


def test_are_equivalent_false(require_clang, code_comparator):
    """Test that are_equivalent returns False for different code."""
    code1 = "void func() { int a = 1; }"
    code2 = "void func() { int a = 2; }"
    assert code_comparator.are_equivalent(code1, code2) is False
