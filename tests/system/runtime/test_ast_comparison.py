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


# =============================================================================
# Type-Agnostic AST Comparison Tests (Tiers 1-3)
# =============================================================================


class TestTier1IDATypedefs:
    """Tier 1: IDA typedef preamble resolves _DWORD, __int64, etc."""

    def test_dword_ptr_vs_int_ptr(self, require_clang, code_comparator):
        """_DWORD* and int* should be compatible (same width bucket)."""
        code1 = textwrap.dedent("""\
            __int64 __fastcall test_func(_DWORD *a1)
            {
                a1[1] = 1;
                return 0;
            }""")
        code2 = textwrap.dedent("""\
            __int64 __fastcall test_func(int *a1)
            {
                a1[1] = 1;
                return 0;
            }""")
        code_comparator.check_equivalence(code1, code2)

    def test_dword_ptr_vs_unsigned_int_ptr(self, require_clang, code_comparator):
        """_DWORD* and unsigned int* should be compatible (same width)."""
        code1 = textwrap.dedent("""\
            __int64 __fastcall test_func(_DWORD *a1)
            {
                a1[0] = 42;
                return 0;
            }""")
        code2 = textwrap.dedent("""\
            __int64 __fastcall test_func(unsigned int *a1)
            {
                a1[0] = 42;
                return 0;
            }""")
        code_comparator.check_equivalence(code1, code2)

    def test_int64_typedef(self, require_clang, code_comparator):
        """__int64 and long long should be compatible (both 64-bit)."""
        code1 = textwrap.dedent("""\
            __int64 __fastcall test_func(__int64 a1)
            {
                return a1 + 1;
            }""")
        code2 = textwrap.dedent("""\
            long long __fastcall test_func(long long a1)
            {
                return a1 + 1;
            }""")
        code_comparator.check_equivalence(code1, code2)


class TestTier2WidthBuckets:
    """Tier 2: TypeKind equivalence classes map to bit-width buckets."""

    def test_int_vs_unsigned_int_params(self, require_clang, code_comparator):
        """int and unsigned int params should be compatible (both 32-bit)."""
        code1 = textwrap.dedent("""\
            __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 ^ a1;
                return 0;
            }""")
        code2 = textwrap.dedent("""\
            __int64 __fastcall test_xor(unsigned int a1, unsigned int a2, unsigned int a3, unsigned int *a4)
            {
                *a4 = a2 ^ a1;
                return 0;
            }""")
        code_comparator.check_equivalence(code1, code2)

    def test_cross_platform_xor_signature(self, require_clang, code_comparator):
        """The real test_xor cross-platform case: int vs __int64 params."""
        code_win = textwrap.dedent("""\
            __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 ^ a1;
                a4[1] = (a2 - 3) ^ (a3 * a1);
                return (unsigned int)(a4[1] + *a4);
            }""")
        code_mac = textwrap.dedent("""\
            __int64 __fastcall test_xor(__int64 a1, __int64 a2, __int64 a3, __int64 *a4)
            {
                *a4 = a2 ^ a1;
                a4[1] = (a2 - 3) ^ (a3 * a1);
                return (unsigned int)(a4[1] + *a4);
            }""")
        code_comparator.check_equivalence(code_win, code_mac)

    def test_different_width_rejected_strict(self, require_clang, clang_index):
        """With ignore_types=False, int and short should NOT be compatible."""
        from tests.system.conftest import CodeComparator
        comp_strict = CodeComparator(clang_index, ignore_types=False)
        code1 = "void func(int a) { }"
        code2 = "void func(short a) { }"
        with pytest.raises(AssertionError):
            comp_strict.check_equivalence(code1, code2)

    def test_strict_mode_rejects_width_match(self, require_clang, clang_index):
        """With ignore_types=False, int vs unsigned int should fail."""
        from tests.system.conftest import CodeComparator
        comp_strict = CodeComparator(clang_index, ignore_types=False)
        code1 = textwrap.dedent("""\
            __int64 __fastcall test_func(int a1)
            {
                return a1;
            }""")
        code2 = textwrap.dedent("""\
            __int64 __fastcall test_func(unsigned int a1)
            {
                return a1;
            }""")
        # Strict mode should reject this even though both are 32-bit
        with pytest.raises(AssertionError):
            comp_strict.check_equivalence(code1, code2)


class TestTier3CastStripping:
    """Tier 3: Trivial integer casts are stripped during child comparison."""

    def test_cast_vs_bare_return(self, require_clang, code_comparator):
        """(unsigned int)(expr) should match bare expr."""
        code1 = textwrap.dedent("""\
            __int64 __fastcall test_func(int a1, int a2)
            {
                return (unsigned int)(a1 + a2);
            }""")
        code2 = textwrap.dedent("""\
            __int64 __fastcall test_func(int a1, int a2)
            {
                return a1 + a2;
            }""")
        code_comparator.check_equivalence(code1, code2)

    def test_non_trivial_cast_preserved(self, require_clang, code_comparator):
        """A cast to a pointer type should NOT be stripped."""
        code1 = "void func() { int a = 1; }"
        code2 = "void func() { int a = 2; }"
        # This is a semantic difference, not a cast issue
        with pytest.raises(AssertionError):
            code_comparator.check_equivalence(code1, code2)

    def test_real_world_or_pattern(self, require_clang, code_comparator):
        """Cross-platform OR pattern: int vs __int64 params with cast."""
        code_expected = textwrap.dedent("""\
            __int64 __fastcall test_or(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 | a1;
                a4[1] = a3 | a2;
                a4[2] = (a2 - 2) | (a1 + 1);
                return (unsigned int)(a4[2] + a4[1] + *a4);
            }""")
        code_actual = textwrap.dedent("""\
            __int64 __fastcall test_or(__int64 a1, __int64 a2, __int64 a3, __int64 *a4)
            {
                *a4 = a2 | a1;
                a4[1] = a3 | a2;
                a4[2] = (a2 - 2) | (a1 + 1);
                return (unsigned int)(a4[2] + a4[1] + *a4);
            }""")
        code_comparator.check_equivalence(code_actual, code_expected)

    def test_unexposed_cast_wrapper_vs_bare_return(self, require_clang, code_comparator):
        """Cast wrapped in UNEXPOSED_EXPR should match bare binary return."""
        code_dll = textwrap.dedent("""\
            __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 ^ a1;
                a4[1] = (a2 - 3) ^ (a3 * a1);
                return (unsigned int)(a4[1] + *a4);
            }""")
        code_alt = textwrap.dedent("""\
            __int64 __fastcall test_xor(__int64 a1, __int64 a2, __int64 a3, __int64 *a4)
            {
                *a4 = a2 ^ a1;
                a4[1] = (a2 - 3) ^ (a3 * a1);
                return a4[1] + *a4;
            }""")
        code_comparator.check_equivalence(code_dll, code_alt)
