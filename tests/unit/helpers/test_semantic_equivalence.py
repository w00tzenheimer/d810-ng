"""Unit tests for semantic equivalence testing infrastructure.

These tests verify that we can compile C code, call functions, and assert
semantic equivalence correctly.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from tests.system.helpers.semantic_equivalence import (
    assert_semantic_equivalence,
    call_function,
    compile_reference_function,
    generate_test_cases,
)


class TestCompileAndCall:
    """Tests for basic compilation and function calling."""

    def test_compile_simple_function(self):
        """Compile and call a trivial addition function."""
        # Write a simple C file
        temp_dir = pathlib.Path(tempfile.mkdtemp())
        c_file = temp_dir / "simple.c"
        c_file.write_text("""
            int add(int a, int b) {
                return a + b;
            }
        """)

        # Compile and load
        lib = compile_reference_function(str(c_file), "add")

        # Call and verify
        result = call_function(lib, "add", (2, 3))
        assert result == 5

        result = call_function(lib, "add", (100, 200))
        assert result == 300

        # Cleanup
        c_file.unlink()
        temp_dir.rmdir()

    def test_compile_dispatcher_patterns(self):
        """Compile dispatcher_patterns.c and call mixed_dispatcher_pattern."""
        # Find the source file
        tests_dir = pathlib.Path(__file__).parent.parent.parent
        project_root = tests_dir.parent
        c_source = project_root / "samples" / "src" / "c" / "dispatcher_patterns.c"

        if not c_source.exists():
            pytest.skip(f"Source file not found: {c_source}")

        # Compile
        lib = compile_reference_function(str(c_source), "mixed_dispatcher_pattern")

        # Test known good inputs
        # (10, 20): result=30, +10=40, <100 so state=0x9ABCDEF0, -1=39, <50 so exit
        result = call_function(lib, "mixed_dispatcher_pattern", (10, 20))
        assert result == 39

        # (5, 5): result=10, +10=20, <100 so state=0x9ABCDEF0, -1=19, <50 so exit
        result = call_function(lib, "mixed_dispatcher_pattern", (5, 5))
        assert result == 19

        # (0, 0): result=0, +10=10, <100 so state=0x9ABCDEF0, -1=9, <50 so exit
        result = call_function(lib, "mixed_dispatcher_pattern", (0, 0))
        assert result == 9


class TestGenerateTestCases:
    """Tests for test case generation."""

    def test_generate_test_cases_deterministic(self):
        """Verify same seed produces same test cases."""
        # Write a simple function
        temp_dir = pathlib.Path(tempfile.mkdtemp())
        c_file = temp_dir / "multiply.c"
        c_file.write_text("""
            int multiply(int a, int b) {
                return a * b;
            }
        """)

        # Generate with seed 42
        cases1 = generate_test_cases(
            str(c_file),
            "multiply",
            arg_ranges=[(0, 10), (0, 10)],
            num_cases=5,
            seed=42,
        )

        # Generate again with same seed
        cases2 = generate_test_cases(
            str(c_file),
            "multiply",
            arg_ranges=[(0, 10), (0, 10)],
            num_cases=5,
            seed=42,
        )

        # Should be identical
        assert cases1 == cases2

        # Generate with different seed
        cases3 = generate_test_cases(
            str(c_file),
            "multiply",
            arg_ranges=[(0, 10), (0, 10)],
            num_cases=5,
            seed=123,
        )

        # Should be different
        assert cases1 != cases3

        # Cleanup
        c_file.unlink()
        temp_dir.rmdir()

    def test_generate_test_cases_values(self):
        """Verify generated test cases have correct outputs."""
        # Write a simple function
        temp_dir = pathlib.Path(tempfile.mkdtemp())
        c_file = temp_dir / "square.c"
        c_file.write_text("""
            int square(int a) {
                return a * a;
            }
        """)

        # Generate test cases
        cases = generate_test_cases(
            str(c_file),
            "square",
            arg_ranges=[(1, 5)],
            num_cases=5,
            seed=42,
        )

        # Verify each case
        for args, expected in cases:
            a = args[0]
            assert expected == a * a

        # Cleanup
        c_file.unlink()
        temp_dir.rmdir()


class TestAssertSemanticEquivalence:
    """Tests for semantic equivalence assertions."""

    def test_assert_semantic_equivalence_passes(self):
        """Test that correct test cases pass."""
        # Write a simple function
        temp_dir = pathlib.Path(tempfile.mkdtemp())
        c_file = temp_dir / "negate.c"
        c_file.write_text("""
            int negate(int a) {
                return -a;
            }
        """)

        # Correct test cases
        test_cases = [
            ((5,), -5),
            ((0,), 0),
            ((-10,), 10),
        ]

        # Should not raise
        assert_semantic_equivalence(str(c_file), "negate", test_cases)

        # Cleanup
        c_file.unlink()
        temp_dir.rmdir()

    def test_assert_semantic_equivalence_fails(self):
        """Test that incorrect test cases fail."""
        # Write a simple function
        temp_dir = pathlib.Path(tempfile.mkdtemp())
        c_file = temp_dir / "increment.c"
        c_file.write_text("""
            int increment(int a) {
                return a + 1;
            }
        """)

        # Wrong test cases
        test_cases = [
            ((5,), 7),  # Expected 6, will get 6
        ]

        # Should raise AssertionError
        with pytest.raises(AssertionError, match="Semantic equivalence check failed"):
            assert_semantic_equivalence(str(c_file), "increment", test_cases)

        # Cleanup
        c_file.unlink()
        temp_dir.rmdir()


class TestMixedDispatcherPattern:
    """Tests specifically for mixed_dispatcher_pattern to document expected behavior."""

    def test_mixed_dispatcher_pattern_values(self):
        """Test and document expected outputs for mixed_dispatcher_pattern.

        This test serves as documentation of the expected behavior and validates
        our understanding of the control flow.

        Expected behavior:
        - (10, 20): result=30, +10=40, result>100? NO, state=0x9ABCDEF0,
                    -1=39, 39<50? YES, exit → 39

        - (5, 5): result=10, +10=20, result>100? NO, state=0x9ABCDEF0,
                  -1=19, 19<50? YES, exit → 19

        - (0, 0): result=0, +10=10, result>100? NO, state=0x9ABCDEF0,
                  -1=9, 9<50? YES, exit → 9

        - (20, 20): result=40, +10=50, result>100? NO, state=0x9ABCDEF0,
                    -1=49, 49<50? YES, exit → 49

        Note: Inputs where (x+y+10) > 100 will enter the "heavy" path and may
        loop many times or infinitely depending on the specific values.
        We avoid such inputs in these tests.
        """
        # Find the source file
        tests_dir = pathlib.Path(__file__).parent.parent.parent
        project_root = tests_dir.parent
        c_source = project_root / "samples" / "src" / "c" / "dispatcher_patterns.c"

        if not c_source.exists():
            pytest.skip(f"Source file not found: {c_source}")

        # Test cases that take the "light" path (sum+10 <= 100)
        test_cases = [
            ((10, 20), 39),  # sum=30, +10=40, -1=39
            ((5, 5), 19),    # sum=10, +10=20, -1=19
            ((0, 0), 9),     # sum=0, +10=10, -1=9
            ((20, 20), 49),  # sum=40, +10=50, -1=49
            ((1, 1), 11),    # sum=2, +10=12, -1=11
        ]

        assert_semantic_equivalence(str(c_source), "mixed_dispatcher_pattern", test_cases)
