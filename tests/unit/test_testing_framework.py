"""Unit tests for d810.testing framework."""

import pytest

from d810.testing import DeobfuscationCase, BinaryOverride
from d810.testing.assertions import (
    assert_contains,
    assert_not_contains,
    assert_code_changed,
)


class TestDeobfuscationCase:
    """Tests for DeobfuscationCase dataclass."""

    def test_basic_creation(self):
        """Test basic case creation with minimal fields."""
        case = DeobfuscationCase(function="test_func")
        assert case.function == "test_func"
        assert case.project == "default_instruction_only.json"
        assert case.must_change is True
        assert case.check_stats is True

    def test_expected_code_dedent(self):
        """Test that expected_code is automatically dedented."""
        case = DeobfuscationCase(
            function="test_func",
            expected_code="""
                int foo() {
                    return 42;
                }
            """,
        )
        assert case.expected_code == "int foo() {\n    return 42;\n}"

    def test_test_id(self):
        """Test that test_id returns the function name."""
        case = DeobfuscationCase(function="my_test_function")
        assert case.test_id == "my_test_function"

    def test_full_case_creation(self):
        """Test case creation with all fields."""
        case = DeobfuscationCase(
            function="complex_test",
            project="custom_project.json",
            description="Test complex deobfuscation",
            obfuscated_contains=["0xDEADBEEF", "0xCAFEBABE"],
            obfuscated_not_contains=["simple"],
            expected_code="int foo() { return 1; }",
            acceptable_patterns=["return 1", "return 0x1"],
            deobfuscated_contains=["return"],
            deobfuscated_not_contains=["0xDEADBEEF"],
            required_rules=["Rule1", "Rule2"],
            expected_rules=["Rule3"],
            forbidden_rules=["BadRule"],
            must_change=True,
            check_stats=True,
            skip=None,
        )
        assert case.function == "complex_test"
        assert case.project == "custom_project.json"
        assert len(case.obfuscated_contains) == 2
        assert len(case.required_rules) == 2


class TestBinaryOverride:
    """Tests for BinaryOverride and get_effective_config."""

    def test_no_override_returns_same(self):
        """Test that no override returns the same config."""
        case = DeobfuscationCase(
            function="test_func",
            required_rules=["Rule1"],
        )
        effective = case.get_effective_config(".so")
        assert effective.function == "test_func"
        assert effective.required_rules == ["Rule1"]

    def test_dll_override_applied(self):
        """Test that .dll override is applied."""
        case = DeobfuscationCase(
            function="test_func",
            required_rules=["DefaultRule"],
            dll_override=BinaryOverride(
                required_rules=["DllRule"],
            ),
        )
        effective = case.get_effective_config(".dll")
        assert effective.required_rules == ["DllRule"]

    def test_dylib_override_applied(self):
        """Test that .dylib override is applied."""
        case = DeobfuscationCase(
            function="test_func",
            required_rules=["DefaultRule"],
            dylib_override=BinaryOverride(
                required_rules=["DylibRule"],
            ),
        )
        effective = case.get_effective_config(".dylib")
        assert effective.required_rules == ["DylibRule"]

    def test_override_preserves_unset_fields(self):
        """Test that override only changes specified fields."""
        case = DeobfuscationCase(
            function="test_func",
            project="original.json",
            obfuscated_contains=["pattern1"],
            required_rules=["Rule1"],
            dll_override=BinaryOverride(
                required_rules=["DllRule"],
                # obfuscated_contains not set, should preserve original
            ),
        )
        effective = case.get_effective_config(".dll")
        assert effective.project == "original.json"  # Preserved
        assert effective.obfuscated_contains == ["pattern1"]  # Preserved
        assert effective.required_rules == ["DllRule"]  # Overridden

    def test_override_skip(self):
        """Test that skip in override works."""
        case = DeobfuscationCase(
            function="test_func",
            dll_override=BinaryOverride(
                skip="DLL not supported",
            ),
        )
        effective = case.get_effective_config(".dll")
        assert effective.skip == "DLL not supported"


class TestAssertContains:
    """Tests for assert_contains."""

    def test_all_patterns_present(self):
        """Test success when all patterns are present."""
        code = "int foo() { return 0xDEADBEEF + 0xCAFEBABE; }"
        assert_contains(code, ["0xDEADBEEF", "0xCAFEBABE"])

    def test_missing_pattern_raises(self):
        """Test that missing pattern raises AssertionError."""
        code = "int foo() { return 42; }"
        with pytest.raises(AssertionError, match="Missing required patterns"):
            assert_contains(code, ["0xDEADBEEF"])

    def test_any_pattern_mode(self):
        """Test that any pattern mode works."""
        code = "int foo() { return 42; }"
        # Should not raise because all_required=False
        assert_contains(code, ["42", "0xDEAD"], all_required=False)

    def test_any_pattern_mode_none_found(self):
        """Test that any pattern mode raises when none found."""
        code = "int foo() { return 0; }"
        with pytest.raises(AssertionError, match="None of the expected patterns"):
            assert_contains(code, ["42", "0xDEAD"], all_required=False)

    def test_empty_patterns(self):
        """Test that empty pattern list does nothing."""
        code = "int foo() { return 42; }"
        assert_contains(code, [])  # Should not raise


class TestAssertNotContains:
    """Tests for assert_not_contains."""

    def test_no_forbidden_patterns(self):
        """Test success when no forbidden patterns present."""
        code = "int foo() { return 42; }"
        assert_not_contains(code, ["0xDEADBEEF", "0xCAFEBABE"])

    def test_forbidden_pattern_raises(self):
        """Test that forbidden pattern raises AssertionError."""
        code = "int foo() { return 0xDEADBEEF; }"
        with pytest.raises(AssertionError, match="Forbidden patterns found"):
            assert_not_contains(code, ["0xDEADBEEF"])

    def test_empty_patterns(self):
        """Test that empty pattern list does nothing."""
        code = "int foo() { return 0xDEADBEEF; }"
        assert_not_contains(code, [])  # Should not raise


class TestAssertCodeChanged:
    """Tests for assert_code_changed."""

    def test_code_changed(self):
        """Test success when code changed."""
        before = "int foo() { return 0xDEADBEEF + 0xCAFEBABE; }"
        after = "int foo() { return 42; }"
        assert_code_changed(before, after)  # Should not raise

    def test_code_unchanged_raises(self):
        """Test that unchanged code raises AssertionError."""
        code = "int foo() { return 42; }"
        with pytest.raises(AssertionError, match="did not change"):
            assert_code_changed(code, code)
