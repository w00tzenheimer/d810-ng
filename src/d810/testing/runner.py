"""Test runner for deobfuscation test cases.

This module provides the main entry point for running deobfuscation tests
defined as DeobfuscationCase dataclasses.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

import pytest

from .assertions import (
    assert_code_changed,
    assert_code_equivalent,
    assert_contains,
    assert_not_contains,
    assert_rules_fired,
)
from .cases import DeobfuscationCase

if TYPE_CHECKING:
    import idaapi


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix.

    Args:
        name: Function name (without leading underscore).

    Returns:
        The function's effective address, or BADADDR if not found.
    """
    import idaapi
    import idc

    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        # Try with macOS underscore prefix
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def get_binary_suffix() -> str:
    """Get the suffix of the current binary being analyzed.

    Returns:
        The file suffix (e.g., ".dll", ".dylib", ".so").
    """
    import idaapi

    input_file = idaapi.get_input_file_path()
    return Path(input_file).suffix if input_file else ""


def run_deobfuscation_test(
    case: DeobfuscationCase,
    d810_state: Callable,
    pseudocode_to_string: Callable,
    code_comparator: Optional[Any] = None,
    capture_stats: Optional[Callable] = None,
    load_expected_stats: Optional[Callable] = None,
    db_capture: Optional[Any] = None,
) -> None:
    """Run a deobfuscation test case.

    This is the main test runner that handles all the common patterns:
    1. Get function EA
    2. Decompile without d810 (check obfuscation patterns)
    3. Decompile with d810 (check deobfuscation)
    4. Verify code equivalence
    5. Check rule statistics

    Args:
        case: The test case specification.
        d810_state: Context manager fixture for D810 state.
        pseudocode_to_string: Function to convert pseudocode to string.
        code_comparator: Optional CodeComparator for AST comparison.
        capture_stats: Optional function to capture statistics.
        load_expected_stats: Optional function to load expected stats.
        db_capture: Optional database capture fixture.

    Raises:
        pytest.skip: If the test should be skipped.
        AssertionError: If any assertion fails.
    """
    import idaapi

    # Apply binary-specific overrides
    binary_suffix = get_binary_suffix()
    effective_case = case.get_effective_config(binary_suffix)

    # Handle skip
    if effective_case.skip:
        pytest.skip(effective_case.skip)

    # Get function address
    func_ea = get_func_ea(effective_case.function)
    if func_ea == idaapi.BADADDR:
        raise AssertionError(f"Function '{effective_case.function}' not found")

    # Validate code_comparator if expected_code is specified
    if effective_case.expected_code and code_comparator is None:
        raise AssertionError(
            "code_comparator fixture is required when expected_code is specified. "
            "Install libclang: pip install clang"
        )

    with d810_state() as state:
        # Configure project if specified
        if effective_case.project:
            # Load the project by name - get index and load
            project_index = state.project_manager.index(effective_case.project)
            state.load_project(project_index)

        # ==========================================
        # BEFORE: Decompile without d810 (obfuscated)
        # ==========================================
        state.stop_d810()
        decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        if decompiled_before is None:
            raise AssertionError(
                f"Decompilation failed for '{effective_case.function}'"
            )

        code_before = pseudocode_to_string(decompiled_before.get_pseudocode())

        # Assert obfuscation patterns are present
        if effective_case.obfuscated_contains:
            assert_contains(
                code_before,
                effective_case.obfuscated_contains,
                context="obfuscated code",
            )

        # Assert forbidden patterns are not present
        if effective_case.obfuscated_not_contains:
            assert_not_contains(
                code_before,
                effective_case.obfuscated_not_contains,
                context="obfuscated code",
            )

        # ==========================================
        # AFTER: Decompile with d810 (deobfuscated)
        # ==========================================
        state.start_d810()
        decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        if decompiled_after is None:
            raise AssertionError(
                f"Decompilation with d810 failed for '{effective_case.function}'"
            )

        code_after = pseudocode_to_string(decompiled_after.get_pseudocode())

        # Assert code changed (if required)
        if effective_case.must_change:
            assert_code_changed(code_before, code_after)

        # Assert deobfuscation patterns are present
        if effective_case.deobfuscated_contains:
            assert_contains(
                code_after,
                effective_case.deobfuscated_contains,
                context="deobfuscated code",
            )

        # Assert forbidden patterns are not present after deobfuscation
        if effective_case.deobfuscated_not_contains:
            assert_not_contains(
                code_after,
                effective_case.deobfuscated_not_contains,
                context="deobfuscated code",
            )

        # Check code equivalence if expected_code is specified
        if effective_case.expected_code:
            assert_code_equivalent(
                code_after,
                effective_case.expected_code,
                code_comparator,
                effective_case.acceptable_patterns,
            )
        elif effective_case.acceptable_patterns:
            # No exact expected code, but check patterns
            assert_contains(
                code_after,
                effective_case.acceptable_patterns,
                context="deobfuscated code",
                all_required=False,  # ANY pattern is acceptable
            )

        # ==========================================
        # STATS: Verify rule firing
        # ==========================================
        if effective_case.check_stats:
            # Check required/expected/forbidden rules
            if (
                effective_case.required_rules
                or effective_case.expected_rules
                or effective_case.forbidden_rules
            ):
                assert_rules_fired(
                    state.stats,
                    required_rules=effective_case.required_rules,
                    expected_rules=effective_case.expected_rules,
                    forbidden_rules=effective_case.forbidden_rules,
                    function_name=effective_case.function,
                )

            # Verify against expected stats file if available
            if capture_stats and load_expected_stats:
                capture_stats(state.stats)
                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected,
                        check_counts=False,
                        allow_extra_rules=True,
                    )

        # ==========================================
        # DATABASE CAPTURE: Record results if enabled
        # ==========================================
        if db_capture:
            db_capture.record(
                function_name=effective_case.function,
                code_before=code_before,
                code_after=code_after,
                stats=state.stats,
                passed=True,  # If we got here, test passed
                function_address=hex(func_ea) if func_ea else None,
            )


def create_parametrized_test(
    cases: list[DeobfuscationCase],
) -> Callable:
    """Create a parametrized test function for a list of cases.

    This is a helper for creating pytest-parametrized tests from case lists.

    Args:
        cases: List of test cases.

    Returns:
        A pytest.mark.parametrize decorator.

    Example::

        CASES = [DeobfuscationCase(...), ...]

        @create_parametrized_test(CASES)
        def test_deobfuscation(case, d810_state, ...):
            run_deobfuscation_test(case, d810_state, ...)
    """
    return pytest.mark.parametrize(
        "case",
        cases,
        ids=lambda c: c.test_id,
    )
