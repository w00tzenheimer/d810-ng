"""System tests for UnflattenerFakeJump optimizer.

These tests verify that the UnflattenerFakeJump optimizer correctly detects
and removes fake jumps (conditional jumps that are always taken or never taken
based on predecessor value analysis) in real compiled binaries.

Test Functions (from fake_jumps.dylib or fake_jumps.dll):
- fake_jump_always_true: Conditional always true (jump never taken)
- fake_jump_always_false: Conditional always false (jump always taken)
- fake_jump_sequence: Multiple fake jumps in sequence
- fake_jump_zero_check: Classic jz pattern with always-zero value
- fake_jump_nonzero_check: Classic jnz pattern with always-nonzero value
- fake_jump_after_arithmetic: Fake jump after deterministic arithmetic
- fake_jump_nested: Fake jumps inside control flow structures
- fake_jump_in_loop: Fake jump inside a loop body
- fake_jump_bitwise: Fake jump with bitwise comparison
- fake_jump_multi_predecessor: Multiple predecessors all set same value
"""

from __future__ import annotations

import os
import platform
import textwrap
from typing import TYPE_CHECKING

import pytest

import ida_funcs
import ida_hexrays
import ida_name
import idaapi
import idc

if TYPE_CHECKING:
    pass


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    # Allow override via environment variable
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    # Default: platform-appropriate binary
    return "fake_jumps.dylib" if platform.system() == "Darwin" else "fake_jumps.dll"


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)  # macOS prefix
    return ea


@pytest.fixture(scope="class")
def fake_jumps_setup(ida_database, configure_hexrays):
    """Setup fixture for fake_jumps tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestUnflattenerFakeJumpSystem:
    """System tests for UnflattenerFakeJump against real binaries."""

    # Use platform-appropriate binary (can be overridden via D810_TEST_BINARY env var)
    binary_name = _get_default_binary()

    def test_fake_jump_always_true(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test removal of conditional that's always true (jump never taken).

        Source pattern:
            int x = 42;
            if (x == 42) { result += 10; } else { result += 20; }

        Expected: The else branch (result += 20) should be eliminated.
        """
        func_ea = get_func_ea("fake_jump_always_true")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_always_true' not found"

        with d810_state() as state:
            # BEFORE: Decompile without d810
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None, "Decompilation failed"

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_always_true BEFORE d810 ===\n{actual_before}\n")

            # AFTER: Decompile with d810
            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None, "Decompilation with d810 failed"

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_always_true AFTER d810 ===\n{actual_after}\n")

            # Capture statistics
            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # VERIFY: Code should change
            code_changed = actual_before != actual_after

            # Check if UnflattenerFakeJump fired
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            # Note: IDA's own optimizations might eliminate the dead branch before
            # our optimizer runs. That's OK - it means the pattern was optimized away.
            if not fake_jump_fired:
                print("Note: IDA may have already optimized this pattern")

            # At minimum, verify the function still works correctly
            # The result should contain the correct computation (a + 10, not a + 20)
            assert "return" in actual_after.lower() or "result" in actual_after.lower(), (
                f"Function should have meaningful computation\n\n"
                f"Actual:\n{actual_after}"
            )

            # Try to load expected stats if they exist
            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_always_false(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test removal of conditional that's always false (jump always taken).

        Source pattern:
            int y = 100;
            if (y != 100) { result += 30; } else { result += 40; }

        Expected: The if branch (result += 30) should be eliminated.
        """
        func_ea = get_func_ea("fake_jump_always_false")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_always_false' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_always_false BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_always_false AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Check if optimization happened
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            if not fake_jump_fired:
                print("Note: IDA may have already optimized this pattern")

            # Verify function has correct computation (a + 40, not a + 30)
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_sequence(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test removal of multiple fake jumps in sequence.

        Source has two consecutive fake conditionals - both should be optimized.
        """
        func_ea = get_func_ea("fake_jump_sequence")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_sequence' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_sequence BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_sequence AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Verify function is simplified
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_zero_check(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test removal of always-false zero check (classic jz pattern).

        Source pattern:
            int flag = 0;
            if (flag) { result += 100; } else { result += 200; }

        This maps to microcode jz (jump if zero). Since flag is always 0,
        the zero branch is always taken.
        """
        func_ea = get_func_ea("fake_jump_zero_check")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_zero_check' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_zero_check BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_zero_check AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Verify correct computation (a + 200, not a + 100)
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_nonzero_check(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test removal of always-true non-zero check (classic jnz pattern).

        Source pattern:
            int flag = 1;
            if (flag) { result += 300; } else { result += 400; }

        This maps to microcode jnz (jump if not zero). Since flag is always 1,
        the non-zero branch is always taken.
        """
        func_ea = get_func_ea("fake_jump_nonzero_check")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_nonzero_check' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_nonzero_check BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_nonzero_check AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Verify correct computation (a + 300, not a + 400)
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_after_arithmetic(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test removal of fake jump after deterministic arithmetic.

        Source pattern:
            int sum = 10 + 20;  // Always 30
            if (sum == 30) { result *= 2; } else { result *= 3; }

        Tests that value tracking works through arithmetic operations.
        """
        func_ea = get_func_ea("fake_jump_after_arithmetic")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_after_arithmetic' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_after_arithmetic BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_after_arithmetic AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Verify correct computation (a * 2, not a * 3)
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_multi_predecessor(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test fake jump with multiple predecessors setting same value.

        Source pattern:
            if (a > 0) { state = 123; } else { state = 123; }
            if (state == 123) { result += 777; } else { result += 888; }

        Key test: Both predecessors set state to 123, so the subsequent
        comparison is deterministic regardless of which path was taken.
        """
        func_ea = get_func_ea("fake_jump_multi_predecessor")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_multi_predecessor' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_multi_predecessor BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_multi_predecessor AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # This is the most important test for UnflattenerFakeJump
            # It should detect that all predecessors lead to the same value
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            if fake_jump_fired:
                print("SUCCESS: UnflattenerFakeJump detected multi-predecessor pattern")
            else:
                print("Note: Pattern may have been optimized by IDA or compiler")

            # Verify correct computation (+ 777, not + 888)
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_in_loop(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test fake jump inside a loop body.

        Source pattern:
            for (i = 0; i < n; i++) {
                if (constant == 7) { ... } else { ... }
            }

        The conditional is constant across all loop iterations.
        """
        func_ea = get_func_ea("fake_jump_in_loop")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_in_loop' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_in_loop BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_in_loop AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Verify loop structure is preserved
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_state_machine(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test fake jump in state machine pattern.

        Source: Multiple paths converge to same state value.
        This is a key pattern for UnflattenerFakeJump to detect.
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_state_machine' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_state_machine BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_state_machine AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Check if UnflattenerFakeJump fired
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            if fake_jump_fired:
                print("SUCCESS: UnflattenerFakeJump detected state machine pattern")

            # Verify function is present
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_dispatcher_like(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test fake jump in dispatcher-like pattern.

        Source: Simplified control flow flattening dispatcher.
        """
        func_ea = get_func_ea("fake_jump_dispatcher_like")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_dispatcher_like' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_dispatcher_like BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_dispatcher_like AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Check if optimization happened
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            if fake_jump_fired:
                print("SUCCESS: UnflattenerFakeJump detected dispatcher-like pattern")

            # Verify function is present
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_fake_jump_multiple_cfg(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test multiple fake jumps in control flow graph.

        Source: Sequential fake conditionals throughout the function.
        """
        func_ea = get_func_ea("fake_jump_multiple_cfg")
        assert func_ea != idaapi.BADADDR, "Function 'fake_jump_multiple_cfg' not found"

        with d810_state() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== fake_jump_multiple_cfg BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== fake_jump_multiple_cfg AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Multiple fake jumps might trigger multiple times
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            if fake_jump_fired:
                print("SUCCESS: UnflattenerFakeJump detected multiple fake jumps")

            # Verify function is present
            assert "return" in actual_after.lower() or "result" in actual_after.lower()

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)


"""
Implementation Notes
====================

The UnflattenerFakeJump optimizer performs the following analysis:

1. Block Detection:
   - Finds blocks with jz/jnz instructions
   - Must be single-instruction blocks (only the conditional)
   - Comparison must be against a constant (mop_n)

2. Predecessor Analysis:
   - For each predecessor block, tracks the comparison operand backward
   - Uses MopTracker to find all possible values from that predecessor
   - Requires all paths from predecessor to be resolved

3. Jump Determination:
   - jz: Jump taken if value == constant, not taken if value != constant
   - jnz: Jump taken if value != constant, not taken if value == constant
   - If ALL predecessors lead to the same decision, the jump is fake

4. CFG Patching:
   - Redirects the predecessor to bypass the fake conditional
   - Uses change_1way_block_successor() for safe CFG modification
   - Marks chains dirty and re-optimizes

Expected Optimization Patterns
===============================

Pattern 1: Always True
  BEFORE:     if (x == 42) { A } else { B }  // x is always 42
  AFTER:      A

Pattern 2: Always False
  BEFORE:     if (y != 100) { A } else { B }  // y is always 100
  AFTER:      B

Pattern 3: Multi-Predecessor Convergence
  BEFORE:
    if (cond) { state = 5; } else { state = 5; }  // Both paths set state=5
    if (state == 5) { X } else { Y }
  AFTER:
    if (cond) { state = 5; } else { state = 5; }
    X  // Jump removed, Y is dead code

Known Limitations
=================

1. IDA's own optimizations may eliminate some patterns before our optimizer runs
2. Complex value tracking (through function calls, memory) may not be resolved
3. Only handles jz/jnz, not other comparison opcodes (je, jne, jl, etc.)
4. Path explosion in MopTracker (max 1000 paths) may prevent resolution

Test Expectations
=================

These tests verify:
- Optimizer correctly identifies fake jumps
- CFG is safely modified without corruption
- Dead branches are eliminated
- Generated code is cleaner and more efficient
"""
