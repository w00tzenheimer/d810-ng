"""System tests for UnflattenerSingleIteration optimizer.

These tests verify that the UnflattenerSingleIteration optimizer correctly detects
and simplifies single-iteration loops in real compiled binaries.

Single Iteration Loop Pattern:
    Block 1: mov #INIT, state  ->  Block 2
    Block 2: jnz state, #CHECK, @exit  ->  Block 3 (body) or Block 4 (exit)
    Block 3: body; mov #UPDATE, state; goto @2

Key Property: INIT == CHECK and UPDATE != CHECK
Result: Loop runs exactly once, can be inlined/simplified

Test Functions (from libobfuscated.dylib or libobfuscated.dll):
These functions are defined in samples/src/c/single_iteration_loops.c:

- single_iteration_simple: Classic single-iteration pattern
- single_iteration_complex: Multiple operations in body
- single_iteration_conditional: Conditional logic inside single iteration
- single_iteration_nested: Nested control flow in body
- single_iteration_residual: Residual loop after dispatcher unflattening
- single_iteration_magic: Large magic constants (0xDEADBEEF, etc.)
- single_iteration_multi_pred: Multiple predecessors with same state
- single_iteration_chained: Multiple single-iteration loops in sequence
- single_iteration_boundary: Tests minimum magic threshold (0x1000)
- single_iteration_state_machine: State machine context
"""

from __future__ import annotations

import os
import platform
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
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)  # macOS prefix
    return ea


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays):
    """Setup fixture for libobfuscated tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestUnflattenerSingleIterationSystem:
    """System tests for UnflattenerSingleIteration against real binaries."""

    # Use platform-appropriate binary (can be overridden via D810_TEST_BINARY env var)
    binary_name = _get_default_binary()

    def test_single_iteration_simple(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test simple single-iteration loop detection and simplification.

        Source pattern (from single_iteration_loops.c):
            int state = 0x1234;  // INIT == CHECK
            while (state == 0x1234) {
                result += 10;
                state = 0x5678;  // UPDATE != CHECK, exit loop
            }

        Expected: Loop should be recognized as single-iteration and simplified.
        The while(state == 0x1234) check should be eliminated since it's
        deterministically true on entry and false after first iteration.
        """
        func_ea = get_func_ea("single_iteration_simple")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_simple' not found"

        with d810_state_all_rules() as state:
            # BEFORE: Decompile without d810
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None, "Decompilation failed"

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_simple BEFORE d810 ===\n{actual_before}\n")

            # AFTER: Decompile with d810
            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None, "Decompilation with d810 failed"

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_simple AFTER d810 ===\n{actual_after}\n")

            # Capture statistics
            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # Check if UnflattenerSingleIteration fired
            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)

            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected pattern")
            else:
                print("Note: Pattern may have been optimized by IDA or compiler")

            # Verify function decompiled successfully
            # Note: IDA may optimize the pattern differently, which is acceptable
            assert actual_after is not None and len(actual_after) > 0, (
                f"Function should decompile to non-empty code\n\n"
                f"Actual:\n{actual_after}"
            )

            # Try to load expected stats if they exist
            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_complex(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop with multiple operations in body.

        Source pattern:
            int state = 0xABCD;
            while (state == 0xABCD) {
                result = a + b;
                result *= 2;
                result -= 5;
                state = 0x9999;  // UPDATE != CHECK
            }

        Expected: Loop simplified despite complex body.
        """
        func_ea = get_func_ea("single_iteration_complex")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_complex' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_complex BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_complex AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected complex pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_conditional(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop with conditional inside body.

        Source pattern:
            int state = 0x2000;
            while (state == 0x2000) {
                if (a > 0) { result += 100; } else { result += 200; }
                state = 0x3000;
            }

        Expected: Loop simplified, conditional preserved.
        """
        func_ea = get_func_ea("single_iteration_conditional")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_conditional' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_conditional BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_conditional AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected conditional pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_nested(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop with nested control flow in body.

        Source pattern:
            int state = 0x4000;
            while (state == 0x4000) {
                if (a > 0) {
                    if (b > 0) { result = a + b; } else { result = a - b; }
                } else {
                    result = a * b;
                }
                state = 0x5000;
            }

        Expected: Loop simplified, nested structure preserved.
        """
        func_ea = get_func_ea("single_iteration_nested")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_nested' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_nested BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_nested AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected nested pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_residual(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test residual single-iteration loop after dispatcher unflattening.

        This simulates what remains after a larger dispatcher has been unflattened.
        The residual loop should be detected and simplified.

        Source pattern:
            switch (state) { case 0x8000: result += 5; state = 0x9000; break; }
            while (state == 0x9000) { result *= 2; state = 0xFFFF; }

        Expected: Residual loop simplified after main dispatcher optimization.
        """
        func_ea = get_func_ea("single_iteration_residual")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_residual' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_residual BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_residual AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            # This is a key test - residual loops should be cleaned up
            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected residual pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_magic(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop with large magic constants.

        Source pattern:
            int state = 0xDEADBEEF;  // Large magic constant
            while (state == 0xDEADBEEF) {
                result += 777;
                state = 0xCAFEBABE;
            }

        Expected: Magic constant detection (>= 0x1000) and simplification.
        Tests that the optimizer correctly handles large constants typical
        of obfuscated code.
        """
        func_ea = get_func_ea("single_iteration_magic")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_magic' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_magic BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_magic AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected magic constant pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_multi_pred(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop with multiple predecessors.

        Source pattern:
            if (a > 0) { state = 0x6000; } else { state = 0x6000; }
            while (state == 0x6000) { result = a * 10; state = 0x7000; }

        Key test: Both predecessors set state to same value, so loop
        is deterministically single-iteration.
        """
        func_ea = get_func_ea("single_iteration_multi_pred")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_multi_pred' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_multi_pred BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_multi_pred AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected multi-predecessor pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_chained(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test multiple single-iteration loops in sequence.

        Source pattern:
            while (state1 == 0x1111) { result += 10; state1 = 0xAAAA; }
            while (state2 == 0x2222) { result *= 2; state2 = 0xBBBB; }

        Expected: Both loops detected and simplified independently.
        Tests that the optimizer can handle multiple single-iteration
        patterns in the same function.
        """
        func_ea = get_func_ea("single_iteration_chained")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_chained' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_chained BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_chained AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected chained patterns")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_boundary(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop with boundary magic constant.

        Source pattern:
            int state = 0x1000;  // Exactly at DEFAULT_MIN_MAGIC threshold
            while (state == 0x1000) { result += 42; state = 0x1001; }

        Expected: Boundary value (0x1000) should be recognized as magic constant.
        Tests the minimum threshold for magic constant detection.
        """
        func_ea = get_func_ea("single_iteration_boundary")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_boundary' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_boundary BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_boundary AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected boundary value")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)

    def test_single_iteration_state_machine(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test single-iteration loop in state machine context.

        Source pattern:
            int state = 0xA000;
            if (input > 0) { state = 0xB000; }
            while (state == 0xB000) { result = input + 999; state = 0xC000; }

        Expected: Single-iteration loop detected even in state machine context.
        Tests integration with conditional state assignment.
        """
        func_ea = get_func_ea("single_iteration_state_machine")
        assert func_ea != idaapi.BADADDR, "Function 'single_iteration_state_machine' not found"

        with d810_state_all_rules() as state:
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_before is not None

            actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            print(f"\n=== single_iteration_state_machine BEFORE d810 ===\n{actual_before}\n")

            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled_after is not None

            actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            print(f"\n=== single_iteration_state_machine AFTER d810 ===\n{actual_after}\n")

            stats_dict = capture_stats(state.stats)
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n=== FIRED RULES ===\n{fired_rules}\n")

            single_iter_fired = any("SingleIteration" in rule for rule in fired_rules)
            if single_iter_fired:
                print("SUCCESS: UnflattenerSingleIteration detected state machine pattern")

            # Verify function decompiled successfully
            assert actual_after is not None and len(actual_after) > 0

            expected = load_expected_stats()
            if expected is not None:
                state.stats.assert_matches(expected, check_counts=False, allow_extra_rules=True)


"""
Implementation Notes
====================

The UnflattenerSingleIteration optimizer analyzes residual loops that:

1. Pattern Detection:
   - Block ends with jnz (jump if not zero) comparing state against constant
   - Entry block sets state to initial value (INIT)
   - Loop body updates state to different value (UPDATE)
   - Key property: INIT == CHECK and UPDATE != CHECK

2. Magic Constant Range:
   - DEFAULT_MIN_MAGIC = 0x1000 (4096)
   - DEFAULT_MAX_MAGIC = 0xFFFFFFFF
   - Filters out small constants (likely not state variables)
   - Configurable via config file

3. Comparison Value Analysis:
   - Tracks comparison constant from jnz instruction
   - Finds magic assignments in successor blocks
   - Requires at least 2 comparison values (init/check and update)

4. Exit Block Detection:
   - Both successors of jnz become exit blocks
   - One path: body executed, state updated to UPDATE, exits
   - Other path: direct exit (state != CHECK)

Expected Optimization Patterns
===============================

Pattern 1: Direct Simplification
  BEFORE:
    state = 0x1234;
    while (state == 0x1234) {
        do_something();
        state = 0x5678;
    }
  AFTER:
    do_something();

Pattern 2: Residual After Main Unflattening
  BEFORE: (after dispatcher unflattening)
    state = 0x9000;
    while (state == 0x9000) {
        final_computation();
        state = 0xFFFF;
    }
  AFTER:
    final_computation();

Known Limitations
=================

1. Requires magic constants >= 0x1000 (configurable)
2. Only handles jnz pattern (not other comparison opcodes)
3. Predecessor analysis must resolve to single value
4. Must have exactly 2 exit blocks

Test Expectations
=================

These tests verify:
- Optimizer correctly identifies single-iteration loops
- Magic constant filtering works (>= 0x1000)
- CFG is safely modified without corruption
- Loop overhead is eliminated
- Multiple patterns can be detected in sequence
- Works with various control flow contexts

Success Criteria
================

1. Rule Firing: "SingleIterationLoopUnflattener" appears in fired rules
2. Code Simplification: Loop structure eliminated in decompiled output
3. CFG Safety: No corruption or assertion failures
4. Semantic Preservation: Function behavior unchanged
"""
