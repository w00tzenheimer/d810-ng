"""Tests for buffer resize function with OLLVM CFF obfuscation.

This module tests the sub_7FFC1E9D3BB0_resize function which demonstrates:
- OLLVM Control-Flow Flattening (CFF) with nested while(1) loops
- Opaque constant table with MBA expressions for state transitions
- FoldReadonlyDataRule with fold_writable_constants configuration
- FixPredecessorOfConditionalJumpBlock for conditional chain dispatch
- GlobalConstantInliner for resolving opaque table loads

The function performs buffer resize/realloc operations with zero-fill,
obscured behind a complex state machine dispatcher.

To run:
    pytest tests/system/e2e/test_resize_buffer_cff.py -v

Incremental config isolation test:
    pytest tests/system/e2e/test_resize_buffer_cff.py::TestResizeBufferCFFIncremental -v -s
"""

import os
import platform

import pytest

import idaapi

from d810.testing.runner import run_deobfuscation_test, get_func_ea
from tests.system.cases.libobfuscated_comprehensive import RESIZE_BUFFER_CFF_CASES


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestResizeBufferCFF:
    """Tests for buffer resize with OLLVM CFF and opaque constant folding.

    This test validates the deobfuscation pipeline on a real-world pattern
    where control flow is flattened using opaque constants loaded from a
    volatile table. The deobfuscation must:

    1. Fold the opaque constant table accesses (FoldReadonlyDataRule)
    2. Resolve MBA expressions in state transitions
    3. Unpack the nested while(1)/if dispatcher (FixPredecessorOfConditionalJumpBlock)
    4. Restore linear control flow

    The underlying clean logic is a buffer resize with capacity check and zero-fill.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize("case", RESIZE_BUFFER_CFF_CASES, ids=lambda c: c.test_id)
    def test_resize_buffer_cff(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Test deobfuscation of buffer resize with OLLVM CFF and opaque constants."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestResizeBufferCFFIncremental:
    """Incremental config testing to isolate which rule causes decompile() -> None.

    Tests the sub_7FFC1E9D3BB0_resize function with progressively more complex
    d810 configurations to find the exact rule that corrupts the MBA.

    Configs tested (in order of complexity):
      1. No d810 (baseline obfuscated)
      2. default_instruction_only.json (MBA simplification, FoldReadonlyData)
      3. flatfold.json (everything including block rules + Unflattener)

    Run with:
        pytest tests/system/e2e/test_resize_buffer_cff.py::TestResizeBufferCFFIncremental -v -s
    """

    binary_name = _get_default_binary()
    FUNC_NAME = "sub_7FFC1E9D3BB0_resize"

    @staticmethod
    def _has_resize_opaque_markers(code: str) -> bool:
        """Backend-stable obfuscation markers for resize CFF function."""
        markers = (
            "g_resize_opaque_table",
            "0x3C837EFA",
            "0x7BE4032F",
            "0x7E069F35",
            "0x4DFE3D51",
        )
        return any(marker in code for marker in markers)

    def _get_func_ea(self):
        """Resolve the function EA, handling macOS underscore prefix."""
        ea = get_func_ea(self.FUNC_NAME)
        if ea == idaapi.BADADDR:
            pytest.skip(f"Function '{self.FUNC_NAME}' not found in binary")
        return ea

    def _try_decompile(self, func_ea):
        """Attempt decompilation, returning (code_str, success) tuple."""
        from tests.system.conftest import _pseudocode_to_string
        result = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        if result is None:
            return None, False
        code = _pseudocode_to_string(result.get_pseudocode())
        return code, True

    def _print_code_summary(self, label, code, max_lines=30):
        """Print a summary of decompiled code."""
        if code is None:
            print(f"\n{'='*60}")
            print(f"  {label}: decompile() returned None")
            print(f"{'='*60}")
            return
        lines = code.splitlines()
        print(f"\n{'='*60}")
        print(f"  {label}: {len(lines)} lines")
        print(f"{'='*60}")
        for line in lines[:max_lines]:
            print(f"  {line}")
        if len(lines) > max_lines:
            print(f"  ... ({len(lines) - max_lines} more lines)")

    def _print_stats_summary(self, state):
        """Print a summary of which rules fired."""
        stats = state.stats.to_dict()
        if not stats:
            print("  (no rules fired)")
            return
        for rule_name, count in sorted(stats.items()):
            if isinstance(count, (int, float)) and count > 0:
                print(f"    {rule_name}: {count}")

    @pytest.mark.ida_required
    def test_01_baseline_no_d810(self, libobfuscated_setup):
        """Step 1: Baseline decompilation without d810 (obfuscated output)."""
        func_ea = self._get_func_ea()
        code, success = self._try_decompile(func_ea)

        self._print_code_summary("BASELINE (no d810)", code)

        assert success, (
            f"Baseline decompilation (no d810) returned None for {self.FUNC_NAME}. "
            "This means IDA cannot decompile it at all."
        )
        # Verify we see obfuscation indicators
        assert self._has_resize_opaque_markers(code), (
            "Expected resize opaque-state markers not found in baseline"
        )

    @pytest.mark.ida_required
    def test_02_instruction_only(self, libobfuscated_setup, d810_state):
        """Step 2: Decompile with instruction-only config (no block rules).

        Uses default_instruction_only.json which has:
        - FoldReadonlyDataRule (folds opaque constant table reads)
        - MBA simplification rules (XOR, AND, OR, etc.)
        - Z3-based constant optimization
        - NO block rules (no Unflattener, no FixPredecessor, etc.)
        """
        func_ea = self._get_func_ea()

        with d810_state() as state:
            project_index = state.project_manager.index("default_instruction_only.json")
            state.load_project(project_index)
            state.start_d810()

            code, success = self._try_decompile(func_ea)

            self._print_code_summary("INSTRUCTION-ONLY (default_instruction_only.json)", code)

            if success:
                print("\n  Stats (rules that fired):")
                self._print_stats_summary(state)

                # Check if opaque table references are folded
                has_opaque_markers = self._has_resize_opaque_markers(code)
                print(f"\n  Opaque/CFF markers remaining: {has_opaque_markers}")
                if not has_opaque_markers:
                    print("  --> FoldReadonlyDataRule successfully resolved table lookups")
                else:
                    print("  --> Opaque table references NOT fully resolved")
            else:
                print("\n  FAILURE: instruction-only config caused decompile() -> None")

            state.stop_d810()

        assert success, (
            "Decompilation with instruction-only config returned None. "
            "This is unexpected since instruction-only rules should not corrupt MBA."
        )

    @pytest.mark.ida_required
    def test_03_flatfold_full(self, libobfuscated_setup, d810_state):
        """Step 3: Decompile with full flatfold.json config.

        Uses flatfold.json which adds block rules on top of instruction rules:
        - StackVariableConstantPropagationRule
        - UnflattenerSwitchCase
        - GlobalConstantInliner
        - JumpFixer (with CompareConstant, Jnz, Jae, Jb rules)
        - Unflattener
        - BadWhileLoop
        - FixPredecessorOfConditionalJumpBlock

        If this returns None but instruction-only works, the bug is in one of
        these block rules.
        """
        func_ea = self._get_func_ea()

        with d810_state() as state:
            project_index = state.project_manager.index("flatfold.json")
            state.load_project(project_index)
            state.start_d810()

            code, success = self._try_decompile(func_ea)

            self._print_code_summary("FLATFOLD (flatfold.json)", code)

            if success:
                print("\n  Stats (rules that fired):")
                self._print_stats_summary(state)

                has_opaque_markers = self._has_resize_opaque_markers(code)
                print(f"\n  Opaque/CFF markers remaining: {has_opaque_markers}")
            else:
                print("\n  FAILURE: flatfold config caused decompile() -> None")
                print("  Block rules are the cause -- isolate further with per-rule tests.")

            state.stop_d810()

        # This test is diagnostic -- we want to see the output either way.
        # Report pass/fail but do NOT assert so subsequent tests still run.
        if not success:
            pytest.xfail(
                "flatfold.json causes decompile() -> None. "
                "Block rules corrupt MBA for this function."
            )

    @pytest.mark.ida_required
    def test_04_isolate_block_rules(self, libobfuscated_setup, d810_state):
        """Step 4: Test each block rule individually to find which one corrupts MBA.

        Loads flatfold.json, then for each block rule:
        1. Clears current_blk_rules
        2. Adds only that single rule back
        3. Starts d810, decompiles, records result
        4. Stops d810

        Rules known to hang inside IDA's C decompiler (uninterruptible) are
        skipped and recorded as HANG_KNOWN. SIGALRM cannot interrupt native
        C extension calls, so we must skip these to avoid blocking the entire
        test suite.

        Prints a summary table showing which rules are safe vs which cause
        decompile() to return None or hang.
        """
        import time as _time

        from d810.expr.utils import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
        from d810.core import (
            MOP_CONSTANT_CACHE as CORE_MOP_CONSTANT_CACHE,
            MOP_TO_AST_CACHE as CORE_MOP_TO_AST_CACHE,
        )
        from d810.optimizers.microcode.flow.flattening.dispatcher_detection import DispatcherCache
        from d810.hexrays.tracker import MopTracker
        from d810.optimizers.microcode.flow.flattening import fix_pred_cond_jump_block

        # Rules known to cause infinite hangs inside idaapi.decompile() due to
        # MBA corruption (C-level, cannot be interrupted by SIGALRM).
        # See: DeferredGraphModifier.apply() safe_verify RuntimeError escaping
        # BlockOptimizerManager, causing corrupted MBA that IDA loops on.
        KNOWN_HANG_RULES = {"Unflattener"}

        func_ea = self._get_func_ea()

        results = []  # list of (rule_name, status_str, line_count_or_none, elapsed)

        with d810_state() as state:
            # Load flatfold to get all block rules configured
            project_index = state.project_manager.index("flatfold.json")
            state.load_project(project_index)

            # Save the full list of configured block rules
            all_blk_rules = list(state.current_blk_rules)
            print(f"\n  Found {len(all_blk_rules)} block rules to test individually:")
            for rule in all_blk_rules:
                skip_tag = " [WILL SKIP - known hang]" if rule.name in KNOWN_HANG_RULES else ""
                print(f"    - {rule.name}{skip_tag}")

            state.stop_d810()

            # Test each block rule in isolation
            for rule in all_blk_rules:
                if rule.name in KNOWN_HANG_RULES:
                    results.append((rule.name, "HANG_KNOWN", None, 0.0))
                    print(f"    [HANG_KNOWN - skipped] {rule.name}")
                    continue

                # Clear all caches to prevent cross-contamination
                MOP_CONSTANT_CACHE.clear()
                MOP_TO_AST_CACHE.clear()
                CORE_MOP_CONSTANT_CACHE.clear()
                CORE_MOP_TO_AST_CACHE.clear()
                DispatcherCache.clear_cache()
                MopTracker.reset()
                fix_pred_cond_jump_block.clear_cache()

                # Set only this one block rule
                state.current_blk_rules = [rule]

                state.start_d810()

                t0 = _time.perf_counter()
                code, success = self._try_decompile(func_ea)
                elapsed = _time.perf_counter() - t0

                state.stop_d810()

                if success:
                    line_count = len(code.splitlines())
                    results.append((rule.name, "OK", line_count, elapsed))
                    print(f"    [OK] {rule.name} ({line_count} lines, {elapsed:.2f}s)")
                else:
                    results.append((rule.name, "FAIL_NONE", None, elapsed))
                    print(f"    [FAIL (None)] {rule.name} ({elapsed:.2f}s)")

        # Print summary table
        print(f"\n{'='*70}")
        print(f"  BLOCK RULE ISOLATION SUMMARY for {self.FUNC_NAME}")
        print(f"{'='*70}")
        print(f"  {'Rule Name':<50} {'Result':<12} {'Lines':<6} {'Time'}")
        print(f"  {'-'*50} {'-'*12} {'-'*6} {'-'*6}")

        safe_rules = []
        corrupt_rules = []
        hang_rules = []
        for rule_name, status, line_count, elapsed in results:
            lines_str = str(line_count) if line_count else "N/A"
            time_str = f"{elapsed:.2f}s" if elapsed > 0 else "N/A"
            print(f"  {rule_name:<50} {status:<12} {lines_str:<6} {time_str}")
            if status == "OK":
                safe_rules.append(rule_name)
            elif status in ("HANG", "HANG_KNOWN"):
                hang_rules.append(rule_name)
            else:
                corrupt_rules.append(rule_name)

        print(f"\n  Safe rules ({len(safe_rules)}):")
        for name in safe_rules:
            print(f"    + {name}")
        print(f"\n  Corrupt rules - decompile() returned None ({len(corrupt_rules)}):")
        for name in corrupt_rules:
            print(f"    - {name}")
        print(f"\n  Hanging rules - decompile() hangs in C code ({len(hang_rules)}):")
        for name in hang_rules:
            print(f"    ! {name}")
        print(f"{'='*70}")

        # The test itself is diagnostic -- do not assert, just report
        bad_rules = corrupt_rules + hang_rules
        if bad_rules:
            pytest.xfail(
                f"Block rules causing decompile() failure: "
                f"None={corrupt_rules}, Hang={hang_rules}"
            )

    @pytest.mark.ida_required
    def test_05_fixpred_output(self, libobfuscated_setup, d810_state):
        """Step 5: Print FULL decompiled output with only FixPredecessorOfConditionalJumpBlock.

        Loads flatfold.json, clears all block rules, adds back ONLY
        FixPredecessorOfConditionalJumpBlock, then decompiles and prints
        the entire pseudocode output for inspection.
        """
        from d810.expr.utils import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
        from d810.core import (
            MOP_CONSTANT_CACHE as CORE_MOP_CONSTANT_CACHE,
            MOP_TO_AST_CACHE as CORE_MOP_TO_AST_CACHE,
        )
        from d810.optimizers.microcode.flow.flattening.dispatcher_detection import DispatcherCache
        from d810.hexrays.tracker import MopTracker
        from d810.optimizers.microcode.flow.flattening import fix_pred_cond_jump_block

        func_ea = self._get_func_ea()

        with d810_state() as state:
            # Load flatfold to get all rules configured
            project_index = state.project_manager.index("flatfold.json")
            state.load_project(project_index)

            # Save original block rules, then find FixPredecessorOfConditionalJumpBlock
            all_blk_rules = list(state.current_blk_rules)
            fixpred_rule = None
            for rule in all_blk_rules:
                if rule.name == "FixPredecessorOfConditionalJumpBlock":
                    fixpred_rule = rule
                    break

            if fixpred_rule is None:
                pytest.skip("FixPredecessorOfConditionalJumpBlock not found in flatfold.json")

            # Clear all caches
            MOP_CONSTANT_CACHE.clear()
            MOP_TO_AST_CACHE.clear()
            CORE_MOP_CONSTANT_CACHE.clear()
            CORE_MOP_TO_AST_CACHE.clear()
            DispatcherCache.clear_cache()
            MopTracker.reset()
            fix_pred_cond_jump_block.clear_cache()

            # Set ONLY FixPredecessorOfConditionalJumpBlock as the active block rule
            state.current_blk_rules = [fixpred_rule]
            print(f"\n  Block rules active: {[r.name for r in state.current_blk_rules]}")
            print(f"  Instruction rules active: {len(state.current_ins_rules)}")

            state.start_d810()

            code, success = self._try_decompile(func_ea)

            # Print FULL decompiled output (no truncation)
            if code is not None:
                lines = code.splitlines()
                print(f"\n{'='*70}")
                print(f"  FIXPRED-ONLY OUTPUT: {len(lines)} lines")
                print(f"{'='*70}")
                for line in lines:
                    print(f"  {line}")
                print(f"{'='*70}")

                print("\n  Stats (rules that fired):")
                self._print_stats_summary(state)
            else:
                print(f"\n{'='*70}")
                print(f"  FIXPRED-ONLY: decompile() returned None")
                print(f"{'='*70}")

            state.stop_d810()

        assert code is not None, (
            "decompile() returned None with only FixPredecessorOfConditionalJumpBlock active"
        )
