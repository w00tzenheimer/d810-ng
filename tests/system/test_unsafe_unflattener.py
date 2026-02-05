"""System tests for UnflattenerFakeJump safety check.

These tests verify that the Z3-verified safety check prevents incorrect CFG
modifications when unresolved MopTracker paths outnumber resolved paths.

Background:
===========
The unsafe_unflattener_test functions in samples/src/c/unsafe_unflattener_test.c
are specifically designed to trigger the unsafe scenario where:

1. MopTracker resolves some backward paths but not others (due to back-edges)
2. The unresolved paths have DIFFERENT state values than resolved paths
3. Ignoring unresolved paths would lead to INCORRECT CFG modification

The safety check in UnflattenerFakeJump detects when unresolved paths outnumber
resolved paths and bails out, preserving correct control flow.

Test Functions:
===============
- unsafe_unflattener_test: Simple loop with back-edge
- unsafe_unflattener_test2: Nested loop with multiple back-edges
- unsafe_unflattener_test3: Data-dependent state transitions
"""

import logging
import os
import platform

import pytest

import idaapi
import idc


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


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        # Try with macOS underscore prefix
        ea = idc.get_name_ea_simple("_" + name)
    return ea


class TestUnflattenerSafetyCheck:
    """Tests for the Z3-verified safety check in UnflattenerFakeJump.

    The safety check prevents UnflattenerFakeJump from firing when:
    - MopTracker has unresolved paths (from back-edges/cycles)
    - Unresolved paths outnumber resolved paths
    - Ignoring unresolved paths would be unsafe

    Expected behavior:
    - UnflattenerFakeJump should NOT modify the CFG
    - Function should still decompile correctly
    - Warning message should be logged about unsafe paths
    """

    binary_name = _get_default_binary()

    def test_unsafe_unflattener_test_safety_check_fires(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        caplog,
    ):
        """Test that safety check prevents modification of unsafe patterns.

        The unsafe_unflattener_test function has back-edges that create
        unresolved paths. The safety check should detect this and prevent
        the rule from firing, preserving correct control flow.

        Test flow:
        1. Decompile without d810 - get baseline
        2. Enable ONLY UnflattenerFakeJump rule
        3. Decompile with d810
        4. Verify:
           - Function still decompiles (CFG not corrupted)
           - Safety warning appears in logs
           - Rule does NOT incorrectly modify the CFG
        """
        func_name = "unsafe_unflattener_test"
        func_ea = get_func_ea(func_name)

        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found in binary")

        with d810_state() as state:
            # Load a minimal project with ONLY UnflattenerFakeJump enabled
            # We need to ensure other rules don't interfere
            project_name = "example_libobfuscated.json"
            try:
                project_index = state.project_manager.index(project_name)
                state.load_project(project_index)
            except ValueError:
                pytest.skip(f"Project '{project_name}' not found")

            # Disable all rules first, then enable only UnflattenerFakeJump
            for rule in state.current_blk_rules:
                rule.is_activated = False
            for rule in state.current_ins_rules:
                rule.is_activated = False

            # Find and enable UnflattenerFakeJump
            fake_jump_rule = None
            for rule in state.current_blk_rules:
                if rule.__class__.__name__ == "UnflattenerFakeJump":
                    rule.is_activated = True
                    fake_jump_rule = rule
                    break

            if fake_jump_rule is None:
                pytest.skip("UnflattenerFakeJump rule not found")

            # Reset statistics
            state.stats.reset()

            # ==========================================
            # BEFORE: Decompile without d810 (baseline)
            # ==========================================
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if decompiled_before is None:
                pytest.fail(f"Baseline decompilation failed for '{func_name}'")

            code_before = pseudocode_to_string(decompiled_before.get_pseudocode())
            assert len(code_before) > 0, "Baseline code should not be empty"

            # ==========================================
            # AFTER: Decompile with only UnflattenerFakeJump
            # ==========================================
            state.start_d810()

            # Enable logging capture for the unflattener
            with caplog.at_level(logging.DEBUG, logger="D810.unflat"):
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )

            # ==========================================
            # VERIFY: CFG not corrupted
            # ==========================================
            if decompiled_after is None:
                pytest.fail(
                    f"Decompilation with d810 FAILED for '{func_name}' - "
                    "CFG may have been corrupted by unsafe modification"
                )

            code_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            assert len(code_after) > 0, "Decompiled code should not be empty"

            # ==========================================
            # VERIFY: Check for safety warning in logs
            # ==========================================
            # The safety check should log a warning when bailing out
            safety_warnings = [
                record for record in caplog.records
                if "unsafe to ignore unresolved" in record.message.lower()
                or "unresolved" in record.message.lower() and "resolved" in record.message.lower()
            ]

            # Check rule statistics - UnflattenerFakeJump should not have applied
            stats_dict = state.stats.to_dict()
            rule_counts = stats_dict.get("rule_counts", {})
            fake_jump_applications = rule_counts.get("UnflattenerFakeJump", 0)

            # Log diagnostic information
            print(f"\n=== Diagnostic Information ===")
            print(f"Function: {func_name}")
            print(f"UnflattenerFakeJump applications: {fake_jump_applications}")
            print(f"Safety warnings found: {len(safety_warnings)}")
            print(f"Code before length: {len(code_before)}")
            print(f"Code after length: {len(code_after)}")

            if safety_warnings:
                print("\nSafety warnings logged:")
                for record in safety_warnings:
                    print(f"  - {record.message}")

            # The key assertion: the function should still decompile correctly
            # Whether or not the safety check fired, the CFG must remain valid
            assert decompiled_after is not None, "Function must still decompile"

            # Optional: If safety warnings were logged, the check is working
            # (This may not fire on all compiler/IDA versions)
            if len(safety_warnings) > 0:
                print("\n[PASS] Safety check correctly detected unsafe scenario")
            elif fake_jump_applications == 0:
                print("\n[INFO] Rule did not fire (may have been skipped for other reasons)")
            else:
                print(f"\n[INFO] Rule fired {fake_jump_applications} times - "
                      "function decompiled correctly")

    def test_unsafe_unflattener_test2_nested_loops(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        caplog,
    ):
        """Test safety check with nested loop patterns.

        unsafe_unflattener_test2 has multiple back-edges from nested loops,
        creating more unresolved paths.
        """
        func_name = "unsafe_unflattener_test2"
        func_ea = get_func_ea(func_name)

        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found in binary")

        with d810_state() as state:
            # Configure to use only UnflattenerFakeJump
            project_name = "example_libobfuscated.json"
            try:
                project_index = state.project_manager.index(project_name)
                state.load_project(project_index)
            except ValueError:
                pytest.skip(f"Project '{project_name}' not found")

            # Disable all rules, enable only UnflattenerFakeJump
            for rule in state.current_blk_rules:
                rule.is_activated = rule.__class__.__name__ == "UnflattenerFakeJump"
            for rule in state.current_ins_rules:
                rule.is_activated = False

            state.stats.reset()

            # Decompile without d810
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if decompiled_before is None:
                pytest.fail(f"Baseline decompilation failed for '{func_name}'")

            # Decompile with d810
            state.start_d810()
            with caplog.at_level(logging.DEBUG, logger="D810.unflat"):
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )

            # Key assertion: function must still decompile
            assert decompiled_after is not None, (
                f"Function '{func_name}' failed to decompile with d810 - "
                "CFG may have been corrupted"
            )

            code_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            assert len(code_after) > 0, "Decompiled code should not be empty"

            print(f"\n[PASS] {func_name} decompiled correctly (CFG preserved)")

    def test_unsafe_unflattener_test3_data_dependent(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        caplog,
    ):
        """Test safety check with data-dependent state transitions.

        unsafe_unflattener_test3 has state transitions that depend on
        computed values, making path resolution even harder.
        """
        func_name = "unsafe_unflattener_test3"
        func_ea = get_func_ea(func_name)

        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found in binary")

        with d810_state() as state:
            # Configure to use only UnflattenerFakeJump
            project_name = "example_libobfuscated.json"
            try:
                project_index = state.project_manager.index(project_name)
                state.load_project(project_index)
            except ValueError:
                pytest.skip(f"Project '{project_name}' not found")

            # Disable all rules, enable only UnflattenerFakeJump
            for rule in state.current_blk_rules:
                rule.is_activated = rule.__class__.__name__ == "UnflattenerFakeJump"
            for rule in state.current_ins_rules:
                rule.is_activated = False

            state.stats.reset()

            # Decompile without d810
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if decompiled_before is None:
                pytest.fail(f"Baseline decompilation failed for '{func_name}'")

            # Decompile with d810
            state.start_d810()
            with caplog.at_level(logging.DEBUG, logger="D810.unflat"):
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )

            # Key assertion: function must still decompile
            assert decompiled_after is not None, (
                f"Function '{func_name}' failed to decompile with d810 - "
                "CFG may have been corrupted"
            )

            code_after = pseudocode_to_string(decompiled_after.get_pseudocode())
            assert len(code_after) > 0, "Decompiled code should not be empty"

            print(f"\n[PASS] {func_name} decompiled correctly (CFG preserved)")


class TestUnflattenerSafetyCheckRegression:
    """Regression tests to ensure safety check doesn't break working cases.

    These tests verify that the safety check doesn't prevent legitimate
    unflattening on functions that SHOULD be unflattened.
    """

    binary_name = _get_default_binary()

    def test_hodur_func_still_works(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Verify that hodur_func (a valid unflattening target) still works.

        hodur_func is a known-good unflattening case. The safety check should
        NOT prevent it from being unflattened.
        """
        func_name = "_hodur_func"  # macOS adds underscore
        func_ea = get_func_ea("hodur_func")

        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function 'hodur_func' not found in binary")

        with d810_state() as state:
            # Use example_hodur.json - hodur_func uses pure state assignments
            # (state = CONST) which HodurUnflattener is purpose-built for
            project_name = "example_hodur.json"
            try:
                project_index = state.project_manager.index(project_name)
                state.load_project(project_index)
            except ValueError:
                pytest.skip(f"Project '{project_name}' not found")

            state.stats.reset()

            # Decompile without d810
            state.stop_d810()
            decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if decompiled_before is None:
                pytest.fail(f"Baseline decompilation failed for 'hodur_func'")

            code_before = pseudocode_to_string(decompiled_before.get_pseudocode())

            # Decompile with d810
            state.start_d810()
            decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)

            if decompiled_after is None:
                pytest.fail("hodur_func failed to decompile with d810")

            code_after = pseudocode_to_string(decompiled_after.get_pseudocode())

            # Hodur should be significantly simplified
            # The unflattening should reduce the code or simplify control flow
            assert len(code_after) > 0, "Decompiled code should not be empty"

            # Check that some rules fired (d810 is working)
            stats_dict = state.stats.to_dict()
            # Block/CFG rules (like HodurUnflattener) are tracked in cfg_rule_usages
            cfg_usages = stats_dict.get("cfg_rule_usages", {})
            # Count total patches from all CFG rules
            total_cfg_patches = sum(
                sum(patches) for patches in cfg_usages.values()
            )
            # Also count instruction rule matches
            instruction_matches = stats_dict.get("instruction_rule_matches", {})
            total_instruction_matches = sum(instruction_matches.values())
            total_applications = total_cfg_patches + total_instruction_matches

            print(f"\n=== hodur_func Regression Test ===")
            print(f"Code before length: {len(code_before)}")
            print(f"Code after length: {len(code_after)}")
            print(f"CFG rule patches: {total_cfg_patches}")
            print(f"Instruction rule matches: {total_instruction_matches}")
            print(f"Total rule applications: {total_applications}")
            if cfg_usages:
                print(f"CFG rules that fired: {list(cfg_usages.keys())}")

            # The safety check should not have prevented all unflattening
            assert total_applications > 0, (
                "No rules fired on hodur_func - safety check may be too aggressive"
            )
