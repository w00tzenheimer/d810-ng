"""Characterization tests for GenericDispatcherUnflatteningRule.

These tests capture the current behavior of the control flow unflattening
logic as ground truth, enabling safe refactoring of the monolithic rule
without functional regression.

Test Categories:
================
1. ABC Pattern Tests - XOR/OR-based state dispatch patterns
2. Nested Dispatcher Tests - Sub-dispatcher detection and removal
3. Exception Path Tests - Edge cases and exception handling paths

Running these tests:
    pytest tests/system/test_unflattening_characterization.py -v

Capturing expectations (run once to establish baseline):
    pytest tests/system/test_unflattening_characterization.py --capture-stats
"""

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


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)  # macOS prefix
    return ea


@pytest.fixture(scope="class")
def libobfuscated_test_setup(
    ida_database, configure_hexrays, setup_libobfuscated_test_funcs
):
    """Setup fixture for libobfuscated_test tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestABCPatternCharacterization:
    """Characterization tests for ABC (Arithmetic/Bitwise/Constant) pattern handling.

    These tests exercise the father_patcher_abc_from_or_xor_* methods in
    GenericDispatcherUnflatteningRule.
    """

    binary_name = _get_default_binary()

    def test_abc_xor_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test XOR-based state dispatch pattern.

        Tests father_patcher_abc_from_or_xor_v1:
        - State transitions use: state = state ^ CONSTANT
        - Dispatcher uses: switch ((state ^ KEY) & MASK)
        """
        func_ea = get_func_ea("abc_xor_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_xor_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None, "Decompilation failed"

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                # Verify flattened pattern is present
                has_switch = "switch" in actual_before
                has_xor = "^" in actual_before
                assert (
                    has_switch or has_xor
                ), "Should have switch or XOR pattern before d810"

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None, "Decompilation with d810 failed"

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                # Capture characterization stats
                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_xor_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )
                print(f"[CHARACTERIZATION] Before:\n{actual_before[:500]}...")
                print(f"[CHARACTERIZATION] After:\n{actual_after[:500]}...")

                # Load and verify expectations if available
                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_or_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test OR-based state manipulation pattern.

        Tests father_patcher_abc_from_or_xor_v2/v3:
        - State transitions use: state = (state & ~mask) | value
        """
        func_ea = get_func_ea("abc_or_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_or_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_or_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_mixed_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test combined XOR/OR state manipulation pattern."""
        func_ea = get_func_ea("abc_mixed_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_mixed_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_mixed_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )


class TestNestedDispatcherCharacterization:
    """Characterization tests for nested dispatcher handling.

    These tests exercise:
    - is_sub_dispatcher() detection
    - remove_sub_dispatchers() filtering
    - get_shared_internal_blocks() identification
    """

    binary_name = _get_default_binary()

    def test_nested_simple(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test simple nested dispatcher (2 levels).

        Outer dispatcher controls overall flow, inner dispatcher handles
        a specific processing phase.
        """
        func_ea = get_func_ea("nested_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'nested_simple' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                # Count switch statements before
                switch_count_before = actual_before.count("switch")

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())
                switch_count_after = actual_after.count("switch")

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] nested_simple: switches {switch_count_before} -> {switch_count_after}"
                )
                print(
                    f"[CHARACTERIZATION] rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_nested_deep(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test deeply nested dispatchers (3 levels).

        L1 -> L2 -> L3 dispatch chains.
        """
        func_ea = get_func_ea("nested_deep")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'nested_deep' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] nested_deep rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_nested_parallel(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test parallel nested dispatchers (sibling dispatchers at same level)."""
        func_ea = get_func_ea("nested_parallel")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'nested_parallel' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] nested_parallel rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_nested_shared_blocks(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test dispatcher with shared internal blocks.

        Tests get_shared_internal_blocks() - multiple dispatchers share
        some internal processing blocks.
        """
        func_ea = get_func_ea("nested_shared_blocks")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'nested_shared_blocks' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] nested_shared_blocks rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )


class TestABCF6ConstantsCharacterization:
    """Characterization tests for ABC magic number range (0xF6xxx / 1010000-1011999).

    These tests exercise the father_patcher_abc_* code path in
    GenericDispatcherUnflatteningRule that handles constants in the specific range:
    - Magic constant range: 1010000-1011999 (decimal) = 0xF6950-0xF719F (hex)
    - Checks: cnst > 1010000 && cnst < 1011999

    See: src/d810/optimizers/microcode/flow/flattening/generic.py:919
    """

    binary_name = _get_default_binary()

    def test_abc_f6_add_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test ADD-based state dispatch with 0xF6xxx/101xxxx constants.

        Tests father_patcher_abc_extract_mop for m_add opcode.
        """
        func_ea = get_func_ea("abc_f6_add_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_f6_add_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None, "Decompilation failed"

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None, "Decompilation with d810 failed"

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_f6_add_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )
                print(f"[CHARACTERIZATION] Before:\n{actual_before[:500]}...")
                print(f"[CHARACTERIZATION] After:\n{actual_after[:500]}...")

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_f6_sub_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test SUB-based state dispatch with 0xF6xxx constants.

        Tests father_patcher_abc_extract_mop for m_sub opcode.
        """
        func_ea = get_func_ea("abc_f6_sub_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_f6_sub_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_f6_sub_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_f6_xor_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test XOR-based state dispatch with 0xF6xxx constants.

        Tests father_patcher_abc_extract_mop for m_xor opcode.
        """
        func_ea = get_func_ea("abc_f6_xor_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_f6_xor_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_f6_xor_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_f6_or_dispatch(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test OR-based state dispatch with 0xF6xxx constants.

        Tests father_patcher_abc_extract_mop for m_or opcode.
        """
        func_ea = get_func_ea("abc_f6_or_dispatch")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_f6_or_dispatch' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_f6_or_dispatch rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_f6_nested(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test nested conditions with 0xF6xxx constants.

        Tests the recursive nature of father_history_patcher_abc.
        """
        func_ea = get_func_ea("abc_f6_nested")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_f6_nested' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_f6_nested rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_abc_f6_64bit_pattern(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test 64-bit constant pattern with high 32 bits in 0xF6xxx range.

        Tests the pattern: high(sub(or(x, #0xF6Axx_0000_0000.8), y))
        where the ABC value is in the high 32 bits.
        """
        func_ea = get_func_ea("abc_f6_64bit_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'abc_f6_64bit_pattern' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] abc_f6_64bit_pattern rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )


class TestApproovFlatteningCharacterization:
    """Characterization tests for Approov-style control flow flattening.

    These tests exercise the ABC patching code path with patterns that match
    the Approov obfuscator's characteristic microcode patterns:
    - m_high(m_sub(m_or(x, #0xF6Axx_0000_xxxx.8), y))
    - jz eax.4, #0xF6A1E.4, @XX style comparisons
    - 64-bit constants with high 32 bits in ABC range (1010000-1011999)

    See: src/d810/optimizers/microcode/flow/flattening/generic.py
    See: src/d810/optimizers/microcode/flow/flattening/unflattener_badwhile_loop.py
    """

    binary_name = _get_default_binary()

    def test_approov_real_pattern(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test real Approov pattern copied from decompiled code.

        This is the exact structure from real Approov-obfuscated binaries:
        - LABEL_xx: v8 = 1010207;
        - while (v8 != 1010208) { ... }
        - State transitions: v8 = 1010206 or v8 = 1010208
        - goto LABEL_xx to reset
        """
        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_real_pattern' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None, "Decompilation failed"

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None, "Decompilation with d810 failed"

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] approov_real_pattern rules fired: {state.stats.get_fired_rule_names()}"
                )
                print(f"[CHARACTERIZATION] Before:\n{actual_before[:500]}...")
                print(f"[CHARACTERIZATION] After:\n{actual_after[:500]}...")

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_approov_vm_dispatcher(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test Approov VM dispatcher with switch-based state machine.

        Uses constants in 0xF6xxx range with self-modifying state transitions
        like `opcode = (int)(qword |= 0xF6A20)` characteristic of Approov.
        """
        func_ea = get_func_ea("approov_vm_dispatcher")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_vm_dispatcher' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None, "Decompilation failed"

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None, "Decompilation with d810 failed"

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] approov_vm_dispatcher rules fired: {state.stats.get_fired_rule_names()}"
                )
                print(f"[CHARACTERIZATION] Before:\n{actual_before[:500]}...")
                print(f"[CHARACTERIZATION] After:\n{actual_after[:500]}...")

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_approov_simple_loop(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test simple Approov loop with do-while state machine.

        Uses volatile state variable and comparisons with 0xF6xxx constants.
        """
        func_ea = get_func_ea("approov_simple_loop")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_simple_loop' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] approov_simple_loop rules fired: {state.stats.get_fired_rule_names()}"
                )
                print(f"[CHARACTERIZATION] Before:\n{actual_before[:500]}...")
                print(f"[CHARACTERIZATION] After:\n{actual_after[:500]}...")

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )


class TestExceptionPathCharacterization:
    """Characterization tests for exception handling paths.

    These tests exercise:
    - NotResolvableFatherException handling
    - NotDuplicableFatherException handling
    - DEFAULT_MAX_DUPLICATION_PASSES (20) limit
    - Unresolvable indirect state transitions
    """

    binary_name = _get_default_binary()

    def test_unresolvable_external(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test NotResolvableFatherException - state from external source.

        State comes from external function that cannot be statically resolved.
        """
        func_ea = get_func_ea("unresolvable_external")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'unresolvable_external' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] unresolvable_external rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_unresolvable_computed(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test unresolvable computed state.

        State is computed from input in a way that prevents static resolution.
        """
        func_ea = get_func_ea("unresolvable_computed")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'unresolvable_computed' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] unresolvable_computed rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_non_duplicable_side_effects(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test NotDuplicableFatherException - path with side effects.

        Path contains side effects that prevent safe duplication.
        """
        func_ea = get_func_ea("non_duplicable_side_effects")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'non_duplicable_side_effects' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] non_duplicable_side_effects rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_deep_duplication_path(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test DEFAULT_MAX_DUPLICATION_PASSES (20) limit.

        Chain of 25 states - exceeds the duplication pass limit.
        """
        func_ea = get_func_ea("deep_duplication_path")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'deep_duplication_path' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] deep_duplication_path rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_loop_dependent_state(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test loop-dependent state transition.

        State depends on loop iteration count - creates partial resolution.
        """
        func_ea = get_func_ea("loop_dependent_state")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'loop_dependent_state' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] loop_dependent_state rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_indirect_state_pointer(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test indirect state via pointer.

        State is loaded through a pointer - tests indirect dispatcher patterns.
        """
        func_ea = get_func_ea("indirect_state_pointer")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'indirect_state_pointer' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] indirect_state_pointer rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )

    def test_external_transform_state(
        self,
        libobfuscated_test_setup,
        d810_state,
        pseudocode_to_string,
        capture_stats,
        load_expected_stats,
    ):
        """Test state transition via external transform.

        State is modified by external function - fully unresolvable.
        """
        func_ea = get_func_ea("external_transform_state")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'external_transform_state' not found in binary")

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.stop_d810()
                decompiled_before = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_before is not None

                actual_before = pseudocode_to_string(decompiled_before.get_pseudocode())

                state.start_d810()
                state.stats.reset()
                decompiled_after = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_after is not None

                actual_after = pseudocode_to_string(decompiled_after.get_pseudocode())

                stats_dict = capture_stats(state.stats)
                print(
                    f"[CHARACTERIZATION] external_transform_state rules fired: {state.stats.get_fired_rule_names()}"
                )

                expected = load_expected_stats()
                if expected is not None:
                    state.stats.assert_matches(
                        expected, check_counts=False, allow_extra_rules=True
                    )
