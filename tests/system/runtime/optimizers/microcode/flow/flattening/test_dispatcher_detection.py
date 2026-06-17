"""Tests for dispatcher analysis and strategies.

These tests validate the unified dispatcher detection system that aggregates
multiple detection strategies for identifying state machine dispatcher blocks.

The tests cover:
- Real IDA integration testing with actual microcode
- Dispatcher type detection (CONDITION_CHAIN vs SWITCH)
- should_skip_dispatcher() integration
"""

import pytest


@pytest.mark.ida_required
class TestDispatcherDetectionWithRealMicrocode:
    """Integration tests for dispatcher detection using real IDA microcode.

    These tests verify analyze_dispatcher_live() against actual decompiled
    functions from libobfuscated binary (dispatcher_patterns.c and related
    sources).
    """

    binary_name = "libobfuscated.dylib"  # macOS default (CI uses libobfuscated.dll)

    @pytest.fixture(scope="class")
    def ida_setup(self, ida_database, configure_hexrays, setup_libobfuscated_funcs):
        """Setup IDA and Hex-Rays for real microcode tests."""
        import idaapi
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        return ida_database

    def _get_func_ea(self, name: str) -> int:
        """Get function address by name, handling macOS underscore prefix."""
        import ida_name
        import idaapi
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            ea = ida_name.get_name_ea(idaapi.BADADDR, "_" + name)
        return ea

    def _gen_microcode(self, func_ea: int, maturity: int):
        """Generate microcode at specific maturity level."""
        import ida_funcs
        import ida_hexrays

        func = ida_funcs.get_func(func_ea)
        if func is None:
            return None

        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
        )
        return mba

    def test_analyze_detects_dispatcher_in_real_function(self, ida_setup):
        """Test analyze_dispatcher_live() detects dispatchers in real functions.

        Tests multiple dispatcher patterns from dispatcher_patterns.c:
        - nested_while_hodur_pattern: CONDITION_CHAIN with nested while(1) loops
        - hardened_cond_chain_simple: CONDITION_CHAIN with binary search dispatch
        - _hodur_func: Real Hodur C2 malware dispatcher

        Also tests functions that may have SWITCH early-return:
        - high_fan_in_pattern: May produce jtbl (SWITCH early-return is expected)
        """
        import ida_hexrays
        import idaapi
        from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
            DEFAULT_DISPATCHER_HISTORY_STORE,
            RouterKind,
            analyze_dispatcher_live,
        )

        # Function name -> expected dispatcher type
        test_functions = [
            ("nested_while_hodur_pattern", RouterKind.CONDITION_CHAIN),  # 3-level nested while
            ("_hodur_func", RouterKind.CONDITION_CHAIN),                 # Real Hodur malware
            ("high_fan_in_pattern", RouterKind.SWITCH),             # May produce jtbl
            ("hardened_cond_chain_simple", RouterKind.CONDITION_CHAIN),  # Uses state values 0x1000-0x7000 (now detected)
        ]

        maturities_to_test = [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
        ]

        for func_name, expected_type in test_functions:
            func_ea = self._get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                pytest.skip(f"{func_name} not found in binary")

            print(f"\n  Testing {func_name} (expected type: {expected_type})...")

            detected_at_any_maturity = False
            for maturity in maturities_to_test:
                mba = self._gen_microcode(func_ea, maturity)
                if mba is None:
                    continue

                # Clear cache and analyze
                DEFAULT_DISPATCHER_HISTORY_STORE.clear()
                analysis = analyze_dispatcher_live(mba)

                print(f"    Maturity {maturity}: type={analysis.router_kind}, "
                      f"dispatchers={len(analysis.dispatchers)}, "
                      f"is_conditional_chain={analysis.is_conditional_chain}")

                # Verify basic structure
                assert analysis.func_ea == func_ea
                assert analysis.maturity == maturity
                assert isinstance(analysis.blocks, dict)
                assert isinstance(analysis.dispatchers, list)

                # Check if we detected the expected type
                if expected_type is not None and analysis.router_kind == expected_type:
                    if expected_type == RouterKind.SWITCH:
                        # SWITCH has empty dispatchers due to early return
                        assert len(analysis.dispatchers) == 0, \
                            "SWITCH should have empty dispatchers (early return)"
                        print(f"      * SWITCH early-return as expected")
                    elif expected_type == RouterKind.CONDITION_CHAIN:
                        assert analysis.is_conditional_chain
                        print(f"      * Detected CONDITION_CHAIN at maturity {maturity}")
                    detected_at_any_maturity = True
                    break

                # For functions with no expected type, just check if dispatchers were found
                if expected_type is None and len(analysis.dispatchers) > 0:
                    print(f"      * Found {len(analysis.dispatchers)} dispatcher(s) at maturity {maturity}")
                    detected_at_any_maturity = True
                    break

            # Ensure we detected something at some maturity
            assert detected_at_any_maturity, \
                f"{func_name} should be detected as dispatcher at some maturity level"

    def test_detect_conditional_chain_in_hodur_function(self, ida_setup):
        """Test CONDITION_CHAIN detection in Hodur-style dispatchers.

        Verifies that nested while(1) + if/else patterns are correctly identified
        as CONDITION_CHAIN (not SWITCH).

        Note: Only tests functions that reliably meet the CONDITION_CHAIN threshold.
        hardened_cond_chain_simple is tested in test_analyze_detects_dispatcher_in_real_function
        where it's allowed to be UNKNOWN type (it finds dispatchers but may not meet
        the nested loop threshold for CONDITION_CHAIN classification).
        """
        import ida_hexrays
        import idaapi
        from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
            DEFAULT_DISPATCHER_HISTORY_STORE,
            RouterKind,
            analyze_dispatcher_live,
        )

        test_functions = [
            "nested_while_hodur_pattern",  # 3-level nested while(1) - strong CONDITION_CHAIN
        ]

        for func_name in test_functions:
            func_ea = self._get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                pytest.skip(f"{func_name} not found in binary")

            print(f"\n  Testing {func_name}...")

            mba = self._gen_microcode(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is None:
                pytest.skip(f"Failed to generate microcode for {func_name}")

            DEFAULT_DISPATCHER_HISTORY_STORE.clear()
            analysis = analyze_dispatcher_live(mba)

            # Verify CONDITION_CHAIN detection
            assert analysis.is_conditional_chain, \
                f"{func_name} should be detected as CONDITION_CHAIN (no jtbl)"
            assert analysis.router_kind == RouterKind.CONDITION_CHAIN, \
                f"router_kind should be CONDITION_CHAIN, got {analysis.router_kind}"

            # Verify we found dispatcher blocks
            assert len(analysis.dispatchers) > 0, \
                "Should detect at least one dispatcher block"

            print(f"    * Detected as CONDITION_CHAIN with {len(analysis.dispatchers)} dispatcher(s)")

    def test_detect_switch_table_in_ollvm_function(self, ida_setup):
        """Test SWITCH detection in O-LLVM style dispatchers.

        Verifies that switch/case patterns with jtbl are correctly identified
        as SWITCH (not CONDITION_CHAIN).
        """
        import ida_hexrays
        import idaapi
        from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
            DEFAULT_DISPATCHER_HISTORY_STORE,
            RouterKind,
            analyze_dispatcher_live,
        )

        func_name = "switch_case_ollvm_pattern"  # Correct name (not "simple_switch_dispatcher")
        func_ea = self._get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"{func_name} not found in binary")

        print(f"\n  Testing {func_name}...")

        mba = self._gen_microcode(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip(f"Failed to generate microcode for {func_name}")

        DEFAULT_DISPATCHER_HISTORY_STORE.clear()
        analysis = analyze_dispatcher_live(mba)

        # Verify SWITCH detection (has jtbl, not conditional chain)
        assert not analysis.is_conditional_chain, \
            f"{func_name} should NOT be CONDITION_CHAIN (has jtbl/switch)"
        assert analysis.router_kind == RouterKind.SWITCH, \
            f"router_kind should be SWITCH, got {analysis.router_kind}"

        print(f"    * Detected as SWITCH (O-LLVM style)")

    def test_should_skip_dispatcher_with_real_blocks(self, ida_setup):
        """Test should_skip_dispatcher() integration with real dispatcher blocks.

        Verifies that:
        - Hodur-style CONDITION_CHAIN dispatchers return True (should skip)
        - O-LLVM-style SWITCH dispatchers return False (should NOT skip)
        """
        import ida_hexrays
        import idaapi
        from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
            DEFAULT_DISPATCHER_HISTORY_STORE,
            analyze_dispatcher_live,
            should_skip_dispatcher,
        )

        test_cases = [
            ("nested_while_hodur_pattern", True, "Hodur-style should skip"),
            ("switch_case_ollvm_pattern", False, "O-LLVM-style should NOT skip"),
        ]

        for func_name, expected_skip, description in test_cases:
            func_ea = self._get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                pytest.skip(f"{func_name} not found in binary")

            print(f"\n  Testing {func_name}: {description}")

            mba = self._gen_microcode(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is None:
                pytest.skip(f"Failed to generate microcode for {func_name}")

            DEFAULT_DISPATCHER_HISTORY_STORE.clear()
            analysis = analyze_dispatcher_live(mba)

            # Find a dispatcher block to test
            if len(analysis.dispatchers) == 0:
                # For SWITCH, early-return leaves dispatchers empty - use first block
                test_block = mba.get_mblock(0)
            else:
                dispatcher_serial = analysis.dispatchers[0]
                test_block = mba.get_mblock(dispatcher_serial)

            if test_block is None:
                pytest.skip(f"Could not find test block for {func_name}")

            # Test should_skip_dispatcher
            result = should_skip_dispatcher(mba, test_block)

            assert result == expected_skip, \
                f"{func_name}: should_skip_dispatcher returned {result}, expected {expected_skip}"

            print(f"    * should_skip_dispatcher={result} (correct)")


"""
Integration with Sample Binaries
================================

For full integration tests with real IDA analysis, see:
- tests/system/test_libdeobfuscated.py
- samples/src/c/hodur_c2_flattened.c (Hodur-style dispatcher)
- samples/src/c/while_switch_flattened.c (O-LLVM style switch)
- samples/src/c/dispatcher_patterns.c (all dispatcher patterns)

These system tests verify:
1. Hodur-style detection (nested while loops, jnz/jz)
2. O-LLVM-style detection (jtbl/switch)
3. State variable identification
4. State constant extraction
5. Initial state detection
"""
