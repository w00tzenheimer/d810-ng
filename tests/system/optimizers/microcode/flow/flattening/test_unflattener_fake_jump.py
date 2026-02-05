"""System tests for UnflattenerFakeJump optimizer using real IDA/HexRays.

This module tests the fake jump/loop removal optimization that detects
conditional jumps that are always taken or never taken from specific
predecessor blocks.

The UnflattenerFakeJump optimizer:
1. Identifies blocks with fake loop opcodes (m_jz/m_jnz)
2. Tracks comparison values backward through predecessors
3. Determines if jump is always/never taken
4. Redirects control flow to eliminate fake jumps

Test Coverage:
- Validation of FAKE_LOOP_OPCODES using real ida_hexrays constants
- Rule initialization and configuration
- Integration with D810 state
"""

import os
import platform

import pytest

import idapro
import ida_hexrays
import idaapi
import idc

from d810.optimizers.microcode.flow.flattening.unflattener_fake_jump import (
    UnflattenerFakeJump,
    FAKE_LOOP_OPCODES,
)


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


class TestUnflattenerFakeJumpConstants:
    """Tests for module constants using real IDA values."""

    binary_name = _get_default_binary()

    def test_fake_loop_opcodes_are_valid(self, libobfuscated_setup):
        """FAKE_LOOP_OPCODES should contain m_jz and m_jnz from real ida_hexrays."""
        # Verify that FAKE_LOOP_OPCODES contains the real IDA constants
        assert ida_hexrays.m_jz in FAKE_LOOP_OPCODES, (
            f"m_jz ({ida_hexrays.m_jz}) not in FAKE_LOOP_OPCODES {FAKE_LOOP_OPCODES}"
        )
        assert ida_hexrays.m_jnz in FAKE_LOOP_OPCODES, (
            f"m_jnz ({ida_hexrays.m_jnz}) not in FAKE_LOOP_OPCODES {FAKE_LOOP_OPCODES}"
        )

    def test_fake_loop_opcodes_count(self, libobfuscated_setup):
        """FAKE_LOOP_OPCODES should contain exactly 2 opcodes."""
        assert len(FAKE_LOOP_OPCODES) == 2

    def test_opcodes_are_different(self, libobfuscated_setup):
        """m_jz and m_jnz should be different opcodes."""
        assert ida_hexrays.m_jz != ida_hexrays.m_jnz


class TestUnflattenerFakeJumpInit:
    """Tests for UnflattenerFakeJump initialization and configuration."""

    binary_name = _get_default_binary()

    def test_class_instantiation(self, libobfuscated_setup):
        """Test that UnflattenerFakeJump can be instantiated."""
        rule = UnflattenerFakeJump()
        assert rule is not None

    def test_class_description(self, libobfuscated_setup):
        """Test class-level description attribute."""
        rule = UnflattenerFakeJump()
        assert rule.DESCRIPTION == "Check if a jump is always taken for each father blocks and remove them"

    def test_default_max_passes(self, libobfuscated_setup):
        """Test DEFAULT_MAX_PASSES is None (unlimited)."""
        rule = UnflattenerFakeJump()
        assert rule.DEFAULT_MAX_PASSES is None

    def test_has_unflattening_maturities(self, libobfuscated_setup):
        """Test class has DEFAULT_UNFLATTENING_MATURITIES attribute."""
        rule = UnflattenerFakeJump()
        assert hasattr(rule, 'DEFAULT_UNFLATTENING_MATURITIES')
        # Should contain MMAT_CALLS and MMAT_GLBOPT1
        maturities = rule.DEFAULT_UNFLATTENING_MATURITIES
        assert ida_hexrays.MMAT_CALLS in maturities
        assert ida_hexrays.MMAT_GLBOPT1 in maturities


class TestUnflattenerFakeJumpWithD810:
    """Tests for UnflattenerFakeJump integration with D810 state."""

    binary_name = _get_default_binary()

    def test_rule_in_known_blk_rules(self, libobfuscated_setup, d810_state):
        """Test that UnflattenerFakeJump is registered in D810 state."""
        with d810_state() as state:
            # Check if the rule is registered
            rule_names = [type(r).__name__ for r in state.known_blk_rules]
            assert "UnflattenerFakeJump" in rule_names, (
                f"UnflattenerFakeJump not found in known_blk_rules: {rule_names}"
            )


class TestUnflattenerFakeJumpOnRealFunctions:
    """Tests for UnflattenerFakeJump against real obfuscated functions."""

    binary_name = _get_default_binary()

    def _get_function_ea(self, func_name: str) -> int:
        """Get function address by name, trying with and without underscore prefix."""
        ea = idc.get_name_ea_simple(func_name)
        if ea == idaapi.BADADDR:
            ea = idc.get_name_ea_simple("_" + func_name)
        return ea

    def _decompile_at_maturity(self, func_ea: int, maturity: int) -> ida_hexrays.mba_t:
        """Decompile function and get microcode at specified maturity."""
        mbr = ida_hexrays.mba_ranges_t()
        mbr.ranges.push_back(idaapi.range_t(func_ea, idaapi.BADADDR))

        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity)
        return mba

    def test_decompile_flattened_function(self, libobfuscated_setup, d810_state):
        """Test decompiling a flattened function with and without D810."""
        # Find a flattened function to test with
        func_ea = self._get_function_ea("test_function_ollvm_fla_bcf_sub")
        if func_ea == idaapi.BADADDR:
            func_ea = self._get_function_ea("_hodur_func")
        if func_ea == idaapi.BADADDR:
            pytest.skip("No suitable test function found")

        with d810_state() as state:
            # Decompile without D810
            state.stop_d810()

            cfunc_before = idaapi.decompile(func_ea)
            assert cfunc_before is not None, "Failed to decompile without D810"

            code_before = str(cfunc_before)

            # Decompile with D810
            state.start_d810()
            state.stats.reset()

            cfunc_after = idaapi.decompile(func_ea)
            assert cfunc_after is not None, "Failed to decompile with D810"

            code_after = str(cfunc_after)

            # The code should be different (simplified) with D810
            # Note: This is a basic sanity check - detailed validation
            # should be done in the DSL-based tests
            print(f"\n  Function: 0x{func_ea:x}")
            print(f"  Code before D810: {len(code_before)} chars")
            print(f"  Code after D810: {len(code_after)} chars")
            print(f"  Stats: {state.stats.to_dict()}")

    def test_rule_can_analyze_microcode(self, libobfuscated_setup, d810_state):
        """Test that the rule can analyze microcode blocks."""
        # Find a function to analyze
        func_ea = self._get_function_ea("test_xor")
        if func_ea == idaapi.BADADDR:
            func_ea = self._get_function_ea("_test_xor")
        if func_ea == idaapi.BADADDR:
            pytest.skip("test_xor function not found")

        with d810_state() as state:
            # Generate microcode at MMAT_CALLS maturity
            mba = self._decompile_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is None:
                pytest.skip("Failed to generate microcode")

            # Create rule instance
            rule = UnflattenerFakeJump()
            rule.mba = mba

            # Iterate through blocks and try to analyze
            changes_made = 0
            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                if blk is not None:
                    # The analyze_blk method should not crash
                    try:
                        changes = rule.analyze_blk(blk)
                        changes_made += changes
                    except Exception as e:
                        pytest.fail(f"analyze_blk raised exception on block {i}: {e}")

            print(f"\n  Analyzed {mba.qty} blocks, changes made: {changes_made}")


class TestFakeLoopOpcodesBehavior:
    """Tests verifying the behavior of m_jz and m_jnz opcodes."""

    binary_name = _get_default_binary()

    def test_jz_opcode_value(self, libobfuscated_setup):
        """Verify m_jz opcode value is valid."""
        # Just verify it's a reasonable positive integer
        assert isinstance(ida_hexrays.m_jz, int)
        assert ida_hexrays.m_jz > 0

    def test_jnz_opcode_value(self, libobfuscated_setup):
        """Verify m_jnz opcode value is valid."""
        # Just verify it's a reasonable positive integer
        assert isinstance(ida_hexrays.m_jnz, int)
        assert ida_hexrays.m_jnz > 0

    def test_opcode_is_jump_instruction(self, libobfuscated_setup):
        """Verify that m_jz and m_jnz are near each other (both are conditional jumps)."""
        # In IDA's microcode, related instructions tend to have nearby opcode values
        # jz and jnz should be relatively close to each other
        diff = abs(ida_hexrays.m_jz - ida_hexrays.m_jnz)
        assert diff < 10, f"m_jz and m_jnz seem too far apart: {ida_hexrays.m_jz} vs {ida_hexrays.m_jnz}"
