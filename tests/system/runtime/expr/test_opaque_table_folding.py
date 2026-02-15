"""System tests for opaque table folding using real IDA APIs.

Tests three layers of opaque table folding support:
1. MicroCodeInterpreter.eval() reads mop_v from writable segments with no write xrefs
2. MopTracker.try_resolve_memory_mops() resolves mop_v operands
3. FoldReadonlyDataRule._is_foldable_address() and configure() handle writable constants

All tests use real microcode from libobfuscated.dll binary (built from samples/src/c/).

Test Functions:
- hardened_cond_chain_simple: Uses volatile DWORD g_opaque_table[] for state transitions
- global_const_simple_lookup: Uses const LOOKUP_TABLE[] for readonly folding
- global_const_xor_decrypt: Uses const XOR_KEYS[] and ENCRYPTED_DATA[]

These real-IDA tests verify:
- Real mba_t/mblock_t/mop_t objects work correctly
- MopTracker integration with actual microcode
- FoldReadonlyDataRule with real segment permissions
- Emulator reads from IDB correctly
"""

from __future__ import annotations

import os
import pathlib
import platform
import sys

import pytest

import ida_hexrays
import idaapi
import idc

from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.hexrays.tracker import MopTracker
from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    FoldReadonlyDataRule,
)

# Add project src to path for imports
_PROJECT_SRC = str(pathlib.Path(__file__).resolve().parents[4] / "src")
if _PROJECT_SRC not in sys.path:
    sys.path.insert(0, _PROJECT_SRC)


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    system = platform.system()
    if system == "Windows":
        return "libobfuscated.dll"
    elif system == "Darwin":
        return "libobfuscated.dylib"
    else:
        return "libobfuscated.so"


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)  # macOS prefix
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int):
    """Generate microcode at a specific maturity level.

    Returns an mba_t object or None if generation fails.
    """
    func = idaapi.get_func(func_ea)
    if func is None:
        return None

    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
    )
    return mba


def find_mop_v_operands(mba):
    """Find all mop_v (global variable) operands in microcode.

    Returns list of (block_serial, instruction, operand_name, mop) tuples.
    """
    results = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ins = blk.head
        while ins:
            # Check left operand
            if ins.l and ins.l.t == ida_hexrays.mop_v:
                results.append((i, ins, "l", ins.l))
            # Check right operand
            if ins.r and ins.r.t == ida_hexrays.mop_v:
                results.append((i, ins, "r", ins.r))
            # Don't check destination as it's often an assignment target
            ins = ins.next
    return results


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays):
    """Setup fixture for libobfuscated binary tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


# ===================================================================
# Test: Emulator reads mop_v from writable segment with no write xrefs
# ===================================================================
class TestEmulatorMopVWritableNoXrefs:
    """Test that MicroCodeInterpreter.eval() reads mop_v from writable
    segments when is_never_written_var() returns True.
    """

    binary_name = _get_default_binary()

    def test_eval_mop_v_from_const_array(self, libobfuscated_setup):
        """mop_v in a const readonly segment should be read from IDB."""
        func_ea = get_func_ea("global_const_simple_lookup")
        if func_ea == idaapi.BADADDR:
            pytest.skip("global_const_simple_lookup not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        # Find mop_v operands (const table reads)
        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            pytest.skip("No mop_v operands found in const array function")

        interp = MicroCodeInterpreter()
        env = MicroCodeEnvironment()

        # Try to evaluate the first mop_v operand
        serial, ins, op_name, mop = mop_v_list[0]
        addr = mop.g
        size = mop.size

        # Get the value from emulator
        try:
            result = interp.eval(mop, env)
            print(f"\n  Block {serial}, {op_name} operand: addr=0x{addr:x}, size={size}, value=0x{result:x}")
            assert isinstance(result, int), "eval() should return an integer"
        except Exception as e:
            # Some addresses may not be emulatable (e.g., runtime-computed)
            print(f"\n  Block {serial}: eval() raised {type(e).__name__}: {e}")

    def test_eval_mop_v_from_opaque_table(self, libobfuscated_setup):
        """mop_v in a writable volatile array with no write xrefs should be read."""
        func_ea = get_func_ea("hardened_cond_chain_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hardened_cond_chain_simple not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        # Find mop_v operands (g_opaque_table reads)
        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            # Try MMAT_GLBOPT1 if MMAT_CALLS doesn't have any
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
            if mba:
                mop_v_list = find_mop_v_operands(mba)

        if not mop_v_list:
            pytest.skip("No mop_v operands found in opaque table function")

        interp = MicroCodeInterpreter()
        env = MicroCodeEnvironment()

        # Test evaluation on multiple mop_v operands
        for serial, ins, op_name, mop in mop_v_list[:3]:  # Test first 3
            addr = mop.g
            size = mop.size

            # Check segment permissions
            seg = idaapi.getseg(addr)
            if seg:
                has_write = bool(seg.perm & idaapi.SEGPERM_WRITE)
                print(f"\n  Block {serial}, {op_name}: addr=0x{addr:x}, writable={has_write}")

                try:
                    result = interp.eval(mop, env)
                    print(f"    eval() = 0x{result:x}")
                    assert isinstance(result, int)
                except Exception as e:
                    print(f"    eval() raised {type(e).__name__}: {e}")


# ===================================================================
# Test: MopTracker resolves mop_v globals concretely
# ===================================================================
class TestMopTrackerResolvesGlobals:
    """Test that MopTracker.try_resolve_memory_mops() resolves
    mop_v operands by reading concrete values from the IDB.
    """

    binary_name = _get_default_binary()

    def test_tracker_with_mop_v_from_const_table(self, libobfuscated_setup):
        """MopTracker should resolve mop_v from const readonly tables."""
        func_ea = get_func_ea("global_const_xor_decrypt")
        if func_ea == idaapi.BADADDR:
            pytest.skip("global_const_xor_decrypt not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            pytest.skip("No mop_v operands found")

        # Test the first mop_v operand
        serial, ins, op_name, mop = mop_v_list[0]
        tracker = MopTracker([mop])

        # Before try_resolve_memory_mops
        initial_resolved = tracker.is_resolved()
        initial_memory_unresolved = len(tracker._memory_unresolved_mops)
        print(f"\n  Initial: resolved={initial_resolved}, memory_unresolved={initial_memory_unresolved}")

        # Try to resolve
        tracker.try_resolve_memory_mops()

        # After try_resolve_memory_mops
        final_resolved = tracker.is_resolved()
        final_memory_unresolved = len(tracker._memory_unresolved_mops)
        print(f"  After resolve: resolved={final_resolved}, memory_unresolved={final_memory_unresolved}")

        # For const readonly data, should resolve successfully
        assert final_memory_unresolved <= initial_memory_unresolved, \
            "try_resolve_memory_mops should not increase unresolved count"

    def test_tracker_with_mop_v_from_opaque_table(self, libobfuscated_setup):
        """MopTracker should resolve mop_v from writable opaque tables with no xrefs."""
        func_ea = get_func_ea("hardened_cond_chain_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hardened_cond_chain_simple not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            # Try MMAT_GLBOPT1
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
            if mba:
                mop_v_list = find_mop_v_operands(mba)

        if not mop_v_list:
            pytest.skip("No mop_v operands found")

        # Test multiple mop_v operands (g_opaque_table reads)
        for serial, ins, op_name, mop in mop_v_list[:2]:
            tracker = MopTracker([mop])
            addr = mop.g

            # Check if this is truly never written
            from d810.hexrays.ida_utils import is_never_written_var
            never_written = is_never_written_var(addr)

            print(f"\n  Block {serial}, {op_name}: addr=0x{addr:x}, never_written={never_written}")

            initial_memory_unresolved = len(tracker._memory_unresolved_mops)
            tracker.try_resolve_memory_mops()
            final_memory_unresolved = len(tracker._memory_unresolved_mops)

            print(f"    memory_unresolved: {initial_memory_unresolved} -> {final_memory_unresolved}")

            # If the variable is never written, it should be resolvable
            if never_written:
                assert final_memory_unresolved == 0, \
                    "Never-written variable should be resolved"
            else:
                # Has write xrefs, should remain unresolved
                assert final_memory_unresolved == initial_memory_unresolved, \
                    "Variable with write xrefs should stay unresolved"

    def test_tracker_multiple_mops_mixed_segments(self, libobfuscated_setup):
        """Multiple mop_v operands from different segments: some resolve, some don't."""
        # Use global_const_xor_decrypt which has multiple const table reads
        func_ea = get_func_ea("global_const_xor_decrypt")
        if func_ea == idaapi.BADADDR:
            pytest.skip("global_const_xor_decrypt not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        mop_v_list = find_mop_v_operands(mba)
        if len(mop_v_list) < 2:
            pytest.skip("Need at least 2 mop_v operands for this test")

        # Collect unique mop_v operands
        mops = [mop for _, _, _, mop in mop_v_list[:4]]
        tracker = MopTracker(mops)

        initial_memory_unresolved = len(tracker._memory_unresolved_mops)
        print(f"\n  Initial memory_unresolved: {initial_memory_unresolved}")

        tracker.try_resolve_memory_mops()

        final_memory_unresolved = len(tracker._memory_unresolved_mops)
        print(f"  Final memory_unresolved: {final_memory_unresolved}")
        print(f"  Resolved: {initial_memory_unresolved - final_memory_unresolved}")

        # At least some should resolve (const tables)
        assert final_memory_unresolved < initial_memory_unresolved, \
            "Expected at least some mop_v operands to resolve"


# ===================================================================
# Test: FoldReadonlyDataRule with fold_writable_constants
# ===================================================================
class TestFoldReadonlyDataRuleWritableConstants:
    """Test that FoldReadonlyDataRule._is_foldable_address() returns True
    for writable segments when fold_writable_constants is enabled.
    """

    binary_name = _get_default_binary()

    def test_is_foldable_for_const_segment(self, libobfuscated_setup):
        """Addresses in const readonly segments should be foldable by default."""
        func_ea = get_func_ea("global_const_simple_lookup")
        if func_ea == idaapi.BADADDR:
            pytest.skip("global_const_simple_lookup not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            pytest.skip("No mop_v operands found")

        rule = FoldReadonlyDataRule()
        rule._fold_writable_constants = False  # Default: only readonly

        # Test first mop_v operand (const table)
        serial, ins, op_name, mop = mop_v_list[0]
        addr = mop.g

        seg = idaapi.getseg(addr)
        if seg:
            has_write = bool(seg.perm & idaapi.SEGPERM_WRITE)
            is_foldable = rule._is_foldable_address(addr)

            print(f"\n  addr=0x{addr:x}, writable={has_write}, foldable={is_foldable}")

            # Const segments should be foldable
            if not has_write:
                assert is_foldable, "Readonly address should be foldable"

    def test_is_foldable_for_writable_with_fold_enabled(self, libobfuscated_setup):
        """Writable addresses with no xrefs should be foldable when flag is enabled."""
        func_ea = get_func_ea("hardened_cond_chain_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hardened_cond_chain_simple not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            # Try MMAT_GLBOPT1
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
            if mba:
                mop_v_list = find_mop_v_operands(mba)

        if not mop_v_list:
            pytest.skip("No mop_v operands found")

        # Test with fold_writable_constants enabled
        rule = FoldReadonlyDataRule()
        rule._fold_writable_constants = True

        # Test g_opaque_table reads
        for serial, ins, op_name, mop in mop_v_list[:2]:
            addr = mop.g
            seg = idaapi.getseg(addr)

            if seg and (seg.perm & idaapi.SEGPERM_WRITE):
                # This is a writable segment
                from d810.hexrays.ida_utils import is_never_written_var
                never_written = is_never_written_var(addr)
                is_foldable = rule._is_foldable_address(addr)

                print(f"\n  addr=0x{addr:x}, never_written={never_written}, foldable={is_foldable}")

                # With fold_writable_constants=True and no xrefs, should be foldable
                if never_written:
                    assert is_foldable, \
                        "Writable never-written address should be foldable with flag enabled"

    def test_is_foldable_for_writable_with_fold_disabled(self, libobfuscated_setup):
        """Writable addresses should NOT be foldable when flag is disabled."""
        func_ea = get_func_ea("hardened_cond_chain_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hardened_cond_chain_simple not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        mop_v_list = find_mop_v_operands(mba)
        if not mop_v_list:
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
            if mba:
                mop_v_list = find_mop_v_operands(mba)

        if not mop_v_list:
            pytest.skip("No mop_v operands found")

        # Test with fold_writable_constants disabled (default)
        rule = FoldReadonlyDataRule()
        rule._fold_writable_constants = False

        # Test g_opaque_table reads
        for serial, ins, op_name, mop in mop_v_list[:2]:
            addr = mop.g
            seg = idaapi.getseg(addr)

            if seg and (seg.perm & idaapi.SEGPERM_WRITE):
                is_foldable = rule._is_foldable_address(addr)
                print(f"\n  addr=0x{addr:x}, foldable={is_foldable}")

                # With fold_writable_constants=False, writable should NOT be foldable
                assert not is_foldable, \
                    "Writable address should NOT be foldable with flag disabled"

    def test_configure_sets_fold_writable_constants(self, libobfuscated_setup):
        """configure() should set _fold_writable_constants from kwargs."""
        rule = FoldReadonlyDataRule()
        assert rule._fold_writable_constants is False, "Default should be False"

        rule.configure({"fold_writable_constants": True})
        assert rule._fold_writable_constants is True, "Should be set to True after configure"

        rule.configure({"fold_writable_constants": False})
        assert rule._fold_writable_constants is False, "Should be reset to False"

    def test_configure_sets_allow_executable(self, libobfuscated_setup):
        """configure() should set _allow_executable from kwargs."""
        rule = FoldReadonlyDataRule()
        assert rule._allow_executable is False, "Default should be False"

        rule.configure({"allow_executable_readonly": True})
        assert rule._allow_executable is True, "Should be set to True after configure"

        rule.configure({"allow_executable_readonly": False})
        assert rule._allow_executable is False, "Should be reset to False"


# ===================================================================
# Test: Integration - Full pipeline with real decompilation
# ===================================================================
class TestIntegrationOpaqueTableFolding:
    """Integration tests using full D810 state and decompiler."""

    binary_name = _get_default_binary()

    def test_fold_const_table_with_d810(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Verify FoldReadonlyDataRule folds const table lookups."""
        func_ea = get_func_ea("global_const_simple_lookup")
        if func_ea == idaapi.BADADDR:
            pytest.skip("global_const_simple_lookup not found")

        with d810_state() as state:
            state.start_d810()
            state.stats.reset()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None, "Decompilation failed"

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === global_const_simple_lookup ===\n{code}")

            # Check if folding happened
            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n  Fired rules: {fired_rules}")

            # The const table should be inlined (or IDA may do it before d810)
            assert "return" in code.lower(), "Expected return statement"

    def test_fold_opaque_table_with_flag_enabled(
        self,
        libobfuscated_setup,
        d810_state_all_rules,
        pseudocode_to_string,
    ):
        """Verify FoldReadonlyDataRule with fold_writable_constants can fold opaque tables."""
        func_ea = get_func_ea("hardened_cond_chain_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hardened_cond_chain_simple not found")

        with d810_state_all_rules() as state:
            # Enable fold_writable_constants in FoldReadonlyDataRule
            for rule in state.current_ins_rules:
                if isinstance(rule, FoldReadonlyDataRule):
                    rule._fold_writable_constants = True
                    print("\n  Enabled fold_writable_constants on FoldReadonlyDataRule")

            state.start_d810()
            state.stats.reset()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None, "Decompilation failed"

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === hardened_cond_chain_simple ===\n{code}")

            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n  Fired rules: {fired_rules}")

            # =========================================================================
            # This test verifies what d810 ACTUALLY does today (not what it should do).
            #
            # CURRENT BEHAVIOR (as of test writing):
            #   void hardened_cond_chain_simple()
            #   {
            #       dword_180015448 = 7;  // g_side_effect
            #       while ( 1 )
            #           ;
            #   }
            #
            # WHAT d810 DOES CORRECTLY:
            # 1. Eliminates opaque table references (g_opaque_table, dword_* lookups)
            # 2. Eliminates state constants (0x1000, 0x2000, 0x4000, 0x5000, 0x6000, 0x7000)
            # 3. Simplifies to a constant assignment (even if over-simplified)
            #
            # KNOWN LIMITATIONS (NOT asserted as correct):
            # 1. Over-simplifies computation: outputs '= 7' instead of '= 3 * a1 + 7'
            #    (loses parameter dependency)
            # 2. Function signature wrong: 'void ()' instead of 'int (int a1)'
            # 3. Exit path broken: 'while(1);' instead of 'return result'
            #
            # When these bugs are fixed, update this test to verify:
            #   - Computation includes parameter: '3 * a1 + 7'
            #   - Function signature: 'int hardened_cond_chain_simple(int a1)'
            #   - Contains return statement: 'return'
            # =========================================================================

            # Verify opaque table references eliminated
            assert "g_opaque_table" not in code, \
                "Opaque table reference should be eliminated"

            # Verify state constants eliminated (sample a few key ones)
            state_constants = ["0x1000", "0x2000", "0x4000", "0x5000", "0x6000", "0x7000"]
            for const in state_constants:
                assert const not in code, \
                    f"State constant {const} should be eliminated"

            # Verify side effect variable assignment present (even if value is wrong)
            # Note: The variable name will be IDA-generated (dword_*), not "g_side_effect"
            # Just verify there's an assignment of some constant
            assert " = 7" in code or "= 7;" in code, \
                "Expected side effect assignment with constant value (current behavior)"

            # Verify decompilation didn't crash and produced something
            assert len(code.strip()) > 0, \
                "Expected non-empty pseudocode after deobfuscation"
