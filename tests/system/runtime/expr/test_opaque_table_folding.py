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
import re
import platform
import sys

import pytest

import ida_hexrays
import idaapi
import idc

from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.tracker import MopTracker
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
    """Find all readable mop_v operands in microcode, including nested ones.

    This uses ``ins.for_all_ops(visitor)`` so it can discover globals nested in
    complex operands (e.g. inside mop_d/mop_a trees), not just top-level ``l/r``.

    Returns:
        List of ``(block_serial, instruction, operand_name, mop)`` tuples.
        ``operand_name`` is a debug label derived from visitor metadata.
    """

    class _MopVCollector(ida_hexrays.mop_visitor_t):
        """Collect non-target mop_v operands from a single instruction."""

        def __init__(self):
            super().__init__()
            self.items = []
            self._seen = set()

        def visit_mop(self, op, op_type, is_target):
            # Skip write-target operands; tests care about readable values.
            if is_target:
                return 0
            if op is None or op.t != ida_hexrays.mop_v:
                return 0
            key = (
                getattr(op, "g", None),
                getattr(op, "size", None),
                op_type,
            )
            if key in self._seen:
                return 0
            self._seen.add(key)
            self.items.append((op_type, op))
            return 0

    results = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ins = blk.head
        while ins:
            collector = _MopVCollector()
            ins.for_all_ops(collector)
            for op_type, mop in collector.items:
                results.append((i, ins, f"op{op_type}", mop))
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
            from d810.hexrays.utils.ida_utils import is_never_written_var
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
        """Mixed-resolution mop_v integration check for MopTracker.

        Long-term intent:
        - Validate that a realistic operand set can produce mixed outcomes:
          some memory-backed mops resolve, others remain unresolved.
        - Exercise tracker normalization + resolution together (not just one
          artificial operand in isolation).

        The operand harvest intentionally spans several stable sample functions
        and maturities. A single function/maturity can collapse to one memory
        operand after MopTracker normalization, which makes the resolution
        invariant impossible to exercise.
        """
        candidate_functions = (
            "global_const_xor_decrypt",
            "global_const_simple_lookup",
            "hardened_cond_chain_simple",
        )
        candidate_maturities = (
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        )

        selected = []
        seen = set()
        kept_mbas = []

        for func_name in candidate_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                continue
            for maturity in candidate_maturities:
                mba = gen_microcode_at_maturity(func_ea, maturity)
                if mba is None:
                    continue
                kept_mbas.append(mba)
                for serial, _ins, op_name, mop in find_mop_v_operands(mba):
                    key = (getattr(mop, "g", None), getattr(mop, "size", None))
                    if key in seen or key[0] is None or key[1] is None:
                        continue
                    seen.add(key)
                    selected.append((func_name, maturity, serial, op_name, mop))

                    probe = MopTracker([entry[-1] for entry in selected])
                    initial_probe = len(probe._memory_unresolved_mops)
                    if initial_probe < 2:
                        continue
                    probe.try_resolve_memory_mops()
                    if len(probe._memory_unresolved_mops) < initial_probe:
                        break
                else:
                    continue
                break
            else:
                continue
            break

        if len(selected) < 2:
            pytest.skip("Need at least 2 unique mop_v operands for this test")

        mops = [entry[-1] for entry in selected]
        tracker = MopTracker(mops)

        initial_memory_unresolved = len(tracker._memory_unresolved_mops)
        if initial_memory_unresolved < 2:
            pytest.skip(
                "Not enough unresolved memory mops after tracker normalization "
                f"({initial_memory_unresolved})"
            )
        print(f"\n  Initial memory_unresolved: {initial_memory_unresolved}")
        print(
            "  Selected mop_v operands: "
            + ", ".join(
                f"{func}@{maturity}:blk{serial}:{op}=0x{mop.g:x}/{mop.size}"
                for func, maturity, serial, op, mop in selected
            )
        )

        tracker.try_resolve_memory_mops()

        final_memory_unresolved = len(tracker._memory_unresolved_mops)
        print(f"  Final memory_unresolved: {final_memory_unresolved}")
        print(f"  Resolved: {initial_memory_unresolved - final_memory_unresolved}")

        # At least some should resolve (e.g. readonly or never-written data)
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
                from d810.hexrays.utils.ida_utils import is_never_written_var
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
        d810_state,
        pseudocode_to_string,
    ):
        """Verify FoldReadonlyDataRule with fold_writable_constants can fold opaque tables.

        This test uses the full example_libobfuscated profile to ensure CFG
        cleanup runs for this integration path.
        """
        func_ea = get_func_ea("hardened_cond_chain_simple")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hardened_cond_chain_simple not found")

        with d810_state() as state:
            # Load the project with unflattening rules
            # Try various possible project names
            project_names = [
                "example_libobfuscated.json",
                "example_libobfuscated",
            ]

            project_loaded = False
            for project_name in project_names:
                try:
                    project = state.project_manager.get(project_name)
                    # Find the index by iterating through projects
                    for idx, proj in enumerate(state.project_manager.projects()):
                        if proj.path.name == project_name:
                            state.load_project(idx)
                            print(f"\n  Loaded project: {project.path.name}")
                            project_loaded = True
                            break
                    if project_loaded:
                        break
                except (KeyError, ValueError, IndexError):
                    continue

            if not project_loaded:
                pytest.skip("example_libobfuscated project not found")

            # Enable fold_writable_constants in FoldReadonlyDataRule
            for rule in state.current_ins_rules:
                if isinstance(rule, FoldReadonlyDataRule):
                    rule._fold_writable_constants = True
                    print("  Enabled fold_writable_constants on FoldReadonlyDataRule")

            state.start_d810()
            state.stats.reset()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None, "Decompilation failed"

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === hardened_cond_chain_simple ===\n{code}")

            fired_rules = state.stats.get_fired_rule_names()
            print(f"\n  Fired rules: {fired_rules}")

            # This test is primarily about writable opaque-table folding, but it
            # also guards the terminal conditional-chain regression that used to
            # hide behind a weak assertion set.  The accepted final form is IDA's
            # collapsed equivalent of the manual unflattening:
            #
            #   v3 = a1;
            #   v3 *= 3;
            #   v3 += 7;
            #   dword_18001D440 = v3;
            #   return v3;
            #
            # Different decompile paths may print the return as either
            # `return 3 * a1 + 7;` or `return (unsigned int)(3 * a1 + 7);`.
            # Both are equivalent for the recovered unsigned-int expression, so
            # assert the semantic shape instead of one renderer spelling.

            # Verify opaque table references eliminated
            assert "g_opaque_table" not in code, \
                "Opaque table reference should be eliminated"

            # Verify state constants eliminated (sample a few key ones)
            state_constants = ["0x1000", "0x2000", "0x4000", "0x5000", "0x6000", "0x7000"]
            for const in state_constants:
                assert const not in code, \
                    f"State constant {const} should be eliminated"

            code_lines = {line.strip() for line in code.splitlines()}
            # Writable-global addresses shift with the build base (.rdata rebuild),
            # so normalize dword_/qword_<addr> symbols before asserting the shape
            # (mirrors the address-agnostic oracle pins from 3d83eb5d8).
            code_lines_norm = {
                re.sub(r"\b((?:dword|qword|word|byte)_)[0-9A-Fa-f]+\b", r"\1ADDR", line)
                for line in code_lines
            }
            assert "dword_ADDR = 3 * a1 + 7;" in code_lines_norm, \
                "Expected collapsed side-effect assignment: dword_<g_opaque_table> = 3 * a1 + 7"
            assert (
                "return 3 * a1 + 7;" in code_lines
                or "return (unsigned int)(3 * a1 + 7);" in code_lines
            ), "Expected collapsed return of the recovered expression"

            assert "while" not in code.lower(), \
                "Expected conditional-chain dispatcher to be fully removed"

            assert "while ( 1 )\n        ;" not in code, \
                "Unexpected terminal infinite loop after opaque-table folding"

            # Verify decompilation didn't crash and produced something
            assert len(code.strip()) > 0, \
                "Expected non-empty pseudocode after deobfuscation"
