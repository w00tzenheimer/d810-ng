"""System tests for convert_jtbl_to_goto() in cfg_utils.py.

Tests that convert_jtbl_to_goto() correctly converts an m_jtbl (switch/jump
table) tail instruction to a direct m_goto by:
1. Collecting old case targets from mcases_t
2. Changing opcode m_jtbl -> m_goto
3. Setting l operand to blkref(new_target)
4. Clearing r (mcases) and d operands
5. Rewiring succset/predset
6. Setting block type to BLT_1WAY
7. Marking lists dirty

These tests require IDA Pro with Hex-Rays decompiler and exercise the
function against real binaries -- no mocks.

Sample requirements:
    A binary containing functions with switch/jump table patterns that
    produce m_jtbl instructions in IDA's microcode at early maturity
    levels.  The libobfuscated sample contains OLLVM-flattened functions
    whose switch dispatchers produce m_jtbl blocks.
"""
from __future__ import annotations

import os
import platform
from typing import TYPE_CHECKING

import pytest

import ida_hexrays
import idaapi
import idc

from d810.hexrays.cfg_utils import convert_jtbl_to_goto, _serial_in_predset

if TYPE_CHECKING:
    pass


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
        ea = idc.get_name_ea_simple("_" + name)
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


def find_jtbl_blocks(mba):
    """Find all blocks whose tail instruction is m_jtbl.

    Returns list of (block_serial, block) tuples.
    """
    candidates = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None or blk.tail is None:
            continue
        if blk.tail.opcode == ida_hexrays.m_jtbl:
            candidates.append((i, blk))
    return candidates


def collect_jtbl_case_targets(blk):
    """Collect the set of case target serials from an m_jtbl block's mcases_t.

    Returns a set of block serial ints, or an empty set if the operand
    structure is unexpected.
    """
    tail = blk.tail
    if tail is None or tail.opcode != ida_hexrays.m_jtbl:
        return set()
    if tail.r is None or tail.r.t != ida_hexrays.mop_c:
        return set()
    cases = tail.r.c
    if cases is None:
        return set()
    targets = cases.targets
    result = set()
    for j in range(targets.size()):
        result.add(targets[j])
    return result


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


# ---------------------------------------------------------------------------
# Test class: Discovery -- verify we can find m_jtbl blocks in real microcode
# ---------------------------------------------------------------------------


class TestJtblBlockDiscovery:
    """Verify that real microcode from flattened functions contains m_jtbl blocks.

    These tests confirm that the libobfuscated binary produces microcode
    blocks with m_jtbl tail instructions at early maturity levels, which is
    a prerequisite for the conversion tests below.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_gen_microcode_produces_jtbl_blocks(self, libobfuscated_setup):
        """Verify that flattened functions produce m_jtbl blocks at early maturity."""
        # These flattened functions use switch-based dispatch which produces m_jtbl
        test_functions = [
            "while_switch_flattened",
            "test_function_ollvm_fla_bcf_sub",
        ]

        total_jtbl_blocks = 0
        for func_name in test_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                continue

            # Try early maturities where jtbl hasn't been optimized away
            for mat_name, maturity in [
                ("MMAT_PREOPTIMIZED", ida_hexrays.MMAT_PREOPTIMIZED),
                ("MMAT_LOCOPT", ida_hexrays.MMAT_LOCOPT),
                ("MMAT_CALLS", ida_hexrays.MMAT_CALLS),
            ]:
                mba = gen_microcode_at_maturity(func_ea, maturity)
                if mba is None:
                    continue

                jtbl_blocks = find_jtbl_blocks(mba)
                total_jtbl_blocks += len(jtbl_blocks)

                if jtbl_blocks:
                    print(
                        f"\n  {func_name} @ {mat_name}: "
                        f"{len(jtbl_blocks)} m_jtbl block(s) found "
                        f"(out of {mba.qty} total blocks)"
                    )
                    for serial, blk in jtbl_blocks:
                        targets = collect_jtbl_case_targets(blk)
                        succ_list = [x for x in blk.succset]
                        print(
                            f"    Block {serial}: "
                            f"case_targets={targets}, succset={succ_list}"
                        )

        # We expect at least one m_jtbl block across all tested functions
        assert total_jtbl_blocks > 0, (
            "Expected to find at least one m_jtbl block in flattened functions. "
            "The switch dispatcher should produce m_jtbl at early maturity levels."
        )

    @pytest.mark.ida_required
    def test_jtbl_block_has_valid_mcases(self, libobfuscated_setup):
        """Verify that m_jtbl blocks have valid mcases_t with case targets."""
        func_ea = get_func_ea("while_switch_flattened")
        if func_ea == idaapi.BADADDR:
            func_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
        if func_ea == idaapi.BADADDR:
            pytest.skip("No flattened function found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_LOCOPT)
        if mba is None:
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        jtbl_blocks = find_jtbl_blocks(mba)
        if not jtbl_blocks:
            pytest.skip("No m_jtbl blocks found at this maturity")

        serial, blk = jtbl_blocks[0]
        tail = blk.tail

        # Verify the mcases_t structure
        assert tail.r is not None, "m_jtbl should have r operand"
        assert tail.r.t == ida_hexrays.mop_c, (
            f"m_jtbl r operand should be mop_c, got {tail.r.t}"
        )
        assert tail.r.c is not None, "mcases_t should not be None"

        targets = tail.r.c.targets
        n = targets.size()
        assert n > 0, "mcases_t should have at least one case target"

        print(f"\n  Block {serial}: {n} case target(s)")
        for j in range(n):
            target_serial = targets[j]
            assert 0 <= target_serial < mba.qty, (
                f"Case target {target_serial} out of range [0, {mba.qty})"
            )
            print(f"    case[{j}] -> block {target_serial}")


# ---------------------------------------------------------------------------
# Test class: Conversion -- exercise convert_jtbl_to_goto on real microcode
# ---------------------------------------------------------------------------


class TestConvertJtblToGoto:
    """System tests for convert_jtbl_to_goto() using real IDA Pro microcode.

    These tests generate real microcode from flattened functions, find blocks
    with m_jtbl tail instructions, and call convert_jtbl_to_goto() to verify
    the CFG transformation.
    """

    binary_name = _get_default_binary()

    def _find_first_jtbl_mba(self):
        """Find the first MBA containing at least one m_jtbl block.

        Tries multiple functions and maturity levels.
        Returns (mba, jtbl_blocks) or skips the test.
        """
        test_functions = [
            "while_switch_flattened",
            "test_function_ollvm_fla_bcf_sub",
        ]
        maturities = [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
        ]

        for func_name in test_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                continue
            for maturity in maturities:
                mba = gen_microcode_at_maturity(func_ea, maturity)
                if mba is None:
                    continue
                jtbl_blocks = find_jtbl_blocks(mba)
                if jtbl_blocks:
                    return mba, jtbl_blocks
        pytest.skip("No m_jtbl blocks found in any tested function/maturity")

    @pytest.mark.ida_required
    def test_converts_opcode_to_goto(self, libobfuscated_setup):
        """Verify that convert_jtbl_to_goto changes the opcode from m_jtbl to m_goto."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        # Pick a valid target from the existing case targets
        old_targets = collect_jtbl_case_targets(blk)
        new_target = next(iter(old_targets)) if old_targets else blk.succset[0]

        assert blk.tail.opcode == ida_hexrays.m_jtbl
        result = convert_jtbl_to_goto(blk, new_target, mba)

        assert result is True, "convert_jtbl_to_goto should return True"
        assert blk.tail.opcode == ida_hexrays.m_goto, (
            f"Opcode should be m_goto after conversion, got {blk.tail.opcode}"
        )
        print(f"\n  Block {serial}: opcode changed m_jtbl -> m_goto")

    @pytest.mark.ida_required
    def test_sets_l_operand_to_blkref(self, libobfuscated_setup):
        """Verify that l operand is set to a block reference of the new target."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        old_targets = collect_jtbl_case_targets(blk)
        new_target = next(iter(old_targets)) if old_targets else blk.succset[0]

        convert_jtbl_to_goto(blk, new_target, mba)

        assert blk.tail.l.t == ida_hexrays.mop_b, (
            f"l operand should be mop_b (block ref), got {blk.tail.l.t}"
        )
        assert blk.tail.l.b == new_target, (
            f"l operand block ref should be {new_target}, got {blk.tail.l.b}"
        )
        print(f"\n  Block {serial}: l operand = blkref({new_target})")

    @pytest.mark.ida_required
    def test_succset_has_single_entry(self, libobfuscated_setup):
        """Verify that succset contains only the new target after conversion."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        old_targets = collect_jtbl_case_targets(blk)
        old_succ = [x for x in blk.succset]
        new_target = next(iter(old_targets)) if old_targets else old_succ[0]

        convert_jtbl_to_goto(blk, new_target, mba)

        succ_list = [x for x in blk.succset]
        assert len(succ_list) == 1, (
            f"succset should have exactly 1 entry after conversion, "
            f"got {len(succ_list)}: {succ_list}"
        )
        assert succ_list[0] == new_target, (
            f"succset[0] should be {new_target}, got {succ_list[0]}"
        )
        print(
            f"\n  Block {serial}: succset changed from {old_succ} to {succ_list}"
        )

    @pytest.mark.ida_required
    def test_predsets_updated_correctly(self, libobfuscated_setup):
        """Verify that old targets' predsets are cleaned and new target's predset is updated."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        old_targets = collect_jtbl_case_targets(blk)
        # Pick a target that IS in old_targets so we can verify predset wiring
        new_target = next(iter(old_targets)) if old_targets else blk.succset[0]

        # Record old predsets for targets that will be removed
        removed_targets = old_targets - {new_target}
        old_predsets = {}
        for tgt in removed_targets:
            if 0 <= tgt < mba.qty:
                tgt_blk = mba.get_mblock(tgt)
                old_predsets[tgt] = [x for x in tgt_blk.predset]

        convert_jtbl_to_goto(blk, new_target, mba)

        # Verify blk.serial is in new target's predset
        if 0 <= new_target < mba.qty:
            dst_blk = mba.get_mblock(new_target)
            assert _serial_in_predset(dst_blk, blk.serial), (
                f"Block {blk.serial} should be in block {new_target}'s predset"
            )
            print(
                f"\n  Block {new_target}: predset contains {blk.serial} (correct)"
            )

        # Verify blk.serial is NOT in removed targets' predsets
        for tgt in removed_targets:
            if 0 <= tgt < mba.qty:
                tgt_blk = mba.get_mblock(tgt)
                assert not _serial_in_predset(tgt_blk, blk.serial), (
                    f"Block {blk.serial} should NOT be in block {tgt}'s predset "
                    f"after conversion"
                )
                print(
                    f"  Block {tgt}: predset no longer contains {blk.serial} (correct)"
                )

    @pytest.mark.ida_required
    def test_block_type_set_to_blt_1way(self, libobfuscated_setup):
        """Verify that block type is set to BLT_1WAY after conversion."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        old_targets = collect_jtbl_case_targets(blk)
        new_target = next(iter(old_targets)) if old_targets else blk.succset[0]

        convert_jtbl_to_goto(blk, new_target, mba)

        assert blk.type == ida_hexrays.BLT_1WAY, (
            f"Block type should be BLT_1WAY after conversion, got {blk.type}"
        )
        print(f"\n  Block {serial}: type = BLT_1WAY")

    @pytest.mark.ida_required
    def test_r_and_d_operands_erased(self, libobfuscated_setup):
        """Verify that r and d operands are erased after conversion."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        old_targets = collect_jtbl_case_targets(blk)
        new_target = next(iter(old_targets)) if old_targets else blk.succset[0]

        convert_jtbl_to_goto(blk, new_target, mba)

        # After erase(), operand type should be mop_z (zero/empty)
        assert blk.tail.r.t == ida_hexrays.mop_z, (
            f"r operand should be mop_z after erase, got {blk.tail.r.t}"
        )
        assert blk.tail.d.t == ida_hexrays.mop_z, (
            f"d operand should be mop_z after erase, got {blk.tail.d.t}"
        )
        print(f"\n  Block {serial}: r and d operands erased (mop_z)")

    @pytest.mark.ida_required
    def test_ea_set_to_entry_ea(self, libobfuscated_setup):
        """Verify that the instruction EA is set to mba.entry_ea (INTERR 50863 prevention)."""
        mba, jtbl_blocks = self._find_first_jtbl_mba()
        serial, blk = jtbl_blocks[0]

        old_targets = collect_jtbl_case_targets(blk)
        new_target = next(iter(old_targets)) if old_targets else blk.succset[0]

        convert_jtbl_to_goto(blk, new_target, mba)

        assert blk.tail.ea == mba.entry_ea, (
            f"Instruction EA should be {mba.entry_ea:#x}, got {blk.tail.ea:#x}"
        )
        print(f"\n  Block {serial}: ea = {mba.entry_ea:#x}")


# ---------------------------------------------------------------------------
# Test class: Edge cases
# ---------------------------------------------------------------------------


class TestConvertJtblToGotoEdgeCases:
    """Edge case tests for convert_jtbl_to_goto().

    These tests verify that the function correctly rejects blocks that
    do not have m_jtbl tail instructions and handles boundary conditions.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_non_jtbl_tail_returns_false(self, libobfuscated_setup):
        """Blocks whose tail is not m_jtbl should return False."""
        func_ea = get_func_ea("while_switch_flattened")
        if func_ea == idaapi.BADADDR:
            func_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
        if func_ea == idaapi.BADADDR:
            pytest.skip("No flattened function found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        non_jtbl_tested = 0
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            if blk.tail is not None and blk.tail.opcode != ida_hexrays.m_jtbl:
                result = convert_jtbl_to_goto(blk, 0, mba)
                assert result is False, (
                    f"Block {i} with opcode {blk.tail.opcode} should return False"
                )
                non_jtbl_tested += 1

        print(f"\n  Tested {non_jtbl_tested} non-jtbl blocks, all returned False")
        assert non_jtbl_tested > 0, "Expected at least one non-jtbl block"

    @pytest.mark.ida_required
    def test_null_tail_returns_false(self, libobfuscated_setup):
        """Blocks with None tail should return False."""
        func_ea = get_func_ea("while_switch_flattened")
        if func_ea == idaapi.BADADDR:
            func_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
        if func_ea == idaapi.BADADDR:
            pytest.skip("No flattened function found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        null_tail_tested = 0
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            if blk.tail is None:
                result = convert_jtbl_to_goto(blk, 0, mba)
                assert result is False, (
                    f"Block {i} with None tail should return False"
                )
                null_tail_tested += 1

        if null_tail_tested == 0:
            # IDA may not produce blocks with None tails at this maturity;
            # this is acceptable -- the code path is still valid.
            print("\n  No blocks with None tail found (acceptable)")
        else:
            print(f"\n  Tested {null_tail_tested} blocks with None tail, all returned False")

    @pytest.mark.ida_required
    def test_does_not_crash_on_any_block(self, libobfuscated_setup):
        """Verify convert_jtbl_to_goto does not crash on any block.

        Robustness test: call on every block (including non-jtbl ones) to
        verify it handles all real microcode gracefully without segfault.
        """
        test_functions = [
            "while_switch_flattened",
            "test_function_ollvm_fla_bcf_sub",
        ]

        for func_name in test_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                continue

            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is None:
                continue

            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                if blk is None:
                    continue
                try:
                    # For non-jtbl blocks this returns False immediately.
                    # For jtbl blocks, target 0 is a valid block serial.
                    convert_jtbl_to_goto(blk, 0, mba)
                except Exception as e:
                    pytest.fail(
                        f"convert_jtbl_to_goto crashed on {func_name} block {i}: "
                        f"{type(e).__name__}: {e}"
                    )

            print(f"\n  {func_name}: all {mba.qty} blocks processed without crash")


# ---------------------------------------------------------------------------
# Test class: _serial_in_predset helper
# ---------------------------------------------------------------------------


class TestSerialInPredset:
    """Tests for the _serial_in_predset() helper function.

    Uses real mblock_t objects to verify predset membership checks.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_finds_existing_predecessor(self, libobfuscated_setup):
        """Verify _serial_in_predset returns True for known predecessors."""
        func_ea = get_func_ea("while_switch_flattened")
        if func_ea == idaapi.BADADDR:
            func_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
        if func_ea == idaapi.BADADDR:
            pytest.skip("No flattened function found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        tested = 0
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            pred_list = [x for x in blk.predset]
            for pred_serial in pred_list:
                assert _serial_in_predset(blk, pred_serial) is True, (
                    f"Block {i}: {pred_serial} is in predset but "
                    f"_serial_in_predset returned False"
                )
                tested += 1

        assert tested > 0, "Expected to test at least one predecessor"
        print(f"\n  Tested {tested} predset memberships, all correct")

    @pytest.mark.ida_required
    def test_rejects_non_predecessor(self, libobfuscated_setup):
        """Verify _serial_in_predset returns False for serials not in predset."""
        func_ea = get_func_ea("while_switch_flattened")
        if func_ea == idaapi.BADADDR:
            func_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
        if func_ea == idaapi.BADADDR:
            pytest.skip("No flattened function found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        tested = 0
        for i in range(1, mba.qty - 1):  # skip entry/exit blocks
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            pred_set = set(x for x in blk.predset)
            # Use a serial that is NOT in the predset
            for candidate in range(mba.qty):
                if candidate not in pred_set:
                    assert _serial_in_predset(blk, candidate) is False, (
                        f"Block {i}: {candidate} is NOT in predset but "
                        f"_serial_in_predset returned True"
                    )
                    tested += 1
                    break  # one per block is enough

        assert tested > 0, "Expected to test at least one non-predecessor"
        print(f"\n  Tested {tested} non-predset memberships, all correct")
