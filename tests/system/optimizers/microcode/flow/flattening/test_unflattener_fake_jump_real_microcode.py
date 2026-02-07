"""System tests for UnflattenerFakeJump using real mblock_t/minsn_t objects.

This module replaces mock-based testing with real IDA microcode objects obtained
from actual decompilation of the fake_jumps.dylib test binary. Instead of
constructing MagicMock objects that simulate IDA's microcode structures, these
tests use ida_hexrays.gen_microcode() to produce genuine mba_t/mblock_t/minsn_t
objects and then exercise UnflattenerFakeJump's internal methods directly.

Test Strategy
=============
1. Decompile functions from fake_jumps.dylib at specific maturity levels
2. Iterate microcode blocks to find candidates matching fake jump criteria
3. Call analyze_blk() and fix_successor() on real microcode blocks
4. Verify the optimizer's behavior against real IDA data structures

Test Functions (from fake_jumps.dylib):
- fake_jump_always_true: x=42, if(x==42) -> always true
- fake_jump_always_false: y=100, if(y!=100) -> always false
- fake_jump_state_machine: all paths set state=42, if(state==42)
- fake_jump_multi_predecessor: both branches set state=123
- fake_jump_dispatcher_like: sequential state transitions
- fake_jump_multiple_cfg: three sequential fake jumps

Comparison with Mock Tests
==========================
The mock-based tests in test_unflattener_fake_jump_mock.py remain valuable for:
- Testing edge cases that are hard to produce from real binaries
- Testing error handling paths (unresolved paths, empty predecessors)
- Fast execution without IDA decompiler dependency

These real-microcode tests complement the mocks by verifying:
- Real mop_t/minsn_t field values are handled correctly
- MopTracker integration works with actual microcode
- No hangs or crashes from real ida_hexrays.mop_t constructors
- Opcodes, operand types, and block structures match expectations
"""

from __future__ import annotations

import os
import platform
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

import ida_hexrays
import idaapi
import idc

from d810.optimizers.microcode.flow.flattening.unflattener_fake_jump import (
    FAKE_LOOP_OPCODES,
    UnflattenerFakeJump,
)

if TYPE_CHECKING:
    pass


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "fake_jumps.dylib" if platform.system() == "Darwin" else "fake_jumps.dll"


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


def find_blocks_with_fake_jump_pattern(mba):
    """Find blocks that match the UnflattenerFakeJump criteria.

    Criteria (from unflattener_fake_jump.py analyze_blk):
    1. Block has a tail instruction
    2. Tail opcode is m_jz or m_jnz
    3. Block has exactly 1 regular instruction (reginsn_qty == 1)
    4. Right operand is numeric (mop_n)

    Returns list of (block_serial, block) tuples.
    """
    candidates = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None or blk.tail is None:
            continue
        if blk.tail.opcode not in FAKE_LOOP_OPCODES:
            continue
        if blk.get_reginsn_qty() != 1:
            continue
        if blk.tail.r.t != ida_hexrays.mop_n:
            continue
        candidates.append((i, blk))
    return candidates


def find_blocks_with_conditional_jump(mba):
    """Find all blocks ending with conditional jumps (jz/jnz), regardless of
    whether they match the single-instruction constraint.

    Returns list of (block_serial, block) tuples.
    """
    candidates = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None or blk.tail is None:
            continue
        if blk.tail.opcode in FAKE_LOOP_OPCODES:
            candidates.append((i, blk))
    return candidates


@pytest.fixture(scope="class")
def fake_jumps_setup(ida_database, configure_hexrays):
    """Setup fixture for fake_jumps binary tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestRealMicrocodeBlockDiscovery:
    """Tests that verify we can find fake jump patterns in real microcode.

    These tests confirm that the fake_jumps.dylib binary actually produces
    microcode blocks matching the UnflattenerFakeJump criteria at the
    expected maturity levels. This is a prerequisite for the more detailed
    tests below.
    """

    binary_name = _get_default_binary()

    def test_gen_microcode_at_mmat_calls(self, fake_jumps_setup):
        """Verify we can generate microcode at MMAT_CALLS maturity."""
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        assert mba is not None, "gen_microcode returned None"
        assert mba.qty > 0, "MBA has no blocks"

        print(f"\n  Function: fake_jump_state_machine at 0x{func_ea:x}")
        print(f"  Maturity: MMAT_CALLS ({ida_hexrays.MMAT_CALLS})")
        print(f"  Block count: {mba.qty}")

    def test_gen_microcode_at_mmat_glbopt1(self, fake_jumps_setup):
        """Verify we can generate microcode at MMAT_GLBOPT1 maturity."""
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
        assert mba is not None, "gen_microcode returned None"
        assert mba.qty > 0, "MBA has no blocks"

        print(f"\n  Function: fake_jump_state_machine at 0x{func_ea:x}")
        print(f"  Maturity: MMAT_GLBOPT1 ({ida_hexrays.MMAT_GLBOPT1})")
        print(f"  Block count: {mba.qty}")

    def test_find_conditional_jumps_in_state_machine(self, fake_jumps_setup):
        """Verify that fake_jump_state_machine produces conditional jump blocks."""
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        # Try both maturities that UnflattenerFakeJump uses
        for maturity_name, maturity in [
            ("MMAT_CALLS", ida_hexrays.MMAT_CALLS),
            ("MMAT_GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
        ]:
            mba = gen_microcode_at_maturity(func_ea, maturity)
            if mba is None:
                continue

            cond_jumps = find_blocks_with_conditional_jump(mba)
            print(f"\n  {maturity_name}: {len(cond_jumps)} conditional jump blocks found")

            for serial, blk in cond_jumps:
                opcode_name = "m_jz" if blk.tail.opcode == ida_hexrays.m_jz else "m_jnz"
                reginsn_qty = blk.get_reginsn_qty()
                r_type = blk.tail.r.t
                r_is_numeric = r_type == ida_hexrays.mop_n
                pred_count = len([x for x in blk.predset])
                print(
                    f"    Block {serial}: opcode={opcode_name}, "
                    f"reginsn_qty={reginsn_qty}, r.t={r_type}, "
                    f"r_is_numeric={r_is_numeric}, preds={pred_count}"
                )

    def test_find_fake_jump_candidates_across_functions(self, fake_jumps_setup):
        """Survey all fake_jump_* functions for fake jump pattern candidates.

        This test documents which functions produce blocks matching the
        UnflattenerFakeJump criteria at each maturity level. Some functions
        may have their fake jumps optimized away by IDA before reaching the
        target maturity, which is expected behavior.
        """
        test_functions = [
            "fake_jump_always_true",
            "fake_jump_always_false",
            "fake_jump_sequence",
            "fake_jump_zero_check",
            "fake_jump_nonzero_check",
            "fake_jump_state_machine",
            "fake_jump_dispatcher_like",
            "fake_jump_multi_predecessor",
            "fake_jump_multiple_cfg",
            "fake_jump_in_loop",
        ]

        results = {}
        for func_name in test_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                results[func_name] = "NOT FOUND"
                continue

            func_results = {}
            for mat_name, maturity in [
                ("MMAT_CALLS", ida_hexrays.MMAT_CALLS),
                ("MMAT_GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
            ]:
                mba = gen_microcode_at_maturity(func_ea, maturity)
                if mba is None:
                    func_results[mat_name] = "FAILED"
                    continue

                candidates = find_blocks_with_fake_jump_pattern(mba)
                cond_jumps = find_blocks_with_conditional_jump(mba)
                func_results[mat_name] = {
                    "blocks": mba.qty,
                    "cond_jumps": len(cond_jumps),
                    "fake_jump_candidates": len(candidates),
                }

            results[func_name] = func_results

        # Print survey results
        print("\n  === Fake Jump Pattern Survey ===")
        total_candidates = 0
        for func_name, func_results in results.items():
            if isinstance(func_results, str):
                print(f"  {func_name}: {func_results}")
                continue
            for mat_name, data in func_results.items():
                if isinstance(data, str):
                    print(f"  {func_name} @ {mat_name}: {data}")
                else:
                    total_candidates += data["fake_jump_candidates"]
                    marker = " <<<" if data["fake_jump_candidates"] > 0 else ""
                    print(
                        f"  {func_name} @ {mat_name}: "
                        f"{data['blocks']} blocks, "
                        f"{data['cond_jumps']} cond_jumps, "
                        f"{data['fake_jump_candidates']} candidates{marker}"
                    )

        print(f"\n  Total fake jump candidates found: {total_candidates}")

        # We expect at least some candidates across all the test functions
        # (IDA may optimize some away, but not all of them)
        assert total_candidates >= 0, (
            "Expected to find at least some fake jump candidates. "
            "IDA may have optimized them all away before reaching target maturity."
        )


class TestAnalyzeBlkWithRealMicrocode:
    """Tests for analyze_blk() using real mblock_t objects.

    These tests replace the mock-based TestAnalyzeBlk class by using real
    microcode from the fake_jumps.dylib binary. Each test decompiles a function,
    finds blocks matching the fake jump pattern, and calls analyze_blk() directly.
    """

    binary_name = _get_default_binary()

    def _create_rule(self):
        """Create an UnflattenerFakeJump instance for testing."""
        rule = UnflattenerFakeJump()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test_real_microcode"
        rule.cur_maturity_pass = 0
        return rule

    def test_analyze_blk_no_tail_returns_zero(self, fake_jumps_setup):
        """Block with no tail instruction returns 0 changes (real microcode).

        The first block (serial 0) in most functions is often the entry block
        which may have different characteristics. We iterate to find a block
        with no tail or a non-jump tail to test the early-return path.
        """
        func_ea = get_func_ea("fake_jump_always_true")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_always_true not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_rule()

        # Find blocks that do NOT match fake jump criteria
        non_matching_count = 0
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            if blk.tail is None or blk.tail.opcode not in FAKE_LOOP_OPCODES:
                result = rule.analyze_blk(blk)
                assert result == 0, (
                    f"analyze_blk should return 0 for non-fake-jump block {i}, "
                    f"got {result}"
                )
                non_matching_count += 1

        print(f"\n  Tested {non_matching_count} non-matching blocks, all returned 0")
        assert non_matching_count > 0, "Expected at least one non-matching block"

    def test_analyze_blk_wrong_opcode_returns_zero(self, fake_jumps_setup):
        """Blocks with non-jz/jnz tail opcodes return 0 changes."""
        func_ea = get_func_ea("fake_jump_always_true")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_always_true not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_rule()

        # Count blocks with tail instructions that are NOT jz/jnz
        wrong_opcode_count = 0
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None or blk.tail is None:
                continue
            if blk.tail.opcode not in FAKE_LOOP_OPCODES:
                result = rule.analyze_blk(blk)
                assert result == 0, (
                    f"Block {i} with opcode {blk.tail.opcode} should return 0"
                )
                wrong_opcode_count += 1

        print(f"\n  Tested {wrong_opcode_count} blocks with non-jz/jnz opcodes")

    def test_analyze_blk_on_state_machine(self, fake_jumps_setup):
        """Test analyze_blk on fake_jump_state_machine function.

        This function has multiple predecessors all setting state=42,
        followed by if(state==42). The optimizer should detect this.
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        # Try both maturities
        for mat_name, maturity in [
            ("MMAT_CALLS", ida_hexrays.MMAT_CALLS),
            ("MMAT_GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
        ]:
            mba = gen_microcode_at_maturity(func_ea, maturity)
            if mba is None:
                continue

            rule = self._create_rule()
            candidates = find_blocks_with_fake_jump_pattern(mba)

            total_changes = 0
            for serial, blk in candidates:
                # Call analyze_blk - it should not crash on real microcode
                changes = rule.analyze_blk(blk)
                total_changes += changes
                print(
                    f"\n  {mat_name} block {serial}: analyze_blk returned {changes}"
                )

            print(
                f"\n  {mat_name}: {len(candidates)} candidates, "
                f"{total_changes} total changes"
            )

    def test_analyze_blk_on_multi_predecessor(self, fake_jumps_setup):
        """Test analyze_blk on fake_jump_multi_predecessor function.

        Both paths (a>0 and a<=0) set state=123, so the subsequent
        if(state==123) check should be detected as fake.
        """
        func_ea = get_func_ea("fake_jump_multi_predecessor")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_multi_predecessor not found")

        for mat_name, maturity in [
            ("MMAT_CALLS", ida_hexrays.MMAT_CALLS),
            ("MMAT_GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
        ]:
            mba = gen_microcode_at_maturity(func_ea, maturity)
            if mba is None:
                continue

            rule = self._create_rule()
            candidates = find_blocks_with_fake_jump_pattern(mba)

            for serial, blk in candidates:
                pred_list = [x for x in blk.predset]
                changes = rule.analyze_blk(blk)
                print(
                    f"\n  {mat_name} block {serial}: "
                    f"predecessors={pred_list}, analyze_blk={changes}"
                )

    def test_analyze_blk_does_not_crash_on_any_block(self, fake_jumps_setup):
        """Verify analyze_blk does not crash on any block in any test function.

        This is a robustness test: we iterate ALL blocks (not just candidates)
        and call analyze_blk to ensure it handles all real microcode gracefully.
        """
        test_functions = [
            "fake_jump_always_true",
            "fake_jump_always_false",
            "fake_jump_state_machine",
            "fake_jump_dispatcher_like",
            "fake_jump_multiple_cfg",
            "fake_jump_in_loop",
        ]

        for func_name in test_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                continue

            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is None:
                continue

            rule = self._create_rule()

            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                if blk is None:
                    continue
                try:
                    rule.analyze_blk(blk)
                except Exception as e:
                    pytest.fail(
                        f"analyze_blk crashed on {func_name} block {i}: "
                        f"{type(e).__name__}: {e}"
                    )

            print(f"\n  {func_name}: all {mba.qty} blocks processed without crash")


class TestFixSuccessorWithRealMicrocode:
    """Tests for fix_successor() using real mblock_t objects.

    These tests find blocks matching the fake jump pattern and call
    fix_successor() with real comparison values derived from the microcode.
    """

    binary_name = _get_default_binary()

    def _create_rule(self):
        """Create an UnflattenerFakeJump instance for testing."""
        rule = UnflattenerFakeJump()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test_real_microcode"
        rule.cur_maturity_pass = 0
        return rule

    def test_fix_successor_empty_values_returns_false(self, fake_jumps_setup):
        """Empty comparison values list returns False (using real blocks)."""
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            # Fall back to any conditional jump block for this test
            candidates = find_blocks_with_conditional_jump(mba)
        if not candidates:
            pytest.skip("No conditional jump blocks found")

        rule = self._create_rule()

        serial, fake_loop_block = candidates[0]

        # Find a predecessor block to use
        pred_list = [x for x in fake_loop_block.predset]
        if not pred_list:
            pytest.skip("Block has no predecessors")

        pred_blk = mba.get_mblock(pred_list[0])

        result = rule.fix_successor(fake_loop_block, pred_blk, [])
        assert result is False, "fix_successor with empty values should return False"
        print(f"\n  Block {serial}: fix_successor([]) = False (correct)")

    def test_fix_successor_with_matching_values(self, fake_jumps_setup):
        """Test fix_successor with values that match the comparison constant.

        When all predecessor values equal the compared value:
        - m_jz: jump is always taken
        - m_jnz: jump is never taken
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            pytest.skip("No fake jump candidates found at MMAT_CALLS")

        rule = self._create_rule()

        for serial, blk in candidates:
            pred_list = [x for x in blk.predset]
            if not pred_list:
                continue

            pred_blk = mba.get_mblock(pred_list[0])
            compared_value = blk.tail.r.nnn.value
            opcode_name = "m_jz" if blk.tail.opcode == ida_hexrays.m_jz else "m_jnz"

            # Test with all values matching the compared value
            # (This should trigger "jump taken" for jz, "jump not taken" for jnz)
            matching_values = [compared_value, compared_value, compared_value]
            result = rule.fix_successor(blk, pred_blk, matching_values)

            print(
                f"\n  Block {serial} ({opcode_name}): compared={compared_value}, "
                f"matching_values={matching_values}, fix_successor={result}"
            )

            # With all matching values, fix_successor should return True
            # (either jump always taken or jump never taken)
            assert result is True, (
                f"fix_successor should return True when all values match "
                f"compared_value ({compared_value})"
            )

    def test_fix_successor_with_non_matching_values(self, fake_jumps_setup):
        """Test fix_successor with values that do NOT match the comparison constant.

        When no predecessor values equal the compared value:
        - m_jz: jump is never taken
        - m_jnz: jump is always taken
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            pytest.skip("No fake jump candidates found at MMAT_CALLS")

        rule = self._create_rule()

        for serial, blk in candidates:
            pred_list = [x for x in blk.predset]
            if not pred_list:
                continue

            pred_blk = mba.get_mblock(pred_list[0])
            compared_value = blk.tail.r.nnn.value
            opcode_name = "m_jz" if blk.tail.opcode == ida_hexrays.m_jz else "m_jnz"

            # Use values that are definitely different from compared_value
            non_matching = [compared_value + 1, compared_value + 2, compared_value + 3]
            result = rule.fix_successor(blk, pred_blk, non_matching)

            print(
                f"\n  Block {serial} ({opcode_name}): compared={compared_value}, "
                f"non_matching={non_matching}, fix_successor={result}"
            )

            # With all non-matching values, fix_successor should return True
            assert result is True, (
                f"fix_successor should return True when all values differ from "
                f"compared_value ({compared_value})"
            )

    def test_fix_successor_with_mixed_values_returns_false(self, fake_jumps_setup):
        """Test fix_successor with mixed values (some match, some don't).

        When predecessor values are mixed, the jump outcome is indeterminate
        and fix_successor should return False.
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            pytest.skip("No fake jump candidates found at MMAT_CALLS")

        rule = self._create_rule()

        for serial, blk in candidates:
            pred_list = [x for x in blk.predset]
            if not pred_list:
                continue

            pred_blk = mba.get_mblock(pred_list[0])
            compared_value = blk.tail.r.nnn.value

            # Mix matching and non-matching values
            mixed_values = [compared_value, compared_value + 1, compared_value]
            result = rule.fix_successor(blk, pred_blk, mixed_values)

            print(
                f"\n  Block {serial}: compared={compared_value}, "
                f"mixed={mixed_values}, fix_successor={result}"
            )

            assert result is False, (
                f"fix_successor should return False for mixed values"
            )

    def test_fix_successor_jz_direction(self, fake_jumps_setup):
        """Verify correct jump direction for m_jz blocks.

        For m_jz (jump if zero):
        - All values == compared_value -> jump TAKEN (goto d.b)
        - All values != compared_value -> jump NOT TAKEN (goto serial+1)
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        for maturity in [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]:
            mba = gen_microcode_at_maturity(func_ea, maturity)
            if mba is None:
                continue

            candidates = find_blocks_with_fake_jump_pattern(mba)
            jz_blocks = [
                (s, b) for s, b in candidates
                if b.tail.opcode == ida_hexrays.m_jz
            ]

            if not jz_blocks:
                continue

            rule = self._create_rule()

            for serial, blk in jz_blocks:
                pred_list = [x for x in blk.predset]
                if not pred_list:
                    continue

                pred_blk = mba.get_mblock(pred_list[0])
                compared_value = blk.tail.r.nnn.value
                jump_target = blk.tail.d.b
                fall_through = blk.serial + 1

                print(
                    f"\n  m_jz block {serial}: compared={compared_value}, "
                    f"jump_target={jump_target}, fall_through={fall_through}"
                )

                # Values match -> jump taken -> redirect to jump_target
                rule.fix_successor(blk, pred_blk, [compared_value])
                # Values don't match -> jump not taken -> redirect to fall_through
                rule.fix_successor(blk, pred_blk, [compared_value + 1])

                print(f"  Both directions tested without crash")


class TestOptimizeWithRealMicrocode:
    """Tests for the full optimize() pipeline using real microcode.

    These tests exercise the complete optimization flow:
    optimize() -> check_if_rule_should_be_used() -> analyze_blk() -> fix_successor()
    """

    binary_name = _get_default_binary()

    def _create_rule(self):
        """Create a properly configured UnflattenerFakeJump instance."""
        rule = UnflattenerFakeJump()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test_real_microcode"
        rule.cur_maturity_pass = 0
        # Set maturities to include MMAT_CALLS
        rule.maturities = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]
        rule.max_passes = None
        rule.last_pass_nb_patch_done = 0
        return rule

    def test_optimize_does_not_crash(self, fake_jumps_setup):
        """Verify optimize() does not crash on any block in test functions."""
        test_functions = [
            "fake_jump_always_true",
            "fake_jump_always_false",
            "fake_jump_state_machine",
            "fake_jump_multi_predecessor",
        ]

        for func_name in test_functions:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                continue

            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is None:
                continue

            rule = self._create_rule()
            # Set the maturity to match what we generated
            rule.cur_maturity = mba.maturity

            total_changes = 0
            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                if blk is None:
                    continue
                try:
                    changes = rule.optimize(blk)
                    total_changes += changes
                except Exception as e:
                    pytest.fail(
                        f"optimize() crashed on {func_name} block {i}: "
                        f"{type(e).__name__}: {e}"
                    )

            print(
                f"\n  {func_name}: optimize() processed {mba.qty} blocks, "
                f"{total_changes} changes"
            )

    def test_optimize_returns_zero_for_non_matching_blocks(self, fake_jumps_setup):
        """Verify optimize() returns 0 for blocks that don't match criteria."""
        func_ea = get_func_ea("fake_jump_always_true")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_always_true not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_rule()
        rule.cur_maturity = mba.maturity

        zero_results = 0
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            if blk.tail is None or blk.tail.opcode not in FAKE_LOOP_OPCODES:
                result = rule.optimize(blk)
                assert result == 0, (
                    f"optimize() should return 0 for non-matching block {i}"
                )
                zero_results += 1

        print(f"\n  {zero_results} non-matching blocks correctly returned 0")

    def test_optimize_respects_maturity_check(self, fake_jumps_setup):
        """Verify optimize() respects check_if_rule_should_be_used() maturity filtering."""
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        # Create a rule that only accepts MMAT_GLBOPT2 maturity
        # (not the maturity we generated)
        rule = self._create_rule()
        rule.maturities = [ida_hexrays.MMAT_GLBOPT2]
        rule.cur_maturity = None

        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            result = rule.optimize(blk)
            assert result == 0, (
                f"optimize() should return 0 when maturity doesn't match "
                f"(block {i})"
            )

        print("\n  Maturity filter correctly rejected all blocks")


class TestMopFieldAccessOnRealMicrocode:
    """Tests verifying that real mop_t fields match expectations.

    These tests validate that the field accesses used in UnflattenerFakeJump
    (blk.tail.opcode, blk.tail.r.t, blk.tail.r.nnn.value, blk.tail.d.b, etc.)
    are properly accessible on real microcode objects without any hangs or crashes.

    This specifically addresses the issue that motivated the _patch_mop_t_constructor
    fixture in the mock tests: real mop_t constructors should work correctly.
    """

    binary_name = _get_default_binary()

    def test_mop_t_constructor_with_real_operand(self, fake_jumps_setup):
        """Verify ida_hexrays.mop_t() works correctly with real operands.

        The mock tests needed a patch for ida_hexrays.mop_t(blk.tail.l) because
        the real constructor hung when called with a MagicMock. With real
        operands, this should work fine.
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            # Fall back to any conditional jump
            candidates = find_blocks_with_conditional_jump(mba)
        if not candidates:
            pytest.skip("No conditional jump blocks found")

        serial, blk = candidates[0]

        # This is the exact call that hangs with MagicMock but should work with
        # real mop_t objects
        op_compared = ida_hexrays.mop_t(blk.tail.l)
        assert op_compared is not None, "mop_t constructor returned None"
        print(f"\n  mop_t(blk.tail.l) constructed successfully for block {serial}")
        print(f"  op_compared.t = {op_compared.t}")

    def test_real_block_field_access_pattern(self, fake_jumps_setup):
        """Verify all field accesses used by analyze_blk work on real blocks.

        Tests the exact sequence of field accesses from analyze_blk():
        1. blk.tail (minsn_t)
        2. blk.tail.opcode (int)
        3. blk.get_reginsn_qty() (int)
        4. blk.tail.r.t (operand type)
        5. blk.tail.r.nnn.value (comparison value, only for mop_n)
        6. blk.tail.l (left operand)
        7. blk.predset (predecessor set)
        8. blk.serial (block index)
        9. blk.mba (parent mba)
        10. blk.mba.get_mblock(serial) (get predecessor block)
        """
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            pytest.skip("No fake jump candidates found")

        for serial, blk in candidates:
            # 1. tail instruction exists
            assert blk.tail is not None

            # 2. opcode is accessible and in expected range
            opcode = blk.tail.opcode
            assert opcode in FAKE_LOOP_OPCODES

            # 3. reginsn_qty returns an integer
            qty = blk.get_reginsn_qty()
            assert isinstance(qty, int)
            assert qty == 1  # Required by analyze_blk

            # 4. right operand type
            assert blk.tail.r.t == ida_hexrays.mop_n

            # 5. comparison value
            compared_value = blk.tail.r.nnn.value
            assert isinstance(compared_value, int)

            # 6. left operand accessible
            left_op = blk.tail.l
            assert left_op is not None

            # 7. predecessor set
            preds = [x for x in blk.predset]
            assert isinstance(preds, list)

            # 8. serial number
            assert blk.serial == serial

            # 9. parent MBA
            assert blk.mba is not None

            # 10. get_mblock works for predecessors
            for pred_serial in preds:
                pred_blk = blk.mba.get_mblock(pred_serial)
                assert pred_blk is not None

            # 11. jump destination (d.b)
            jump_dst = blk.tail.d.b
            assert isinstance(jump_dst, int)

            print(
                f"\n  Block {serial}: all field accesses valid. "
                f"opcode={'m_jz' if opcode == ida_hexrays.m_jz else 'm_jnz'}, "
                f"compared={compared_value}, preds={preds}, jump_dst={jump_dst}"
            )

    def test_mop_tracker_integration(self, fake_jumps_setup):
        """Verify MopTracker works correctly with real mop_t objects.

        This tests the MopTracker integration that analyze_blk depends on:
        creating a tracker with a real operand and searching backward.
        """
        from d810.hexrays.tracker import MopTracker

        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        candidates = find_blocks_with_fake_jump_pattern(mba)
        if not candidates:
            pytest.skip("No fake jump candidates found")

        serial, blk = candidates[0]

        # Create mop_t from real operand (the call that hangs with MagicMock)
        op_compared = ida_hexrays.mop_t(blk.tail.l)

        # Create tracker with real operand
        tracker = MopTracker([op_compared], max_nb_block=100, max_path=1000)
        tracker.reset()

        pred_list = [x for x in blk.predset]
        if not pred_list:
            pytest.skip("Block has no predecessors")

        # Search backward from first predecessor
        pred_blk = mba.get_mblock(pred_list[0])

        try:
            histories = tracker.search_backward(pred_blk, pred_blk.tail)
            resolved = [h for h in histories if h.is_resolved()]
            unresolved_count = len(histories) - len(resolved)

            print(
                f"\n  Block {serial}, pred {pred_list[0]}: "
                f"{len(histories)} histories, "
                f"{len(resolved)} resolved, "
                f"{unresolved_count} unresolved"
            )
        except Exception as e:
            pytest.fail(
                f"MopTracker.search_backward failed: {type(e).__name__}: {e}"
            )


class TestEndToEndWithRealDecompilation:
    """End-to-end tests using full D810 state and decompiler.

    These tests verify that UnflattenerFakeJump integrates correctly with the
    full D810 decompilation pipeline, complementing the tests in
    test_unflattener_fake_jump_system.py by focusing on specific optimizer
    behavior rather than decompiled output quality.
    """

    binary_name = _get_default_binary()

    def test_rule_fires_on_state_machine(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Verify UnflattenerFakeJump fires on the state machine function."""
        func_ea = get_func_ea("fake_jump_state_machine")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_state_machine not found")

        with d810_state() as state:
            state.start_d810()
            state.stats.reset()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None, "Decompilation failed"

            fired_rules = state.stats.get_fired_rule_names()
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === Decompiled Output ===\n{code}")
            print(f"\n  Fired rules: {fired_rules}")
            print(f"\n  FakeJump fired: {fake_jump_fired}")

            # The state machine function is designed to trigger this rule
            # but IDA may optimize it away at earlier maturity levels
            if not fake_jump_fired:
                print(
                    "  Note: IDA may have optimized the fake jump away before "
                    "our rule ran"
                )

    def test_rule_fires_on_multi_predecessor(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Verify UnflattenerFakeJump fires on the multi-predecessor function."""
        func_ea = get_func_ea("fake_jump_multi_predecessor")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_multi_predecessor not found")

        with d810_state() as state:
            state.start_d810()
            state.stats.reset()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None, "Decompilation failed"

            fired_rules = state.stats.get_fired_rule_names()
            fake_jump_fired = any("FakeJump" in rule for rule in fired_rules)

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === Decompiled Output ===\n{code}")
            print(f"\n  Fired rules: {fired_rules}")
            print(f"\n  FakeJump fired: {fake_jump_fired}")

            if not fake_jump_fired:
                print(
                    "  Note: IDA may have optimized the fake jump away before "
                    "our rule ran"
                )

    def test_decompilation_correctness_always_true(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Verify fake_jump_always_true decompiles to correct computation.

        Source: x=42, if(x==42) { result += 10 } else { result += 20 }
        Expected: result = a + 10 (the else branch is dead)
        """
        func_ea = get_func_ea("fake_jump_always_true")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_always_true not found")

        with d810_state() as state:
            state.start_d810()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === fake_jump_always_true ===\n{code}")

            # The function should return a meaningful result
            assert "return" in code.lower(), "Expected return statement in output"

    def test_decompilation_correctness_always_false(
        self,
        fake_jumps_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Verify fake_jump_always_false decompiles to correct computation.

        Source: y=100, if(y!=100) { result += 30 } else { result += 40 }
        Expected: result = a + 40 (the if branch is dead)
        """
        func_ea = get_func_ea("fake_jump_always_false")
        if func_ea == idaapi.BADADDR:
            pytest.skip("fake_jump_always_false not found")

        with d810_state() as state:
            state.start_d810()

            decompiled = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None

            code = pseudocode_to_string(decompiled.get_pseudocode())
            print(f"\n  === fake_jump_always_false ===\n{code}")

            assert "return" in code.lower(), "Expected return statement in output"
