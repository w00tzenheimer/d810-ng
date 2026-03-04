"""Tests for GotoChainRemovalPass.

This module tests the FlowGraphTransform that collapses chains of goto-only blocks.
Tests cover:
- Detection of goto-only blocks (exactly 1 m_goto instruction with mop_b operand)
- RedirectGoto emission for 1-way predecessors
- RedirectBranch emission for 2-way predecessors (CRITICAL-2)
- Rejection of empty blocks as non-goto (CRITICAL-1)
- Rejection of single non-goto instruction blocks (CRITICAL-1)
- Rejection of blocks without valid mop_b operand (CRITICAL-1 / HIGH-2)
- Last (sentinel dummy) block is skipped (HIGH-1)
- Self-loop handling
- Multi-predecessor goto blocks
- Integration with PassPipeline and InMemoryBackend
"""
from __future__ import annotations

import ida_hexrays
import pytest

from d810.cfg.graph_modification import RedirectBranch, RedirectGoto
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.cfg.pipeline import PassPipeline
from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
from d810.hexrays.mutation.passes.goto_chain_removal import GotoChainRemovalPass

from tests.system.runtime.hexrays.conftest import InMemoryBackend

# Microcode constants
_M_GOTO_OPCODE = ida_hexrays.m_goto
_MOP_B_TYPE = ida_hexrays.mop_b


def _make_goto_insn(ea: int, dest_serial: int) -> InsnSnapshot:
    """Helper: build an m_goto InsnSnapshot with a valid mop_b operand."""
    dest_mop = MopSnapshot(t=_MOP_B_TYPE, size=4, block_num=dest_serial)
    return InsnSnapshot(opcode=_M_GOTO_OPCODE, ea=ea, operands=(dest_mop,))


class TestGotoChainRemovalPass:
    """Tests for GotoChainRemovalPass transform logic."""

    def test_no_goto_blocks_returns_empty(self):
        """Pass returns empty list when no goto-only blocks exist."""
        # Create CFG: 0 -> 1 (both have multiple instructions, not goto-only)
        insn0a = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        insn0b = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(insn0a, insn0b)
        )
        insn1a = InsnSnapshot(opcode=0x03, ea=0x1010, operands=())
        insn1b = InsnSnapshot(opcode=0x04, ea=0x1014, operands=())
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=(insn1a, insn1b)
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_single_goto_chain_returns_redirect_edge(self):
        """Pass returns RedirectGoto to bypass single goto-only block."""
        # Create chain: 0 -> 10 (goto only, has m_goto insn) -> 20
        # blk0 is a 1-way predecessor
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10_goto, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        assert isinstance(mods[0], RedirectGoto)
        assert mods[0].from_serial == 0
        assert mods[0].old_target == 10
        assert mods[0].new_target == 20

    def test_self_loop_skipped(self):
        """Pass skips self-loop goto blocks."""
        # Create self-loop: 0 -> 10 (goto to itself)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Self-loop goto block (would pass _is_simple_goto_block but self-loop guard fires first)
        self_goto_insn = _make_goto_insn(ea=0x1100, dest_serial=10)
        blk10_selfloop = BlockSnapshot(
            serial=10, block_type=3, succs=(10,), preds=(0, 10),
            flags=0, start_ea=0x1100, insn_snapshots=(self_goto_insn,)
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10_selfloop},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # Self-loop is skipped, no modifications
        assert mods == []

    def test_multi_predecessor_goto_block_1way_preds(self):
        """Pass emits one RedirectGoto per 1-way predecessor."""
        # Create CFG: {0 (2way->5,10), 5 (1way->10)} -> 10 (goto only) -> 20
        # blk0 is a 2-way block so it gets RedirectBranch (tested separately)
        # blk5 is 1-way so it gets RedirectGoto
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Block 5 with instructions (not goto-only, 1-way predecessor of 10)
        insn5a = InsnSnapshot(opcode=0x01, ea=0x1050, operands=())
        insn5b = InsnSnapshot(opcode=0x02, ea=0x1054, operands=())
        blk5 = BlockSnapshot(
            serial=5, block_type=3, succs=(10,), preds=(0,),
            flags=0, start_ea=0x1050, insn_snapshots=(insn5a, insn5b)
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0, 5),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 5: blk5, 10: blk10_goto, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 2 predecessors -> 2 modifications
        assert len(mods) == 2

        # blk5 is 1-way -> RedirectGoto
        mod5 = next(m for m in mods if m.from_serial == 5)
        assert isinstance(mod5, RedirectGoto)
        assert mod5.old_target == 10
        assert mod5.new_target == 20

        # blk0 is 2-way -> RedirectBranch
        mod0 = next(m for m in mods if m.from_serial == 0)
        assert isinstance(mod0, RedirectBranch)
        assert mod0.old_target == 10
        assert mod0.new_target == 20

    def test_block_with_instructions_not_goto_only(self):
        """Block with >1 instructions is not simplified."""
        # Create CFG: 0 -> 10 (2 instructions) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Block with 2 instructions (not goto-only)
        insn10a = InsnSnapshot(opcode=0x01, ea=0x1100, operands=())
        insn10b = InsnSnapshot(opcode=0x02, ea=0x1104, operands=())
        blk10 = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(insn10a, insn10b)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # Block 10 has >1 instructions, not goto-only
        assert mods == []

    def test_2way_block_ignored_as_candidate(self):
        """2-way blocks are not eligible as simple goto blocks (2 succs, nsucc != 1)."""
        # Create CFG: 0 (2-way) -> {1, 2}
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 2-way block (nsucc=2) is not a goto-only candidate
        assert mods == []

    def test_0way_block_ignored(self):
        """0-way blocks (terminals) are ignored."""
        # Create CFG: 0 -> 1 (0-way terminal)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 0-way block (nsucc=0) is not goto-only
        assert mods == []

    def test_empty_cfg_returns_empty(self):
        """Pass handles empty CFG gracefully."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_pass_name_and_tags(self):
        """Pass has correct name and tags."""
        pass_instance = GotoChainRemovalPass()

        assert pass_instance.name == "goto_chain_removal"
        assert pass_instance.tags == frozenset({"cleanup", "topology"})

    def test_entry_block_as_goto_only(self):
        """Pass handles entry block (serial 0) that is itself a goto-only block.

        When the entry block is a pure goto (1-way, 1 m_goto instruction) it should
        be treated the same as any other goto-only block. However, entry block
        serial 0 has no predecessors in the snapshot, so the pass emits zero
        modifications for it (there is nothing to redirect from).
        This test verifies the pass does not crash and correctly handles the entry
        block when it has no predecessors, while still processing other goto-only
        blocks in the same CFG.
        """
        # Entry block 0 is goto-only (1 m_goto instruction, single successor)
        goto0 = _make_goto_insn(ea=0x1000, dest_serial=1)
        blk0_entry = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto0,)
        )
        # Block 1 is also goto-only with a predecessor (block 0)
        goto1 = _make_goto_insn(ea=0x1010, dest_serial=2)
        blk1_goto = BlockSnapshot(
            serial=1, block_type=3, succs=(2,), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=(goto1,)
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(1,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0_entry, 1: blk1_goto, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # Block 2 is the last (max serial) -> sentinel, skip it as candidate.
        # Block 0 has no predecessors -> no redirect emitted for it.
        # Block 1 is goto-only with predecessor 0 -> RedirectGoto(0->1 becomes 0->2).
        # Block 0 is goto-only with no predecessors -> 0 redirects from it.
        assert len(mods) == 1
        mod = mods[0]
        assert isinstance(mod, RedirectGoto)
        assert mod.from_serial == 0
        assert mod.old_target == 1
        assert mod.new_target == 2

    def test_multiple_goto_chains(self):
        """Pass handles multiple goto chains in same CFG."""
        # Create CFG with 2 goto chains:
        # 0 -> 10 (goto only) -> 20
        # 0 -> 30 (goto only) -> 40
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(10, 30), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # First goto chain
        goto10 = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto10,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        # Second goto chain
        goto30 = _make_goto_insn(ea=0x3000, dest_serial=40)
        blk30_goto = BlockSnapshot(
            serial=30, block_type=3, succs=(40,), preds=(0,),
            flags=0, start_ea=0x3000, insn_snapshots=(goto30,)
        )
        blk40 = BlockSnapshot(
            serial=40, block_type=2, succs=(), preds=(30,),
            flags=0, start_ea=0x4000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10_goto, 20: blk20, 30: blk30_goto, 40: blk40},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 2 goto blocks, each with 1 predecessor (blk0 is 2-way -> RedirectBranch x2)
        assert len(mods) == 2
        assert all(isinstance(m, RedirectBranch) for m in mods)
        assert all(mod.from_serial == 0 for mod in mods)
        redirects = {(mod.old_target, mod.new_target) for mod in mods}
        assert redirects == {(10, 20), (30, 40)}

    # *** NEW TESTS FOR 4 SAFETY GAPS *****************************************

    # CRITICAL-1: non-goto single instruction must NOT be treated as goto block
    def test_single_non_goto_instruction_not_treated_as_goto(self):
        """CRITICAL-1: Block with 1 instruction that is NOT m_goto is rejected.

        This covers the key safety gap: len(insn_snapshots) <= 1 was previously
        enough to qualify. Now the instruction must have opcode == 55 (m_goto).
        """
        # blk10 has exactly 1 instruction but it's a m_mov (opcode 0x03), not m_goto
        non_goto_insn = InsnSnapshot(opcode=0x03, ea=0x1100, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(non_goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # blk10's single instruction is NOT m_goto -> must not produce any modification
        assert mods == [], (
            f"Expected no modifications but got {mods}. "
            "A block with a single non-goto instruction must NOT be treated as a simple goto block."
        )

    def test_empty_block_not_treated_as_simple_goto(self):
        """CRITICAL-1: Empty blocks (0 instructions) are NOT simple goto blocks.

        The legacy is_simple_goto_block() requires exactly 1 m_goto instruction.
        An empty block has no tail instruction at all and must be rejected.
        """
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # blk10 is empty (0 instructions) - must NOT qualify as simple goto
        blk10_empty = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10_empty, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == [], (
            f"Expected no modifications for empty block but got {mods}. "
            "Empty blocks have no tail goto instruction and must NOT be simplified."
        )

    # CRITICAL-2: 2-way predecessor must get RedirectBranch, not RedirectGoto
    def test_2way_predecessor_emits_redirect_branch(self):
        """CRITICAL-2: A 2-way predecessor of a goto block gets RedirectBranch."""
        # blk0 is a 2-way conditional block (block_type=4) with succs=(10, 30).
        # blk10 is a simple goto block pointing to blk20.
        # blk0 -> blk10 edge must produce RedirectBranch(from=0, old=10, new=20).
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(10, 30), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        blk30 = BlockSnapshot(
            serial=30, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1300, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10_goto, 20: blk20, 30: blk30},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        mod = mods[0]
        assert isinstance(mod, RedirectBranch), (
            f"Expected RedirectBranch for 2-way predecessor but got {type(mod).__name__}. "
            "2-way (conditional) predecessors must use RedirectBranch, not RedirectGoto."
        )
        assert mod.from_serial == 0
        assert mod.old_target == 10
        assert mod.new_target == 20

    def test_1way_predecessor_emits_redirect_goto(self):
        """CRITICAL-2 (complement): A 1-way predecessor gets RedirectGoto."""
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10_goto, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        mod = mods[0]
        assert isinstance(mod, RedirectGoto), (
            f"Expected RedirectGoto for 1-way predecessor but got {type(mod).__name__}."
        )
        assert mod.from_serial == 0
        assert mod.old_target == 10
        assert mod.new_target == 20

    # HIGH-1: Last (sentinel dummy) block must be excluded
    def test_last_serial_block_excluded_as_sentinel(self):
        """HIGH-1: The block with the highest serial is never treated as a goto block.

        IDA's MBA has a sentinel dummy block at mba.qty-1. The legacy code
        iterates range(last_block_index) which excludes it. Even if that block
        looks like a simple goto, it must be skipped.
        """
        # Construct a CFG where the highest-serial block looks like a simple goto.
        # Serials: 0 (pred), 10 (goto-ish, max serial = sentinel), 20 (target)
        # Note: 20 > 10 so blk20 is the actual sentinel here.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        # blk99 is the highest-serial block and looks like a simple goto
        goto_insn = _make_goto_insn(ea=0x9900, dest_serial=10)
        blk99_sentinel = BlockSnapshot(
            serial=99, block_type=3, succs=(10,), preds=(0,),
            flags=0, start_ea=0x9900, insn_snapshots=(goto_insn,)
        )
        # blk0 also has blk99 as a successor (contrived but valid for testing)
        blk0_with_sentinel = BlockSnapshot(
            serial=0, block_type=4, succs=(10, 99), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0_with_sentinel, 10: blk10, 99: blk99_sentinel},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # blk99 is the highest serial -> sentinel -> must be excluded as a candidate.
        # blk10 has nsucc=0 -> not a goto candidate.
        # blk0 has nsucc=2 -> not a goto candidate.
        # Result: no modifications.
        assert mods == [], (
            f"Expected no modifications but got {mods}. "
            "The block with the highest serial (IDA sentinel dummy) must never be "
            "treated as a goto-only block candidate."
        )

    def test_only_block_in_cfg_is_sentinel_excluded(self):
        """HIGH-1: Single-block CFG - that block IS the sentinel, nothing to do."""
        # Only one block -> it IS the max serial -> excluded
        goto_insn = _make_goto_insn(ea=0x1000, dest_serial=0)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(0,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        cfg = FlowGraph(blocks={0: blk0}, entry_serial=0, func_ea=0x1000)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    # HIGH-2: Destination verified via mop_b operand
    def test_goto_insn_without_mop_b_operand_is_rejected(self):
        """HIGH-2: A block whose m_goto has no mop_b operand is rejected.

        The pass must verify the tail's mop_b operand matches succs[0].
        A block with m_goto but no mop_b operand (empty operands) must not
        produce a modification.
        """
        # m_goto with no operands at all (no mop_b -> destination unverifiable)
        goto_no_mop_b = InsnSnapshot(opcode=_M_GOTO_OPCODE, ea=0x1100, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_no_mop_b,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == [], (
            f"Expected no modifications but got {mods}. "
            "A m_goto without a mop_b operand referencing the successor must be rejected "
            "(destination cannot be verified from the tail instruction)."
        )

    def test_goto_insn_mop_b_wrong_dest_is_rejected(self):
        """HIGH-2: mop_b operand pointing to wrong block serial is rejected."""
        # mop_b points to serial 99 but succs[0] == 20 -> mismatch -> rejected
        wrong_dest_mop = MopSnapshot(t=_MOP_B_TYPE, size=4, block_num=99)
        goto_wrong_dest = InsnSnapshot(
            opcode=_M_GOTO_OPCODE, ea=0x1100, operands=(wrong_dest_mop,)
        )
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_wrong_dest,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 10: blk10, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == [], (
            f"Expected no modifications but got {mods}. "
            "A m_goto whose mop_b operand points to a different block than succs[0] "
            "must be rejected - the tail instruction destination does not match the CFG edge."
        )


class TestGotoChainRemovalPassIntegration:
    """Integration tests with PassPipeline and InMemoryBackend."""

    def test_pipeline_with_single_goto_chain(self):
        """PassPipeline integration: single goto chain."""
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        blocks = {0: blk0, 10: blk10_goto, 20: blk20}
        backend = InMemoryBackend(blocks)

        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, RedirectGoto)
        assert mod.from_serial == 0
        assert mod.old_target == 10
        assert mod.new_target == 20

    def test_pipeline_with_no_goto_chains(self):
        """PassPipeline integration: no goto chains returns 0."""
        insn0 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        insn1 = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(insn0, insn1)
        )
        insn2 = InsnSnapshot(opcode=0x03, ea=0x1010, operands=())
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=(insn2,)
        )
        blocks = {0: blk0, 1: blk1}
        backend = InMemoryBackend(blocks)

        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 0
        assert len(backend.applied_modifications) == 0

    def test_pipeline_2way_pred_emits_redirect_branch(self):
        """PassPipeline integration: 2-way predecessor gets RedirectBranch."""
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(10, 30), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        blk30 = BlockSnapshot(
            serial=30, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1300, insn_snapshots=()
        )
        blocks = {0: blk0, 10: blk10_goto, 20: blk20, 30: blk30}
        backend = InMemoryBackend(blocks)

        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, RedirectBranch), (
            f"Expected RedirectBranch but got {type(mod).__name__}"
        )
        assert mod.from_serial == 0
        assert mod.old_target == 10
        assert mod.new_target == 20

    def test_pipeline_with_multiple_predecessors_mixed_types(self):
        """PassPipeline integration: mixed 1-way and 2-way predecessors."""
        # blk0 (2-way) -> blk10 (goto) and blk5 (1-way) -> blk10 (goto)
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        insn5a = InsnSnapshot(opcode=0x01, ea=0x1050, operands=())
        insn5b = InsnSnapshot(opcode=0x02, ea=0x1054, operands=())
        blk5 = BlockSnapshot(
            serial=5, block_type=3, succs=(10,), preds=(0,),
            flags=0, start_ea=0x1050, insn_snapshots=(insn5a, insn5b)
        )
        goto_insn = _make_goto_insn(ea=0x1100, dest_serial=20)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=3, succs=(20,), preds=(0, 5),
            flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        blocks = {0: blk0, 5: blk5, 10: blk10_goto, 20: blk20}
        backend = InMemoryBackend(blocks)

        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 2
        assert len(backend.applied_modifications) == 2

        mod_by_serial = {m.from_serial: m for m in backend.applied_modifications}
        assert 0 in mod_by_serial
        assert 5 in mod_by_serial

        # blk0 is 2-way -> RedirectBranch
        assert isinstance(mod_by_serial[0], RedirectBranch)
        assert mod_by_serial[0].old_target == 10
        assert mod_by_serial[0].new_target == 20

        # blk5 is 1-way -> RedirectGoto
        assert isinstance(mod_by_serial[5], RedirectGoto)
        assert mod_by_serial[5].old_target == 10
        assert mod_by_serial[5].new_target == 20
