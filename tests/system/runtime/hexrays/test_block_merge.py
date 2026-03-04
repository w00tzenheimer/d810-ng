"""Unit tests for BlockMergeTransform.

Tests the FlowGraphTransform that merges artificially split basic blocks by NOPing
redundant goto instructions.
"""
from __future__ import annotations

import ida_hexrays
import pytest

from d810.cfg.graph_modification import NopInstructions
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.mutation.transform.block_merge import BlockMergeTransform
from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph

# IDA microcode constants
_M_GOTO_OPCODE = ida_hexrays.m_goto
_MOP_B_TYPE = ida_hexrays.mop_b


def _make_goto_insn(ea: int, target_serial: int) -> InsnSnapshot:
    """Create an m_goto InsnSnapshot with a mop_b operand pointing to target_serial."""
    dest_mop = MopSnapshot(t=_MOP_B_TYPE, size=4, block_num=target_serial)
    return InsnSnapshot(opcode=_M_GOTO_OPCODE, ea=ea, operands=(dest_mop,))


class TestBlockMergeTransform:
    """Test suite for BlockMergeTransform."""

    def test_pass_metadata(self):
        """Verify pass name and tags are correctly defined."""
        pass_instance = BlockMergeTransform()
        assert pass_instance.name == "block_merge"
        assert "cleanup" in pass_instance.tags
        assert "topology" in pass_instance.tags

    def test_no_merge_candidates_returns_empty(self):
        """No merge candidates should return empty modification list."""
        # Single block with no successors (0-way)
        blk = BlockSnapshot(
            serial=0, block_type=2, succs=(), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_simple_merge_candidate(self):
        """Simple A->B merge candidate should emit NopInstructions for tail goto."""
        goto_insn = _make_goto_insn(ea=0x1000, target_serial=1)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        assert isinstance(mods[0], NopInstructions)
        assert mods[0].block_serial == 0
        assert mods[0].insn_eas == (0x1000,)

    def test_multi_predecessor_successor_not_merged(self):
        """Successor with multiple predecessors should not be merged."""
        goto_insn_a = _make_goto_insn(ea=0x1000, target_serial=2)
        goto_insn_b = _make_goto_insn(ea=0x2000, target_serial=2)
        # Block A: 0 -> 2
        blk_a = BlockSnapshot(
            serial=0, block_type=3, succs=(2,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn_a,)
        )
        # Block B: 1 -> 2
        blk_b = BlockSnapshot(
            serial=1, block_type=3, succs=(2,), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(goto_insn_b,)
        )
        # Block C: 2 has two predecessors (A and B)
        blk_c = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0, 1),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk_a, 1: blk_b, 2: blk_c}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        # Neither A nor B should be merged with C
        assert mods == []

    def test_self_loop_not_merged(self):
        """Self-referencing goto (infinite loop) should not be merged."""
        goto_insn = _make_goto_insn(ea=0x1000, target_serial=0)
        # Block 0 -> 0 (self-loop)
        blk = BlockSnapshot(
            serial=0, block_type=3, succs=(0,), preds=(0,),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_chain_of_mergeable_blocks(self):
        """Chain A->B->C where A,B are mergeable should detect both pairs."""
        # Block 0: -> 1
        goto_insn_0 = _make_goto_insn(ea=0x1000, target_serial=1)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn_0,)
        )
        # Block 1: 0 -> 1 -> 2
        goto_insn_1 = _make_goto_insn(ea=0x1010, target_serial=2)
        blk1 = BlockSnapshot(
            serial=1, block_type=3, succs=(2,), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=(goto_insn_1,)
        )
        # Block 2: 1 -> (no successors)
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(1,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        # Both pairs (0->1 and 1->2) should be detected
        assert len(mods) == 2
        serials = {mod.block_serial for mod in mods}
        assert serials == {0, 1}

    def test_block_with_zero_ea_instruction_not_merged(self):
        """Block with tail instruction at EA=0 should not emit NOP."""
        # EA=0 is used for synthetic instructions without real addresses
        dest_mop = MopSnapshot(t=_MOP_B_TYPE, size=4, block_num=1)
        goto_insn = InsnSnapshot(opcode=_M_GOTO_OPCODE, ea=0, operands=(dest_mop,))
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        # Should not emit NOP for EA=0 instruction
        assert mods == []

    def test_block_with_no_instructions_not_merged(self):
        """Block with no instructions should not emit NOP."""
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_2way_block_not_merged(self):
        """2-way blocks (conditional branches) should not be merged."""
        # Conditional branch to two different targets
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
        cfg = FlowGraph(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_missing_successor_not_merged(self):
        """Block with successor not in CFG should not be merged."""
        goto_insn = _make_goto_insn(ea=0x1000, target_serial=99)
        # Block 0 -> 99 (99 doesn't exist)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(99,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        cfg = FlowGraph(blocks={0: blk0}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_is_applicable_returns_true(self):
        """is_applicable should return True (default implementation)."""
        pass_instance = BlockMergeTransform()
        blk = BlockSnapshot(
            serial=0, block_type=2, succs=(), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)

        assert pass_instance.is_applicable(cfg) is True

    def test_non_goto_tail_not_merged(self):
        """Block whose tail is not m_goto (e.g. fall-through) should not be merged."""
        # opcode 1 is m_ldx, not m_goto
        non_goto_insn = InsnSnapshot(opcode=1, ea=0x1000, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(non_goto_insn,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_goto_wrong_destination_not_merged(self):
        """Goto targeting a different block (wrong mop_b) should not be merged."""
        # goto points to block 99, but successor is 1
        wrong_dest_mop = MopSnapshot(t=_MOP_B_TYPE, size=4, block_num=99)
        goto_insn = InsnSnapshot(opcode=_M_GOTO_OPCODE, ea=0x1000, operands=(wrong_dest_mop,))
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_goto_no_mop_b_operand_not_merged(self):
        """Goto with no mop_b operand (empty operands) should not be merged."""
        goto_insn = InsnSnapshot(opcode=_M_GOTO_OPCODE, ea=0x1000, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_nway_block_not_merged(self):
        """N-way blocks (switch) should not be merged even with single successor."""
        goto_insn = _make_goto_insn(ea=0x1000, target_serial=1)
        # block_type=5 is BLT_NWAY (switch)
        blk0 = BlockSnapshot(
            serial=0, block_type=5, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = BlockMergeTransform()
        mods = pass_instance.transform(cfg)

        assert mods == []
