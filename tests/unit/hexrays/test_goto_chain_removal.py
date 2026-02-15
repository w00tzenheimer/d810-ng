"""Tests for GotoChainRemovalPass.

This module tests the CFGPass that collapses chains of goto-only blocks.
Tests cover:
- Detection of goto-only blocks (1-way, 0-1 instructions)
- RedirectEdge emission for each predecessor
- Self-loop handling
- Multi-predecessor goto blocks
- Integration with PassPipeline and InMemoryBackend
"""
from __future__ import annotations

import pytest

from d810.hexrays.graph_modification import RedirectEdge
from d810.hexrays.pass_pipeline import PassPipeline
from d810.hexrays.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
from d810.hexrays.passes.goto_chain_removal import GotoChainRemovalPass

# Import InMemoryBackend from test_cfg_pass
from tests.unit.hexrays.test_cfg_pass import InMemoryBackend


class TestGotoChainRemovalPass:
    """Tests for GotoChainRemovalPass transform logic."""

    def test_no_goto_blocks_returns_empty(self):
        """Pass returns empty list when no goto-only blocks exist."""
        # Create CFG: 0 -> 1 (both have multiple instructions, not goto-only)
        insn0a = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        insn0b = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(insn0a, insn0b)
        )
        insn1a = InsnSnapshot(opcode=0x03, ea=0x1010, operands=())
        insn1b = InsnSnapshot(opcode=0x04, ea=0x1014, operands=())
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=(insn1a, insn1b)
        )
        cfg = PortableCFG(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_single_goto_chain_returns_redirect_edge(self):
        """Pass returns RedirectEdge to bypass single goto-only block."""
        # Create chain: 0 -> 10 (goto only) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Goto-only block (0 instructions, successor is implicit)
        blk10_goto = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 10: blk10_goto, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        assert isinstance(mods[0], RedirectEdge)
        assert mods[0].from_serial == 0
        assert mods[0].old_target == 10
        assert mods[0].new_target == 20

    def test_self_loop_skipped(self):
        """Pass skips self-loop goto blocks."""
        # Create self-loop: 0 -> 10 (goto to itself)
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Self-loop goto block
        blk10_selfloop = BlockSnapshot(
            serial=10, block_type=1, succs=(10,), preds=(0, 10),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 10: blk10_selfloop},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # Self-loop is skipped, no modifications
        assert mods == []

    def test_multi_predecessor_goto_block(self):
        """Pass emits one RedirectEdge per predecessor."""
        # Create CFG: {0, 5} -> 10 (goto only) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=2, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Block 5 with instructions (not goto-only)
        insn5a = InsnSnapshot(opcode=0x01, ea=0x1050, operands=())
        insn5b = InsnSnapshot(opcode=0x02, ea=0x1054, operands=())
        blk5 = BlockSnapshot(
            serial=5, block_type=1, succs=(10,), preds=(0,),
            flags=0, start_ea=0x1050, insn_snapshots=(insn5a, insn5b)
        )
        # Goto-only block with 2 predecessors
        blk10_goto = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0, 5),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 5: blk5, 10: blk10_goto, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 2 predecessors -> 2 RedirectEdge modifications
        assert len(mods) == 2
        from_serials = {mod.from_serial for mod in mods}
        assert from_serials == {0, 5}
        for mod in mods:
            assert mod.old_target == 10
            assert mod.new_target == 20

    def test_block_with_instructions_not_goto_only(self):
        """Block with >1 instructions is not simplified."""
        # Create CFG: 0 -> 10 (2 instructions) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Block with 2 instructions (not goto-only)
        insn10a = InsnSnapshot(opcode=0x01, ea=0x1100, operands=())
        insn10b = InsnSnapshot(opcode=0x02, ea=0x1104, operands=())
        blk10 = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(insn10a, insn10b)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 10: blk10, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # Block 10 has >1 instructions, not goto-only
        assert mods == []

    def test_goto_block_with_single_instruction(self):
        """Block with exactly 1 instruction (e.g., NOP) is treated as goto-only."""
        # Create CFG: 0 -> 10 (1 instruction) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Block with single NOP (goto-only)
        insn10 = InsnSnapshot(opcode=0x00, ea=0x1100, operands=())
        blk10_goto = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=(insn10,)
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 10: blk10_goto, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # Block 10 has <=1 instructions, treated as goto-only
        assert len(mods) == 1
        assert mods[0].from_serial == 0
        assert mods[0].old_target == 10
        assert mods[0].new_target == 20

    def test_2way_block_ignored(self):
        """2-way blocks are ignored (not goto-only)."""
        # Create CFG: 0 (2-way) -> {1, 2}
        blk0 = BlockSnapshot(
            serial=0, block_type=2, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 2-way block (nsucc=2) is not goto-only
        assert mods == []

    def test_0way_block_ignored(self):
        """0-way blocks (terminals) are ignored."""
        # Create CFG: 0 -> 1 (0-way terminal)
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = PortableCFG(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 0-way block (nsucc=0) is not goto-only
        assert mods == []

    def test_empty_cfg_returns_empty(self):
        """Pass handles empty CFG gracefully."""
        cfg = PortableCFG(blocks={}, entry_serial=0, func_ea=0)

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_pass_name_and_tags(self):
        """Pass has correct name and tags."""
        pass_instance = GotoChainRemovalPass()

        assert pass_instance.name == "goto_chain_removal"
        assert pass_instance.tags == frozenset({"cleanup", "topology"})

    def test_multiple_goto_chains(self):
        """Pass handles multiple goto chains in same CFG."""
        # Create CFG with 2 goto chains:
        # 0 -> 10 (goto only) -> 20
        # 0 -> 30 (goto only) -> 40
        blk0 = BlockSnapshot(
            serial=0, block_type=2, succs=(10, 30), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # First goto chain
        blk10_goto = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        # Second goto chain
        blk30_goto = BlockSnapshot(
            serial=30, block_type=1, succs=(40,), preds=(0,),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        blk40 = BlockSnapshot(
            serial=40, block_type=0, succs=(), preds=(30,),
            flags=0, start_ea=0x4000, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 10: blk10_goto, 20: blk20, 30: blk30_goto, 40: blk40},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = GotoChainRemovalPass()
        mods = pass_instance.transform(cfg)

        # 2 goto blocks, each with 1 predecessor
        assert len(mods) == 2
        # Check that both redirects come from block 0
        assert all(mod.from_serial == 0 for mod in mods)
        # Check old/new targets
        redirects = {(mod.old_target, mod.new_target) for mod in mods}
        assert redirects == {(10, 20), (30, 40)}


class TestGotoChainRemovalPassIntegration:
    """Integration tests with PassPipeline and InMemoryBackend."""

    def test_pipeline_with_single_goto_chain(self):
        """PassPipeline integration: single goto chain."""
        # Create CFG: 0 -> 10 (goto only) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk10_goto = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0,),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        blocks = {0: blk0, 10: blk10_goto, 20: blk20}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, RedirectEdge)
        assert mod.from_serial == 0
        assert mod.old_target == 10
        assert mod.new_target == 20

    def test_pipeline_with_no_goto_chains(self):
        """PassPipeline integration: no goto chains returns 0."""
        # Create CFG: 0 -> 1 (both have multiple instructions)
        insn0 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        insn1 = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(insn0, insn1)
        )
        insn2 = InsnSnapshot(opcode=0x03, ea=0x1010, operands=())
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=(insn2,)
        )
        blocks = {0: blk0, 1: blk1}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 0
        assert len(backend.applied_modifications) == 0

    def test_pipeline_with_multiple_predecessors(self):
        """PassPipeline integration: goto block with multiple predecessors."""
        # Create CFG: {0, 5} -> 10 (goto only) -> 20
        blk0 = BlockSnapshot(
            serial=0, block_type=2, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        # Block 5 with instructions (not goto-only)
        insn5a = InsnSnapshot(opcode=0x01, ea=0x1050, operands=())
        insn5b = InsnSnapshot(opcode=0x02, ea=0x1054, operands=())
        blk5 = BlockSnapshot(
            serial=5, block_type=1, succs=(10,), preds=(0,),
            flags=0, start_ea=0x1050, insn_snapshots=(insn5a, insn5b)
        )
        blk10_goto = BlockSnapshot(
            serial=10, block_type=1, succs=(20,), preds=(0, 5),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=0, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        blocks = {0: blk0, 5: blk5, 10: blk10_goto, 20: blk20}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [GotoChainRemovalPass()])
        total_mods = pipeline.run(blocks)

        # 2 predecessors -> 2 modifications
        assert total_mods == 2
        assert len(backend.applied_modifications) == 2
        from_serials = {mod.from_serial for mod in backend.applied_modifications}
        assert from_serials == {0, 5}
        for mod in backend.applied_modifications:
            assert mod.old_target == 10
            assert mod.new_target == 20
