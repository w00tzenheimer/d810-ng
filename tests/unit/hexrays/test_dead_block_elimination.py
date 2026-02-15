"""Tests for DeadBlockEliminationPass.

This module tests the CFGPass that eliminates unreachable (dead) blocks
from the CFG. Tests cover:
- Detection of dead blocks via reachability analysis
- NopInstructions emission for dead blocks
- Handling of various CFG topologies
- Integration with PassPipeline and InMemoryBackend
"""
from __future__ import annotations

import pytest

from d810.hexrays.graph_modification import NopInstructions
from d810.hexrays.pass_pipeline import PassPipeline
from d810.hexrays.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
from d810.hexrays.passes.dead_block_elimination import DeadBlockEliminationPass

# Import InMemoryBackend from test_cfg_pass
from tests.unit.hexrays.test_cfg_pass import InMemoryBackend


class TestDeadBlockEliminationPass:
    """Tests for DeadBlockEliminationPass transform logic."""

    def test_all_reachable_returns_empty(self):
        """Pass returns empty list when all blocks are reachable."""
        # Create simple chain: 0 -> 1 -> 2
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=1, succs=(2,), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=0, succs=(), preds=(1,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_single_dead_block_returns_nop_instructions(self):
        """Pass returns NopInstructions for a single unreachable block."""
        # Create CFG: 0 -> 1, with unreachable block 2
        insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(insn1,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block with 2 instructions
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2000, operands=())
        insn3 = InsnSnapshot(opcode=0x03, ea=0x2004, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn2, insn3)
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2_dead},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        assert isinstance(mods[0], NopInstructions)
        assert mods[0].block_serial == 2
        assert mods[0].insn_eas == (0x2000, 0x2004)

    def test_multiple_dead_blocks_returns_all(self):
        """Pass returns NopInstructions for multiple dead blocks."""
        # Create CFG: 0 -> 1, with unreachable blocks 5, 10
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block 5 with 1 instruction
        insn5 = InsnSnapshot(opcode=0x05, ea=0x5000, operands=())
        blk5_dead = BlockSnapshot(
            serial=5, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x5000, insn_snapshots=(insn5,)
        )
        # Dead block 10 with 3 instructions
        insn10a = InsnSnapshot(opcode=0x0A, ea=0xA000, operands=())
        insn10b = InsnSnapshot(opcode=0x0B, ea=0xA004, operands=())
        insn10c = InsnSnapshot(opcode=0x0C, ea=0xA008, operands=())
        blk10_dead = BlockSnapshot(
            serial=10, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0xA000, insn_snapshots=(insn10a, insn10b, insn10c)
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 5: blk5_dead, 10: blk10_dead},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 2
        serials = {mod.block_serial for mod in mods}
        assert serials == {5, 10}
        # Find mod for block 5
        mod5 = next(m for m in mods if m.block_serial == 5)
        assert mod5.insn_eas == (0x5000,)
        # Find mod for block 10
        mod10 = next(m for m in mods if m.block_serial == 10)
        assert mod10.insn_eas == (0xA000, 0xA004, 0xA008)

    def test_diamond_cfg_all_reachable(self):
        """Pass returns empty for diamond CFG (all reachable)."""
        # Create diamond: 0 -> {1, 2} -> 3
        blk0 = BlockSnapshot(
            serial=0, block_type=2, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=1, succs=(3,), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=1, succs=(3,), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        blk3 = BlockSnapshot(
            serial=3, block_type=0, succs=(), preds=(1, 2),
            flags=0, start_ea=0x1030, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2, 3: blk3},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_dead_block_no_instructions_returns_empty(self):
        """Dead block with no instructions (ea=0) emits no modification."""
        # Create CFG: 0 -> 1, with dead block 2 (no real instructions)
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block with placeholder instruction (ea=0)
        insn_placeholder = InsnSnapshot(opcode=0x00, ea=0, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn_placeholder,)
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2_dead},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # No modification because insn_eas is empty (ea=0 filtered out)
        assert mods == []

    def test_dead_block_mixed_ea_filters_zeros(self):
        """Dead block with mix of real and placeholder EAs filters ea=0."""
        # Create CFG: 0 -> 1, with dead block 2 (mixed EAs)
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block with 3 instructions: ea=0, ea=0x2004, ea=0
        insn0a = InsnSnapshot(opcode=0x00, ea=0, operands=())
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2004, operands=())
        insn0b = InsnSnapshot(opcode=0x00, ea=0, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn0a, insn2, insn0b)
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2_dead},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        assert mods[0].block_serial == 2
        # Only ea=0x2004 should be included
        assert mods[0].insn_eas == (0x2004,)

    def test_empty_cfg_returns_empty(self):
        """Pass handles empty CFG gracefully."""
        cfg = PortableCFG(blocks={}, entry_serial=0, func_ea=0)

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_pass_name_and_tags(self):
        """Pass has correct name and tags."""
        pass_instance = DeadBlockEliminationPass()

        assert pass_instance.name == "dead_block_elimination"
        assert pass_instance.tags == frozenset({"cleanup", "topology"})

    def test_reachability_with_loop(self):
        """Reachability analysis handles loops correctly."""
        # Create CFG with loop: 0 -> 1 <-> 2 -> 3, dead block 10
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=1, succs=(2,), preds=(0, 2),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(1, 3), preds=(1,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        blk3 = BlockSnapshot(
            serial=3, block_type=0, succs=(), preds=(2,),
            flags=0, start_ea=0x1030, insn_snapshots=()
        )
        # Dead block 10
        insn10 = InsnSnapshot(opcode=0x0A, ea=0xA000, operands=())
        blk10_dead = BlockSnapshot(
            serial=10, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0xA000, insn_snapshots=(insn10,)
        )
        cfg = PortableCFG(
            blocks={0: blk0, 1: blk1, 2: blk2, 3: blk3, 10: blk10_dead},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # Only block 10 is dead (0,1,2,3 all reachable via loop)
        assert len(mods) == 1
        assert mods[0].block_serial == 10
        assert mods[0].insn_eas == (0xA000,)


class TestDeadBlockEliminationPassIntegration:
    """Integration tests with PassPipeline and InMemoryBackend."""

    def test_pipeline_with_single_dead_block(self):
        """PassPipeline integration: single dead block."""
        # Create CFG: 0 -> 1, dead block 2
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2000, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn2,)
        )
        blocks = {0: blk0, 1: blk1, 2: blk2_dead}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [DeadBlockEliminationPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, NopInstructions)
        assert mod.block_serial == 2
        assert mod.insn_eas == (0x2000,)

    def test_pipeline_with_no_dead_blocks(self):
        """PassPipeline integration: no dead blocks returns 0."""
        # Create CFG: 0 -> 1 (all reachable)
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [DeadBlockEliminationPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 0
        assert len(backend.applied_modifications) == 0

    def test_pipeline_with_multiple_dead_blocks(self):
        """PassPipeline integration: multiple dead blocks."""
        # Create CFG: 0 -> 1, dead blocks 5, 10
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=0, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        insn5 = InsnSnapshot(opcode=0x05, ea=0x5000, operands=())
        blk5_dead = BlockSnapshot(
            serial=5, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x5000, insn_snapshots=(insn5,)
        )
        insn10 = InsnSnapshot(opcode=0x0A, ea=0xA000, operands=())
        blk10_dead = BlockSnapshot(
            serial=10, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0xA000, insn_snapshots=(insn10,)
        )
        blocks = {0: blk0, 1: blk1, 5: blk5_dead, 10: blk10_dead}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [DeadBlockEliminationPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 2
        assert len(backend.applied_modifications) == 2
        serials = {mod.block_serial for mod in backend.applied_modifications}
        assert serials == {5, 10}
