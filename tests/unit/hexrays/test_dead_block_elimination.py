"""Tests for DeadBlockEliminationPass.

This module tests the FlowGraphTransform that eliminates unreachable (dead) blocks
from the CFG. Tests cover:
- Detection of dead blocks via reachability analysis
- NopInstructions emission for dead blocks
- Handling of various CFG topologies
- Integration with PassPipeline and InMemoryBackend
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import NopInstructions
from d810.cfg.pipeline import FlowGraphTransformPipeline
from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
from d810.cfg.transform.dead_block_elimination import DeadBlockEliminationPass

from tests.unit.hexrays.conftest import InMemoryBackend


class TestDeadBlockEliminationPass:
    """Tests for DeadBlockEliminationPass transform logic."""

    def test_all_reachable_returns_empty(self):
        """Pass returns empty list when all blocks are reachable."""
        # Create simple chain: 0 -> 1 -> 2
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=3, succs=(2,), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(1,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_single_dead_block_returns_nop_instructions(self):
        """Pass returns NopInstructions for a single unreachable block."""
        # Create CFG: 0 -> 1, with unreachable block 2, sentinel block 3
        # Block 3 is the sentinel (highest serial) and must never be removed.
        insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(insn1,)
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block with 2 instructions
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2000, operands=())
        insn3 = InsnSnapshot(opcode=0x03, ea=0x2004, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn2, insn3)
        )
        # Sentinel block at highest serial - represents IDA's mba.qty-1 dummy block
        blk3_sentinel = BlockSnapshot(
            serial=3, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2_dead, 3: blk3_sentinel},
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
        # Create CFG: 0 -> 1, with unreachable blocks 5, 10, sentinel block 11
        # Block 11 is the sentinel (highest serial) and must never be removed.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block 5 with 1 instruction
        insn5 = InsnSnapshot(opcode=0x05, ea=0x5000, operands=())
        blk5_dead = BlockSnapshot(
            serial=5, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x5000, insn_snapshots=(insn5,)
        )
        # Dead block 10 with 3 instructions
        insn10a = InsnSnapshot(opcode=0x0A, ea=0xA000, operands=())
        insn10b = InsnSnapshot(opcode=0x0B, ea=0xA004, operands=())
        insn10c = InsnSnapshot(opcode=0x0C, ea=0xA008, operands=())
        blk10_dead = BlockSnapshot(
            serial=10, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0xA000, insn_snapshots=(insn10a, insn10b, insn10c)
        )
        # Sentinel block at highest serial
        blk11_sentinel = BlockSnapshot(
            serial=11, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0xB000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 5: blk5_dead, 10: blk10_dead, 11: blk11_sentinel},
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
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=3, succs=(3,), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=3, succs=(3,), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        blk3 = BlockSnapshot(
            serial=3, block_type=2, succs=(),preds=(1, 2),
            flags=0, start_ea=0x1030, insn_snapshots=()
        )
        cfg = FlowGraph(
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
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block with placeholder instruction (ea=0)
        insn_placeholder = InsnSnapshot(opcode=0x00, ea=0, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn_placeholder,)
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2_dead},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # No modification because insn_eas is empty (ea=0 filtered out)
        assert mods == []

    def test_dead_block_mixed_ea_filters_zeros(self):
        """Dead block with mix of real and placeholder EAs filters ea=0."""
        # Create CFG: 0 -> 1, with dead block 2 (mixed EAs), sentinel block 3
        # Block 3 is the sentinel (highest serial) and is always protected.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block with 3 instructions: ea=0, ea=0x2004, ea=0
        insn0a = InsnSnapshot(opcode=0x00, ea=0, operands=())
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2004, operands=())
        insn0b = InsnSnapshot(opcode=0x00, ea=0, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn0a, insn2, insn0b)
        )
        # Sentinel block at highest serial
        blk3_sentinel = BlockSnapshot(
            serial=3, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2_dead, 3: blk3_sentinel},
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
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0)

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
        # Create CFG with loop: 0 -> 1 <-> 2 -> 3, dead block 10, sentinel 11
        # Block 11 is the sentinel (highest serial) and must never be removed.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=3, succs=(2,), preds=(0, 2),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=4, succs=(1, 3), preds=(1,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        blk3 = BlockSnapshot(
            serial=3, block_type=2, succs=(),preds=(2,),
            flags=0, start_ea=0x1030, insn_snapshots=()
        )
        # Dead block 10
        insn10 = InsnSnapshot(opcode=0x0A, ea=0xA000, operands=())
        blk10_dead = BlockSnapshot(
            serial=10, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0xA000, insn_snapshots=(insn10,)
        )
        # Sentinel block at highest serial
        blk11_sentinel = BlockSnapshot(
            serial=11, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0xB000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2, 3: blk3, 10: blk10_dead, 11: blk11_sentinel},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # Only block 10 is dead (0,1,2,3 all reachable via loop; 11 is sentinel)
        assert len(mods) == 1
        assert mods[0].block_serial == 10
        assert mods[0].insn_eas == (0xA000,)

    def test_last_dummy_block_not_removed_when_unreachable(self):
        """Last dummy/sentinel block (highest serial) is never removed even if unreachable.

        IDA's MBA has a sentinel block at serial mba.qty-1 that must never
        be removed. In FlowGraph we protect max(cfg.blocks.keys()).
        """
        # Create CFG: 0 -> 1, dead block 2, sentinel block 3 (highest serial)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Dead block 2 with instructions
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2000, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn2,)
        )
        # Sentinel block 3 (highest serial) - unreachable but must NOT be removed
        insn3 = InsnSnapshot(opcode=0x03, ea=0x3000, operands=())
        blk3_sentinel = BlockSnapshot(
            serial=3, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x3000, insn_snapshots=(insn3,)
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2_dead, 3: blk3_sentinel},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # Only block 2 is dead; block 3 (last dummy) must be protected
        assert len(mods) == 1
        assert mods[0].block_serial == 2
        assert mods[0].insn_eas == (0x2000,)
        # Verify sentinel block 3 is NOT in the modifications
        mod_serials = {mod.block_serial for mod in mods}
        assert 3 not in mod_serials

    def test_last_dummy_block_protected_when_it_is_only_unreachable_block(self):
        """Last dummy block is not emitted even when it is the only unreachable block."""
        # Create CFG: 0 -> 1, sentinel block 2 (highest serial, unreachable)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Sentinel block 2 is unreachable and has instructions - still protected
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2000, operands=())
        blk2_sentinel = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn2,)
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2_sentinel},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # No modifications - block 2 is the last dummy and must not be touched
        assert mods == []

    def test_last_dummy_block_protection_uses_max_serial(self):
        """Protection targets the block with the absolute maximum serial, not a contiguous last."""
        # Non-contiguous serials: 0, 1, 50 (highest). Block 50 is unreachable.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Block at serial 50 is the highest - treated as sentinel
        insn50 = InsnSnapshot(opcode=0x50, ea=0x5000, operands=())
        blk50_sentinel = BlockSnapshot(
            serial=50, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x5000, insn_snapshots=(insn50,)
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 50: blk50_sentinel},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = DeadBlockEliminationPass()
        mods = pass_instance.transform(cfg)

        # Block 50 (max serial) must be protected even though it is unreachable
        assert mods == []


class TestDeadBlockEliminationPassIntegration:
    """Integration tests with PassPipeline and InMemoryBackend."""

    def test_pipeline_with_single_dead_block(self):
        """PassPipeline integration: single dead block."""
        # Create CFG: 0 -> 1, dead block 2, sentinel block 3
        # Block 3 is the sentinel (highest serial) and is never removed.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        insn2 = InsnSnapshot(opcode=0x02, ea=0x2000, operands=())
        blk2_dead = BlockSnapshot(
            serial=2, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=(insn2,)
        )
        # Sentinel block at highest serial
        blk3_sentinel = BlockSnapshot(
            serial=3, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1, 2: blk2_dead, 3: blk3_sentinel}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = FlowGraphTransformPipeline(backend, [DeadBlockEliminationPass()])
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
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = FlowGraphTransformPipeline(backend, [DeadBlockEliminationPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 0
        assert len(backend.applied_modifications) == 0

    def test_pipeline_with_multiple_dead_blocks(self):
        """PassPipeline integration: multiple dead blocks."""
        # Create CFG: 0 -> 1, dead blocks 5, 10, sentinel block 11
        # Block 11 is the sentinel (highest serial) and is never removed.
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(),preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        insn5 = InsnSnapshot(opcode=0x05, ea=0x5000, operands=())
        blk5_dead = BlockSnapshot(
            serial=5, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0x5000, insn_snapshots=(insn5,)
        )
        insn10 = InsnSnapshot(opcode=0x0A, ea=0xA000, operands=())
        blk10_dead = BlockSnapshot(
            serial=10, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0xA000, insn_snapshots=(insn10,)
        )
        # Sentinel block at highest serial
        blk11_sentinel = BlockSnapshot(
            serial=11, block_type=2, succs=(),preds=(),
            flags=0, start_ea=0xB000, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1, 5: blk5_dead, 10: blk10_dead, 11: blk11_sentinel}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = FlowGraphTransformPipeline(backend, [DeadBlockEliminationPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 2
        assert len(backend.applied_modifications) == 2
        serials = {mod.block_serial for mod in backend.applied_modifications}
        assert serials == {5, 10}
