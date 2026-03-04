"""Tests for SimplifyIdenticalBranchPass.

This module tests the CFGPass migration of make_2way_block_goto() functionality
from cfg_mutations.py. Tests cover:
- Detection of 2-way blocks with identical successors
- Ignoring blocks that don't match the pattern
- Integration with PassPipeline and InMemoryBackend
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import ConvertToGoto
from d810.cfg.pipeline import PassPipeline
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.passes.simplify_identical_branch import SimplifyIdenticalBranchPass

from tests.unit.hexrays.conftest import InMemoryBackend


class TestSimplifyIdenticalBranchPass:
    """Tests for SimplifyIdenticalBranchPass transform logic."""

    def test_no_2way_blocks_returns_empty(self):
        """Pass returns empty list when no 2-way blocks exist."""
        # Create CFG with only 1-way and 0-way blocks
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        pass_instance = SimplifyIdenticalBranchPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_2way_block_different_targets_returns_empty(self):
        """Pass returns empty list when 2-way block has different successors."""
        # Create 2-way block with different targets
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

        pass_instance = SimplifyIdenticalBranchPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_2way_block_identical_targets_returns_convert_to_goto(self):
        """Pass returns ConvertToGoto when 2-way block has identical successors."""
        # Create 2-way block with identical targets (both go to block 5)
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(5, 5), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk5 = BlockSnapshot(
            serial=5, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1050, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 5: blk5}, entry_serial=0, func_ea=0x1000)

        pass_instance = SimplifyIdenticalBranchPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 1
        assert isinstance(mods[0], ConvertToGoto)
        assert mods[0].block_serial == 0
        assert mods[0].goto_target == 5

    def test_multiple_2way_blocks_some_identical(self):
        """Pass returns modifications only for matching blocks."""
        # Block 0: 2-way with different targets (1, 2) - NO match
        # Block 3: 2-way with identical targets (5, 5) - MATCH
        # Block 10: 2-way with identical targets (20, 20) - MATCH
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
            serial=3, block_type=4, succs=(5, 5), preds=(1, 2),
            flags=0, start_ea=0x1030, insn_snapshots=()
        )
        blk5 = BlockSnapshot(
            serial=5, block_type=3, succs=(10,), preds=(3,),
            flags=0, start_ea=0x1050, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=4, succs=(20, 20), preds=(5,),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=2, succs=(), preds=(10,),
            flags=0, start_ea=0x1200, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2, 3: blk3, 5: blk5, 10: blk10, 20: blk20},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = SimplifyIdenticalBranchPass()
        mods = pass_instance.transform(cfg)

        assert len(mods) == 2
        serials = {mod.block_serial for mod in mods}
        assert serials == {3, 10}
        # Find mod for block 3
        mod3 = next(m for m in mods if m.block_serial == 3)
        assert mod3.goto_target == 5
        # Find mod for block 10
        mod10 = next(m for m in mods if m.block_serial == 10)
        assert mod10.goto_target == 20

    def test_1way_and_0way_blocks_ignored(self):
        """1-way and 0-way blocks are ignored by the pass."""
        # Mix of block types, none matching the pattern
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        # Even a 1-way block with "duplicate" successor (only 1 entry)
        blk2 = BlockSnapshot(
            serial=2, block_type=3, succs=(5,), preds=(),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = SimplifyIdenticalBranchPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_empty_cfg_returns_empty(self):
        """Pass handles empty CFG gracefully."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0)

        pass_instance = SimplifyIdenticalBranchPass()
        mods = pass_instance.transform(cfg)

        assert mods == []

    def test_pass_name_and_tags(self):
        """Pass has correct name and tags."""
        pass_instance = SimplifyIdenticalBranchPass()

        assert pass_instance.name == "simplify_identical_branch"
        assert pass_instance.tags == frozenset({"cleanup"})


class TestSimplifyIdenticalBranchPassIntegration:
    """Integration tests with PassPipeline and InMemoryBackend."""

    def test_pipeline_with_matching_block(self):
        """PassPipeline integration: single matching block."""
        # Create 2-way block with identical successors
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(5, 5), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk5 = BlockSnapshot(
            serial=5, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1050, insn_snapshots=()
        )
        blocks = {0: blk0, 5: blk5}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [SimplifyIdenticalBranchPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, ConvertToGoto)
        assert mod.block_serial == 0
        assert mod.goto_target == 5

    def test_pipeline_with_no_matches(self):
        """PassPipeline integration: no matching blocks returns 0."""
        # Create 2-way block with different successors
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
        blocks = {0: blk0, 1: blk1, 2: blk2}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [SimplifyIdenticalBranchPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 0
        assert len(backend.applied_modifications) == 0

    def test_pipeline_with_multiple_matches(self):
        """PassPipeline integration: multiple matching blocks."""
        # Block 3: identical successors (10, 10)
        # Block 7: identical successors (10, 10)
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(3, 7), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk3 = BlockSnapshot(
            serial=3, block_type=4, succs=(10, 10), preds=(0,),
            flags=0, start_ea=0x1030, insn_snapshots=()
        )
        blk7 = BlockSnapshot(
            serial=7, block_type=4, succs=(10, 10), preds=(0,),
            flags=0, start_ea=0x1070, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=2, succs=(), preds=(3, 7),
            flags=0, start_ea=0x1100, insn_snapshots=()
        )
        blocks = {0: blk0, 3: blk3, 7: blk7, 10: blk10}
        backend = InMemoryBackend(blocks)

        # Run through PassPipeline
        pipeline = PassPipeline(backend, [SimplifyIdenticalBranchPass()])
        total_mods = pipeline.run(blocks)

        assert total_mods == 2
        assert len(backend.applied_modifications) == 2
        serials = {mod.block_serial for mod in backend.applied_modifications}
        assert serials == {3, 7}
        # Both should target block 10
        for mod in backend.applied_modifications:
            assert mod.goto_target == 10
