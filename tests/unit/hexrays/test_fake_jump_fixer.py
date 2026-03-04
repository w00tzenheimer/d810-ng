"""Tests for FakeJumpFixerPass CFG transformation pass.

This module tests the CFG-level fake/opaque jump fixing logic extracted from
UnflattenerFakeJump.
"""
from __future__ import annotations

import pytest

from d810.cfg.transform.fake_jump_fixer import FakeJumpFixerPass
from d810.cfg.graph_modification import RedirectBranch, RedirectGoto
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.pipeline import FlowGraphTransformPipeline

from tests.unit.hexrays.conftest import InMemoryBackend


class TestFakeJumpFixerPass:
    """Test suite for FakeJumpFixerPass."""

    def test_empty_fixes_not_applicable(self):
        """Pass with empty fixes should not be applicable."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        pass_instance = FakeJumpFixerPass(fixes={})

        assert not pass_instance.is_applicable(cfg)

    def test_non_empty_fixes_applicable(self):
        """Pass with non-empty fixes should be applicable."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        pass_instance = FakeJumpFixerPass(fixes={5: 10})

        assert pass_instance.is_applicable(cfg)

    def test_empty_fixes_no_modifications(self):
        """Pass with empty fixes should return empty modification list."""
        blk = BlockSnapshot(
            serial=0, block_type=4, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        pass_instance = FakeJumpFixerPass(fixes={})

        mods = pass_instance.transform(cfg)
        assert len(mods) == 0

    def test_single_2way_block_fix_emits_redirect_branch(self):
        """Pass with single 2-way block fix should emit one RedirectBranch."""
        blk = BlockSnapshot(
            serial=5, block_type=4, succs=(10, 20), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={5: blk}, entry_serial=5, func_ea=0x1000)
        fixes = {5: 10}  # Block 5 always goes to 10, never 20
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 1
        assert isinstance(mods[0], RedirectBranch)
        assert mods[0].from_serial == 5
        assert mods[0].old_target == 20  # Redirect 5->20 to 5->10
        assert mods[0].new_target == 10

    def test_single_1way_block_fix_emits_redirect_goto(self):
        """Pass with single 1-way block fix should emit one RedirectGoto."""
        blk = BlockSnapshot(
            serial=5, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={5: blk}, entry_serial=5, func_ea=0x1000)
        fixes = {5: 20}  # Block 5 should goto 20, not 10
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 1
        assert isinstance(mods[0], RedirectGoto)
        assert mods[0].from_serial == 5
        assert mods[0].old_target == 10
        assert mods[0].new_target == 20

    def test_1way_block_target_matches_fix_no_modification(self):
        """1-way block where current target matches fix should emit no modification."""
        blk = BlockSnapshot(
            serial=5, block_type=3, succs=(10,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={5: blk}, entry_serial=5, func_ea=0x1000)
        fixes = {5: 10}  # Already goes to 10
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 0

    def test_multiple_fixes_emit_all_modifications(self):
        """Pass with multiple fixes should emit RedirectBranch/RedirectGoto for each."""
        blk10 = BlockSnapshot(
            serial=10, block_type=4, succs=(20, 30), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk15 = BlockSnapshot(
            serial=15, block_type=3, succs=(25,), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=3, succs=(99,), preds=(10,),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={10: blk10, 15: blk15, 20: blk20},
            entry_serial=10, func_ea=0x1000
        )
        fixes = {10: 20, 15: 35}  # Block 10 -> 20, Block 15 -> 35
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 2

        # Check both modifications are present (order not guaranteed)
        serials = {mod.from_serial for mod in mods}
        new_targets = {mod.new_target for mod in mods}
        assert serials == {10, 15}
        assert new_targets == {20, 35}

    def test_fix_for_nonexistent_block_skipped(self):
        """Fix referencing a block not in CFG should be skipped."""
        blk5 = BlockSnapshot(
            serial=5, block_type=4, succs=(10, 20), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
        # Fix references block 99 which doesn't exist
        fixes = {99: 100}
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 0

    def test_mixed_valid_and_invalid_fixes(self):
        """Mix of valid and invalid fixes should emit only valid ones."""
        blk5 = BlockSnapshot(
            serial=5, block_type=4, succs=(10, 20), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=3, succs=(99,), preds=(5,),
            flags=0, start_ea=0x2000, insn_snapshots=()
        )
        cfg = FlowGraph(
            blocks={5: blk5, 10: blk10},
            entry_serial=5, func_ea=0x1000
        )
        # Fix for 5 is valid, fix for 99 is invalid
        fixes = {5: 10, 99: 100}
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 1
        assert mods[0].from_serial == 5
        assert mods[0].new_target == 10

    def test_pass_name_and_tags(self):
        """Pass should have correct name and tags."""
        pass_instance = FakeJumpFixerPass(fixes={})

        assert pass_instance.name == "fake_jump_fixer"
        assert "unflattening" in pass_instance.tags
        assert "cleanup" in pass_instance.tags

    def test_repr(self):
        """Pass should have meaningful repr."""
        pass_instance = FakeJumpFixerPass(fixes={})
        repr_str = repr(pass_instance)

        assert "FakeJumpFixerPass" in repr_str
        assert "fake_jump_fixer" in repr_str

    def test_pipeline_integration(self):
        """Pass should integrate with PassPipeline and InMemoryBackend."""
        # Create a simple CFG with one 2-way block
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x2000, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1, 2: blk2}
        backend = InMemoryBackend(blocks)

        # Create pipeline with fake jump fixer
        fixes = {0: 1}  # Block 0's fake jump always goes to 1
        pass_instance = FakeJumpFixerPass(fixes=fixes)
        pipeline = FlowGraphTransformPipeline(backend, [pass_instance])

        # Run pipeline
        total_mods = pipeline.run(blocks)

        # Verify result
        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, RedirectBranch)
        assert mod.from_serial == 0
        assert mod.old_target == 2
        assert mod.new_target == 1

    def test_multiple_passes_in_pipeline(self):
        """Pass should work correctly when combined with other transform."""
        # Create CFG with two fake jumps
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=4, succs=(3, 4), preds=(0,),
            flags=0, start_ea=0x2000, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        blk3 = BlockSnapshot(
            serial=3, block_type=2, succs=(), preds=(1,),
            flags=0, start_ea=0x4000, insn_snapshots=()
        )
        blk4 = BlockSnapshot(
            serial=4, block_type=2, succs=(), preds=(1,),
            flags=0, start_ea=0x5000, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1, 2: blk2, 3: blk3, 4: blk4}
        backend = InMemoryBackend(blocks)

        # Create two transform: one for block 0, one for block 1
        pass1 = FakeJumpFixerPass(fixes={0: 1})
        pass2 = FakeJumpFixerPass(fixes={1: 3})
        pipeline = FlowGraphTransformPipeline(backend, [pass1, pass2])

        # Run pipeline
        total_mods = pipeline.run(blocks)

        # Verify both transform applied
        assert total_mods == 2
        assert len(backend.applied_modifications) == 2

        # Check both modifications
        serials = {mod.from_serial for mod in backend.applied_modifications}
        new_targets = {mod.new_target for mod in backend.applied_modifications}
        assert serials == {0, 1}
        assert new_targets == {1, 3}

    def test_default_none_fixes_creates_empty_dict(self):
        """Passing fixes=None should create empty dict, not None."""
        pass_instance = FakeJumpFixerPass(fixes=None)

        assert pass_instance._fixes == {}
        assert not pass_instance.is_applicable(FlowGraph(
            blocks={}, entry_serial=0, func_ea=0x1000
        ))

    def test_0way_block_with_fix_no_modification(self):
        """0-way block (no successors) should emit no modification even if in fixes."""
        blk5 = BlockSnapshot(
            serial=5, block_type=2, succs=(), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
        # Fix for 0-way block (should be ignored)
        fixes = {5: 10}
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 0

    def test_2way_block_both_succs_match_target_no_modification(self):
        """2-way block where both successors match target should emit no modification."""
        # Edge case: block has succs (10, 10) and target is 10
        blk5 = BlockSnapshot(
            serial=5, block_type=4, succs=(10, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
        fixes = {5: 10}
        pass_instance = FakeJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 0
