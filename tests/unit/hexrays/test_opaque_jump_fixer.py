"""Tests for OpaqueJumpFixerPass CFG transformation pass.

This module tests the CFG-level jump fixing logic extracted from JumpFixer.
"""
from __future__ import annotations

import pytest

from d810.cfg.passes.opaque_jump_fixer import OpaqueJumpFixerPass
from d810.cfg.graph_modification import ConvertToGoto
from d810.cfg.flowgraph import BlockSnapshot, PortableCFG
from d810.cfg.pipeline import PassPipeline

from tests.unit.hexrays.conftest import InMemoryBackend


class TestOpaqueJumpFixerPass:
    """Test suite for OpaqueJumpFixerPass."""

    def test_empty_fixes_not_applicable(self):
        """Pass with empty fixes should not be applicable."""
        cfg = PortableCFG(blocks={}, entry_serial=0, func_ea=0x1000)
        pass_instance = OpaqueJumpFixerPass(fixes={})

        assert not pass_instance.is_applicable(cfg)

    def test_non_empty_fixes_applicable(self):
        """Pass with non-empty fixes should be applicable."""
        cfg = PortableCFG(blocks={}, entry_serial=0, func_ea=0x1000)
        pass_instance = OpaqueJumpFixerPass(fixes={5: 10})

        assert pass_instance.is_applicable(cfg)

    def test_empty_fixes_no_modifications(self):
        """Pass with empty fixes should return empty modification list."""
        blk = BlockSnapshot(
            serial=0, block_type=4, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = PortableCFG(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        pass_instance = OpaqueJumpFixerPass(fixes={})

        mods = pass_instance.transform(cfg)
        assert len(mods) == 0

    def test_single_fix_emits_convert_to_goto(self):
        """Pass with single fix should emit one ConvertToGoto."""
        blk = BlockSnapshot(
            serial=5, block_type=4, succs=(10, 20), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = PortableCFG(blocks={5: blk}, entry_serial=5, func_ea=0x1000)
        fixes = {5: 10}
        pass_instance = OpaqueJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 1
        assert isinstance(mods[0], ConvertToGoto)
        assert mods[0].block_serial == 5
        assert mods[0].goto_target == 10

    def test_multiple_fixes_emit_all_modifications(self):
        """Pass with multiple fixes should emit ConvertToGoto for each."""
        blk10 = BlockSnapshot(
            serial=10, block_type=4, succs=(20, 30), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk15 = BlockSnapshot(
            serial=15, block_type=4, succs=(25, 35), preds=(),
            flags=0, start_ea=0x2000, insn_snapshots=()
        )
        blk20 = BlockSnapshot(
            serial=20, block_type=3, succs=(99,), preds=(10,),
            flags=0, start_ea=0x3000, insn_snapshots=()
        )
        cfg = PortableCFG(
            blocks={10: blk10, 15: blk15, 20: blk20},
            entry_serial=10, func_ea=0x1000
        )
        fixes = {10: 20, 15: 25}
        pass_instance = OpaqueJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 2

        # Check both modifications are present (order not guaranteed)
        serials = {mod.block_serial for mod in mods}
        targets = {mod.goto_target for mod in mods}
        assert serials == {10, 15}
        assert targets == {20, 25}

    def test_fix_for_nonexistent_block_skipped(self):
        """Fix referencing a block not in CFG should be skipped."""
        blk5 = BlockSnapshot(
            serial=5, block_type=4, succs=(10, 20), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = PortableCFG(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
        # Fix references block 99 which doesn't exist
        fixes = {99: 100}
        pass_instance = OpaqueJumpFixerPass(fixes=fixes)

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
        cfg = PortableCFG(
            blocks={5: blk5, 10: blk10},
            entry_serial=5, func_ea=0x1000
        )
        # Fix for 5 is valid, fix for 99 is invalid
        fixes = {5: 10, 99: 100}
        pass_instance = OpaqueJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 1
        assert mods[0].block_serial == 5
        assert mods[0].goto_target == 10

    def test_pass_name_and_tags(self):
        """Pass should have correct name and tags."""
        pass_instance = OpaqueJumpFixerPass(fixes={})

        assert pass_instance.name == "opaque_jump_fixer"
        assert "deobfuscation" in pass_instance.tags
        assert "jump" in pass_instance.tags

    def test_repr(self):
        """Pass should have meaningful repr."""
        pass_instance = OpaqueJumpFixerPass(fixes={})
        repr_str = repr(pass_instance)

        assert "OpaqueJumpFixerPass" in repr_str
        assert "opaque_jump_fixer" in repr_str

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

        # Create pipeline with opaque jump fixer
        fixes = {0: 1}  # Block 0's opaque predicate always goes to 1
        pass_instance = OpaqueJumpFixerPass(fixes=fixes)
        pipeline = PassPipeline(backend, [pass_instance])

        # Run pipeline
        total_mods = pipeline.run(blocks)

        # Verify result
        assert total_mods == 1
        assert len(backend.applied_modifications) == 1
        mod = backend.applied_modifications[0]
        assert isinstance(mod, ConvertToGoto)
        assert mod.block_serial == 0
        assert mod.goto_target == 1

    def test_multiple_passes_in_pipeline(self):
        """Pass should work correctly when combined with other passes."""
        # Create CFG with two opaque jumps
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

        # Create two passes: one for block 0, one for block 1
        pass1 = OpaqueJumpFixerPass(fixes={0: 1})
        pass2 = OpaqueJumpFixerPass(fixes={1: 3})
        pipeline = PassPipeline(backend, [pass1, pass2])

        # Run pipeline
        total_mods = pipeline.run(blocks)

        # Verify both passes applied
        assert total_mods == 2
        assert len(backend.applied_modifications) == 2

        # Check both modifications
        serials = {mod.block_serial for mod in backend.applied_modifications}
        targets = {mod.goto_target for mod in backend.applied_modifications}
        assert serials == {0, 1}
        assert targets == {1, 3}

    def test_default_none_fixes_creates_empty_dict(self):
        """Passing fixes=None should create empty dict, not None."""
        pass_instance = OpaqueJumpFixerPass(fixes=None)

        assert pass_instance._fixes == {}
        assert not pass_instance.is_applicable(PortableCFG(
            blocks={}, entry_serial=0, func_ea=0x1000
        ))

    def test_fix_pointing_to_same_block_allowed(self):
        """Fix where target equals source should be allowed (edge case)."""
        blk5 = BlockSnapshot(
            serial=5, block_type=4, succs=(5, 10), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = PortableCFG(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
        # Self-loop fix (unusual but allowed by ConvertToGoto)
        fixes = {5: 5}
        pass_instance = OpaqueJumpFixerPass(fixes=fixes)

        mods = pass_instance.transform(cfg)
        assert len(mods) == 1
        assert mods[0].block_serial == 5
        assert mods[0].goto_target == 5
