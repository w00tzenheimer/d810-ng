"""CFGPass implementations for common CFG transformations."""
from __future__ import annotations

from d810.cfg.passes.block_merge import BlockMergePass
from d810.cfg.passes.dead_block_elimination import DeadBlockEliminationPass
from d810.cfg.passes.fake_jump_fixer import FakeJumpFixerPass
from d810.cfg.passes.goto_chain_removal import GotoChainRemovalPass
from d810.cfg.passes.opaque_jump_fixer import OpaqueJumpFixerPass
from d810.cfg.passes.simplify_identical_branch import SimplifyIdenticalBranchPass

__all__ = [
    "BlockMergePass",
    "DeadBlockEliminationPass",
    "FakeJumpFixerPass",
    "GotoChainRemovalPass",
    "OpaqueJumpFixerPass",
    "SimplifyIdenticalBranchPass",
]
