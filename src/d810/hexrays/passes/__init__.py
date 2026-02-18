"""CFGPass implementations for common CFG transformations."""
from __future__ import annotations

from d810.hexrays.passes.block_merge import BlockMergePass
from d810.hexrays.passes.dead_block_elimination import DeadBlockEliminationPass
from d810.hexrays.passes.fake_jump_fixer import FakeJumpFixerPass
from d810.hexrays.passes.goto_chain_removal import GotoChainRemovalPass
from d810.hexrays.passes.opaque_jump_fixer import OpaqueJumpFixerPass
from d810.hexrays.passes.simplify_identical_branch import SimplifyIdenticalBranchPass

__all__ = [
    "BlockMergePass",
    "DeadBlockEliminationPass",
    "FakeJumpFixerPass",
    "GotoChainRemovalPass",
    "OpaqueJumpFixerPass",
    "SimplifyIdenticalBranchPass",
]
