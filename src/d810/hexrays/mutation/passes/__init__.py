"""IDA/Hex-Rays specific mutation passes."""
from __future__ import annotations

from d810.hexrays.mutation.passes.block_merge import BlockMergePass
from d810.hexrays.mutation.passes.goto_chain_removal import GotoChainRemovalPass

__all__ = [
    "BlockMergePass",
    "GotoChainRemovalPass",
]
