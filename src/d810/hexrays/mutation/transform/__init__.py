"""IDA/Hex-Rays specific mutation transform."""
from __future__ import annotations

from d810.hexrays.mutation.transform.block_merge import BlockMergeTransform
from d810.hexrays.mutation.transform.goto_chain_removal import GotoChainRemovalPass

__all__ = [
    "BlockMergeTransform",
    "GotoChainRemovalPass",
]
