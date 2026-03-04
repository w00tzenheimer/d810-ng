"""FlowGraphTransform that simplifies 2-way blocks with identical branch targets to 1-way gotos.

This pass migrates the functionality of make_2way_block_goto() from cfg_mutations.py
into the FlowGraphTransform/PassPipeline framework. When a conditional branch has identical
true/false targets, the condition is dead and can be replaced with an unconditional goto.

Example:
    >>> # Before: if (cond) goto B else goto B
    >>> # After:  goto B
"""
from __future__ import annotations

from d810.cfg.transform._base import FlowGraphTransform
from d810.cfg.graph_modification import ConvertToGoto, GraphModification
from d810.cfg.flowgraph import FlowGraph


class SimplifyIdenticalBranchPass(FlowGraphTransform):
    """Convert 2-way blocks where both successors are the same to 1-way goto.

    When a conditional branch has identical true/false targets, the condition
    is dead and can be replaced with an unconditional goto.

    This is the FlowGraphTransform equivalent of the existing make_2way_block_goto()
    function in cfg_mutations.py.

    Attributes:
        name: Unique identifier "simplify_identical_branch".
        tags: Frozen set containing "cleanup" tag.

    Example:
        >>> from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
        >>> # Create 2-way block with identical successors
        >>> blk = BlockSnapshot(
        ...     serial=0, block_type=2, succs=(5, 5), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=()
        ... )
        >>> cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        >>> pass_instance = SimplifyIdenticalBranchPass()
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> mods[0].block_serial
        0
        >>> mods[0].goto_target
        5
    """
    name = "simplify_identical_branch"
    tags = frozenset({"cleanup"})

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Analyze CFG and return ConvertToGoto for 2-way blocks with identical targets.

        Args:
            cfg: FlowGraph snapshot to analyze.

        Returns:
            List of ConvertToGoto modifications for blocks where:
            - Block has exactly 2 successors (2-way conditional)
            - Both successors are the same serial number
            Empty list if no such blocks exist.

        Example:
            >>> # 2-way block with different targets: no modification
            >>> blk = BlockSnapshot(
            ...     serial=0, block_type=2, succs=(5, 10), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
            >>> pass_instance = SimplifyIdenticalBranchPass()
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            0
        """
        mods = []
        for serial, blk in cfg.blocks.items():
            # Check: 2-way block (nsucc == 2) with identical successors
            if len(blk.succs) == 2 and blk.succs[0] == blk.succs[1]:
                mods.append(ConvertToGoto(block_serial=serial, goto_target=blk.succs[0]))
        return mods


__all__ = ["SimplifyIdenticalBranchPass"]
