"""CFGPass that collapses chains of goto-only blocks.

This pass identifies 1-way blocks that contain only a goto instruction
(no meaningful computation) and redirects their predecessors to bypass
the intermediate goto block, directly targeting the goto's destination.

This is the CFGPass equivalent of mba_remove_simple_goto_blocks() from
cfg_mutations.py.

Example:
    >>> # Before: blk0 -> goto_blk (goto only) -> target
    >>> # After:  blk0 -> target
"""
from __future__ import annotations

from d810.hexrays.cfg_pass import CFGPass
from d810.hexrays.graph_modification import GraphModification, RedirectGoto
from d810.hexrays.portable_cfg import PortableCFG


class GotoChainRemovalPass(CFGPass):
    """Collapse goto-only blocks by redirecting their predecessors.

    This pass finds 1-way blocks that contain only a goto instruction
    (0-1 instructions total, since the goto itself is implicit in the
    block's successor edge). For each such block, it emits RedirectGoto
    modifications to update each predecessor to bypass the goto block.

    Self-loops are skipped to avoid infinite loops.

    Attributes:
        name: Unique identifier "goto_chain_removal".
        tags: Frozen set containing "cleanup" and "topology" tags.

    Example:
        >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
        >>> # Create chain: 0 -> 10 (goto only) -> 20
        >>> blk0 = BlockSnapshot(
        ...     serial=0, block_type=1, succs=(10,), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=()
        ... )
        >>> blk10_goto = BlockSnapshot(
        ...     serial=10, block_type=1, succs=(20,), preds=(0,),
        ...     flags=0, start_ea=0x1100, insn_snapshots=()
        ... )
        >>> blk20 = BlockSnapshot(
        ...     serial=20, block_type=0, succs=(), preds=(10,),
        ...     flags=0, start_ea=0x1200, insn_snapshots=()
        ... )
        >>> cfg = PortableCFG(blocks={0: blk0, 10: blk10_goto, 20: blk20}, entry_serial=0, func_ea=0x1000)
        >>> pass_instance = GotoChainRemovalPass()
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> mods[0].from_serial
        0
        >>> isinstance(mods[0], RedirectGoto)
        True
        >>> mods[0].old_target
        10
        >>> mods[0].new_target
        20
    """
    name = "goto_chain_removal"
    tags = frozenset({"cleanup", "topology"})

    def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        """Analyze CFG and return RedirectGoto for goto-only blocks.

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of RedirectGoto modifications to bypass goto-only blocks.
            Each predecessor of a goto-only block gets one RedirectGoto
            modification. Empty list if no goto-only blocks exist.

        Example:
            >>> # No goto-only blocks: no modifications
            >>> blk0 = BlockSnapshot(
            ...     serial=0, block_type=1, succs=(1,), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=(
            ...         InsnSnapshot(opcode=0x01, ea=0x1000, operands=()),
            ...         InsnSnapshot(opcode=0x02, ea=0x1004, operands=()),
            ...     )
            ... )
            >>> blk1 = BlockSnapshot(
            ...     serial=1, block_type=0, succs=(), preds=(0,),
            ...     flags=0, start_ea=0x1010, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)
            >>> pass_instance = GotoChainRemovalPass()
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            0
        """
        mods = []

        for serial, blk in cfg.blocks.items():
            # Check: 1-way block (single successor) with 0-1 instructions
            # A goto-only block has at most 1 instruction (the goto itself,
            # which is represented implicitly by the successor edge)
            if len(blk.succs) != 1:
                continue

            target = blk.succs[0]

            # Skip self-loops (block that gotos itself)
            if target == serial:
                continue

            # Goto-only blocks have 0-1 instructions
            # (0 = empty block, 1 = may have a single NOP or placeholder)
            if len(blk.insn_snapshots) > 1:
                continue

            # For each predecessor, emit RedirectGoto to bypass this goto block.
            # Goto-only blocks are 1-way (single successor), so predecessors
            # targeting them via unconditional goto use RedirectGoto.
            for pred_serial in blk.preds:
                mods.append(
                    RedirectGoto(
                        from_serial=pred_serial,
                        old_target=serial,
                        new_target=target,
                    )
                )

        return mods


__all__ = ["GotoChainRemovalPass"]
