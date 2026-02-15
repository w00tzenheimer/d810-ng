"""CFGPass that merges artificially split basic blocks.

This pass migrates the functionality of BlockMerger from
optimizers/microcode/flow/block_merge.py into the CFGPass/PassPipeline framework.

When a block B has a single successor S, and S has a single predecessor B,
the trailing goto in B is redundant. This pass signals to NOP that goto so
IDA's optimizer can merge the two blocks.

Algorithm:
1. For each block B:
   - Check B has exactly one successor S
   - Check S has exactly one predecessor (B)
   - Check B is not a self-loop (B != S)
   - If all conditions hold, emit NopInstructions for B's tail goto

Example:
    >>> # Before: Block 10 -> goto -> Block 20 (no other edges)
    >>> # After:  Block 10 merged with Block 20 (goto NOPed)
"""
from __future__ import annotations

from d810.hexrays.cfg_pass import CFGPass
from d810.hexrays.graph_modification import GraphModification, NopInstructions
from d810.hexrays.portable_cfg import PortableCFG


class BlockMergePass(CFGPass):
    """Merge artificially split basic blocks by NOPing redundant gotos.

    This pass detects block pairs where:
    - Block B has exactly one successor S
    - Block S has exactly one predecessor (B)
    - B is not a self-loop

    When detected, the trailing goto in B is NOPed via NopInstructions,
    signaling to IDA's optimizer that the blocks can be merged.

    This is the CFGPass equivalent of the existing BlockMerger rule in
    optimizers/microcode/flow/block_merge.py.

    Attributes:
        name: Unique identifier "block_merge".
        tags: Frozen set containing "cleanup" and "topology" tags.

    Example:
        >>> from d810.hexrays.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
        >>> # Create mergeable pair: block 0 -> block 1 (1:1 relationship)
        >>> goto_insn = InsnSnapshot(opcode=0x2b, ea=0x1000, operands=())  # m_goto
        >>> blk0 = BlockSnapshot(
        ...     serial=0, block_type=1, succs=(1,), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        ... )
        >>> blk1 = BlockSnapshot(
        ...     serial=1, block_type=1, succs=(2,), preds=(0,),
        ...     flags=0, start_ea=0x1010, insn_snapshots=()
        ... )
        >>> blk2 = BlockSnapshot(
        ...     serial=2, block_type=0, succs=(), preds=(1,),
        ...     flags=0, start_ea=0x1020, insn_snapshots=()
        ... )
        >>> cfg = PortableCFG(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)
        >>> pass_instance = BlockMergePass()
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> mods[0].block_serial
        0
        >>> mods[0].insn_eas
        (4096,)
    """
    name = "block_merge"
    tags = frozenset({"cleanup", "topology"})

    def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        """Analyze CFG and return NopInstructions for mergeable block pairs.

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of NopInstructions modifications for blocks where:
            - Block has exactly 1 successor
            - Successor has exactly 1 predecessor (this block)
            - Block is not a self-loop
            - Block has at least one instruction with a valid EA (tail goto)

            Empty list if no mergeable pairs exist.

        Example:
            >>> # Block with multiple successors: no merge
            >>> blk = BlockSnapshot(
            ...     serial=0, block_type=2, succs=(5, 10), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
            >>> pass_instance = BlockMergePass()
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            0
        """
        mods = []
        for serial, blk in cfg.blocks.items():
            # Candidate: 1-way block with single successor
            if len(blk.succs) != 1:
                continue

            succ_serial = blk.succs[0]

            # Reject self-loop (infinite loop guard)
            if succ_serial == serial:
                continue

            # Successor must exist in CFG
            if succ_serial not in cfg.blocks:
                continue

            succ = cfg.blocks[succ_serial]

            # Successor must have single predecessor (this block)
            if len(succ.preds) != 1 or succ.preds[0] != serial:
                continue

            # Emit NOP for the tail goto instruction
            # The actual block merging is done by IDA's optimizer after NOPing
            if blk.insn_snapshots:
                tail_insn = blk.insn_snapshots[-1]
                # Only NOP if the instruction has a valid EA (non-zero)
                if tail_insn.ea != 0:
                    mods.append(NopInstructions(
                        block_serial=serial,
                        insn_eas=(tail_insn.ea,)
                    ))

        return mods


__all__ = ["BlockMergePass"]
