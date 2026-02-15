"""CFGPass that eliminates unreachable (dead) blocks from the CFG.

This pass identifies blocks that are unreachable from the entry block via
standard control flow (following successor edges). For each dead block,
it emits a NopInstructions modification to clear all instructions, allowing
IDA's subsequent cleanup passes to remove the empty block.

Example:
    >>> # Entry block (0) connects to block 1
    >>> # Block 2 is unreachable (dead)
    >>> # Pass emits NopInstructions(block_serial=2, insn_eas=(...))
"""
from __future__ import annotations

from d810.hexrays.cfg_pass import CFGPass
from d810.hexrays.graph_modification import GraphModification, NopInstructions
from d810.hexrays.portable_cfg import PortableCFG


class DeadBlockEliminationPass(CFGPass):
    """Eliminate unreachable blocks by NOPing their instructions.

    This pass performs a reachability analysis from the entry block,
    following successor edges. Any block not reachable from entry is
    considered dead. For each dead block, the pass emits a NopInstructions
    modification containing all instruction EAs in that block.

    Attributes:
        name: Unique identifier "dead_block_elimination".
        tags: Frozen set containing "cleanup" and "topology" tags.

    Example:
        >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG, InsnSnapshot
        >>> # Create entry block (0) -> block 1
        >>> blk0 = BlockSnapshot(
        ...     serial=0, block_type=1, succs=(1,), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=()
        ... )
        >>> blk1 = BlockSnapshot(
        ...     serial=1, block_type=0, succs=(), preds=(0,),
        ...     flags=0, start_ea=0x1010, insn_snapshots=()
        ... )
        >>> # Dead block 2 (unreachable)
        >>> insn_dead = InsnSnapshot(opcode=0x01, ea=0x2000, operands=())
        >>> blk2 = BlockSnapshot(
        ...     serial=2, block_type=0, succs=(), preds=(),
        ...     flags=0, start_ea=0x2000, insn_snapshots=(insn_dead,)
        ... )
        >>> cfg = PortableCFG(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)
        >>> pass_instance = DeadBlockEliminationPass()
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> mods[0].block_serial
        2
        >>> 0x2000 in mods[0].insn_eas
        True
    """
    name = "dead_block_elimination"
    tags = frozenset({"cleanup", "topology"})

    def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        """Analyze CFG and return NopInstructions for unreachable blocks.

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of NopInstructions modifications for blocks unreachable
            from entry. Each modification contains all instruction EAs
            in the dead block. Empty list if all blocks are reachable.

        Example:
            >>> # All blocks reachable: no modifications
            >>> blk0 = BlockSnapshot(
            ...     serial=0, block_type=1, succs=(1,), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> blk1 = BlockSnapshot(
            ...     serial=1, block_type=0, succs=(), preds=(0,),
            ...     flags=0, start_ea=0x1010, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)
            >>> pass_instance = DeadBlockEliminationPass()
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            0
        """
        # Find all reachable blocks from entry
        reachable = self._find_reachable(cfg)

        # Build modification list for unreachable blocks
        mods = []
        for serial, blk in cfg.blocks.items():
            if serial not in reachable:
                # Collect all instruction EAs in this dead block
                # Skip instructions with ea=0 (synthesized/placeholder)
                insn_eas = tuple(
                    insn.ea for insn in blk.insn_snapshots if insn.ea != 0
                )
                # Only emit modification if there are instructions to NOP
                if insn_eas:
                    mods.append(NopInstructions(block_serial=serial, insn_eas=insn_eas))

        return mods

    @staticmethod
    def _find_reachable(cfg: PortableCFG) -> set[int]:
        """Perform reachability analysis from entry block.

        Uses depth-first traversal to mark all blocks reachable from
        the entry block by following successor edges.

        Args:
            cfg: Portable CFG to analyze.

        Returns:
            Set of block serials reachable from entry.

        Example:
            >>> blk0 = BlockSnapshot(
            ...     serial=0, block_type=1, succs=(1,), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> blk1 = BlockSnapshot(
            ...     serial=1, block_type=0, succs=(), preds=(0,),
            ...     flags=0, start_ea=0x1010, insn_snapshots=()
            ... )
            >>> blk2 = BlockSnapshot(
            ...     serial=2, block_type=0, succs=(), preds=(),
            ...     flags=0, start_ea=0x2000, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)
            >>> reachable = DeadBlockEliminationPass._find_reachable(cfg)
            >>> reachable == {0, 1}
            True
            >>> 2 in reachable
            False
        """
        visited = set()
        stack = [cfg.entry_serial]

        while stack:
            serial = stack.pop()
            if serial in visited:
                continue
            visited.add(serial)

            # Add successors to stack if block exists in CFG
            if serial in cfg.blocks:
                for succ_serial in cfg.blocks[serial].succs:
                    if succ_serial not in visited:
                        stack.append(succ_serial)

        return visited


__all__ = ["DeadBlockEliminationPass"]
