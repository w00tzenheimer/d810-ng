"""FlowGraphTransform that merges artificially split basic blocks.

This pass migrates the functionality of BlockMerger from
optimizers/microcode/flow/block_merge.py into the FlowGraphTransform/PassPipeline framework.

When a block B has a single successor S, and S has a single predecessor B,
the trailing goto in B is redundant. This pass signals to NOP that goto so
IDA's optimizer can merge the two blocks.

Algorithm:
1. For each block B:
   - Check B is BLT_1WAY (block_type == 3)
   - Check B has exactly one successor S
   - Check B is not a self-loop (B != S)
   - Check B's tail instruction is m_goto (opcode == 55 / 0x37)
   - Check the goto destination operand (mop_b, type==7) matches S's serial
   - Check S has exactly one predecessor (B)
   - If all conditions hold, emit NopInstructions for B's tail goto

Example:
    >>> # Before: Block 10 -> goto -> Block 20 (no other edges)
    >>> # After:  Block 10 merged with Block 20 (goto NOPed)
"""
from __future__ import annotations

import ida_hexrays

from d810.cfg.passes._base import FlowGraphTransform
from d810.cfg.graph_modification import GraphModification, NopInstructions
from d810.cfg.flowgraph import FlowGraph

_BLT_1WAY = ida_hexrays.BLT_1WAY
_M_GOTO_OPCODE = ida_hexrays.m_goto
_MOP_B_TYPE = ida_hexrays.mop_b


class BlockMergeTransform(FlowGraphTransform):
    """Merge artificially split basic blocks by NOPing redundant gotos.

    This pass detects block pairs where:
    - Block B has block_type == 3 (BLT_1WAY)
    - Block B has exactly one successor S
    - B is not a self-loop
    - B's tail instruction is m_goto (opcode 55 / 0x37)
    - The goto's destination operand has type mop_b (7) matching S's serial
    - Block S has exactly one predecessor (this block)

    When detected, the trailing goto in B is NOPed via NopInstructions,
    signaling to IDA's optimizer that the blocks can be merged.

    This is the FlowGraphTransform equivalent of the existing BlockMerger rule in
    optimizers/microcode/flow/block_merge.py.

    Attributes:
        name: Unique identifier "block_merge".
        tags: Frozen set containing "cleanup" and "topology" tags.

    Example:
        >>> from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
        >>> from d810.hexrays.ir.mop_snapshot import MopSnapshot
        >>> # Create mergeable pair: block 0 -> block 1 (1:1 relationship)
        >>> dest_mop = MopSnapshot(t=7, size=4, block_num=1)  # mop_b -> block 1
        >>> goto_insn = InsnSnapshot(opcode=55, ea=0x1000, operands=(dest_mop,))
        >>> blk0 = BlockSnapshot(
        ...     serial=0, block_type=3, succs=(1,), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,)
        ... )
        >>> blk1 = BlockSnapshot(
        ...     serial=1, block_type=3, succs=(2,), preds=(0,),
        ...     flags=0, start_ea=0x1010, insn_snapshots=()
        ... )
        >>> blk2 = BlockSnapshot(
        ...     serial=2, block_type=2, succs=(), preds=(1,),
        ...     flags=0, start_ea=0x1020, insn_snapshots=()
        ... )
        >>> cfg = FlowGraph(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)
        >>> pass_instance = BlockMergeTransform()
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

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Analyze CFG and return NopInstructions for mergeable block pairs.

        Args:
            cfg: FlowGraph snapshot to analyze.

        Returns:
            List of NopInstructions modifications for blocks where:
            - Block has block_type == 3 (BLT_1WAY)
            - Block has exactly 1 successor
            - Successor has exactly 1 predecessor (this block)
            - Block is not a self-loop
            - Block tail is m_goto (opcode 55) with mop_b destination matching
              the successor serial
            - Block has at least one instruction with a valid EA (tail goto)

            Empty list if no mergeable pairs exist.

        Example:
            >>> # Block with multiple successors: no merge
            >>> blk = BlockSnapshot(
            ...     serial=0, block_type=4, succs=(5, 10), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
            >>> pass_instance = BlockMergeTransform()
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            0
        """
        mods = []
        for serial, blk in cfg.blocks.items():
            # Check 1: Block must be BLT_1WAY (unconditional jump block)
            # Reject BLT_0WAY (2), BLT_2WAY (4), BLT_NWAY (5)
            if blk.block_type != _BLT_1WAY:
                continue

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

            # Must have instructions to NOP
            if not blk.insn_snapshots:
                continue

            tail_insn = blk.insn_snapshots[-1]

            # Check 2: Tail instruction must be m_goto (opcode 55 / 0x37)
            # If the tail is not a goto, it's a fall-through block - skip it.
            if tail_insn.opcode != _M_GOTO_OPCODE:
                continue

            # Only NOP if the instruction has a valid EA (non-zero)
            if tail_insn.ea == 0:
                continue

            # Check 3: Goto destination must reference the successor block
            # The destination operand has type mop_b (7) with block_num == succ_serial
            if not self._goto_targets_successor(tail_insn.operands, succ_serial):
                continue

            mods.append(NopInstructions(
                block_serial=serial,
                insn_eas=(tail_insn.ea,)
            ))

        return mods

    @staticmethod
    def _goto_targets_successor(operands: tuple, succ_serial: int) -> bool:
        """Check whether any operand is a mop_b reference to succ_serial.

        For m_goto the destination is stored in the ``l`` slot of the
        instruction, which becomes operands[0] in InsnSnapshot.  However,
        we scan all captured operands so the check is robust against
        different lift implementations.

        Args:
            operands: Tuple of MopSnapshot instances from the tail instruction.
            succ_serial: Expected target block serial number.

        Returns:
            True if an operand with type mop_b (7) and block_num == succ_serial
            is found; False otherwise (including when operands is empty).
        """
        for op in operands:
            if op.t == _MOP_B_TYPE and op.block_num == succ_serial:
                return True
        return False


__all__ = ["BlockMergeTransform"]
