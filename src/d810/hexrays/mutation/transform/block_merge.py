"""FlowGraphTransform that merges artificially split basic blocks.

This pass contains the CFG analysis for block-merge cleanup and emits
backend-neutral ``NopInstructions`` primitives.

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

from d810.transforms._base import FlowGraphTransform
from d810.transforms.graph_modification import GraphModification, NopInstructions
from d810.ir.flowgraph import FlowGraph

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

    This is the FlowGraphTransform form of the legacy block-merge cleanup.

    Attributes:
        name: Unique identifier "block_merge".
        tags: Frozen set containing "cleanup" and "topology" tags.

    Example:
        >>> from d810.ir.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
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

            # Check 3: Goto destination must reference the successor block.
            # Live snapshots carry the Hex-Rays destination slot separately;
            # require that slot to match when present so this transform stays
            # equivalent to the legacy block-merge rule.  Minimal unit-test
            # snapshots predate typed slots, so they fall back to operand scan.
            if not self._goto_targets_successor(tail_insn, succ_serial):
                continue

            mods.append(NopInstructions(
                block_serial=serial,
                insn_eas=(tail_insn.ea,)
            ))

        return mods

    @staticmethod
    def _goto_targets_successor(tail_insn, succ_serial: int) -> bool:
        """Check whether the goto destination references succ_serial.

        Live snapshots populate the typed ``d`` slot.  When it is present,
        mirror the legacy rule exactly: the destination slot must be ``mop_b``
        and must equal the successor.  Older tests construct minimal snapshots
        with only ``operands`` populated, so those still use the broader scan.

        Args:
            tail_insn: Tail instruction snapshot.
            succ_serial: Expected target block serial number.

        Returns:
            True if the destination references ``succ_serial``.
        """
        d = getattr(tail_insn, "d", None)
        if d is not None:
            return (
                getattr(d, "t", None) == _MOP_B_TYPE
                and getattr(d, "block_ref", None) == succ_serial
            )

        for op in getattr(tail_insn, "operands", ()):
            if (
                getattr(op, "t", None) == _MOP_B_TYPE
                and getattr(op, "block_num", None) == succ_serial
            ):
                return True
        return False


__all__ = ["BlockMergeTransform"]
