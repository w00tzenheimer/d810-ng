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
from d810.hexrays.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.hexrays.microcode_constants import BLT_1WAY as _BLT_1WAY
from d810.hexrays.microcode_constants import BLT_2WAY as _BLT_2WAY
from d810.hexrays.microcode_constants import M_GOTO as _M_GOTO_OPCODE
from d810.hexrays.microcode_constants import MOP_B as _MOP_B_TYPE
from d810.hexrays.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG


def _goto_targets_successor(operands: tuple, succ_serial: int) -> bool:
    """Check whether any operand is a mop_b reference to succ_serial.

    For m_goto the destination is stored in the ``l`` slot of the
    instruction, which becomes operands[0] in InsnSnapshot.  We scan
    all captured operands so the check is robust against different lift
    implementations.

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


def _is_simple_goto_block(blk: BlockSnapshot, cfg: PortableCFG) -> bool:
    """Return True if blk is a simple goto-only block (equivalent to is_simple_goto_block()).

    A simple goto block must satisfy ALL of:
    - Exactly one instruction (not 0, not 2+)
    - That instruction's opcode == _M_GOTO_OPCODE (55 / m_goto)
    - That instruction has a mop_b operand (type 7) referencing blk.succs[0]

    Empty blocks (0 instructions) and blocks whose single instruction is NOT
    m_goto are explicitly rejected.

    Args:
        blk: BlockSnapshot to test.
        cfg: Containing PortableCFG (used to validate successor exists).

    Returns:
        True if blk is a simple goto block, False otherwise.
    """
    # Must have exactly 1 instruction
    if len(blk.insn_snapshots) != 1:
        return False

    tail = blk.insn_snapshots[0]

    # That instruction must be m_goto
    if tail.opcode != _M_GOTO_OPCODE:
        return False

    # Must have exactly one successor to validate against
    if len(blk.succs) != 1:
        return False

    succ_serial = blk.succs[0]

    # The goto's mop_b operand must match the successor
    if not _goto_targets_successor(tail.operands, succ_serial):
        return False

    return True


class GotoChainRemovalPass(CFGPass):
    """Collapse goto-only blocks by redirecting their predecessors.

    This pass finds 1-way blocks that contain exactly one m_goto instruction
    whose mop_b destination operand matches the block's single successor.
    For each such block it emits the appropriate modification for each
    predecessor:

    - 1-way predecessor (block_type == 3)  -> RedirectGoto
    - 2-way predecessor (block_type == 4)  -> RedirectBranch

    Safety guards (matching the legacy mba_remove_simple_goto_blocks()):
    - The last block (highest serial, IDA sentinel dummy) is never treated
      as a goto-only block.
    - Empty blocks (0 instructions) are NOT considered simple goto blocks.
    - Self-loops are skipped to avoid infinite loops.
    - The goto destination is verified via the tail instruction's mop_b
      operand (not solely from blk.succs[0]).

    Attributes:
        name: Unique identifier "goto_chain_removal".
        tags: Frozen set containing "cleanup" and "topology" tags.

    Example:
        >>> from d810.hexrays.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
        >>> from d810.hexrays.mop_snapshot import MopSnapshot
        >>> dest_mop = MopSnapshot(t=7, size=4, block_num=20)
        >>> goto_insn = InsnSnapshot(opcode=55, ea=0x1100, operands=(dest_mop,))
        >>> blk0 = BlockSnapshot(
        ...     serial=0, block_type=3, succs=(10,), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=()
        ... )
        >>> blk10_goto = BlockSnapshot(
        ...     serial=10, block_type=3, succs=(20,), preds=(0,),
        ...     flags=0, start_ea=0x1100, insn_snapshots=(goto_insn,)
        ... )
        >>> blk20 = BlockSnapshot(
        ...     serial=20, block_type=2, succs=(), preds=(10,),
        ...     flags=0, start_ea=0x1200, insn_snapshots=()
        ... )
        >>> cfg = PortableCFG(blocks={0: blk0, 10: blk10_goto, 20: blk20}, entry_serial=0, func_ea=0x1000)
        >>> pass_instance = GotoChainRemovalPass()
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> isinstance(mods[0], RedirectGoto)
        True
        >>> mods[0].from_serial
        0
        >>> mods[0].old_target
        10
        >>> mods[0].new_target
        20
    """
    name = "goto_chain_removal"
    tags = frozenset({"cleanup", "topology"})

    def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        """Analyze CFG and return edge-redirect modifications for goto-only blocks.

        Mirrors the logic of mba_remove_simple_goto_blocks() from cfg_mutations.py:
        - Skips the last block (IDA sentinel dummy block at max serial).
        - Requires the candidate block to pass _is_simple_goto_block() which
          verifies exactly 1 instruction, m_goto opcode, and mop_b destination.
        - Emits RedirectGoto for 1-way predecessors and RedirectBranch for
          2-way predecessors.
        - Uses the mop_b operand's block_num as new_target (not just succs[0]).

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of RedirectGoto / RedirectBranch modifications. Empty list if
            no simple goto blocks exist.

        Example:
            >>> # No goto-only blocks: no modifications
            >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
            >>> blk0 = BlockSnapshot(
            ...     serial=0, block_type=3, succs=(1,), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> blk1 = BlockSnapshot(
            ...     serial=1, block_type=2, succs=(), preds=(0,),
            ...     flags=0, start_ea=0x1010, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)
            >>> pass_instance = GotoChainRemovalPass()
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            0
        """
        mods: list[GraphModification] = []

        if not cfg.blocks:
            return mods

        # HIGH-1: IDA's MBA has a sentinel dummy block at the highest serial.
        # The legacy code iterates range(last_block_index) which excludes it.
        last_serial = max(cfg.blocks.keys())

        for serial, blk in cfg.blocks.items():
            # HIGH-1: Skip the sentinel dummy block (highest serial in CFG)
            if serial == last_serial:
                continue

            # Must be a 1-way block (single unconditional successor)
            if len(blk.succs) != 1:
                continue

            target = blk.succs[0]

            # Skip self-loops (block that gotos itself)
            if target == serial:
                continue

            # CRITICAL-1: Must be a true simple goto block:
            # exactly 1 instruction, opcode==m_goto, mop_b operand matches successor
            if not _is_simple_goto_block(blk, cfg):
                continue

            # HIGH-2: Read the authoritative destination from the mop_b operand
            # (same as legacy: goto_blk_dst_serial = goto_blk.tail.l.b)
            tail = blk.insn_snapshots[0]
            new_target: int | None = None
            for op in tail.operands:
                if op.t == _MOP_B_TYPE and op.block_num == target:
                    new_target = op.block_num
                    break

            if new_target is None:
                # Should not happen since _is_simple_goto_block passed, but guard anyway
                continue

            # CRITICAL-2: For each predecessor emit the correct modification type:
            # - 1-way predecessor (block_type == 1) -> RedirectGoto
            # - 2-way predecessor (block_type == 2) -> RedirectBranch
            for pred_serial in blk.preds:
                pred_blk = cfg.blocks.get(pred_serial)
                if pred_blk is None:
                    continue

                if pred_blk.block_type == _BLT_2WAY:
                    mods.append(
                        RedirectBranch(
                            from_serial=pred_serial,
                            old_target=serial,
                            new_target=new_target,
                        )
                    )
                else:
                    # 1-way (and any other type) -> RedirectGoto
                    mods.append(
                        RedirectGoto(
                            from_serial=pred_serial,
                            old_target=serial,
                            new_target=new_target,
                        )
                    )

        return mods


__all__ = ["GotoChainRemovalPass"]
