"""Block Merge Optimization Rule.

Merges artificially split basic blocks by removing redundant goto
instructions.  When an obfuscator (e.g. Hikari, OLLVM) splits a single
basic block into many tiny blocks connected by unconditional jumps, this
rule detects the pattern and NOPs the intermediate ``m_goto`` instructions
so that IDA's built-in optimizer can recombine them.

Algorithm
---------
For every block *blk* passed to :meth:`BlockMerger.optimize`:

1. Check that *blk* ends with ``m_goto``.
2. Check that *blk* has exactly **one** successor.
3. Check that the goto destination operand (``mop_b``) matches the
   successor's serial.
4. Check that the successor has exactly **one** predecessor (i.e. *blk*
   itself).
5. If all conditions hold, NOP the ``m_goto`` instruction.  IDA will
   merge the two blocks in the next ``optimize_local`` pass.

Ported from **copycat** ``block_merge_handler_t`` (``block_merge.cpp``).
"""
from __future__ import annotations

import ida_hexrays

from d810.core import getLogger
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger("D810.optimizer")


class BlockMerger(FlowOptimizationRule):
    """Merge artificially split basic blocks.

    This rule operates per-block.  When a block satisfies all mergeability
    criteria with its sole successor, the trailing ``m_goto`` is NOPed so
    that IDA's ``optimize_local`` pass combines the two blocks.

    CFG Safety
    ----------
    The rule only *removes* an instruction (NOP) and never adds edges or
    blocks.  Combined with ``USES_DEFERRED_CFG = False`` and a
    conservative ``SAFE_MATURITIES`` declaration, this is safe at the
    listed maturities.
    """

    DESCRIPTION = (
        "Merges artificially split basic blocks by removing "
        "redundant goto instructions"
    )

    # We directly NOP the goto -- no deferred CFG modification needed.
    # The actual block merging is done by IDA's optimize_local.
    USES_DEFERRED_CFG = False
    SAFE_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Check whether *blk* can be merged with its successor.

        A block is mergeable when:

        1. It ends in ``m_goto``.
        2. It has exactly one successor.
        3. The successor has exactly one predecessor (this block).
        4. The goto destination (``mop_b``) equals the successor's serial.

        When all conditions are met the ``m_goto`` is NOPed and ``1`` is
        returned.  Otherwise ``0`` is returned.
        """
        if not self._can_merge(blk):
            return 0

        # NOP the goto -- IDA will merge the blocks in optimize_local.
        logger.info(
            "BlockMerger: NOPing goto in block %d -> %d",
            blk.serial,
            blk.tail.d.b,
        )
        blk.make_nop(blk.tail)
        return 1

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _can_merge(blk: ida_hexrays.mblock_t) -> bool:
        """Return ``True`` if *blk* can be merged with its successor.

        Criteria (mirroring copycat ``can_merge`` + ``has_single_goto_succ``):

        * *blk* has a tail instruction whose opcode is ``m_goto``.
        * *blk* has exactly one successor.
        * The goto destination operand type is ``mop_b`` and its value
          equals the successor's serial.
        * The successor has exactly one predecessor.
        """
        # --- tail must be m_goto ---
        if blk.tail is None:
            return False
        if blk.tail.opcode != ida_hexrays.m_goto:
            return False

        # --- single successor ---
        if blk.nsucc() != 1:
            return False

        succ_serial: int = blk.succ(0)

        # --- reject self-referencing goto (infinite loop guard) ---
        if succ_serial == blk.serial:
            return False

        # --- goto destination must reference the successor block ---
        if blk.tail.d.t != ida_hexrays.mop_b:
            return False
        if blk.tail.d.b != succ_serial:
            return False

        # --- successor must have exactly one predecessor ---
        mba = blk.mba
        succ_blk = mba.get_mblock(succ_serial)
        if succ_blk is None:
            return False
        if succ_blk.npred() != 1:
            return False

        return True
