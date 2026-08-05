"""Post-transaction invariants for Hex-Rays block retention flags."""

from __future__ import annotations

import ida_hexrays


def synchronize_explicit_goto_flag(block: object) -> bool:
    """Clear a stale ``MBL_GOTO`` bit when the block no longer ends in goto."""
    if not int(block.flags) & int(ida_hexrays.MBL_GOTO):
        return False
    tail = block.tail
    if tail is not None and int(tail.opcode) == int(ida_hexrays.m_goto):
        return False
    block.flags &= ~int(ida_hexrays.MBL_GOTO)
    return True


def release_committed_block_retention(block: object) -> bool:
    """Release transaction-only keep state and synchronize explicit goto."""
    before = int(block.flags)
    block.flags &= ~int(ida_hexrays.MBL_KEEP)
    synchronize_explicit_goto_flag(block)
    return int(block.flags) != before
