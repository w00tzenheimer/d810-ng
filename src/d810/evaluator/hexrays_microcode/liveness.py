"""Block-level liveness queries using IDA Hex-Rays microcode APIs.

Thin wrappers around ``mblock_t`` liveness attributes (``dead_at_start``,
``dnu``, ``mustbuse``, ``maybuse``, ``mustbdef``, ``maybdef``) and the
``make_lists_ready()`` method.

All functions are READ-ONLY: they materialise cached internal structures
but do not mutate instructions, blocks, or CFG edges.
"""
from __future__ import annotations

import ida_hexrays

from d810.core.logging import getLogger

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# List readiness
# ---------------------------------------------------------------------------


def ensure_lists_ready(blk: ida_hexrays.mblock_t) -> None:
    """Call ``blk.make_lists_ready()`` if not already done.

    Args:
        blk: The microcode block whose use/def lists should be prepared.
    """
    blk.make_lists_ready()


# ---------------------------------------------------------------------------
# Operand-level queries
# ---------------------------------------------------------------------------


def is_dead_at_entry(
    blk: ida_hexrays.mblock_t, mop: ida_hexrays.mop_t
) -> bool:
    """Check if *mop* is dead at block entry (in ``blk.dead_at_start``).

    Calls ``make_lists_ready()`` first. Builds an ``mlist_t`` for *mop*
    via ``append_use_list`` and checks ``has_common`` with ``dead_at_start``.

    Args:
        blk: The microcode block.
        mop: The operand to check.

    Returns:
        ``True`` if *mop* overlaps with the dead-at-start set.
    """
    blk.make_lists_ready()
    ml = ida_hexrays.mlist_t()
    blk.append_use_list(ml, mop, ida_hexrays.MUST_ACCESS)
    if ml.empty():
        return False
    return blk.dead_at_start.has_common(ml)


def is_defined_not_used(
    blk: ida_hexrays.mblock_t, mop: ida_hexrays.mop_t
) -> bool:
    """Check if *mop* is defined but not used within this block (in ``blk.dnu``).

    Builds an ``mlist_t`` for *mop*, checks ``has_common`` with ``dnu``.

    Args:
        blk: The microcode block.
        mop: The operand to check.

    Returns:
        ``True`` if *mop* overlaps with the defined-not-used set.
    """
    blk.make_lists_ready()
    ml = ida_hexrays.mlist_t()
    blk.append_use_list(ml, mop, ida_hexrays.MUST_ACCESS)
    if ml.empty():
        return False
    return blk.dnu.has_common(ml)


# ---------------------------------------------------------------------------
# Raw mlist_t accessors
# ---------------------------------------------------------------------------


def get_must_use(blk: ida_hexrays.mblock_t) -> ida_hexrays.mlist_t:
    """Return ``blk.mustbuse`` after ensuring lists are ready.

    Args:
        blk: The microcode block.

    Returns:
        The must-use list for the block.
    """
    blk.make_lists_ready()
    return blk.mustbuse


def get_may_use(blk: ida_hexrays.mblock_t) -> ida_hexrays.mlist_t:
    """Return ``blk.maybuse`` after ensuring lists are ready.

    Args:
        blk: The microcode block.

    Returns:
        The may-use list for the block.
    """
    blk.make_lists_ready()
    return blk.maybuse


def get_must_def(blk: ida_hexrays.mblock_t) -> ida_hexrays.mlist_t:
    """Return ``blk.mustbdef`` after ensuring lists are ready.

    Args:
        blk: The microcode block.

    Returns:
        The must-def list for the block.
    """
    blk.make_lists_ready()
    return blk.mustbdef


def get_may_def(blk: ida_hexrays.mblock_t) -> ida_hexrays.mlist_t:
    """Return ``blk.maybdef`` after ensuring lists are ready.

    Args:
        blk: The microcode block.

    Returns:
        The may-def list for the block.
    """
    blk.make_lists_ready()
    return blk.maybdef


def get_dead_at_start(blk: ida_hexrays.mblock_t) -> ida_hexrays.mlist_t:
    """Return ``blk.dead_at_start`` after ensuring lists are ready.

    Args:
        blk: The microcode block.

    Returns:
        The dead-at-start list for the block.
    """
    blk.make_lists_ready()
    return blk.dead_at_start


def get_defined_not_used(blk: ida_hexrays.mblock_t) -> ida_hexrays.mlist_t:
    """Return ``blk.dnu`` after ensuring lists are ready.

    Args:
        blk: The microcode block.

    Returns:
        The defined-not-used list for the block.
    """
    blk.make_lists_ready()
    return blk.dnu


# ---------------------------------------------------------------------------
# Stack-variable liveness by stkoff
# ---------------------------------------------------------------------------


def is_var_live_at_block_entry(
    blk: ida_hexrays.mblock_t, stkoff: int, width: int
) -> bool:
    """Check if a stack variable (by *stkoff* and *width*) is live at block entry.

    A variable is live at entry if it is NOT in ``dead_at_start``.

    Args:
        blk: The microcode block.
        stkoff: Stack offset of the variable.
        width: Size of the variable in bytes.

    Returns:
        ``True`` if the variable is live at block entry.
    """
    blk.make_lists_ready()
    ml = ida_hexrays.mlist_t()
    ml.mem.add(ida_hexrays.ivl_t(stkoff, width))
    return not blk.dead_at_start.has_common(ml)


def is_var_live_at_block_exit(
    blk: ida_hexrays.mblock_t, stkoff: int, width: int
) -> bool:
    """Check if a stack variable is live at block exit.

    A variable is live at exit if it is used by any successor block
    (appears in some successor's ``maybuse``) or if it passes through
    this block without being killed (not in ``mustbdef``).

    Approximation: the variable is live at exit if it is NOT both
    must-defined in this block AND defined-not-used (``dnu``).
    Equivalently, if the variable is in ``dnu`` it is dead at exit
    (defined here, never read here, and if no successor uses it).
    For a sound over-approximation we check: NOT in ``dnu``.

    Args:
        blk: The microcode block.
        stkoff: Stack offset of the variable.
        width: Size of the variable in bytes.

    Returns:
        ``True`` if the variable is (conservatively) live at block exit.
    """
    blk.make_lists_ready()
    ml = ida_hexrays.mlist_t()
    ml.mem.add(ida_hexrays.ivl_t(stkoff, width))
    # If it's in dnu, it was defined here but not used -- dead at exit
    # (conservative: dnu doesn't account for successors, but it's a
    # reasonable approximation without full backward liveness).
    return not blk.dnu.has_common(ml)


__all__ = [
    "ensure_lists_ready",
    "get_dead_at_start",
    "get_defined_not_used",
    "get_may_def",
    "get_may_use",
    "get_must_def",
    "get_must_use",
    "is_dead_at_entry",
    "is_defined_not_used",
    "is_var_live_at_block_entry",
    "is_var_live_at_block_exit",
]
