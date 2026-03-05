"""Conditional exit block classification helpers for flattening analysis."""

from __future__ import annotations

from enum import Enum


class ExitBlockType(Enum):
    """Classification of dispatcher exit block types based on successor patterns."""

    ONE_WAY_EXIT = "one_way_exit"
    CONDITIONAL_EXIT_WITH_LOOPBACK = "conditional_exit_with_loopback"
    NORMAL_EXIT = "normal_exit"


def classify_exit_block(
    exit_blk,
    dispatcher_internal_serials: set[int],
) -> ExitBlockType:
    """Classify an exit block based on successor pattern."""
    if exit_blk.nsucc() != 2:
        return ExitBlockType.ONE_WAY_EXIT

    succ_0 = exit_blk.succ(0)
    succ_1 = exit_blk.succ(1)
    succ_0_in_dispatcher = succ_0 in dispatcher_internal_serials
    succ_1_in_dispatcher = succ_1 in dispatcher_internal_serials

    if succ_0_in_dispatcher and not succ_1_in_dispatcher:
        return ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK
    if succ_1_in_dispatcher and not succ_0_in_dispatcher:
        return ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK
    return ExitBlockType.NORMAL_EXIT


def get_loopback_successor(
    exit_blk,
    dispatcher_internal_serials: set[int],
) -> int | None:
    """Return successor serial that loops back into dispatcher."""
    if exit_blk.nsucc() != 2:
        return None

    succ_0 = exit_blk.succ(0)
    succ_1 = exit_blk.succ(1)
    if succ_0 in dispatcher_internal_serials:
        return succ_0
    if succ_1 in dispatcher_internal_serials:
        return succ_1
    return None


def get_exit_successor(
    exit_blk,
    dispatcher_internal_serials: set[int],
) -> int | None:
    """Return successor serial that exits the dispatcher."""
    if exit_blk.nsucc() != 2:
        return None

    succ_0 = exit_blk.succ(0)
    succ_1 = exit_blk.succ(1)
    if succ_0 not in dispatcher_internal_serials and succ_1 in dispatcher_internal_serials:
        return succ_0
    if succ_1 not in dispatcher_internal_serials and succ_0 in dispatcher_internal_serials:
        return succ_1
    return None

