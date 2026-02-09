"""
Conditional Exit Block Detection for Control Flow Unflattening.

This module provides utilities to classify dispatcher exit blocks based on their
successor patterns, distinguishing between:
- One-way exits (single successor, direct function exit)
- Conditional exits with loopback (two successors: one to dispatcher, one to exit)
- Normal exits (neither of the above)

This classification is critical for proper control flow reconstruction when
resolving dispatcher fathers.
"""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.generic import GenericDispatcherInfo


class ExitBlockType(Enum):
    """Classification of dispatcher exit block types based on successor patterns."""

    ONE_WAY_EXIT = "one_way_exit"
    """Block has a single successor (unconditional exit from dispatcher)."""

    CONDITIONAL_EXIT_WITH_LOOPBACK = "conditional_exit_with_loopback"
    """Block has two successors: one loops back to dispatcher, one exits."""

    NORMAL_EXIT = "normal_exit"
    """Block does not match exit patterns (e.g., both successors outside dispatcher)."""


def classify_exit_block(
    exit_blk,
    dispatcher_internal_serials: set[int]
) -> ExitBlockType:
    """Classify an exit block based on its successor pattern.

    Args:
        exit_blk: The block to classify (mblock_t or mock with nsucc() method)
        dispatcher_internal_serials: Set of block serials that are inside the
            dispatcher loop structure

    Returns:
        ExitBlockType classification:
        - ONE_WAY_EXIT: Block has single successor
        - CONDITIONAL_EXIT_WITH_LOOPBACK: Block has 2 successors, exactly one
          is in dispatcher_internal_serials
        - NORMAL_EXIT: Any other pattern

    Examples:
        >>> # One-way exit (unconditional goto)
        >>> classify_exit_block(blk_with_1_succ, {1, 2, 3})
        ExitBlockType.ONE_WAY_EXIT

        >>> # Conditional exit: one successor to dispatcher (2), one to exit (10)
        >>> classify_exit_block(blk_with_2_succs_2_and_10, {1, 2, 3})
        ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK

        >>> # Normal exit: both successors outside dispatcher
        >>> classify_exit_block(blk_with_2_succs_10_and_11, {1, 2, 3})
        ExitBlockType.NORMAL_EXIT
    """
    # Check if block is a 2-way block
    nsucc = exit_blk.nsucc()

    if nsucc != 2:
        # Not a 2-way block, so it's a simple one-way exit
        return ExitBlockType.ONE_WAY_EXIT

    # For 2-way blocks, check successor patterns
    # Get both successors
    succ_0 = exit_blk.succ(0)
    succ_1 = exit_blk.succ(1)

    # Check if exactly one successor is in the dispatcher
    succ_0_in_dispatcher = succ_0 in dispatcher_internal_serials
    succ_1_in_dispatcher = succ_1 in dispatcher_internal_serials

    if succ_0_in_dispatcher and not succ_1_in_dispatcher:
        # One successor loops back, one exits
        return ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK
    elif succ_1_in_dispatcher and not succ_0_in_dispatcher:
        # One successor loops back, one exits (reversed order)
        return ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK
    else:
        # Either both in dispatcher, or both outside dispatcher
        # Neither pattern represents a conditional exit with loopback
        return ExitBlockType.NORMAL_EXIT


def get_loopback_successor(
    exit_blk,
    dispatcher_internal_serials: set[int]
) -> int | None:
    """Get the successor serial that leads back into the dispatcher.

    Args:
        exit_blk: The exit block to analyze
        dispatcher_internal_serials: Set of block serials inside the dispatcher

    Returns:
        Serial number of the successor that loops back to dispatcher, or None
        if no such successor exists (e.g., for one-way blocks or when no
        successor is in the dispatcher)

    Examples:
        >>> # Block with successors 2 (in dispatcher) and 10 (exit)
        >>> get_loopback_successor(blk, {1, 2, 3})
        2

        >>> # One-way block
        >>> get_loopback_successor(one_way_blk, {1, 2, 3})
        None
    """
    # Only 2-way blocks can have loopback successors
    if exit_blk.nsucc() != 2:
        return None

    succ_0 = exit_blk.succ(0)
    succ_1 = exit_blk.succ(1)

    # Return the successor that's in the dispatcher
    if succ_0 in dispatcher_internal_serials:
        return succ_0
    elif succ_1 in dispatcher_internal_serials:
        return succ_1
    else:
        return None


def get_exit_successor(
    exit_blk,
    dispatcher_internal_serials: set[int]
) -> int | None:
    """Get the successor serial that leads out of the dispatcher.

    Args:
        exit_blk: The exit block to analyze
        dispatcher_internal_serials: Set of block serials inside the dispatcher

    Returns:
        Serial number of the successor that exits the dispatcher, or None
        if no such successor exists (e.g., when both successors are in the
        dispatcher, or for non-2-way blocks)

    Examples:
        >>> # Block with successors 2 (in dispatcher) and 10 (exit)
        >>> get_exit_successor(blk, {1, 2, 3})
        10

        >>> # Both successors in dispatcher
        >>> get_exit_successor(blk_both_inside, {1, 2, 3})
        None
    """
    # Only 2-way blocks can have distinct exit successors
    if exit_blk.nsucc() != 2:
        return None

    succ_0 = exit_blk.succ(0)
    succ_1 = exit_blk.succ(1)

    # Return the successor that's NOT in the dispatcher
    if succ_0 not in dispatcher_internal_serials and succ_1 in dispatcher_internal_serials:
        return succ_0
    elif succ_1 not in dispatcher_internal_serials and succ_0 in dispatcher_internal_serials:
        return succ_1
    else:
        # Either both inside or both outside - no clear exit successor
        return None


def find_state_assignment_in_block(blk, state_mop) -> int | None:
    """Find a constant state variable assignment in a block.

    Scans instructions in the block backward looking for a mov instruction that
    writes a constant value to the state variable.

    Args:
        blk: The block to scan (mblock_t or mock with head/tail attributes)
        state_mop: The state variable mop to search for (mop_t)

    Returns:
        The constant value assigned to the state variable, or None if:
        - No assignment found
        - Assignment is not a constant (computed value)
        - state_mop is None

    Examples:
        >>> # Block with: mov state, 0xABCD1234
        >>> find_state_assignment_in_block(blk, state_mop)
        2882404660  # 0xABCD1234

        >>> # Block with no state assignment
        >>> find_state_assignment_in_block(blk_no_assign, state_mop)
        None

        >>> # Block with computed assignment: mov state, rax
        >>> find_state_assignment_in_block(blk_computed, state_mop)
        None
    """
    if not IDA_AVAILABLE or state_mop is None:
        return None

    # Import here to avoid circular dependency
    from d810.hexrays.hexrays_helpers import equal_mops_ignore_size

    # Scan instructions backward from tail
    ins = blk.tail
    while ins:
        # Check if this is a mov instruction
        if ins.opcode == ida_hexrays.m_mov:
            # Check if destination matches state_mop
            if equal_mops_ignore_size(ins.d, state_mop):
                # Check if source is a constant
                if ins.l.t == ida_hexrays.mop_n:
                    # Return the constant value
                    return ins.l.nnn.value
                else:
                    # Assignment found but not constant (computed value)
                    return None

        # Move to previous instruction
        ins = ins.prev

    # No assignment found
    return None


def resolve_loopback_target(
    exit_blk,
    loopback_successor_serial: int,
    dispatcher_info: "GenericDispatcherInfo",
    state_mop
) -> tuple[int, int] | None:
    """Resolve where a loopback path leads by re-emulating through dispatcher.

    When a conditional exit block has one path that loops back into the dispatcher
    (setting state = SOME_CONSTANT), this function determines where that loopback
    actually leads by looking up the state value in the dispatcher's mapping.

    Args:
        exit_blk: The conditional exit block
        loopback_successor_serial: Serial of the block that loops back to dispatcher
        dispatcher_info: Dispatcher information with state-to-block mapping
        state_mop: The state variable being tracked

    Returns:
        Tuple of (target_block_serial, state_value) if resolvable, or None if:
        - No constant state assignment found in loopback path
        - State value not in dispatcher's known mappings
        - loopback_successor_serial doesn't lead to dispatcher entry

    Examples:
        >>> # Loopback sets state=0xABCD1234, dispatcher maps it to block 5
        >>> resolve_loopback_target(exit_blk, 2, dispatcher_info, state_mop)
        (5, 2882404660)  # Block 5, state=0xABCD1234

        >>> # Loopback uses computed state value
        >>> resolve_loopback_target(exit_blk_computed, 2, dispatcher_info, state_mop)
        None

        >>> # State value not in dispatcher mapping
        >>> resolve_loopback_target(exit_blk, 2, dispatcher_info, state_mop)
        None
    """
    if not IDA_AVAILABLE:
        return None

    # Get the loopback block
    loopback_blk = exit_blk.mba.get_mblock(loopback_successor_serial)
    if loopback_blk is None:
        return None

    # Find the state assignment in the loopback block
    state_value = find_state_assignment_in_block(loopback_blk, state_mop)
    if state_value is None:
        # No constant assignment found
        return None

    # Look up this state value in the dispatcher's exit block mapping
    # Each exit block in dispatcher_exit_blocks has a comparison_value field
    for exit_block_info in dispatcher_info.dispatcher_exit_blocks:
        if exit_block_info.comparison_value == state_value:
            # Found the target block for this state value
            return (exit_block_info.serial, state_value)

    # State value not found in dispatcher mapping
    return None
