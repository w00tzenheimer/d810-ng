"""IDA-specific helpers for resolving conditional dispatcher exits."""

from __future__ import annotations

try:
    import ida_hexrays

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


def find_state_assignment_in_block(blk, state_mop) -> int | None:
    """Find a constant assignment to state variable in the given block."""
    if not IDA_AVAILABLE or state_mop is None:
        return None

    from d810.hexrays.utils.hexrays_helpers import equal_mops_ignore_size

    ins = blk.tail
    while ins:
        if ins.opcode == ida_hexrays.m_mov and equal_mops_ignore_size(ins.d, state_mop):
            if ins.l.t == ida_hexrays.mop_n:
                return ins.l.nnn.value
            return None
        ins = ins.prev
    return None


def resolve_loopback_target(
    exit_blk,
    loopback_successor_serial: int,
    dispatcher_info,
    state_mop,
) -> tuple[int, int] | None:
    """Resolve target block reached through loopback path."""
    if not IDA_AVAILABLE:
        return None

    loopback_blk = exit_blk.mba.get_mblock(loopback_successor_serial)
    if loopback_blk is None:
        return None

    state_value = find_state_assignment_in_block(loopback_blk, state_mop)
    if state_value is None:
        return None

    for exit_block_info in dispatcher_info.dispatcher_exit_blocks:
        if exit_block_info.comparison_value == state_value:
            return (exit_block_info.serial, state_value)
    return None

