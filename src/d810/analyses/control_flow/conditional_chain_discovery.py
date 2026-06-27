"""Conditional-chain discovery helpers for dormant fallback fork recovery."""

from __future__ import annotations

from collections.abc import Callable

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.varnode import Space, varnode_from_mop_snapshot

# Callable port signatures (injected by the Hex-Rays backend).
#   normalize_reversed_jump_opcode(opcode) -> normalized opcode
#   is_jump_taken_for_state(opcode, state_value, check_const, check_size) -> taken?
NormalizeReversedJumpOpcode = Callable[[int | None], int | None]
IsJumpTakenForState = Callable[[int, int, int, int], bool | None]


def _operand(insn: InsnSnapshot, slot: str) -> MopSnapshot | None:
    """Read a typed operand slot from an instruction snapshot.

    Mirrors the canonical reader used by the other migrated control-flow
    analyses: it consults ``operand_slots`` provenance when present and otherwise
    falls back to the typed slot field by name.  Reading the slot through a
    variable name (not a literal ``.l`` / ``.r`` / ``.d``) keeps this module free
    of backend-shaped raw-slot reads.
    """
    for slot_name, operand in getattr(insn, "operand_slots", ()) or ():
        if slot_name == slot:
            return operand if isinstance(operand, MopSnapshot) else None
    return getattr(insn, slot, None)


def _const_value_and_size(mop: MopSnapshot | None) -> tuple[int, int] | None:
    """Return ``(value, size)`` when ``mop`` is a numeric constant, else ``None``."""
    varnode = varnode_from_mop_snapshot(mop)
    if varnode is None or varnode.space is not Space.CONST:
        return None
    return int(varnode.offset), int(varnode.size)


def _block_ref(mop: MopSnapshot | None) -> int | None:
    """Return the referenced block serial for a BLOCK operand, else ``None``."""
    if mop is None or mop.kind is not OperandKind.BLOCK:
        return None
    block_ref = mop.block_ref
    return int(block_ref) if block_ref is not None else None


def find_conditional_predecessor(
    start_block: int,
    flow_graph: FlowGraph,
    *,
    conditional_opcodes: tuple[int, ...] | list[int],
) -> int | None:
    """Walk backward along a single-predecessor chain to the first 2-way check."""
    current = int(start_block)
    visited: set[int] = {current}
    max_depth = flow_graph.block_count

    for _ in range(max_depth):
        blk_snap = flow_graph.get_block(current)
        if blk_snap is None or blk_snap.npred != 1:
            return None

        pred_serial = int(blk_snap.preds[0])
        if pred_serial in visited:
            return None

        pred_snap = flow_graph.get_block(pred_serial)
        if pred_snap is None:
            return None
        if (
            pred_snap.nsucc == 2
            and pred_snap.tail_opcode is not None
            and pred_snap.tail_opcode in conditional_opcodes
        ):
            return pred_serial

        visited.add(pred_serial)
        current = pred_serial

    return None


def extract_check_constant_from_snapshot(
    insn_snap: InsnSnapshot,
    *,
    normalize_reversed_jump_opcode: NormalizeReversedJumpOpcode,
) -> tuple[int, int, int] | None:
    """Read the numeric comparison operand from an InsnSnapshot."""
    l_mop = _operand(insn_snap, "l")
    r_mop = _operand(insn_snap, "r")
    opcode = insn_snap.opcode

    l_const = _const_value_and_size(l_mop)
    r_const = _const_value_and_size(r_mop)

    if l_const is not None:
        num_val, num_size = l_const
        normalized = normalize_reversed_jump_opcode(opcode)
    elif r_const is not None:
        num_val, num_size = r_const
        normalized = opcode
    else:
        return None

    if normalized is None:
        return None
    return (int(normalized), int(num_val), int(num_size))


def get_jump_and_fallthrough_from_snapshot(
    blk_snap: BlockSnapshot,
) -> tuple[int | None, int | None]:
    """Resolve jump target and fallthrough successor from a 2-way snapshot block."""
    tail = blk_snap.tail
    if tail is None:
        return None, None

    jump_target = _block_ref(_operand(tail, "d"))
    if jump_target is None:
        return None, None

    fallthrough = None
    for succ in tuple(blk_snap.succs):
        if int(succ) != int(jump_target):
            fallthrough = int(succ)
            break

    return int(jump_target), fallthrough


def resolve_conditional_chain_target(
    start_block: int,
    state_value: int,
    flow_graph: FlowGraph,
    *,
    conditional_opcodes: tuple[int, ...] | list[int],
    normalize_reversed_jump_opcode: NormalizeReversedJumpOpcode,
    is_jump_taken_for_state: IsJumpTakenForState,
) -> int | None:
    """Follow a conditional dispatcher chain for one concrete state."""
    visited: set[int] = set()
    current = int(start_block)
    max_depth = flow_graph.block_count

    for _ in range(max_depth):
        if current in visited:
            return None
        visited.add(current)

        blk_snap = flow_graph.get_block(current)
        if blk_snap is None:
            return None
        if (
            blk_snap.tail_opcode is None
            or blk_snap.tail_opcode not in conditional_opcodes
        ):
            return current

        tail_insn = blk_snap.tail
        if tail_insn is None:
            return current
        check_info = extract_check_constant_from_snapshot(
            tail_insn,
            normalize_reversed_jump_opcode=normalize_reversed_jump_opcode,
        )
        if check_info is None:
            return current
        check_opcode, check_const, check_size = check_info

        jump_target, fallthrough = get_jump_and_fallthrough_from_snapshot(blk_snap)
        if jump_target is None or fallthrough is None:
            return None

        jump_taken = is_jump_taken_for_state(
            check_opcode,
            int(state_value),
            check_const,
            check_size,
        )
        if jump_taken is None:
            return None

        current = int(jump_target if jump_taken else fallthrough)

    return None


def get_successor_into_dispatcher(
    dispatcher_set: set[int],
    flow_graph: FlowGraph,
    from_block_serial: int,
) -> int | None:
    """Return the successor that enters or stays in the dispatcher set."""
    from_snap = flow_graph.get_block(int(from_block_serial))
    if from_snap is None:
        return None
    succs = [int(succ) for succ in tuple(from_snap.succs)]
    if not succs:
        return None
    if from_snap.nsucc == 1:
        return succs[0]
    if from_snap.nsucc == 2:
        in_disp = [succ for succ in succs if succ in dispatcher_set]
        if in_disp:
            return in_disp[0]
        for succ in succs:
            succ_snap = flow_graph.get_block(succ)
            if succ_snap is None:
                continue
            for succ2 in tuple(succ_snap.succs):
                if int(succ2) in dispatcher_set:
                    return succ
        return None
    return succs[0]


__all__ = [
    "extract_check_constant_from_snapshot",
    "find_conditional_predecessor",
    "get_jump_and_fallthrough_from_snapshot",
    "get_successor_into_dispatcher",
    "resolve_conditional_chain_target",
]
