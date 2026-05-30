"""Conditional-chain discovery helpers for dormant fallback fork recovery."""

from __future__ import annotations

from d810.ir.flowgraph import OperandKind


def find_conditional_predecessor(
    start_block: int,
    flow_graph: object,
    *,
    conditional_opcodes: tuple[int, ...] | list[int],
) -> int | None:
    """Walk backward along a single-predecessor chain to the first 2-way check."""
    current = int(start_block)
    visited: set[int] = {current}
    max_depth = getattr(flow_graph, "block_count", 0) or 0

    for _ in range(max_depth):
        blk_snap = flow_graph.get_block(current)
        if blk_snap is None or getattr(blk_snap, "npred", 0) != 1:
            return None

        pred_serial = int(blk_snap.preds[0])
        if pred_serial in visited:
            return None

        pred_snap = flow_graph.get_block(pred_serial)
        if pred_snap is None:
            return None
        if (
            getattr(pred_snap, "nsucc", 0) == 2
            and getattr(pred_snap, "tail_opcode", None) is not None
            and pred_snap.tail_opcode in conditional_opcodes
        ):
            return pred_serial

        visited.add(pred_serial)
        current = pred_serial

    return None


def extract_check_constant_from_snapshot(
    insn_snap: object,
    *,
    normalize_reversed_jump_opcode: object,
) -> tuple[int, int, int] | None:
    """Read the numeric comparison operand from an InsnSnapshot."""
    l_mop = getattr(insn_snap, "l", None)
    r_mop = getattr(insn_snap, "r", None)
    opcode = getattr(insn_snap, "opcode", None)

    if l_mop is not None and getattr(l_mop, "kind", None) == OperandKind.NUMBER:
        num_val = getattr(l_mop, "value", None)
        num_size = getattr(l_mop, "size", None)
        if not callable(normalize_reversed_jump_opcode):
            return None
        normalized = normalize_reversed_jump_opcode(opcode)
    elif r_mop is not None and getattr(r_mop, "kind", None) == OperandKind.NUMBER:
        num_val = getattr(r_mop, "value", None)
        num_size = getattr(r_mop, "size", None)
        normalized = opcode
    else:
        return None

    if num_val is None or num_size is None or normalized is None:
        return None
    return (int(normalized), int(num_val), int(num_size))


def get_jump_and_fallthrough_from_snapshot(
    blk_snap: object,
) -> tuple[int | None, int | None]:
    """Resolve jump target and fallthrough successor from a 2-way snapshot block."""
    tail = getattr(blk_snap, "tail", None)
    if tail is None:
        return None, None
    d_mop = getattr(tail, "d", None)
    if d_mop is None or getattr(d_mop, "kind", None) != OperandKind.BLOCK:
        return None, None

    jump_target = getattr(d_mop, "block_ref", None)
    if jump_target is None:
        return None, None

    fallthrough = None
    for succ in tuple(getattr(blk_snap, "succs", ())):
        if int(succ) != int(jump_target):
            fallthrough = int(succ)
            break

    return int(jump_target), fallthrough


def resolve_conditional_chain_target(
    start_block: int,
    state_value: int,
    flow_graph: object,
    *,
    conditional_opcodes: tuple[int, ...] | list[int],
    normalize_reversed_jump_opcode: object,
    is_jump_taken_for_state: object,
) -> int | None:
    """Follow a conditional dispatcher chain for one concrete state."""
    if not callable(is_jump_taken_for_state):
        return None

    visited: set[int] = set()
    current = int(start_block)
    max_depth = getattr(flow_graph, "block_count", 0) or 0

    for _ in range(max_depth):
        if current in visited:
            return None
        visited.add(current)

        blk_snap = flow_graph.get_block(current)
        if blk_snap is None:
            return None
        if (
            getattr(blk_snap, "tail_opcode", None) is None
            or blk_snap.tail_opcode not in conditional_opcodes
        ):
            return current

        tail_insn = getattr(blk_snap, "tail", None)
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
    flow_graph: object,
    from_block_serial: int,
) -> int | None:
    """Return the successor that enters or stays in the dispatcher set."""
    from_snap = flow_graph.get_block(int(from_block_serial))
    if from_snap is None:
        return None
    succs = [int(succ) for succ in tuple(getattr(from_snap, "succs", ()))]
    if not succs:
        return None
    if getattr(from_snap, "nsucc", 0) == 1:
        return succs[0]
    if getattr(from_snap, "nsucc", 0) == 2:
        in_disp = [succ for succ in succs if succ in dispatcher_set]
        if in_disp:
            return in_disp[0]
        for succ in succs:
            succ_snap = flow_graph.get_block(succ)
            if succ_snap is None:
                continue
            for succ2 in tuple(getattr(succ_snap, "succs", ())):
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
