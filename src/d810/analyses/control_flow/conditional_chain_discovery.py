"""Conditional-chain discovery helpers for dormant fallback fork recovery.

d81-qlal -- canonical Instruction port.  The operand reads no longer touch
backend-shaped ``InsnSnapshot`` operand slots (``.l`` / ``.r`` / ``.d`` or their
``operand_slots`` provenance).  Each :class:`~d810.ir.flowgraph.InsnSnapshot` is
projected through :func:`~d810.ir.insn_projection.project_instruction` to the
canonical :class:`~d810.ir.instructions.Instruction`, and:

* the compare-operand numeric constants (was ``insn.l`` / ``insn.r`` ->
  const value/size) are read off the canonical ``Instruction.inputs`` via
  ``_const_value_from_varnode`` / ``_size_from_varnode`` (a ``NUMBER`` operand
  projects to a ``Varnode(Space.CONST, value, size)``);
* the conditional jump target (was ``tail.d.block_ref``) is read off
  ``Instruction.control.target`` (populated from ``insn.d.block_ref`` by the
  projection's ``_block_target_from``).  The fallthrough is derived from the
  block snapshot's successors as before.

STRUCTURAL block topology stays direct -- ``flow_graph.block_count`` /
``flow_graph.get_block`` and ``BlockSnapshot.succs`` / ``.preds`` / ``.nsucc`` /
``.npred`` / ``.tail`` / ``.tail_opcode`` are portable model surfaces, not
operand slots.  The raw branch opcode passed to the injected backend ports
(``normalize_reversed_jump_opcode`` / ``is_jump_taken_for_state``) is read off
``InsnSnapshot.opcode`` (an opcode field, not an operand slot).
"""

from __future__ import annotations

from collections.abc import Callable

from d810.analyses.value_flow.induction_carrier import (
    _const_value_from_varnode,
    _size_from_varnode,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.insn_projection import operand_storages, project_instruction
from d810.ir.varnode import Varnode

# Callable port signatures (injected by the Hex-Rays backend).
#   normalize_reversed_jump_opcode(opcode) -> normalized opcode
#   is_jump_taken_for_state(opcode, state_value, check_const, check_size) -> taken?
NormalizeReversedJumpOpcode = Callable[[int | None], int | None]
IsJumpTakenForState = Callable[[int, int, int, int], bool | None]


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
    """Read the numeric comparison operand from an InsnSnapshot.

    The compared operands are read from the canonical projection's
    slot-aligned storage views (``operand_storages`` -> ``l`` / ``r`` / ``d``):
    a ``NUMBER`` operand projects to a ``Varnode(Space.CONST, value, size)``,
    an absent operand to ``None`` -- never from the raw ``insn.l`` / ``insn.r``
    slots, and never positionally collapsed.  The numeric value on the LEFT
    means the compare is reversed (the const is the left-hand side), so the
    opcode is normalized; a value on the RIGHT keeps the opcode as-is.
    """
    left, right, _ = operand_storages(insn_snap)
    left = left if isinstance(left, Varnode) else None
    right = right if isinstance(right, Varnode) else None

    l_value = _const_value_from_varnode(left)
    r_value = _const_value_from_varnode(right)
    opcode = insn_snap.opcode

    if l_value is not None:
        num_val = l_value
        num_size = _size_from_varnode(left)
        normalized = normalize_reversed_jump_opcode(opcode)
    elif r_value is not None:
        num_val = r_value
        num_size = _size_from_varnode(right)
        normalized = opcode
    else:
        return None

    if normalized is None or num_size is None:
        return None
    return (int(normalized), int(num_val), int(num_size))


def get_jump_and_fallthrough_from_snapshot(
    blk_snap: BlockSnapshot,
) -> tuple[int | None, int | None]:
    """Resolve jump target and fallthrough successor from a 2-way snapshot block."""
    tail = blk_snap.tail
    if tail is None:
        return None, None

    jump_target = _jump_target_from_snapshot(tail)
    if jump_target is None:
        return None, None

    fallthrough = None
    for succ in tuple(blk_snap.succs):
        if int(succ) != int(jump_target):
            fallthrough = int(succ)
            break

    return int(jump_target), fallthrough


def _jump_target_from_snapshot(insn_snap: InsnSnapshot) -> int | None:
    """Return the conditional jump target block serial, else ``None``.

    Read off the canonical ``Instruction.control.target`` (the projection
    populates it from ``insn.d.block_ref`` for a CONDITIONAL_BRANCH), never from
    the raw ``insn.d`` operand slot.
    """
    instruction = project_instruction(insn_snap)
    control = instruction.control
    if control is None or control.target is None:
        return None
    return int(control.target)


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
