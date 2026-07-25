"""Recognize complete local two-arm residual indirect-transfer snippets."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays
import ida_ida

from d810.analyses.control_flow.residual_indirect_transfer import (
    ResidualIndirectTransferProof,
    ResidualTransferCandidate,
    validate_residual_transfer,
)
from d810.core.typing import Mapping, Sequence
from d810.hexrays.utils.table_utils import read_global_value


@dataclass(frozen=True, slots=True)
class ResidualIndirectTransferEvidence:
    """Pure proof paired with the live microcode locations needed for delivery."""

    candidate: ResidualTransferCandidate
    proof: ResidualIndirectTransferProof
    conditional_branch_ea: int
    selector_state_constant: int | None
    terminal_indirect_transfer_ea: int
    terminal_indirect_transfer_end_ea: int


def _opcode(name: str) -> int | None:
    value = getattr(ida_hexrays, name, None)
    return int(value) if value is not None else None


def _conditional_codes() -> dict[int, int]:
    result: dict[int, int] = {}
    for name, code in (
        ("m_jc", 2),
        ("m_jb", 2),
        ("m_jnc", 3),
        ("m_jae", 3),
        ("m_jz", 4),
        ("m_jnz", 5),
        ("m_jbe", 6),
        ("m_ja", 7),
        ("m_jl", 12),
        ("m_jge", 13),
        ("m_jle", 14),
        ("m_jg", 15),
    ):
        opcode = _opcode(name)
        if opcode is not None:
            result[opcode] = code
    return result


def _instructions(block: object) -> tuple[object, ...]:
    current = getattr(block, "head", None)
    tail = getattr(block, "tail", None)
    result: list[object] = []
    while current is not None:
        result.append(current)
        # SWIG may hand out distinct Python wrappers for ``head`` and ``tail``
        # even when both proxy the same native minsn_t.  The terminal ``next``
        # link is therefore the authoritative fallback.
        if current is tail or current == tail:
            return tuple(result)
        following = getattr(current, "next", None)
        if following is None:
            return tuple(result)
        current = following
    return tuple(result)


def _successors(block: object) -> tuple[int, ...]:
    try:
        return tuple(int(block.succ(index)) for index in range(int(block.nsucc())))
    except Exception:
        return ()


def _register(mop: object) -> int | None:
    if getattr(mop, "t", None) != _opcode("mop_r"):
        return None
    value = getattr(mop, "r", None)
    return int(value) if value is not None else None


def _stack_offset(mop: object) -> int | None:
    if getattr(mop, "t", None) != _opcode("mop_S"):
        return None
    value = getattr(getattr(mop, "s", None), "off", None)
    return int(value) if value is not None else None


def _immediate(mop: object) -> int | None:
    if getattr(mop, "t", None) != _opcode("mop_n"):
        return None
    value = getattr(getattr(mop, "nnn", None), "value", None)
    return int(value) if value is not None else None


def _global_ea(mop: object) -> int | None:
    if getattr(mop, "t", None) == _opcode("mop_v"):
        value = getattr(mop, "g", None)
        return int(value) if value is not None else None
    # ``lea reg, global`` lifts as address-of a global value operand.
    if getattr(mop, "t", None) == _opcode("mop_a"):
        return _global_ea(getattr(mop, "a", None))
    return None


def _global_move(insn: object, register: int) -> int | None:
    if int(getattr(insn, "opcode", -1)) != _opcode("m_mov"):
        return None
    if _register(getattr(insn, "d", None)) != int(register):
        return None
    return _global_ea(getattr(insn, "l", None))


def _last_global_move_before_branch(block: object) -> tuple[int, int] | None:
    """Return the final ``global -> register`` definition before a branch.

    Hex-Rays expands a native ``cmp`` into several flag-setting microinstructions
    before the terminal ``m_j*``.  The pointer setup therefore need not be the
    instruction immediately preceding the branch.
    """
    instructions = _instructions(block)
    for insn in reversed(instructions[:-1]):
        register = _register(getattr(insn, "d", None))
        if register is None:
            continue
        value = _global_move(insn, register)
        if value is not None:
            return register, value
    return None


def _one_way_merge(mba: object, serial: int) -> int | None:
    try:
        block = mba.get_mblock(int(serial))
    except Exception:
        return None
    successors = _successors(block)
    return successors[0] if len(successors) == 1 else None


def _context_values(
    values: Mapping[int, int] | Sequence[tuple[int, int]],
) -> dict[int, int] | None:
    try:
        items = values.items() if isinstance(values, Mapping) else values
        result = {int(register): int(value) for register, value in items}
    except (AttributeError, TypeError, ValueError):
        return None
    return result or None


def _read_pointer_cell(ea: int) -> int | None:
    """Read the concrete value selected by a microcode-proven global address."""
    width = 8 if ida_ida.inf_is_64bit() else 4
    value = read_global_value(int(ea), width)
    return int(value) if value is not None else None


def _terminal_shape(
    block: object,
    pointer_register: int,
    context: Mapping[int, int],
) -> tuple[int, int, int] | None:
    instructions = _instructions(block)
    if len(instructions) < 3:
        return None
    terminal = instructions[-1]
    if int(getattr(terminal, "opcode", -1)) not in {
        value for value in (_opcode("m_ijmp"), _opcode("m_icall")) if value is not None
    }:
        return None
    ldx = next(
        (
            insn
            for insn in instructions[:-1]
            if int(getattr(insn, "opcode", -1)) == _opcode("m_ldx")
        ),
        None,
    )
    if ldx is None:
        return None
    if pointer_register not in {
        _register(getattr(ldx, "l", None)),
        _register(getattr(ldx, "r", None)),
    }:
        return None
    loaded_register = _register(getattr(ldx, "d", None))
    if loaded_register is None:
        return None
    ldx_index = instructions.index(ldx)
    add = next(
        (
            insn
            for insn in instructions[ldx_index + 1 : -1]
            if int(getattr(insn, "opcode", -1)) == _opcode("m_add")
        ),
        None,
    )
    if add is None:
        return None
    operands = (_register(getattr(add, "l", None)), _register(getattr(add, "r", None)))
    base_registers = {register for register in operands if register in context}
    if operands.count(loaded_register) != 1 or len(base_registers) != 1:
        return None
    if _register(getattr(add, "d", None)) != loaded_register:
        return None
    if loaded_register not in {
        _register(getattr(terminal, "l", None)),
        _register(getattr(terminal, "r", None)),
    }:
        return None
    base_register = next(iter(base_registers))
    terminal_ea = getattr(terminal, "ea", None)
    end_ea = getattr(block, "end", None)
    if terminal_ea is None or end_ea is None or int(end_ea) <= int(terminal_ea):
        return None
    return int(context[base_register]), int(terminal_ea), int(end_ea)


def recognize_residual_indirect_transfer(
    mba: object,
    function_context_register_values: Mapping[int, int] | Sequence[tuple[int, int]],
    envelope_start_ea: int,
    envelope_end_ea: int,
) -> ResidualIndirectTransferEvidence | None:
    """Return a proof only for one fully-local conditional indirect transfer.

    The adapter inspects only microcode operands and CFG edges.  It deliberately
    does not read native bytes or infer an unproven register value.
    """
    context = _context_values(function_context_register_values)
    if context is None:
        return None
    try:
        blocks = tuple(mba.get_mblock(index) for index in range(int(mba.qty)))
    except Exception:
        return None
    for branch_block in blocks:
        if branch_block is None:
            continue
        branch = getattr(branch_block, "tail", None)
        condition_code = _conditional_codes().get(int(getattr(branch, "opcode", -1)))
        successors = _successors(branch_block)
        taken = getattr(getattr(branch, "d", None), "b", None)
        branch_ea = getattr(branch, "ea", None)
        if (
            condition_code is None
            or branch_ea is None
            or len(successors) != 2
            or taken is None
        ):
            continue
        taken = int(taken)
        if taken not in successors:
            continue
        fallthrough = next((item for item in successors if item != taken), None)
        selector_stack = _stack_offset(getattr(branch, "l", None))
        if selector_stack is None:
            selector_stack = _stack_offset(getattr(branch, "r", None))
        selector_register = None
        if selector_stack is None:
            selector_register = _register(getattr(branch, "l", None))
            if selector_register is None:
                selector_register = _register(getattr(branch, "r", None))
        if (
            selector_stack is None and selector_register is None
        ) or fallthrough is None:
            continue
        selector_constant = _immediate(getattr(branch, "r", None))
        if selector_constant is None:
            selector_constant = _immediate(getattr(branch, "l", None))
        prebranch_pointer = _last_global_move_before_branch(branch_block)
        if prebranch_pointer is None:
            continue
        pointer_register, true_pointer_cell = prebranch_pointer
        try:
            fallthrough_block = mba.get_mblock(int(fallthrough))
        except Exception:
            continue
        fallthrough_instructions = _instructions(fallthrough_block)
        if len(fallthrough_instructions) != 1:
            continue
        false_pointer_cell = _global_move(fallthrough_instructions[0], pointer_register)
        fallthrough_merge = _one_way_merge(mba, fallthrough)
        if fallthrough_merge is None:
            continue
        # Hex-Rays may put the taken arm directly on the merge/terminal block
        # (the real residual x86 shape), or introduce an empty one-way bridge.
        merge_serial = (
            int(taken)
            if int(taken) == int(fallthrough_merge)
            else _one_way_merge(mba, taken)
        )
        if false_pointer_cell is None or merge_serial != fallthrough_merge:
            continue
        true_pointer = _read_pointer_cell(true_pointer_cell)
        false_pointer = _read_pointer_cell(false_pointer_cell)
        if true_pointer is None or false_pointer is None:
            continue
        try:
            merge_block = mba.get_mblock(merge_serial)
        except Exception:
            continue
        terminal = _terminal_shape(merge_block, pointer_register, context)
        if terminal is None:
            continue
        additive_base, terminal_ea, terminal_end_ea = terminal
        candidate = ResidualTransferCandidate(
            fragment_start_ea=int(branch_ea),
            fragment_end_ea=int(terminal_end_ea),
            selector_stack_offset=selector_stack,
            condition_code=condition_code,
            true_pointer_value=true_pointer,
            false_pointer_value=false_pointer,
            additive_base=additive_base,
            envelope_start_ea=int(envelope_start_ea),
            envelope_end_ea=int(envelope_end_ea),
            selector_register=selector_register,
            address_bits=64 if ida_ida.inf_is_64bit() else 32,
        )
        proof = validate_residual_transfer(candidate)
        if proof is not None:
            return ResidualIndirectTransferEvidence(
                candidate=candidate,
                proof=proof,
                conditional_branch_ea=int(branch_ea),
                selector_state_constant=selector_constant,
                terminal_indirect_transfer_ea=terminal_ea,
                terminal_indirect_transfer_end_ea=terminal_end_ea,
            )
    return None


__all__ = [
    "ResidualIndirectTransferEvidence",
    "recognize_residual_indirect_transfer",
]
