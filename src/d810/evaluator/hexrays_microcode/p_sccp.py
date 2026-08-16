"""Pure-Python sparse conditional constant propagation solver.

The module intentionally depends only on :mod:`sccp_model` and the standard
library.  Live IDA objects are converted into that model by the separate
snapshot adapter owned by the facade task.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import time

from d810.core.typing import Any

from d810.evaluator.hexrays_microcode.sccp_model import (
    OperandKind,
    SccpBlock,
    SccpInstruction,
    SccpProgram,
    SccpResult,
    SccpStatus,
)


_MAX_BLOCKS = 500
_UNARY_OPCODES = frozenset({"mov", "neg", "lnot", "bnot", "xds", "xdu", "low", "high"})
_BINARY_OPCODES = frozenset(
    {
        "add",
        "sub",
        "mul",
        "udiv",
        "sdiv",
        "umod",
        "smod",
        "or",
        "and",
        "xor",
        "shl",
        "shr",
        "sar",
    }
)
_COMPARE_OPCODES = frozenset(
    {"setz", "setnz", "setae", "setb", "seta", "setbe", "setg", "setge", "setl", "setle"}
)
_CONDITIONAL_BRANCHES = frozenset(
    {"jcnd", "jz", "jnz", "jae", "jb", "ja", "jbe", "jg", "jge", "jl", "jle"}
)
_BRANCH_OPCODES = _CONDITIONAL_BRANCHES | {"goto"}


@dataclass(frozen=True, slots=True)
class _Const:
    value: int
    size: int


class _Bottom:
    __slots__ = ()


class _Top:
    __slots__ = ()


_BOTTOM = _Bottom()
_TOP = _Top()


def _mask(size: int) -> int:
    if size <= 0:
        return 0
    return (1 << (size * 8)) - 1


def _unsigned(value: int, size: int) -> int:
    return value & _mask(size)


def _signed(value: int, size: int) -> int:
    value &= _mask(size)
    sign = 1 << (size * 8 - 1) if size > 0 else 0
    return value - (1 << (size * 8)) if sign and value & sign else value


def _signed_to_unsigned(value: int, size: int) -> int:
    return value & _mask(size)


def _trunc_div(left: int, right: int) -> int | None:
    if right == 0:
        return None
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) ^ (right < 0) else quotient


def _meet(old: object, new: object) -> object:
    """Meet two values in BOTTOM -> Const -> TOP order."""

    if old is _TOP or new is _TOP:
        return _TOP
    if old is _BOTTOM:
        return new
    if new is _BOTTOM:
        return old
    if isinstance(old, _Const) and isinstance(new, _Const) and old == new:
        return old
    return _TOP


def _resolve_operand(operand: Any, lattice: dict[int, object]) -> object:
    if operand is None:
        return _TOP
    if operand.kind is OperandKind.CONSTANT:
        assert operand.constant is not None
        return _Const(operand.constant, operand.size)
    if operand.kind is OperandKind.VALUE:
        assert operand.value_id is not None
        return lattice.get(operand.value_id, _BOTTOM)
    return _TOP


def _binary_result(
    opcode: str,
    left: _Const,
    right: _Const,
    destination_size: int,
) -> _Const | object:
    if destination_size <= 0:
        return _TOP

    a = left.value
    b = right.value
    mask = _mask(destination_size)
    left_unsigned = _unsigned(a, left.size)
    right_unsigned = _unsigned(b, right.size)

    if opcode == "add":
        value = a + b
    elif opcode == "sub":
        value = a - b
    elif opcode == "mul":
        value = a * b
    elif opcode == "udiv":
        if right_unsigned == 0:
            return _TOP
        value = left_unsigned // right_unsigned
    elif opcode == "sdiv":
        value = _trunc_div(_signed(a, left.size), _signed(b, right.size))
        if value is None:
            return _TOP
    elif opcode == "umod":
        if right_unsigned == 0:
            return _TOP
        value = left_unsigned % right_unsigned
    elif opcode == "smod":
        signed_left = _signed(a, left.size)
        signed_right = _signed(b, right.size)
        quotient = _trunc_div(signed_left, signed_right)
        if quotient is None:
            return _TOP
        value = signed_left - quotient * signed_right
    elif opcode == "or":
        value = a | b
    elif opcode == "and":
        value = a & b
    elif opcode == "xor":
        value = a ^ b
    elif opcode == "shl":
        if b < 0:
            return _TOP
        value = a << b
    elif opcode == "shr":
        if b < 0:
            return _TOP
        value = left_unsigned >> b
    elif opcode == "sar":
        if b < 0:
            return _TOP
        value = _signed(a, left.size) >> b
    elif opcode == "setz":
        value = int(a == b)
    elif opcode == "setnz":
        value = int(a != b)
    elif opcode == "setae":
        value = int(left_unsigned >= right_unsigned)
    elif opcode == "setb":
        value = int(left_unsigned < right_unsigned)
    elif opcode == "seta":
        value = int(left_unsigned > right_unsigned)
    elif opcode == "setbe":
        value = int(left_unsigned <= right_unsigned)
    elif opcode == "setg":
        value = int(_signed(a, left.size) > _signed(b, right.size))
    elif opcode == "setge":
        value = int(_signed(a, left.size) >= _signed(b, right.size))
    elif opcode == "setl":
        value = int(_signed(a, left.size) < _signed(b, right.size))
    elif opcode == "setle":
        value = int(_signed(a, left.size) <= _signed(b, right.size))
    else:
        return _TOP
    return _Const(value & mask, destination_size)


def _unary_result(
    opcode: str,
    operand: _Const,
    destination_size: int,
) -> _Const | object:
    if destination_size <= 0:
        return _TOP
    mask = _mask(destination_size)
    value = operand.value
    if opcode == "mov":
        result = value
    elif opcode == "neg":
        result = -value
    elif opcode == "lnot":
        result = int(value == 0)
    elif opcode == "bnot":
        result = ~value
    elif opcode == "xds":
        result = _signed(value, operand.size)
    elif opcode == "xdu" or opcode == "low":
        result = _unsigned(value, operand.size)
    elif opcode == "high":
        result = _unsigned(value, operand.size) >> (destination_size * 8)
    else:
        return _TOP
    return _Const(result & mask, destination_size)


def _eval_instruction(instruction: SccpInstruction, lattice: dict[int, object]) -> object:
    left = _resolve_operand(instruction.left, lattice)
    if instruction.opcode in _UNARY_OPCODES:
        if left is _BOTTOM:
            return _BOTTOM
        if left is _TOP or not isinstance(left, _Const):
            return _TOP
        return _unary_result(instruction.opcode, left, instruction.size)

    if instruction.opcode in _BINARY_OPCODES or instruction.opcode in _COMPARE_OPCODES:
        right = _resolve_operand(instruction.right, lattice)
        if left is _BOTTOM or right is _BOTTOM:
            return _BOTTOM
        if left is _TOP or right is _TOP:
            return _TOP
        if not isinstance(left, _Const) or not isinstance(right, _Const):
            return _TOP
        return _binary_result(instruction.opcode, left, right, instruction.size)

    # Branches and unknown side-effecting operations do not define a value in
    # the model; a destination on either is conservatively overdefined.
    return _TOP


def _condition_result(instruction: SccpInstruction, lattice: dict[int, object]) -> object:
    left = _resolve_operand(instruction.left, lattice)
    if instruction.opcode == "jcnd":
        if left is _BOTTOM or left is _TOP:
            return left
        assert isinstance(left, _Const)
        return _Const(int(left.value != 0), 1)

    right = _resolve_operand(instruction.right, lattice)
    if left is _BOTTOM or right is _BOTTOM:
        return _BOTTOM
    if left is _TOP or right is _TOP:
        return _TOP
    if not isinstance(left, _Const) or not isinstance(right, _Const):
        return _TOP

    a = left.value
    b = right.value
    if instruction.opcode == "jz":
        result = a == b
    elif instruction.opcode == "jnz":
        result = a != b
    elif instruction.opcode == "jae":
        result = _unsigned(a, left.size) >= _unsigned(b, right.size)
    elif instruction.opcode == "jb":
        result = _unsigned(a, left.size) < _unsigned(b, right.size)
    elif instruction.opcode == "ja":
        result = _unsigned(a, left.size) > _unsigned(b, right.size)
    elif instruction.opcode == "jbe":
        result = _unsigned(a, left.size) <= _unsigned(b, right.size)
    elif instruction.opcode == "jg":
        result = _signed(a, left.size) > _signed(b, right.size)
    elif instruction.opcode == "jge":
        result = _signed(a, left.size) >= _signed(b, right.size)
    elif instruction.opcode == "jl":
        result = _signed(a, left.size) < _signed(b, right.size)
    elif instruction.opcode == "jle":
        result = _signed(a, left.size) <= _signed(b, right.size)
    else:
        return _TOP
    return _Const(int(result), 1)


def _instruction_map(program: SccpProgram) -> dict[int, SccpInstruction]:
    result: dict[int, SccpInstruction] = {}
    for instruction in program.instructions:
        if instruction.index in result:
            raise ValueError(f"duplicate instruction index: {instruction.index}")
        result[instruction.index] = instruction
    return result


def _block_map(program: SccpProgram) -> dict[int, SccpBlock]:
    result: dict[int, SccpBlock] = {}
    for block in program.blocks:
        if block.index in result:
            raise ValueError(f"duplicate block index: {block.index}")
        result[block.index] = block
    return result


def _validate_program(
    program: SccpProgram,
    blocks: dict[int, SccpBlock],
    instructions: dict[int, SccpInstruction],
) -> None:
    for block in blocks.values():
        for successor in block.successors:
            if successor not in blocks:
                raise ValueError(f"block {block.index} has unknown successor {successor}")
        for instruction_index in block.instruction_indices:
            instruction = instructions.get(instruction_index)
            if instruction is None:
                raise ValueError(f"block {block.index} has unknown instruction {instruction_index}")
            if instruction.block_index != block.index:
                raise ValueError(f"instruction {instruction_index} belongs to another block")


def _empty_nonconverged(
    status: SccpStatus,
    program: SccpProgram,
    *,
    backend: str = "python",
    fallback_reason: str = "",
    solver_seconds: float = 0.0,
) -> SccpResult:
    return SccpResult.empty(
        status=status,
        program_fingerprint=program.fingerprint,
        backend=backend,
        fallback_reason=fallback_reason,
        solver_seconds=solver_seconds,
    )


def solve(program: SccpProgram, *, work_budget: int | None = None) -> SccpResult:
    """Solve *program* with bounded CFG/value worklists.

    A non-converged solve deliberately returns an empty proof surface.  A
    caller may inspect the status and telemetry, but no partial constants or
    edge claims can authorize a rewrite.
    """

    started = time.perf_counter()
    try:
        if len(program.blocks) > _MAX_BLOCKS:
            return _empty_nonconverged(
                SccpStatus.BLOCK_LIMIT,
                program,
                solver_seconds=time.perf_counter() - started,
            )
        blocks = _block_map(program)
        instructions = _instruction_map(program)
        _validate_program(program, blocks, instructions)
    except Exception as exc:
        return _empty_nonconverged(
            SccpStatus.ERROR,
            program,
            fallback_reason=f"invalid SCCP program: {exc}",
            solver_seconds=time.perf_counter() - started,
        )

    edge_count = sum(len(block.successors) for block in program.blocks)
    value_count = len(program.mop_keys_by_value)
    instruction_count = len(program.instructions)
    default_budget = max(1, 2 * value_count + edge_count + instruction_count)
    if work_budget is None:
        budget = default_budget
    else:
        try:
            budget = max(0, int(work_budget))
        except (TypeError, ValueError):
            return _empty_nonconverged(
                SccpStatus.ERROR,
                program,
                fallback_reason="work_budget must be an integer",
                solver_seconds=time.perf_counter() - started,
            )

    if budget == 0:
        return _empty_nonconverged(
            SccpStatus.WORK_LIMIT,
            program,
            solver_seconds=time.perf_counter() - started,
        )

    lattice: dict[int, object] = {}
    executable_edges: set[tuple[int, int]] = set()
    reachable_blocks: set[int] = set()
    pending_edges: deque[tuple[int, int]] = deque()
    pending_edge_set: set[tuple[int, int]] = set()
    pending_values: deque[int] = deque()
    pending_value_set: set[int] = set()
    block_visited: set[int] = set()
    cfg_events = 0
    value_events = 0
    peak_cfg_queue = 0
    peak_value_queue = 0

    def enqueue_edge(edge: tuple[int, int]) -> None:
        if edge in executable_edges or edge in pending_edge_set:
            return
        pending_edges.append(edge)
        pending_edge_set.add(edge)

    def enqueue_value(value_id: int) -> None:
        if value_id in pending_value_set:
            return
        pending_values.append(value_id)
        pending_value_set.add(value_id)

    def update_value(value_id: int, new_value: object) -> None:
        old_value = lattice.get(value_id, _BOTTOM)
        merged = _meet(old_value, new_value)
        if merged is old_value or merged == old_value:
            return
        lattice[value_id] = merged
        enqueue_value(value_id)

    def visit_instruction(instruction: SccpInstruction) -> None:
        if instruction.destination_value_id is None:
            return
        update_value(
            instruction.destination_value_id,
            _eval_instruction(instruction, lattice),
        )

    def visit_branch(block: SccpBlock) -> None:
        if not block.successors:
            return
        tail_index = block.instruction_indices[-1] if block.instruction_indices else None
        tail = instructions.get(tail_index) if tail_index is not None else None
        if tail is None or tail.opcode not in _BRANCH_OPCODES:
            for successor in block.successors:
                enqueue_edge((block.index, successor))
            return
        if tail.opcode == "goto":
            enqueue_edge((block.index, block.successors[0]))
            return

        condition = _condition_result(tail, lattice)
        if condition is _BOTTOM:
            return
        if len(block.successors) == 1 or condition is _TOP:
            for successor in block.successors:
                enqueue_edge((block.index, successor))
            return
        assert isinstance(condition, _Const)
        # Hex-Rays successor ordering is fall-through first, taken second.
        successor = block.successors[1] if condition.value != 0 else block.successors[0]
        enqueue_edge((block.index, successor))

    # Seed the entry block with a virtual edge.  It establishes reachability,
    # but is not real CFG work and must not consume the real-edge budget.
    enqueue_edge((-1, 0))
    peak_cfg_queue = 1

    while pending_edges or pending_values:
        if cfg_events + value_events >= budget:
            return _empty_nonconverged(
                SccpStatus.WORK_LIMIT,
                program,
                solver_seconds=time.perf_counter() - started,
            )

        if pending_edges:
            edge = pending_edges.popleft()
            pending_edge_set.remove(edge)
            source, target = edge
            is_virtual_entry = source < 0
            if not is_virtual_entry:
                cfg_events += 1
            if source >= 0:
                executable_edges.add(edge)
            if target not in blocks:
                return _empty_nonconverged(
                    SccpStatus.ERROR,
                    program,
                    fallback_reason=f"edge targets unknown block {target}",
                    solver_seconds=time.perf_counter() - started,
                )

            was_visited = target in block_visited
            block_visited.add(target)
            reachable_blocks.add(target)
            block = blocks[target]
            if not was_visited:
                for instruction_index in block.instruction_indices:
                    visit_instruction(instructions[instruction_index])
                visit_branch(block)
            else:
                # A predecessor arrival can change only values defined in the
                # arriving block.  Revisit those exact destinations, not every
                # instruction in the block or the entire program.
                for instruction_index in block.instruction_indices:
                    destination = instructions[instruction_index].destination_value_id
                    if destination is not None:
                        visit_instruction(instructions[instruction_index])
            peak_cfg_queue = max(peak_cfg_queue, len(pending_edges))
            peak_value_queue = max(peak_value_queue, len(pending_values))
            continue

        value_id = pending_values.popleft()
        pending_value_set.remove(value_id)
        value_events += 1
        for instruction_index in program.uses_for(value_id):
            instruction = instructions.get(instruction_index)
            if instruction is None or instruction.block_index not in block_visited:
                continue
            if instruction.destination_value_id is not None:
                visit_instruction(instruction)
            block = blocks[instruction.block_index]
            if block.instruction_indices and block.instruction_indices[-1] == instruction.index:
                visit_branch(block)
        peak_cfg_queue = max(peak_cfg_queue, len(pending_edges))
        peak_value_queue = max(peak_value_queue, len(pending_values))

    elapsed = time.perf_counter() - started
    constants: dict[Any, int | None] = {}
    for value_id, lattice_value in lattice.items():
        key = program.mop_key_for(value_id)
        if key is None:
            continue
        constants[key] = lattice_value.value if isinstance(lattice_value, _Const) else None
    return SccpResult(
        status=SccpStatus.CONVERGED,
        constants=constants,
        executable_edges=frozenset(executable_edges),
        reachable_blocks=frozenset(reachable_blocks),
        program_fingerprint=program.fingerprint,
        backend="python",
        cfg_events=cfg_events,
        value_events=value_events,
        peak_cfg_queue=peak_cfg_queue,
        peak_value_queue=peak_value_queue,
        solver_seconds=elapsed,
    )


__all__ = ["solve"]
