# cython: language_level=3, boundscheck=False, wraparound=False

"""Independent Cython SCCP solver over the detached primitive model.

This module intentionally has no IDA imports.  The only objects crossing its
public boundary are the immutable model/result objects; hot loops first copy
those fields into compact primitive tuples and then use typed queue heads,
sets, and counters.  It mirrors ``p_sccp`` rather than calling it so the
optional backend remains a real speedup implementation.
"""

import time

from d810.evaluator.hexrays_microcode.sccp_model import (
    OperandKind,
    SccpProgram,
    SccpResult,
    SccpStatus,
)


cdef int _BOTTOM_TAG = 0
cdef int _CONST_TAG = 1
cdef int _TOP_TAG = 2
cdef int _MAX_BLOCKS = 500

cdef object _BOTTOM = (_BOTTOM_TAG, 0, 0)
cdef object _TOP = (_TOP_TAG, 0, 0)
cdef object _UNARY_OPCODES = frozenset(
    ("mov", "neg", "lnot", "bnot", "xds", "xdu", "low", "high")
)
cdef object _BINARY_OPCODES = frozenset(
    (
        "add", "sub", "mul", "udiv", "sdiv", "umod", "smod",
        "or", "and", "xor", "shl", "shr", "sar",
    )
)
cdef object _COMPARE_OPCODES = frozenset(
    ("setz", "setnz", "setae", "setb", "seta", "setbe", "setg", "setge", "setl", "setle")
)
cdef object _CONDITIONAL_BRANCHES = frozenset(
    ("jcnd", "jz", "jnz", "jae", "jb", "ja", "jbe", "jg", "jge", "jl", "jle")
)
cdef object _BRANCH_OPCODES = _CONDITIONAL_BRANCHES | frozenset(("goto",))

# SccpProgram is frozen and contains only detached primitive values.  Retain
# that object beside the compact view so a fingerprint collision cannot reuse
# the wrong snapshot; live MBA/SWIG objects are never retained here.  A small
# bounded cache removes adapter-like tuple conversion from repeated solver-
# only replays without replacing the facade's proof-result memo.
cdef int _PROGRAM_CACHE_LIMIT = 8
cdef dict _PROGRAM_CACHE = {}
cdef list _PROGRAM_CACHE_ORDER = []


cdef inline object _const_state(object value, object size):
    return (_CONST_TAG, value, size)


cdef inline object _mask(object size):
    cdef object one = 1
    if size <= 0:
        return 0
    return (one << (size * 8)) - 1


cdef inline object _unsigned(object value, object size):
    return value & _mask(size)


cdef inline object _signed(object value, object size):
    cdef object masked = value & _mask(size)
    cdef object sign
    if size <= 0:
        return masked
    sign = 1 << (size * 8 - 1)
    if masked & sign:
        return masked - (1 << (size * 8))
    return masked


cdef inline object _trunc_div(object left, object right):
    cdef object quotient
    if right == 0:
        return None
    quotient = abs(left) // abs(right)
    if (left < 0) != (right < 0):
        return -quotient
    return quotient


cdef inline object _meet(object old_value, object new_value):
    cdef int old_tag = <int>old_value[0]
    cdef int new_tag = <int>new_value[0]
    if old_tag == _TOP_TAG or new_tag == _TOP_TAG:
        return _TOP
    if old_tag == _BOTTOM_TAG:
        return new_value
    if new_tag == _BOTTOM_TAG:
        return old_value
    if old_value[1] == new_value[1] and old_value[2] == new_value[2]:
        return old_value
    return _TOP


cdef inline object _resolve_operand(object operand, dict lattice):
    cdef int kind
    cdef object value_id
    if operand is None:
        return _TOP
    kind = <int>operand[0]
    if kind == 1:
        return _const_state(operand[2], operand[1])
    if kind == 2:
        value_id = operand[3]
        return lattice.get(value_id, _BOTTOM)
    return _TOP


cdef inline object _binary_result(
    object opcode,
    object left,
    object right,
    object destination_size,
):
    cdef object a = left[1]
    cdef object b = right[1]
    cdef object left_size = left[2]
    cdef object right_size = right[2]
    cdef object left_unsigned
    cdef object right_unsigned
    cdef object value
    cdef object quotient

    if destination_size <= 0:
        return _TOP
    left_unsigned = _unsigned(a, left_size)
    right_unsigned = _unsigned(b, right_size)
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
        value = _trunc_div(_signed(a, left_size), _signed(b, right_size))
        if value is None:
            return _TOP
    elif opcode == "umod":
        if right_unsigned == 0:
            return _TOP
        value = left_unsigned % right_unsigned
    elif opcode == "smod":
        quotient = _trunc_div(_signed(a, left_size), _signed(b, right_size))
        if quotient is None:
            return _TOP
        value = _signed(a, left_size) - quotient * _signed(b, right_size)
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
        value = _signed(a, left_size) >> b
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
        value = int(_signed(a, left_size) > _signed(b, right_size))
    elif opcode == "setge":
        value = int(_signed(a, left_size) >= _signed(b, right_size))
    elif opcode == "setl":
        value = int(_signed(a, left_size) < _signed(b, right_size))
    elif opcode == "setle":
        value = int(_signed(a, left_size) <= _signed(b, right_size))
    else:
        return _TOP
    return _const_state(value & _mask(destination_size), destination_size)


cdef inline object _unary_result(object opcode, object operand, object destination_size):
    cdef object value = operand[1]
    cdef object result
    if destination_size <= 0:
        return _TOP
    if opcode == "mov":
        result = value
    elif opcode == "neg":
        result = -value
    elif opcode == "lnot":
        result = int(value == 0)
    elif opcode == "bnot":
        result = ~value
    elif opcode == "xds":
        result = _signed(value, operand[2])
    elif opcode == "xdu" or opcode == "low":
        result = _unsigned(value, operand[2])
    elif opcode == "high":
        result = _unsigned(value, operand[2]) >> (destination_size * 8)
    else:
        return _TOP
    return _const_state(result & _mask(destination_size), destination_size)


cdef inline object _eval_instruction(object instruction, dict lattice):
    cdef object opcode = instruction[2]
    cdef object left = _resolve_operand(instruction[5], lattice)
    cdef int left_tag = <int>left[0]
    cdef object right
    cdef int right_tag
    if opcode in _UNARY_OPCODES:
        if left_tag == _BOTTOM_TAG:
            return _BOTTOM
        if left_tag == _TOP_TAG:
            return _TOP
        return _unary_result(opcode, left, instruction[4])
    if opcode in _BINARY_OPCODES or opcode in _COMPARE_OPCODES:
        right = _resolve_operand(instruction[6], lattice)
        right_tag = <int>right[0]
        if left_tag == _BOTTOM_TAG or right_tag == _BOTTOM_TAG:
            return _BOTTOM
        if left_tag == _TOP_TAG or right_tag == _TOP_TAG:
            return _TOP
        return _binary_result(opcode, left, right, instruction[4])
    return _TOP


cdef inline object _condition_result(object instruction, dict lattice):
    cdef object opcode = instruction[2]
    cdef object left = _resolve_operand(instruction[5], lattice)
    cdef int left_tag = <int>left[0]
    cdef object right
    cdef int right_tag
    cdef object a
    cdef object b
    cdef bint result

    if opcode == "jcnd":
        if left_tag == _BOTTOM_TAG or left_tag == _TOP_TAG:
            return left
        return _const_state(int(left[1] != 0), 1)
    right = _resolve_operand(instruction[6], lattice)
    right_tag = <int>right[0]
    if left_tag == _BOTTOM_TAG or right_tag == _BOTTOM_TAG:
        return _BOTTOM
    if left_tag == _TOP_TAG or right_tag == _TOP_TAG:
        return _TOP
    a = left[1]
    b = right[1]
    if opcode == "jz":
        result = a == b
    elif opcode == "jnz":
        result = a != b
    elif opcode == "jae":
        result = _unsigned(a, left[2]) >= _unsigned(b, right[2])
    elif opcode == "jb":
        result = _unsigned(a, left[2]) < _unsigned(b, right[2])
    elif opcode == "ja":
        result = _unsigned(a, left[2]) > _unsigned(b, right[2])
    elif opcode == "jbe":
        result = _unsigned(a, left[2]) <= _unsigned(b, right[2])
    elif opcode == "jg":
        result = _signed(a, left[2]) > _signed(b, right[2])
    elif opcode == "jge":
        result = _signed(a, left[2]) >= _signed(b, right[2])
    elif opcode == "jl":
        result = _signed(a, left[2]) < _signed(b, right[2])
    elif opcode == "jle":
        result = _signed(a, left[2]) <= _signed(b, right[2])
    else:
        return _TOP
    return _const_state(int(result), 1)


cdef tuple _primitive_operand(object operand):
    cdef object kind
    cdef object kind_value
    cdef object size
    if operand is None:
        return None
    kind = operand.kind
    kind_value = getattr(kind, "value", kind)
    size = int(operand.size)
    if kind_value == OperandKind.CONSTANT.value:
        return (1, size, operand.constant, None)
    if kind_value == OperandKind.VALUE.value:
        return (2, size, None, operand.value_id)
    return (0, size, None, None)


cdef tuple _primitive_instruction(object instruction):
    cdef object destination = instruction.destination_value_id
    if destination is not None:
        destination = int(destination)
    return (
        int(instruction.index),
        int(instruction.block_index),
        instruction.opcode,
        int(instruction.ea),
        int(instruction.size),
        _primitive_operand(instruction.left),
        _primitive_operand(instruction.right),
        destination,
    )


cdef inline void _enqueue_edge(
    list queue,
    set pending,
    set executable,
    object source,
    object target,
):
    cdef tuple edge = (source, target)
    if edge in executable or edge in pending:
        return
    queue.append(edge)
    pending.add(edge)


cdef inline void _enqueue_value(list queue, set pending, object value_id):
    if value_id in pending:
        return
    queue.append(value_id)
    pending.add(value_id)


cdef inline void _update_value(
    object value_id,
    object new_value,
    dict lattice,
    list pending_values,
    set pending_value_set,
):
    cdef object old_value = lattice.get(value_id, _BOTTOM)
    cdef object merged = _meet(old_value, new_value)
    if merged[0] == old_value[0] and merged[1] == old_value[1] and merged[2] == old_value[2]:
        return
    lattice[value_id] = merged
    _enqueue_value(pending_values, pending_value_set, value_id)


cdef inline void _visit_instruction(
    object instruction,
    dict lattice,
    list pending_values,
    set pending_value_set,
):
    cdef object destination = instruction[7]
    if destination is None:
        return
    _update_value(
        destination,
        _eval_instruction(instruction, lattice),
        lattice,
        pending_values,
        pending_value_set,
    )


cdef inline void _visit_branch(
    object block,
    dict instruction_map,
    dict lattice,
    list pending_edges,
    set pending_edge_set,
    set executable_edges,
):
    cdef tuple successors = block[1]
    cdef tuple instruction_indices = block[2]
    cdef Py_ssize_t instruction_count = len(instruction_indices)
    cdef object tail
    cdef object tail_index
    cdef object condition
    cdef int condition_tag
    cdef object successor
    if not successors:
        return
    if instruction_count:
        tail_index = instruction_indices[instruction_count - 1]
        tail = instruction_map.get(tail_index)
    else:
        tail = None
    if tail is None or tail[2] not in _BRANCH_OPCODES:
        for successor in successors:
            _enqueue_edge(
                pending_edges,
                pending_edge_set,
                executable_edges,
                block[0],
                successor,
            )
        return
    if tail[2] == "goto":
        _enqueue_edge(
            pending_edges,
            pending_edge_set,
            executable_edges,
            block[0],
            successors[0],
        )
        return
    condition = _condition_result(tail, lattice)
    condition_tag = <int>condition[0]
    if condition_tag == _BOTTOM_TAG:
        return
    if len(successors) == 1 or condition_tag == _TOP_TAG:
        for successor in successors:
            _enqueue_edge(
                pending_edges,
                pending_edge_set,
                executable_edges,
                block[0],
                successor,
            )
        return
    successor = successors[1] if condition[1] != 0 else successors[0]
    _enqueue_edge(
        pending_edges,
        pending_edge_set,
        executable_edges,
        block[0],
        successor,
    )


cdef object _empty_result(
    object status,
    object fingerprint,
    object reason,
    double solver_seconds,
):
    return SccpResult.empty(
        status=status,
        program_fingerprint=fingerprint,
        backend="cython",
        fallback_reason=reason,
        solver_seconds=solver_seconds,
    )


cpdef object solve(object program, object work_budget=None):
    """Solve an immutable :class:`SccpProgram` using Cython queue/index loops."""

    cdef double started = time.perf_counter()
    cdef object fingerprint = getattr(program, "fingerprint", "")
    cdef object blocks_source
    cdef object instructions_source
    cdef object blocks = []
    cdef object instructions = []
    cdef dict block_map = {}
    cdef dict instruction_map = {}
    cdef dict uses = {}
    cdef dict mop_keys = {}
    cdef object block
    cdef object instruction
    cdef object primitive_block
    cdef object primitive_instruction
    cdef list primitive_successors
    cdef list primitive_instruction_indices
    cdef object block_index
    cdef object instruction_index
    cdef object successor
    cdef tuple successors
    cdef tuple instruction_indices
    cdef object value_id
    cdef object key
    cdef object edge_count
    cdef object value_count
    cdef object instruction_count
    cdef object budget
    cdef list pending_edges
    cdef list pending_values
    cdef Py_ssize_t edge_head
    cdef Py_ssize_t value_head
    cdef Py_ssize_t cfg_events
    cdef Py_ssize_t value_events
    cdef Py_ssize_t peak_cfg_queue
    cdef Py_ssize_t peak_value_queue
    cdef tuple edge
    cdef object source
    cdef object target
    cdef object current_block
    cdef object current_instruction
    cdef object destination
    cdef bint is_virtual_entry
    cdef bint was_visited
    cdef set pending_edge_set
    cdef set executable_edges
    cdef set reachable_blocks
    cdef set pending_value_set
    cdef set visited_blocks
    cdef dict lattice
    cdef object result
    cdef object state
    cdef dict constants
    cdef object elapsed
    cdef object cached_entry
    cdef object cached_program
    cdef bint cache_hit
    cdef bint cacheable_program

    try:
        blocks_source = program.blocks
        instructions_source = program.instructions
        if len(blocks_source) > _MAX_BLOCKS:
            return _empty_result(
                SccpStatus.BLOCK_LIMIT,
                fingerprint,
                "",
                time.perf_counter() - started,
            )

        cacheable_program = isinstance(program, SccpProgram)
        cached_entry = _PROGRAM_CACHE.get(fingerprint) if cacheable_program else None
        cache_hit = False
        if cached_entry is not None:
            cached_program = cached_entry[0]
            if cached_program is program or cached_program == program:
                cached_program = cached_entry[1]
                cache_hit = True
        if cache_hit:
            (
                blocks,
                instructions,
                block_map,
                instruction_map,
                uses,
                mop_keys,
                edge_count,
            ) = cached_program
        else:
            for block in blocks_source:
                block_index = int(block.index)
                if block_index in block_map:
                    raise ValueError(f"duplicate block index: {block_index}")
                primitive_successors = []
                for successor in block.successors:
                    primitive_successors.append(int(successor))
                successors = tuple(primitive_successors)
                primitive_instruction_indices = []
                for instruction_index in block.instruction_indices:
                    primitive_instruction_indices.append(int(instruction_index))
                instruction_indices = tuple(primitive_instruction_indices)
                primitive_block = (block_index, successors, instruction_indices)
                blocks.append(primitive_block)
                block_map[block_index] = primitive_block

            for instruction in instructions_source:
                primitive_instruction = _primitive_instruction(instruction)
                instruction_index = primitive_instruction[0]
                if instruction_index in instruction_map:
                    raise ValueError(f"duplicate instruction index: {instruction_index}")
                instructions.append(primitive_instruction)
                instruction_map[instruction_index] = primitive_instruction

            for primitive_block in blocks:
                block_index = primitive_block[0]
                for successor in primitive_block[1]:
                    if successor not in block_map:
                        raise ValueError(
                            f"block {block_index} has unknown successor {successor}"
                        )
                for instruction_index in primitive_block[2]:
                    current_instruction = instruction_map.get(instruction_index)
                    if current_instruction is None:
                        raise ValueError(
                            f"block {block_index} has unknown instruction {instruction_index}"
                        )
                    if current_instruction[1] != block_index:
                        raise ValueError(
                            f"instruction {instruction_index} belongs to another block"
                        )

            for value_id, instruction_indices in program.uses_by_value.items():
                primitive_instruction_indices = []
                for instruction_index in instruction_indices:
                    primitive_instruction_indices.append(int(instruction_index))
                uses[int(value_id)] = tuple(primitive_instruction_indices)
            for value_id, key in program.mop_keys_by_value.items():
                mop_keys[int(value_id)] = key

            edge_count = 0
            for primitive_block in blocks:
                edge_count += len(primitive_block[1])
            if fingerprint not in _PROGRAM_CACHE:
                if len(_PROGRAM_CACHE_ORDER) >= _PROGRAM_CACHE_LIMIT:
                    _PROGRAM_CACHE.pop(_PROGRAM_CACHE_ORDER.pop(0), None)
                _PROGRAM_CACHE_ORDER.append(fingerprint)
            if cacheable_program:
                _PROGRAM_CACHE[fingerprint] = (
                    program,
                    (
                        tuple(blocks),
                        tuple(instructions),
                        block_map,
                        instruction_map,
                        uses,
                        mop_keys,
                        edge_count,
                    ),
                )
        value_count = len(mop_keys)
        instruction_count = len(instructions)
        budget = max(1, 2 * value_count + edge_count + instruction_count)
        if work_budget is not None:
            budget = int(work_budget)
            if budget < 0:
                budget = 0
        if budget == 0:
            return _empty_result(
                SccpStatus.WORK_LIMIT,
                fingerprint,
                "",
                time.perf_counter() - started,
            )

        lattice = {}
        executable_edges = set()
        reachable_blocks = set()
        visited_blocks = set()
        pending_edges = []
        pending_edge_set = set()
        pending_values = []
        pending_value_set = set()
        edge_head = 0
        value_head = 0
        cfg_events = 0
        value_events = 0
        peak_cfg_queue = 0
        peak_value_queue = 0

        # The virtual entry edge establishes reachability but is not a real
        # CFG event, matching the Python solver's budget contract exactly.
        _enqueue_edge(pending_edges, pending_edge_set, executable_edges, -1, 0)
        peak_cfg_queue = 1

        while edge_head < len(pending_edges) or value_head < len(pending_values):
            if cfg_events + value_events >= budget:
                return _empty_result(
                    SccpStatus.WORK_LIMIT,
                    fingerprint,
                    "",
                    time.perf_counter() - started,
                )

            if edge_head < len(pending_edges):
                edge = pending_edges[edge_head]
                edge_head += 1
                pending_edge_set.remove(edge)
                source = edge[0]
                target = edge[1]
                is_virtual_entry = source < 0
                if not is_virtual_entry:
                    cfg_events += 1
                if source >= 0:
                    executable_edges.add(edge)
                if target not in block_map:
                    return _empty_result(
                        SccpStatus.ERROR,
                        fingerprint,
                        f"edge targets unknown block {target}",
                        time.perf_counter() - started,
                    )
                was_visited = target in visited_blocks
                visited_blocks.add(target)
                reachable_blocks.add(target)
                current_block = block_map[target]
                if not was_visited:
                    for instruction_index in current_block[2]:
                        _visit_instruction(
                            instruction_map[instruction_index],
                            lattice,
                            pending_values,
                            pending_value_set,
                        )
                    _visit_branch(
                        current_block,
                        instruction_map,
                        lattice,
                        pending_edges,
                        pending_edge_set,
                        executable_edges,
                    )
                else:
                    for instruction_index in current_block[2]:
                        current_instruction = instruction_map[instruction_index]
                        destination = current_instruction[7]
                        if destination is not None:
                            _visit_instruction(
                                current_instruction,
                                lattice,
                                pending_values,
                                pending_value_set,
                            )
                peak_cfg_queue = max(peak_cfg_queue, len(pending_edges) - edge_head)
                peak_value_queue = max(peak_value_queue, len(pending_values) - value_head)
                continue

            value_id = pending_values[value_head]
            value_head += 1
            pending_value_set.remove(value_id)
            value_events += 1
            for instruction_index in uses.get(value_id, ()):
                current_instruction = instruction_map.get(instruction_index)
                if (
                    current_instruction is None
                    or current_instruction[1] not in visited_blocks
                ):
                    continue
                destination = current_instruction[7]
                if destination is not None:
                    _visit_instruction(
                        current_instruction,
                        lattice,
                        pending_values,
                        pending_value_set,
                    )
                current_block = block_map[current_instruction[1]]
                if (
                    current_block[2]
                    and current_block[2][len(current_block[2]) - 1] == current_instruction[0]
                ):
                    _visit_branch(
                        current_block,
                        instruction_map,
                        lattice,
                        pending_edges,
                        pending_edge_set,
                        executable_edges,
                    )
            peak_cfg_queue = max(peak_cfg_queue, len(pending_edges) - edge_head)
            peak_value_queue = max(peak_value_queue, len(pending_values) - value_head)

        constants = {}
        for value_id, state in lattice.items():
            key = mop_keys.get(value_id)
            if key is None:
                continue
            constants[key] = state[1] if state[0] == _CONST_TAG else None
        elapsed = time.perf_counter() - started
        result = SccpResult(
            status=SccpStatus.CONVERGED,
            constants=constants,
            executable_edges=frozenset(executable_edges),
            reachable_blocks=frozenset(reachable_blocks),
            program_fingerprint=fingerprint,
            backend="cython",
            cfg_events=cfg_events,
            value_events=value_events,
            peak_cfg_queue=peak_cfg_queue,
            peak_value_queue=peak_value_queue,
            solver_seconds=elapsed,
        )
        return result
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError) as exc:
        return _empty_result(
            SccpStatus.ERROR,
            fingerprint,
            f"invalid SCCP program: {exc}",
            time.perf_counter() - started,
        )


__all__ = ["solve"]
