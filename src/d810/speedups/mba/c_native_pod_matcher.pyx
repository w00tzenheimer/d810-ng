# distutils: language = c++
# cython: language_level=3, embedsignature=True
# cython: cdivision=True, boundscheck=False, wraparound=False
"""Numeric structural matching for packed native MBA terms.

This module receives only integer tuples.  It deliberately has no Hex-Rays,
Egglog, constraint, or replacement-materialization dependency.
"""

from libcpp.vector cimport vector


DEF KIND_CONSTANT = 1
DEF KIND_LEAF = 2
DEF KIND_OPERATOR = 3
DEF OP_ADD = 1
DEF OP_AND = 2
DEF OP_MUL = 4
DEF OP_OR = 6
DEF OP_XOR = 8
DEF MAX_POD_NODES = 32
DEF MAX_POD_BINDINGS = 16


cdef struct MatchCounter:
    int comparisons
    int lazy_swaps
    int limit
    bint exceeded


cdef struct BindingState:
    # Fixed-capacity bindings with a local transactional undo log.
    int values[MAX_POD_BINDINGS]
    int undo_slots[MAX_POD_BINDINGS]
    int undo_values[MAX_POD_BINDINGS]
    int undo_count


cdef inline bint _is_ac(int operation) noexcept nogil:
    return operation in (OP_ADD, OP_AND, OP_MUL, OP_OR, OP_XOR)


cdef void _reset_bindings(BindingState* state, int variable_count) noexcept:
    cdef int index
    for index in range(variable_count):
        state.values[index] = -1
    state.undo_count = 0


cdef inline int _binding_checkpoint(BindingState* state) noexcept:
    return state.undo_count


cdef void _bind(BindingState* state, int slot, int candidate_index) noexcept:
    cdef int undo_index = state.undo_count
    state.undo_slots[undo_index] = slot
    state.undo_values[undo_index] = state.values[slot]
    state.values[slot] = candidate_index
    state.undo_count = undo_index + 1


cdef void _rollback_bindings(BindingState* state, int checkpoint) noexcept:
    cdef int undo_index
    while state.undo_count > checkpoint:
        state.undo_count -= 1
        undo_index = state.undo_count
        state.values[state.undo_slots[undo_index]] = state.undo_values[undo_index]


cdef vector[BindingState] _empty_results():
    cdef vector[BindingState] result
    return result


cdef void _collect_pattern_ac(
    tuple pattern_rows,
    int pattern_index,
    int operation,
    vector[int]* items,
):
    cdef tuple pattern = <tuple>pattern_rows[pattern_index]
    cdef int left
    cdef int right
    if <int>pattern[0] == KIND_OPERATOR and <int>pattern[1] == operation:
        left = <int>pattern[5]
        right = <int>pattern[6]
        if left >= 0 and right >= 0:
            _collect_pattern_ac(pattern_rows, left, operation, items)
            _collect_pattern_ac(pattern_rows, right, operation, items)
            return
    items[0].push_back(pattern_index)


cdef void _collect_candidate_ac(
    tuple candidate_rows,
    int candidate_index,
    int operation,
    vector[int]* items,
):
    cdef tuple candidate = <tuple>candidate_rows[candidate_index]
    cdef int left
    cdef int right
    if <int>candidate[0] == KIND_OPERATOR and <int>candidate[1] == operation:
        left = <int>candidate[3]
        right = <int>candidate[4]
        if left >= 0 and right >= 0:
            _collect_candidate_ac(candidate_rows, left, operation, items)
            _collect_candidate_ac(candidate_rows, right, operation, items)
            return
    items[0].push_back(candidate_index)


cdef void _sort_candidate_ac_items(
    tuple candidate_rows,
    vector[int]* items,
):
    """Stable insertion-sort by the Python adapter's structural rank."""

    cdef size_t index
    cdef size_t previous
    cdef int current
    cdef int prior
    for index in range(1, items[0].size()):
        current = items[0][index]
        previous = index
        while previous > 0:
            prior = items[0][previous - 1]
            if <int>candidate_rows[prior][8] <= <int>candidate_rows[current][8]:
                break
            items[0][previous] = prior
            previous -= 1
        items[0][previous] = current


cdef void _extend(
    vector[BindingState]* destination,
    vector[BindingState] source,
) noexcept:
    cdef size_t index
    for index in range(source.size()):
        destination[0].push_back(source[index])


cdef vector[BindingState] _match(
    tuple pattern_rows,
    tuple candidate_rows,
    int pattern_index,
    int candidate_index,
    BindingState bindings,
    MatchCounter* counter,
):
    cdef tuple pattern
    cdef tuple candidate
    cdef int pattern_kind
    cdef int candidate_kind
    cdef int slot
    cdef int bound_index
    cdef int pattern_left
    cdef int pattern_right
    cdef int candidate_left
    cdef int candidate_right
    cdef vector[BindingState] result
    cdef vector[BindingState] left_results
    cdef vector[BindingState] right_results
    cdef vector[int] pattern_items
    cdef vector[int] candidate_items
    cdef size_t index
    cdef size_t next_index
    cdef int checkpoint

    counter.comparisons += 1
    if counter.comparisons > counter.limit:
        counter.exceeded = True
        return _empty_results()
    pattern = <tuple>pattern_rows[pattern_index]
    candidate = <tuple>candidate_rows[candidate_index]
    pattern_kind = <int>pattern[0]
    candidate_kind = <int>candidate[0]
    if pattern_kind == KIND_CONSTANT:
        if candidate_kind != KIND_CONSTANT:
            return _empty_results()
        if <unsigned long long>pattern[3] != <unsigned long long>candidate[5]:
            return _empty_results()
        result.push_back(bindings)
        return result
    if pattern_kind == KIND_LEAF:
        slot = <int>pattern[2]
        if <int>pattern[4] and candidate_kind != KIND_CONSTANT:
            return _empty_results()
        if slot < 0:
            result.push_back(bindings)
            return result
        bound_index = bindings.values[slot]
        if bound_index >= 0:
            if <int>candidate_rows[bound_index][7] != <int>candidate[7]:
                return _empty_results()
            result.push_back(bindings)
            return result
        checkpoint = _binding_checkpoint(&bindings)
        _bind(&bindings, slot, candidate_index)
        result.push_back(bindings)
        _rollback_bindings(&bindings, checkpoint)
        return result
    if pattern_kind != KIND_OPERATOR or candidate_kind != KIND_OPERATOR:
        return _empty_results()
    if <int>pattern[1] != <int>candidate[1] or <int>candidate[2] <= 0:
        return _empty_results()
    pattern_left = <int>pattern[5]
    pattern_right = <int>pattern[6]
    candidate_left = <int>candidate[3]
    candidate_right = <int>candidate[4]
    if pattern_left < 0 or candidate_left < 0:
        return _empty_results()
    if (
        _is_ac(<int>pattern[1])
        and pattern_right >= 0
        and candidate_right >= 0
    ):
        _collect_pattern_ac(pattern_rows, pattern_index, <int>pattern[1], &pattern_items)
        _collect_candidate_ac(
            candidate_rows, candidate_index, <int>pattern[1], &candidate_items
        )
        if pattern_items.size() != candidate_items.size():
            return _empty_results()
        _sort_candidate_ac_items(candidate_rows, &candidate_items)
        if pattern_items.size() == 2:
            left_results = _match(
                pattern_rows,
                candidate_rows,
                pattern_items[0],
                candidate_items[0],
                bindings,
                counter,
            )
            for index in range(left_results.size()):
                right_results = _match(
                    pattern_rows,
                    candidate_rows,
                    pattern_items[1],
                    candidate_items[1],
                    left_results[index],
                    counter,
                )
                _extend(&result, right_results)
            if counter.exceeded:
                return _empty_results()
            if <int>candidate_rows[candidate_items[0]][7] != <int>candidate_rows[
                candidate_items[1]
            ][7]:
                counter.lazy_swaps += 1
                left_results = _match(
                    pattern_rows,
                    candidate_rows,
                    pattern_items[0],
                    candidate_items[1],
                    bindings,
                    counter,
                )
                for index in range(left_results.size()):
                    right_results = _match(
                        pattern_rows,
                        candidate_rows,
                        pattern_items[1],
                        candidate_items[0],
                        left_results[index],
                        counter,
                    )
                    _extend(&result, right_results)
            return result
        return _match_ac_items(
            pattern_rows,
            candidate_rows,
            pattern_items,
            0,
            candidate_items,
            bindings,
            counter,
        )
    left_results = _match(
        pattern_rows, candidate_rows, pattern_left, candidate_left, bindings, counter
    )
    for index in range(left_results.size()):
        if pattern_right < 0:
            result.push_back(left_results[index])
        elif candidate_right >= 0:
            right_results = _match(
                pattern_rows,
                candidate_rows,
                pattern_right,
                candidate_right,
                left_results[index],
                counter,
            )
            _extend(&result, right_results)
    return result


cdef vector[BindingState] _match_ac_items(
    tuple pattern_rows,
    tuple candidate_rows,
    vector[int] pattern_items,
    size_t pattern_position,
    vector[int] remaining_candidates,
    BindingState bindings,
    MatchCounter* counter,
):
    """Match one flattened AC item per candidate without group capture."""

    cdef vector[BindingState] result
    cdef vector[BindingState] partial
    cdef vector[BindingState] completed
    cdef vector[int] remaining
    cdef size_t candidate_position
    cdef size_t index
    cdef size_t result_index
    if pattern_position == pattern_items.size():
        if remaining_candidates.empty():
            result.push_back(bindings)
        return result
    for candidate_position in range(remaining_candidates.size()):
        partial = _match(
            pattern_rows,
            candidate_rows,
            pattern_items[pattern_position],
            remaining_candidates[candidate_position],
            bindings,
            counter,
        )
        if counter.exceeded:
            return _empty_results()
        for result_index in range(partial.size()):
            remaining.clear()
            for index in range(remaining_candidates.size()):
                if index != candidate_position:
                    remaining.push_back(remaining_candidates[index])
            completed = _match_ac_items(
                pattern_rows,
                candidate_rows,
                pattern_items,
                pattern_position + 1,
                remaining,
                partial[result_index],
                counter,
            )
            if counter.exceeded:
                return _empty_results()
            _extend(&result, completed)
    return result


def match_pod_pattern(
    tuple pattern_rows,
    tuple candidate_rows,
    int candidate_root_index,
    int variable_count,
    int comparison_budget,
):
    """Return all structural bindings as variable-slot/candidate-node indices.

    Pattern rows are ``(kind, operation, slot, literal, requires_constant,
    left, right)``. Candidate rows are numeric ``PackedPodNode`` tuples with
    structural-identity and stable-order fields. The return shape is
    ``(bindings, comparisons, lazy_swaps, budget_exceeded)``.
    """

    cdef BindingState bindings
    cdef vector[BindingState] results
    cdef BindingState result
    cdef MatchCounter counter
    cdef int index
    cdef size_t result_index
    cdef size_t binding_index
    cdef list output = []
    cdef object record
    if variable_count < 0 or comparison_budget <= 0:
        raise ValueError("variable_count and comparison_budget must be positive")
    if not pattern_rows or candidate_root_index < 0:
        return (), 0, 0, False
    if (
        len(pattern_rows) > MAX_POD_NODES
        or len(candidate_rows) > MAX_POD_NODES
        or variable_count > MAX_POD_BINDINGS
    ):
        raise ValueError("POD matcher fixed capacity exceeded")
    if any(type(record) is not tuple or len(record) != 7 for record in pattern_rows):
        raise ValueError("pattern POD rows must contain seven integers")
    if any(type(record) is not tuple or len(record) != 9 for record in candidate_rows):
        raise ValueError("candidate POD rows must contain nine integers")
    _reset_bindings(&bindings, variable_count)
    counter.comparisons = 0
    counter.lazy_swaps = 0
    counter.limit = comparison_budget
    counter.exceeded = False
    results = _match(
        pattern_rows,
        candidate_rows,
        len(pattern_rows) - 1,
        candidate_root_index,
        bindings,
        &counter,
    )
    if counter.exceeded:
        return (), counter.comparisons, counter.lazy_swaps, True
    for result_index in range(results.size()):
        result = results[result_index]
        output.append(
            tuple(result.values[binding_index] for binding_index in range(variable_count))
        )
    return tuple(output), counter.comparisons, counter.lazy_swaps, False


def match_pod_catalogue(
    tuple patterns,
    tuple candidate_rows,
    int candidate_root_index,
    int comparison_budget,
):
    """Match a root bucket in one Cython call with one global work cap.

    ``patterns`` is a declaration-ordered tuple of
    ``(pattern_rows, variable_count)`` records.  The nested result tuple has
    one binding tuple per pattern, preserving the Python catalogue's order.
    """

    cdef tuple record
    cdef tuple pattern_rows
    cdef int variable_count
    cdef BindingState bindings
    cdef vector[BindingState] results
    cdef BindingState result
    cdef MatchCounter counter
    cdef int index
    cdef size_t result_index
    cdef size_t binding_index
    cdef list catalogue_output = []
    cdef list pattern_output
    cdef object candidate_record

    if comparison_budget <= 0:
        raise ValueError("comparison_budget must be positive")
    if candidate_root_index < 0:
        return (), 0, 0, False
    if len(candidate_rows) > MAX_POD_NODES:
        raise ValueError("POD matcher fixed capacity exceeded")
    if any(
        type(candidate_record) is not tuple or len(candidate_record) != 9
        for candidate_record in candidate_rows
    ):
        raise ValueError("candidate POD rows must contain nine integers")
    counter.comparisons = 0
    counter.lazy_swaps = 0
    counter.limit = comparison_budget
    counter.exceeded = False
    for record in patterns:
        if type(record) is not tuple or len(record) != 2:
            raise ValueError("catalogue POD records must contain a pattern and arity")
        pattern_rows = <tuple>record[0]
        variable_count = <int>record[1]
        if any(
            type(candidate_record) is not tuple or len(candidate_record) != 7
            for candidate_record in pattern_rows
        ):
            raise ValueError("pattern POD rows must contain seven integers")
        if variable_count < 0:
            raise ValueError("variable_count must be non-negative")
        if variable_count > MAX_POD_BINDINGS:
            raise ValueError("POD matcher fixed capacity exceeded")
        if len(pattern_rows) > MAX_POD_NODES:
            raise ValueError("POD matcher fixed capacity exceeded")
        _reset_bindings(&bindings, variable_count)
        results = _match(
            pattern_rows,
            candidate_rows,
            len(pattern_rows) - 1,
            candidate_root_index,
            bindings,
            &counter,
        )
        if counter.exceeded:
            return (), counter.comparisons, counter.lazy_swaps, True
        pattern_output = []
        for result_index in range(results.size()):
            result = results[result_index]
            pattern_output.append(
                tuple(
                    result.values[binding_index]
                    for binding_index in range(variable_count)
                )
            )
        catalogue_output.append(tuple(pattern_output))
    return tuple(catalogue_output), counter.comparisons, counter.lazy_swaps, False
