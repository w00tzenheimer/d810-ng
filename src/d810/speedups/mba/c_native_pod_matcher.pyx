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


cdef struct MatchCounter:
    int comparisons
    int lazy_swaps
    int limit
    bint exceeded


cdef inline bint _is_ac(int operation) noexcept nogil:
    return operation in (OP_ADD, OP_AND, OP_MUL, OP_OR, OP_XOR)


cdef vector[vector[int]] _empty_results():
    cdef vector[vector[int]] result
    return result


cdef void _extend(
    vector[vector[int]]* destination,
    vector[vector[int]] source,
) noexcept:
    cdef size_t index
    for index in range(source.size()):
        destination[0].push_back(source[index])


cdef vector[vector[int]] _match(
    tuple pattern_rows,
    tuple candidate_rows,
    int pattern_index,
    int candidate_index,
    vector[int] bindings,
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
    cdef vector[vector[int]] result
    cdef vector[vector[int]] left_results
    cdef vector[vector[int]] right_results
    cdef vector[int] updated
    cdef size_t index
    cdef size_t next_index

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
        bound_index = bindings[slot]
        if bound_index >= 0:
            if <int>candidate_rows[bound_index][7] != <int>candidate[7]:
                return _empty_results()
            result.push_back(bindings)
            return result
        updated = bindings
        updated[slot] = candidate_index
        result.push_back(updated)
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
    if (
        _is_ac(<int>pattern[1])
        and pattern_right >= 0
        and candidate_right >= 0
        and <int>candidate_rows[candidate_left][7]
        != <int>candidate_rows[candidate_right][7]
    ):
        counter.lazy_swaps += 1
        left_results = _match(
            pattern_rows, candidate_rows, pattern_left, candidate_right, bindings, counter
        )
        for index in range(left_results.size()):
            right_results = _match(
                pattern_rows,
                candidate_rows,
                pattern_right,
                candidate_left,
                left_results[index],
                counter,
            )
            _extend(&result, right_results)
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
    left, right)``. Candidate rows are numeric ``PackedPodNode`` tuples with a
    final structural identity field. The return shape is
    ``(bindings, comparisons, lazy_swaps, budget_exceeded)``.
    """

    cdef vector[int] bindings
    cdef vector[vector[int]] results
    cdef vector[int] result
    cdef MatchCounter counter
    cdef int index
    cdef size_t result_index
    cdef size_t binding_index
    cdef list output = []
    if variable_count < 0 or comparison_budget <= 0:
        raise ValueError("variable_count and comparison_budget must be positive")
    if not pattern_rows or candidate_root_index < 0:
        return (), 0, 0, False
    for index in range(variable_count):
        bindings.push_back(-1)
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
        output.append(tuple(result[binding_index] for binding_index in range(result.size())))
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
    cdef vector[int] bindings
    cdef vector[vector[int]] results
    cdef vector[int] result
    cdef MatchCounter counter
    cdef int index
    cdef size_t result_index
    cdef size_t binding_index
    cdef list catalogue_output = []
    cdef list pattern_output

    if comparison_budget <= 0:
        raise ValueError("comparison_budget must be positive")
    if candidate_root_index < 0:
        return (), 0, 0, False
    counter.comparisons = 0
    counter.lazy_swaps = 0
    counter.limit = comparison_budget
    counter.exceeded = False
    for record in patterns:
        pattern_rows = <tuple>record[0]
        variable_count = <int>record[1]
        if variable_count < 0:
            raise ValueError("variable_count must be non-negative")
        bindings.clear()
        for index in range(variable_count):
            bindings.push_back(-1)
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
                tuple(result[binding_index] for binding_index in range(result.size()))
            )
        catalogue_output.append(tuple(pattern_output))
    return tuple(catalogue_output), counter.comparisons, counter.lazy_swaps, False
