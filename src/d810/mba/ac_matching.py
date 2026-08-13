"""Bounded, read-only structural matching for certified MBA DSL patterns.

This is deliberately not general AC unification: a symbolic leaf always binds
one concrete term, and homogeneous AC chains must have the same arity.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.typed_term import AC_OPERATIONS, TypedBvTerm, term_fingerprint


_SUPPORTED_WIDTHS = frozenset({8, 16, 32, 64})


class AcMatchStopReason(enum.StrEnum):
    MATCHED = "matched"
    MISS = "miss"
    CARDINALITY_MISMATCH = "cardinality_mismatch"
    AMBIGUOUS_GROUP_CAPTURE = "ambiguous_group_capture"
    COMPARISON_BUDGET = "comparison_budget"
    UNSUPPORTED_WIDTH = "unsupported_width"


@dataclass(frozen=True)
class AcMatchBindings:
    candidate_path_by_name: Mapping[str, tuple[int, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_path_by_name",
            MappingProxyType(dict(self.candidate_path_by_name)),
        )


@dataclass(frozen=True)
class AcMatchReport:
    bindings: AcMatchBindings | None
    comparisons: int
    commuted_branches: int
    flattened_nodes: int
    stop_reason: AcMatchStopReason


@dataclass
class _State:
    comparison_budget: int
    comparisons: int = 0
    commuted_branches: int = 0
    flattened_nodes: int = 0
    stopped: AcMatchStopReason | None = None

    def compare(self) -> bool:
        if self.comparisons >= self.comparison_budget:
            self.stopped = AcMatchStopReason.COMPARISON_BUDGET
            return False
        self.comparisons += 1
        return True


def _is_expression(value: object) -> bool:
    return isinstance(value, SymbolicExpressionProtocol)


def _pattern_leaf_name(pattern: SymbolicExpressionProtocol) -> str | None:
    name = getattr(pattern, "name", None)
    return name if type(name) is str and name else None


def _is_pattern_constant(pattern: SymbolicExpressionProtocol) -> bool:
    return bool(getattr(pattern, "is_pattern_constant", False))


def _bind(
    bindings: dict[str, tuple[str, tuple[int, ...]]],
    name: str | None,
    candidate: TypedBvTerm,
    path: tuple[int, ...],
) -> dict[str, tuple[str, tuple[int, ...]]] | None:
    if name is None:
        return bindings
    fingerprint = term_fingerprint(candidate)
    existing = bindings.get(name)
    if existing is not None:
        return bindings if existing[0] == fingerprint else None
    updated = dict(bindings)
    updated[name] = (fingerprint, path)
    return updated


def _flatten_pattern(
    pattern: SymbolicExpressionProtocol, operation: str
) -> list[SymbolicExpressionProtocol]:
    if pattern.operation != operation:
        return [pattern]
    left, right = pattern.left, pattern.right
    if left is None or right is None:
        return [pattern]
    result: list[SymbolicExpressionProtocol] = []
    for child in (left, right):
        if child.operation == operation:
            result.extend(_flatten_pattern(child, operation))
        else:
            result.append(child)
    return result


def _flatten_term(
    term: TypedBvTerm, path: tuple[int, ...], operation: str, state: _State
) -> list[tuple[TypedBvTerm, tuple[int, ...]]]:
    if term.operation != operation:
        return [(term, path)]
    result: list[tuple[TypedBvTerm, tuple[int, ...]]] = []
    for index, child in enumerate(term.children):
        if child.operation == operation and child.width == term.width:
            state.flattened_nodes += 1
            result.extend(_flatten_term(child, path + (index,), operation, state))
        else:
            result.append((child, path + (index,)))
    return result


def _is_flexible_leaf(pattern: SymbolicExpressionProtocol) -> bool:
    return pattern.operation is None and not _is_pattern_constant(pattern)


def _pattern_sort_key(pattern: SymbolicExpressionProtocol) -> tuple[object, ...]:
    # Rigid subtrees and constants constrain candidate search before wildcard vars.
    return (1 if _is_flexible_leaf(pattern) else 0, repr(pattern))


def _match_ac_operands(
    patterns: list[SymbolicExpressionProtocol],
    candidates: list[tuple[TypedBvTerm, tuple[int, ...]]],
    state: _State,
    bindings: dict[str, tuple[str, tuple[int, ...]]],
) -> dict[str, tuple[str, tuple[int, ...]]] | None:
    if not patterns:
        return bindings
    pattern = patterns[0]
    ordered_candidates = sorted(
        candidates, key=lambda item: (term_fingerprint(item[0]), item[1])
    )
    for candidate, path in ordered_candidates:
        matched = _match(pattern, candidate, path, state, bindings)
        if state.stopped is not None:
            return None
        if matched is None:
            continue
        remaining = list(candidates)
        remaining.remove((candidate, path))
        completed = _match_ac_operands(patterns[1:], remaining, state, matched)
        if completed is not None:
            return completed
        if state.stopped is not None:
            return None
    return None


def _match(
    pattern: SymbolicExpressionProtocol,
    candidate: TypedBvTerm,
    path: tuple[int, ...],
    state: _State,
    bindings: dict[str, tuple[str, tuple[int, ...]]],
) -> dict[str, tuple[str, tuple[int, ...]]] | None:
    if not state.compare():
        return None
    operation = pattern.operation
    if operation is None:
        if candidate.operation is not None:
            return None
        if _is_pattern_constant(pattern):
            if candidate.value is None:
                return None
            value = pattern.value
            if value is not None and candidate.value != (
                value & ((1 << candidate.width) - 1)
            ):
                return None
        return _bind(bindings, _pattern_leaf_name(pattern), candidate, path)
    if candidate.operation != operation or pattern.left is None:
        return None
    if operation in AC_OPERATIONS:
        if pattern.right is None or len(candidate.children) != 2:
            return None
        pattern_operands = _flatten_pattern(pattern, operation)
        candidate_operands = _flatten_term(candidate, path, operation, state)
        if len(pattern_operands) != len(candidate_operands):
            state.stopped = AcMatchStopReason.CARDINALITY_MISMATCH
            return None
        # Binary matching intentionally follows declared order before one swap.
        if len(pattern_operands) == 2:
            first = _match(
                pattern_operands[0],
                candidate_operands[0][0],
                candidate_operands[0][1],
                state,
                bindings,
            )
            if first is not None:
                second = _match(
                    pattern_operands[1],
                    candidate_operands[1][0],
                    candidate_operands[1][1],
                    state,
                    first,
                )
                if second is not None:
                    return second
            if state.stopped is not None:
                return None
            state.commuted_branches += 1
            first = _match(
                pattern_operands[0],
                candidate_operands[1][0],
                candidate_operands[1][1],
                state,
                bindings,
            )
            if first is None:
                return None
            return _match(
                pattern_operands[1],
                candidate_operands[0][0],
                candidate_operands[0][1],
                state,
                first,
            )
        return _match_ac_operands(
            sorted(pattern_operands, key=_pattern_sort_key),
            candidate_operands,
            state,
            bindings,
        )
    if pattern.right is None:
        if len(candidate.children) != 1:
            return None
        return _match(pattern.left, candidate.children[0], path + (0,), state, bindings)
    if len(candidate.children) != 2:
        return None
    left = _match(pattern.left, candidate.children[0], path + (0,), state, bindings)
    if left is None:
        return None
    return _match(pattern.right, candidate.children[1], path + (1,), state, left)


def match_ac_pattern(
    pattern: SymbolicExpressionProtocol,
    candidate: TypedBvTerm,
    *,
    comparison_budget: int,
) -> AcMatchReport:
    """Match one DSL pattern without mutation or implicit group capture."""

    if type(comparison_budget) is not int or comparison_budget < 0:
        raise ValueError("comparison_budget must be a non-negative integer")
    state = _State(comparison_budget)
    if not _is_expression(pattern) or candidate.width not in _SUPPORTED_WIDTHS:
        return AcMatchReport(None, 0, 0, 0, AcMatchStopReason.UNSUPPORTED_WIDTH)
    bindings = _match(pattern, candidate, (), state, {})
    reason = state.stopped
    if reason is None and bindings is not None:
        paths = {name: path for name, (_, path) in bindings.items()}
        return AcMatchReport(
            AcMatchBindings(paths),
            state.comparisons,
            state.commuted_branches,
            state.flattened_nodes,
            AcMatchStopReason.MATCHED,
        )
    return AcMatchReport(
        None,
        state.comparisons,
        state.commuted_branches,
        state.flattened_nodes,
        reason or AcMatchStopReason.MISS,
    )


__all__ = [
    "AcMatchBindings",
    "AcMatchReport",
    "AcMatchStopReason",
    "match_ac_pattern",
]
