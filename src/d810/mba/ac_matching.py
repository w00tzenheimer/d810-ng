"""Bounded, read-only structural matching for certified MBA DSL patterns.

This is deliberately not general AC unification: a symbolic leaf always binds
one concrete term, and homogeneous AC chains must have the same arity.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import TYPE_CHECKING
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.typed_term import (
    AC_OPERATIONS,
    TypedBvTerm,
    _term_sort_key,
    term_fingerprint,
)

if TYPE_CHECKING:
    from d810.mba.canonical_pattern import CanonicalPatternMatchReport


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
    saw_cardinality_mismatch: bool = False

    def compare(self) -> bool:
        if self.comparisons >= self.comparison_budget:
            self.stopped = AcMatchStopReason.COMPARISON_BUDGET
            return False
        self.comparisons += 1
        return True


@dataclass(frozen=True)
class _PatternAdapter:
    """Representation hooks shared by DSL and typed-template matching."""

    pattern_operation: Callable[[object], str | None]
    pattern_children: Callable[[object], tuple[object, ...]]
    pattern_placeholder: Callable[[object], tuple[str, str] | None]
    pattern_literal: Callable[[object], int | None]
    candidate_operation: Callable[[object], str | None]
    candidate_children: Callable[[object], tuple[object, ...]]
    candidate_value: Callable[[object], int | None]
    candidate_is_bindable: Callable[[object], bool]
    candidate_is_terminal: Callable[[object], bool]
    candidate_is_constant: Callable[[object], bool]
    candidate_fingerprint: Callable[[object], str]
    pattern_sort_key: Callable[[object], tuple[object, ...]]


def _flatten_pattern(
    pattern: object, operation: str, adapter: _PatternAdapter
) -> list[object]:
    if adapter.pattern_operation(pattern) != operation:
        return [pattern]
    children = adapter.pattern_children(pattern)
    if len(children) != 2:
        return [pattern]
    result: list[object] = []
    for child in children:
        if adapter.pattern_operation(child) == operation:
            result.extend(_flatten_pattern(child, operation, adapter))
        else:
            result.append(child)
    return result


def _flatten_candidate(
    candidate: object,
    path: tuple[int, ...],
    operation: str,
    state: _State,
    adapter: _PatternAdapter,
) -> list[tuple[object, tuple[int, ...]]]:
    if adapter.candidate_operation(candidate) != operation:
        return [(candidate, path)]
    result: list[tuple[object, tuple[int, ...]]] = []
    for index, child in enumerate(adapter.candidate_children(candidate)):
        if (
            adapter.candidate_operation(child) == operation
            and getattr(child, "width", None) == getattr(candidate, "width", None)
        ):
            state.flattened_nodes += 1
            result.extend(
                _flatten_candidate(child, path + (index,), operation, state, adapter)
            )
        else:
            result.append((child, path + (index,)))
    return result


def _candidate_matches_rigid_root(
    pattern: object, candidate: object, adapter: _PatternAdapter
) -> bool:
    placeholder = adapter.pattern_placeholder(pattern)
    if placeholder is not None:
        if placeholder[0] != "pattern_const":
            return True
        if not adapter.candidate_is_constant(candidate):
            return False
        value = adapter.pattern_literal(pattern)
        return value is None or adapter.candidate_value(candidate) == (
            value & ((1 << getattr(candidate, "width")) - 1)
        )
    operation = adapter.pattern_operation(pattern)
    if operation is None:
        if not adapter.candidate_is_terminal(candidate):
            return False
        value = adapter.pattern_literal(pattern)
        return value is None or adapter.candidate_value(candidate) == (
            value & ((1 << getattr(candidate, "width")) - 1)
        )
    return adapter.candidate_operation(candidate) == operation


def _iter_ac_operand_matches(
    patterns: list[object],
    candidates: list[tuple[object, tuple[int, ...]]],
    state: _State,
    bindings: dict[str, tuple[str, object, tuple[int, ...]]],
    adapter: _PatternAdapter,
    pattern_index: int = 0,
) -> Iterator[dict[str, tuple[str, object, tuple[int, ...]]]]:
    if not patterns:
        yield bindings
        return
    pattern = patterns[0]
    ordered_candidates = sorted(
        (
            item
            for item in candidates
            if _candidate_matches_rigid_root(pattern, item[0], adapter)
        ),
        key=lambda item: (adapter.candidate_fingerprint(item[0]), item[1]),
    )
    for candidate, path in ordered_candidates:
        if pattern_index > 0:
            state.commuted_branches += 1
        for matched in _iter_matches(
            pattern, candidate, path, state, bindings, adapter
        ):
            remaining = list(candidates)
            remaining.remove((candidate, path))
            yield from _iter_ac_operand_matches(
                patterns[1:],
                remaining,
                state,
                matched,
                adapter,
                pattern_index + 1,
            )
            if state.stopped is not None:
                return


def _iter_matches(
    pattern: object,
    candidate: object,
    path: tuple[int, ...],
    state: _State,
    bindings: dict[str, tuple[str, object, tuple[int, ...]]],
    adapter: _PatternAdapter,
) -> Iterator[dict[str, tuple[str, object, tuple[int, ...]]]]:
    if not state.compare():
        return
    placeholder = adapter.pattern_placeholder(pattern)
    if placeholder is not None:
        kind, name = placeholder
        if not adapter.candidate_is_bindable(candidate):
            return
        if kind == "pattern_const" and not adapter.candidate_is_constant(candidate):
            return
        value = adapter.pattern_literal(pattern)
        if kind == "pattern_const" and value is not None:
            if adapter.candidate_value(candidate) != (
                value & ((1 << getattr(candidate, "width")) - 1)
            ):
                return
        fingerprint = adapter.candidate_fingerprint(candidate)
        existing = bindings.get(name)
        if existing is not None:
            if existing[0] == fingerprint:
                yield dict(bindings)
            return
        updated = dict(bindings)
        updated[name] = (fingerprint, candidate, path)
        yield updated
        return
    operation = adapter.pattern_operation(pattern)
    if operation is None:
        if not adapter.candidate_is_terminal(candidate):
            return
        value = adapter.pattern_literal(pattern)
        if value is not None and adapter.candidate_value(candidate) != (
            value & ((1 << getattr(candidate, "width")) - 1)
        ):
            return
        yield dict(bindings)
        return
    if adapter.candidate_operation(candidate) != operation:
        return
    if operation in AC_OPERATIONS:
        pattern_items = _flatten_pattern(pattern, operation, adapter)
        candidate_items = _flatten_candidate(
            candidate, path, operation, state, adapter
        )
        if len(pattern_items) != len(candidate_items):
            state.saw_cardinality_mismatch = True
            return
        if len(pattern_items) == 2:
            for first in _iter_matches(
                pattern_items[0],
                candidate_items[0][0],
                candidate_items[0][1],
                state,
                bindings,
                adapter,
            ):
                yield from _iter_matches(
                    pattern_items[1],
                    candidate_items[1][0],
                    candidate_items[1][1],
                    state,
                    first,
                    adapter,
                )
            if state.stopped is not None:
                return
            state.commuted_branches += 1
            for first in _iter_matches(
                pattern_items[0],
                candidate_items[1][0],
                candidate_items[1][1],
                state,
                bindings,
                adapter,
            ):
                yield from _iter_matches(
                    pattern_items[1],
                    candidate_items[0][0],
                    candidate_items[0][1],
                    state,
                    first,
                    adapter,
                )
            return
        yield from _iter_ac_operand_matches(
            sorted(pattern_items, key=adapter.pattern_sort_key),
            candidate_items,
            state,
            bindings,
            adapter,
        )
        return
    pattern_children = adapter.pattern_children(pattern)
    candidate_children = adapter.candidate_children(candidate)
    if len(pattern_children) != len(candidate_children):
        return

    def match_children(
        index: int,
        current: dict[str, tuple[str, object, tuple[int, ...]]],
    ) -> Iterator[dict[str, tuple[str, object, tuple[int, ...]]]]:
        if index == len(pattern_children):
            yield current
            return
        for matched in _iter_matches(
            pattern_children[index],
            candidate_children[index],
            path + (index,),
            state,
            current,
            adapter,
        ):
            yield from match_children(index + 1, matched)
            if state.stopped is not None:
                return

    yield from match_children(0, dict(bindings))


def _legacy_adapter() -> _PatternAdapter:
    def pattern_operation(pattern: object) -> str | None:
        return getattr(pattern, "operation", None)

    def pattern_children(pattern: object) -> tuple[object, ...]:
        return tuple(
            child
            for child in (
                getattr(pattern, "left", None),
                getattr(pattern, "right", None),
            )
            if child is not None
        )

    def pattern_placeholder(pattern: object) -> tuple[str, str] | None:
        if pattern_operation(pattern) is not None:
            return None
        name = getattr(pattern, "name", None)
        if type(name) is not str or not name:
            return None
        kind = (
            "pattern_const"
            if bool(getattr(pattern, "is_pattern_constant", False))
            else "pattern_var"
        )
        return kind, name

    def pattern_literal(pattern: object) -> int | None:
        value = getattr(pattern, "value", None)
        return value if type(value) is int else None

    def candidate_operation(candidate: object) -> str | None:
        return getattr(candidate, "operation", None)

    def candidate_children(candidate: object) -> tuple[object, ...]:
        return tuple(getattr(candidate, "children", ()))

    def candidate_value(candidate: object) -> int | None:
        value = getattr(candidate, "value", None)
        return value if type(value) is int else None

    return _PatternAdapter(
        pattern_operation,
        pattern_children,
        pattern_placeholder,
        pattern_literal,
        candidate_operation,
        candidate_children,
        candidate_value,
        lambda candidate: candidate_operation(candidate) is None,
        lambda candidate: candidate_operation(candidate) is None,
        lambda candidate: candidate_operation(candidate) is None
        and candidate_value(candidate) is not None,
        term_fingerprint,
        lambda pattern: (
            1 if (placeholder := pattern_placeholder(pattern)) is not None
            and placeholder[0] == "pattern_var"
            else 0,
            repr(pattern),
        ),
    )


def _typed_adapter() -> _PatternAdapter:
    def operation(term: object) -> str | None:
        return getattr(term, "operation", None)

    def children(term: object) -> tuple[object, ...]:
        return tuple(getattr(term, "children", ()))

    def placeholder(term: object) -> tuple[str, str] | None:
        if operation(term) is not None:
            return None
        key = getattr(term, "leaf_key", None)
        if (
            type(key) is tuple
            and len(key) == 2
            and key[0] in {"pattern_var", "pattern_const"}
            and type(key[1]) is str
            and key[1]
        ):
            return str(key[0]), key[1]
        return None

    def literal(term: object) -> int | None:
        value = getattr(term, "value", None)
        return value if type(value) is int else None

    return _PatternAdapter(
        operation,
        children,
        placeholder,
        literal,
        operation,
        children,
        literal,
        lambda _term: True,
        lambda term: operation(term) is None,
        lambda term: operation(term) is None and literal(term) is not None,
        term_fingerprint,
        lambda term: (
            1
            if (placeholder_value := placeholder(term)) is not None
            and placeholder_value[0] == "pattern_var"
            else 0,
            _term_sort_key(term),
        ),
    )


def _compatibility_bindings(
    compiled_pattern: object,
    candidate: TypedBvTerm,
    bindings: object,
):
    """Add uniquely located named fixed constants for legacy report readers."""

    from d810.mba.canonical_pattern import CanonicalFixedBindings

    terms = dict(bindings.terms)
    paths = dict(bindings.candidate_paths)
    fixed_constants = getattr(compiled_pattern, "fixed_constant_values", {})
    occurrences: dict[str, list[tuple[TypedBvTerm, tuple[int, ...]]]] = {
        name: [] for name in fixed_constants
    }

    def walk(term: TypedBvTerm, path: tuple[int, ...]) -> None:
        if term.operation is None:
            if term.value is not None:
                for name, expected in fixed_constants.items():
                    if term.value == (expected & ((1 << term.width) - 1)):
                        occurrences[name].append((term, path))
            return
        for index, child in enumerate(term.children):
            walk(child, path + (index,))

    walk(candidate, ())
    for name, matches in occurrences.items():
        if name in terms or len(matches) != 1:
            continue
        terms[name], paths[name] = matches[0]
    return CanonicalFixedBindings(terms, paths, candidate.width)


def match_ac_pattern(
    pattern: SymbolicExpressionProtocol,
    candidate: TypedBvTerm,
    *,
    comparison_budget: int,
) -> AcMatchReport:
    """Match one DSL pattern without mutation or implicit group capture."""

    if type(comparison_budget) is not int or comparison_budget <= 0:
        raise ValueError("comparison_budget must be a positive integer")
    state = _State(comparison_budget)
    if not isinstance(pattern, SymbolicExpressionProtocol) or candidate.width not in _SUPPORTED_WIDTHS:
        return AcMatchReport(None, 0, 0, 0, AcMatchStopReason.UNSUPPORTED_WIDTH)
    bindings = next(
        _iter_matches(pattern, candidate, (), state, {}, _legacy_adapter()), None
    )
    reason = state.stopped
    if reason is None and bindings is not None:
        paths = {name: value[2] for name, value in bindings.items()}
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
        reason
        or (
            AcMatchStopReason.CARDINALITY_MISMATCH
            if state.saw_cardinality_mismatch
            else AcMatchStopReason.MISS
        ),
    )


def match_canonical_term_pattern(
    compiled_pattern: object,
    candidate: TypedBvTerm,
    *,
    comparison_budget: int,
) -> "CanonicalPatternMatchReport":
    """Match one frozen canonical template through the shared AC core."""

    from d810.mba.canonical_pattern import (
        CanonicalFixedBindings,
        CanonicalPatternMatch,
        CanonicalPatternMatchReport,
    )

    if type(comparison_budget) is not int or comparison_budget <= 0:
        raise ValueError("comparison_budget must be a positive integer")
    if not isinstance(candidate, TypedBvTerm):
        raise TypeError("candidate must be a TypedBvTerm")
    width = getattr(compiled_pattern, "width", None)
    if candidate.width != width:
        return CanonicalPatternMatchReport(
            (), 0, 0, 0, AcMatchStopReason.UNSUPPORTED_WIDTH
        )
    state = _State(comparison_budget)
    pattern_term = getattr(compiled_pattern, "pattern_term", None)
    raw_matches = _iter_matches(
        pattern_term,
        candidate,
        (),
        state,
        {},
        _typed_adapter(),
    )
    matches: list[CanonicalPatternMatch] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for raw in raw_matches:
        if state.stopped is not None:
            break
        terms = {name: value[1] for name, value in raw.items()}
        paths = {name: value[2] for name, value in raw.items()}
        identity = tuple(
            sorted((name, term_fingerprint(term)) for name, term in terms.items())
        )
        if identity in seen:
            continue
        seen.add(identity)
        matches.append(
            CanonicalPatternMatch(
                compiled_pattern=compiled_pattern,
                bindings=CanonicalFixedBindings(terms, paths, width),
            )
        )
    if state.stopped is not None:
        reason = state.stopped
    elif matches:
        reason = AcMatchStopReason.MATCHED
    elif state.saw_cardinality_mismatch:
        reason = AcMatchStopReason.CARDINALITY_MISMATCH
    else:
        reason = AcMatchStopReason.MISS
    compatibility_bindings = None
    if matches:
        compatibility_bindings = _compatibility_bindings(
            compiled_pattern,
            candidate,
            matches[0].bindings,
        )
    return CanonicalPatternMatchReport(
        tuple(matches),
        state.comparisons,
        state.commuted_branches,
        state.flattened_nodes,
        reason,
        compatibility_bindings,
    )


__all__ = [
    "AcMatchBindings",
    "AcMatchReport",
    "AcMatchStopReason",
    "match_canonical_term_pattern",
    "match_ac_pattern",
]
