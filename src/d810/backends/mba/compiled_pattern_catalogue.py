"""Cached structural patterns for matching certified MBA rules to native views.

This layer intentionally sits between the catalogue certificate boundary and
Egglog.  It matches an immutable :class:`NativeMbaTermView` without converting
the candidate into a Hex-Rays AST or creating portable terms until a rule has
matched.  The resulting bindings are fixed: later extraction only materializes
the replacement from those bindings and never re-runs pattern matching.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.backends.mba.egglog_add_rule_compiler import (
    CompiledEgglogRule,
    _constraints_match_term,
    _materialize_symbolic_term,
    is_admitted_compiled_rule,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.core.typing import Any
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_PodPattern = tuple[tuple[tuple[int, ...], ...], tuple[str, ...]]


@dataclass(frozen=True)
class FixedBindings:
    """One verified, candidate-local binding environment.

    ``native`` retains the direct live-mop provenance for bindings that came
    from the candidate. ``terms`` contains its portable equivalent plus any
    derived constants established by declarative constraints.
    """

    native: Mapping[str, NativeMbaTermView]
    terms: Mapping[str, TypedBvTerm]
    width: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "native", MappingProxyType(dict(self.native)))
        object.__setattr__(self, "terms", MappingProxyType(dict(self.terms)))

    def materialize_replacement(self, rule: CompiledEgglogRule) -> TypedBvTerm:
        """Build a certified replacement from fixed bindings only."""

        return _materialize_symbolic_term(
            rule.replacement,
            dict(self.terms),
            width=self.width,
        )


@dataclass(frozen=True)
class NativePatternMatch:
    """A single admitted root match, in certified declaration order."""

    rule: CompiledEgglogRule
    bindings: FixedBindings
    catalogue_index: int

    @property
    def source_names(self) -> tuple[str, ...]:
        return (self.rule.source_name, *self.rule.aliases)


@dataclass(frozen=True)
class NativePatternMatchResult:
    """Bounded root-match result, including the actual comparison count."""

    matches: tuple[NativePatternMatch, ...]
    comparisons: int
    lazy_swaps: int
    comparison_budget_exceeded: bool = False
    candidate_term: TypedBvTerm | None = None
    # Diagnostic-only: semantic parity compares matches and resource facts,
    # while the performance receipt must retain the actual matching path.
    matcher_backend: str = field(default="python", compare=False)


@dataclass(frozen=True)
class _CompiledPattern:
    rule: CompiledEgglogRule
    catalogue_index: int
    pod_pattern: _PodPattern | None


class _ComparisonBudgetExceeded(RuntimeError):
    pass


@dataclass
class _MatchBudget:
    limit: int
    comparisons: int = 0
    lazy_swaps: int = 0

    def compare(self) -> None:
        self.comparisons += 1
        if self.comparisons > self.limit:
            raise _ComparisonBudgetExceeded


@dataclass(frozen=True)
class CompiledPatternCatalogue:
    """Immutable, declaration-ordered native matcher projection.

    This is deliberately not an EGraph cache. It contains only certified rule
    descriptors and can therefore be shared with the catalogue cache safely.
    """

    rules: tuple[_CompiledPattern, ...]
    root_width_buckets: Mapping[tuple[str, int], tuple[_CompiledPattern, ...]]

    @classmethod
    def from_rules(
        cls, rules: tuple[CompiledEgglogRule, ...]
    ) -> CompiledPatternCatalogue:
        # The POD encoder is intentionally loaded only while building the
        # immutable certified catalogue. Candidate matching must never walk a
        # symbolic rule tree again.
        from d810.backends.mba.native_pod_matcher import encode_symbolic_pattern

        compiled: list[_CompiledPattern] = []
        buckets: dict[tuple[str, int], list[_CompiledPattern]] = {}
        for index, rule in enumerate(rules):
            if not is_admitted_compiled_rule(rule):
                raise ValueError("compiled pattern catalogue requires admitted rules")
            pattern = _CompiledPattern(
                rule,
                index,
                encode_symbolic_pattern(rule.pattern),
            )
            compiled.append(pattern)
            operation = rule.pattern.operation
            if operation is None:
                continue
            for width in rule.proof_widths:
                buckets.setdefault((operation, width), []).append(pattern)
        return cls(
            tuple(compiled),
            MappingProxyType({key: tuple(value) for key, value in buckets.items()}),
        )

    def match_root(
        self, candidate: NativeMbaTermView, *, comparison_budget: int = 64
    ) -> NativePatternMatchResult:
        """Return bounded deterministic root applications without AST materialization.

        The callback-local POD layer owns numeric matching when the accelerated
        backend is available.  It falls back to ``_match_root_portable`` for
        unsupported packed shapes, keeping this implementation as the semantic
        oracle and avoiding a second rule catalogue.
        """

        from d810.backends.mba.native_pod_matcher import match_root_pod

        return match_root_pod(self, candidate, comparison_budget=comparison_budget)

    def _match_root_portable(
        self, candidate: NativeMbaTermView, *, comparison_budget: int = 64
    ) -> NativePatternMatchResult:
        """Portable native-view matcher used as the POD parity oracle."""

        if type(comparison_budget) is not int or comparison_budget <= 0:
            raise ValueError("comparison_budget must be a positive integer")
        if candidate.operation is None:
            return NativePatternMatchResult((), 0, 0)

        matches: list[NativePatternMatch] = []
        budget = _MatchBudget(comparison_budget)
        for compiled in self.root_width_buckets.get(
            (candidate.operation, candidate.width), ()
        ):
            seen_replacements: set[str] = set()
            try:
                for native_bindings in _iter_native_matches(
                    compiled.rule.pattern, candidate, {}, budget
                ):
                    term_bindings = {
                        name: value.to_typed_term()
                        for name, value in native_bindings.items()
                    }
                    if not _constraints_match_term(
                        compiled.rule, term_bindings, width=candidate.width
                    ):
                        continue
                    fixed = FixedBindings(
                        native=native_bindings,
                        terms=term_bindings,
                        width=candidate.width,
                    )
                    try:
                        replacement = fixed.materialize_replacement(compiled.rule)
                    except (TypeError, ValueError):
                        continue
                    replacement_fingerprint = term_fingerprint(replacement)
                    if replacement_fingerprint in seen_replacements:
                        continue
                    seen_replacements.add(replacement_fingerprint)
                    matches.append(
                        NativePatternMatch(
                            rule=compiled.rule,
                            bindings=fixed,
                            catalogue_index=compiled.catalogue_index,
                        )
                    )
            except _ComparisonBudgetExceeded:
                return NativePatternMatchResult(
                    (), budget.comparisons, budget.lazy_swaps, True
                )
        return NativePatternMatchResult(
            tuple(matches),
            budget.comparisons,
            budget.lazy_swaps,
            candidate_term=candidate.to_typed_term() if matches else None,
        )


def _iter_native_matches(
    expression: SymbolicExpressionProtocol,
    candidate: NativeMbaTermView,
    bindings: Mapping[str, NativeMbaTermView],
    budget: _MatchBudget,
) -> Iterator[dict[str, NativeMbaTermView]]:
    budget.compare()
    operation = expression.operation
    if operation is None:
        name = expression.name
        if not name:
            return
        if bool(getattr(expression, "is_pattern_constant", False)):
            if candidate.constant_value is None:
                return
        if expression.value is not None:
            if candidate.constant_value is None:
                return
            mask = (1 << candidate.width) - 1
            if candidate.constant_value != (int(expression.value) & mask):
                return
        existing = bindings.get(name)
        if existing is not None:
            if _view_key(existing) == _view_key(candidate):
                yield dict(bindings)
            return
        matched = dict(bindings)
        matched[name] = candidate
        yield matched
        return

    if candidate.operation != operation:
        return
    if operation in _AC_OPERATIONS:
        pattern_items = _flatten_symbolic_ac(expression, operation)
        candidate_items = _flatten_native_ac(candidate, operation)
        if len(pattern_items) != len(candidate_items):
            return

        def match_items(
            index: int,
            remaining: tuple[NativeMbaTermView, ...],
            current: Mapping[str, NativeMbaTermView],
        ) -> Iterator[dict[str, NativeMbaTermView]]:
            if index == len(pattern_items):
                if not remaining:
                    yield dict(current)
                return
            pattern_item = pattern_items[index]
            for candidate_index, candidate_item in enumerate(remaining):
                for updated in _iter_native_matches(
                    pattern_item, candidate_item, current, budget
                ):
                    yield from match_items(
                        index + 1,
                        remaining[:candidate_index] + remaining[candidate_index + 1 :],
                        updated,
                    )

        if len(pattern_items) == 2:
            candidate_orders = ((0, 1), (1, 0))
            for order_index, order in enumerate(candidate_orders):
                if order_index and _view_key(candidate_items[0]) == _view_key(
                    candidate_items[1]
                ):
                    continue
                if order_index:
                    budget.lazy_swaps += 1
                first = candidate_items[order[0]]
                second = candidate_items[order[1]]
                for first_bindings in _iter_native_matches(
                    pattern_items[0], first, bindings, budget
                ):
                    yield from _iter_native_matches(
                        pattern_items[1], second, first_bindings, budget
                    )
            return
        yield from match_items(0, candidate_items, dict(bindings))
        return

    if expression.left is None or not candidate.children:
        return
    for left_bindings in _iter_native_matches(
        expression.left, candidate.children[0], bindings, budget
    ):
        if operation in {"bnot", "neg"}:
            if expression.right is None and len(candidate.children) == 1:
                yield left_bindings
            continue
        if expression.right is None or len(candidate.children) != 2:
            continue
        yield from _iter_native_matches(
            expression.right, candidate.children[1], left_bindings, budget
        )


def _flatten_symbolic_ac(
    expression: SymbolicExpressionProtocol, operation: str
) -> tuple[SymbolicExpressionProtocol, ...]:
    if expression.operation != operation:
        return (expression,)
    assert expression.left is not None and expression.right is not None
    return _flatten_symbolic_ac(expression.left, operation) + _flatten_symbolic_ac(
        expression.right, operation
    )


def _flatten_native_ac(
    candidate: NativeMbaTermView, operation: str
) -> tuple[NativeMbaTermView, ...]:
    if candidate.operation != operation:
        return (candidate,)
    flattened: list[NativeMbaTermView] = []
    for child in candidate.children:
        flattened.extend(_flatten_native_ac(child, operation))
    return tuple(sorted(flattened, key=_view_key))


def _view_key(candidate: NativeMbaTermView) -> tuple[Any, ...]:
    if candidate.operation is None:
        if candidate.constant_value is not None:
            return ("constant", candidate.width, candidate.constant_value)
        return ("leaf", candidate.width, candidate.leaf_key)
    return (
        "node",
        candidate.operation,
        candidate.width,
        tuple(_view_key(child) for child in candidate.canonical_children()),
    )


__all__ = [
    "CompiledPatternCatalogue",
    "FixedBindings",
    "NativePatternMatch",
    "NativePatternMatchResult",
]
