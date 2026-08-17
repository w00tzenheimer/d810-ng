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
    require_admitted_compiled_rules,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.core.typing import Any
from d810.mba.canonical_pattern import (
    CanonicalCompiledPattern,
    CanonicalFixedBindings,
    CanonicalPatternMatchReport,
    CanonicalPatternMalformed,
    CanonicalPatternUnsupported,
    compile_canonical_pattern,
    evaluate_frozen_constraints,
    match_canonical_term_pattern,
)
from d810.mba.ac_matching import AcMatchStopReason
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_PodPattern = tuple[tuple[tuple[int, ...], ...], tuple[str, ...]]


class CanonicalPatternComparisonBudgetExceeded(RuntimeError):
    """Canonical matching exhausted its comparison budget.

    Earlier matches may still be present for diagnostic/shadow telemetry, but
    saturation must never consume them as executable rewrite applications.
    """


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
    structural_node_count: int
    canonical_by_width: Mapping[int, CanonicalCompiledPattern]


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
    pod_records_by_root_width: Mapping[
        tuple[str, int], tuple[tuple[tuple[tuple[int, ...], ...], int], ...] | None
    ]
    canonical_root_width_buckets: Mapping[
        tuple[str, int], tuple[_CompiledPattern, ...]
    ]

    @classmethod
    def from_rules(
        cls, rules: tuple[CompiledEgglogRule, ...]
    ) -> CompiledPatternCatalogue:
        # The POD encoder is intentionally loaded only while building the
        # immutable certified catalogue. Candidate matching must never walk a
        # symbolic rule tree again.
        from d810.backends.mba.native_pod_matcher import encode_symbolic_pattern

        admitted_rules = require_admitted_compiled_rules(rules)
        compiled: list[_CompiledPattern] = []
        buckets: dict[tuple[str, int], list[_CompiledPattern]] = {}
        canonical_buckets: dict[tuple[str, int], list[_CompiledPattern]] = {}
        for index, rule in enumerate(admitted_rules):
            canonical_by_width: dict[int, CanonicalCompiledPattern] = {}
            for width in rule.proof_widths:
                try:
                    canonical_by_width[width] = compile_canonical_pattern(
                        rule,
                        width=width,
                        declaration_index=index,
                    )
                except (CanonicalPatternMalformed, CanonicalPatternUnsupported):
                    # Unsupported DSL semantics remain available to the POD
                    # matcher and therefore stay legacy-eligible.
                    continue
            pattern = _CompiledPattern(
                rule,
                index,
                encode_symbolic_pattern(rule.pattern),
                _symbolic_node_count(rule.pattern),
                MappingProxyType(canonical_by_width),
            )
            compiled.append(pattern)
            operation = rule.pattern.operation
            if operation is None:
                continue
            for width in rule.proof_widths:
                buckets.setdefault((operation, width), []).append(pattern)
            for width, canonical in canonical_by_width.items():
                canonical_buckets.setdefault(
                    (canonical.pattern_term.operation or "", width), []
                ).append(pattern)
        frozen_buckets = {key: tuple(value) for key, value in buckets.items()}
        frozen_canonical_buckets = {
            key: tuple(value) for key, value in canonical_buckets.items()
        }
        pod_records = {
            key: (
                None
                if any(pattern.pod_pattern is None for pattern in patterns)
                else tuple(
                    (pattern.pod_pattern[0], len(pattern.pod_pattern[1]))
                    for pattern in patterns
                    if pattern.pod_pattern is not None
                )
            )
            for key, patterns in frozen_buckets.items()
        }
        return cls(
            tuple(compiled),
            MappingProxyType(frozen_buckets),
            MappingProxyType(pod_records),
            MappingProxyType(frozen_canonical_buckets),
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

    def match_canonical_root(
        self,
        candidate: TypedBvTerm,
        *,
        comparison_budget: int = 64,
    ) -> CanonicalPatternMatchReport:
        """Match one candidate against the precompiled canonical root bucket.

        The candidate is lowered through the shared canonicalizer exactly once
        for this callback.  Rule proof compilation and catalogue inventory
        construction happen only in :meth:`from_rules`; this method consumes
        immutable width-specific templates and performs no backend work.
        """

        if type(comparison_budget) is not int or comparison_budget <= 0:
            raise ValueError("comparison_budget must be a positive integer")
        if not isinstance(candidate, TypedBvTerm):
            raise TypeError("candidate must be a TypedBvTerm")
        canonical_candidate = canonicalize_mba_term(candidate).canonical_term
        operation = canonical_candidate.operation
        if operation is None:
            return CanonicalPatternMatchReport((), 0, 0, 0, AcMatchStopReason.MISS)
        bucket = self.canonical_root_width_buckets.get(
            (operation, canonical_candidate.width), ()
        )
        if not bucket:
            return CanonicalPatternMatchReport((), 0, 0, 0, AcMatchStopReason.MISS)

        matches = []
        comparisons = 0
        commuted_branches = 0
        flattened_nodes = 0
        saw_cardinality = False
        stop_reason = AcMatchStopReason.MISS
        for compiled in bucket:
            remaining = comparison_budget - comparisons
            if remaining <= 0:
                stop_reason = AcMatchStopReason.COMPARISON_BUDGET
                break
            pattern = compiled.canonical_by_width.get(canonical_candidate.width)
            if pattern is None:
                continue
            report = match_canonical_term_pattern(
                pattern,
                canonical_candidate,
                comparison_budget=remaining,
            )
            comparisons += report.comparisons
            commuted_branches += report.commuted_branches
            flattened_nodes += report.flattened_nodes
            if report.stop_reason is AcMatchStopReason.COMPARISON_BUDGET:
                stop_reason = report.stop_reason
                break
            if report.stop_reason is AcMatchStopReason.CARDINALITY_MISMATCH:
                saw_cardinality = True
            for match in report.matches:
                terms = dict(match.bindings.terms)
                if not evaluate_frozen_constraints(
                    pattern.constraints,
                    terms,
                    width=canonical_candidate.width,
                ):
                    continue
                matches.append(
                    type(match)(
                        compiled_pattern=match.compiled_pattern,
                        bindings=CanonicalFixedBindings(
                            terms,
                            match.bindings.candidate_paths,
                            canonical_candidate.width,
                        ),
                    )
                )
        if matches and stop_reason is not AcMatchStopReason.COMPARISON_BUDGET:
            reason = AcMatchStopReason.MATCHED
        elif matches:
            reason = AcMatchStopReason.COMPARISON_BUDGET
        elif stop_reason is AcMatchStopReason.COMPARISON_BUDGET:
            reason = stop_reason
        elif saw_cardinality:
            reason = AcMatchStopReason.CARDINALITY_MISMATCH
        else:
            reason = AcMatchStopReason.MISS
        return CanonicalPatternMatchReport(
            tuple(matches),
            comparisons,
            commuted_branches,
            flattened_nodes,
            reason,
        )

    def canonical_applications(
        self,
        candidate: TypedBvTerm,
        *,
        comparison_budget: int = 256,
    ) -> tuple[tuple[CompiledEgglogRule, TypedBvTerm, int], ...]:
        """Return deduplicated replacements from frozen canonical templates.

        This is the only saturation-facing rule application projection.  It
        consumes the canonical matcher report and materializes each replacement
        from its fixed bindings; no symbolic rule walk or AC rewrite is needed
        after the catalogue has been frozen.
        """

        report = self.match_canonical_root(
            candidate,
            comparison_budget=comparison_budget,
        )
        if report.stop_reason is AcMatchStopReason.COMPARISON_BUDGET:
            raise CanonicalPatternComparisonBudgetExceeded(
                "canonical matcher comparison budget exhausted"
            )
        applications: list[tuple[CompiledEgglogRule, TypedBvTerm, int]] = []
        seen: set[tuple[int, str]] = set()
        for match in report.matches:
            compiled = match.compiled_pattern
            replacement = canonicalize_mba_term(
                compiled.materialize_replacement(match.bindings)
            ).canonical_term
            key = (id(compiled.rule), term_fingerprint(replacement))
            if key in seen:
                continue
            seen.add(key)
            applications.append(
                (compiled.rule, replacement, compiled.declaration_index)
            )
        return tuple(applications)

    def feasible_root_patterns(
        self, candidate: NativeMbaTermView
    ) -> tuple[_CompiledPattern, ...]:
        """Return the common zero-cost structural feasibility subset.

        Each pattern operator must match an operator in the candidate.  A
        pattern therefore cannot fit into a candidate with fewer structural
        nodes.  The filter deliberately lives above both matchers so it never
        changes the shared comparison-budget semantics between Python and
        Cython.
        """

        if candidate.operation is None:
            return ()
        bucket = self.root_width_buckets.get((candidate.operation, candidate.width), ())
        candidate_node_count = candidate.term_cost[1]
        if all(
            pattern.structural_node_count <= candidate_node_count for pattern in bucket
        ):
            return bucket
        return tuple(
            pattern
            for pattern in bucket
            if pattern.structural_node_count <= candidate_node_count
        )

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
        for compiled in self.feasible_root_patterns(candidate):
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


def _symbolic_node_count(expression: SymbolicExpressionProtocol) -> int:
    """Return the immutable structural cardinality of one rule pattern."""

    if expression.operation is None:
        return 1
    assert expression.left is not None
    return (
        1
        + _symbolic_node_count(expression.left)
        + (0 if expression.right is None else _symbolic_node_count(expression.right))
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
    "CanonicalPatternComparisonBudgetExceeded",
    "CompiledPatternCatalogue",
    "FixedBindings",
    "NativePatternMatch",
    "NativePatternMatchResult",
]
