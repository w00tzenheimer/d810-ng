"""Pure typed-term contracts for bounded Egglog MBA extraction.

The module deliberately imports no IDA or Egglog runtime at module load time.
Native AST types are resolved only when a native lowering function is called,
so budget, receipt, and term contracts remain usable in portable unit tests.
"""

from __future__ import annotations

import enum
import importlib
import time
import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial

from d810.core.typing import Any
from d810.backends.mba.egglog_statistics import (
    read_egraph_statistics,
    read_rule_firing_count,
)
from d810.backends.mba.hexrays_island import (
    HexRaysIslandLowering,
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.mba.island_profile import profile_typed_term
from d810.mba.native_corpus_capture import native_profile_metadata
from d810.mba import typed_term as _typed_term
from d810.mba.typed_term import (
    TypedBvTerm,
    _leaf_key_fingerprint,
    canonicalize_ac_term,
    term_cost as _term_cost,
    term_fingerprint,
)


# One-release compatibility re-export. Keep this identity assertion close to
# the import so plugin hot reloads cannot silently split the term type.
assert TypedBvTerm is _typed_term.TypedBvTerm
term_cost = _term_cost


# Public capability contract.  This spike explores rewrites of the candidate
# root only; it does not recursively close over eligible nested subterms.
EGGLOG_EXPLORATION_SCOPE = "candidate-root-only"

# Egglog 13.2.0 exposes no interruptible or resource-capped run call. A reviewed
# single-rewrite run took 46 ms, so the live 3 ms default must never enter the
# Rust executor. Larger explicitly configured budgets reserve that observed
# baseline plus one millisecond per deterministic ground-graph work unit. This
# is deliberately conservative admission control, not a hard wall interrupt.
_MINIMUM_EGGLOG_RUN_BUDGET_MS = 50
_RUN_WORK_UNIT_BUDGET_MS = 1


try:
    _EGGLOG_MODULE = importlib.import_module("egglog")
except (ImportError, ModuleNotFoundError):
    _EGGLOG_MODULE = None
egglog = _EGGLOG_MODULE


if _EGGLOG_MODULE is not None:

    class BvExpr(egglog.Expr):
        """Width-carrying Egglog term for the bounded MBA adapter only."""

        @classmethod
        def leaf(
            cls,
            width: egglog.i64Like,
            key: egglog.StringLike,
        ) -> BvExpr: ...

        @classmethod
        def constant(
            cls,
            width: egglog.i64Like,
            value: egglog.i64Like,
        ) -> BvExpr: ...

        @classmethod
        def unary(
            cls,
            operation: egglog.StringLike,
            width: egglog.i64Like,
            operand: BvExpr,
        ) -> BvExpr: ...

        @classmethod
        def binary(
            cls,
            operation: egglog.StringLike,
            width: egglog.i64Like,
            left: BvExpr,
            right: BvExpr,
        ) -> BvExpr: ...

    class DegreeExpr(egglog.Expr):
        """Reachability wrapper whose integer tag is an exact rule degree."""

        @classmethod
        def at(
            cls,
            degree: egglog.i64Like,
            expression: BvExpr,
        ) -> DegreeExpr: ...

else:

    class BvExpr:  # pragma: no cover - exercised only without the optional extra.
        pass

    class DegreeExpr:  # pragma: no cover - exercised only without the optional extra.
        pass


def _load_egglog_module() -> Any | None:
    return _EGGLOG_MODULE


_monotonic = time.monotonic


class ExtractionSkipReason(enum.StrEnum):
    """Stable wire values for successful no-op extraction outcomes."""

    EGGLOG_UNAVAILABLE = "egglog_unavailable"
    UNSUPPORTED_WIDTH_SEMANTICS = "unsupported_width_semantics"
    NON_MBA_CANDIDATE = "non_mba_candidate"
    CANDIDATE_BUDGET = "candidate_budget"
    TIME_BUDGET = "time_budget"
    ECLASS_BUDGET = "eclass_budget"
    ENODE_BUDGET = "enode_budget"
    RULE_FIRING_BUDGET = "rule_firing_budget"
    NO_DEGREE_ELIGIBLE_IMPROVEMENT = "no_degree_eligible_improvement"
    LOWERING_FAILED = "lowering_failed"
    NATIVE_Z3_FAILED = "native_z3_failed"
    INTERNAL_ERROR = "internal_error"
    UNAVAILABLE_EGRAPH_STATISTICS = "unavailable_egraph_statistics"


def _positive_integer(name: str, value: object) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class EgglogExtractionBudget:
    """Admission and acceptance limits for one fresh candidate session.

    ``time_budget_ms`` values below 50, including the live 3 ms default, are a
    safe telemetry/no-op mode: they prevent Egglog registration and execution.
    Larger values admit structurally capped work but cannot hard-interrupt an
    individual Egglog 13.2.0 Rust call.
    """

    max_leaves: int = 2
    max_operator_nodes: int = 10
    max_degree: int = 1
    saturation_rounds: int = 2
    max_eclasses: int = 64
    max_enodes: int = 128
    max_rule_firings: int = 32
    time_budget_ms: int = 3
    require_proof: bool = True

    def __post_init__(self) -> None:
        for name in (
            "max_leaves",
            "max_operator_nodes",
            "saturation_rounds",
            "max_eclasses",
            "max_enodes",
            "max_rule_firings",
            "time_budget_ms",
        ):
            _positive_integer(name, getattr(self, name))
        if type(self.max_degree) is not int or self.max_degree not in (1, 2):
            raise ValueError("max_degree must be exactly 1 or 2")
        if not 1 <= self.saturation_rounds <= 6:
            raise ValueError("saturation_rounds must be an integer from 1 to 6")
        if self.require_proof is not True:
            raise ValueError("require_proof must remain true")


@dataclass(frozen=True)
class EgglogExtractionReceipt:
    """Immutable telemetry for either an extraction or a fail-closed skip."""

    input_cost: tuple[int, int] | None = None
    extracted_cost: tuple[int, int] | None = None
    degree: int | None = None
    eclass_count: int | None = None
    enode_count: int | None = None
    rule_firings: int = 0
    elapsed_ms: float = 0.0
    selected_family: str | None = None
    selected_source: str | None = None
    selected_aliases: tuple[str, ...] = ()
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    island_class: str | None = None
    island_fingerprint: str | None = None
    operator_count: int | None = None
    distinct_leaf_count: int | None = None
    nonlinear_product_count: int | None = None
    blockers: tuple[str, ...] = ()
    native_profile: Mapping[str, object] | None = None
    skip_reason: ExtractionSkipReason | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "selected_aliases", tuple(self.selected_aliases))
        object.__setattr__(self, "blockers", tuple(sorted(map(str, self.blockers))))
        object.__setattr__(
            self,
            "derivation_trace",
            tuple(
                (str(family), str(source_name), tuple(aliases))
                for family, source_name, aliases in self.derivation_trace
            ),
        )
        if self.input_cost is not None:
            object.__setattr__(self, "input_cost", tuple(self.input_cost))
        if self.extracted_cost is not None:
            object.__setattr__(self, "extracted_cost", tuple(self.extracted_cost))


@dataclass(frozen=True)
class EgglogExtractionResult:
    """One immutable candidate extraction outcome and its selected provenance."""

    replacement_ast: Any | None
    receipt: EgglogExtractionReceipt
    selected_provenance: tuple[str, str, tuple[str, ...]] | None = None
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "derivation_trace",
            tuple(
                (str(family), str(source_name), tuple(aliases))
                for family, source_name, aliases in self.derivation_trace
            ),
        )
        if self.selected_provenance is None:
            return
        family, source_name, aliases = self.selected_provenance
        object.__setattr__(
            self,
            "selected_provenance",
            (str(family), str(source_name), tuple(aliases)),
        )


def lower_native_ast_to_term(
    ast: Any,
    *,
    destination_size: int,
) -> TypedBvTerm | None:
    """Deprecated compatibility facade delegating to the native adapter."""

    return lower_hexrays_island(ast, destination_size=destination_size).term


def lower_term_to_native_ast(
    term: TypedBvTerm,
    *,
    leafs: Mapping[tuple[object, ...], Any],
    destination_size: int,
) -> Any | None:
    """Deprecated compatibility facade delegating to the native adapter."""

    lowering = HexRaysIslandLowering(
        term=term,
        profile=profile_typed_term(term),
        leafs=leafs,
        native_nodes_by_path={},
    )
    return rebuild_hexrays_island(
        term,
        lowering=lowering,
        destination_size=destination_size,
    )


def _term_leafs(term: TypedBvTerm) -> frozenset[tuple[object, ...]]:
    if term.operation is None:
        return frozenset() if term.leaf_key is None else frozenset((term.leaf_key,))
    return frozenset().union(*(_term_leafs(child) for child in term.children))


def _leaf_key_string(leaf_key: tuple[object, ...]) -> str:
    return json.dumps(
        _leaf_key_fingerprint(leaf_key),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _egglog_integer(value: int, width: int) -> int:
    masked = value & ((1 << width) - 1)
    if masked >= (1 << 63):
        masked -= 1 << 64
    return masked


def _term_to_egglog(term: TypedBvTerm) -> Any:
    if term.operation is None and term.value is not None:
        return BvExpr.constant(term.width, _egglog_integer(term.value, term.width))
    if term.operation is None:
        assert term.leaf_key is not None
        return BvExpr.leaf(term.width, _leaf_key_string(term.leaf_key))
    children = tuple(_term_to_egglog(child) for child in term.children)
    if len(children) == 1:
        return BvExpr.unary(term.operation, term.width, children[0])
    return BvExpr.binary(
        term.operation,
        term.width,
        children[0],
        children[1],
    )


def _elapsed_ms(started: float) -> float:
    return max(0.0, (_monotonic() - started) * 1000.0)


def _egglog_term_work_units(term: TypedBvTerm) -> int:
    """Conservatively count constructor and literal nodes for one expression."""

    if term.operation is None:
        return 3
    return 1 + sum(_egglog_term_work_units(child) for child in term.children)


def _degree_expression_work_units(term: TypedBvTerm) -> int:
    return 2 + _egglog_term_work_units(term)


def _degree_expression_work_unit_keys(
    degree: int, term: TypedBvTerm
) -> frozenset[tuple[object, ...]]:
    """Identify shared registered structure once, as Egglog's graph does."""

    keys: set[tuple[object, ...]] = {
        ("degree", degree, "constructor"),
        ("degree", degree, "literal"),
    }

    def visit(node: TypedBvTerm) -> None:
        keys.add(("term", degree, node))
        if node.operation is None:
            keys.add(("term-width", degree, node.width))
            keys.add(("term-literal", degree, node.value, node.leaf_key))
        for child in node.children:
            visit(child)

    visit(term)
    return frozenset(keys)


def _pre_run_time_guard(
    *,
    started: float,
    budget: EgglogExtractionBudget,
    work_units: int,
) -> tuple[bool, float]:
    """Admit a bounded run workload only while deterministic headroom remains."""

    elapsed = _elapsed_ms(started)
    remaining_ms = max(0.0, budget.time_budget_ms - elapsed)
    required_ms = _MINIMUM_EGGLOG_RUN_BUDGET_MS + work_units * _RUN_WORK_UNIT_BUDGET_MS
    return (required_ms <= remaining_ms, elapsed)


def _extraction_result(
    *,
    started: float,
    input_cost: tuple[int, int] | None,
    extracted_cost: tuple[int, int] | None = None,
    degree: int | None = None,
    eclass_count: int | None = None,
    enode_count: int | None = None,
    rule_firings: int = 0,
    provenance: tuple[str, str, tuple[str, ...]] | None = None,
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
    replacement_ast: Any | None = None,
    skip_reason: ExtractionSkipReason | None = None,
    elapsed_ms: float | None = None,
    lowering: HexRaysIslandLowering | None = None,
) -> EgglogExtractionResult:
    elapsed = _elapsed_ms(started) if elapsed_ms is None else elapsed_ms
    family = provenance[0] if provenance is not None else None
    source_name = provenance[1] if provenance is not None else None
    aliases = provenance[2] if provenance is not None else ()
    profile = None if lowering is None else lowering.profile
    return EgglogExtractionResult(
        replacement_ast=replacement_ast,
        receipt=EgglogExtractionReceipt(
            input_cost=input_cost,
            extracted_cost=extracted_cost,
            degree=degree,
            eclass_count=eclass_count,
            enode_count=enode_count,
            rule_firings=rule_firings,
            elapsed_ms=elapsed,
            selected_family=family,
            selected_source=source_name,
            selected_aliases=aliases,
            derivation_trace=derivation_trace,
            island_class=None if profile is None else profile.island_class.value,
            island_fingerprint=None if profile is None else profile.fingerprint,
            operator_count=None if profile is None else profile.operator_count,
            distinct_leaf_count=None
            if profile is None
            else profile.distinct_leaf_count,
            nonlinear_product_count=(
                None if profile is None else profile.nonlinear_product_count
            ),
            blockers=()
            if profile is None
            else tuple(blocker.value for blocker in profile.blockers),
            native_profile=(
                None if profile is None else native_profile_metadata(profile)
            ),
            skip_reason=skip_reason,
        ),
        selected_provenance=provenance,
        derivation_trace=derivation_trace,
    )


_build_extraction_result = _extraction_result


def extraction_receipt_for_lowering(
    lowering: HexRaysIslandLowering,
    skip_reason: ExtractionSkipReason,
) -> EgglogExtractionReceipt:
    """Return a profile-bearing no-op receipt for a known native candidate."""

    profile = lowering.profile
    return EgglogExtractionReceipt(
        island_class=profile.island_class.value,
        island_fingerprint=profile.fingerprint,
        operator_count=profile.operator_count,
        distinct_leaf_count=profile.distinct_leaf_count,
        nonlinear_product_count=profile.nonlinear_product_count,
        blockers=tuple(blocker.value for blocker in profile.blockers),
        native_profile=native_profile_metadata(profile),
        skip_reason=skip_reason,
    )


@dataclass(frozen=True)
class _ReachableCandidate:
    degree: int
    term: TypedBvTerm
    family: str
    source_name: str
    aliases: tuple[str, ...]
    expression: Any
    rule_decl: Any
    catalogue_index: int
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...] = ()

    @property
    def provenance(self) -> tuple[str, str, tuple[str, ...]]:
        return (self.family, self.source_name, self.aliases)


def _extraction_selection_key(
    candidate: _ReachableCandidate,
    candidate_cost: tuple[int, int],
) -> tuple[int, int, int, int]:
    """Rank equal candidates by their checked-in catalogue declaration order."""

    return (*candidate_cost, candidate.degree, candidate.catalogue_index)


def extract_bounded_candidate(
    candidate_ast: Any,
    rules: Any,
    budget: EgglogExtractionBudget,
    destination_size: int,
) -> EgglogExtractionResult:
    """Extract one strictly cheaper candidate through exact catalogue layers.

    One fresh e-graph is created only after an invocation passes host-side
    candidate and time admission. Exploration is candidate-root-only;
    eligible nested subterms are not traversed or claimed. Host-side grounding
    evaluates only the already-admitted compiler constraints.

    Egglog 13.2.0 cannot interrupt an individual Rust run. The time field is
    therefore an acceptance deadline plus a strict pre-run workload guard, not
    a hard wall-clock interrupt. Frontier construction is cooperative, all
    graph/firing caps are enforced before registration, and only one bounded
    schedule round is submitted at a time.
    """

    try:
        started = _monotonic()
    except Exception:
        started = 0.0
    input_cost: tuple[int, int] | None = None
    lowering = lower_hexrays_island(
        candidate_ast,
        destination_size=destination_size,
    )
    _extraction_result = partial(_build_extraction_result, lowering=lowering)

    try:
        term = lowering.term
        if term is None:
            return _extraction_result(
                started=started,
                input_cost=None,
                skip_reason=ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS,
            )
        input_cost = _term_cost(term)
        if input_cost[0] > budget.max_operator_nodes:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.CANDIDATE_BUDGET,
            )
        if len(_term_leafs(term)) > budget.max_leaves:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.CANDIDATE_BUDGET,
            )
        if budget.time_budget_ms < _MINIMUM_EGGLOG_RUN_BUDGET_MS:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
            )
        elapsed = _elapsed_ms(started)
        if elapsed > budget.time_budget_ms:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
                elapsed_ms=elapsed,
            )

        egglog = _load_egglog_module()
        if egglog is None or _EGGLOG_MODULE is None:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.EGGLOG_UNAVAILABLE,
                elapsed_ms=elapsed,
            )
        egraph = egglog.EGraph()

        from d810.backends.mba.egglog_add_rule_compiler import (
            apply_compiled_rule_to_term,
        )

        ordered_rules = tuple(rules)
        frontier: dict[
            int,
            dict[TypedBvTerm, tuple[tuple[str, str, tuple[str, ...]], ...]],
        ] = {0: {term: ()}}
        reachable: list[_ReachableCandidate] = []
        rewrites: list[Any] = []
        registration_work_unit_keys = set(_degree_expression_work_unit_keys(0, term))
        for degree in range(budget.max_degree):
            next_terms: dict[
                TypedBvTerm,
                tuple[tuple[str, str, tuple[str, ...]], ...],
            ] = {}
            for source_term, source_trace in frontier.get(degree, {}).items():
                for catalogue_index, rule in enumerate(ordered_rules):
                    elapsed = _elapsed_ms(started)
                    if elapsed > budget.time_budget_ms:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.TIME_BUDGET,
                            elapsed_ms=elapsed,
                        )
                    replacement = apply_compiled_rule_to_term(rule, source_term)
                    if replacement is None:
                        continue
                    replacement = canonicalize_ac_term(replacement)
                    elapsed = _elapsed_ms(started)
                    if elapsed > budget.time_budget_ms:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.TIME_BUDGET,
                            elapsed_ms=elapsed,
                        )
                    if len(rewrites) + 1 > budget.max_rule_firings:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.RULE_FIRING_BUDGET,
                        )
                    projected_work_unit_keys = (
                        registration_work_unit_keys
                        | set(_degree_expression_work_unit_keys(degree, source_term))
                        | set(
                            _degree_expression_work_unit_keys(degree + 1, replacement)
                        )
                    )
                    projected_work_units = len(projected_work_unit_keys)
                    if projected_work_units > budget.max_eclasses:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.ECLASS_BUDGET,
                        )
                    if projected_work_units > budget.max_enodes:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.ENODE_BUDGET,
                        )
                    source_expression = DegreeExpr.at(
                        degree,
                        _term_to_egglog(source_term),
                    )
                    target_expression = DegreeExpr.at(
                        degree + 1,
                        _term_to_egglog(replacement),
                    )
                    executable_rewrite = egglog.rewrite(source_expression).to(
                        target_expression
                    )
                    rewrites.append(executable_rewrite)
                    reachable.append(
                        _ReachableCandidate(
                            degree=degree + 1,
                            term=replacement,
                            family=str(rule.family),
                            source_name=str(rule.source_name),
                            aliases=tuple(rule.aliases),
                            expression=target_expression,
                            rule_decl=executable_rewrite.decl,
                            catalogue_index=catalogue_index,
                            derivation_trace=source_trace
                            + (
                                (
                                    str(rule.family),
                                    str(rule.source_name),
                                    tuple(rule.aliases),
                                ),
                            ),
                        )
                    )
                    next_terms.setdefault(
                        replacement,
                        source_trace
                        + (
                            (
                                str(rule.family),
                                str(rule.source_name),
                                tuple(rule.aliases),
                            ),
                        ),
                    )
                    registration_work_unit_keys = projected_work_unit_keys
            frontier[degree + 1] = next_terms

        registration_work_units = len(registration_work_unit_keys)
        scheduled_work_units = registration_work_units + (
            len(rewrites) * budget.saturation_rounds
        )
        admitted, elapsed = _pre_run_time_guard(
            started=started,
            budget=budget,
            work_units=scheduled_work_units,
        )
        if not admitted:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
                elapsed_ms=elapsed,
            )
        seed = DegreeExpr.at(0, _term_to_egglog(term))
        egraph.register(seed, *rewrites)
        matches_per_rule: dict[Any, int] = {}
        eclass_count = 0
        enode_count = 0
        for _round in range(budget.saturation_rounds):
            admitted, elapsed = _pre_run_time_guard(
                started=started,
                budget=budget,
                work_units=registration_work_units + len(rewrites),
            )
            if not admitted:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    rule_firings=sum(matches_per_rule.values()),
                    skip_reason=ExtractionSkipReason.TIME_BUDGET,
                    elapsed_ms=elapsed,
                )
            round_report = egraph.run(1)
            round_firings = read_rule_firing_count(round_report)
            statistics = read_egraph_statistics(egraph)
            elapsed = _elapsed_ms(started)
            if elapsed > budget.time_budget_ms:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    rule_firings=sum(matches_per_rule.values()) + (round_firings or 0),
                    skip_reason=ExtractionSkipReason.TIME_BUDGET,
                    elapsed_ms=elapsed,
                )
            if round_firings is None or statistics is None:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    rule_firings=sum(matches_per_rule.values()) + (round_firings or 0),
                    skip_reason=ExtractionSkipReason.UNAVAILABLE_EGRAPH_STATISTICS,
                    elapsed_ms=elapsed,
                )
            for declaration, count in round_report.num_matches_per_rule.items():
                matches_per_rule[declaration] = (
                    matches_per_rule.get(declaration, 0) + count
                )
            eclass_count, enode_count = statistics
            current_firings = sum(matches_per_rule.values())
            if eclass_count > budget.max_eclasses:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    eclass_count=eclass_count,
                    enode_count=enode_count,
                    rule_firings=current_firings,
                    skip_reason=ExtractionSkipReason.ECLASS_BUDGET,
                )
            if enode_count > budget.max_enodes:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    eclass_count=eclass_count,
                    enode_count=enode_count,
                    rule_firings=current_firings,
                    skip_reason=ExtractionSkipReason.ENODE_BUDGET,
                )
            if current_firings > budget.max_rule_firings:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    eclass_count=eclass_count,
                    enode_count=enode_count,
                    rule_firings=current_firings,
                    skip_reason=ExtractionSkipReason.RULE_FIRING_BUDGET,
                )
            if not getattr(round_report, "updated", True):
                break
        rule_firings = sum(matches_per_rule.values())
        report = type(
            "_AggregateRunReport",
            (),
            {"num_matches_per_rule": matches_per_rule},
        )()
        common = {
            "started": started,
            "input_cost": input_cost,
            "eclass_count": eclass_count,
            "enode_count": enode_count,
            "rule_firings": rule_firings,
        }
        if eclass_count > budget.max_eclasses:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.ECLASS_BUDGET,
            )
        if enode_count > budget.max_enodes:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.ENODE_BUDGET,
            )
        if rule_firings > budget.max_rule_firings:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.RULE_FIRING_BUDGET,
            )

        selections: list[
            tuple[
                tuple[int, int, int, int],
                Any,
                _ReachableCandidate,
            ]
        ] = []
        for candidate in reachable:
            if report.num_matches_per_rule.get(candidate.rule_decl, 0) <= 0:
                continue
            try:
                egraph.extract(candidate.expression)
            except egglog.EggSmolError:
                continue
            candidate_cost = _term_cost(candidate.term)
            if candidate_cost >= input_cost:
                continue
            rebuilt = rebuild_hexrays_island(
                candidate.term,
                lowering=lowering,
                destination_size=destination_size,
            )
            if rebuilt is None:
                continue
            selections.append(
                (
                    _extraction_selection_key(candidate, candidate_cost),
                    rebuilt,
                    candidate,
                )
            )
        if not selections:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
            )
        selection_key, replacement_ast, selected = min(
            selections,
            key=lambda item: item[0],
        )
        elapsed = _elapsed_ms(started)
        if elapsed > budget.time_budget_ms:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
                elapsed_ms=elapsed,
            )
        return _extraction_result(
            **common,
            extracted_cost=(selection_key[0], selection_key[1]),
            degree=selected.degree,
            provenance=selected.provenance,
            derivation_trace=selected.derivation_trace,
            replacement_ast=replacement_ast,
        )
    except Exception:
        try:
            elapsed = _elapsed_ms(started)
        except Exception:
            elapsed = 0.0
        return _extraction_result(
            started=started,
            input_cost=input_cost,
            skip_reason=ExtractionSkipReason.INTERNAL_ERROR,
            elapsed_ms=elapsed,
        )


__all__ = [
    "BvExpr",
    "DegreeExpr",
    "EGGLOG_EXPLORATION_SCOPE",
    "EgglogExtractionBudget",
    "EgglogExtractionReceipt",
    "EgglogExtractionResult",
    "ExtractionSkipReason",
    "TypedBvTerm",
    "canonicalize_ac_term",
    "extract_bounded_candidate",
    "lower_native_ast_to_term",
    "lower_term_to_native_ast",
    "term_cost",
    "term_fingerprint",
]
