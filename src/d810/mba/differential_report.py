"""Portable, deterministic MBA provider outcome comparison.

This module deliberately knows nothing about Hex-Rays or provider invocation.
It consumes the stable outcome records emitted at backend boundaries and turns
them into a corpus report that an offline tool can compare across providers.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from d810.mba.island_profile import IslandBlocker, MbaIslandClass, MbaIslandProfile
from d810.mba.provider_outcome import (
    MatcherOutcomeMetadata,
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


_WIN_STATUSES = frozenset(
    {ProviderOutcomeStatus.APPLIED, ProviderOutcomeStatus.IMPROVED}
)


def egglog_receipt_to_outcome(receipt: object) -> MbaProviderOutcome:
    """Convert a receipt-shaped Egglog result without invoking Egglog or IDA.

    The structural attribute protocol keeps the report/CLI importable in a
    plain Python process.  The native handler owns the actual receipt type and
    simply delegates here after every attempt.
    """

    raw_skip = getattr(receipt, "skip_reason", None)
    skip_reason = getattr(raw_skip, "value", raw_skip)
    skip_text = None if skip_reason is None else str(skip_reason)
    status_by_skip = {
        "egglog_unavailable": ProviderOutcomeStatus.UNAVAILABLE,
        "unavailable_egraph_statistics": ProviderOutcomeStatus.UNAVAILABLE,
        "time_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "eclass_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "enode_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "rule_firing_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "native_z3_failed": ProviderOutcomeStatus.PROOF_FAILED,
        "lowering_failed": ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
        "internal_error": ProviderOutcomeStatus.ERROR,
    }
    if skip_text is None:
        input_cost = getattr(receipt, "input_cost", None)
        extracted_cost = getattr(receipt, "extracted_cost", None)
        status = (
            ProviderOutcomeStatus.IMPROVED
            if input_cost is not None
            and extracted_cost is not None
            and tuple(extracted_cost) < tuple(input_cost)
            else ProviderOutcomeStatus.UNCHANGED
        )
    else:
        status = status_by_skip.get(skip_text, ProviderOutcomeStatus.INELIGIBLE)
    source = getattr(receipt, "selected_source", None)
    aliases = tuple(str(item) for item in getattr(receipt, "selected_aliases", ()))
    provenance = () if source is None else (str(source), *aliases)
    input_cost = getattr(receipt, "input_cost", None)
    extracted_cost = getattr(receipt, "extracted_cost", None)
    metadata = {
        "degree": getattr(receipt, "degree", None),
        "eclass_count": getattr(receipt, "eclass_count", None),
        "enode_count": getattr(receipt, "enode_count", None),
        "rule_firings": getattr(receipt, "rule_firings", 0),
        "selected_family": getattr(receipt, "selected_family", None),
        "island_class": getattr(receipt, "island_class", None),
        "operator_count": getattr(receipt, "operator_count", None),
        "distinct_leaf_count": getattr(receipt, "distinct_leaf_count", None),
        "nonlinear_product_count": getattr(receipt, "nonlinear_product_count", None),
        "blockers": tuple(str(item) for item in getattr(receipt, "blockers", ())),
    }
    return MbaProviderOutcome(
        provider=MbaProviderKind.EGGLOG,
        status=status,
        fingerprint=str(getattr(receipt, "island_fingerprint", None) or "unprofiled"),
        input_cost=None if input_cost is None else tuple(input_cost),
        output_cost=None if extracted_cost is None else tuple(extracted_cost),
        proof_verdict=(
            False
            if status is ProviderOutcomeStatus.PROOF_FAILED
            else True
            if skip_text is None
            else None
        ),
        elapsed_ms=float(getattr(receipt, "elapsed_ms", 0.0)),
        source_provenance=provenance,
        refusal_reason=skip_text,
        metadata=metadata,
    )


def _profile_to_dict(profile: MbaIslandProfile) -> dict[str, object]:
    return {
        "width_bits": profile.width_bits,
        "operator_count": profile.operator_count,
        "total_node_count": profile.total_node_count,
        "distinct_leaf_count": profile.distinct_leaf_count,
        "constant_count": profile.constant_count,
        "operations": [list(item) for item in profile.operations],
        "has_boolean": profile.has_boolean,
        "has_arithmetic": profile.has_arithmetic,
        "nonlinear_product_count": profile.nonlinear_product_count,
        "island_class": profile.island_class.value,
        "blockers": [item.value for item in profile.blockers],
        "fingerprint": profile.fingerprint,
    }


def profile_from_dict(data: Mapping[str, object]) -> MbaIslandProfile:
    """Strictly decode the portable profile wire shape used by the CLI."""

    try:
        operations = tuple(
            (str(item[0]), int(item[1]))
            for item in data["operations"]  # type: ignore[index,union-attr]
        )
        blockers = tuple(
            IslandBlocker(str(item))
            for item in data["blockers"]  # type: ignore[index,union-attr]
        )
        return MbaIslandProfile(
            width_bits=int(data["width_bits"]),
            operator_count=int(data["operator_count"]),
            total_node_count=int(data["total_node_count"]),
            distinct_leaf_count=int(data["distinct_leaf_count"]),
            constant_count=int(data["constant_count"]),
            operations=operations,
            has_boolean=bool(data["has_boolean"]),
            has_arithmetic=bool(data["has_arithmetic"]),
            nonlinear_product_count=int(data["nonlinear_product_count"]),
            island_class=MbaIslandClass(str(data["island_class"])),
            blockers=blockers,
            fingerprint=str(data["fingerprint"]),
        )
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise ValueError(f"invalid MBA island profile: {exc}") from exc


def outcome_from_dict(data: Mapping[str, object]) -> MbaProviderOutcome:
    """Strictly decode one :class:`MbaProviderOutcome` JSON object."""

    try:
        raw_matcher = data.get("matcher")
        matcher = (
            None
            if raw_matcher is None
            else MatcherOutcomeMetadata(
                comparisons=int(raw_matcher["comparisons"]),  # type: ignore[index]
                lazy_swaps=int(raw_matcher["lazy_swaps"]),  # type: ignore[index]
                flattened_arity=int(raw_matcher["flattened_arity"]),  # type: ignore[index]
                stop_reason=str(raw_matcher["stop_reason"]),  # type: ignore[index]
            )
        )
        raw_input_cost = data.get("input_cost")
        raw_output_cost = data.get("output_cost")
        return MbaProviderOutcome(
            provider=MbaProviderKind(str(data["provider"])),
            status=ProviderOutcomeStatus(str(data["status"])),
            fingerprint=str(data["fingerprint"]),
            input_cost=(
                None
                if raw_input_cost is None
                else (int(raw_input_cost[0]), int(raw_input_cost[1]))  # type: ignore[index]
            ),
            output_cost=(
                None
                if raw_output_cost is None
                else (int(raw_output_cost[0]), int(raw_output_cost[1]))  # type: ignore[index]
            ),
            proof_verdict=data.get("proof_verdict"),  # type: ignore[arg-type]
            elapsed_ms=float(data.get("elapsed_ms", 0.0)),
            source_provenance=tuple(
                str(item) for item in data.get("source_provenance", ())
            ),  # type: ignore[arg-type]
            refusal_reason=data.get("refusal_reason"),  # type: ignore[arg-type]
            metadata=data.get("metadata", {}),  # type: ignore[arg-type]
            matcher=matcher,
        )
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise ValueError(f"invalid MBA provider outcome: {exc}") from exc


@dataclass(frozen=True)
class MbaCorpusCaseReport:
    """All provider attempts for one fixed-width semantic corpus case."""

    case_id: str
    profile: MbaIslandProfile
    outcomes: tuple[MbaProviderOutcome, ...]
    stratum: str = "unclassified"

    def __post_init__(self) -> None:
        if type(self.case_id) is not str or not self.case_id:
            raise ValueError("case_id must be a non-empty string")
        if type(self.stratum) is not str or not self.stratum:
            raise ValueError("stratum must be a non-empty string")
        normalized_outcomes = tuple(
            sorted(self.outcomes, key=lambda outcome: outcome.provider.value)
        )
        object.__setattr__(self, "outcomes", normalized_outcomes)
        providers = tuple(outcome.provider for outcome in self.outcomes)
        if len(set(providers)) != len(providers):
            raise ValueError(f"{self.case_id}: each provider may have only one outcome")
        if any(
            outcome.fingerprint != self.profile.fingerprint for outcome in self.outcomes
        ):
            raise ValueError(f"{self.case_id}: outcome fingerprint must match profile")

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "stratum": self.stratum,
            "profile": _profile_to_dict(self.profile),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


@dataclass(frozen=True)
class MbaDifferentialReport:
    """Normalized outcome corpus, independent of IDA and individual providers."""

    schema_version: int
    corpus_identity: str
    toolchain_identity: Mapping[str, str]
    cases: tuple[MbaCorpusCaseReport, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version <= 0:
            raise ValueError("schema_version must be a positive integer")
        if type(self.corpus_identity) is not str or not self.corpus_identity:
            raise ValueError("corpus_identity must be a non-empty string")
        if any(
            type(key) is not str or type(value) is not str
            for key, value in self.toolchain_identity.items()
        ):
            raise ValueError("toolchain_identity must map strings to strings")
        object.__setattr__(
            self,
            "toolchain_identity",
            MappingProxyType(dict(sorted(self.toolchain_identity.items()))),
        )
        object.__setattr__(self, "cases", tuple(self.cases))
        case_ids = tuple(case.case_id for case in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("case IDs must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "corpus_identity": self.corpus_identity,
            "toolchain_identity": dict(self.toolchain_identity),
            "cases": [case.to_dict() for case in self.cases],
        }

    def to_json(self) -> str:
        return (
            json.dumps(
                self.to_dict(),
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


@dataclass(frozen=True)
class ProviderDifferentialStats:
    attempts: int = 0
    unique_wins: int = 0
    shared_wins: int = 0
    misses: int = 0
    proof_failures: int = 0
    unsafe_abstentions: int = 0
    over_budget: int = 0
    reconstruction_failures: int = 0
    unavailable: int = 0
    errors: int = 0
    node_reduction: int = 0
    p50_elapsed_ms: float = 0.0
    p95_elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "attempts": self.attempts,
            "unique_wins": self.unique_wins,
            "shared_wins": self.shared_wins,
            "misses": self.misses,
            "proof_failures": self.proof_failures,
            "unsafe_abstentions": self.unsafe_abstentions,
            "over_budget": self.over_budget,
            "reconstruction_failures": self.reconstruction_failures,
            "unavailable": self.unavailable,
            "errors": self.errors,
            "node_reduction": self.node_reduction,
            "p50_elapsed_ms": self.p50_elapsed_ms,
            "p95_elapsed_ms": self.p95_elapsed_ms,
        }


@dataclass(frozen=True)
class DifferentialSummary:
    """Aggregate outcomes by provider and corpus stratum."""

    by_provider: Mapping[MbaProviderKind, ProviderDifferentialStats]
    by_stratum: Mapping[str, ProviderDifferentialStats]

    def to_dict(self) -> dict[str, object]:
        return {
            "by_provider": {
                provider.value: stats.to_dict()
                for provider, stats in sorted(
                    self.by_provider.items(), key=lambda item: item[0].value
                )
            },
            "by_stratum": {
                stratum: stats.to_dict()
                for stratum, stats in sorted(self.by_stratum.items())
            },
        }


def _percentile(samples: Sequence[float], percent: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * percent
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def _stats_for_outcomes(
    outcomes: Iterable[tuple[MbaProviderOutcome, bool, bool]],
) -> ProviderDifferentialStats:
    rows = tuple(outcomes)
    elapsed = tuple(outcome.elapsed_ms for outcome, _shared, _unsafe in rows)
    unique_wins = sum(
        1
        for outcome, shared, _unsafe in rows
        if outcome.status in _WIN_STATUSES and not shared
    )
    shared_wins = sum(
        1
        for outcome, shared, _unsafe in rows
        if outcome.status in _WIN_STATUSES and shared
    )
    node_reduction = sum(
        outcome.input_cost[1] - outcome.output_cost[1]
        for outcome, _shared, _unsafe in rows
        if outcome.status in _WIN_STATUSES
        and outcome.input_cost is not None
        and outcome.output_cost is not None
    )
    return ProviderDifferentialStats(
        attempts=len(rows),
        unique_wins=unique_wins,
        shared_wins=shared_wins,
        misses=sum(
            1
            for outcome, _shared, _unsafe in rows
            if outcome.status is ProviderOutcomeStatus.UNCHANGED
        ),
        proof_failures=sum(
            1
            for outcome, _shared, _unsafe in rows
            if outcome.status is ProviderOutcomeStatus.PROOF_FAILED
        ),
        unsafe_abstentions=sum(1 for outcome, _shared, unsafe in rows if unsafe),
        over_budget=sum(
            1
            for outcome, _shared, _unsafe in rows
            if outcome.status is ProviderOutcomeStatus.OVER_BUDGET
        ),
        reconstruction_failures=sum(
            1
            for outcome, _shared, _unsafe in rows
            if outcome.status is ProviderOutcomeStatus.RECONSTRUCTION_FAILED
        ),
        unavailable=sum(
            1
            for outcome, _shared, _unsafe in rows
            if outcome.status is ProviderOutcomeStatus.UNAVAILABLE
        ),
        errors=sum(
            1
            for outcome, _shared, _unsafe in rows
            if outcome.status is ProviderOutcomeStatus.ERROR
        ),
        node_reduction=node_reduction,
        p50_elapsed_ms=_percentile(elapsed, 0.50),
        p95_elapsed_ms=_percentile(elapsed, 0.95),
    )


def _is_unsafe_abstention(
    profile: MbaIslandProfile,
    outcome: MbaProviderOutcome,
) -> bool:
    """Return whether an ineligible outcome is the intended fail-closed result.

    Resource exhaustion and reconstruction defects are operational failures on
    otherwise safe islands, not evidence that the semantic blocker policy
    worked.  Only an explicitly blocked/unsupported island that the provider
    declines is counted as an unsafe abstention.
    """

    return outcome.status is ProviderOutcomeStatus.INELIGIBLE and (
        bool(profile.blockers) or profile.island_class is MbaIslandClass.UNSUPPORTED
    )


def _stats_for_cases(cases: Iterable[MbaCorpusCaseReport]) -> ProviderDifferentialStats:
    """Aggregate stratum yield once per corpus case, never once per provider."""

    grouped_cases = tuple(cases)
    rows = tuple(
        (
            case,
            tuple(
                outcome for outcome in case.outcomes if outcome.status in _WIN_STATUSES
            ),
        )
        for case in grouped_cases
    )
    all_outcomes = tuple(outcome for case in grouped_cases for outcome in case.outcomes)
    elapsed = tuple(outcome.elapsed_ms for outcome in all_outcomes)
    return ProviderDifferentialStats(
        attempts=len(grouped_cases),
        unique_wins=sum(1 for _case, winners in rows if len(winners) == 1),
        shared_wins=sum(1 for _case, winners in rows if len(winners) > 1),
        misses=sum(
            1
            for case, winners in rows
            if not winners
            and case.outcomes
            and all(
                outcome.status is ProviderOutcomeStatus.UNCHANGED
                for outcome in case.outcomes
            )
        ),
        proof_failures=sum(
            1
            for case in grouped_cases
            if any(
                outcome.status is ProviderOutcomeStatus.PROOF_FAILED
                for outcome in case.outcomes
            )
        ),
        unsafe_abstentions=sum(
            1
            for case in grouped_cases
            if any(
                _is_unsafe_abstention(case.profile, outcome)
                for outcome in case.outcomes
            )
        ),
        over_budget=sum(
            1
            for case in grouped_cases
            if any(
                outcome.status is ProviderOutcomeStatus.OVER_BUDGET
                for outcome in case.outcomes
            )
        ),
        reconstruction_failures=sum(
            1
            for case in grouped_cases
            if any(
                outcome.status is ProviderOutcomeStatus.RECONSTRUCTION_FAILED
                for outcome in case.outcomes
            )
        ),
        unavailable=sum(
            1
            for case in grouped_cases
            if any(
                outcome.status is ProviderOutcomeStatus.UNAVAILABLE
                for outcome in case.outcomes
            )
        ),
        errors=sum(
            1
            for case in grouped_cases
            if any(
                outcome.status is ProviderOutcomeStatus.ERROR
                for outcome in case.outcomes
            )
        ),
        node_reduction=sum(
            max(
                (
                    outcome.input_cost[1] - outcome.output_cost[1]
                    for outcome in case.outcomes
                    if outcome.status in _WIN_STATUSES
                    and outcome.input_cost is not None
                    and outcome.output_cost is not None
                ),
                default=0,
            )
            for case in grouped_cases
        ),
        p50_elapsed_ms=_percentile(elapsed, 0.50),
        p95_elapsed_ms=_percentile(elapsed, 0.95),
    )


def compare_provider_outcomes(report: MbaDifferentialReport) -> DifferentialSummary:
    """Compare provider yield without conflating unavailable and missed attempts."""

    provider_rows: dict[
        MbaProviderKind, list[tuple[MbaProviderOutcome, bool, bool]]
    ] = defaultdict(list)
    stratum_cases: dict[str, list[MbaCorpusCaseReport]] = defaultdict(list)
    for case in report.cases:
        winners = {
            outcome.provider
            for outcome in case.outcomes
            if outcome.status in _WIN_STATUSES
        }
        shared = len(winners) > 1
        stratum_cases[case.stratum].append(case)
        for outcome in case.outcomes:
            row = (
                outcome,
                shared and outcome.status in _WIN_STATUSES,
                _is_unsafe_abstention(case.profile, outcome),
            )
            provider_rows[outcome.provider].append(row)
    return DifferentialSummary(
        by_provider=MappingProxyType(
            {
                provider: _stats_for_outcomes(rows)
                for provider, rows in provider_rows.items()
            }
        ),
        by_stratum=MappingProxyType(
            {
                stratum: _stats_for_cases(cases)
                for stratum, cases in stratum_cases.items()
            }
        ),
    )


def normalize_outcome_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    corpus_identity: str,
    toolchain_identity: Mapping[str, str],
    expected_providers: Sequence[MbaProviderKind] = (),
    schema_version: int = 1,
) -> MbaDifferentialReport:
    """Group flat portable outcome rows and reject ambiguous or missing coverage."""

    grouped: dict[str, tuple[str, MbaIslandProfile, list[MbaProviderOutcome]]] = {}
    for row in rows:
        try:
            case_id = str(row["case_id"])
            stratum = str(row.get("stratum", "unclassified"))
            profile_value = row["profile"]
            outcome_value = row["outcome"]
        except KeyError as exc:
            raise ValueError(f"outcome row missing {exc.args[0]}") from exc
        profile = (
            profile_value
            if isinstance(profile_value, MbaIslandProfile)
            else profile_from_dict(profile_value)  # type: ignore[arg-type]
        )
        outcome = (
            outcome_value
            if isinstance(outcome_value, MbaProviderOutcome)
            else outcome_from_dict(outcome_value)  # type: ignore[arg-type]
        )
        current = grouped.get(case_id)
        if current is None:
            grouped[case_id] = (stratum, profile, [outcome])
        else:
            current_stratum, current_profile, outcomes = current
            if current_stratum != stratum or current_profile != profile:
                raise ValueError(f"{case_id}: conflicting profile or stratum rows")
            outcomes.append(outcome)

    cases: list[MbaCorpusCaseReport] = []
    expected = tuple(expected_providers)
    for case_id in sorted(grouped):
        stratum, profile, outcomes = grouped[case_id]
        case = MbaCorpusCaseReport(case_id, profile, tuple(outcomes), stratum)
        actual = frozenset(outcome.provider for outcome in case.outcomes)
        missing = tuple(
            provider.value for provider in expected if provider not in actual
        )
        unexpected = (
            tuple(sorted(provider.value for provider in actual - frozenset(expected)))
            if expected
            else ()
        )
        if missing:
            raise ValueError(
                f"{case_id}: missing outcome rows for {', '.join(missing)}"
            )
        if unexpected:
            raise ValueError(
                f"{case_id}: unexpected outcome rows for {', '.join(unexpected)}"
            )
        cases.append(case)
    return MbaDifferentialReport(
        schema_version, corpus_identity, toolchain_identity, tuple(cases)
    )


def report_from_dict(data: Mapping[str, object]) -> MbaDifferentialReport:
    """Decode a normalized report JSON document for offline comparisons."""

    try:
        rows: list[dict[str, object]] = []
        for case in data["cases"]:  # type: ignore[index]
            for outcome in case["outcomes"]:  # type: ignore[index]
                rows.append(
                    {
                        "case_id": case["case_id"],
                        "stratum": case.get("stratum", "unclassified"),
                        "profile": case["profile"],
                        "outcome": outcome,
                    }
                )
        return normalize_outcome_rows(
            rows,
            corpus_identity=str(data["corpus_identity"]),
            toolchain_identity=data["toolchain_identity"],  # type: ignore[arg-type]
            schema_version=int(data["schema_version"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid MBA differential report: {exc}") from exc


def summary_markdown(summary: DifferentialSummary) -> str:
    """Return a concise stable Markdown summary suitable for CI artifacts."""

    lines = [
        "| provider | attempts | unique | shared | misses | proof failures | unsafe abstentions | unavailable | node reduction | p50 ms | p95 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for provider, stats in sorted(
        summary.by_provider.items(), key=lambda item: item[0].value
    ):
        lines.append(
            "| {provider} | {attempts} | {unique_wins} | {shared_wins} | {misses} | "
            "{proof_failures} | {unsafe_abstentions} | {unavailable} | {node_reduction} | "
            "{p50_elapsed_ms:.3f} | {p95_elapsed_ms:.3f} |".format(
                provider=provider.value, **stats.to_dict()
            )
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "DifferentialSummary",
    "MbaCorpusCaseReport",
    "MbaDifferentialReport",
    "ProviderDifferentialStats",
    "compare_provider_outcomes",
    "normalize_outcome_rows",
    "outcome_from_dict",
    "profile_from_dict",
    "report_from_dict",
    "summary_markdown",
]
