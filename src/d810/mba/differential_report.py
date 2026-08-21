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
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.mba.island_profile import (
    MbaIslandClass,
    MbaIslandProfile,
    profile_from_dict,
    profile_to_dict,
)
from d810.mba.provider_outcome import (
    MatcherOutcomeMetadata,
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


_WIN_STATUSES = frozenset(
    {ProviderOutcomeStatus.APPLIED, ProviderOutcomeStatus.IMPROVED}
)


def egraph_receipt_to_outcome(receipt: object) -> MbaProviderOutcome:
    """Convert a receipt-shaped e-graph result without invoking a backend or IDA.

    The structural attribute protocol keeps the report/CLI importable in a
    plain Python process.  The native handler owns the actual receipt type and
    simply delegates here after every attempt.
    """

    raw_skip = getattr(receipt, "skip_reason", None)
    skip_reason = getattr(raw_skip, "value", raw_skip)
    skip_text = None if skip_reason is None else str(skip_reason)
    status_by_skip = {
        "runtime_unavailable": ProviderOutcomeStatus.UNAVAILABLE,
        "time_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "eclass_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "enode_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "rule_firing_budget": ProviderOutcomeStatus.OVER_BUDGET,
        "proof_failed": ProviderOutcomeStatus.PROOF_FAILED,
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
        "backend": getattr(receipt, "backend", None),
        "backend_version": getattr(receipt, "backend_version", None),
        "canonicalizer_version": getattr(receipt, "canonicalizer_version", None),
        "canonical_input_cost": getattr(receipt, "canonical_input_cost", None),
        "normalization_steps": tuple(
            str(item) for item in getattr(receipt, "normalization_steps", ())
        ),
        "execution_path": getattr(receipt, "execution_path", None),
        "cache_status": getattr(receipt, "cache_status", None),
        "cache_key": getattr(receipt, "cache_key", None),
        "replayed_trace": tuple(
            tuple(row) for row in getattr(receipt, "replayed_trace", ())
        ),
        "cache_lookup_elapsed_ms": getattr(
            receipt, "cache_lookup_elapsed_ms", None
        ),
        "replay_rebuild_elapsed_ms": getattr(
            receipt, "replay_rebuild_elapsed_ms", None
        ),
        "replay_proof_elapsed_ms": getattr(receipt, "replay_proof_elapsed_ms", None),
        "derivation_trace": tuple(
            tuple(row) for row in getattr(receipt, "derivation_trace", ())
        ),
        "egraph_work_units": getattr(receipt, "egraph_work_units", 0),
        "replay_saved_egraph_runs": getattr(
            receipt, "replay_saved_egraph_runs", None
        ),
        "replay_fallback_reason": getattr(receipt, "replay_fallback_reason", None),
        "degree": getattr(receipt, "degree", None),
        "eclass_count": getattr(receipt, "eclass_count", None),
        "enode_count": getattr(receipt, "enode_count", None),
        "rule_firings": getattr(receipt, "rule_firings", 0),
        "selected_family": getattr(receipt, "selected_family", None),
        "selected_source": getattr(receipt, "selected_source", None),
        "selected_aliases": tuple(
            str(item) for item in getattr(receipt, "selected_aliases", ())
        ),
        "island_class": getattr(receipt, "island_class", None),
        "operator_count": getattr(receipt, "operator_count", None),
        "distinct_leaf_count": getattr(receipt, "distinct_leaf_count", None),
        "nonlinear_product_count": getattr(receipt, "nonlinear_product_count", None),
        "blockers": tuple(str(item) for item in getattr(receipt, "blockers", ())),
        "proof_mode": getattr(receipt, "proof_mode", None),
        "template_source_name": getattr(receipt, "template_source_name", None),
        "template_fallback_reason": getattr(receipt, "template_fallback_reason", None),
        "template_proof_verdict": getattr(receipt, "template_proof_verdict", None),
        "legacy_proof_verdict": getattr(receipt, "legacy_proof_verdict", None),
        "template_proof_elapsed_ms": getattr(
            receipt, "template_proof_elapsed_ms", None
        ),
        "legacy_proof_elapsed_ms": getattr(receipt, "legacy_proof_elapsed_ms", None),
        "native_matcher_backend": getattr(receipt, "native_matcher_backend", None),
        "native_matcher_comparisons": getattr(
            receipt, "native_matcher_comparisons", None
        ),
        "native_matcher_lazy_swaps": getattr(
            receipt, "native_matcher_lazy_swaps", None
        ),
        "native_fixed_binding_count": getattr(
            receipt, "native_fixed_binding_count", None
        ),
        "native_matcher_elapsed_ms": getattr(
            receipt, "native_matcher_elapsed_ms", None
        ),
    }
    # Run counts are producer evidence, not report inference.  Missing
    # measurements remain absent so a path label cannot masquerade as proof of
    # a runtime call.
    raw_run_count = getattr(receipt, "egraph_run_count", None)
    if type(raw_run_count) is int and raw_run_count >= 0:
        metadata["egraph_run_count"] = raw_run_count
    native_profile = getattr(receipt, "native_profile", None)
    if isinstance(native_profile, Mapping):
        metadata["native_profile"] = dict(native_profile)
    return MbaProviderOutcome(
        provider=MbaProviderKind.EGRAPH,
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
    profile: MbaIslandProfile | None
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
        if self.profile is None:
            if any(
                outcome.status is not ProviderOutcomeStatus.UNAVAILABLE
                or outcome.refusal_reason
                not in {"native_candidate_not_observed", "native_candidate_ambiguous"}
                for outcome in self.outcomes
            ):
                raise ValueError(
                    f"{self.case_id}: a missing native candidate may only emit "
                    "explicit unavailable rows"
                )
        elif any(
            outcome.fingerprint != self.profile.fingerprint for outcome in self.outcomes
        ):
            raise ValueError(f"{self.case_id}: outcome fingerprint must match profile")
        applied_providers = tuple(
            outcome.provider.value
            for outcome in self.outcomes
            if outcome.status is ProviderOutcomeStatus.APPLIED
        )
        if len(applied_providers) > 1:
            raise ValueError(
                f"{self.case_id}: at most one applied provider is allowed for "
                f"fingerprint {self.profile.fingerprint if self.profile else '<none>'}: "
                f"{', '.join(applied_providers)}"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "stratum": self.stratum,
            "profile": (
                None if self.profile is None else profile_to_dict(self.profile)
            ),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


@dataclass(frozen=True)
class MbaDifferentialReport:
    """Normalized outcome corpus, independent of IDA and individual providers."""

    schema_version: int
    corpus_identity: str
    toolchain_identity: Mapping[str, str]
    cases: tuple[MbaCorpusCaseReport, ...]
    # Capture-level measurements belong to the one native corpus invocation,
    # rather than being duplicated into every provider row.  They are emitted
    # only by a real runner; the portable report never invents a measurement.
    capture_metadata: Mapping[str, object] = field(default_factory=dict)

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
        try:
            normalized_metadata = json.loads(
                json.dumps(
                    self.capture_metadata,
                    allow_nan=False,
                    ensure_ascii=True,
                    sort_keys=True,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capture_metadata must be finite JSON data") from exc
        if not isinstance(normalized_metadata, dict):
            raise ValueError("capture_metadata must be a mapping")
        object.__setattr__(
            self,
            "capture_metadata",
            MappingProxyType(normalized_metadata),
        )
        case_ids = tuple(case.case_id for case in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("case IDs must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "corpus_identity": self.corpus_identity,
            "toolchain_identity": dict(self.toolchain_identity),
            "capture_metadata": dict(self.capture_metadata),
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
class LatencyStats:
    """One explicitly measured latency population, never a filled-in zero."""

    count: int
    p50_ms: float | None
    p95_ms: float | None

    def to_dict(self) -> dict[str, int | float | None]:
        return {"count": self.count, "p50_ms": self.p50_ms, "p95_ms": self.p95_ms}


@dataclass(frozen=True)
class LifecycleMeasurement:
    """A measured lifecycle counter or duration from actual capture metadata."""

    count: int
    total: int | float
    p50_ms: float | None = None
    p95_ms: float | None = None

    def to_dict(self) -> dict[str, int | float | None]:
        return {
            "count": self.count,
            "total": self.total,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
        }


@dataclass(frozen=True)
class RolloutEvidence:
    """Measurements required to decide a portfolio rollout from captured rows.

    Missing instrumentation remains absent from its mapping.  This prevents an
    incomplete run from being rendered as a measured zero.
    """

    egraph_unique_wins_by_degree: Mapping[int, int]
    external_reference_unique_wins: int
    nonlinear_residuals: int
    refusals_by_reason: Mapping[str, int]
    matcher_bucket_size_p50: float | None
    matcher_attempted_rules_p95: float | None
    matcher_comparisons_p95: float | None
    matcher_lazy_swaps_total: int
    matcher_flattened_arity_p95: float | None
    matcher_cap_refusals: int
    reassociation_proved: int
    reassociation_pending: int
    lifecycle_measurements: Mapping[str, LifecycleMeasurement]
    candidate_latency_by_mode: Mapping[str, Mapping[str, LatencyStats]]
    whole_function_latency_by_mode: Mapping[str, Mapping[str, LatencyStats]]
    root_only_strict_subisland_misses: int
    # Task 13 domain-lifted measurements are additive to the original
    # rollout questions above.  Empty mappings and ``None`` mean that the
    # producer did not record the measurement; they are never synthetic zero
    # evidence.
    normalization_counts_by_kind: Mapping[str, int] = field(default_factory=dict)
    raw_vs_canonical_input_costs: tuple[Mapping[str, object], ...] = ()
    eligible_rule_measurements: Mapping[str, int] = field(default_factory=dict)
    fixed_shift_admissions: int | None = None
    fixed_shift_refusals_by_reason: Mapping[str, int] = field(default_factory=dict)
    rotate_extractions_by_width_direction: Mapping[str, int] = field(
        default_factory=dict
    )
    execution_path_counts: Mapping[str, int] = field(default_factory=dict)
    execution_path_latency: Mapping[str, LatencyStats] = field(default_factory=dict)
    replay_saved_egraph_runs: int | None = None
    cache_status_counts: Mapping[str, int] = field(default_factory=dict)
    cache_peak_entries: int | None = None
    cache_peak_bytes: int | None = None
    runtime_parity: Mapping[str, object] = field(default_factory=dict)
    certificate_activation: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "egraph_unique_wins_by_degree": {
                str(degree): count
                for degree, count in sorted(self.egraph_unique_wins_by_degree.items())
            },
            "external_reference_unique_wins": self.external_reference_unique_wins,
            "nonlinear_residuals": self.nonlinear_residuals,
            "refusals_by_reason": dict(sorted(self.refusals_by_reason.items())),
            "matcher": {
                "bucket_size_p50": self.matcher_bucket_size_p50,
                "attempted_rules_p95": self.matcher_attempted_rules_p95,
                "comparisons_p95": self.matcher_comparisons_p95,
                "lazy_swaps_total": self.matcher_lazy_swaps_total,
                "flattened_arity_p95": self.matcher_flattened_arity_p95,
                "cap_refusals": self.matcher_cap_refusals,
                "reassociation_proved": self.reassociation_proved,
                "reassociation_pending": self.reassociation_pending,
            },
            "lifecycle_measurements": {
                name: measurement.to_dict()
                for name, measurement in sorted(self.lifecycle_measurements.items())
            },
            "candidate_latency_by_mode": _latency_by_mode_to_dict(
                self.candidate_latency_by_mode
            ),
            "whole_function_latency_by_mode": _latency_by_mode_to_dict(
                self.whole_function_latency_by_mode
            ),
            "root_only_strict_subisland_misses": self.root_only_strict_subisland_misses,
            "normalization_counts_by_kind": dict(
                sorted(self.normalization_counts_by_kind.items())
            ),
            "raw_vs_canonical_input_costs": [
                dict(sample) for sample in self.raw_vs_canonical_input_costs
            ],
            "eligible_rule_measurements": dict(
                sorted(self.eligible_rule_measurements.items())
            ),
            "fixed_shift_admissions": self.fixed_shift_admissions,
            "fixed_shift_refusals_by_reason": dict(
                sorted(self.fixed_shift_refusals_by_reason.items())
            ),
            "rotate_extractions_by_width_direction": dict(
                sorted(self.rotate_extractions_by_width_direction.items())
            ),
            "execution_path_counts": dict(sorted(self.execution_path_counts.items())),
            "execution_path_latency": {
                path: stats.to_dict()
                for path, stats in sorted(self.execution_path_latency.items())
            },
            "replay_saved_egraph_runs": self.replay_saved_egraph_runs,
            "cache_status_counts": dict(sorted(self.cache_status_counts.items())),
            "cache_peak_entries": self.cache_peak_entries,
            "cache_peak_bytes": self.cache_peak_bytes,
            "runtime_parity": dict(self.runtime_parity),
            "certificate_activation": dict(self.certificate_activation),
        }


def _latency_by_mode_to_dict(
    values: Mapping[str, Mapping[str, LatencyStats]],
) -> dict[str, object]:
    return {
        mode: {
            provider: stats.to_dict()
            for provider, stats in sorted(by_provider.items())
        }
        for mode, by_provider in sorted(values.items())
    }


@dataclass(frozen=True)
class DifferentialSummary:
    """Aggregate outcomes by provider and corpus stratum."""

    by_provider: Mapping[MbaProviderKind, ProviderDifferentialStats]
    by_stratum: Mapping[str, ProviderDifferentialStats]
    rollout_evidence: RolloutEvidence

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
            "rollout_evidence": self.rollout_evidence.to_dict(),
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
    profile: MbaIslandProfile | None,
    outcome: MbaProviderOutcome,
) -> bool:
    """Return whether an ineligible outcome is the intended fail-closed result.

    Resource exhaustion and reconstruction defects are operational failures on
    otherwise safe islands, not evidence that the semantic blocker policy
    worked.  Only an explicitly blocked/unsupported island that the provider
    declines is counted as an unsafe abstention.
    """

    return profile is not None and outcome.status is ProviderOutcomeStatus.INELIGIBLE and (
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


def _metadata_number(metadata: Mapping[str, object], name: str) -> float | None:
    value = metadata.get(name)
    if type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _metadata_int(metadata: Mapping[str, object], name: str) -> int | None:
    value = metadata.get(name)
    return value if type(value) is int and value >= 0 else None


def _metadata_cost(metadata: Mapping[str, object], name: str) -> tuple[int, int] | None:
    """Read one finite two-dimensional cost without coercing telemetry."""

    value = metadata.get(name)
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        return None
    if any(type(item) is not int or item < 0 for item in value):
        return None
    return (value[0], value[1])


def _nonnegative_int_mapping(value: object) -> dict[str, int]:
    """Copy only explicit integer measurements from a JSON mapping."""

    if not isinstance(value, Mapping):
        return {}
    return {
        key: item
        for key, item in value.items()
        if type(key) is str and type(item) is int and item >= 0
    }


def _rotate_key(metadata: Mapping[str, object]) -> str | None:
    """Read the producer's explicit rotate width/direction evidence."""

    width = metadata.get("rotate_width")
    direction = metadata.get("rotate_direction")
    if type(width) is int and width > 0 and type(direction) is str and direction:
        return f"{width}:{direction}"
    return None


def _rollout_evidence(report: MbaDifferentialReport) -> RolloutEvidence:
    """Aggregate explicit rollout instrumentation from captured provider rows."""

    refusals: dict[str, int] = defaultdict(int)
    egraph_unique_by_degree: dict[int, int] = defaultdict(int)
    observed_egraph_degrees: set[int] = set()
    external_unique = 0
    nonlinear_residuals = 0
    bucket_sizes: list[float] = []
    attempted_rules: list[float] = []
    comparisons: list[float] = []
    flattened_arities: list[float] = []
    lazy_swaps_total = 0
    cap_refusals = 0
    reassociation_proved = 0
    reassociation_pending = 0
    lifecycle_samples: dict[str, list[float]] = defaultdict(list)
    candidate_latencies: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    whole_function_latencies: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    root_only_misses = 0
    normalization_counts: dict[str, int] = defaultdict(int)
    capture_normalization_counts: dict[str, int] = defaultdict(int)
    raw_vs_canonical: list[dict[str, object]] = []
    capture_raw_vs_canonical: list[dict[str, object]] = []
    eligible_rule_measurements: dict[str, int] = {}
    fixed_shift_admissions = 0
    fixed_shift_seen = False
    fixed_shift_refusals: dict[str, int] = defaultdict(int)
    rotate_extractions: dict[str, int] = defaultdict(int)
    execution_path_counts: dict[str, int] = defaultdict(int)
    execution_path_latencies: dict[str, list[float]] = defaultdict(list)
    replay_saved_egraph_runs: int | None = None
    row_replay_saved_egraph_runs = 0
    row_replay_savings_observed = False
    cache_status_counts: dict[str, int] = defaultdict(int)
    cache_peak_entries: int | None = None
    cache_peak_bytes: int | None = None
    capture_cache_status_counts: dict[str, int] = defaultdict(int)
    runtime_parity: dict[str, object] = {}
    certificate_activation: dict[str, object] = {}

    capture_metadata = report.capture_metadata
    raw_modes = capture_metadata.get("provider_execution_modes", {})
    provider_modes = raw_modes if isinstance(raw_modes, Mapping) else {}
    raw_whole = capture_metadata.get("whole_function_elapsed_ms_by_case", {})
    whole_by_case = raw_whole if isinstance(raw_whole, Mapping) else {}

    def record_int_measurement(target: dict[str, int], name: str, value: object) -> None:
        if type(name) is str and type(value) is int and value >= 0:
            target.setdefault(name, value)

    # Capture-level domain-lifted measurements are emitted once by the native
    # runner. Missing keys remain absent; the report never infers a value from
    # an execution-path label or a source name.
    for name, value in _nonnegative_int_mapping(
        capture_metadata.get("eligible_rule_measurements")
    ).items():
        record_int_measurement(eligible_rule_measurements, name, value)
    for kind, count in _nonnegative_int_mapping(
        capture_metadata.get("normalization_counts_by_kind")
    ).items():
        capture_normalization_counts[kind] += count
    raw_cost_rows = capture_metadata.get("raw_vs_canonical_input_costs", ())
    if isinstance(raw_cost_rows, list):
        for row in raw_cost_rows:
            if not isinstance(row, Mapping) or row.get("non_yield") is not True:
                continue
            raw = _metadata_cost(row, "raw_input_cost")
            canonical = _metadata_cost(row, "canonical_input_cost")
            case_id = row.get("case_id")
            provider = row.get("provider")
            if (
                raw is None
                or canonical is None
                or type(case_id) is not str
                or type(provider) is not str
            ):
                continue
            capture_raw_vs_canonical.append(
                {
                    "case_id": case_id,
                    "provider": provider,
                    "raw_input_cost": list(raw),
                    "canonical_input_cost": list(canonical),
                    "non_yield": True,
                }
            )
    fixed_measurements = capture_metadata.get("fixed_shift_measurements")
    if isinstance(fixed_measurements, Mapping):
        admissions = fixed_measurements.get("admissions")
        if type(admissions) is int and admissions >= 0:
            fixed_shift_seen = True
            fixed_shift_admissions += admissions
        for reason, count in _nonnegative_int_mapping(
            fixed_measurements.get("refusal_reasons")
        ).items():
            fixed_shift_seen = True
            fixed_shift_refusals[reason] += count
    for name in ("base_pattern_count", "legacy_permutation_count"):
        value = capture_metadata.get(name)
        if type(value) is int and value >= 0:
            record_int_measurement(eligible_rule_measurements, name, value)

    cache_measurements = capture_metadata.get("cache_measurements")
    if isinstance(cache_measurements, Mapping):
        entries = cache_measurements.get("peak_entries")
        if type(entries) is int and entries >= 0:
            cache_peak_entries = entries
        bytes_used = cache_measurements.get("peak_bytes")
        if type(bytes_used) is int and bytes_used >= 0:
            cache_peak_bytes = bytes_used
        for status, count in _nonnegative_int_mapping(
            cache_measurements.get("status_counts")
        ).items():
            capture_cache_status_counts[status] += count
    for field_name, target in (
        ("runtime_parity", runtime_parity),
        ("certificate_activation", certificate_activation),
    ):
        value = capture_metadata.get(field_name)
        if isinstance(value, Mapping):
            target.update(value)

    # Keep an explicit zero-sample lane for every configured provider.  An
    # unavailable extension or a telemetry-only e-graph admission must be
    # visible as "measured, no candidate" rather than disappear from the
    # portfolio report.
    for provider, mode in provider_modes.items():
        if type(provider) is str and type(mode) is str and mode:
            candidate_latencies[mode][provider]
            whole_function_latencies[mode][provider]

    def capture_number(name: str) -> float | None:
        return _metadata_number(capture_metadata, name)

    raw_lifecycle = capture_metadata.get("lifecycle_measurements", {})
    if isinstance(raw_lifecycle, Mapping):
        for name, values in raw_lifecycle.items():
            if type(name) is not str:
                continue
            samples = values if isinstance(values, list) else [values]
            for value in samples:
                if type(value) in (int, float) and math.isfinite(float(value)) and value >= 0:
                    lifecycle_samples[name].append(float(value))

    raw_matcher_samples = capture_metadata.get("matcher_samples", ())
    if isinstance(raw_matcher_samples, list):
        for sample in raw_matcher_samples:
            if not isinstance(sample, Mapping):
                continue
            bucket = _metadata_number(sample, "bucket_size")
            if bucket is not None:
                bucket_sizes.append(bucket)
            attempted = _metadata_number(sample, "attempted_rule_count")
            if attempted is not None:
                attempted_rules.append(attempted)
            comparison = _metadata_number(sample, "comparisons")
            if comparison is not None:
                comparisons.append(comparison)
            flattened = _metadata_number(sample, "flattened_arity")
            if flattened is not None:
                flattened_arities.append(flattened)
            swaps = _metadata_int(sample, "lazy_swaps")
            if swaps is not None:
                lazy_swaps_total += swaps
            if sample.get("comparison_cap_refusal") is True:
                cap_refusals += 1
            coverage = sample.get("reassociation_coverage")
            if coverage == "proved":
                reassociation_proved += 1
            elif coverage == "pending":
                reassociation_pending += 1

    raw_latency_lanes = capture_metadata.get("latency_lanes", ())
    if isinstance(raw_latency_lanes, list):
        for lane in raw_latency_lanes:
            if not isinstance(lane, Mapping):
                continue
            population = lane.get("population")
            mode = lane.get("mode")
            provider = lane.get("provider")
            if not all(type(value) is str and value for value in (population, mode, provider)):
                continue
            target = (
                candidate_latencies
                if population == "candidate"
                else whole_function_latencies
                if population == "whole_function"
                else None
            )
            if target is not None:
                target[mode][provider]

    raw_latency_samples = capture_metadata.get("latency_samples", ())
    if isinstance(raw_latency_samples, list):
        for sample in raw_latency_samples:
            if not isinstance(sample, Mapping):
                continue
            population = sample.get("population")
            mode = sample.get("mode")
            provider = sample.get("provider")
            elapsed = _metadata_number(sample, "elapsed_ms")
            if (
                not all(
                    type(value) is str and value
                    for value in (population, mode, provider)
                )
                or elapsed is None
            ):
                continue
            target = (
                candidate_latencies
                if population == "candidate"
                else whole_function_latencies
                if population == "whole_function"
                else None
            )
            if target is not None:
                target[mode][provider].append(elapsed)

    root_only_misses += int(capture_number("root_only_strict_subisland_misses") or 0)

    for case in report.cases:
        winners = tuple(
            outcome for outcome in case.outcomes if outcome.status in _WIN_STATUSES
        )
        if (
            case.stratum == "nonlinear"
            or (
                case.profile is not None
                and case.profile.island_class is MbaIslandClass.NONLINEAR_MBA
            )
        ) and not winners:
            nonlinear_residuals += 1
        if len(winners) == 1:
            winner = winners[0]
            if winner.provider is MbaProviderKind.EGRAPH:
                degree = _metadata_int(winner.metadata, "degree")
                if degree is not None:
                    egraph_unique_by_degree[degree] += 1
            if winner.provider is MbaProviderKind.EXTERNAL_REFERENCE:
                external_unique += 1

        for outcome in case.outcomes:
            metadata = outcome.metadata
            if outcome.provider is MbaProviderKind.EGRAPH:
                degree = _metadata_int(metadata, "degree")
                if degree is not None:
                    observed_egraph_degrees.add(degree)
            if outcome.refusal_reason is not None:
                refusals[outcome.refusal_reason] += 1

            # Domain-lifted normalization is an input characterization, not a
            # yield claim.  Keep every raw/canonical cost pair explicitly
            # marked non-yield, including unchanged or refused provider rows.
            raw_steps = metadata.get("normalization_steps")
            if isinstance(raw_steps, (tuple, list)):
                for step in raw_steps:
                    if type(step) is str and step:
                        normalization_counts[step] += 1
            canonical_cost = _metadata_cost(metadata, "canonical_input_cost")
            raw_cost = outcome.input_cost
            if (
                raw_cost is not None
                and canonical_cost is not None
                and len(raw_cost) == 2
                and all(type(item) is int and item >= 0 for item in raw_cost)
            ):
                raw_vs_canonical.append(
                    {
                        "case_id": case.case_id,
                        "provider": outcome.provider.value,
                        "raw_input_cost": list(raw_cost),
                        "canonical_input_cost": list(canonical_cost),
                        "non_yield": True,
                    }
                )

            for name in ("base_pattern_count", "legacy_permutation_count"):
                value = metadata.get(name)
                if type(value) is int and value >= 0:
                    record_int_measurement(eligible_rule_measurements, name, value)
            eligible_mapping = metadata.get("eligible_rule_measurements")
            for name, value in _nonnegative_int_mapping(eligible_mapping).items():
                record_int_measurement(eligible_rule_measurements, name, value)

            selected_family = metadata.get("selected_family")
            fixed_row = case.stratum == "fixed_shift" or selected_family in {
                "fixed_rotate",
                "fixed_shift",
            }
            fixed_admitted = metadata.get("fixed_shift_admitted")
            if type(fixed_admitted) is bool or selected_family in {
                "fixed_rotate",
                "fixed_shift",
            }:
                fixed_shift_seen = True
            if fixed_admitted is True:
                fixed_shift_admissions += 1
            elif (
                selected_family == "fixed_rotate"
                and outcome.status in _WIN_STATUSES
            ):
                # Receipt provenance is sufficient native/provider evidence
                # for an admitted complementary rotate when an older adapter
                # did not yet emit the explicit boolean field.
                fixed_shift_admissions += 1
            refusal_reason = metadata.get("fixed_shift_refusal_reason")
            if type(refusal_reason) is str and refusal_reason:
                fixed_shift_seen = True
                fixed_shift_refusals[refusal_reason] += 1
            elif fixed_row and outcome.refusal_reason in {
                "noncomplementary_shift",
                "arithmetic_shift",
                "variable_shift_count",
            }:
                fixed_shift_seen = True
                fixed_shift_refusals[outcome.refusal_reason] += 1  # type: ignore[index]
            if (
                selected_family == "fixed_rotate"
                and outcome.status in _WIN_STATUSES
            ):
                rotate_key = _rotate_key(metadata)
                if rotate_key is not None:
                    rotate_extractions[rotate_key] += 1

            execution_path = metadata.get("execution_path")
            if type(execution_path) is str and execution_path:
                execution_path_counts[execution_path] += 1
                if type(outcome.elapsed_ms) in (int, float) and math.isfinite(
                    float(outcome.elapsed_ms)
                ) and outcome.elapsed_ms >= 0:
                    execution_path_latencies[execution_path].append(
                        float(outcome.elapsed_ms)
                    )
            explicit_replay_savings = _metadata_int(metadata, "replay_saved_egraph_runs")
            if explicit_replay_savings is not None:
                row_replay_savings_observed = True
                row_replay_saved_egraph_runs += explicit_replay_savings

            cache_status = metadata.get("cache_status")
            if type(cache_status) is str and cache_status:
                cache_status_counts[cache_status] += 1

            for field_name, target in (
                ("runtime_parity", runtime_parity),
                ("certificate_activation", certificate_activation),
            ):
                value = metadata.get(field_name)
                if isinstance(value, Mapping):
                    target.update(value)

            dispatch = metadata.get("structural_dispatch")
            dispatch_metadata = dispatch if isinstance(dispatch, Mapping) else metadata
            bucket_size = _metadata_number(dispatch_metadata, "bucket_size")
            if bucket_size is None:
                bucket_size = _metadata_number(metadata, "root_bucket_size")
            if bucket_size is not None:
                bucket_sizes.append(bucket_size)
            attempted = _metadata_number(dispatch_metadata, "attempted_rule_count")
            if attempted is not None:
                attempted_rules.append(attempted)
            if outcome.matcher is not None:
                comparisons.append(float(outcome.matcher.comparisons))
                flattened_arities.append(float(outcome.matcher.flattened_arity))
                lazy_swaps_total += outcome.matcher.lazy_swaps
                if outcome.matcher.stop_reason == "comparison_budget":
                    cap_refusals += 1
            if metadata.get("comparison_cap_refusal") is True:
                cap_refusals += 1
            reassociation = metadata.get("reassociation_coverage")
            if reassociation == "proved":
                reassociation_proved += 1
            elif reassociation == "pending":
                reassociation_pending += 1

            for name, source in (
                ("cold_snapshot_ms", "cold_snapshot_ms"),
                ("handler_startup_ms", "handler_startup_ms"),
                ("plugin_startup_ms", "plugin_startup_ms"),
                ("registration_pattern_count", "registration_pattern_count"),
                ("native_proof_invocations", "native_proof_invocations"),
                ("catalogue_compiler_invocations", "catalogue_compiler_invocations"),
            ):
                value = _metadata_number(metadata, source)
                if value is not None:
                    lifecycle_samples[name].append(value)
            if metadata.get("catalogue_cache_hit") is True:
                lifecycle_samples["catalogue_cache_hits"].append(1.0)

            mode = metadata.get("egraph_execution_mode")
            if type(mode) is not str or not mode:
                configured_mode = provider_modes.get(outcome.provider.value)
                mode = configured_mode if type(configured_mode) is str else None
            if type(mode) is not str or not mode:
                continue
            candidate_elapsed = _metadata_number(metadata, "candidate_elapsed_ms")
            if candidate_elapsed is None and outcome.status is not ProviderOutcomeStatus.UNAVAILABLE:
                # Provider adapters already measure this attempt.  Capture
                # metadata controls its execution lane, so this is real
                # candidate latency rather than a reporter-side estimate.
                candidate_elapsed = outcome.elapsed_ms
            if candidate_elapsed is not None:
                candidate_latencies[mode][outcome.provider.value].append(
                    candidate_elapsed
                )
            whole_elapsed = _metadata_number(metadata, "whole_function_elapsed_ms")
            if whole_elapsed is None:
                whole_elapsed = _metadata_number(whole_by_case, case.case_id)
            if whole_elapsed is not None:
                whole_function_latencies[mode][outcome.provider.value].append(
                    whole_elapsed
                )
            if metadata.get("root_only_strict_subisland_miss") is True:
                root_only_misses += 1

    if not normalization_counts and capture_normalization_counts:
        normalization_counts.update(capture_normalization_counts)
    if not raw_vs_canonical and capture_raw_vs_canonical:
        raw_vs_canonical.extend(capture_raw_vs_canonical)
    if not cache_status_counts and capture_cache_status_counts:
        cache_status_counts.update(capture_cache_status_counts)
    if row_replay_savings_observed:
        # Only the producer's explicit template measurement is additive
        # evidence.  A zero ``egraph_run_count`` on a replay is not itself a
        # measurement of the fresh work that the template replaced.
        replay_saved_egraph_runs = row_replay_saved_egraph_runs

    # A zero-win lane is evidence only when an e-graph outcome explicitly
    # reports that degree. Unavailable rows without degree metadata remain
    # unmeasured rather than being materialized as synthetic zeroes.
    for degree in observed_egraph_degrees:
        egraph_unique_by_degree.setdefault(degree, 0)

    def latency_stats(
        values: Mapping[str, Mapping[str, list[float]]],
    ) -> Mapping[str, Mapping[str, LatencyStats]]:
        return MappingProxyType(
            {
                mode: MappingProxyType(
                    {
                        provider: LatencyStats(
                            count=len(samples),
                            p50_ms=(
                                _percentile(samples, 0.50) if samples else None
                            ),
                            p95_ms=(
                                _percentile(samples, 0.95) if samples else None
                            ),
                        )
                        for provider, samples in sorted(by_provider.items())
                    }
                )
                for mode, by_provider in sorted(values.items())
            }
        )

    execution_latency = MappingProxyType(
        {
            path: LatencyStats(
                count=len(samples),
                p50_ms=_percentile(samples, 0.50) if samples else None,
                p95_ms=_percentile(samples, 0.95) if samples else None,
            )
            for path, samples in sorted(execution_path_latencies.items())
        }
    )

    duration_measurements = {
        "cold_snapshot_ms",
        "handler_startup_ms",
        "plugin_startup_ms",
    }
    lifecycle = MappingProxyType(
        {
            name: LifecycleMeasurement(
                count=len(samples),
                total=sum(samples),
                p50_ms=(
                    _percentile(samples, 0.50)
                    if name in duration_measurements
                    else None
                ),
                p95_ms=(
                    _percentile(samples, 0.95)
                    if name in duration_measurements
                    else None
                ),
            )
            for name, samples in sorted(lifecycle_samples.items())
        }
    )
    return RolloutEvidence(
        egraph_unique_wins_by_degree=MappingProxyType(dict(egraph_unique_by_degree)),
        external_reference_unique_wins=external_unique,
        nonlinear_residuals=nonlinear_residuals,
        refusals_by_reason=MappingProxyType(dict(sorted(refusals.items()))),
        matcher_bucket_size_p50=(
            _percentile(bucket_sizes, 0.50) if bucket_sizes else None
        ),
        matcher_attempted_rules_p95=(
            _percentile(attempted_rules, 0.95) if attempted_rules else None
        ),
        matcher_comparisons_p95=(
            _percentile(comparisons, 0.95) if comparisons else None
        ),
        matcher_lazy_swaps_total=lazy_swaps_total,
        matcher_flattened_arity_p95=(
            _percentile(flattened_arities, 0.95) if flattened_arities else None
        ),
        matcher_cap_refusals=cap_refusals,
        reassociation_proved=reassociation_proved,
        reassociation_pending=reassociation_pending,
        lifecycle_measurements=lifecycle,
        candidate_latency_by_mode=latency_stats(candidate_latencies),
        whole_function_latency_by_mode=latency_stats(whole_function_latencies),
        root_only_strict_subisland_misses=root_only_misses,
        normalization_counts_by_kind=MappingProxyType(
            dict(sorted(normalization_counts.items()))
        ),
        raw_vs_canonical_input_costs=tuple(
            sorted(
                raw_vs_canonical,
                key=lambda sample: (str(sample["case_id"]), str(sample["provider"])),
            )
        ),
        eligible_rule_measurements=MappingProxyType(
            dict(sorted(eligible_rule_measurements.items()))
        ),
        fixed_shift_admissions=(
            fixed_shift_admissions if fixed_shift_seen else None
        ),
        fixed_shift_refusals_by_reason=MappingProxyType(
            dict(sorted(fixed_shift_refusals.items()))
        ),
        rotate_extractions_by_width_direction=MappingProxyType(
            dict(sorted(rotate_extractions.items()))
        ),
        execution_path_counts=MappingProxyType(
            dict(sorted(execution_path_counts.items()))
        ),
        execution_path_latency=execution_latency,
        replay_saved_egraph_runs=replay_saved_egraph_runs,
        cache_status_counts=MappingProxyType(dict(sorted(cache_status_counts.items()))),
        cache_peak_entries=cache_peak_entries,
        cache_peak_bytes=cache_peak_bytes,
        runtime_parity=MappingProxyType(dict(runtime_parity)),
        certificate_activation=MappingProxyType(dict(certificate_activation)),
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
        rollout_evidence=_rollout_evidence(report),
    )


def normalize_outcome_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    corpus_identity: str,
    toolchain_identity: Mapping[str, str],
    expected_providers: Sequence[MbaProviderKind] = (),
    schema_version: int = 1,
    capture_metadata: Mapping[str, object] | None = None,
) -> MbaDifferentialReport:
    """Group flat portable outcome rows and reject ambiguous or missing coverage."""

    grouped: dict[
        str, tuple[str, MbaIslandProfile | None, list[MbaProviderOutcome]]
    ] = {}
    for row in rows:
        try:
            case_id = str(row["case_id"])
            stratum = str(row.get("stratum", "unclassified"))
            profile_value = row["profile"]
            outcome_value = row["outcome"]
        except KeyError as exc:
            raise ValueError(f"outcome row missing {exc.args[0]}") from exc
        profile = (
            None
            if profile_value is None
            else (
                profile_value
                if isinstance(profile_value, MbaIslandProfile)
                else profile_from_dict(profile_value)  # type: ignore[arg-type]
            )
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
        schema_version,
        corpus_identity,
        toolchain_identity,
        tuple(cases),
        {} if capture_metadata is None else capture_metadata,
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
            capture_metadata=data.get("capture_metadata", {}),  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid MBA differential report: {exc}") from exc


def summary_markdown(summary: DifferentialSummary) -> str:
    """Return a concise stable Markdown summary suitable for CI artifacts."""

    lines = [
        "| provider | attempts | unique | shared | misses | proof failures | unsafe abstentions | over budget | reconstruction failures | unavailable | node reduction | p50 ms | p95 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for provider, stats in sorted(
        summary.by_provider.items(), key=lambda item: item[0].value
    ):
        lines.append(
            "| {provider} | {attempts} | {unique_wins} | {shared_wins} | {misses} | "
            "{proof_failures} | {unsafe_abstentions} | {over_budget} | "
            "{reconstruction_failures} | {unavailable} | {node_reduction} | "
            "{p50_elapsed_ms:.3f} | {p95_elapsed_ms:.3f} |".format(
                provider=provider.value, **stats.to_dict()
            )
        )
    evidence = summary.rollout_evidence
    lines.extend(
        (
            "",
            "## Rollout evidence",
            "",
            "E-graph unique wins by degree: "
            + (
                ", ".join(
                    f"degree {degree}={count}"
                    for degree, count in sorted(
                        evidence.egraph_unique_wins_by_degree.items()
                    )
                )
                or "unmeasured"
            ),
            f"External-reference unique wins: {evidence.external_reference_unique_wins}",
            f"Nonlinear residuals: {evidence.nonlinear_residuals}",
            "Refusals by stable reason: "
            + (
                ", ".join(
                    f"{reason}={count}"
                    for reason, count in sorted(evidence.refusals_by_reason.items())
                )
                or "not measured"
            ),
            "Matcher: "
            f"bucket p50={_format_measurement(evidence.matcher_bucket_size_p50)}, "
            f"attempted-rule p95={_format_measurement(evidence.matcher_attempted_rules_p95)}, "
            f"comparison p95={_format_measurement(evidence.matcher_comparisons_p95)}, "
            f"lazy swaps={evidence.matcher_lazy_swaps_total}, "
            f"flattened-arity p95={_format_measurement(evidence.matcher_flattened_arity_p95)}, "
            f"cap refusals={evidence.matcher_cap_refusals}, "
            f"reassociation proved={evidence.reassociation_proved}, "
            f"pending={evidence.reassociation_pending}",
            "Lifecycle measurements: "
            + (
                ", ".join(
                    f"{name}=count:{measurement.count},total:{measurement.total}"
                    for name, measurement in sorted(
                        evidence.lifecycle_measurements.items()
                    )
                )
                or "not measured"
            ),
            "Candidate latency by mode: "
            + _format_latency_modes(evidence.candidate_latency_by_mode),
            "Whole-function latency by mode: "
            + _format_latency_modes(evidence.whole_function_latency_by_mode),
            "Root-only strict-sub-island misses: "
            f"{evidence.root_only_strict_subisland_misses}",
            "Normalization counts by kind: "
            + (
                ", ".join(
                    f"{kind}={count}"
                    for kind, count in sorted(
                        evidence.normalization_counts_by_kind.items()
                    )
                )
                or "not measured"
            ),
            "Raw versus canonical input costs (non-yield): "
            f"{len(evidence.raw_vs_canonical_input_costs)} samples",
            "Eligible rules: "
            + (
                ", ".join(
                    f"{name}={count}"
                    for name, count in sorted(
                        evidence.eligible_rule_measurements.items()
                    )
                )
                or "not measured"
            ),
            "Fixed-shift admissions: "
            + (
                "not measured"
                if evidence.fixed_shift_admissions is None
                else str(evidence.fixed_shift_admissions)
            )
            + "; refusals: "
            + (
                ", ".join(
                    f"{reason}={count}"
                    for reason, count in sorted(
                        evidence.fixed_shift_refusals_by_reason.items()
                    )
                )
                or "not measured"
            ),
            "Rotate extractions by width/direction: "
            + (
                ", ".join(
                    f"{key}={count}"
                    for key, count in sorted(
                        evidence.rotate_extractions_by_width_direction.items()
                    )
                )
                or "not measured"
            ),
            "Execution paths: "
            + (
                ", ".join(
                    f"{path.replace('_', ' ').capitalize()}={count}"
                    for path, count in sorted(evidence.execution_path_counts.items())
                )
                or "not measured"
            ),
            "Execution-path latency: "
            + (
                "; ".join(
                    f"{path}(n={stats.count},p50={_format_measurement(stats.p50_ms)},"
                    f"p95={_format_measurement(stats.p95_ms)})"
                    for path, stats in sorted(evidence.execution_path_latency.items())
                )
                or "not measured"
            ),
            "Replay saved e-graph runs: "
            + (
                "not measured"
                if evidence.replay_saved_egraph_runs is None
                else str(evidence.replay_saved_egraph_runs)
            ),
            "Cache status counts: "
            + (
                ", ".join(
                    f"{status}={count}"
                    for status, count in sorted(evidence.cache_status_counts.items())
                )
                or "not measured"
            )
            + "; peak entries="
            + (
                "not measured"
                if evidence.cache_peak_entries is None
                else str(evidence.cache_peak_entries)
            )
            + "; peak bytes="
            + (
                "not measured"
                if evidence.cache_peak_bytes is None
                else str(evidence.cache_peak_bytes)
            ),
            "Python/Cython parity: "
            + (json.dumps(dict(evidence.runtime_parity), sort_keys=True)
               if evidence.runtime_parity
               else "not measured"),
            "Certificate activation: "
            + (json.dumps(dict(evidence.certificate_activation), sort_keys=True)
               if evidence.certificate_activation
               else "not measured"),
        )
    )
    return "\n".join(lines) + "\n"


def _format_measurement(value: float | None) -> str:
    return "not measured" if value is None else f"{value:.3f}"


def _format_latency_modes(
    values: Mapping[str, Mapping[str, LatencyStats]],
) -> str:
    if not values:
        return "not measured"
    return "; ".join(
        f"{mode}: "
        + ", ".join(
            f"{provider}(n={stats.count},p50={_format_measurement(stats.p50_ms)},"
            f"p95={_format_measurement(stats.p95_ms)})"
            for provider, stats in sorted(by_provider.items())
        )
        for mode, by_provider in sorted(values.items())
    )


__all__ = [
    "DifferentialSummary",
    "LatencyStats",
    "LifecycleMeasurement",
    "MbaCorpusCaseReport",
    "MbaDifferentialReport",
    "ProviderDifferentialStats",
    "RolloutEvidence",
    "compare_provider_outcomes",
    "egraph_receipt_to_outcome",
    "normalize_outcome_rows",
    "outcome_from_dict",
    "profile_to_dict",
    "profile_from_dict",
    "report_from_dict",
    "summary_markdown",
]
