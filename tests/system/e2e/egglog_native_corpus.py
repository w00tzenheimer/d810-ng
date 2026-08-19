"""Immutable real-IDB Egglog corpus declarations and attempt receipts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus


_STAGE_ORDER = (
    "root_eligibility",
    "native_preflight",
    "egglog_extraction",
    "ast_construction",
    "native_z3",
    "reconstruction",
)
_PROOF_MODES = frozenset({"legacy", "shadow"})


@dataclass(frozen=True)
class NativeEgglogCorpusEntry:
    """One real-IDB function with stable expected Egglog outcomes."""

    corpus: str
    function: str
    project: str
    expected_sources: tuple[tuple[str, ...], ...]
    expected_outcomes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("corpus", "function", "project"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if bool(self.expected_sources) != bool(self.expected_outcomes):
            raise ValueError(
                "corpus expected sources and outcomes must both be empty or set"
            )
        if len(self.expected_sources) != len(self.expected_outcomes):
            raise ValueError("corpus expected sources and outcomes must align")
        if any(
            not source or any(type(name) is not str or not name for name in source)
            for source in self.expected_sources
        ):
            raise ValueError("corpus expected sources must be non-empty strings")
        if any(
            type(outcome) is not str or not outcome
            for outcome in self.expected_outcomes
        ):
            raise ValueError("corpus expected outcomes must be non-empty strings")


def _stage_timings(outcome: MbaProviderOutcome) -> Mapping[str, object]:
    metadata = outcome.metadata or {}
    timings = metadata.get("stage_timings_ms")
    if not isinstance(timings, Mapping) or not timings:
        raise ValueError("live attempt must provide a stage schema")
    names = tuple(timings)
    if not set(names).issubset(_STAGE_ORDER):
        raise ValueError("live attempt must provide only known stages")
    if any(type(timings[name]) is not float or timings[name] < 0 for name in names):
        raise ValueError("live attempt stage timings must be non-negative floats")
    return timings


def build_native_egglog_attempt_receipt(
    attempts: Iterable[MbaProviderOutcome],
    *,
    entry: NativeEgglogCorpusEntry,
) -> dict[str, object]:
    """Serialize every live provider attempt for a fixed real-IDB entry."""

    outcomes = tuple(attempts)
    if not outcomes:
        raise ValueError("corpus must contain at least one live attempt")
    if any(outcome.provider.value != "egraph" for outcome in outcomes):
        raise ValueError("corpus must contain only e-graph provider attempts")

    stage_counts = Counter()
    serialized_attempts: list[dict[str, object]] = []
    proof_mode_counts = Counter()
    for outcome in outcomes:
        timings = _stage_timings(outcome)
        if (
            outcome.status
            not in {ProviderOutcomeStatus.APPLIED, ProviderOutcomeStatus.IMPROVED}
            and outcome.refusal_reason is None
        ):
            raise ValueError(
                "refused live attempt requires a structured refusal reason"
            )
        stage_counts.update(timings.keys())
        metadata = outcome.metadata or {}
        template_verdict = metadata.get("template_proof_verdict")
        legacy_verdict = metadata.get("legacy_proof_verdict")
        if template_verdict is not None and type(template_verdict) is not bool:
            raise ValueError("template proof verdict must be boolean or null")
        if legacy_verdict is not None and type(legacy_verdict) is not bool:
            raise ValueError("legacy proof verdict must be boolean or null")
        proof_attempted = template_verdict is not None or legacy_verdict is not None
        proof_mode = metadata.get("proof_mode") if proof_attempted else None
        if proof_mode not in _PROOF_MODES and proof_mode is not None:
            raise ValueError("live proof attempt has an unknown mode")
        if proof_mode is not None:
            proof_mode_counts[proof_mode] += 1
        source = tuple(outcome.source_provenance)
        serialized_attempts.append(
            {
                "candidate_identity": f"{entry.corpus}#{len(serialized_attempts) + 1}:{outcome.fingerprint}",
                "status": outcome.status.value,
                "refusal_reason": outcome.refusal_reason,
                "source_names": list(source),
                "degree": metadata.get("degree"),
                "input_cost": (
                    None if outcome.input_cost is None else list(outcome.input_cost)
                ),
                "output_cost": (
                    None if outcome.output_cost is None else list(outcome.output_cost)
                ),
                "stage_timings_ms": dict(timings),
                "proof_mode": proof_mode,
                "template_source_name": metadata.get("template_source_name"),
                "template_fallback_reason": metadata.get("template_fallback_reason"),
                "template_proof_verdict": template_verdict,
                "legacy_proof_verdict": legacy_verdict,
                "template_proof_elapsed_ms": metadata.get("template_proof_elapsed_ms"),
                "legacy_proof_elapsed_ms": metadata.get("legacy_proof_elapsed_ms"),
                "native_matcher_backend": metadata.get("native_matcher_backend"),
                "native_matcher_comparisons": metadata.get(
                    "native_matcher_comparisons"
                ),
                "native_matcher_lazy_swaps": metadata.get("native_matcher_lazy_swaps"),
                "native_fixed_binding_count": metadata.get(
                    "native_fixed_binding_count"
                ),
                "native_matcher_elapsed_ms": metadata.get("native_matcher_elapsed_ms"),
            }
        )

    statuses = tuple(outcome.status.value for outcome in outcomes)
    sources = tuple(tuple(outcome.source_provenance) for outcome in outcomes)
    applied = tuple(
        outcome
        for outcome in outcomes
        if outcome.status is ProviderOutcomeStatus.APPLIED
    )
    if tuple(outcome.status.value for outcome in applied) != entry.expected_outcomes:
        raise ValueError("live applied outcomes differ from corpus manifest")
    if (
        tuple(outcome.source_provenance for outcome in applied)
        != entry.expected_sources
    ):
        raise ValueError("live applied source provenance differs from corpus manifest")

    return {
        "schema_version": 3,
        "corpus": entry.corpus,
        "function": entry.function,
        "project": entry.project,
        "execution_count": len(outcomes),
        "candidate_identities": [
            attempt["candidate_identity"] for attempt in serialized_attempts
        ],
        "outcomes": dict(sorted(Counter(statuses).items())),
        "source_names": [list(source) for source in sources],
        "proof_attempt_count": sum(proof_mode_counts.values()),
        "proof_mode_counts": dict(sorted(proof_mode_counts.items())),
        "stage_sample_counts": dict(sorted(stage_counts.items())),
        "attempts": serialized_attempts,
    }


__all__ = [
    "NativeEgglogCorpusEntry",
    "build_native_egglog_attempt_receipt",
]
