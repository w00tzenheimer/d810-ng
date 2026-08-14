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
_PROOF_MODES = frozenset({"legacy_native_ast", "shadow", "native_template"})


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
        if not self.expected_sources or not self.expected_outcomes:
            raise ValueError("corpus entry must declare expected outcomes")
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
    proof_mode: str,
) -> dict[str, object]:
    """Serialize every live provider attempt for a fixed real-IDB entry."""

    if proof_mode not in _PROOF_MODES:
        raise ValueError("unknown native proof mode")
    outcomes = tuple(attempts)
    if not outcomes:
        raise ValueError("corpus must contain at least one live attempt")
    if any(outcome.provider.value != "egglog" for outcome in outcomes):
        raise ValueError("corpus must contain only Egglog provider attempts")

    stage_counts = Counter()
    for outcome in outcomes:
        _stage_timings(outcome)
        if (
            outcome.status
            not in {ProviderOutcomeStatus.APPLIED, ProviderOutcomeStatus.IMPROVED}
            and outcome.refusal_reason is None
        ):
            raise ValueError(
                "refused live attempt requires a structured refusal reason"
            )
        stage_counts.update(_stage_timings(outcome).keys())

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
        "schema_version": 2,
        "corpus": entry.corpus,
        "function": entry.function,
        "project": entry.project,
        "execution_count": len(outcomes),
        "candidate_identities": [
            f"{entry.corpus}#{index}:{outcome.fingerprint}"
            for index, outcome in enumerate(outcomes, start=1)
        ],
        "outcomes": dict(sorted(Counter(statuses).items())),
        "source_names": [list(source) for source in sources],
        "proof_mode_counts": {proof_mode: len(outcomes)},
        "stage_sample_counts": dict(sorted(stage_counts.items())),
    }


__all__ = [
    "NativeEgglogCorpusEntry",
    "build_native_egglog_attempt_receipt",
]
