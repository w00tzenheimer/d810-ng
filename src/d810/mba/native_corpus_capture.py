"""Fail-closed producer for native MBA provider-history corpus captures.

The differential-report CLI is intentionally a JSON consumer.  This module is
the separate runtime producer: it turns the histories retained by actually
activated providers into normal portable report rows without inventing attempts
for providers that did not run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from d810.mba.differential_report import (
    MbaCorpusCaseReport,
    MbaDifferentialReport,
    profile_from_dict,
    profile_to_dict,
)
from d810.mba.island_profile import MbaIslandProfile
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus


_NATIVE_PROFILE_METADATA_KEY = "native_profile"


@dataclass(frozen=True)
class NativeProviderHistorySnapshot:
    """Per-rule history lengths captured immediately before one decompilation."""

    outcome_counts_by_rule_id: Mapping[int, int]


def native_profile_metadata(profile: MbaIslandProfile) -> dict[str, object]:
    """Return the JSON-safe profile snapshot bound to a provider outcome."""

    return profile_to_dict(profile)


def native_profile_from_outcome(outcome: MbaProviderOutcome) -> MbaIslandProfile:
    """Recover and validate the actual profile recorded with one outcome."""

    metadata = outcome.metadata or {}
    raw_profile = metadata.get(_NATIVE_PROFILE_METADATA_KEY)
    if not isinstance(raw_profile, Mapping):
        raise ValueError(
            "native provider outcome is missing its native_profile metadata"
        )
    profile = profile_from_dict(raw_profile)
    if profile.fingerprint != outcome.fingerprint:
        raise ValueError(
            "native provider outcome profile fingerprint does not match outcome"
        )
    return profile


def _history_for_provider(
    rule: object,
    snapshot: NativeProviderHistorySnapshot | None = None,
) -> tuple[MbaProviderOutcome, ...]:
    method = getattr(rule, "provider_outcomes", None)
    if not callable(method):
        return ()
    outcomes = tuple(method())
    if any(not isinstance(outcome, MbaProviderOutcome) for outcome in outcomes):
        raise ValueError("provider_outcomes must return MbaProviderOutcome objects")
    if snapshot is None:
        return outcomes
    try:
        start = snapshot.outcome_counts_by_rule_id[id(rule)]
    except KeyError as exc:
        raise ValueError("provider was not present in the history snapshot") from exc
    since = getattr(rule, "provider_outcomes_since", None)
    if callable(since):
        return tuple(since(start))
    if len(outcomes) < start:
        raise ValueError("provider history was reset after the capture snapshot")
    return outcomes[start:]


def snapshot_native_provider_histories(
    rules: Iterable[object],
) -> NativeProviderHistorySnapshot:
    """Anchor capture to exactly the attempts from one later decompilation."""

    selected = tuple(rules)
    def cursor(rule: object) -> int:
        method = getattr(rule, "provider_outcome_cursor", None)
        if callable(method):
            return int(method())
        return len(_history_for_provider(rule))

    return NativeProviderHistorySnapshot(
        outcome_counts_by_rule_id={
            id(rule): cursor(rule) for rule in selected
        }
    )


@contextmanager
def capture_native_provider_histories(rules: Iterable[object]):
    """Retain bounded provider outcomes only while a caller captures one run."""

    selected = tuple(rules)
    started: list[object] = []
    try:
        for rule in selected:
            begin = getattr(rule, "begin_provider_outcome_capture", None)
            if callable(begin):
                begin()
                started.append(rule)
        yield selected
    finally:
        for rule in reversed(started):
            end = getattr(rule, "end_provider_outcome_capture", None)
            if callable(end):
                end()


def profiles_from_native_provider_histories(
    rules: Iterable[object],
    *,
    history_snapshot: NativeProviderHistorySnapshot | None = None,
) -> tuple[MbaIslandProfile, ...]:
    """Return the distinct actual profiles observed during one decompilation."""

    profiles: dict[str, MbaIslandProfile] = {}
    for rule in rules:
        for outcome in _history_for_provider(rule, history_snapshot):
            if outcome.fingerprint == "profile_unavailable":
                continue
            profile = native_profile_from_outcome(outcome)
            previous = profiles.setdefault(profile.fingerprint, profile)
            if previous != profile:
                raise ValueError(
                    "same native profile fingerprint has conflicting serialized profiles"
                )
    return tuple(profiles[fingerprint] for fingerprint in sorted(profiles))


def _final_provider_outcome(
    outcomes: tuple[MbaProviderOutcome, ...],
) -> MbaProviderOutcome:
    """Select one actual terminal observation, never synthesizing a result."""

    applied = tuple(
        outcome
        for outcome in outcomes
        if outcome.status is ProviderOutcomeStatus.APPLIED
    )
    # An accepted mutation must not be hidden by later non-mutating probes in
    # the same function.  Within an equal status, preserve history order.
    return applied[-1] if applied else outcomes[-1]


def capture_native_provider_case(
    *,
    case_id: str,
    stratum: str,
    profile: MbaIslandProfile,
    rules: Iterable[object],
    history_snapshot: NativeProviderHistorySnapshot | None = None,
) -> MbaCorpusCaseReport:
    """Produce exactly one final row per actually observed provider.

    Only outcomes for the declared, actual profile fingerprint participate.
    Providers without a matching history are absent; callers must not convert
    absence into ``UNAVAILABLE`` because that would be invented telemetry.
    """

    grouped: dict[object, list[MbaProviderOutcome]] = {}
    for rule in rules:
        for outcome in _history_for_provider(rule, history_snapshot):
            if outcome.fingerprint != profile.fingerprint:
                continue
            recorded_profile = native_profile_from_outcome(outcome)
            if recorded_profile != profile:
                raise ValueError(
                    "native provider outcome profile does not match requested case"
                )
            grouped.setdefault(outcome.provider, []).append(outcome)
    final_outcomes = tuple(
        _final_provider_outcome(tuple(outcomes))
        for _provider, outcomes in sorted(grouped.items(), key=lambda item: str(item[0]))
    )
    return MbaCorpusCaseReport(
        case_id=case_id,
        profile=profile,
        outcomes=final_outcomes,
        stratum=stratum,
    )


@dataclass
class NativeMbaCorpusCapture:
    """Accumulate real per-case provider histories into one report artifact."""

    corpus_identity: str
    toolchain_identity: Mapping[str, str]
    _cases: list[MbaCorpusCaseReport] = field(default_factory=list)

    def add_case(
        self,
        *,
        case_id: str,
        stratum: str,
        profile: MbaIslandProfile,
        rules: Iterable[object],
        history_snapshot: NativeProviderHistorySnapshot | None = None,
    ) -> MbaCorpusCaseReport:
        case = capture_native_provider_case(
            case_id=case_id,
            stratum=stratum,
            profile=profile,
            rules=rules,
            history_snapshot=history_snapshot,
        )
        self._cases.append(case)
        return case

    def report(self) -> MbaDifferentialReport:
        return MbaDifferentialReport(
            schema_version=1,
            corpus_identity=self.corpus_identity,
            toolchain_identity=self.toolchain_identity,
            cases=tuple(self._cases),
        )

    def write_json(self, path: Path) -> None:
        """Write the normal differential-report wire shape for the existing CLI."""

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.report().to_json(), encoding="utf-8")


__all__ = [
    "NativeMbaCorpusCapture",
    "NativeProviderHistorySnapshot",
    "capture_native_provider_case",
    "capture_native_provider_histories",
    "native_profile_from_outcome",
    "native_profile_metadata",
    "profiles_from_native_provider_histories",
    "snapshot_native_provider_histories",
]
