"""Fail-closed producer for native MBA provider-history corpus captures.

The differential-report CLI is intentionally a JSON consumer.  This module is
the separate runtime producer: it turns the histories retained by actually
activated providers into normal portable report rows without inventing attempts
for providers that did not run.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from d810.mba.differential_report import (
    MbaCorpusCaseReport,
    MbaDifferentialReport,
)
from d810.mba.island_profile import MbaIslandProfile, profile_from_dict, profile_to_dict
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


_NATIVE_PROFILE_METADATA_KEY = "native_profile"
_NATIVE_CANDIDATE_NOT_OBSERVED = "native_candidate_not_observed"


@dataclass(frozen=True)
class NativeProviderHistorySnapshot:
    """Per-rule history lengths captured immediately before one decompilation."""

    outcome_counts_by_rule_id: Mapping[int, int]


@dataclass(frozen=True)
class ManifestNativeCaptureCase:
    """One declared native-capture invocation from the corpus manifest."""

    case_id: str
    stratum: str

    def __post_init__(self) -> None:
        if type(self.case_id) is not str or not self.case_id:
            raise ValueError("manifest capture case_id must be a non-empty string")
        if type(self.stratum) is not str or not self.stratum:
            raise ValueError("manifest capture stratum must be a non-empty string")


@dataclass(frozen=True)
class NativeCaptureSelection:
    """One exact native candidate selection or an explicit no-profile reason."""

    profile: MbaIslandProfile | None
    unavailable_reason: str = _NATIVE_CANDIDATE_NOT_OBSERVED

    def __post_init__(self) -> None:
        if self.profile is not None:
            if not isinstance(self.profile, MbaIslandProfile):
                raise ValueError("native capture profile must be MbaIslandProfile or None")
            if self.unavailable_reason != _NATIVE_CANDIDATE_NOT_OBSERVED:
                raise ValueError("a selected profile cannot have an unavailable reason")
        elif self.unavailable_reason not in {
            _NATIVE_CANDIDATE_NOT_OBSERVED,
            "native_candidate_ambiguous",
        }:
            raise ValueError("unknown native capture unavailable reason")


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


def _has_native_profile(outcome: MbaProviderOutcome) -> bool:
    return isinstance((outcome.metadata or {}).get(_NATIVE_PROFILE_METADATA_KEY), Mapping)


def _native_profile_key_present(outcome: MbaProviderOutcome) -> bool:
    """Return whether an outcome explicitly supplied native-profile metadata."""

    return _NATIVE_PROFILE_METADATA_KEY in (outcome.metadata or {})


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


def select_native_capture_profile(
    rules: Iterable[object],
    *,
    history_snapshot: NativeProviderHistorySnapshot | None = None,
    preferred_providers: Sequence[MbaProviderKind] = (),
) -> MbaIslandProfile:
    """Select one actual candidate profile or reject ambiguous capture evidence.

    A manifest case may name the provider expected to own its native root.  That
    narrows selection only among profiles actually emitted by that provider;
    it never derives a profile from a function, a microinstruction fragment,
    or source-level expectation.  No preferred provider means exactly one
    observed profile is required.
    """

    preferred = frozenset(preferred_providers)
    profiles: dict[str, MbaIslandProfile] = {}
    for rule in rules:
        for outcome in _history_for_provider(rule, history_snapshot):
            if preferred and outcome.provider not in preferred:
                continue
            if outcome.fingerprint == "profile_unavailable" or not _has_native_profile(
                outcome
            ):
                continue
            profile = native_profile_from_outcome(outcome)
            previous = profiles.setdefault(profile.fingerprint, profile)
            if previous != profile:
                raise ValueError(
                    "same native profile fingerprint has conflicting serialized profiles"
                )
    if len(profiles) != 1:
        observed = ", ".join(sorted(profiles)) or "none"
        raise ValueError(f"ambiguous native capture profile: {observed}")
    return next(iter(profiles.values()))


def _final_provider_outcome(
    outcomes: tuple[MbaProviderOutcome, ...],
) -> MbaProviderOutcome:
    """Select one actual terminal observation, never synthesizing a result."""

    applied = tuple(
        outcome
        for outcome in outcomes
        if outcome.status is ProviderOutcomeStatus.APPLIED
    )
    if len(applied) > 1:
        raise ValueError(
            "at most one applied outcome is allowed for one provider capture"
        )
    # An accepted mutation must not be hidden by later non-mutating probes in
    # the same function.  Within an equal status, preserve history order.
    return applied[0] if applied else outcomes[-1]


def capture_native_provider_case(
    *,
    case_id: str,
    stratum: str,
    profile: MbaIslandProfile | None,
    rules: Iterable[object],
    history_snapshot: NativeProviderHistorySnapshot | None = None,
    expected_providers: Sequence[MbaProviderKind] = (),
    unavailable_reason: str = _NATIVE_CANDIDATE_NOT_OBSERVED,
) -> MbaCorpusCaseReport:
    """Produce exactly one final row per actually observed provider.

    Only outcomes for the declared, actual profile fingerprint participate.
    A declared provider matrix is the one exception to absent-history rows:
    the capture records ``UNAVAILABLE`` with a stable refusal reason. This is
    explicit coverage evidence, not an invented provider attempt.
    """

    expected = tuple(expected_providers)
    if expected and len(set(expected)) != len(expected):
        raise ValueError("expected_providers must not contain duplicates")
    if profile is None:
        if not expected:
            raise ValueError(
                "missing native candidate evidence requires declared provider coverage"
            )
        return MbaCorpusCaseReport(
            case_id=case_id,
            stratum=stratum,
            profile=None,
            outcomes=tuple(
                MbaProviderOutcome(
                    provider=provider,
                    status=ProviderOutcomeStatus.UNAVAILABLE,
                    fingerprint=f"{unavailable_reason}:{case_id}",
                    refusal_reason=unavailable_reason,
                    metadata={"native_capture": unavailable_reason},
                )
                for provider in expected
            ),
        )

    grouped: dict[object, list[MbaProviderOutcome]] = {}
    for rule in rules:
        for outcome in _history_for_provider(rule, history_snapshot):
            if outcome.fingerprint != profile.fingerprint:
                continue
            # A provider can report that the candidate is ineligible after a
            # previous provider established the island fingerprint.  That
            # refusal is not native-profile evidence and, by design, carries
            # no profile metadata.  Retain the refusal as provider telemetry,
            # while keeping strict validation for every other matching
            # outcome: an observed candidate outcome must still be
            # self-describing.
            if (
                outcome.status is ProviderOutcomeStatus.INELIGIBLE
                and not _native_profile_key_present(outcome)
            ):
                grouped.setdefault(outcome.provider, []).append(outcome)
                continue
            recorded_profile = native_profile_from_outcome(outcome)
            if recorded_profile != profile:
                raise ValueError(
                    "native provider outcome profile does not match requested case"
                )
            grouped.setdefault(outcome.provider, []).append(outcome)
    final_by_provider = {
        provider: _final_provider_outcome(tuple(outcomes))
        for provider, outcomes in grouped.items()
    }
    if expected:
        unexpected = frozenset(final_by_provider) - frozenset(expected)
        if unexpected:
            names = ", ".join(sorted(provider.value for provider in unexpected))
            raise ValueError(f"native capture observed undeclared providers: {names}")
        for provider in expected:
            final_by_provider.setdefault(
                provider,
                MbaProviderOutcome(
                    provider=provider,
                    status=ProviderOutcomeStatus.UNAVAILABLE,
                    fingerprint=profile.fingerprint,
                    refusal_reason="provider_not_observed",
                    metadata={_NATIVE_PROFILE_METADATA_KEY: native_profile_metadata(profile)},
                ),
            )
    final_outcomes = tuple(
        final_by_provider[provider]
        for provider in (expected or tuple(sorted(final_by_provider, key=str)))
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
    _capture_metadata: dict[str, object] = field(default_factory=dict)

    def set_capture_metadata(self, metadata: Mapping[str, object]) -> None:
        """Attach measured run-level evidence before the report is rendered.

        This deliberately accepts only one immutable recording for each key.
        A runner must not average, overwrite, or fabricate a measurement after
        the fact; repeated evidence is represented as a list in that one value.
        """

        for key, value in metadata.items():
            if type(key) is not str or not key:
                raise ValueError("capture metadata keys must be non-empty strings")
            if key in self._capture_metadata:
                raise ValueError(f"capture metadata already records {key}")
            self._capture_metadata[key] = value

    def add_case(
        self,
        *,
        case_id: str,
        stratum: str,
        profile: MbaIslandProfile | None,
        rules: Iterable[object],
        history_snapshot: NativeProviderHistorySnapshot | None = None,
        expected_providers: Sequence[MbaProviderKind] = (),
        unavailable_reason: str = _NATIVE_CANDIDATE_NOT_OBSERVED,
    ) -> MbaCorpusCaseReport:
        case = capture_native_provider_case(
            case_id=case_id,
            stratum=stratum,
            profile=profile,
            rules=rules,
            history_snapshot=history_snapshot,
            expected_providers=expected_providers,
            unavailable_reason=unavailable_reason,
        )
        self._cases.append(case)
        return case

    def report(self) -> MbaDifferentialReport:
        return MbaDifferentialReport(
            schema_version=1,
            corpus_identity=self.corpus_identity,
            toolchain_identity=self.toolchain_identity,
            cases=tuple(self._cases),
            capture_metadata=self._capture_metadata,
        )

    def write_json(self, path: Path) -> None:
        """Write the normal differential-report wire shape for the existing CLI."""

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.report().to_json(), encoding="utf-8")


def capture_manifest_native_cases(
    *,
    capture: NativeMbaCorpusCapture,
    cases: Sequence[ManifestNativeCaptureCase],
    rules: Iterable[object],
    expected_providers: Sequence[MbaProviderKind],
    run_case: Callable[
        [ManifestNativeCaptureCase, NativeProviderHistorySnapshot],
        MbaIslandProfile | NativeCaptureSelection | None,
    ],
) -> tuple[MbaCorpusCaseReport, ...]:
    """Run and capture every declared case as one exact bounded-history delta.

    ``run_case`` owns native decompilation.  The portable coordinator owns the
    evidence boundary: it snapshots before each invocation and consumes the
    resulting delta immediately, so a later case cannot evict or inherit it.
    """

    selected_rules = tuple(rules)
    declared_cases = tuple(cases)
    identifiers = tuple(case.case_id for case in declared_cases)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("manifest capture cases must have unique case_id values")
    captured: list[MbaCorpusCaseReport] = []
    for case in declared_cases:
        # Provider adapters are session-long objects.  Each function gets its
        # own bounded retention window so a prior case cannot consume the
        # current case's fixed-capacity evidence budget.
        with capture_native_provider_histories(selected_rules):
            snapshot = snapshot_native_provider_histories(selected_rules)
            selected = run_case(case, snapshot)
            selection = (
                selected
                if isinstance(selected, NativeCaptureSelection)
                else NativeCaptureSelection(selected)
            )
            profile = selection.profile
            if profile is not None and not isinstance(profile, MbaIslandProfile):
                raise TypeError(
                    "manifest native runner must return MbaIslandProfile or None"
                )
            captured.append(
                capture.add_case(
                    case_id=case.case_id,
                    stratum=case.stratum,
                    profile=profile,
                    rules=selected_rules,
                    history_snapshot=snapshot,
                    expected_providers=expected_providers,
                    unavailable_reason=selection.unavailable_reason,
                )
            )
    return tuple(captured)


__all__ = [
    "NativeMbaCorpusCapture",
    "NativeCaptureSelection",
    "NativeProviderHistorySnapshot",
    "ManifestNativeCaptureCase",
    "capture_manifest_native_cases",
    "capture_native_provider_case",
    "capture_native_provider_histories",
    "native_profile_from_outcome",
    "native_profile_metadata",
    "profiles_from_native_provider_histories",
    "select_native_capture_profile",
    "snapshot_native_provider_histories",
]
