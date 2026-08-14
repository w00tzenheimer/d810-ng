"""Portable contracts for recording real native provider histories."""

from __future__ import annotations

import pytest

from d810.mba.island_profile import MbaIslandClass, MbaIslandProfile
from d810.mba.native_corpus_capture import (
    ManifestNativeCaptureCase,
    NativeMbaCorpusCapture,
    NativeProviderHistorySnapshot,
    capture_manifest_native_cases,
    capture_native_provider_case,
    native_profile_metadata,
    profiles_from_native_provider_histories,
    snapshot_native_provider_histories,
)
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


class _Provider:
    def __init__(self, *outcomes: MbaProviderOutcome) -> None:
        self._outcomes = list(outcomes)

    def provider_outcomes(self) -> tuple[MbaProviderOutcome, ...]:
        return tuple(self._outcomes)


class _TruncatedProvider(_Provider):
    def provider_outcome_cursor(self) -> int:
        return 0

    def provider_outcomes_since(self, cursor: int) -> tuple[MbaProviderOutcome, ...]:
        raise ValueError("provider outcome history was truncated after the capture cursor")


def _profile(fingerprint: str = "native-shape") -> MbaIslandProfile:
    return MbaIslandProfile(
        width_bits=32,
        operator_count=4,
        total_node_count=7,
        distinct_leaf_count=2,
        constant_count=1,
        operations=(("add", 2), ("and", 1), ("xor", 1)),
        has_boolean=True,
        has_arithmetic=True,
        nonlinear_product_count=0,
        island_class=MbaIslandClass.LINEAR_MBA,
        blockers=(),
        fingerprint=fingerprint,
    )


def _outcome(
    provider: MbaProviderKind,
    status: ProviderOutcomeStatus,
    profile: MbaIslandProfile,
) -> MbaProviderOutcome:
    return MbaProviderOutcome(
        provider=provider,
        status=status,
        fingerprint=profile.fingerprint,
        input_cost=(4, 7),
        output_cost=(2, 3),
        metadata={"native_profile": native_profile_metadata(profile)},
    )


def test_capture_uses_actual_profile_and_one_final_history_row_per_provider(
    tmp_path,
) -> None:
    profile = _profile()
    catalogue = _Provider(
        _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.UNCHANGED, profile),
        _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.APPLIED, profile),
        _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.UNCHANGED, profile),
    )
    absent_egglog = _Provider()

    assert profiles_from_native_provider_histories((catalogue,)) == (profile,)
    case = capture_native_provider_case(
        case_id="catalogue_01",
        stratum="catalogue",
        profile=profile,
        rules=(catalogue, absent_egglog),
    )
    assert [outcome.provider for outcome in case.outcomes] == [
        MbaProviderKind.CATALOGUE
    ]
    assert case.outcomes[0].status is ProviderOutcomeStatus.APPLIED

    capture = NativeMbaCorpusCapture(
        corpus_identity="actual-native-corpus",
        toolchain_identity={"ida": "9.4", "engine": "cython"},
    )
    capture.add_case(
        case_id="catalogue_01",
        stratum="catalogue",
        profile=profile,
        rules=(catalogue, absent_egglog),
    )
    output_path = tmp_path / "capture.json"
    capture.write_json(output_path)
    encoded = output_path.read_text(encoding="utf-8")
    assert '"provider": "catalogue"' in encoded
    assert "unavailable" not in encoded


def test_capture_rejects_missing_or_conflicting_actual_profile_evidence() -> None:
    profile = _profile()
    missing = MbaProviderOutcome(
        provider=MbaProviderKind.CATALOGUE,
        status=ProviderOutcomeStatus.UNCHANGED,
        fingerprint=profile.fingerprint,
    )
    with pytest.raises(ValueError, match="native_profile"):
        capture_native_provider_case(
            case_id="missing",
            stratum="catalogue",
            profile=profile,
            rules=(_Provider(missing),),
        )
    with pytest.raises(ValueError, match="at most one applied"):
        capture_native_provider_case(
            case_id="duplicate-applied",
            stratum="catalogue",
            profile=profile,
            rules=(
                _Provider(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.APPLIED,
                        profile,
                    )
                ),
                _Provider(
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.APPLIED,
                        profile,
                    )
                ),
            ),
        )


def test_capture_snapshot_excludes_prior_decompilation_history() -> None:
    profile = _profile()
    provider = _Provider(
        _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.APPLIED, profile)
    )
    snapshot = snapshot_native_provider_histories((provider,))
    provider._outcomes.append(
        _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.UNCHANGED, profile)
    )

    case = capture_native_provider_case(
        case_id="new-decompilation-only",
        stratum="catalogue",
        profile=profile,
        rules=(provider,),
        history_snapshot=snapshot,
    )

    assert case.outcomes[0].status is ProviderOutcomeStatus.UNCHANGED


def test_capture_emits_declared_unavailable_rows_for_missing_provider_history() -> None:
    """The manifest provider matrix is complete even when a provider did not run."""

    profile = _profile()
    case = capture_native_provider_case(
        case_id="complete-matrix",
        stratum="catalogue",
        profile=profile,
        rules=(
            _Provider(
                _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.APPLIED, profile)
            ),
        ),
        expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGGLOG),
    )

    assert [(outcome.provider, outcome.status) for outcome in case.outcomes] == [
        (MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.APPLIED),
        (MbaProviderKind.EGGLOG, ProviderOutcomeStatus.UNAVAILABLE),
    ]


def test_manifest_runner_snapshots_each_case_and_rejects_evicted_delta() -> None:
    profile = _profile()
    provider = _Provider()
    seen: list[str] = []

    def run_case(
        case: ManifestNativeCaptureCase,
        snapshot: NativeProviderHistorySnapshot,
    ) -> MbaIslandProfile:
        seen.append(case.case_id)
        assert snapshot.outcome_counts_by_rule_id[id(provider)] == len(provider._outcomes)
        provider._outcomes.append(
            _outcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.APPLIED, profile)
        )
        return profile

    capture = NativeMbaCorpusCapture("manifest", {"runtime": "python"})
    cases = (
        ManifestNativeCaptureCase("one", "catalogue"),
        ManifestNativeCaptureCase("two", "catalogue"),
    )
    captured = capture_manifest_native_cases(
        capture=capture,
        cases=cases,
        rules=(provider,),
        expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGGLOG),
        run_case=run_case,
    )

    assert seen == ["one", "two"]
    assert [case.case_id for case in captured] == ["one", "two"]
    assert all(len(case.outcomes) == 2 for case in captured)


def test_manifest_runner_fails_closed_when_a_case_delta_is_truncated() -> None:
    capture = NativeMbaCorpusCapture("manifest", {"runtime": "python"})
    with pytest.raises(ValueError, match="truncated"):
        capture_manifest_native_cases(
            capture=capture,
            cases=(ManifestNativeCaptureCase("evicted", "catalogue"),),
            rules=(_TruncatedProvider(),),
            expected_providers=(MbaProviderKind.CATALOGUE,),
            run_case=lambda _case, _snapshot: _profile(),
        )
