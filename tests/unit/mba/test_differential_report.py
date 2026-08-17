"""Tests for portable MBA provider differential reporting."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from d810.mba.differential_report import (
    MbaCorpusCaseReport,
    MbaDifferentialReport,
    compare_provider_outcomes,
    egglog_receipt_to_outcome,
    normalize_outcome_rows,
    outcome_from_dict,
    report_from_dict,
    summary_markdown,
)
from d810.mba.island_profile import IslandBlocker, MbaIslandClass, MbaIslandProfile
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


_ROOT = Path(__file__).resolve().parents[3]
_REPORT_CLI = _ROOT / "tools/scripts/mba_differential_report.py"


def _report_cli_module():
    spec = importlib.util.spec_from_file_location("mba_differential_report_cli", _REPORT_CLI)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _profile(fingerprint: str) -> MbaIslandProfile:
    return MbaIslandProfile(
        width_bits=32,
        operator_count=4,
        total_node_count=7,
        distinct_leaf_count=2,
        constant_count=1,
        operations=(("add", 2), ("and", 1), ("or", 1)),
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
    fingerprint: str,
    *,
    elapsed_ms: float = 1.0,
    input_cost: tuple[int, int] | None = (4, 7),
    output_cost: tuple[int, int] | None = (2, 3),
) -> MbaProviderOutcome:
    return MbaProviderOutcome(
        provider=provider,
        status=status,
        fingerprint=fingerprint,
        elapsed_ms=elapsed_ms,
        input_cost=input_cost,
        output_cost=output_cost,
        proof_verdict=status is not ProviderOutcomeStatus.PROOF_FAILED,
    )


def test_summary_keeps_unique_shared_miss_proof_abstention_and_unavailable_distinct() -> (
    None
):
    first = _profile("first")
    second = _profile("second")
    third = _profile("third")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="unit-corpus",
        toolchain_identity={"compiler": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="chain-only",
                profile=first,
                stratum="chain",
                outcomes=(
                    _outcome(
                        MbaProviderKind.STRUCTURAL_CHAIN,
                        ProviderOutcomeStatus.APPLIED,
                        first.fingerprint,
                        elapsed_ms=1.0,
                    ),
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.UNCHANGED,
                        first.fingerprint,
                        elapsed_ms=2.0,
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="shared",
                profile=second,
                stratum="direct",
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.IMPROVED,
                        second.fingerprint,
                        elapsed_ms=3.0,
                    ),
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.APPLIED,
                        second.fingerprint,
                        elapsed_ms=4.0,
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="refusals",
                profile=third,
                stratum="unsafe",
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.PROOF_FAILED,
                        third.fingerprint,
                        elapsed_ms=5.0,
                    ),
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.INELIGIBLE,
                        third.fingerprint,
                        elapsed_ms=6.0,
                    ),
                    _outcome(
                        MbaProviderKind.COEFFICIENT_SOLVER,
                        ProviderOutcomeStatus.UNAVAILABLE,
                        third.fingerprint,
                        elapsed_ms=7.0,
                    ),
                ),
            ),
        ),
    )

    summary = compare_provider_outcomes(report)

    assert summary.by_provider[MbaProviderKind.STRUCTURAL_CHAIN].unique_wins == 1
    assert summary.by_provider[MbaProviderKind.CATALOGUE].shared_wins == 1
    assert summary.by_provider[MbaProviderKind.EGGLOG].shared_wins == 1
    assert summary.by_provider[MbaProviderKind.CATALOGUE].misses == 1
    assert summary.by_provider[MbaProviderKind.CATALOGUE].proof_failures == 1
    assert summary.by_provider[MbaProviderKind.EGGLOG].unsafe_abstentions == 0
    assert summary.by_provider[MbaProviderKind.COEFFICIENT_SOLVER].unavailable == 1
    assert summary.by_provider[MbaProviderKind.COEFFICIENT_SOLVER].misses == 0
    assert summary.by_provider[MbaProviderKind.STRUCTURAL_CHAIN].node_reduction == 4
    assert summary.by_provider[MbaProviderKind.EGGLOG].p50_elapsed_ms == 5.0
    assert summary.by_provider[MbaProviderKind.EGGLOG].p95_elapsed_ms == 5.9
    assert summary.by_stratum["chain"].unique_wins == 1
    # Stratum yield counts solved corpus cases, not provider rows.  The two
    # providers both improve the same ``shared`` case.
    assert summary.by_stratum["direct"].shared_wins == 1


def test_summary_only_counts_blocked_cases_as_unsafe_abstentions() -> None:
    safe = _profile("safe")
    blocked = MbaIslandProfile(
        width_bits=32,
        operator_count=2,
        total_node_count=3,
        distinct_leaf_count=1,
        constant_count=0,
        operations=(("add", 1), ("xor", 1)),
        has_boolean=True,
        has_arithmetic=True,
        nonlinear_product_count=0,
        island_class=MbaIslandClass.UNSUPPORTED,
        blockers=(IslandBlocker.CAST,),
        fingerprint="blocked",
    )
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="unit-corpus",
        toolchain_identity={"compiler": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="safe-timeout",
                profile=safe,
                outcomes=(
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.OVER_BUDGET,
                        safe.fingerprint,
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="safe-rebuild-failure",
                profile=safe,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                        safe.fingerprint,
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="blocked",
                profile=blocked,
                outcomes=(
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.INELIGIBLE,
                        blocked.fingerprint,
                    ),
                ),
            ),
        ),
    )

    summary = compare_provider_outcomes(report)

    egglog = summary.by_provider[MbaProviderKind.EGGLOG]
    assert egglog.unsafe_abstentions == 1
    assert egglog.over_budget == 1
    assert summary.by_provider[MbaProviderKind.CATALOGUE].unsafe_abstentions == 0
    assert summary.by_provider[MbaProviderKind.CATALOGUE].reconstruction_failures == 1


def test_normalization_requires_exactly_one_explicit_outcome_for_each_provider_case_pair() -> (
    None
):
    profile = _profile("row")
    first = _outcome(
        MbaProviderKind.CATALOGUE,
        ProviderOutcomeStatus.UNAVAILABLE,
        profile.fingerprint,
    )
    normalized = normalize_outcome_rows(
        (
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": profile,
                "outcome": first,
            },
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": profile,
                "outcome": _outcome(
                    MbaProviderKind.EGGLOG,
                    ProviderOutcomeStatus.UNCHANGED,
                    profile.fingerprint,
                ),
            },
        ),
        corpus_identity="unit",
        toolchain_identity={"compiler": "unit"},
        expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGGLOG),
    )
    assert normalized.cases[0].outcomes[0].status is ProviderOutcomeStatus.UNAVAILABLE

    with pytest.raises(ValueError, match="missing outcome rows"):
        normalize_outcome_rows(
            (
                {
                    "case_id": "case",
                    "stratum": "direct",
                    "profile": profile,
                    "outcome": first,
                },
            ),
            corpus_identity="unit",
            toolchain_identity={"compiler": "unit"},
            expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGGLOG),
        )


def test_report_round_trips_explicit_native_candidate_unavailability() -> None:
    """A native compiler-elided root has coverage rows but no invented profile."""

    rows = (
        {
            "case_id": "elided",
            "stratum": "chain",
            "profile": None,
            "outcome": MbaProviderOutcome(
                provider=MbaProviderKind.STRUCTURAL_CHAIN,
                status=ProviderOutcomeStatus.UNAVAILABLE,
                fingerprint="native_candidate_not_observed:elided",
                refusal_reason="native_candidate_not_observed",
            ),
        },
        {
            "case_id": "elided",
            "stratum": "chain",
            "profile": None,
            "outcome": MbaProviderOutcome(
                provider=MbaProviderKind.EGGLOG,
                status=ProviderOutcomeStatus.UNAVAILABLE,
                fingerprint="native_candidate_not_observed:elided",
                refusal_reason="native_candidate_not_observed",
            ),
        },
    )
    report = normalize_outcome_rows(
        rows,
        corpus_identity="unit",
        toolchain_identity={"compiler": "unit"},
        expected_providers=(MbaProviderKind.STRUCTURAL_CHAIN, MbaProviderKind.EGGLOG),
    )

    assert report.cases[0].profile is None
    assert json.loads(report.to_json())["cases"][0]["profile"] is None
    assert compare_provider_outcomes(report).by_stratum["chain"].unavailable == 1


def test_report_json_is_normalized_and_rejects_profile_fingerprint_mismatch() -> None:
    profile = _profile("fingerprint")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="unit",
        toolchain_identity={"compiler": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.APPLIED,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
    )

    decoded = json.loads(report.to_json())
    assert decoded["schema_version"] == 1
    assert decoded["cases"][0]["outcomes"][0]["provider"] == "catalogue"

    with pytest.raises(ValueError, match="fingerprint"):
        MbaCorpusCaseReport(
            case_id="case",
            profile=profile,
            outcomes=(
                _outcome(
                    MbaProviderKind.CATALOGUE,
                    ProviderOutcomeStatus.APPLIED,
                    "different",
                ),
            ),
        )


def test_case_report_rejects_two_applied_providers_for_one_fingerprint() -> None:
    profile = _profile("one-mutation")

    with pytest.raises(ValueError, match="at most one applied provider"):
        MbaCorpusCaseReport(
            case_id="one-mutation",
            profile=profile,
            outcomes=(
                _outcome(
                    MbaProviderKind.CATALOGUE,
                    ProviderOutcomeStatus.APPLIED,
                    profile.fingerprint,
                ),
                _outcome(
                    MbaProviderKind.EGGLOG,
                    ProviderOutcomeStatus.APPLIED,
                    profile.fingerprint,
                ),
            ),
        )


def test_egglog_receipt_conversion_preserves_skip_semantics_without_invoking_egglog() -> (
    None
):
    class Receipt:
        input_cost = (5, 8)
        extracted_cost = (2, 3)
        degree = 1
        eclass_count = 4
        enode_count = 6
        rule_firings = 1
        elapsed_ms = 2.5
        selected_family = "add"
        selected_source = "add_identity"
        selected_aliases = ("add_zero",)
        island_fingerprint = "receipt"
        island_class = "linear_mba"
        operator_count = 5
        distinct_leaf_count = 2
        nonlinear_product_count = 0
        blockers = ()
        skip_reason = None

    improved = egglog_receipt_to_outcome(Receipt())
    assert improved.status is ProviderOutcomeStatus.IMPROVED
    assert improved.proof_verdict is True
    assert improved.source_provenance == ("add_identity", "add_zero")

    Receipt.skip_reason = "egglog_unavailable"
    unavailable = egglog_receipt_to_outcome(Receipt())
    assert unavailable.status is ProviderOutcomeStatus.UNAVAILABLE
    Receipt.skip_reason = "native_z3_failed"
    assert (
        egglog_receipt_to_outcome(Receipt()).status
        is ProviderOutcomeStatus.PROOF_FAILED
    )
    Receipt.skip_reason = "candidate_budget"
    assert (
        egglog_receipt_to_outcome(Receipt()).status is ProviderOutcomeStatus.INELIGIBLE
    )


def test_egglog_receipt_metadata_is_additive_and_legacy_rows_remain_readable() -> None:
    class Receipt:
        input_cost = (5, 8)
        extracted_cost = (2, 3)
        canonicalizer_version = 1
        canonical_input_cost = (3, 5)
        normalization_steps = ("negative_coefficient", "add_neg_to_sub")
        execution_path = "fresh_saturation"
        cache_status = "disabled"
        cache_key = None
        skip_reason = None

    outcome = egglog_receipt_to_outcome(Receipt())
    assert outcome.input_cost == (5, 8)
    assert outcome.metadata["canonicalizer_version"] == 1
    assert outcome.metadata["canonical_input_cost"] == (3, 5)
    assert outcome.metadata["normalization_steps"] == (
        "negative_coefficient",
        "add_neg_to_sub",
    )
    assert outcome.metadata["execution_path"] == "fresh_saturation"
    assert outcome.metadata["cache_status"] == "disabled"
    encoded = json.loads(outcome.to_json())
    assert encoded["metadata"]["canonical_input_cost"] == [3, 5]

    legacy = outcome_from_dict(
        {
            "provider": "egglog",
            "status": "unchanged",
            "fingerprint": "legacy-row",
            "input_cost": [5, 8],
            "output_cost": [5, 8],
            "proof_verdict": True,
            "elapsed_ms": 1.0,
            "source_provenance": [],
            "refusal_reason": None,
        }
    )
    assert legacy.input_cost == (5, 8)
    assert legacy.output_cost == (5, 8)
    assert legacy.metadata == {}


def test_offline_cli_builds_normalized_report_and_requires_explicit_provider_rows(
    tmp_path,
) -> None:
    from tools.scripts.mba_differential_report import build_report

    profile = _profile("cli")
    catalogue = _outcome(
        MbaProviderKind.CATALOGUE,
        ProviderOutcomeStatus.APPLIED,
        profile.fingerprint,
    )
    egglog = _outcome(
        MbaProviderKind.EGGLOG,
        ProviderOutcomeStatus.UNAVAILABLE,
        profile.fingerprint,
    )
    first_path = tmp_path / "catalogue.json"
    second_path = tmp_path / "egglog.json"
    first_path.write_text(
        json.dumps(
            [
                {
                    "case_id": "case",
                    "stratum": "direct",
                    "profile": _profile_dict(profile),
                    "outcome": catalogue.to_dict(),
                }
            ]
        ),
        encoding="utf-8",
    )
    second_path.write_text(
        json.dumps(
            [
                {
                    "case_id": "case",
                    "stratum": "direct",
                    "profile": _profile_dict(profile),
                    "outcome": egglog.to_dict(),
                }
            ]
        ),
        encoding="utf-8",
    )

    payload, markdown = build_report((first_path, second_path))

    assert payload["cases"][0]["case_id"] == "case"
    assert payload["summary"]["by_provider"]["egglog"]["unavailable"] == 1
    assert "| egglog |" in markdown
    with pytest.raises(ValueError, match="missing outcome rows"):
        build_report(
            (first_path,),
            expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGGLOG),
        )


def test_offline_cli_uses_manifest_provider_matrix_when_no_override_is_given(
    tmp_path,
) -> None:
    from tools.scripts.mba_differential_report import build_report

    profile = _profile("manifest-matrix")
    outcomes_path = tmp_path / "outcomes.json"
    manifest_path = tmp_path / "manifest.json"
    outcomes_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_identity": "unit",
                "toolchain_identity": {},
                "cases": [
                    MbaCorpusCaseReport(
                        case_id="case",
                        profile=profile,
                        outcomes=(
                            _outcome(
                                MbaProviderKind.CATALOGUE,
                                ProviderOutcomeStatus.UNAVAILABLE,
                                profile.fingerprint,
                            ),
                        ),
                    ).to_dict()
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "provider_matrix": ["catalogue", "egglog"],
                "cases": [{"case_id": "case"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing outcome rows for egglog"):
        build_report((outcomes_path,), manifest=manifest_path)


def test_summary_markdown_keeps_budget_and_reconstruction_failures_distinct() -> None:
    profile = _profile("summary")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="corpus",
        toolchain_identity={},
        cases=(
            MbaCorpusCaseReport(
                case_id="budget",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.OVER_BUDGET,
                        profile.fingerprint,
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="rebuild",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
    )

    markdown = summary_markdown(compare_provider_outcomes(report))

    assert "over budget" in markdown
    assert "reconstruction failures" in markdown
    assert "| egglog | 2 |" in markdown


def test_rollout_evidence_keeps_runtime_modes_refusals_and_root_only_misses_distinct() -> None:
    """The rollout report must answer measurement questions without zero-filling gaps."""

    profile = _profile("rollout-evidence")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="corpus",
        toolchain_identity={"compiler": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="degree-one",
                profile=profile,
                stratum="degree2",
                outcomes=(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.EGGLOG,
                        status=ProviderOutcomeStatus.APPLIED,
                        fingerprint=profile.fingerprint,
                        input_cost=(4, 7),
                        output_cost=(2, 3),
                        elapsed_ms=2.0,
                        metadata={
                            "degree": 1,
                            "egglog_execution_mode": "interactive",
                            "candidate_elapsed_ms": 2.0,
                            "whole_function_elapsed_ms": 9.0,
                            "root_only_strict_subisland_miss": False,
                        },
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="degree-two-timeout",
                profile=profile,
                stratum="degree2",
                outcomes=(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.EGGLOG,
                        status=ProviderOutcomeStatus.OVER_BUDGET,
                        fingerprint=profile.fingerprint,
                        elapsed_ms=3.0,
                        refusal_reason="time_budget",
                        metadata={
                            "degree": 2,
                            "egglog_execution_mode": "telemetry_3ms",
                            "candidate_elapsed_ms": 3.0,
                            "whole_function_elapsed_ms": 11.0,
                            "root_only_strict_subisland_miss": True,
                            "root_bucket_size": 4,
                            "attempted_rule_count": 3,
                            "comparison_cap_refusal": True,
                            "reassociation_coverage": "proved",
                            "cold_snapshot_ms": 12.0,
                            "catalogue_cache_hit": True,
                            "native_proof_invocations": 1,
                            "catalogue_compiler_invocations": 0,
                        },
                        matcher=None,
                    ),
                ),
            ),
        ),
    )

    evidence = compare_provider_outcomes(report).rollout_evidence

    assert evidence.egglog_unique_wins_by_degree == {1: 1, 2: 0}
    assert evidence.refusals_by_reason == {"time_budget": 1}
    assert evidence.matcher_bucket_size_p50 == 4.0
    assert evidence.matcher_attempted_rules_p95 == 3.0
    assert evidence.matcher_cap_refusals == 1
    assert evidence.reassociation_proved == 1
    assert evidence.lifecycle_measurements["cold_snapshot_ms"].p50_ms == 12.0
    assert evidence.lifecycle_measurements["catalogue_cache_hits"].count == 1
    assert evidence.lifecycle_measurements["native_proof_invocations"].total == 1
    assert evidence.candidate_latency_by_mode["interactive"]["egglog"].p50_ms == 2.0
    assert evidence.whole_function_latency_by_mode["telemetry_3ms"]["egglog"].p95_ms == 11.0
    assert evidence.root_only_strict_subisland_misses == 1
    markdown = summary_markdown(compare_provider_outcomes(report))
    assert "## Rollout evidence" in markdown
    assert "Egglog unique wins by degree" in markdown
    assert "telemetry_3ms" in markdown
    assert "Root-only strict-sub-island misses: 1" in markdown


def test_rollout_evidence_marks_unmeasured_questions_as_unavailable() -> None:
    profile = _profile("no-rollout-evidence")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="corpus",
        toolchain_identity={},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.UNAVAILABLE,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
    )

    evidence = compare_provider_outcomes(report).rollout_evidence

    assert evidence.candidate_latency_by_mode == {}
    assert evidence.whole_function_latency_by_mode == {}
    assert evidence.lifecycle_measurements == {}


def test_rollout_evidence_counts_declared_nonlinear_residual_without_profile() -> None:
    """Native lowering may reject a nonlinear source before a profile exists."""

    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="nonlinear",
        toolchain_identity={},
        cases=(
            MbaCorpusCaseReport(
                case_id="nonlinear-native-refusal",
                profile=None,
                stratum="nonlinear",
                outcomes=(
                    MbaProviderOutcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.UNAVAILABLE,
                        "nonlinear-native-refusal",
                        refusal_reason="native_candidate_not_observed",
                    ),
                ),
            ),
        ),
    )

    assert compare_provider_outcomes(report).rollout_evidence.nonlinear_residuals == 1


def test_capture_metadata_supplies_measured_provider_lanes_without_row_duplication() -> None:
    """A native runner owns whole-function/lifecycle facts once per capture."""

    profile = _profile("captured-run")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="captured",
        toolchain_identity={"runtime": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.APPLIED,
                        profile.fingerprint,
                        elapsed_ms=1.5,
                    ),
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.OVER_BUDGET,
                        profile.fingerprint,
                        elapsed_ms=3.0,
                    ),
                ),
            ),
        ),
        capture_metadata={
            "provider_execution_modes": {
                "catalogue": "interactive",
                "egglog": "telemetry_3ms",
            },
            "whole_function_elapsed_ms_by_case": {"case": 12.0},
            "lifecycle_measurements": {
                "handler_startup_ms": [4.0],
                "registration_pattern_count": 9,
            },
            "matcher_samples": [
                {
                    "bucket_size": 3,
                    "attempted_rule_count": 2,
                    "comparisons": 4,
                    "lazy_swaps": 1,
                    "flattened_arity": 2,
                    "reassociation_coverage": "proved",
                }
            ],
            "root_only_strict_subisland_misses": 2,
        },
    )

    evidence = compare_provider_outcomes(report).rollout_evidence

    assert evidence.candidate_latency_by_mode["interactive"]["catalogue"].p50_ms == 1.5
    assert evidence.candidate_latency_by_mode["telemetry_3ms"]["egglog"].p50_ms == 3.0
    assert evidence.whole_function_latency_by_mode["interactive"]["catalogue"].p95_ms == 12.0
    assert evidence.whole_function_latency_by_mode["telemetry_3ms"]["egglog"].p95_ms == 12.0
    assert evidence.lifecycle_measurements["handler_startup_ms"].p50_ms == 4.0
    assert evidence.lifecycle_measurements["registration_pattern_count"].total == 9
    assert evidence.matcher_bucket_size_p50 == 3.0
    assert evidence.reassociation_proved == 1
    assert evidence.root_only_strict_subisland_misses == 2


def test_rollout_evidence_keeps_zero_sample_telemetry_lane_visible() -> None:
    """Configured telemetry is evidence even when no candidate reaches Egglog."""

    profile = _profile("telemetry-empty")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="telemetry",
        toolchain_identity={},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.EGGLOG,
                        ProviderOutcomeStatus.UNAVAILABLE,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
        capture_metadata={
            "provider_execution_modes": {"egglog": "telemetry_3ms"},
        },
    )

    lane = compare_provider_outcomes(report).rollout_evidence.candidate_latency_by_mode[
        "telemetry_3ms"
    ]["egglog"]
    assert lane.count == 0
    assert lane.p50_ms is None
    assert "p50=not measured" in summary_markdown(compare_provider_outcomes(report))


def test_rollout_evidence_accepts_sidecar_latency_lanes() -> None:
    """A second configuration contributes latency without duplicate outcomes."""

    profile = _profile("telemetry-sidecar")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="telemetry",
        toolchain_identity={},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.APPLIED,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
        capture_metadata={
            "latency_lanes": [
                {
                    "population": "candidate",
                    "mode": "telemetry_3ms",
                    "provider": "egglog",
                }
            ],
            "latency_samples": [
                {
                    "population": "whole_function",
                    "mode": "telemetry_3ms",
                    "provider": "egglog",
                    "elapsed_ms": 7.0,
                }
            ],
        },
    )

    evidence = compare_provider_outcomes(report).rollout_evidence
    assert evidence.candidate_latency_by_mode["telemetry_3ms"]["egglog"].count == 0
    assert evidence.whole_function_latency_by_mode["telemetry_3ms"]["egglog"].p95_ms == 7.0


def test_report_wire_round_trip_preserves_capture_metadata() -> None:
    profile = _profile("wire-capture")
    source = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="wire",
        toolchain_identity={"runtime": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.APPLIED,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
        capture_metadata={"whole_function_elapsed_ms_by_case": {"case": 7.0}},
    )

    restored = report_from_dict(source.to_dict())

    assert restored.capture_metadata == source.capture_metadata


def test_report_cli_merges_real_measurement_sidecars(tmp_path: Path) -> None:
    """Sidecars add measurements without replacing captured provider rows."""

    profile = _profile("sidecar")
    capture = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="sidecar",
        toolchain_identity={"runtime": "unit"},
        cases=(
            MbaCorpusCaseReport(
                case_id="case",
                profile=profile,
                outcomes=(
                    _outcome(
                        MbaProviderKind.CATALOGUE,
                        ProviderOutcomeStatus.APPLIED,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
        capture_metadata={"lifecycle_measurements": {"configuration_ms": [1.0]}},
    )
    capture_path = tmp_path / "capture.json"
    capture_path.write_text(json.dumps(capture.to_dict()), encoding="utf-8")
    sidecar_path = tmp_path / "sidecar.json"
    sidecar_path.write_text(
        json.dumps(
            {
                "capture_metadata": {
                    "matcher_samples": [{"bucket_size": 2, "comparisons": 3}],
                    "lifecycle_measurements": {
                        "configuration_ms": [2.0],
                        "native_proof_invocations": [1],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    module = _report_cli_module()
    payload, _markdown = module.build_report(
        (capture_path,),
        rollout_evidence=(sidecar_path,),
    )

    metadata = payload["capture_metadata"]
    assert metadata["lifecycle_measurements"] == {
        "configuration_ms": [1.0, 2.0],
        "native_proof_invocations": [1],
    }
    assert metadata["matcher_samples"] == [{"bucket_size": 2, "comparisons": 3}]


def _profile_dict(profile: MbaIslandProfile) -> dict[str, object]:
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
        "blockers": [],
        "fingerprint": profile.fingerprint,
    }
