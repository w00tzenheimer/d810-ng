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
    egraph_receipt_to_outcome,
    normalize_outcome_rows,
    outcome_from_dict,
    report_from_dict,
    summary_markdown,
)
from d810.mba.egraph_contracts import EgraphExtractionReceipt, EgraphSkipReason
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
                        MbaProviderKind.EGRAPH,
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
                        MbaProviderKind.EGRAPH,
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
    assert summary.by_provider[MbaProviderKind.EGRAPH].shared_wins == 1
    assert summary.by_provider[MbaProviderKind.CATALOGUE].misses == 1
    assert summary.by_provider[MbaProviderKind.CATALOGUE].proof_failures == 1
    assert summary.by_provider[MbaProviderKind.EGRAPH].unsafe_abstentions == 0
    assert summary.by_provider[MbaProviderKind.COEFFICIENT_SOLVER].unavailable == 1
    assert summary.by_provider[MbaProviderKind.COEFFICIENT_SOLVER].misses == 0
    assert summary.by_provider[MbaProviderKind.STRUCTURAL_CHAIN].node_reduction == 4
    assert summary.by_provider[MbaProviderKind.EGRAPH].p50_elapsed_ms == 5.0
    assert summary.by_provider[MbaProviderKind.EGRAPH].p95_elapsed_ms == 5.9
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
                        MbaProviderKind.EGRAPH,
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
                        MbaProviderKind.EGRAPH,
                        ProviderOutcomeStatus.INELIGIBLE,
                        blocked.fingerprint,
                    ),
                ),
            ),
        ),
    )

    summary = compare_provider_outcomes(report)

    egraph = summary.by_provider[MbaProviderKind.EGRAPH]
    assert egraph.unsafe_abstentions == 1
    assert egraph.over_budget == 1
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
                    MbaProviderKind.EGRAPH,
                    ProviderOutcomeStatus.UNCHANGED,
                    profile.fingerprint,
                ),
            },
        ),
        corpus_identity="unit",
        toolchain_identity={"compiler": "unit"},
        expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGRAPH),
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
            expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGRAPH),
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
                provider=MbaProviderKind.EGRAPH,
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
        expected_providers=(MbaProviderKind.STRUCTURAL_CHAIN, MbaProviderKind.EGRAPH),
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
                    MbaProviderKind.EGRAPH,
                    ProviderOutcomeStatus.APPLIED,
                    profile.fingerprint,
                ),
            ),
        )


def test_egraph_receipt_conversion_preserves_skip_semantics_without_invoking_backend() -> (
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

    improved = egraph_receipt_to_outcome(Receipt())
    assert improved.status is ProviderOutcomeStatus.IMPROVED
    assert improved.proof_verdict is True
    assert improved.source_provenance == ("add_identity", "add_zero")

    Receipt.skip_reason = "runtime_unavailable"
    unavailable = egraph_receipt_to_outcome(Receipt())
    assert unavailable.status is ProviderOutcomeStatus.UNAVAILABLE
    Receipt.skip_reason = "proof_failed"
    assert (
        egraph_receipt_to_outcome(Receipt()).status
        is ProviderOutcomeStatus.PROOF_FAILED
    )
    Receipt.skip_reason = "candidate_budget"
    assert (
        egraph_receipt_to_outcome(Receipt()).status is ProviderOutcomeStatus.INELIGIBLE
    )


def test_egraph_receipt_metadata_retains_the_concrete_backend() -> None:
    class Receipt:
        input_cost = (5, 8)
        extracted_cost = (2, 3)
        canonicalizer_version = 1
        canonical_input_cost = (3, 5)
        normalization_steps = ("negative_coefficient", "add_neg_to_sub")
        execution_path = "fresh_saturation"
        cache_status = "disabled"
        cache_key = None
        backend = "egglog"
        backend_version = "13.2.0"
        skip_reason = None

    outcome = egraph_receipt_to_outcome(Receipt())
    assert outcome.input_cost == (5, 8)
    assert outcome.metadata["canonicalizer_version"] == 1
    assert outcome.metadata["canonical_input_cost"] == (3, 5)
    assert outcome.metadata["normalization_steps"] == (
        "negative_coefficient",
        "add_neg_to_sub",
    )
    assert outcome.metadata["execution_path"] == "fresh_saturation"
    assert outcome.metadata["cache_status"] == "disabled"
    assert outcome.metadata["backend"] == "egglog"
    assert outcome.metadata["backend_version"] == "13.2.0"
    assert "egraph_run_count" not in outcome.metadata
    encoded = json.loads(outcome.to_json())
    assert encoded["metadata"]["canonical_input_cost"] == [3, 5]

    legacy = outcome_from_dict(
        {
            "provider": "egraph",
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


def test_report_does_not_infer_egraph_runs_from_a_replay_path() -> None:
    class Receipt:
        execution_path = "learned_replay"
        skip_reason = None

    outcome = egraph_receipt_to_outcome(Receipt())

    assert "egraph_run_count" not in outcome.metadata


def test_egraph_receipt_conversion_preserves_trace_and_generic_skip_semantics() -> None:
    trace = (("add", "add.identity", ("add.alias",)),)
    proof_failed = EgraphExtractionReceipt(
        input_cost=(5, 8),
        extracted_cost=(2, 3),
        derivation_trace=trace,
        egraph_work_units=7,
        egraph_run_count=1,
        replay_saved_egraph_runs=0,
        backend="egglog",
        backend_version="13.2.0",
        skip_reason=EgraphSkipReason.PROOF_FAILED,
    )

    outcome = egraph_receipt_to_outcome(proof_failed)

    assert outcome.status is ProviderOutcomeStatus.PROOF_FAILED
    assert outcome.metadata["derivation_trace"] == trace
    assert outcome.metadata["egraph_work_units"] == 7
    assert outcome.metadata["egraph_run_count"] == 1
    assert outcome.metadata["replay_saved_egraph_runs"] == 0
    assert outcome.metadata["backend"] == "egglog"
    assert outcome.metadata["backend_version"] == "13.2.0"
    serialized = json.loads(outcome.to_json())
    assert serialized["metadata"]["derivation_trace"] == [
        ["add", "add.identity", ["add.alias"]]
    ]

    unavailable = EgraphExtractionReceipt(
        skip_reason=EgraphSkipReason.RUNTIME_UNAVAILABLE,
        backend="egglog",
        backend_version="13.2.0",
    )
    assert (
        egraph_receipt_to_outcome(unavailable).status
        is ProviderOutcomeStatus.UNAVAILABLE
    )


def test_report_requires_explicit_replay_saved_runs_measurement() -> None:
    profile = _profile("replay-measurement")
    replay = MbaProviderOutcome(
        provider=MbaProviderKind.EGRAPH,
        status=ProviderOutcomeStatus.APPLIED,
        fingerprint=profile.fingerprint,
        input_cost=(4, 6),
        output_cost=(2, 3),
        metadata={
            "execution_path": "learned_replay",
            "egraph_run_count": 0,
        },
    )
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="replay-measurement",
        toolchain_identity={},
        cases=(
            MbaCorpusCaseReport(
                case_id="replay-without-template-measurement",
                profile=profile,
                outcomes=(replay,),
            ),
        ),
    )

    assert compare_provider_outcomes(report).rollout_evidence.replay_saved_egraph_runs is None


def test_report_sums_explicit_replay_saved_runs_measurements() -> None:
    profile = _profile("replay-sum")
    cases = tuple(
        MbaCorpusCaseReport(
            case_id=f"replay-{saved}",
            profile=profile,
            outcomes=(
                MbaProviderOutcome(
                    provider=MbaProviderKind.EGRAPH,
                    status=ProviderOutcomeStatus.APPLIED,
                    fingerprint=profile.fingerprint,
                    input_cost=(4, 6),
                    output_cost=(2, 3),
                    metadata={
                        "execution_path": "learned_replay",
                        "egraph_run_count": 0,
                        "replay_saved_egraph_runs": saved,
                    },
                ),
            ),
        )
        for saved in (2, 3)
    )
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="replay-sum",
        toolchain_identity={},
        cases=cases,
    )

    assert compare_provider_outcomes(report).rollout_evidence.replay_saved_egraph_runs == 5


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
    egraph = _outcome(
        MbaProviderKind.EGRAPH,
        ProviderOutcomeStatus.UNAVAILABLE,
        profile.fingerprint,
    )
    first_path = tmp_path / "catalogue.json"
    second_path = tmp_path / "egraph.json"
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
                    "outcome": egraph.to_dict(),
                }
            ]
        ),
        encoding="utf-8",
    )

    payload, markdown = build_report((first_path, second_path))

    assert payload["cases"][0]["case_id"] == "case"
    assert payload["summary"]["by_provider"]["egraph"]["unavailable"] == 1
    assert "| egraph |" in markdown
    with pytest.raises(ValueError, match="missing outcome rows"):
        build_report(
            (first_path,),
            expected_providers=(MbaProviderKind.CATALOGUE, MbaProviderKind.EGRAPH),
        )


def test_offline_cli_preserves_input_toolchain_identity(tmp_path) -> None:
    from tools.scripts.mba_differential_report import build_report

    profile = _profile("toolchain")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="native-toolchain",
        toolchain_identity={
            "compiler_executable": "/usr/bin/clang",
            "compiler_version": "Apple clang version 17.0.0",
            "compiler_flags": "-shared -fPIC -O0 -fno-inline",
            "ida_sdk": "94",
            "matcher_backend": "python",
            "profile": "portfolio-python",
        },
        cases=(
            MbaCorpusCaseReport(
                case_id="toolchain-case",
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
    input_path = tmp_path / "native-report.json"
    input_path.write_text(report.to_json(), encoding="utf-8")

    payload, _markdown = build_report((input_path,))

    identity = payload["toolchain_identity"]
    assert identity["compiler_executable"] == "/usr/bin/clang"
    assert identity["compiler_version"] == "Apple clang version 17.0.0"
    assert identity["compiler_flags"] == "-shared -fPIC -O0 -fno-inline"
    assert identity["ida_sdk"] == "94"
    assert identity["matcher_backend"] == "python"
    assert identity["profile"] == "portfolio-python"
    assert identity["reporter"] == "mba_differential_report"


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
                "provider_matrix": ["catalogue", "egraph"],
                "cases": [{"case_id": "case"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing outcome rows for egraph"):
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
                        MbaProviderKind.EGRAPH,
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
                        MbaProviderKind.EGRAPH,
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
    assert "| egraph | 2 |" in markdown


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
                        provider=MbaProviderKind.EGRAPH,
                        status=ProviderOutcomeStatus.APPLIED,
                        fingerprint=profile.fingerprint,
                        input_cost=(4, 7),
                        output_cost=(2, 3),
                        elapsed_ms=2.0,
                        metadata={
                            "degree": 1,
                            "egraph_execution_mode": "interactive",
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
                        provider=MbaProviderKind.EGRAPH,
                        status=ProviderOutcomeStatus.OVER_BUDGET,
                        fingerprint=profile.fingerprint,
                        elapsed_ms=3.0,
                        refusal_reason="time_budget",
                        metadata={
                            "degree": 2,
                            "egraph_execution_mode": "telemetry_3ms",
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

    assert evidence.egraph_unique_wins_by_degree == {1: 1, 2: 0}
    assert evidence.refusals_by_reason == {"time_budget": 1}
    assert evidence.matcher_bucket_size_p50 == 4.0
    assert evidence.matcher_attempted_rules_p95 == 3.0
    assert evidence.matcher_cap_refusals == 1
    assert evidence.reassociation_proved == 1
    assert evidence.lifecycle_measurements["cold_snapshot_ms"].p50_ms == 12.0
    assert evidence.lifecycle_measurements["catalogue_cache_hits"].count == 1
    assert evidence.lifecycle_measurements["native_proof_invocations"].total == 1
    assert evidence.candidate_latency_by_mode["interactive"]["egraph"].p50_ms == 2.0
    assert evidence.whole_function_latency_by_mode["telemetry_3ms"]["egraph"].p95_ms == 11.0
    assert evidence.root_only_strict_subisland_misses == 1
    markdown = summary_markdown(compare_provider_outcomes(report))
    assert "## Rollout evidence" in markdown
    assert "E-graph unique wins by degree" in markdown
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

    summary = compare_provider_outcomes(report)
    assert evidence.candidate_latency_by_mode == {}
    assert evidence.whole_function_latency_by_mode == {}
    assert evidence.lifecycle_measurements == {}
    assert evidence.egraph_unique_wins_by_degree == {}
    assert summary.to_dict()["rollout_evidence"]["egraph_unique_wins_by_degree"] == {}
    markdown = summary_markdown(summary)
    assert "E-graph unique wins by degree: unmeasured" in markdown
    assert "degree 1=0" not in markdown
    assert "degree 2=0" not in markdown


def test_rollout_evidence_extends_domain_lifted_measurements_additively() -> None:
    """Task 13 fields preserve legacy evidence and keep missing data absent."""

    profile = _profile("domain-lifted")
    report = MbaDifferentialReport(
        schema_version=1,
        corpus_identity="domain-lifted",
        toolchain_identity={"runtime": "python"},
        cases=(
            MbaCorpusCaseReport(
                case_id="fresh",
                profile=profile,
                stratum="semantic_canonicalization",
                outcomes=(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.EGRAPH,
                        status=ProviderOutcomeStatus.APPLIED,
                        fingerprint=profile.fingerprint,
                        input_cost=(5, 8),
                        output_cost=(2, 3),
                        elapsed_ms=4.0,
                        metadata={
                            "canonical_input_cost": (3, 5),
                            "normalization_steps": (
                                "negative_coefficient",
                                "add_neg_to_sub",
                            ),
                            "execution_path": "fresh_saturation",
                            "cache_status": "miss",
                            "egraph_work_units": 7,
                            "egraph_run_count": 1,
                        },
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="replay",
                profile=profile,
                stratum="semantic_canonicalization",
                outcomes=(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.EGRAPH,
                        status=ProviderOutcomeStatus.APPLIED,
                        fingerprint=profile.fingerprint,
                        input_cost=(5, 8),
                        output_cost=(2, 3),
                        elapsed_ms=1.0,
                        metadata={
                            "canonical_input_cost": (3, 5),
                            "execution_path": "learned_replay",
                            "cache_status": "hit",
                            "egraph_work_units": 0,
                            "egraph_run_count": 0,
                            "cache_lookup_elapsed_ms": 0.25,
                            "replay_rebuild_elapsed_ms": 0.5,
                            "replay_proof_elapsed_ms": 0.75,
                        },
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="rotate",
                profile=profile,
                stratum="fixed_shift",
                outcomes=(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.EGRAPH,
                        status=ProviderOutcomeStatus.APPLIED,
                        fingerprint=profile.fingerprint,
                        elapsed_ms=2.0,
                        metadata={
                            "selected_family": "fixed_rotate",
                            "rotate_width": 32,
                            "rotate_direction": "rol",
                            "fixed_shift_admitted": True,
                        },
                    ),
                ),
            ),
            MbaCorpusCaseReport(
                case_id="refused-shift",
                profile=profile,
                stratum="fixed_shift",
                outcomes=(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.EGRAPH,
                        status=ProviderOutcomeStatus.INELIGIBLE,
                        fingerprint=profile.fingerprint,
                        refusal_reason="noncomplementary_shift",
                        metadata={"fixed_shift_refusal_reason": "noncomplementary_shift"},
                    ),
                ),
            ),
        ),
        capture_metadata={
            "eligible_rule_measurements": {
                "base_pattern_count": 9,
                "legacy_permutation_count": 36,
            },
            "cache_measurements": {
            # Provider receipts below are authoritative when measured;
            # this deliberately differs to guard against capture-only
            # replay-savings claims.
                "saved_egraph_runs": 9,
                "peak_entries": 2,
                "peak_bytes": 1024,
            },
            "runtime_parity": {"python": "matched", "cython": "matched"},
            "certificate_activation": {"python": True, "cython": False},
        },
    )

    evidence = compare_provider_outcomes(report).rollout_evidence

    assert evidence.normalization_counts_by_kind == {
        "add_neg_to_sub": 1,
        "negative_coefficient": 1,
    }
    assert evidence.raw_vs_canonical_input_costs == (
        {
            "case_id": "fresh",
            "provider": "egraph",
            "raw_input_cost": [5, 8],
            "canonical_input_cost": [3, 5],
            "non_yield": True,
        },
        {
            "case_id": "replay",
            "provider": "egraph",
            "raw_input_cost": [5, 8],
            "canonical_input_cost": [3, 5],
            "non_yield": True,
        },
    )
    assert evidence.eligible_rule_measurements == {
        "base_pattern_count": 9,
        "legacy_permutation_count": 36,
    }
    assert evidence.fixed_shift_admissions == 1
    assert evidence.fixed_shift_refusals_by_reason == {"noncomplementary_shift": 1}
    assert evidence.rotate_extractions_by_width_direction == {"32:rol": 1}
    assert evidence.execution_path_counts == {
        "fresh_saturation": 1,
        "learned_replay": 1,
    }
    # The legacy capture-only aggregate is intentionally ignored.  A saved-run
    # claim now requires the accepted template's explicit producer measurement.
    assert evidence.replay_saved_egraph_runs is None
    assert evidence.cache_status_counts == {"hit": 1, "miss": 1}
    assert evidence.cache_peak_entries == 2
    assert evidence.cache_peak_bytes == 1024
    assert evidence.runtime_parity == {"python": "matched", "cython": "matched"}
    assert evidence.certificate_activation == {"python": True, "cython": False}
    encoded = compare_provider_outcomes(report).to_dict()
    assert encoded["rollout_evidence"]["raw_vs_canonical_input_costs"][0]["non_yield"]
    markdown = summary_markdown(compare_provider_outcomes(report))
    assert "Fresh saturation=1" in markdown
    assert "Learned replay=1" in markdown


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
                        MbaProviderKind.EGRAPH,
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
                        MbaProviderKind.EGRAPH,
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
                "egraph": "telemetry_3ms",
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
    assert evidence.candidate_latency_by_mode["telemetry_3ms"]["egraph"].p50_ms == 3.0
    assert evidence.whole_function_latency_by_mode["interactive"]["catalogue"].p95_ms == 12.0
    assert evidence.whole_function_latency_by_mode["telemetry_3ms"]["egraph"].p95_ms == 12.0
    assert evidence.lifecycle_measurements["handler_startup_ms"].p50_ms == 4.0
    assert evidence.lifecycle_measurements["registration_pattern_count"].total == 9
    assert evidence.matcher_bucket_size_p50 == 3.0
    assert evidence.reassociation_proved == 1
    assert evidence.root_only_strict_subisland_misses == 2


def test_rollout_evidence_keeps_zero_sample_telemetry_lane_visible() -> None:
    """Configured telemetry is evidence even when no candidate reaches an e-graph."""

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
                        MbaProviderKind.EGRAPH,
                        ProviderOutcomeStatus.UNAVAILABLE,
                        profile.fingerprint,
                    ),
                ),
            ),
        ),
        capture_metadata={
            "provider_execution_modes": {"egraph": "telemetry_3ms"},
        },
    )

    lane = compare_provider_outcomes(report).rollout_evidence.candidate_latency_by_mode[
        "telemetry_3ms"
    ]["egraph"]
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
                    "provider": "egraph",
                }
            ],
            "latency_samples": [
                {
                    "population": "whole_function",
                    "mode": "telemetry_3ms",
                    "provider": "egraph",
                    "elapsed_ms": 7.0,
                }
            ],
        },
    )

    evidence = compare_provider_outcomes(report).rollout_evidence
    assert evidence.candidate_latency_by_mode["telemetry_3ms"]["egraph"].count == 0
    assert evidence.whole_function_latency_by_mode["telemetry_3ms"]["egraph"].p95_ms == 7.0


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
