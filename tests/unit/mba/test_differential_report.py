"""Tests for portable MBA provider differential reporting."""

from __future__ import annotations

import json

import pytest

from d810.mba.differential_report import (
    MbaCorpusCaseReport,
    MbaDifferentialReport,
    compare_provider_outcomes,
    egglog_receipt_to_outcome,
    normalize_outcome_rows,
)
from d810.mba.island_profile import MbaIslandClass, MbaIslandProfile
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


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


def test_summary_keeps_unique_shared_miss_proof_abstention_and_unavailable_distinct() -> None:
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
    assert summary.by_provider[MbaProviderKind.EGGLOG].unsafe_abstentions == 1
    assert summary.by_provider[MbaProviderKind.COEFFICIENT_SOLVER].unavailable == 1
    assert summary.by_provider[MbaProviderKind.COEFFICIENT_SOLVER].misses == 0
    assert summary.by_provider[MbaProviderKind.STRUCTURAL_CHAIN].node_reduction == 4
    assert summary.by_provider[MbaProviderKind.EGGLOG].p50_elapsed_ms == 5.0
    assert summary.by_provider[MbaProviderKind.EGGLOG].p95_elapsed_ms == 5.9
    assert summary.by_stratum["chain"].unique_wins == 1
    assert summary.by_stratum["direct"].shared_wins == 2


def test_normalization_requires_exactly_one_explicit_outcome_for_each_provider_case_pair() -> None:
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


def test_egglog_receipt_conversion_preserves_skip_semantics_without_invoking_egglog() -> None:
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
    assert egglog_receipt_to_outcome(Receipt()).status is ProviderOutcomeStatus.PROOF_FAILED
    Receipt.skip_reason = "candidate_budget"
    assert egglog_receipt_to_outcome(Receipt()).status is ProviderOutcomeStatus.INELIGIBLE


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
            [{"case_id": "case", "stratum": "direct", "profile": _profile_dict(profile), "outcome": catalogue.to_dict()}]
        ),
        encoding="utf-8",
    )
    second_path.write_text(
        json.dumps(
            [{"case_id": "case", "stratum": "direct", "profile": _profile_dict(profile), "outcome": egglog.to_dict()}]
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
