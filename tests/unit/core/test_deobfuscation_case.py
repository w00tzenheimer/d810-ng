from __future__ import annotations

import pytest

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
    StrategyDeficiency,
    StrategyRecommendation,
    StrategyWorkflowStage,
)


def _finding(
    finding_id: str,
    *,
    kind: CaseFindingKind = CaseFindingKind.OBSERVATION,
    native_ea: int | None = None,
) -> CaseFinding:
    return CaseFinding(
        finding_id=finding_id,
        kind=kind,
        summary="Observed native control-flow evidence.",
        detail="",
        native_ea=native_ea,
        confidence=1.0,
        provenance=("diagnostic:run-1",),
    )


def test_portable_evidence_requires_a_native_anchor() -> None:
    with pytest.raises(ValueError, match="native anchor"):
        _finding("route-1", kind=CaseFindingKind.PORTABLE_EVIDENCE)


def test_c5_receipt_is_progress_not_semantic_success() -> None:
    verdict = CaseVerdict(
        level=CaseEvidenceLevel.C5_PUBLICATION,
        summary="Publication receipt committed.",
        first_blocked_obligation=None,
    )

    assert verdict.semantic_verified is False


def test_c6_requires_an_explicit_semantic_witness() -> None:
    with pytest.raises(ValueError, match="semantic witness"):
        CaseVerdict(
            level=CaseEvidenceLevel.C6_SEMANTIC_OUTPUT,
            summary="Semantic result verified.",
            first_blocked_obligation=None,
        )


def test_unresolved_question_and_rejection_remain_distinct_findings() -> None:
    question = _finding(
        "question-1",
        kind=CaseFindingKind.UNRESOLVED_QUESTION,
    )
    rejection = _finding(
        "rejection-1",
        kind=CaseFindingKind.REJECTION,
    )

    assert question.kind is CaseFindingKind.UNRESOLVED_QUESTION
    assert rejection.kind is CaseFindingKind.REJECTION
    assert question.kind is not rejection.kind


def test_recommendation_requires_a_strategy_deficiency_not_profile_text() -> None:
    recommendation = StrategyRecommendation(
        deficiency=StrategyDeficiency.CFG_FORMATION,
        summary="Reconstruct the missing control-flow edge before lowering.",
        required_finding_ids=("route-1",),
        stages=(
            StrategyWorkflowStage.FRONTEND_NORMALIZATION,
            StrategyWorkflowStage.CANONICAL_ANALYSIS,
        ),
    )

    assert recommendation.deficiency is StrategyDeficiency.CFG_FORMATION

    with pytest.raises(ValueError, match="StrategyDeficiency"):
        StrategyRecommendation(
            deficiency="ollvm_flat",  # type: ignore[arg-type]
            summary="Do not recommend a vendor/profile label.",
            required_finding_ids=(),
            stages=(),
        )


def test_case_evidence_rejects_duplicate_finding_ids() -> None:
    observation = _finding("observation-1")

    with pytest.raises(ValueError, match="duplicate finding"):
        DeobfuscationCaseEvidence(
            schema_version=1,
            function_fingerprint="sha256:fixture",
            runtime_identity="runtime-1",
            run_identity="run-1",
            findings=(observation, observation),
            verdict=CaseVerdict(
                level=CaseEvidenceLevel.C1_DISCOVERY,
                summary="Discovery evidence recorded.",
                first_blocked_obligation=None,
            ),
        )
