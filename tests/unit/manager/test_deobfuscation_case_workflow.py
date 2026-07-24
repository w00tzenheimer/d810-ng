from __future__ import annotations

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
    DeobfuscationCaseSnapshot,
    StrategyDeficiency,
    StrategyRecommendation,
    StrategyWorkflowStage,
)
from d810.manager.deobfuscation_case_workflow import (
    CaseWorkflowPhase,
    project_case_workflow,
)
from d810.manager.workbench_models import (
    AttackSummary,
    BaselineRef,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    FunctionRef,
    RuleScopeSummary,
    RuntimeConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
)


def _evidence(
    *,
    level: CaseEvidenceLevel = CaseEvidenceLevel.C1_DISCOVERY,
    blocked: str | None = None,
    semantic_witness: str | None = None,
) -> DeobfuscationCaseEvidence:
    finding_kind = (
        CaseFindingKind.RECEIPT
        if level is CaseEvidenceLevel.C5_PUBLICATION
        else CaseFindingKind.SEMANTIC_RESULT
        if level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
        else CaseFindingKind.OBSERVATION
    )
    return DeobfuscationCaseEvidence(
        schema_version=1,
        function_fingerprint="native:fixture",
        runtime_identity="native-runtime:fixture",
        run_identity="run:fixture",
        findings=(
            CaseFinding(
                finding_id="evidence:1",
                kind=finding_kind,
                summary="Recorded evidence.",
                detail="",
                native_ea=(0x1800020F0 if finding_kind is not CaseFindingKind.OBSERVATION else None),
                confidence=1.0,
                provenance=("run:fixture",),
            ),
        ),
        verdict=CaseVerdict(
            level=level,
            summary=(
                "Publication receipt committed."
                if level is CaseEvidenceLevel.C5_PUBLICATION
                else "Semantic result verified."
                if level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
                else "Discovery evidence recorded."
            ),
            first_blocked_obligation=blocked,
            semantic_witness=semantic_witness,
        ),
    )


def _snapshot(
    *,
    case: DeobfuscationCaseSnapshot | None = None,
    freshness: SnapshotFreshness = SnapshotFreshness.CURRENT,
    engine_started: bool = True,
) -> DeobfuscationWorkbenchSnapshot:
    return DeobfuscationWorkbenchSnapshot(
        generation=4,
        function=FunctionRef(0x1800020F0, "target", "workbench:fixture", 4),
        runtime=RuntimeConfigRef(
            source_name="source.json",
            source_path="/source.json",
            runtime_name="runtime.json",
            runtime_path="/runtime.json",
            mode="config-v2",
            routed=True,
            hook_mode="config-v2",
            pass_ids=("recover_dispatcher",),
        ),
        attack=AttackSummary(
            observed_shape="unknown",
            mechanism="unavailable",
            selected_profile=None,
            selection_mode="not-analyzed",
            confidence=None,
            recommended_inferences=(),
            suppressed_rules=(),
            candidate_kinds=(),
        ),
        pipeline=(),
        consumers=(),
        rule_scope=RuleScopeSummary((), (), (), (), (), "", None, (), (), False),
        statistics=StatisticsSummary((), (), (), 0, (), 0),
        baseline=BaselineRef(False, None, None, None),
        latest_output=D810OutputRef(False, None, None, None),
        artifacts=(),
        freshness=freshness,
        engine_started=engine_started,
        collection_errors=(),
        case=case,
    )


def _case(
    *,
    evidence: DeobfuscationCaseEvidence | None = None,
    strategy: StrategyRecommendation | None = None,
    direct_run_permitted: bool = False,
) -> DeobfuscationCaseSnapshot:
    return DeobfuscationCaseSnapshot(
        evidence=evidence,
        strategy=strategy,
        direct_run_permitted=direct_run_permitted,
        direct_run_reason=(
            "A current saved function recipe is active."
            if direct_run_permitted
            else "Build a strategy before running it."
        ),
    )


def _strategy() -> StrategyRecommendation:
    return StrategyRecommendation(
        deficiency=StrategyDeficiency.CFG_FORMATION,
        summary="Recover the verified control-flow shape.",
        required_finding_ids=("evidence:1",),
        stages=(StrategyWorkflowStage.CANONICAL_ANALYSIS,),
    )


def test_unknown_case_makes_build_deobfuscator_the_primary_action() -> None:
    view = project_case_workflow(_snapshot(case=_case()))

    assert view.phase is CaseWorkflowPhase.BUILD
    assert view.primary.action_id == "build_deobfuscator"
    assert view.primary.label == "Build Deobfuscator"
    assert view.direct.action_id == "deobfuscate"
    assert view.direct.enabled is False
    assert "Build a strategy" in view.direct.reason


def test_validated_recommendation_makes_deobfuscate_function_available() -> None:
    view = project_case_workflow(
        _snapshot(
            case=_case(
                evidence=_evidence(),
                strategy=_strategy(),
                direct_run_permitted=True,
            )
        )
    )

    assert view.phase is CaseWorkflowPhase.STRATEGY_READY
    assert view.primary.action_id == "deobfuscate"
    assert view.primary.label == "Deobfuscate Function"
    assert view.build.label == "Build Deobfuscator"


def test_c5_receipt_names_publication_without_claiming_semantic_success() -> None:
    view = project_case_workflow(
        _snapshot(case=_case(evidence=_evidence(level=CaseEvidenceLevel.C5_PUBLICATION)))
    )

    assert view.verdict.label == "Publication receipt committed."
    assert "deobfuscated" not in view.verdict.detail.casefold()


def test_unavailable_snapshot_disables_both_entry_points() -> None:
    stale = project_case_workflow(
        _snapshot(
            case=_case(),
            freshness=SnapshotFreshness.STALE,
        )
    )
    stopped = project_case_workflow(_snapshot(case=_case(), engine_started=False))

    assert stale.phase is CaseWorkflowPhase.UNAVAILABLE
    assert stale.build.enabled is False
    assert stale.direct.enabled is False
    assert stopped.build.enabled is False
    assert stopped.direct.enabled is False


def test_running_commands_name_the_correct_non_mutating_or_direct_phase() -> None:
    snapshot = _snapshot(case=_case(evidence=_evidence(), direct_run_permitted=True))

    build = project_case_workflow(snapshot, running_command="build_deobfuscator")
    direct = project_case_workflow(snapshot, running_command="deobfuscate")

    assert build.phase is CaseWorkflowPhase.BUILD
    assert build.primary.enabled is False
    assert direct.phase is CaseWorkflowPhase.RUNNING
    assert direct.primary.enabled is False


def test_rejected_case_surfaces_the_first_blocked_obligation() -> None:
    snapshot = _snapshot(
        case=_case(
            evidence=_evidence(blocked="Validate predicate and both destinations first."),
        )
    )

    view = project_case_workflow(snapshot)

    assert view.phase is CaseWorkflowPhase.INVESTIGATE
    assert view.blocked_obligation == "Validate predicate and both destinations first."
    assert "Validate predicate" in view.detail


def test_c6_requires_its_existing_witness_to_name_semantic_verification() -> None:
    view = project_case_workflow(
        _snapshot(
            case=_case(
                evidence=_evidence(
                    level=CaseEvidenceLevel.C6_SEMANTIC_OUTPUT,
                    semantic_witness="verified-output:fixture",
                )
            )
        )
    )

    assert view.phase is CaseWorkflowPhase.VERDICT
    assert view.verdict.label == "Semantic result verified."
    assert "verified-output:fixture" in view.verdict.detail


def test_saved_recipe_can_enable_direct_run_without_an_automatic_recommendation() -> None:
    snapshot = _snapshot(
        case=_case(
            evidence=_evidence(),
            direct_run_permitted=True,
        )
    )

    view = project_case_workflow(snapshot)

    assert view.primary.action_id == "deobfuscate"
    assert view.primary.label == "Deobfuscate Function"
    assert view.strategy_summary == "Current saved function recipe."
