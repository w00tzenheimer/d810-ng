"""Pure manager-owned decisions for the algorithm-driven Workbench."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFindingKind,
    DeobfuscationCaseEvidence,
    DeobfuscationCaseSnapshot,
)
from d810.manager.workbench_models import (
    DeobfuscationWorkbenchSnapshot,
    OutcomeStatus,
    SnapshotFreshness,
    WorkbenchCommandResult,
)

__all__ = [
    "CaseActionView",
    "CaseStageStatus",
    "CaseStageView",
    "CaseVerdictView",
    "CaseWorkflowPhase",
    "CaseWorkflowView",
    "RecommendedAttackTransition",
    "project_case_workflow",
    "recommended_attack_transition",
]


class CaseWorkflowPhase(str, enum.Enum):
    """The current user-facing step in one function's case workflow."""

    UNAVAILABLE = "unavailable"
    BUILD = "build"
    STRATEGY_READY = "strategy_ready"
    RUNNING = "running"
    INVESTIGATE = "investigate"
    VERDICT = "verdict"


class CaseStageStatus(str, enum.Enum):
    """A stage status intentionally independent of Qt and execution order."""

    NOT_STARTED = "not_started"
    READY = "ready"
    BLOCKED = "blocked"
    COMPLETE = "complete"
    UNAVAILABLE = "unavailable"


@dataclasses.dataclass(frozen=True, slots=True)
class CaseActionView:
    action_id: str
    label: str
    enabled: bool
    reason: str = ""


@dataclasses.dataclass(frozen=True, slots=True)
class CaseStageView:
    stage_id: str
    label: str
    status: CaseStageStatus
    detail: str


@dataclasses.dataclass(frozen=True, slots=True)
class CaseVerdictView:
    label: str
    detail: str
    semantic_verified: bool


@dataclasses.dataclass(frozen=True, slots=True)
class CaseWorkflowView:
    phase: CaseWorkflowPhase
    headline: str
    detail: str
    primary: CaseActionView
    build: CaseActionView
    direct: CaseActionView
    stages: tuple[CaseStageView, ...]
    evidence_summary: str
    strategy_summary: str
    blocked_obligation: str | None
    verdict: CaseVerdictView


@dataclasses.dataclass(frozen=True, slots=True)
class RecommendedAttackTransition:
    refresh: bool
    compare: bool


_BUILD_ACTION = "build_deobfuscator"
_DIRECT_ACTION = "deobfuscate"
_STAGE_LABELS = (
    ("dossier", "Dossier"),
    ("hypotheses", "Hypotheses"),
    ("validated_evidence", "Validated evidence"),
    ("strategy", "Strategy"),
    ("execution", "Execution"),
    ("verdict", "Verdict"),
)


def _action(
    action_id: str,
    label: str,
    *,
    enabled: bool = True,
    reason: str = "",
) -> CaseActionView:
    return CaseActionView(action_id, label, enabled, reason)


def _context_name(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    return snapshot.function.name or f"sub_{snapshot.function.ea:x}"


def _current_result(
    snapshot: DeobfuscationWorkbenchSnapshot,
    result: WorkbenchCommandResult | None,
    *,
    command: str | None = None,
) -> bool:
    return bool(
        result is not None
        and result.accepted
        and (command is None or result.command == command)
        and result.function_ea == snapshot.function.ea
        and result.requested_generation == snapshot.generation
        and result.function_fingerprint == snapshot.function.fingerprint
    )


def recommended_attack_transition(
    snapshot: DeobfuscationWorkbenchSnapshot | None,
    result: WorkbenchCommandResult | None,
) -> RecommendedAttackTransition:
    """Keep direct-run refresh-before-comparison sequencing outside Qt."""
    if snapshot is None or not _current_result(snapshot, result, command=_DIRECT_ACTION):
        return RecommendedAttackTransition(refresh=False, compare=False)
    assert result is not None
    if result.status is OutcomeStatus.STALE:
        return RecommendedAttackTransition(refresh=False, compare=False)
    return RecommendedAttackTransition(
        refresh=True,
        compare=result.refresh_requested,
    )


def _is_grounded(case: DeobfuscationCaseSnapshot) -> bool:
    if case.strategy is None:
        return case.direct_run_permitted
    if case.evidence is None:
        return False
    available = {finding.finding_id for finding in case.evidence.findings}
    return set(case.strategy.required_finding_ids).issubset(available)


def _verdict(evidence: DeobfuscationCaseEvidence | None) -> CaseVerdictView:
    if evidence is None:
        return CaseVerdictView(
            label="No case evidence yet.",
            detail="Build a deobfuscator to collect a current dossier.",
            semantic_verified=False,
        )
    verdict = evidence.verdict
    if verdict.semantic_verified:
        return CaseVerdictView(
            label=verdict.summary,
            detail=f"Semantic witness: {verdict.semantic_witness}",
            semantic_verified=True,
        )
    if verdict.first_blocked_obligation:
        return CaseVerdictView(
            label=verdict.summary,
            detail=f"Blocked obligation: {verdict.first_blocked_obligation}",
            semantic_verified=False,
        )
    return CaseVerdictView(
        label=verdict.summary,
        detail="No semantic verification has been recorded.",
        semantic_verified=False,
    )


def _stage_views(
    case: DeobfuscationCaseSnapshot | None,
    *,
    direct_completed: bool,
) -> tuple[CaseStageView, ...]:
    if case is None:
        return tuple(
            CaseStageView(
                stage_id=stage_id,
                label=label,
                status=CaseStageStatus.UNAVAILABLE,
                detail="No current case snapshot.",
            )
            for stage_id, label in _STAGE_LABELS
        )
    evidence = case.evidence
    findings = () if evidence is None else evidence.findings
    kinds = {finding.kind for finding in findings}
    blocked = None if evidence is None else evidence.verdict.first_blocked_obligation
    states = {
        "dossier": (
            CaseStageStatus.COMPLETE if findings else CaseStageStatus.NOT_STARTED,
            "Current diagnostic evidence." if findings else "No evidence collected yet.",
        ),
        "hypotheses": (
            (
                CaseStageStatus.COMPLETE
                if CaseFindingKind.HYPOTHESIS in kinds
                else CaseStageStatus.NOT_STARTED
            ),
            "Competing explanations are recorded."
            if CaseFindingKind.HYPOTHESIS in kinds
            else "No explicit hypothesis is recorded.",
        ),
        "validated_evidence": (
            (
                CaseStageStatus.COMPLETE
                if kinds.intersection(
                    {
                        CaseFindingKind.VALIDATION,
                        CaseFindingKind.PORTABLE_EVIDENCE,
                        CaseFindingKind.FRAGMENT_PLAN,
                        CaseFindingKind.RECEIPT,
                        CaseFindingKind.SEMANTIC_RESULT,
                    }
                )
                else CaseStageStatus.READY if findings else CaseStageStatus.NOT_STARTED
            ),
            "Anchored or validated evidence is available."
            if findings
            else "Build the dossier first.",
        ),
        "strategy": (
            (
                CaseStageStatus.COMPLETE
                if case.strategy is not None or case.direct_run_permitted
                else CaseStageStatus.BLOCKED if blocked else CaseStageStatus.NOT_STARTED
            ),
            (
                case.strategy.summary
                if case.strategy is not None
                else "Current saved function recipe."
                if case.direct_run_permitted
                else blocked or "No validated strategy is selected."
            ),
        ),
        "execution": (
            CaseStageStatus.COMPLETE
            if direct_completed
            else CaseStageStatus.READY
            if case.direct_run_permitted
            else CaseStageStatus.NOT_STARTED,
            "A direct run completed; inspect its comparison evidence."
            if direct_completed
            else "A validated strategy may run."
            if case.direct_run_permitted
            else "Execution remains gated by strategy selection.",
        ),
        "verdict": (
            CaseStageStatus.COMPLETE
            if evidence is not None and evidence.verdict.semantic_verified
            else CaseStageStatus.BLOCKED
            if blocked
            else CaseStageStatus.READY
            if evidence is not None
            else CaseStageStatus.NOT_STARTED,
            _verdict(evidence).detail,
        ),
    }
    return tuple(
        CaseStageView(stage_id, label, *states[stage_id])
        for stage_id, label in _STAGE_LABELS
    )


def _unavailable_view(reason: str) -> CaseWorkflowView:
    build = _action(_BUILD_ACTION, "Build Deobfuscator", enabled=False, reason=reason)
    direct = _action(_DIRECT_ACTION, "Deobfuscate Function", enabled=False, reason=reason)
    return CaseWorkflowView(
        phase=CaseWorkflowPhase.UNAVAILABLE,
        headline="Deobfuscation workflow unavailable",
        detail=reason,
        primary=build,
        build=build,
        direct=direct,
        stages=_stage_views(None, direct_completed=False),
        evidence_summary="No current case evidence.",
        strategy_summary="No strategy is available.",
        blocked_obligation=None,
        verdict=_verdict(None),
    )


def project_case_workflow(
    snapshot: DeobfuscationWorkbenchSnapshot | None,
    *,
    last_result: WorkbenchCommandResult | None = None,
    running_command: str | None = None,
) -> CaseWorkflowView:
    """Select safe Build/Deobfuscate actions without importing Qt or IDA."""
    if snapshot is None:
        return _unavailable_view("Select a pseudocode function.")
    if snapshot.freshness is not SnapshotFreshness.CURRENT:
        return _unavailable_view("Refresh the stale workbench snapshot.")
    if not snapshot.engine_started:
        return _unavailable_view("Start D810 before building or running a deobfuscator.")

    case = snapshot.case
    evidence = None if case is None else case.evidence
    blocked = None if evidence is None else evidence.verdict.first_blocked_obligation
    direct_enabled = bool(case is not None and _is_grounded(case))
    direct_reason = (
        case.direct_run_reason
        if case is not None
        else "Build a strategy before running it."
    )
    build = _action(_BUILD_ACTION, "Build Deobfuscator")
    direct = _action(
        _DIRECT_ACTION,
        "Deobfuscate Function",
        enabled=direct_enabled,
        reason="" if direct_enabled else direct_reason,
    )
    verdict = _verdict(evidence)
    strategy_summary = (
        case.strategy.summary
        if case is not None and case.strategy is not None
        else "Current saved function recipe."
        if direct_enabled
        else "No validated strategy is selected."
    )
    direct_completed = _current_result(snapshot, last_result, command=_DIRECT_ACTION) and bool(
        last_result and last_result.succeeded and last_result.status is not OutcomeStatus.STALE
    )
    stages = _stage_views(case, direct_completed=direct_completed)
    evidence_summary = (
        "No case evidence yet."
        if evidence is None
        else f"{len(evidence.findings)} finding(s); {evidence.verdict.summary}"
    )

    if running_command == _BUILD_ACTION:
        disabled_build = dataclasses.replace(
            build,
            label="Building Deobfuscator...",
            enabled=False,
            reason="D810 is collecting a non-mutating dossier.",
        )
        return dataclasses.replace(
            _workflow_view(
                CaseWorkflowPhase.BUILD,
                snapshot,
                disabled_build,
                disabled_build,
                dataclasses.replace(direct, enabled=False, reason="Build is running."),
                stages,
                evidence_summary,
                strategy_summary,
                blocked,
                verdict,
            ),
            headline=f"Building a deobfuscator for {_context_name(snapshot)}",
        )
    if running_command == _DIRECT_ACTION:
        disabled_direct = dataclasses.replace(
            direct,
            label="Deobfuscating Function...",
            enabled=False,
            reason="The established deobfuscation lifecycle is running.",
        )
        return _workflow_view(
            CaseWorkflowPhase.RUNNING,
            snapshot,
            disabled_direct,
            dataclasses.replace(build, enabled=False, reason="Direct run is active."),
            disabled_direct,
            stages,
            evidence_summary,
            strategy_summary,
            blocked,
            verdict,
        )
    if blocked:
        return _workflow_view(
            CaseWorkflowPhase.INVESTIGATE,
            snapshot,
            build,
            build,
            direct,
            stages,
            evidence_summary,
            strategy_summary,
            blocked,
            verdict,
            detail=f"First blocked obligation: {blocked}",
        )
    if evidence is not None and evidence.verdict.semantic_verified:
        return _workflow_view(
            CaseWorkflowPhase.VERDICT,
            snapshot,
            direct if direct_enabled else build,
            build,
            direct,
            stages,
            evidence_summary,
            strategy_summary,
            blocked,
            verdict,
        )
    if direct_enabled:
        return _workflow_view(
            CaseWorkflowPhase.STRATEGY_READY,
            snapshot,
            direct,
            build,
            direct,
            stages,
            evidence_summary,
            strategy_summary,
            blocked,
            verdict,
        )
    return _workflow_view(
        CaseWorkflowPhase.BUILD,
        snapshot,
        build,
        build,
        direct,
        stages,
        evidence_summary,
        strategy_summary,
        blocked,
        verdict,
    )


def _workflow_view(
    phase: CaseWorkflowPhase,
    snapshot: DeobfuscationWorkbenchSnapshot,
    primary: CaseActionView,
    build: CaseActionView,
    direct: CaseActionView,
    stages: tuple[CaseStageView, ...],
    evidence_summary: str,
    strategy_summary: str,
    blocked_obligation: str | None,
    verdict: CaseVerdictView,
    *,
    detail: str | None = None,
) -> CaseWorkflowView:
    return CaseWorkflowView(
        phase=phase,
        headline=(
            f"Strategy ready for {_context_name(snapshot)}"
            if phase is CaseWorkflowPhase.STRATEGY_READY
            else f"Build a deobfuscator for {_context_name(snapshot)}"
            if phase is CaseWorkflowPhase.BUILD
            else f"Deobfuscating {_context_name(snapshot)}"
            if phase is CaseWorkflowPhase.RUNNING
            else verdict.label
            if phase is CaseWorkflowPhase.VERDICT
            else f"Investigate {_context_name(snapshot)}"
        ),
        detail=detail or strategy_summary,
        primary=primary,
        build=build,
        direct=direct,
        stages=stages,
        evidence_summary=evidence_summary,
        strategy_summary=strategy_summary,
        blocked_obligation=blocked_obligation,
        verdict=verdict,
    )
