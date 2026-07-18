"""Pure workflow projection for the deobfuscation workbench attack card."""

from __future__ import annotations

import dataclasses
import enum

from d810.manager.workbench_models import (
    DeobfuscationWorkbenchSnapshot,
    OutcomeStatus,
    SnapshotFreshness,
    WorkbenchCommandResult,
)
from d810.ui.workbench_logic import ComparisonView


class WorkflowPhase(str, enum.Enum):
    READY = "ready"
    UNAVAILABLE = "unavailable"
    RUNNING = "running"
    VERIFY = "verify"
    INVESTIGATE = "investigate"


@dataclasses.dataclass(frozen=True, slots=True)
class WorkflowActionView:
    action_id: str
    label: str
    enabled: bool
    reason: str = ""


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchWorkflowView:
    phase: WorkflowPhase
    headline: str
    detail: str
    primary: WorkflowActionView
    secondary: tuple[WorkflowActionView, ...] = ()
    comparison_state: str = "unavailable"


_DIRECT_ACTION = "deobfuscate"
_INVESTIGATION_STATUSES = frozenset(
    {
        OutcomeStatus.NOT_ELIGIBLE,
        OutcomeStatus.NO_MATCH,
        OutcomeStatus.ABSTAINED,
        OutcomeStatus.BLOCKED,
        OutcomeStatus.FAILED,
        OutcomeStatus.STALE,
    }
)


def _action(
    action_id: str,
    label: str,
    *,
    enabled: bool = True,
    reason: str = "",
) -> WorkflowActionView:
    return WorkflowActionView(action_id, label, enabled, reason)


def _context_name(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    return snapshot.function.name or f"sub_{snapshot.function.ea:x}"


def _runtime_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    runtime = snapshot.runtime
    pass_count = len(runtime.pass_ids)
    pass_word = "pass" if pass_count == 1 else "passes"
    if snapshot.attack.observed_shape == "ollvm_flat":
        path = "effective routed pipeline" if runtime.routed else "effective pipeline"
        return (
            f"D810 will run the {path} {runtime.runtime_name} "
            f"with {pass_count} {pass_word}."
        )
    return (
        f"D810 will run the effective project pipeline {runtime.runtime_name} "
        f"with {pass_count} {pass_word} and retain observed shape evidence "
        f"({snapshot.attack.observed_shape})."
    )


def _secondary_actions() -> tuple[WorkflowActionView, ...]:
    return (
        _action("diagnostics", "Investigate diagnostics"),
        _action("recipe", "Tune recipe"),
        _action("function_override", "Adjust function rules"),
    )


def _ready_view(snapshot: DeobfuscationWorkbenchSnapshot) -> WorkbenchWorkflowView:
    return WorkbenchWorkflowView(
        phase=WorkflowPhase.READY,
        headline=f"Ready to deobfuscate {_context_name(snapshot)}",
        detail=_runtime_detail(snapshot),
        primary=_action(_DIRECT_ACTION, "Deobfuscate this function"),
        comparison_state="offer",
    )


def _unavailable_view(
    reason: str,
    snapshot: DeobfuscationWorkbenchSnapshot | None = None,
) -> WorkbenchWorkflowView:
    detail = reason if snapshot is None else f"{reason} {_runtime_detail(snapshot)}"
    return WorkbenchWorkflowView(
        phase=WorkflowPhase.UNAVAILABLE,
        headline="Deobfuscation unavailable",
        detail=detail,
        primary=_action(
            _DIRECT_ACTION,
            "Deobfuscate this function",
            enabled=False,
            reason=reason,
        ),
    )


def _running_view(snapshot: DeobfuscationWorkbenchSnapshot) -> WorkbenchWorkflowView:
    return WorkbenchWorkflowView(
        phase=WorkflowPhase.RUNNING,
        headline=f"Deobfuscating {_context_name(snapshot)}",
        detail="The established deobfuscation lifecycle is running.",
        primary=_action(
            _DIRECT_ACTION,
            "Running deobfuscation...",
            enabled=False,
            reason="Deobfuscation is already running.",
        ),
    )


def _verification_view(
    snapshot: DeobfuscationWorkbenchSnapshot,
    comparison: ComparisonView,
) -> WorkbenchWorkflowView:
    headline = (
        "Pseudocode text differs"
        if comparison.text_changed
        else "Pseudocode text matches"
    )
    return WorkbenchWorkflowView(
        phase=WorkflowPhase.VERIFY,
        headline=headline,
        detail=comparison.summary,
        primary=_action("compare", "View comparison"),
        secondary=_secondary_actions(),
        comparison_state="current",
    )


def _investigation_view(
    snapshot: DeobfuscationWorkbenchSnapshot,
    result: WorkbenchCommandResult | None = None,
    *,
    comparison_detail: str | None = None,
) -> WorkbenchWorkflowView:
    if comparison_detail is not None:
        return WorkbenchWorkflowView(
            phase=WorkflowPhase.INVESTIGATE,
            headline="Comparison unavailable",
            detail=comparison_detail,
            primary=_action("compare", "Retry comparison"),
            secondary=_secondary_actions(),
            comparison_state="retry",
        )
    detail = (
        result.message
        if result is not None and result.message
        else f"Review diagnostics for {_context_name(snapshot)}."
    )
    return WorkbenchWorkflowView(
        phase=WorkflowPhase.INVESTIGATE,
        headline="Investigate deobfuscation evidence",
        detail=detail,
        primary=_action("diagnostics", "Investigate diagnostics"),
        secondary=(
            _action("recipe", "Tune recipe"),
            _action("function_override", "Adjust function rules"),
        ),
        comparison_state="retry",
    )


def _result_matches_current_function(
    snapshot: DeobfuscationWorkbenchSnapshot,
    result: WorkbenchCommandResult,
) -> bool:
    return (
        result.function_ea == snapshot.function.ea
        and result.function_fingerprint == snapshot.function.fingerprint
    )


def _is_deobfuscation_result(result: WorkbenchCommandResult | None) -> bool:
    return result is not None and result.command == _DIRECT_ACTION


def _needs_investigation(
    snapshot: DeobfuscationWorkbenchSnapshot,
    result: WorkbenchCommandResult | None,
) -> bool:
    if not _is_deobfuscation_result(result):
        return False
    assert result is not None
    return (
        not _result_matches_current_function(snapshot, result)
        or not result.accepted
        or not result.succeeded
        or result.status in _INVESTIGATION_STATUSES
    )


def _current_successful_deobfuscation(
    snapshot: DeobfuscationWorkbenchSnapshot,
    result: WorkbenchCommandResult | None,
) -> bool:
    return (
        _is_deobfuscation_result(result)
        and result is not None
        and _result_matches_current_function(snapshot, result)
        and result.accepted
        and result.succeeded
        and result.status not in _INVESTIGATION_STATUSES
    )


def project_workbench_workflow(
    snapshot: DeobfuscationWorkbenchSnapshot | None,
    *,
    comparison: ComparisonView | None = None,
    last_result: WorkbenchCommandResult | None = None,
    running: bool = False,
    comparison_error: str | None = None,
) -> WorkbenchWorkflowView:
    """Project workbench state without mutating IDA or inferring correctness."""
    if snapshot is None:
        return _unavailable_view("Select a pseudocode function.")
    if running:
        return _running_view(snapshot)
    if snapshot.freshness is not SnapshotFreshness.CURRENT:
        return _unavailable_view(
            "Refresh the stale workbench snapshot before running deobfuscation.",
            snapshot,
        )
    if not snapshot.engine_started:
        return _unavailable_view("Start D810 before running deobfuscation.", snapshot)
    if _needs_investigation(snapshot, last_result):
        return _investigation_view(snapshot, last_result)
    if _current_successful_deobfuscation(snapshot, last_result):
        if comparison_error:
            return _investigation_view(snapshot, comparison_detail=comparison_error)
        if (
            comparison is not None
            and comparison.comparable
            and comparison.function_ea == snapshot.function.ea
        ):
            return _verification_view(snapshot, comparison)
        if comparison is not None:
            return _investigation_view(snapshot, comparison_detail=comparison.summary)
    return _ready_view(snapshot)


__all__ = [
    "WorkbenchWorkflowView",
    "WorkflowActionView",
    "WorkflowPhase",
    "project_workbench_workflow",
]
