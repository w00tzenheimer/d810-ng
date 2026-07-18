from __future__ import annotations

import dataclasses
import importlib.util

from d810.manager.workbench_models import (
    ArtifactFreshness,
    ArtifactRef,
    AttackSummary,
    BaselineRef,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    FunctionRef,
    OutcomeStatus,
    RuleScopeSummary,
    RuntimeConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
    WorkbenchCommandResult,
    WorkbenchComparisonSnapshot,
)
from d810.ui import workbench_logic
from d810.ui import workbench_workflow_logic as workflow


def _snapshot(*, generation: int = 4) -> DeobfuscationWorkbenchSnapshot:
    return DeobfuscationWorkbenchSnapshot(
        generation=generation,
        function=FunctionRef(0x401000, "target", "sha256:abc", generation),
        runtime=RuntimeConfigRef(
            source_name="default_ollvm.json",
            source_path="/configs/default_ollvm.json",
            runtime_name="default_ollvm_v2.json",
            runtime_path="/configs/default_ollvm_v2.json",
            mode="config-v2",
            routed=True,
            hook_mode="config-v2",
            pass_ids=("first", "second"),
        ),
        attack=AttackSummary(
            observed_shape="ollvm_flat",
            mechanism="unavailable",
            selected_profile=None,
            selection_mode="recon-hints",
            confidence=0.9,
            recommended_inferences=("unflattening",),
            suppressed_rules=(),
            candidate_kinds=("flattened_switch",),
        ),
        pipeline=(),
        consumers=(),
        rule_scope=RuleScopeSummary((), (), (), (), (), "", None, (), (), False),
        statistics=StatisticsSummary((), (), (), 0, (), 0),
        baseline=BaselineRef(False, None, None, None),
        latest_output=D810OutputRef(False, None, None, None),
        artifacts=(ArtifactRef("recon-db", "Recon database", "/logs/recon.db", True),),
        freshness=SnapshotFreshness.CURRENT,
        engine_started=True,
        collection_errors=(),
    )


def _comparison_view(
    *,
    text_changed: bool,
    comparable: bool = True,
    function_ea: int = 0x401000,
):
    comparison = workbench_logic.comparison_view(
        WorkbenchComparisonSnapshot(
            function_ea=function_ea,
            baseline=BaselineRef(True, "sha256:abc", None, 4, pseudocode="native();"),
            d810_output=D810OutputRef(
                True, "sha256:abc", None, 4, pseudocode="d810();"
            ),
            baseline_freshness=(
                ArtifactFreshness.CURRENT if comparable else ArtifactFreshness.STALE
            ),
            d810_freshness=ArtifactFreshness.CURRENT,
            baseline_stale_reasons=("Baseline generation changed",)
            if not comparable
            else (),
            d810_stale_reasons=(),
            text_changed=text_changed if comparable else None,
            metrics=(),
        )
    )
    return comparison


def _accepted_deobfuscation_result(
    snapshot: DeobfuscationWorkbenchSnapshot | None = None,
    *,
    status: OutcomeStatus = OutcomeStatus.CHANGED,
) -> WorkbenchCommandResult:
    snapshot = snapshot or _snapshot()
    return WorkbenchCommandResult(
        command="deobfuscate",
        function_ea=snapshot.function.ea,
        requested_generation=snapshot.generation,
        function_fingerprint=snapshot.function.fingerprint,
        status=status,
        succeeded=True,
        accepted=True,
        refresh_requested=True,
        message="run completed",
    )


def test_workbench_workflow_logic_module_exists() -> None:
    assert importlib.util.find_spec("d810.ui.workbench_workflow_logic") is not None


def test_current_started_snapshot_offers_immediate_deobfuscation() -> None:
    view = workflow.project_workbench_workflow(_snapshot())

    assert view.phase is workflow.WorkflowPhase.READY
    assert view.primary.action_id == "deobfuscate"
    assert view.primary.label == "Deobfuscate this function"
    assert view.primary.enabled is True
    assert "default_ollvm_v2.json" in view.detail


def test_current_comparison_offers_contextual_tuning() -> None:
    view = workflow.project_workbench_workflow(
        _snapshot(),
        comparison=_comparison_view(text_changed=True),
        last_result=_accepted_deobfuscation_result(),
    )

    assert view.phase is workflow.WorkflowPhase.VERIFY
    assert view.primary.action_id == "compare"
    assert tuple(action.action_id for action in view.secondary) == (
        "diagnostics",
        "recipe",
        "function_override",
    )
    assert "correct" not in (view.headline + view.detail).casefold()


def test_refreshed_snapshot_verifies_accepted_direct_run() -> None:
    pre_run_snapshot = _snapshot(generation=4)
    refreshed_snapshot = _snapshot(generation=5)

    view = workflow.project_workbench_workflow(
        refreshed_snapshot,
        comparison=_comparison_view(text_changed=True),
        last_result=_accepted_deobfuscation_result(pre_run_snapshot),
    )

    assert view.phase is workflow.WorkflowPhase.VERIFY
    assert view.comparison_state == "current"


def test_comparison_for_another_function_cannot_verify_a_direct_run() -> None:
    view = workflow.project_workbench_workflow(
        _snapshot(),
        comparison=_comparison_view(text_changed=True, function_ea=0x402000),
        last_result=_accepted_deobfuscation_result(),
    )

    assert view.phase is workflow.WorkflowPhase.INVESTIGATE
    assert view.primary.action_id == "compare"
    assert view.comparison_state == "retry"


def test_stale_and_stopped_snapshots_disable_the_direct_action() -> None:
    stale = workflow.project_workbench_workflow(
        dataclasses.replace(_snapshot(), freshness=SnapshotFreshness.STALE)
    )
    stopped = workflow.project_workbench_workflow(
        dataclasses.replace(_snapshot(), engine_started=False)
    )

    assert stale.phase is workflow.WorkflowPhase.UNAVAILABLE
    assert stale.primary.enabled is False
    assert "Refresh" in stale.primary.reason
    assert stopped.phase is workflow.WorkflowPhase.UNAVAILABLE
    assert stopped.primary.enabled is False
    assert "Start D810" in stopped.primary.reason


def test_running_snapshot_reports_the_transient_run_state() -> None:
    view = workflow.project_workbench_workflow(_snapshot(), running=True)

    assert view.phase is workflow.WorkflowPhase.RUNNING
    assert view.primary.enabled is False
    assert view.primary.label == "Running deobfuscation..."


def test_blocked_failed_abstained_no_match_and_stale_results_require_investigation() -> (
    None
):
    blocked = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(status=OutcomeStatus.BLOCKED),
    )
    failed = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=dataclasses.replace(
            _accepted_deobfuscation_result(),
            succeeded=False,
            status=OutcomeStatus.FAILED,
        ),
    )
    stale = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(status=OutcomeStatus.STALE),
    )
    abstained = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(status=OutcomeStatus.ABSTAINED),
    )
    no_match = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(status=OutcomeStatus.NO_MATCH),
    )

    assert blocked.phase is workflow.WorkflowPhase.INVESTIGATE
    assert failed.phase is workflow.WorkflowPhase.INVESTIGATE
    assert stale.phase is workflow.WorkflowPhase.INVESTIGATE
    assert abstained.phase is workflow.WorkflowPhase.INVESTIGATE
    assert no_match.phase is workflow.WorkflowPhase.INVESTIGATE
    assert all(
        view.primary.action_id == "diagnostics"
        for view in (blocked, failed, stale, abstained, no_match)
    )


def test_rejected_direct_results_remain_investigation_despite_comparison_error() -> (
    None
):
    rejected = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=dataclasses.replace(
            _accepted_deobfuscation_result(), accepted=False
        ),
        comparison_error="Native capture timed out",
    )
    blocked = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(status=OutcomeStatus.BLOCKED),
        comparison_error="Native capture timed out",
    )
    failed = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=dataclasses.replace(
            _accepted_deobfuscation_result(),
            succeeded=False,
            status=OutcomeStatus.FAILED,
        ),
        comparison_error="Native capture timed out",
    )
    stale = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(status=OutcomeStatus.STALE),
        comparison_error="Native capture timed out",
    )

    assert all(
        view.phase is workflow.WorkflowPhase.INVESTIGATE
        and view.primary.action_id == "diagnostics"
        for view in (rejected, blocked, failed, stale)
    )


def test_unavailable_comparison_after_current_run_is_retryable_investigation() -> None:
    view = workflow.project_workbench_workflow(
        _snapshot(),
        comparison=_comparison_view(text_changed=False, comparable=False),
        last_result=_accepted_deobfuscation_result(),
    )

    assert view.phase is workflow.WorkflowPhase.INVESTIGATE
    assert view.primary.action_id == "compare"
    assert view.primary.label == "Retry comparison"
    assert "correct" not in (view.headline + view.detail).casefold()


def test_comparison_error_requires_an_accepted_current_direct_run() -> None:
    snapshot = _snapshot()
    altered_statistics = dataclasses.replace(
        snapshot,
        statistics=StatisticsSummary((), (), (), 999, (), 0),
    )

    original = workflow.project_workbench_workflow(
        snapshot, comparison_error="Native capture timed out"
    )
    altered = workflow.project_workbench_workflow(
        altered_statistics, comparison_error="Native capture timed out"
    )

    assert original.phase is workflow.WorkflowPhase.READY
    assert original.primary.action_id == "deobfuscate"
    assert "Native capture timed out" not in original.detail
    assert (original.headline, original.detail) == (altered.headline, altered.detail)
    assert "correct" not in (original.headline + original.detail).casefold()
    assert "rule firing" not in (original.headline + original.detail).casefold()


def test_comparison_error_after_accepted_current_direct_run_is_retryable() -> None:
    view = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(),
        comparison_error="Native capture timed out",
    )

    assert view.phase is workflow.WorkflowPhase.INVESTIGATE
    assert view.primary.action_id == "compare"
    assert "Native capture timed out" in view.detail


def test_missing_comparison_after_accepted_current_direct_run_is_retryable() -> None:
    view = workflow.project_workbench_workflow(
        _snapshot(),
        last_result=_accepted_deobfuscation_result(),
    )

    assert view.phase is workflow.WorkflowPhase.INVESTIGATE
    assert view.primary.action_id == "compare"
    assert view.primary.label == "Retry comparison"
    assert view.comparison_state == "retry"
