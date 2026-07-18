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


def _snapshot() -> DeobfuscationWorkbenchSnapshot:
    generation = 4
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


def _comparison_view(*, text_changed: bool, comparable: bool = True):
    comparison = workbench_logic.comparison_view(
        WorkbenchComparisonSnapshot(
            function_ea=0x401000,
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
    *, status: OutcomeStatus = OutcomeStatus.CHANGED
) -> WorkbenchCommandResult:
    snapshot = _snapshot()
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


def test_blocked_failed_and_stale_results_require_investigation() -> None:
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
        last_result=dataclasses.replace(
            _accepted_deobfuscation_result(), requested_generation=3
        ),
    )

    assert blocked.phase is workflow.WorkflowPhase.INVESTIGATE
    assert failed.phase is workflow.WorkflowPhase.INVESTIGATE
    assert stale.phase is workflow.WorkflowPhase.INVESTIGATE
    assert all(
        view.primary.action_id == "diagnostics" for view in (blocked, failed, stale)
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


def test_comparison_error_is_retryable_and_rule_firings_do_not_change_copy() -> None:
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

    assert original.phase is workflow.WorkflowPhase.INVESTIGATE
    assert original.primary.action_id == "compare"
    assert "Native capture timed out" in original.detail
    assert (original.headline, original.detail) == (altered.headline, altered.detail)
    assert "correct" not in (original.headline + original.detail).casefold()
    assert "rule firing" not in (original.headline + original.detail).casefold()
