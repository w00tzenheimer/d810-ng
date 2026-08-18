from __future__ import annotations

import ast
import dataclasses
import importlib.util
import json
from pathlib import Path

from d810.manager.workbench_models import (
    ArtifactFreshness,
    ArtifactRef,
    AttackSummary,
    BaselineRef,
    ConsumerOutcomeSnapshot,
    ComparisonMetric,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    EffectiveStageDecisionSummary,
    ExecutionAttemptSummary,
    ExecutionLedgerSummary,
    FunctionRef,
    OutcomeStatus,
    PipelineStageSnapshot,
    ExecutionScopeSummary,
    ProjectConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
    EffectiveMaturitySchedule,
    EffectiveMaturityScheduleRow,
    EffectiveScheduleStage,
    WorkbenchCommandResult,
    WorkbenchComparisonSnapshot,
)
from d810.ui import workbench_logic as logic


def test_workbench_logic_module_exists() -> None:
    assert importlib.util.find_spec("d810.ui.workbench_logic") is not None


def _snapshot() -> DeobfuscationWorkbenchSnapshot:
    generation = 4
    return DeobfuscationWorkbenchSnapshot(
        generation=generation,
        function=FunctionRef(0x401000, "target", "sha256:abc", generation),
        project=ProjectConfigRef(
            project_name="default_ollvm.json",
            project_path="/configs/default_ollvm.json",
            pass_ids=("first", "second"),
        ),
        attack=AttackSummary(
            observed_shape="ollvm_flat",
            mechanism="unavailable",
            selected_profile=None,
            selection_mode="recon-hints",
            confidence=0.9,
            recommended_inferences=("unflattening",),
            suppressed_stages=(),
            candidate_kinds=("flattened_switch",),
        ),
        pipeline=(
            PipelineStageSnapshot(
                ordinal=0,
                pass_id="first",
                phase="function",
                scope="function",
                maturity="any",
                status=OutcomeStatus.READY,
                summary="requirements satisfied",
                contract_json='{"pass":"first"}',
                diagnostics=(),
            ),
            PipelineStageSnapshot(
                ordinal=1,
                pass_id="second",
                phase="function",
                scope="function",
                maturity="ir.global.optimized",
                status=OutcomeStatus.BLOCKED,
                summary="missing state_transition",
                contract_json='{"pass":"second"}',
                diagnostics=(),
            ),
        ),
        consumers=(
            ConsumerOutcomeSnapshot(
                phase="supporting",
                consumer_name="execution_scope",
                status=OutcomeStatus.ABSTAINED,
                detail="verdict was not applied",
                provenance_json=None,
            ),
        ),
        execution_scope=ExecutionScopeSummary(
            public_passes=("constant-simplification",),
            function_tags=("hard",),
            inference_names=("unflattening",),
            decisions=(
                EffectiveStageDecisionSummary(
                    "constant-simplification",
                    "fold-constant-subtree",
                    "instruction",
                    (1,),
                    True,
                    "active",
                    "passed all scope gates",
                ),
            ),
            unknown_targets=(),
        ),
        statistics=StatisticsSummary((), 0, ()),
        baseline=BaselineRef(False, None, None, None),
        latest_output=D810OutputRef(False, None, None, None),
        artifacts=(
            ArtifactRef(
                kind="recon-db",
                label="Recon database",
                path="/logs/recon.db",
                available=True,
            ),
        ),
        freshness=SnapshotFreshness.CURRENT,
        engine_started=True,
        collection_errors=("statistics: unavailable",),
    )


def test_status_presentations_cover_every_approved_outcome() -> None:
    presentations = {
        status: logic.status_presentation(status) for status in OutcomeStatus
    }

    assert set(presentations) == set(OutcomeStatus)
    assert all(presentation.color_role for presentation in presentations.values())
    assert all(presentation.tooltip for presentation in presentations.values())
    assert presentations[OutcomeStatus.CHANGED].color_role == "success"
    assert presentations[OutcomeStatus.FAILED].color_role == "danger"
    assert presentations[OutcomeStatus.STALE].color_role == "stale"


def test_rows_preserve_pipeline_order_and_keep_consumers_supporting() -> None:
    rows = logic.project_workbench_rows(_snapshot())
    pipeline = tuple(
        row for row in rows if row.section is logic.WorkbenchSection.PIPELINE
    )
    supporting = tuple(
        row for row in rows if row.section is logic.WorkbenchSection.SUPPORTING
    )

    assert tuple(row.label for row in pipeline) == ("1. first", "2. second")
    assert tuple(row.status for row in pipeline) == (
        OutcomeStatus.READY,
        OutcomeStatus.BLOCKED,
    )
    assert all("execution_scope" not in row.key for row in pipeline)
    assert any(row.key == "consumer:execution_scope" for row in supporting)
    assert (
        next(row for row in supporting if row.key == "consumer:execution_scope").status
        is OutcomeStatus.ABSTAINED
    )


def test_compiled_schedule_rows_show_contract_fields_and_preparation_state() -> None:
    readonly = EffectiveScheduleStage(
        configured_index=0,
        runtime_order=0,
        pass_id="constant-simplification",
        stage_id="fold-readonly-data",
        pipeline="instruction",
        implementation_name="FoldReadonlyDataRule",
        requirements=(),
        provider_maturities=("MMAT_PREOPTIMIZED",),
        maturity_source="compiled stage contract",
        enabled=True,
        supported_maturities=("CANONICAL", "LOCAL_OPTIMIZED"),
        requested_maturities=("CANONICAL",),
        pass_maturity_gates=("CANONICAL", "LOCAL_OPTIMIZED"),
        effective_maturities=("CANONICAL",),
        lifecycle_domain="microcode",
        schedule_source="compiled stage contract",
        inactive_reason=None,
    )
    disabled = dataclasses.replace(
        readonly,
        stage_id="fold-constant-subtree",
        implementation_name="ConstantSubtreeFoldRule",
        runtime_order=-1,
        provider_maturities=(),
        enabled=False,
        requested_maturities=("LOCAL_OPTIMIZED",),
        effective_maturities=(),
        inactive_reason="disabled by configuration",
    )
    forward = dataclasses.replace(
        readonly,
        stage_id="forward-constants",
        pipeline="flow",
        implementation_name="ForwardConstantPropagationRule",
        runtime_order=0,
        provider_maturities=("MMAT_LOCOPT",),
        supported_maturities=("CALL_MODELED",),
        requested_maturities=("CALL_MODELED",),
        pass_maturity_gates=("CALL_MODELED",),
        effective_maturities=("CALL_MODELED",),
    )
    preparation = EffectiveScheduleStage(
        configured_index=0,
        runtime_order=-1,
        pass_id="constant-simplification",
        stage_id="global-const-types",
        pipeline="",
        implementation_name="",
        requirements=(),
        provider_maturities=(),
        maturity_source="compiled stage contract",
        enabled=True,
        supported_maturities=(),
        requested_maturities=(),
        pass_maturity_gates=(),
        effective_maturities=(),
        lifecycle_domain="PRE_HEXRAYS",
        schedule_source="compiled stage contract",
        inactive_reason=None,
        preparation_state="pending",
        preparation_reason="next preparation round",
    )
    scheduled = dataclasses.replace(
        _snapshot(),
        effective_schedule=EffectiveMaturitySchedule(
            rows=(
                EffectiveMaturityScheduleRow(
                    ordinal=1,
                    ir_maturity="ir.local.optimized",
                    provider_maturity="MMAT_LOCOPT",
                    pipeline_stages=(
                        ("instruction", (readonly, disabled)),
                        ("flow", (forward,)),
                    ),
                ),
            ),
            stages=(preparation, readonly, disabled, forward),
        ),
    )

    rows = logic.project_workbench_rows(scheduled)
    pipeline_rows = tuple(
        row for row in rows if row.section is logic.WorkbenchSection.PIPELINE
    )
    detail = "\n".join(row.detail for row in pipeline_rows)

    assert "supported: CANONICAL, LOCAL_OPTIMIZED" in detail
    assert "requested: CANONICAL" in detail
    assert "pass gates: CANONICAL, LOCAL_OPTIMIZED" in detail
    assert "effective: CANONICAL" in detail
    assert "source: compiled stage contract" in detail
    assert "instruction pipeline" in detail
    assert "flow pipeline" in detail
    assert "no total callback order is implied" in detail
    assert "runtime order: 0" in detail
    assert "disabled by configuration" in detail
    assert any(
        row.key == "pipeline:stage:fold-constant-subtree" for row in pipeline_rows
    )
    assert "PRE_HEXRAYS" in detail
    assert "pending" in detail
    assert "next preparation round" in detail


def test_preparation_row_projects_each_durable_proposal_state() -> None:
    base = EffectiveScheduleStage(
        configured_index=0,
        runtime_order=-1,
        pass_id="constant-simplification",
        stage_id="global-const-types",
        pipeline="",
        implementation_name="",
        requirements=(),
        provider_maturities=(),
        maturity_source="compiled stage contract",
        enabled=True,
        supported_maturities=(),
        requested_maturities=(),
        pass_maturity_gates=(),
        effective_maturities=(),
        lifecycle_domain="PRE_HEXRAYS",
        schedule_source="compiled stage contract",
        inactive_reason=None,
    )
    expected_status = {
        "pending": OutcomeStatus.READY,
        "applied": OutcomeStatus.CHANGED,
        "conflicting": OutcomeStatus.BLOCKED,
        "restored": OutcomeStatus.UNCHANGED,
    }
    for state in expected_status:
        stage = dataclasses.replace(
            base,
            preparation_state=state,
            preparation_reason=(
                "next preparation round" if state == "pending" else None
            ),
        )
        scheduled = dataclasses.replace(
            _snapshot(),
            effective_schedule=EffectiveMaturitySchedule(stages=(stage,)),
        )

        rows = logic.project_workbench_rows(scheduled)
        preparation = next(row for row in rows if row.key == "pipeline:preparation:global-const-types")

        assert state in preparation.detail
        assert preparation.status is expected_status[state]
        if state == "pending":
            assert "next preparation round" in preparation.detail


def test_preparation_row_renders_simultaneous_buckets_and_provider_failures() -> None:
    stage = EffectiveScheduleStage(
        configured_index=0,
        runtime_order=-1,
        pass_id="constant-simplification",
        stage_id="global-const-types",
        pipeline="",
        implementation_name="",
        requirements=(),
        provider_maturities=(),
        maturity_source="compiled stage contract",
        enabled=True,
        lifecycle_domain="PRE_HEXRAYS",
        schedule_source="compiled stage contract",
        preparation_state="pending, applied, conflicting, restored, unknown",
        preparation_reason="next preparation round",
        preparation_pending_count=2,
        preparation_applied_count=3,
        preparation_conflicting_count=4,
        preparation_restored_count=5,
        preparation_unknown_count=1,
        preparation_provider_failures=(
            "transaction_type_deltas: RuntimeError: provider unavailable",
        ),
    )
    scheduled = dataclasses.replace(
        _snapshot(),
        effective_schedule=EffectiveMaturitySchedule(stages=(stage,)),
    )

    row = next(
        row
        for row in logic.project_workbench_rows(scheduled)
        if row.key == "pipeline:preparation:global-const-types"
    )

    assert row.status is OutcomeStatus.FAILED
    assert "preparation buckets: pending: 2, applied: 3, conflicting: 4, restored: 5, unknown: 1" in row.detail
    assert "provider failure: transaction_type_deltas: RuntimeError: provider unavailable" in row.detail
    assert "preparation reason: next preparation round" in row.detail


def test_missing_compiled_schedule_is_visible_as_unavailable_contract() -> None:
    stage = EffectiveScheduleStage(
        configured_index=0,
        runtime_order=-1,
        pass_id="constant-simplification",
        stage_id="fold-readonly-data",
        pipeline="instruction",
        implementation_name="FoldReadonlyDataRule",
        requirements=(),
        provider_maturities=(),
        maturity_source="compiled stage contract unavailable",
        enabled=False,
        supported_maturities=("CANONICAL",),
        schedule_source="compiled stage contract unavailable",
        inactive_reason="compiled schedule unavailable",
        lifecycle_domain="MICROCODE",
    )
    scheduled = dataclasses.replace(
        _snapshot(),
        effective_schedule=EffectiveMaturitySchedule(stages=(stage,)),
    )

    row = next(
        row
        for row in logic.project_workbench_rows(scheduled)
        if row.key == "pipeline:stage:fold-readonly-data"
    )

    assert row.status is OutcomeStatus.NOT_ELIGIBLE
    assert "source: compiled stage contract unavailable" in row.detail
    assert "inactive/rejected reason: compiled schedule unavailable" in row.detail


def test_supporting_rows_lead_with_session_execution_ledger_and_demote_counters() -> (
    None
):
    snapshot = _snapshot()
    snapshot = dataclasses.replace(
        snapshot,
        execution_ledger=ExecutionLedgerSummary(
            session_id="session-1",
            function_ea=0x401000,
            attempts=(
                ExecutionAttemptSummary(
                    sequence=1,
                    parent_sequence=None,
                    stage_id="hexrays_preanalysis",
                    domain="hook",
                    status="completed",
                    reason_code=None,
                    elapsed_ms=1.25,
                    effect_refs_json="[]",
                    details_json="{}",
                ),
                ExecutionAttemptSummary(
                    sequence=2,
                    parent_sequence=1,
                    stage_id="ctree_rule:noop",
                    domain="hook",
                    status="abstained",
                    reason_code="no_modifications",
                    elapsed_ms=0.5,
                    effect_refs_json="[]",
                    details_json='{"patch_count":0}',
                ),
            ),
            terminal_attempts=2,
            in_progress_attempts=0,
        ),
    )

    supporting = tuple(
        row
        for row in logic.project_workbench_rows(snapshot)
        if row.section is logic.WorkbenchSection.SUPPORTING
    )
    ledger = next(row for row in supporting if row.key == "supporting:execution-ledger")
    legacy = next(row for row in supporting if row.key == "supporting:statistics")

    assert ledger.label == "Execution ledger"
    assert ledger.summary == "2 terminal, 0 in progress"
    assert "2 <- 1 hook ctree_rule:noop: abstained" in ledger.detail
    assert "reason=no_modifications" in ledger.detail
    assert ledger.status is OutcomeStatus.READY
    assert legacy.label == "Legacy counters"
    assert supporting.index(ledger) < supporting.index(legacy)


def test_context_rows_project_one_canonical_identity() -> None:
    rows = logic.project_workbench_rows(_snapshot())
    project = next(row for row in rows if row.key == "context:project")

    assert "default_ollvm.json" in project.summary
    assert "/configs/default_ollvm.json" in project.detail
    assert "passes: first, second" in project.detail


def test_context_project_labels_saved_recipe_as_explicit_only() -> None:
    snapshot = _snapshot()
    scoped = dataclasses.replace(
        snapshot,
        project=dataclasses.replace(
            snapshot.project,
            recipe_scope="saved-recipe-explicit",
            pass_ids=("jump-fixer",),
        ),
    )

    project = next(
        row
        for row in logic.project_workbench_rows(scoped)
        if row.key == "context:project"
    )

    assert "saved recipe" in project.summary
    assert "ordinary refresh uses the project" in project.detail
    assert "Deobfuscate This" in project.detail
    assert "passes: jump-fixer" in project.detail


def test_filter_is_case_insensitive_searches_status_and_preserves_order() -> None:
    rows = logic.project_workbench_rows(_snapshot())

    by_text = logic.filter_workbench_rows(rows, "STATE_TRANSITION")
    by_status = logic.filter_workbench_rows(rows, "blocked")
    empty = logic.filter_workbench_rows(rows, "  ")

    assert tuple(row.key for row in by_text) == ("pipeline:1:second",)
    assert tuple(row.key for row in by_status) == ("pipeline:1:second",)
    assert empty == rows


def test_current_started_snapshot_enables_scoped_slice_two_actions() -> None:
    states = {state.action_id: state for state in logic.action_states(_snapshot())}

    assert states["refresh"].enabled is True
    assert states["export"].enabled is True
    assert states["analyze"].enabled is True
    assert states["deobfuscate"].enabled is True
    assert "function_override" not in states
    assert states["compare"].enabled is True
    assert states["recipe"].enabled is True
    assert states["recipe"].reason == ""
    assert states["diagnostics"].enabled is True
    assert states["diagnostics"].reason == ""


def test_stale_snapshot_marks_pipeline_consumers_and_disables_scoped_actions() -> None:
    snapshot = _snapshot()

    stale = logic.stale_snapshot(snapshot)
    states = {state.action_id: state for state in logic.action_states(stale)}

    assert stale.freshness is SnapshotFreshness.STALE
    assert tuple(stage.status for stage in stale.pipeline) == (
        OutcomeStatus.STALE,
        OutcomeStatus.STALE,
    )
    assert tuple(outcome.status for outcome in stale.consumers) == (
        OutcomeStatus.STALE,
    )
    assert stale.pipeline[0].contract_json == snapshot.pipeline[0].contract_json
    assert stale.artifacts == snapshot.artifacts
    assert states["refresh"].enabled is True
    assert states["export"].enabled is True
    assert states["analyze"].enabled is False
    assert states["deobfuscate"].enabled is False
    assert "function_override" not in states
    assert states["compare"].enabled is False


def _comparison(
    *,
    baseline_freshness: ArtifactFreshness = ArtifactFreshness.CURRENT,
    d810_freshness: ArtifactFreshness = ArtifactFreshness.CURRENT,
) -> WorkbenchComparisonSnapshot:
    baseline = BaselineRef(
        True,
        "sha256:abc",
        None,
        4,
        function_ea=0x401000,
        pseudocode="native();\n",
        line_count=1,
        character_count=10,
    )
    output = D810OutputRef(
        True,
        "sha256:abc",
        None,
        4,
        function_ea=0x401000,
        pseudocode="d810();\n",
        line_count=1,
        character_count=8,
    )
    baseline_reasons = (
        ()
        if baseline_freshness is ArtifactFreshness.CURRENT
        else ("Type generation changed",)
    )
    output_reasons = (
        ()
        if d810_freshness is ArtifactFreshness.CURRENT
        else ("Project generation changed",)
    )
    return WorkbenchComparisonSnapshot(
        function_ea=0x401000,
        baseline=baseline,
        d810_output=output,
        baseline_freshness=baseline_freshness,
        d810_freshness=d810_freshness,
        baseline_stale_reasons=baseline_reasons,
        d810_stale_reasons=output_reasons,
        text_changed=(
            True
            if baseline_freshness is ArtifactFreshness.CURRENT
            and d810_freshness is ArtifactFreshness.CURRENT
            else None
        ),
        metrics=(
            (
                ComparisonMetric("Lines", 1, 1, 0),
                ComparisonMetric("Characters", 10, 8, -2),
            )
            if baseline_freshness is ArtifactFreshness.CURRENT
            and d810_freshness is ArtifactFreshness.CURRENT
            else ()
        ),
    )


def test_comparison_view_projects_current_labeled_text_and_metrics() -> None:
    view = logic.comparison_view(_comparison())

    assert view.comparable is True
    assert view.native.label == "Native"
    assert view.native.text == "native();\n"
    assert view.native.freshness is ArtifactFreshness.CURRENT
    assert view.d810.label == "D810"
    assert view.d810.text == "d810();\n"
    assert view.text_changed is True
    assert [metric.label for metric in view.metrics] == ["Lines", "Characters"]
    assert view.metrics[1].delta == -2
    assert "correct" not in view.summary.casefold()


def test_comparison_view_exposes_stale_reasons_and_suppresses_metrics() -> None:
    view = logic.comparison_view(_comparison(d810_freshness=ArtifactFreshness.STALE))

    assert view.comparable is False
    assert view.native.is_current is True
    assert view.d810.is_current is False
    assert view.d810.reasons == ("Project generation changed",)
    assert view.metrics == ()
    assert view.text_changed is None
    assert "stale" in view.d810.status.casefold()


def test_comparison_view_labels_missing_artifact_without_placeholder_truth() -> None:
    comparison = dataclasses.replace(
        _comparison(),
        baseline=BaselineRef(False, None, None, None, function_ea=0x401000),
        baseline_freshness=ArtifactFreshness.MISSING,
        baseline_stale_reasons=("Native baseline has not been captured",),
        text_changed=None,
        metrics=(),
    )

    view = logic.comparison_view(comparison)

    assert view.comparable is False
    assert view.native.text == ""
    assert view.native.is_current is False
    assert view.native.reasons == ("Native baseline has not been captured",)


def test_command_request_binds_current_function_identity() -> None:
    snapshot = _snapshot()

    request = logic.command_request(snapshot, "analyze")

    assert request.command == "analyze"
    assert request.function_ea == snapshot.function.ea
    assert request.expected_generation == snapshot.generation
    assert request.function_fingerprint == snapshot.function.fingerprint


def test_command_completion_requires_exact_identity_and_acceptance() -> None:
    snapshot = _snapshot()
    result = WorkbenchCommandResult(
        command="analyze",
        function_ea=snapshot.function.ea,
        requested_generation=snapshot.generation,
        function_fingerprint=snapshot.function.fingerprint,
        status=OutcomeStatus.READY,
        succeeded=True,
        accepted=True,
        refresh_requested=True,
        message="done",
    )

    assert logic.should_accept_command_result(snapshot, result) is True
    assert (
        logic.should_accept_command_result(
            snapshot,
            dataclasses.replace(result, accepted=False),
        )
        is False
    )
    assert (
        logic.should_accept_command_result(
            snapshot,
            dataclasses.replace(result, function_ea=0x402000),
        )
        is False
    )
    assert (
        logic.should_accept_command_result(
            snapshot,
            dataclasses.replace(result, requested_generation=3),
        )
        is False
    )
    assert (
        logic.should_accept_command_result(
            snapshot,
            dataclasses.replace(result, function_fingerprint="sha256:other"),
        )
        is False
    )


def test_evidence_export_is_canonical_deterministic_json() -> None:
    snapshot = _snapshot()
    first = logic.export_evidence_json(snapshot)
    second = logic.export_evidence_json(snapshot)
    expected = {
        "artifacts": [
            {
                "available": True,
                "kind": "recon-db",
                "label": "Recon database",
                "path": "/logs/recon.db",
            }
        ],
        "attack": {
            "candidate_kinds": ["flattened_switch"],
            "confidence": 0.9,
            "mechanism": "unavailable",
            "observed_shape": "ollvm_flat",
            "recommended_inferences": ["unflattening"],
            "selected_profile": None,
            "selection_mode": "recon-hints",
            "suppressed_stages": [],
        },
        "baseline": {
            "available": False,
            "captured_at": None,
            "character_count": 0,
            "content_sha256": None,
            "fingerprint": None,
            "function_ea": None,
            "generation": None,
            "hexrays_version": None,
            "idb_identity": None,
            "line_count": 0,
            "path": None,
            "pseudocode": None,
            "type_generation": None,
        },
        "case": None,
        "collection_errors": ["statistics: unavailable"],
        "consumers": [
            {
                "consumer_name": "execution_scope",
                "detail": "verdict was not applied",
                "phase": "supporting",
                "provenance_json": None,
                "status": "Abstained",
            }
        ],
        "engine_started": True,
        "effective_schedule": {
            "rows": [],
            "stages": [],
        },
        "execution_ledger": {
            "attempts": [],
            "function_ea": 0,
            "in_progress_attempts": 0,
            "session_id": None,
            "terminal_attempts": 0,
        },
        "execution_profile": {
            "candidates": [],
            "identity_json": None,
            "ignored_identity_mismatch_count": 0,
            "ignored_in_progress_count": 0,
            "is_read_only": True,
        },
        "freshness": "current",
        "function": {
            "ea": 0x401000,
            "fingerprint": "sha256:abc",
            "generation": 4,
            "name": "target",
        },
        "generation": 4,
        "latest_output": {
            "available": False,
            "captured_at": None,
            "character_count": 0,
            "content_sha256": None,
            "fingerprint": None,
            "function_ea": None,
            "generation": None,
            "hexrays_version": None,
            "idb_identity": None,
            "line_count": 0,
            "path": None,
            "pseudocode": None,
            "project_generation": None,
            "project_pass_ids": [],
            "project_path": None,
            "type_generation": None,
        },
        "pipeline": [
            {
                "contract_json": '{"pass":"first"}',
                "diagnostics": [],
                "maturity": "any",
                "ordinal": 0,
                "pass_id": "first",
                "phase": "function",
                "scope": "function",
                "status": "Ready",
                "summary": "requirements satisfied",
            },
            {
                "contract_json": '{"pass":"second"}',
                "diagnostics": [],
                "maturity": "ir.global.optimized",
                "ordinal": 1,
                "pass_id": "second",
                "phase": "function",
                "scope": "function",
                "status": "Blocked",
                "summary": "missing state_transition",
            },
        ],
        "preparation": {
            "database_identity": None,
            "scripts": [],
            "transactions": [],
        },
        "execution_scope": {
            "decisions": [
                {
                    "active": True,
                    "maturities": [1],
                    "pass_id": "constant-simplification",
                    "pipeline": "instruction",
                    "reason": "active",
                    "stage_id": "fold-constant-subtree",
                    "detail": "passed all scope gates",
                }
            ],
            "function_tags": ["hard"],
            "inference_names": ["unflattening"],
            "public_passes": ["constant-simplification"],
            "unknown_targets": [],
        },
        "project": {
            "pass_ids": ["first", "second"],
            "project_name": "default_ollvm.json",
            "project_path": "/configs/default_ollvm.json",
            "recipe_scope": "project",
        },
        "statistics": {
            "stage_patches": [],
            "stage_matches": [],
            "total_stage_firings": 0,
        },
    }

    assert first == second
    assert first == json.dumps(expected, indent=2, sort_keys=True) + "\n"


def test_logic_module_has_no_ida_qt_or_non_model_ui_dependencies() -> None:
    path = Path(logic.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)

    assert not any(
        name.startswith(("ida", "PyQt", "PySide", "shiboken")) for name in imports
    )
    assert not any(
        name.startswith("d810.ui.") and name != "d810.ui.workbench_logic"
        for name in imports
    )
    assert not any(
        token in name
        for name in imports
        for token in ("sqlite", "persistence", "registry", "pipeline_config")
    )
