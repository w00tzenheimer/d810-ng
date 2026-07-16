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
    FunctionRef,
    OutcomeStatus,
    PipelineStageSnapshot,
    RuleScopeSummary,
    RuntimeConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
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
                consumer_name="rule_scope",
                status=OutcomeStatus.ABSTAINED,
                detail="verdict was not applied",
                provenance_json=None,
            ),
        ),
        rule_scope=RuleScopeSummary(
            project_instruction_rules=("ProjectRule",),
            project_block_rules=(),
            function_enabled_rules=(),
            function_disabled_rules=(),
            function_tags=("hard",),
            function_notes="",
            inference_name="unflattening",
            inference_enabled_rules=("UnflattenRule",),
            inference_disabled_rules=(),
            inference_applies=True,
        ),
        statistics=StatisticsSummary((), (), (), 0, (), 0),
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
    pipeline = tuple(row for row in rows if row.section is logic.WorkbenchSection.PIPELINE)
    supporting = tuple(
        row for row in rows if row.section is logic.WorkbenchSection.SUPPORTING
    )

    assert tuple(row.label for row in pipeline) == ("1. first", "2. second")
    assert tuple(row.status for row in pipeline) == (
        OutcomeStatus.READY,
        OutcomeStatus.BLOCKED,
    )
    assert all("rule_scope" not in row.key for row in pipeline)
    assert any(row.key == "consumer:rule_scope" for row in supporting)
    assert next(row for row in supporting if row.key == "consumer:rule_scope").status \
        is OutcomeStatus.ABSTAINED


def test_context_rows_keep_source_and_runtime_truth_distinct() -> None:
    rows = logic.project_workbench_rows(_snapshot())
    runtime = next(row for row in rows if row.key == "context:runtime")

    assert "default_ollvm_v2.json" in runtime.summary
    assert "default_ollvm.json" in runtime.detail
    assert "/configs/default_ollvm_v2.json" in runtime.detail
    assert "config-v2" in runtime.detail


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
    assert states["function_override"].enabled is True
    assert states["compare"].enabled is True
    for action_id in ("recipe", "diagnostics"):
        assert states[action_id].enabled is False
        assert states[action_id].reason


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
    assert states["function_override"].enabled is False
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
        else ("Runtime generation changed",)
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
            ComparisonMetric("Lines", 1, 1, 0),
            ComparisonMetric("Characters", 10, 8, -2),
        )
        if baseline_freshness is ArtifactFreshness.CURRENT
        and d810_freshness is ArtifactFreshness.CURRENT
        else (),
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
    view = logic.comparison_view(
        _comparison(d810_freshness=ArtifactFreshness.STALE)
    )

    assert view.comparable is False
    assert view.native.is_current is True
    assert view.d810.is_current is False
    assert view.d810.reasons == ("Runtime generation changed",)
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
    assert logic.should_accept_command_result(
        snapshot,
        dataclasses.replace(result, accepted=False),
    ) is False
    assert logic.should_accept_command_result(
        snapshot,
        dataclasses.replace(result, function_ea=0x402000),
    ) is False
    assert logic.should_accept_command_result(
        snapshot,
        dataclasses.replace(result, requested_generation=3),
    ) is False
    assert logic.should_accept_command_result(
        snapshot,
        dataclasses.replace(result, function_fingerprint="sha256:other"),
    ) is False


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
            "suppressed_rules": [],
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
        "collection_errors": ["statistics: unavailable"],
        "consumers": [
            {
                "consumer_name": "rule_scope",
                "detail": "verdict was not applied",
                "phase": "supporting",
                "provenance_json": None,
                "status": "Abstained",
            }
        ],
        "engine_started": True,
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
            "runtime_generation": None,
            "runtime_pass_ids": [],
            "runtime_path": None,
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
        "rule_scope": {
            "function_disabled_rules": [],
            "function_enabled_rules": [],
            "function_notes": "",
            "function_tags": ["hard"],
            "inference_applies": True,
            "inference_disabled_rules": [],
            "inference_enabled_rules": ["UnflattenRule"],
            "inference_name": "unflattening",
            "project_block_rules": [],
            "project_instruction_rules": ["ProjectRule"],
        },
        "runtime": {
            "hook_mode": "config-v2",
            "mode": "config-v2",
            "pass_ids": ["first", "second"],
            "routed": True,
            "runtime_name": "default_ollvm_v2.json",
            "runtime_path": "/configs/default_ollvm_v2.json",
            "source_name": "default_ollvm.json",
            "source_path": "/configs/default_ollvm.json",
        },
        "statistics": {
            "cfg_patches": [],
            "cycles_detected": [],
            "optimizer_matches": [],
            "rule_matches": [],
            "total_cycles_detected": 0,
            "total_rule_firings": 0,
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
        name.startswith(("ida", "PyQt", "PySide", "shiboken"))
        for name in imports
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
