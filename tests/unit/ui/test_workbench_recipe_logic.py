from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

from d810.core.deobfuscation_case import (
    DeobfuscationCaseSnapshot,
    StrategyDeficiency,
    StrategyRecommendation,
    StrategyWorkflowStage,
)
from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_models import OutcomeStatus
from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeCommandResult,
    RecipeDiagnostic,
    RecipePass,
    RecipeValidation,
)
from d810.ui import workbench_recipe_logic as logic


def test_state_cff_minimum_constant_parser_accepts_hex_and_rejects_non_integer() -> (
    None
):
    assert logic.parse_state_cff_minimum_constant("0x8000").min_state_constant == 0x8000

    try:
        logic.parse_state_cff_minimum_constant("12.5")
    except ValueError as exc:
        assert "integer" in str(exc)
    else:
        raise AssertionError("non-integer state-CFF threshold was accepted")


def _catalog() -> tuple[PassCatalogEntry, ...]:
    return (
        PassCatalogEntry(
            "z-pass",
            "Z pass",
            '{"contract":"z"}',
            "{}",
            "function",
            "late",
            "mutation_backend",
            "golden",
            ("RuleZ",),
            ("TransformZ",),
            True,
            PassEditorSpec.summary(),
        ),
        PassCatalogEntry(
            "a-pass",
            "A pass",
            '{"contract":"a"}',
            "{}",
            "function",
            "early",
            "mutation_backend",
            "default",
            (),
            (),
            False,
            PassEditorSpec.summary(),
        ),
    )


def _draft() -> PipelineRecipeDraft:
    return PipelineRecipeDraft(
        "draft-1",
        1,
        2,
        0x401000,
        "sha256:abc",
        4,
        "/source.json",
        "/runtime.json",
        (
            RecipePass("item-z", "z-pass", True, '{"pass_id":"z-pass"}'),
            RecipePass("item-a", "a-pass", False, '{"pass_id":"a-pass"}'),
        ),
    )


def _validation(*, satisfied: bool = True) -> RecipeValidation:
    diagnostics = (
        ()
        if satisfied
        else (
            RecipeDiagnostic(
                "missing-contract-input",
                "missing recovered state",
                0,
                "z-pass",
                "requires.facts.required",
                ("recovered.state",),
            ),
        )
    )
    return RecipeValidation("draft-1", 2, satisfied, diagnostics, "[]")


def test_catalog_filter_and_sort_do_not_change_draft_execution_order() -> None:
    catalog_rows = logic.project_catalog_rows(_catalog(), query="transformz")
    draft_rows = logic.project_draft_rows(_draft(), _validation())

    assert [row.pass_id for row in catalog_rows] == ["z-pass"]
    assert catalog_rows[0].stage_children == ("TransformZ",)
    assert [row.pass_id for row in logic.project_catalog_rows(_catalog())] == [
        "a-pass",
        "z-pass",
    ]
    assert [row.pass_id for row in draft_rows] == ["z-pass", "a-pass"]
    assert [row.ordinal for row in draft_rows] == [0, 1]


def test_dangerous_executable_readonly_requires_confirmation_only_when_enabled():
    assert logic.enables_dangerous_executable_readonly(
        "constant-simplification",
        {"memory_policy": "strict", "allow_executable_readonly": False},
        {"memory_policy": "strict", "allow_executable_readonly": True},
    )
    assert not logic.enables_dangerous_executable_readonly(
        "constant-simplification",
        {"allow_executable_readonly": True},
        {"allow_executable_readonly": True},
    )
    assert not logic.enables_dangerous_executable_readonly(
        "jump-fixer",
        {},
        {"allow_executable_readonly": True},
    )


def test_catalog_exposes_display_stage_without_reordering_the_draft() -> None:
    catalog = (
        dataclasses.replace(
            _catalog()[0],
            workflow_stage=StrategyWorkflowStage.CANONICAL_TRANSFORM,
        ),
        dataclasses.replace(
            _catalog()[1],
            workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
        ),
    )

    rows = logic.project_catalog_rows(catalog, sort_by="stage")
    draft_rows = logic.project_draft_rows(_draft(), _validation())

    assert [row.workflow_stage for row in rows] == [
        StrategyWorkflowStage.FRONTEND_NORMALIZATION,
        StrategyWorkflowStage.CANONICAL_TRANSFORM,
    ]
    assert [row.pass_id for row in draft_rows] == ["z-pass", "a-pass"]


def test_recipe_strategy_explains_missing_evidence_without_raw_transform_editing() -> (
    None
):
    case = DeobfuscationCaseSnapshot(
        evidence=None,
        strategy=StrategyRecommendation(
            deficiency=StrategyDeficiency.CFG_FORMATION,
            summary="Recover the control-flow shape first.",
            required_finding_ids=("predicate:0x401000",),
            stages=(StrategyWorkflowStage.CANONICAL_ANALYSIS,),
        ),
        direct_run_permitted=False,
        direct_run_reason="Build a strategy before running it.",
    )

    view = logic.project_recipe_strategy(case, _catalog())

    assert view.strategy_summary == "Recover the control-flow shape first."
    assert view.blocked_reason == "Build the case dossier before composing a run."
    assert view.can_add_transform is False


def test_draft_rows_show_disabled_and_blocked_states_without_reordering() -> None:
    rows = logic.project_draft_rows(_draft(), _validation(satisfied=False))

    assert rows[0].status is OutcomeStatus.BLOCKED
    assert rows[0].diagnostics == ("missing recovered state",)
    assert rows[1].status is OutcomeStatus.NOT_RUN
    assert rows[1].enabled is False


def test_recipe_action_enablement_requires_current_valid_started_identity() -> None:
    ready = {
        item.action_id: item
        for item in logic.recipe_action_states(
            _draft(),
            _validation(),
            workbench_current=True,
            engine_started=True,
        )
    }
    blocked = {
        item.action_id: item
        for item in logic.recipe_action_states(
            _draft(),
            _validation(satisfied=False),
            workbench_current=True,
            engine_started=True,
        )
    }

    assert ready["apply_once"].enabled is True
    assert ready["save_function"].enabled is True
    assert ready["save_function"].label == "Save for Deobfuscate This"
    assert ready["save_project"].enabled is False
    assert "serializer" in ready["save_project"].reason
    assert blocked["apply_once"].enabled is False
    assert blocked["save_function"].enabled is False

    project_ready = {
        item.action_id: item
        for item in logic.recipe_action_states(
            _draft(),
            _validation(),
            workbench_current=True,
            engine_started=False,
            project_profile_save_available=True,
        )
    }
    assert project_ready["save_project"].enabled is True


def test_recipe_command_request_and_completion_bind_exact_draft_identity() -> None:
    request = logic.recipe_command_request(_draft(), "apply_recipe_once")
    result = RecipeCommandResult(
        command=request.command,
        draft_id=request.draft_id,
        draft_revision=request.draft_revision,
        function_ea=request.function_ea,
        requested_workbench_generation=request.expected_workbench_generation,
        function_fingerprint=request.function_fingerprint,
        status=OutcomeStatus.READY,
        succeeded=True,
        accepted=True,
        refresh_requested=True,
        message="done",
    )

    assert logic.should_accept_recipe_result(_draft(), result) is True
    assert (
        logic.should_accept_recipe_result(
            _draft(), dataclasses.replace(result, draft_revision=1)
        )
        is False
    )
    assert (
        logic.should_accept_recipe_result(
            _draft(), dataclasses.replace(result, function_ea=0x402000)
        )
        is False
    )


def test_recipe_logic_has_no_ida_qt_registry_or_persistence_imports() -> None:
    path = Path(logic.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )

    assert not any(name.startswith(("ida", "PyQt", "PySide")) for name in imports)
    assert not any(
        token in name
        for name in imports
        for token in ("registry", "persistence", "sqlite", "pipeline_config")
    )


def test_canvas_add_candidates_exclude_wrong_maturity_and_unconfigured_passes() -> None:
    draft = dataclasses.replace(_draft(), passes=())
    catalog = (
        dataclasses.replace(
            _catalog()[0],
            pass_id="recover-dispatcher",
            maturity="ir.local.optimized",
            configured=True,
        ),
        dataclasses.replace(
            _catalog()[1],
            pass_id="unconfigured-local-pass",
            maturity="ir.local.optimized",
            configured=False,
        ),
        dataclasses.replace(
            _catalog()[1],
            pass_id="later-pass",
            maturity="ir.global.analyzed",
            configured=True,
        ),
    )

    assert [
        entry.pass_id
        for entry in logic.canvas_add_candidates(catalog, "ir.local.optimized", draft)
    ] == ["recover-dispatcher"]


def test_canvas_add_candidates_normalizes_ranges_and_any_fallback() -> None:
    draft = dataclasses.replace(_draft(), passes=())
    catalog = (
        dataclasses.replace(
            _catalog()[0],
            pass_id="range-pass",
            maturity="ir.canonical..ir.global.analyzed",
            configured=True,
        ),
        dataclasses.replace(
            _catalog()[1],
            pass_id="any-pass",
            maturity="any",
            configured=True,
        ),
    )

    assert [
        entry.pass_id
        for entry in logic.canvas_add_candidates(catalog, "ir.local.optimized", draft)
    ] == ["range-pass"]
    assert [
        entry.pass_id for entry in logic.canvas_add_candidates(catalog, "any", draft)
    ] == ["any-pass"]


def test_canvas_add_candidates_reject_unknown_stages() -> None:
    try:
        logic.canvas_add_candidates(_catalog(), "MMAT_LOCOPT", _draft())
    except logic.CanvasAddError as exc:
        assert exc.code == "unknown-stage"
    else:
        raise AssertionError("unknown canvas stages must be rejected")
