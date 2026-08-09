from __future__ import annotations

import json

import pytest

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipePass,
)
from d810.ui.workbench_canvas_palette_logic import (
    CanvasPaletteRow,
    CanvasPaletteSelection,
    project_canvas_add_palette,
)
from d810.ui.workbench_recipe_logic import CanvasAddError


def _entry(
    pass_id: str,
    display_name: str,
    maturity: str,
    *,
    configured: bool = True,
    workflow_stage: StrategyWorkflowStage = StrategyWorkflowStage.CANONICAL_ANALYSIS,
    contract: dict[str, object] | None = None,
) -> PassCatalogEntry:
    return PassCatalogEntry(
        pass_id=pass_id,
        display_name=display_name,
        contract_json=json.dumps(contract or {"pass": pass_id}),
        option_template_json="{}",
        granularity="function",
        maturity=maturity,
        backend_route="mutation_backend",
        safety_policy="default",
        transform_ids=(),
        stage_ids=(),
        configured=configured,
        editor_spec=PassEditorSpec.summary(),
        workflow_stage=workflow_stage,
    )


def _draft(*passes: RecipePass) -> PipelineRecipeDraft:
    return PipelineRecipeDraft(
        draft_id="draft-1",
        schema_version=1,
        revision=1,
        function_ea=0x401000,
        function_fingerprint="sha256:canvas",
        workbench_generation=1,
        source_path="/source.json",
        runtime_path="/runtime.json",
        passes=passes,
    )


@pytest.fixture
def catalog() -> tuple[PassCatalogEntry, ...]:
    return (
        _entry(
            "recover-dispatcher",
            "Recover Dispatcher",
            "ir.local.optimized",
            contract={
                "requires": {"facts": {"required": ["ir.branch_target"]}},
                "outputs": {"facts": ["dispatcher"]},
            },
        ),
        _entry("later-pass", "Later Pass", "ir.global.analyzed"),
        _entry(
            "unconfigured-pass",
            "Unconfigured Pass",
            "ir.local.optimized",
            configured=False,
        ),
    )


@pytest.fixture
def draft() -> PipelineRecipeDraft:
    return _draft()


def test_palette_reuses_legal_candidate_policy_before_filtering(
    catalog: tuple[PassCatalogEntry, ...], draft: PipelineRecipeDraft
) -> None:
    rows = project_canvas_add_palette(catalog, "ir.local.optimized", draft)

    assert [row.pass_id for row in rows] == ["recover-dispatcher"]
    assert "Canonical analysis" in rows[0].subtitle
    assert "ir.local.optimized" in rows[0].subtitle


def test_palette_filters_display_name_pass_id_stage_and_contract_case_insensitively(
    catalog: tuple[PassCatalogEntry, ...], draft: PipelineRecipeDraft
) -> None:
    stage = "ir.local.optimized"

    assert [
        row.pass_id for row in project_canvas_add_palette(catalog, stage, draft, "dispatch")
    ] == ["recover-dispatcher"]
    assert [
        row.pass_id
        for row in project_canvas_add_palette(
            catalog,
            stage,
            draft,
            "RECOVER-DISPATCHER",
        )
    ] == ["recover-dispatcher"]
    assert [
        row.pass_id
        for row in project_canvas_add_palette(catalog, stage, draft, "canonical analysis")
    ] == ["recover-dispatcher"]
    assert [
        row.pass_id
        for row in project_canvas_add_palette(catalog, stage, draft, "ir.branch_target")
    ] == ["recover-dispatcher"]


def test_palette_preserves_unknown_stage_error(
    catalog: tuple[PassCatalogEntry, ...], draft: PipelineRecipeDraft
) -> None:
    with pytest.raises(CanvasAddError, match="unknown-stage") as error:
        project_canvas_add_palette(catalog, "MMAT_LOCOPT", draft)

    assert error.value.code == "unknown-stage"


def test_palette_empty_query_preserves_legal_candidate_order(
    catalog: tuple[PassCatalogEntry, ...], draft: PipelineRecipeDraft
) -> None:
    ordered_catalog = catalog + (
        _entry("second-local-pass", "Second Local Pass", "ir.local.optimized"),
    )

    assert [
        row.pass_id
        for row in project_canvas_add_palette(
            ordered_catalog,
            "ir.local.optimized",
            draft,
            "",
        )
    ] == ["recover-dispatcher", "second-local-pass"]


def test_palette_selection_commits_one_visible_row_then_resets_for_reuse() -> None:
    selection = CanvasPaletteSelection()
    rows = (
        CanvasPaletteRow("second", "Second", "", ""),
        CanvasPaletteRow("first", "First", "", ""),
    )

    assert selection.take(rows, 1) == "first"
    assert selection.take(rows, 1) is None
    assert selection.take(rows, 0) is None

    selection.reset()

    assert selection.take(rows, 0) == "second"


def test_palette_selection_does_not_commit_an_invalid_visible_row() -> None:
    selection = CanvasPaletteSelection()
    rows = (CanvasPaletteRow("only", "Only", "", ""),)

    assert selection.take(rows, 1) is None
    assert selection.take(rows, 0) == "only"
