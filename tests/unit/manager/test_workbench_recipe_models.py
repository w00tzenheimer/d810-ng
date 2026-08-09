from __future__ import annotations

import dataclasses

import pytest

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeCommandRequest,
    RecipeCommandResult,
    RecipeDiagnostic,
    RecipePass,
    RecipeValidation,
)
from d810.manager.workbench_models import OutcomeStatus


def test_recipe_records_are_frozen_and_keep_ordered_tuple_payloads() -> None:
    entry = PassCatalogEntry(
        pass_id="recover_dispatcher",
        display_name="Recover dispatcher",
        contract_json='{"pass":"recover_dispatcher"}',
        option_template_json="{}",
        granularity="function",
        maturity="ir.global.optimized",
        backend_route="mutation_backend",
        safety_policy="default",
        transform_ids=(),
        stage_ids=("recover_dispatcher",),
        configured=False,
        editor_spec=PassEditorSpec.summary(),
    )
    recipe_pass = RecipePass(
        item_id="item-1",
        pass_id=entry.pass_id,
        enabled=True,
        config_json='{"pass_id":"recover_dispatcher"}',
    )
    draft = PipelineRecipeDraft(
        draft_id="draft-1",
        schema_version=1,
        revision=0,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=4,
        source_path="/source.json",
        runtime_path="/runtime.json",
        passes=(recipe_pass,),
    )

    assert draft.passes == (recipe_pass,)
    assert entry.stage_ids == ("recover_dispatcher",)
    assert entry.workflow_stage is StrategyWorkflowStage.CANONICAL_PIPELINE
    with pytest.raises(dataclasses.FrozenInstanceError):
        draft.revision = 2  # type: ignore[misc]


def test_validation_override_and_command_records_preserve_exact_identity() -> None:
    diagnostic = RecipeDiagnostic(
        code="missing-contract-input",
        message="state transition unavailable",
        ordinal=1,
        pass_id="lower_state_machine",
        namespace="requires.facts.required",
        missing=("recovered.state_transition",),
    )
    validation = RecipeValidation(
        draft_id="draft-1",
        revision=3,
        satisfied=False,
        diagnostics=(diagnostic,),
        manifest_json='[{"pass":"lower_state_machine"}]',
    )
    override = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        source_path="/source.json",
        runtime_path="/runtime.json",
        pass_configs_json='[{"pass_id":"lower_state_machine"}]',
        updated_at=10.5,
    )
    request = RecipeCommandRequest(
        command="save_function_recipe",
        draft_id="draft-1",
        draft_revision=3,
        function_ea=0x401000,
        expected_workbench_generation=4,
        function_fingerprint="sha256:abc",
    )
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
        message="saved",
    )

    assert validation.diagnostics == (diagnostic,)
    assert override.pass_configs_json.startswith("[")
    assert result.requested_workbench_generation == 4
