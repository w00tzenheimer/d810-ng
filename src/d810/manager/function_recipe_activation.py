"""In-memory runtime project materialization for per-function recipes."""

from __future__ import annotations

import dataclasses
import pathlib

from d810.core.config import ProjectConfiguration
from d810.manager.project_runtime import (
    ProjectConfigMode,
    ProjectRuntimeSnapshot,
    RuleProjectionKind,
)
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PipelineRecipeDraft,
)
from d810.manager.workbench_recipe_service import RecipeService
from d810.manager.workbench_recipe_service import RecipeEditError
from d810.passes.function_recipe_runtime import build_recipe_runtime_project
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


@dataclasses.dataclass(frozen=True, slots=True)
class FunctionRecipeWorkbenchProjection:
    runtime_project: ProjectConfiguration
    project_snapshot: ProjectRuntimeSnapshot
    draft: PipelineRecipeDraft


@dataclasses.dataclass(frozen=True, slots=True)
class FunctionRecipeWorkbenchSelection:
    runtime_project: ProjectConfiguration
    project_snapshot: ProjectRuntimeSnapshot
    recipe_scope: str
    errors: tuple[str, ...]
    draft: PipelineRecipeDraft | None


def _active_rule_names(rules: tuple[object, ...]) -> tuple[str, ...]:
    return tuple(
        str(getattr(rule, "name"))
        for rule in rules
        if bool(getattr(rule, "is_activated", False)) and getattr(rule, "name", None)
    )


def build_workbench_recipe_projection(
    base_project: ProjectConfiguration,
    project_snapshot: ProjectRuntimeSnapshot,
    override: FunctionPipelineOverride,
    *,
    function_ea: int,
    function_fingerprint: str | None,
    workbench_generation: int,
) -> FunctionRecipeWorkbenchProjection:
    """Project a validated saved recipe as the effective workbench runtime."""
    recipe_service = RecipeService(operational_config_v2_pass_registry())
    draft = recipe_service.create_draft_from_override(
        override,
        function_ea=function_ea,
        function_fingerprint=function_fingerprint,
        workbench_generation=workbench_generation,
        source_path=str(project_snapshot.source.path),
        runtime_path=str(project_snapshot.runtime.path),
    )
    runtime_project = build_recipe_runtime_project(
        base_project,
        recipe_service.deserialize_configs(
            recipe_service.serialize_enabled_configs(draft)
        ),
        function_ea=function_ea,
    )
    runtime_project.path = pathlib.Path(base_project.path)
    activation = pipeline_v2_hook_activation(runtime_project)
    effective_snapshot = dataclasses.replace(
        project_snapshot,
        mode=ProjectConfigMode.CONFIG_V2,
        hook_mode="config-v2",
        effective_pass_ids=activation.configured_pass_ids,
        effective_instruction_rule_names=_active_rule_names(
            activation.instruction_rules
        ),
        effective_block_rule_names=_active_rule_names(activation.block_rules),
        rule_projection=RuleProjectionKind.RUNTIME_EXPANSION,
    )
    return FunctionRecipeWorkbenchProjection(
        runtime_project=runtime_project,
        project_snapshot=effective_snapshot,
        draft=draft,
    )


def select_workbench_recipe_projection(
    base_project: ProjectConfiguration,
    project_snapshot: ProjectRuntimeSnapshot,
    override: FunctionPipelineOverride | None,
    *,
    function_ea: int,
    function_fingerprint: str | None,
) -> FunctionRecipeWorkbenchSelection:
    """Select project or saved-function runtime truth without importing IDA."""
    if override is None:
        return FunctionRecipeWorkbenchSelection(
            runtime_project=base_project,
            project_snapshot=project_snapshot,
            recipe_scope="project",
            errors=(),
            draft=None,
        )
    try:
        projection = build_workbench_recipe_projection(
            base_project,
            project_snapshot,
            override,
            function_ea=function_ea,
            function_fingerprint=function_fingerprint,
            workbench_generation=0,
        )
    except (PipelineConfigError, RecipeEditError) as exc:
        return FunctionRecipeWorkbenchSelection(
            runtime_project=base_project,
            project_snapshot=project_snapshot,
            recipe_scope="function-recipe-blocked",
            errors=(f"function recipe: {exc}",),
            draft=None,
        )
    return FunctionRecipeWorkbenchSelection(
        runtime_project=projection.runtime_project,
        project_snapshot=projection.project_snapshot,
        recipe_scope="function-recipe",
        errors=(),
        draft=projection.draft,
    )


__all__ = [
    "FunctionRecipeWorkbenchProjection",
    "FunctionRecipeWorkbenchSelection",
    "build_workbench_recipe_projection",
    "select_workbench_recipe_projection",
]
