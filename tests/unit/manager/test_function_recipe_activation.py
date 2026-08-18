from __future__ import annotations

import json
import pathlib

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.manager.function_recipe_activation import build_workbench_recipe_projection
from d810.manager.function_recipe_activation import select_workbench_recipe_projection
from d810.manager.project_runtime import (
    ProjectIdentitySnapshot,
    ProjectRuntimeSnapshot,
)
from d810.manager.workbench_recipe_models import FunctionPipelineOverride
from d810.manager.workbench_recipe_service import RecipeEditError, RecipeService
from d810.passes.function_recipe_runtime import (
    FunctionRecipeRuntimeActivationError,
    activate_function_recipe_runtime,
    build_recipe_runtime_project,
)
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry


def _base_project() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=pathlib.Path("/configs/runtime.json"),
        description="Runtime",
        ins_rules=[RuleConfiguration("LegacyInsn", True, {"x": 1})],
        blk_rules=[RuleConfiguration("JumpFixer", True, {"y": 2})],
        additional_configuration={
            "unknown_nested": {"keep": [1, 2]},
            "pipeline_v2": [
                {
                    "pass_id": "jump-fixer",
                    "options": {},
                }
            ],
        },
    )


def test_recipe_runtime_project_is_in_memory_lossless_and_config_v2() -> None:
    base = _base_project()
    configs = RecipeService(operational_config_v2_pass_registry()).deserialize_configs(
        '[{"pass_id":"mba-simplify","options":{"transforms":["add-xor-1"],"transform_options":{}}}]'
    )
    project = build_recipe_runtime_project(
        base,
        configs,
        function_ea=0x401000,
    )

    assert project.path == pathlib.Path("/configs/.runtime.function-recipe-401000.json")
    assert project.path.exists() is False
    assert project.description == "Runtime [function recipe 0x401000]"
    assert project.ins_rules is not base.ins_rules
    assert project.blk_rules is not base.blk_rules
    assert project.additional_configuration["unknown_nested"] == {"keep": [1, 2]}
    assert (
        project.additional_configuration["unknown_nested"]
        is not base.additional_configuration["unknown_nested"]
    )
    assert tuple(
        config.pass_id for config in pipeline_configs_from_project_config(project)
    ) == ("mba-simplify",)
    assert tuple(
        config.pass_id for config in pipeline_configs_from_project_config(base)
    ) == ("jump-fixer",)


def test_recipe_runtime_project_requires_typed_nonempty_configs() -> None:
    with pytest.raises(RecipeEditError, match="not-registered"):
        RecipeService(operational_config_v2_pass_registry()).deserialize_configs(
            '[{"pass_id":"not-registered"}]',
        )
    with pytest.raises(PipelineConfigError, match="no pass configs"):
        build_recipe_runtime_project(_base_project(), (), function_ea=0x401000)


def test_workbench_projection_reports_saved_recipe_as_the_effective_pipeline() -> None:
    base = _base_project()
    snapshot = ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot("runtime.json", base.path, "Runtime"),
        effective_pass_ids=("jump-fixer",),
    )
    override = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        project_path="/configs/runtime.json",
        pass_configs_json='[{"pass_id":"mba-simplify","options":{"transforms":["add-xor-1"],"transform_options":{}}}]',
        updated_at=1.0,
    )

    projection = build_workbench_recipe_projection(
        base,
        snapshot,
        override,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=7,
    )

    assert projection.project.path == base.path
    assert projection.project_snapshot.project == snapshot.project
    assert projection.project_snapshot.effective_pass_ids == ("mba-simplify",)
    assert projection.draft.workbench_generation == 7
    assert tuple(item.pass_id for item in projection.draft.passes) == ("mba-simplify",)
    assert tuple(
        config.pass_id for config in pipeline_configs_from_project_config(base)
    ) == ("jump-fixer",)


def test_selection_keeps_project_runtime_and_marks_recipe_explicit_only() -> None:
    base = _base_project()
    snapshot = ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot("runtime.json", base.path, "Runtime"),
        effective_pass_ids=("jump-fixer",),
    )
    override = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        project_path="/configs/runtime.json",
        pass_configs_json='[{"pass_id":"mba-simplify","options":{"transforms":["add-xor-1"],"transform_options":{}}}]',
        updated_at=1.0,
    )
    selection = select_workbench_recipe_projection(
        base,
        snapshot,
        override,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
    )

    assert selection.recipe_scope == "saved-recipe-explicit"
    assert selection.errors == ()
    assert selection.project_snapshot is snapshot
    assert selection.project is base
    assert selection.project_snapshot.effective_pass_ids == ("jump-fixer",)
    assert selection.draft is not None
    assert tuple(
        config.pass_id
        for config in pipeline_configs_from_project_config(selection.project)
    ) == ("jump-fixer",)


def test_selection_blocks_stale_saved_recipe_without_mutating_project() -> None:
    base = _base_project()
    snapshot = ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot("runtime.json", base.path, "Runtime"),
        effective_pass_ids=("jump-fixer",),
    )
    stale = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:old",
        project_path="/configs/runtime.json",
        pass_configs_json='[{"pass_id":"jump-fixer"}]',
        updated_at=1.0,
    )

    selection = select_workbench_recipe_projection(
        base,
        snapshot,
        stale,
        function_ea=0x401000,
        function_fingerprint="sha256:new",
    )

    assert selection.project is base
    assert selection.project_snapshot is snapshot
    assert selection.recipe_scope == "saved-recipe-blocked"
    assert selection.draft is None
    assert "fingerprint is stale" in selection.errors[0]


def test_selection_blocks_cross_pass_hook_materialization_failure() -> None:
    base = _base_project()
    snapshot = ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot("runtime.json", base.path, "Runtime"),
        effective_pass_ids=("jump-fixer",),
    )
    individually_valid = operational_config_v2_pass_registry().config_template_for(
        "recover_dispatcher"
    )
    invalid_spine = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        project_path="/configs/runtime.json",
        pass_configs_json=json.dumps([individually_valid.to_dict()]),
        updated_at=1.0,
    )

    selection = select_workbench_recipe_projection(
        base,
        snapshot,
        invalid_spine,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
    )

    assert selection.project is base
    assert selection.project_snapshot is snapshot
    assert selection.recipe_scope == "saved-recipe-blocked"
    assert selection.draft is None
    assert "complete native pass sequence" in selection.errors[0]


def _runtime_lifecycle(start_outcomes: list[bool]):
    state = {"started": True}
    events: list[str] = []
    outcomes = iter(start_outcomes)

    def stop_runtime() -> None:
        events.append("stop")
        state["started"] = False

    def start_runtime() -> None:
        events.append("start")
        state["started"] = next(outcomes)

    return state, events, stop_runtime, start_runtime


def test_temporary_recipe_runtime_restores_after_body_failure() -> None:
    state, events, stop_runtime, start_runtime = _runtime_lifecycle([True, True])

    with pytest.raises(ValueError, match="body failed"):
        with activate_function_recipe_runtime(
            object(),
            stop_runtime=stop_runtime,
            start_runtime=start_runtime,
            runtime_started=lambda: state["started"],
            activate_recipe=lambda: events.append("activate-recipe"),
            restore_project=lambda: events.append("restore-project"),
        ):
            events.append("body")
            raise ValueError("body failed")

    assert state["started"] is True
    assert events == [
        "stop",
        "activate-recipe",
        "start",
        "body",
        "stop",
        "restore-project",
        "start",
    ]


def test_temporary_recipe_runtime_restores_after_recipe_start_failure() -> None:
    state, events, stop_runtime, start_runtime = _runtime_lifecycle([False, True])

    with pytest.raises(
        FunctionRecipeRuntimeActivationError,
        match="failed to start the function recipe runtime",
    ):
        with activate_function_recipe_runtime(
            object(),
            stop_runtime=stop_runtime,
            start_runtime=start_runtime,
            runtime_started=lambda: state["started"],
            activate_recipe=lambda: events.append("activate-recipe"),
            restore_project=lambda: events.append("restore-project"),
        ):
            raise AssertionError("recipe body must not run")

    assert state["started"] is True
    assert events == [
        "stop",
        "activate-recipe",
        "start",
        "restore-project",
        "start",
    ]


def test_temporary_recipe_runtime_propagates_restore_start_failure() -> None:
    state, events, stop_runtime, start_runtime = _runtime_lifecycle([True, False])

    with pytest.raises(
        FunctionRecipeRuntimeActivationError,
        match="failed to restore the project runtime",
    ):
        with activate_function_recipe_runtime(
            object(),
            stop_runtime=stop_runtime,
            start_runtime=start_runtime,
            runtime_started=lambda: state["started"],
            activate_recipe=lambda: events.append("activate-recipe"),
            restore_project=lambda: events.append("restore-project"),
        ):
            events.append("body")

    assert state["started"] is False
    assert events == [
        "stop",
        "activate-recipe",
        "start",
        "body",
        "stop",
        "restore-project",
        "start",
    ]
