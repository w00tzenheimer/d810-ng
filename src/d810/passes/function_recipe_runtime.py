"""IDA-independent temporary runtime support for function recipes."""

from __future__ import annotations

import contextlib
import copy
import pathlib
from collections.abc import Callable, Iterator, Sequence

from d810.core.config import ProjectConfiguration
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError


class FunctionRecipeRuntimeActivationError(RuntimeError):
    """A temporary recipe runtime could not start or restore safely."""


@contextlib.contextmanager
def activate_function_recipe_runtime(
    recipe_project: ProjectConfiguration,
    *,
    stop_runtime: Callable[[], None],
    start_runtime: Callable[[], None],
    runtime_started: Callable[[], bool],
    activate_recipe: Callable[[], None],
    restore_project: Callable[[], None],
) -> Iterator[ProjectConfiguration]:
    """Activate one recipe scope and fail if the original runtime cannot return."""
    stop_runtime()
    try:
        activate_recipe()
        start_runtime()
        if not runtime_started():
            raise FunctionRecipeRuntimeActivationError(
                "D810 failed to start the function recipe runtime"
            )
        yield recipe_project
    finally:
        if runtime_started():
            stop_runtime()
        restore_project()
        start_runtime()
        if not runtime_started():
            raise FunctionRecipeRuntimeActivationError(
                "D810 failed to restore the project runtime after recipe use"
            )


def build_recipe_runtime_project(
    base_project: ProjectConfiguration,
    configs: Sequence[PipelineConfig],
    *,
    function_ea: int,
) -> ProjectConfiguration:
    """Build a typed config-v2 recipe runtime project without writing a file."""
    materialized_configs = tuple(configs)
    if not materialized_configs:
        raise PipelineConfigError("function recipe contains no pass configs")
    additional_configuration = copy.deepcopy(
        dict(base_project.additional_configuration)
    )
    additional_configuration["pipeline_v2_mode"] = "config-v2"
    additional_configuration["pipeline_v2"] = [
        config.to_dict() for config in materialized_configs
    ]
    path = pathlib.Path(base_project.path)
    synthetic_path = path.with_name(
        f".{path.stem}.function-recipe-{int(function_ea):x}.json"
    )
    return ProjectConfiguration(
        path=synthetic_path,
        description=(
            f"{base_project.description} [function recipe 0x{int(function_ea):X}]"
        ),
        ins_rules=copy.deepcopy(base_project.ins_rules),
        blk_rules=copy.deepcopy(base_project.blk_rules),
        additional_configuration=additional_configuration,
    )


__all__ = [
    "FunctionRecipeRuntimeActivationError",
    "activate_function_recipe_runtime",
    "build_recipe_runtime_project",
]
