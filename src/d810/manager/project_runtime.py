"""Immutable project-runtime facts and manager-owned edit commands."""

from __future__ import annotations

import dataclasses
import enum
import pathlib
from collections.abc import Mapping

from d810.capabilities.idb_preparation import PreparationScriptDescriptor
from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import ConfigV2DefaultSelection
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
)
from d810.passes.constant_simplification_options import (
    CompiledConstantSimplificationSchedule,
)
from d810.manager.preparation_scripts import PreparationScriptRegistry
from d810.passes.config_v2_hook_runtime import ConfigV2HookSchedule
from d810.passes.pipeline_config_parser import require_config_v2_project


class ProjectConfigMode(str, enum.Enum):
    """The authoring model used by the effective runtime project."""

    LEGACY = "legacy"
    CONFIG_V2 = "config-v2"


class ProjectConfigurationEditError(RuntimeError):
    """A project edit is invalid for the active runtime or could not persist."""


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectIdentitySnapshot:
    basename: str
    path: pathlib.Path
    description: str


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectRuntimeSnapshot:
    source: ProjectIdentitySnapshot
    runtime: ProjectIdentitySnapshot
    mode: ProjectConfigMode
    routed: bool
    hook_mode: str | None
    effective_pass_ids: tuple[str, ...]
    preparation_scripts: tuple[PreparationScriptDescriptor, ...] = ()
    global_const_persistence_enabled: bool = False
    constant_simplification_schedule: CompiledConstantSimplificationSchedule | None = None


def _identity(project: ProjectConfiguration) -> ProjectIdentitySnapshot:
    path = pathlib.Path(project.path).resolve()
    return ProjectIdentitySnapshot(
        basename=path.name,
        path=path,
        description=project.description,
    )


def build_project_runtime_snapshot(
    *,
    source_project: ProjectConfiguration,
    runtime_project: ProjectConfiguration,
    default_selection: ConfigV2DefaultSelection | None,
    schedule: ConfigV2HookSchedule | None,
    hook_mode: str | None,
) -> ProjectRuntimeSnapshot:
    """Capture the source policy and effective runtime without UI inference."""
    if schedule is not None:
        mode = ProjectConfigMode.CONFIG_V2
        effective_pass_ids = schedule.configured_pass_ids
    else:
        mode = ProjectConfigMode.LEGACY
        effective_pass_ids = ()

    preparation_registry = PreparationScriptRegistry.from_project(
        runtime_project.path,
        runtime_project.pre_hexrays_payload,
    )

    return ProjectRuntimeSnapshot(
        source=_identity(source_project),
        runtime=_identity(runtime_project),
        mode=mode,
        routed=bool(default_selection and default_selection.routed),
        hook_mode=hook_mode,
        effective_pass_ids=tuple(effective_pass_ids),
        preparation_scripts=preparation_registry.descriptors,
        global_const_persistence_enabled=(
            schedule.global_const_persistence_enabled
            if schedule is not None
            else False
        ),
        constant_simplification_schedule=(
            schedule.constant_simplification_schedule
            if schedule is not None
            else None
        ),
    )


def clone_runtime_project(
    *,
    runtime_project: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
) -> ProjectConfiguration:
    """Clone the exact effective runtime document, preserving unknown fields."""
    if runtime_project is None:
        raise ProjectConfigurationEditError(
            "No effective runtime project is available to clone"
        )
    try:
        additional = runtime_project.additional_configuration
        validator = (
            require_config_v2_project
            if isinstance(additional, Mapping)
            and (
                "pipeline_v2" in additional
                or additional.get("pipeline_v2_mode") == "config-v2"
            )
            else None
        )
        return clone_project_configuration(
            source=runtime_project,
            destination=destination,
            description=description,
            validator=validator,
        )
    except ProjectConfigurationWriteError as exc:
        raise ProjectConfigurationEditError(str(exc)) from exc


__all__ = [
    "ProjectConfigurationEditError",
    "ProjectConfigMode",
    "ProjectIdentitySnapshot",
    "ProjectRuntimeSnapshot",
    "build_project_runtime_snapshot",
    "clone_runtime_project",
]
