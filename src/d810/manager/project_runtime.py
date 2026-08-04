"""Immutable project-runtime facts and manager-owned edit commands."""

from __future__ import annotations

import dataclasses
import enum
import pathlib

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import ConfigV2DefaultSelection
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
)
from d810.passes.pipeline_v2_hook_bridge import PipelineV2HookActivation


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
    hook_activation: PipelineV2HookActivation,
    hook_mode: str | None,
) -> ProjectRuntimeSnapshot:
    """Capture the source policy and effective runtime without UI inference."""
    if hook_activation.enabled:
        mode = ProjectConfigMode.CONFIG_V2
        effective_pass_ids = hook_activation.configured_pass_ids
    else:
        mode = ProjectConfigMode.LEGACY
        effective_pass_ids = ()

    return ProjectRuntimeSnapshot(
        source=_identity(source_project),
        runtime=_identity(runtime_project),
        mode=mode,
        routed=bool(default_selection and default_selection.routed),
        hook_mode=hook_mode,
        effective_pass_ids=tuple(effective_pass_ids),
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
        return clone_project_configuration(
            source=runtime_project,
            destination=destination,
            description=description,
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
