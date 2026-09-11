"""Immutable project-runtime facts and manager-owned edit commands."""

from __future__ import annotations

import dataclasses
import pathlib
from copy import deepcopy
from collections.abc import Mapping

from d810.capabilities.idb_preparation import PreparationScriptDescriptor
from d810.core.config import ProjectConfiguration
from d810.core.plugins import ImplementationOwnership
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
)
from d810.manager.preparation_scripts import PreparationScriptRegistry
from d810.passes.config_v2_hook_runtime import ConfigV2HookSchedule
from d810.passes.pipeline_config_parser import require_config_v2_project


class ProjectConfigurationEditError(RuntimeError):
    """A project edit is invalid for the active project or could not persist."""


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectIdentitySnapshot:
    basename: str
    path: pathlib.Path
    description: str


@dataclasses.dataclass(frozen=True, slots=True, init=False)
class ExternalImplementationRestartRecipe:
    """Exact external ownership plus an isolated resolved configuration."""

    binding_key: tuple[str, str, str]
    ownership: ImplementationOwnership
    _resolved_configuration: dict[str, object] = dataclasses.field(repr=False)

    def __init__(
        self,
        *,
        binding_key: tuple[str, str, str],
        ownership: ImplementationOwnership,
        resolved_configuration: Mapping[str, object],
    ) -> None:
        normalized_key = tuple(str(value) for value in binding_key)
        if len(normalized_key) != 3 or not all(normalized_key):
            raise ValueError(
                "external restart binding key must contain three non-empty values"
            )
        object.__setattr__(self, "binding_key", normalized_key)
        object.__setattr__(self, "ownership", ownership)
        object.__setattr__(
            self,
            "_resolved_configuration",
            deepcopy(dict(resolved_configuration)),
        )

    def fresh_configuration(self) -> dict[str, object]:
        """Return a copy no plugin callback can use to mutate this recipe."""
        return deepcopy(self._resolved_configuration)

    def with_ownership(
        self,
        ownership: ImplementationOwnership,
    ) -> ExternalImplementationRestartRecipe:
        """Carry the isolated configuration into one replacement generation."""
        return type(self)(
            binding_key=self.binding_key,
            ownership=ownership,
            resolved_configuration=self._resolved_configuration,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectRuntimeSnapshot:
    """Immutable identity and compiled pass sequence for one active project."""

    project: ProjectIdentitySnapshot
    effective_pass_ids: tuple[str, ...]
    preparation_scripts: tuple[PreparationScriptDescriptor, ...] = ()
    global_const_persistence_enabled: bool = False
    activated_plugins: tuple[object, ...] = ()
    activated_implementations: tuple[ImplementationOwnership, ...] = ()
    external_implementation_restart_recipes: tuple[
        ExternalImplementationRestartRecipe, ...
    ] = ()


def _identity(project: ProjectConfiguration) -> ProjectIdentitySnapshot:
    path = pathlib.Path(project.path).resolve()
    return ProjectIdentitySnapshot(
        basename=path.name,
        path=path,
        description=project.description,
    )


def build_project_runtime_snapshot(
    *,
    project: ProjectConfiguration,
    schedule: ConfigV2HookSchedule,
    activated_plugins: tuple[object, ...] = (),
    activated_implementations: tuple[ImplementationOwnership, ...] = (),
    external_implementation_restart_recipes: tuple[
        ExternalImplementationRestartRecipe, ...
    ] = (),
) -> ProjectRuntimeSnapshot:
    """Capture one canonical project and its validated executable schedule."""
    preparation_registry = PreparationScriptRegistry.from_project(
        project.path,
        project.pre_hexrays_payload,
    )
    return ProjectRuntimeSnapshot(
        project=_identity(project),
        effective_pass_ids=tuple(schedule.configured_pass_ids),
        preparation_scripts=preparation_registry.descriptors,
        global_const_persistence_enabled=schedule.global_const_persistence_enabled,
        activated_plugins=tuple(activated_plugins),
        activated_implementations=tuple(activated_implementations),
        external_implementation_restart_recipes=tuple(
            external_implementation_restart_recipes
        ),
    )


def clone_project(
    *,
    project: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
) -> ProjectConfiguration:
    """Clone the exact active project document, preserving unknown fields."""
    if project is None:
        raise ProjectConfigurationEditError(
            "No active project is available to clone"
        )
    try:
        return clone_project_configuration(
            source=project,
            destination=destination,
            description=description,
            validator=require_config_v2_project,
        )
    except ProjectConfigurationWriteError as exc:
        raise ProjectConfigurationEditError(str(exc)) from exc


__all__ = [
    "ProjectConfigurationEditError",
    "ExternalImplementationRestartRecipe",
    "ProjectIdentitySnapshot",
    "ProjectRuntimeSnapshot",
    "build_project_runtime_snapshot",
    "clone_project",
]
