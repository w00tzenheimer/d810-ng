"""Immutable project-runtime facts and manager-owned edit commands."""
from __future__ import annotations

import dataclasses
import enum
import pathlib
from collections.abc import Sequence

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.config_v2_defaults import ConfigV2DefaultSelection
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
    save_legacy_project_configuration,
)
from d810.passes.pipeline_v2_hook_bridge import PipelineV2HookActivation


class ProjectConfigMode(enum.Enum):
    """The authoring model used by the effective runtime project."""

    LEGACY = "legacy"
    CONFIG_V2 = "config-v2"


class RuleProjectionKind(enum.Enum):
    """What the effective rule names represent in the snapshot."""

    SOURCE_POLICY = "source-policy"
    RUNTIME_EXPANSION = "runtime-expansion"


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
    effective_instruction_rule_names: tuple[str, ...]
    effective_block_rule_names: tuple[str, ...]
    rule_projection: RuleProjectionKind


def _identity(project: ProjectConfiguration) -> ProjectIdentitySnapshot:
    path = pathlib.Path(project.path).resolve()
    return ProjectIdentitySnapshot(
        basename=path.name,
        path=path,
        description=project.description,
    )


def _active_rule_names(
    rules: Sequence[RuleConfiguration],
) -> tuple[str, ...]:
    return tuple(
        str(rule.name)
        for rule in rules
        if rule.is_activated and rule.name
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
        rule_projection = RuleProjectionKind.RUNTIME_EXPANSION
        effective_pass_ids = hook_activation.configured_pass_ids
        instruction_rules = hook_activation.instruction_rules
        block_rules = hook_activation.block_rules
    else:
        mode = ProjectConfigMode.LEGACY
        rule_projection = RuleProjectionKind.SOURCE_POLICY
        effective_pass_ids = ()
        instruction_rules = tuple(runtime_project.ins_rules)
        block_rules = tuple(runtime_project.blk_rules)

    return ProjectRuntimeSnapshot(
        source=_identity(source_project),
        runtime=_identity(runtime_project),
        mode=mode,
        routed=bool(default_selection and default_selection.routed),
        hook_mode=hook_mode,
        effective_pass_ids=tuple(effective_pass_ids),
        effective_instruction_rule_names=_active_rule_names(instruction_rules),
        effective_block_rule_names=_active_rule_names(block_rules),
        rule_projection=rule_projection,
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


def save_legacy_project(
    *,
    snapshot: ProjectRuntimeSnapshot | None,
    source: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
    ins_rules: Sequence[RuleConfiguration],
    blk_rules: Sequence[RuleConfiguration],
) -> ProjectConfiguration:
    """Persist legacy rule policy after enforcing the manager-owned mode guard."""
    if snapshot is not None and snapshot.mode is ProjectConfigMode.CONFIG_V2:
        raise ProjectConfigurationEditError(
            "The legacy rule editor cannot save a config-v2 runtime project; "
            "clone the effective runtime and edit its JSON in an external editor"
        )
    try:
        return save_legacy_project_configuration(
            source=source,
            destination=destination,
            description=description,
            ins_rules=ins_rules,
            blk_rules=blk_rules,
        )
    except ProjectConfigurationWriteError as exc:
        raise ProjectConfigurationEditError(str(exc)) from exc


__all__ = [
    "ProjectConfigurationEditError",
    "ProjectConfigMode",
    "ProjectIdentitySnapshot",
    "ProjectRuntimeSnapshot",
    "RuleProjectionKind",
    "build_project_runtime_snapshot",
    "clone_runtime_project",
    "save_legacy_project",
]
