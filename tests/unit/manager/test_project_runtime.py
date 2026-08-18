from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.config_v2_defaults import select_config_v2_default_project
from d810.manager.project_runtime import (
    ProjectConfigurationEditError,
    ProjectConfigMode,
    build_project_runtime_snapshot,
    clone_runtime_project,
)
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


CONF_DIR = Path("src/d810/conf")


def test_non_v2_snapshot_exposes_no_public_pass_pipeline(
    tmp_path: Path,
) -> None:
    project = ProjectConfiguration(
        path=tmp_path / "legacy.json",
        description="legacy",
        ins_rules=[
            RuleConfiguration(name="EnabledInstruction", is_activated=True),
            RuleConfiguration(name="DisabledInstruction", is_activated=False),
        ],
        blk_rules=[RuleConfiguration(name="EnabledBlock", is_activated=True)],
    )
    activation = pipeline_v2_hook_activation(project)

    snapshot = build_project_runtime_snapshot(
        source_project=project,
        runtime_project=project,
        default_selection=None,
        hook_activation=activation,
        hook_mode=None,
    )

    assert snapshot.mode is ProjectConfigMode.LEGACY
    assert snapshot.routed is False
    assert snapshot.effective_pass_ids == ()
    assert snapshot.global_const_persistence_enabled is False


def test_routed_config_v2_snapshot_reports_distinct_source_and_runtime() -> None:
    source = ProjectConfiguration.from_file(CONF_DIR / "default_instruction_only.json")
    selection = select_config_v2_default_project(source)
    assert selection is not None
    activation = pipeline_v2_hook_activation(selection.runtime_project)

    snapshot = build_project_runtime_snapshot(
        source_project=source,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=activation,
        hook_mode="config-v2",
    )

    assert snapshot.source.basename == "default_instruction_only.json"
    assert snapshot.runtime.basename == "default_instruction_only_config_v2_canary.json"
    assert snapshot.source.path != snapshot.runtime.path
    assert snapshot.mode is ProjectConfigMode.CONFIG_V2
    assert snapshot.routed is True
    assert snapshot.hook_mode == "config-v2"
    assert snapshot.effective_pass_ids == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    )


def test_direct_canary_snapshot_is_config_v2_without_routing() -> None:
    canary = ProjectConfiguration.from_file(
        CONF_DIR / "default_instruction_only_config_v2_canary.json"
    )
    selection = select_config_v2_default_project(canary)
    assert selection is not None
    activation = pipeline_v2_hook_activation(selection.runtime_project)

    snapshot = build_project_runtime_snapshot(
        source_project=canary,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=activation,
        hook_mode="config-v2",
    )

    assert snapshot.source == snapshot.runtime
    assert snapshot.mode is ProjectConfigMode.CONFIG_V2
    assert snapshot.routed is False
    assert snapshot.effective_pass_ids == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    )


def test_snapshot_projects_explicit_global_const_persistence_authority(
    tmp_path: Path,
) -> None:
    project = ProjectConfiguration(
        path=tmp_path / "const-persistence.json",
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "options": {
                        "memory_policy": "strict",
                        "persist_global_const_annotations": True,
                    },
                }
            ],
        },
    )
    activation = pipeline_v2_hook_activation(project)

    snapshot = build_project_runtime_snapshot(
        source_project=project,
        runtime_project=project,
        default_selection=None,
        hook_activation=activation,
        hook_mode="config-v2",
    )

    assert snapshot.global_const_persistence_enabled is True


def test_snapshot_is_immutable(tmp_path: Path) -> None:
    project = ProjectConfiguration(path=tmp_path / "legacy.json")
    snapshot = build_project_runtime_snapshot(
        source_project=project,
        runtime_project=project,
        default_selection=None,
        hook_activation=pipeline_v2_hook_activation(project),
        hook_mode=None,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.routed = True


def test_manager_requires_runtime_project_for_clone(tmp_path: Path) -> None:
    with pytest.raises(ProjectConfigurationEditError, match="No effective runtime"):
        clone_runtime_project(
            runtime_project=None,
            destination=tmp_path / "missing.json",
            description="missing",
        )
