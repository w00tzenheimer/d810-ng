from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.manager.project_runtime import (
    ProjectConfigurationEditError,
    ProjectRuntimeSnapshot,
    build_project_runtime_snapshot,
    clone_project,
)
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule


def _project(tmp_path: Path, *, name: str = "project.json") -> ProjectConfiguration:
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "description": "canonical project",
                "additional_configuration": {
                    "pipeline_v2": [
                        {"pass_id": "constant-simplification"},
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    return ProjectConfiguration.from_file(path)


def test_snapshot_has_one_canonical_project_identity(tmp_path: Path) -> None:
    project = _project(tmp_path)
    schedule = compile_config_v2_hook_schedule(project)

    snapshot = build_project_runtime_snapshot(project=project, schedule=schedule)

    assert snapshot.project.basename == "project.json"
    assert snapshot.project.path == project.path.resolve()
    assert snapshot.effective_pass_ids == ("constant-simplification",)
    assert not hasattr(snapshot, "source")
    assert not hasattr(snapshot, "runtime")
    assert not hasattr(snapshot, "routed")
    assert not hasattr(snapshot, "mode")
    assert not hasattr(snapshot, "hook_mode")


def test_snapshot_is_immutable(tmp_path: Path) -> None:
    project = _project(tmp_path)
    snapshot = build_project_runtime_snapshot(
        project=project,
        schedule=compile_config_v2_hook_schedule(project),
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.project = snapshot.project


def test_clone_project_uses_the_canonical_document(tmp_path: Path) -> None:
    source = _project(tmp_path, name="source.json")
    destination = tmp_path / "clone.json"

    clone_project(project=source, destination=destination, description="clone")

    actual = json.loads(destination.read_text(encoding="utf-8"))
    assert actual["description"] == "clone"
    assert "pipeline_v2" in actual["additional_configuration"]
    assert "ins_rules" not in actual
    assert "blk_rules" not in actual


def test_clone_project_rejects_missing_canonical_pipeline_before_write(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "invalid.json"
    source_path.write_text(
        json.dumps(
            {
                "description": "incomplete",
                "additional_configuration": {},
            }
        ),
        encoding="utf-8",
    )
    source = ProjectConfiguration.from_file(source_path)
    destination = tmp_path / "clone.json"

    with pytest.raises(ProjectConfigurationEditError, match="clone.json"):
        clone_project(project=source, destination=destination, description="clone")
    assert not destination.exists()


def test_project_runtime_snapshot_type_contains_only_canonical_fields() -> None:
    assert tuple(
        field.name for field in dataclasses.fields(ProjectRuntimeSnapshot)
    ) == (
        "project",
        "effective_pass_ids",
        "preparation_scripts",
        "global_const_persistence_enabled",
        "activated_plugins",
        "activated_implementations",
    )


def test_snapshot_owns_activated_plugin_lifetimes(tmp_path: Path) -> None:
    project = _project(tmp_path)
    activation = object()

    snapshot = build_project_runtime_snapshot(
        project=project,
        schedule=compile_config_v2_hook_schedule(project),
        activated_plugins=(activation,),
    )

    assert snapshot.activated_plugins == (activation,)


def test_snapshot_projects_global_const_persistence_from_typed_pass(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    project.additional_configuration["pipeline_v2"][0]["options"] = {
        "persist_global_const_annotations": True,
    }

    snapshot = build_project_runtime_snapshot(
        project=project,
        schedule=compile_config_v2_hook_schedule(project),
    )

    assert snapshot.global_const_persistence_enabled is True
