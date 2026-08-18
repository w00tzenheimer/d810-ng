from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.passes.pipeline_config_parser import require_config_v2_project
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
    write_project_document_atomically,
)


def _write_source(path: Path) -> ProjectConfiguration:
    path.write_text(
        json.dumps(
            {
                "description": "source",
                "ins_rules": [],
                "blk_rules": [],
                "future_top_level": {"retain": [1, 2, 3]},
                "additional_configuration": {
                    "pipeline_v2_mode": "config-v2",
                    "recon_fact_profile_modules": ["example.profile"],
                    "pipeline_v2": [
                        {
                            "pass": "recover_dispatcher",
                            "migration": {"source_section": "blk_rules"},
                            "options": {"nested": {"threshold": 7}},
                        }
                    ],
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ProjectConfiguration.from_file(path)


def test_clone_changes_only_path_and_description_and_preserves_nested_v2_payload(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "copy.json"

    duplicate = clone_project_configuration(
        source=source,
        destination=destination,
        description="copy",
    )

    expected = json.loads(source.path.read_text(encoding="utf-8"))
    expected["description"] = "copy"
    assert json.loads(destination.read_text(encoding="utf-8")) == expected
    assert duplicate.path == destination
    assert duplicate.additional_configuration == source.additional_configuration


def test_clone_without_validator_preserves_legacy_document_shape(tmp_path: Path) -> None:
    source_path = tmp_path / "legacy-source.json"
    source_path.write_text(
        json.dumps(
            {
                "description": "legacy",
                "ins_rules": [
                    {"name": "legacy-rule", "is_activated": True, "config": {}}
                ],
                "blk_rules": [],
                "additional_configuration": {"enable_pass_pipeline": True},
            }
        ),
        encoding="utf-8",
    )
    source = ProjectConfiguration.from_file(source_path)
    destination = tmp_path / "legacy-copy.json"

    clone_project_configuration(
        source=source,
        destination=destination,
        description="copy",
    )

    actual = json.loads(destination.read_text(encoding="utf-8"))
    assert actual["ins_rules"][0]["name"] == "legacy-rule"
    assert actual["blk_rules"] == []


def test_atomic_reload_failure_leaves_existing_destination_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "destination.json"
    destination.write_text('{"sentinel": "old"}', encoding="utf-8")

    def reject_temporary(path: Path | str) -> ProjectConfiguration:
        raise ValueError(f"rejected {path}")

    monkeypatch.setattr(ProjectConfiguration, "from_file", reject_temporary)

    with pytest.raises(ProjectConfigurationWriteError, match="destination.json"):
        clone_project_configuration(
            source=source,
            destination=destination,
            description="copy",
        )

    assert destination.read_text(encoding="utf-8") == '{"sentinel": "old"}'


def test_atomic_replace_failure_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "destination.json"

    def reject_replace(source_path: Path | str, destination_path: Path | str) -> None:
        raise OSError(f"cannot replace {source_path} -> {destination_path}")

    monkeypatch.setattr(os, "replace", reject_replace)

    with pytest.raises(ProjectConfigurationWriteError, match="destination.json"):
        clone_project_configuration(
            source=source,
            destination=destination,
            description="copy",
        )

    assert not destination.exists()
    assert list(tmp_path.glob(".destination.json.*.tmp")) == []


def test_full_validator_runs_on_temporary_reload_before_atomic_replace(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination.json"
    destination.write_text('{"sentinel": "old"}', encoding="utf-8")
    observed_paths = []

    def reject(project: ProjectConfiguration) -> None:
        observed_paths.append(project.path)
        raise ValueError("full pipeline rejected")

    with pytest.raises(ProjectConfigurationWriteError, match="destination.json"):
        write_project_document_atomically(
            destination,
            {
                "description": "candidate",
                "ins_rules": [],
                "blk_rules": [],
                "additional_configuration": {},
            },
            validator=reject,
        )

    assert observed_paths and observed_paths[0] != destination
    assert destination.read_text(encoding="utf-8") == '{"sentinel": "old"}'
    assert list(tmp_path.glob(".destination.json.*.tmp")) == []


def test_strict_atomic_v2_result_remains_canonical_on_second_save(
    tmp_path: Path,
):
    document = {
        "description": "migration-era v2",
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
        },
    }
    destination = tmp_path / "strict-v2.json"

    result = write_project_document_atomically(
        destination,
        document,
        validator=require_config_v2_project,
    )
    result.save()
    actual = json.loads(destination.read_text(encoding="utf-8"))

    assert "ins_rules" not in actual
    assert "blk_rules" not in actual
    assert "pipeline_v2_mode" not in actual["additional_configuration"]


def test_v2_atomic_write_without_validator_preserves_migration_metadata(
    tmp_path: Path,
):
    document = {
        "description": "migration-era v2",
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
        },
    }
    destination = tmp_path / "unvalidated-v2.json"

    write_project_document_atomically(destination, document)
    actual = json.loads(destination.read_text(encoding="utf-8"))

    assert actual["ins_rules"] == []
    assert actual["blk_rules"] == []
    assert actual["additional_configuration"]["pipeline_v2_mode"] == "config-v2"
