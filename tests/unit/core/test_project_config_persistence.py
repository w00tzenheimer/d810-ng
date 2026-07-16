from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
    save_legacy_project_configuration,
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


def test_legacy_save_preserves_unrepresented_top_level_fields(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "legacy-copy.json"
    ins_rule = RuleConfiguration(name="InstructionRule", is_activated=True)
    blk_rule = RuleConfiguration(name="BlockRule", is_activated=True)

    save_legacy_project_configuration(
        source=source,
        destination=destination,
        description="legacy copy",
        ins_rules=(ins_rule,),
        blk_rules=(blk_rule,),
    )

    actual = json.loads(destination.read_text(encoding="utf-8"))
    assert actual["description"] == "legacy copy"
    assert actual["ins_rules"] == [ins_rule.to_dict()]
    assert actual["blk_rules"] == [blk_rule.to_dict()]
    assert actual["future_top_level"] == {"retain": [1, 2, 3]}
    assert actual["additional_configuration"] == source.additional_configuration


def test_new_legacy_save_has_the_canonical_four_top_level_fields(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "new.json"

    save_legacy_project_configuration(
        source=None,
        destination=destination,
        description="new",
        ins_rules=(),
        blk_rules=(),
    )

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "description": "new",
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {},
    }


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
