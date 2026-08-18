from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.project_config_persistence import write_project_document_atomically
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_parser import require_config_v2_project


def _v2_document() -> dict[str, object]:
    additional: dict[str, object] = {
        "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
        "future_nested": {"retain": [1, {"value": True}]},
    }
    return {
        "description": "v2 project",
        "ins_rules": [],
        "blk_rules": [],
        "future_top_level": {"retain": "exactly"},
        "additional_configuration": additional,
    }


def _write_project(tmp_path: Path, document: dict[str, object]) -> ProjectConfiguration:
    path = tmp_path / "project.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return ProjectConfiguration.from_file(path)


def test_canonical_v2_save_omits_legacy_arrays_and_preserves_unknown_fields(
    tmp_path: Path,
):
    project = _write_project(tmp_path, _v2_document())

    require_config_v2_project(project)
    project.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))

    assert "ins_rules" not in actual
    assert "blk_rules" not in actual
    assert actual["future_top_level"] == {"retain": "exactly"}
    assert actual["additional_configuration"]["future_nested"] == {
        "retain": [1, {"value": True}]
    }
    assert require_config_v2_project(ProjectConfiguration.from_file(project.path))[0].pass_id == (
        "recover_dispatcher"
    )

def test_legacy_project_save_keeps_legacy_arrays_and_does_not_implicitly_migrate(
    tmp_path: Path,
):
    project = ProjectConfiguration(
        path=tmp_path / "legacy.json",
        description="legacy",
        ins_rules=[RuleConfiguration(name="Legacy", is_activated=True)],
        blk_rules=[],
        additional_configuration={"enable_pass_pipeline": True},
    )

    project.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))

    assert actual["ins_rules"][0]["name"] == "Legacy"
    assert actual["blk_rules"] == []
    assert "pipeline_v2" not in actual["additional_configuration"]


def test_already_canonical_absence_survives_load_save_without_revalidation(
    tmp_path: Path,
):
    document = {
        "description": "already canonical",
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
        },
    }
    project = _write_project(tmp_path, document)

    project.save()

    actual = json.loads(project.path.read_text(encoding="utf-8"))
    assert "ins_rules" not in actual
    assert "blk_rules" not in actual


@pytest.mark.parametrize(
    "field,value",
    [("ins_rules", None), ("blk_rules", None), ("ins_rules", {}), ("blk_rules", "bad")],
)
def test_project_file_rejects_malformed_legacy_rule_array_with_migration_command(
    tmp_path: Path, field: str, value: object
):
    document = _v2_document()
    document[field] = value
    path = tmp_path / "malformed-array.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="migrate_project_config_v2.py"):
        ProjectConfiguration.from_file(path)


def test_existing_v2_file_with_empty_legacy_arrays_loads_and_saves_canonically(
    tmp_path: Path,
):
    project = _write_project(tmp_path, _v2_document())

    reloaded = ProjectConfiguration.from_file(project.path)
    assert reloaded.ins_rules == []
    assert reloaded.blk_rules == []

    require_config_v2_project(reloaded)
    reloaded.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))
    assert "ins_rules" not in actual
    assert "blk_rules" not in actual


def test_unknown_pass_direct_save_retains_source_fields(tmp_path: Path):
    document = _v2_document()
    document["additional_configuration"]["pipeline_v2"] = [
        {"pass_id": "not-a-registered-pass"}
    ]
    project = _write_project(tmp_path, document)

    project.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))

    assert actual["ins_rules"] == []
    assert actual["blk_rules"] == []
    assert actual["additional_configuration"]["pipeline_v2"] == [
        {"pass_id": "not-a-registered-pass"}
    ]


def test_save_does_not_reuse_stale_validation_after_pipeline_mutation(tmp_path: Path):
    project = _write_project(tmp_path, _v2_document())
    require_config_v2_project(project)
    project.additional_configuration["pipeline_v2"] = [
        {"pass_id": "not-a-registered-pass"}
    ]

    project.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))

    assert actual["ins_rules"] == []
    assert actual["blk_rules"] == []


def test_unknown_pass_atomic_persistence_retains_source_fields(tmp_path: Path):
    document = _v2_document()
    document["additional_configuration"]["pipeline_v2"] = [
        {"pass_id": "not-a-registered-pass"}
    ]
    destination = tmp_path / "atomic.json"

    write_project_document_atomically(destination, document)
    actual = json.loads(destination.read_text(encoding="utf-8"))

    assert actual["ins_rules"] == []
    assert actual["blk_rules"] == []


def test_malformed_inactive_source_rule_is_not_stripped_on_save(tmp_path: Path):
    document = _v2_document()
    malformed_rule = {"name": "bad", "is_activated": 0, "config": {}}
    document["ins_rules"] = [malformed_rule]
    project = _write_project(tmp_path, document)

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(project)

    project.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))

    assert actual["ins_rules"] == [malformed_rule]
    assert actual["blk_rules"] == []
