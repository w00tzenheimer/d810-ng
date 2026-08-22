from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
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
    assert require_config_v2_project(ProjectConfiguration.from_file(project.path))[
        0
    ].pass_id == ("recover_dispatcher")


def test_runtime_project_model_has_no_legacy_rule_array_fields():
    field_names = {field.name for field in fields(ProjectConfiguration)}

    assert "ins_rules" not in field_names
    assert "blk_rules" not in field_names


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
    [
        ("ins_rules", []),
        ("blk_rules", []),
        ("ins_rules", None),
        ("blk_rules", None),
        ("ins_rules", {}),
        ("blk_rules", "bad"),
    ],
)
def test_project_file_rejects_any_legacy_rule_array_with_migration_command(
    tmp_path: Path, field: str, value: object
):
    document = _v2_document()
    document[field] = value
    path = tmp_path / "malformed-array.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="migrate_project_config_v2.py"):
        ProjectConfiguration.from_file(path)


def test_unknown_pass_direct_save_retains_source_fields(tmp_path: Path):
    document = _v2_document()
    document["additional_configuration"]["pipeline_v2"] = [
        {"pass_id": "not-a-registered-pass"}
    ]
    project = _write_project(tmp_path, document)

    project.save()
    actual = json.loads(project.path.read_text(encoding="utf-8"))

    assert "ins_rules" not in actual
    assert "blk_rules" not in actual
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

    assert "ins_rules" not in actual
    assert "blk_rules" not in actual


def test_unknown_pass_atomic_persistence_retains_source_fields(tmp_path: Path):
    document = _v2_document()
    document["additional_configuration"]["pipeline_v2"] = [
        {"pass_id": "not-a-registered-pass"}
    ]
    destination = tmp_path / "atomic.json"

    write_project_document_atomically(destination, document)
    actual = json.loads(destination.read_text(encoding="utf-8"))

    assert "ins_rules" not in actual
    assert "blk_rules" not in actual


def test_legacy_source_rule_is_rejected_before_runtime_model_construction(
    tmp_path: Path,
):
    document = _v2_document()
    malformed_rule = {"name": "bad", "is_activated": 0, "config": {}}
    document["ins_rules"] = [malformed_rule]
    with pytest.raises(ValueError, match="migrate_project_config_v2.py"):
        _write_project(tmp_path, document)


@pytest.mark.parametrize("field", ["ins_rules", "blk_rules"])
def test_strict_mapping_parser_rejects_even_empty_legacy_arrays(field: str):
    document = _v2_document()
    document[field] = []

    with pytest.raises(PipelineConfigError, match="removed legacy field"):
        require_config_v2_project(document)
