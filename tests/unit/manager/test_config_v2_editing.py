from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.manager.config_v2_editing import (
    ConfigV2EditError,
    ConfigV2EditableField,
    ConfigV2EditingService,
)
from d810.manager.workbench_recipe_models import PipelineRecipeDraft, RecipePass
from d810.passes.pass_pipeline import PipelineConfig


CONF_DIR = Path("src/d810/conf")


def _runtime_project(tmp_path: Path) -> tuple[ProjectConfiguration, dict[str, object]]:
    document = json.loads(
        (CONF_DIR / "default_instruction_only_config_v2_canary.json").read_text(
            encoding="utf-8"
        )
    )
    document["future_top_level"] = {"retain": [1, 2, 3]}
    additional = document["additional_configuration"]
    additional["future_additional"] = {"retain": True}
    additional["pipeline_v2"][0]["future_pass_field"] = {"retain": "yes"}
    source = tmp_path / "runtime.json"
    source.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return ProjectConfiguration.from_file(source), document


def _service() -> ConfigV2EditingService:
    return ConfigV2EditingService()


def test_serializer_manifest_is_explicit_immutable_and_bounded():
    serializers = _service().serializer_manifest()

    assert tuple(item.field for item in serializers) == tuple(ConfigV2EditableField)
    assert {item.field.value for item in serializers} == {
        "description",
        "pipeline_selection",
        "pass_rules",
        "router_resolution",
    }
    assert all(dataclasses.is_dataclass(item) for item in serializers)
    assert all(item.__dataclass_params__.frozen for item in serializers)
    assert all(not hasattr(item, "__dict__") for item in serializers)


def test_complete_document_edit_save_preserves_unknowns_and_flat_rule_policy(tmp_path: Path):
    project, original = _runtime_project(tmp_path)
    destination = tmp_path / "edited.json"
    service = _service()
    draft = service.create_draft(project, destination=destination)
    draft = service.set_description(draft, "edited config-v2")
    draft = service.set_routing_override(
        draft,
        prefer={"approov": 10.0},
        require=None,
        deny=("tigress",),
    )
    draft = service.set_pass_rules(
        draft,
        pass_index=0,
        include=("FoldReadonlyDataRule",),
        exclude=(),
        options={"FoldReadonlyDataRule": {"fold_writable_constants": False}},
    )
    validation = service.validate(draft)

    assert validation.valid is True
    assert validation.pass_ids == (
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    )
    saved = service.save(draft, validation)
    actual = json.loads(destination.read_text(encoding="utf-8"))

    assert saved.path == destination
    assert actual["description"] == "edited config-v2"
    assert actual["future_top_level"] == original["future_top_level"]
    assert actual["additional_configuration"]["future_additional"] == {
        "retain": True
    }
    assert actual["additional_configuration"]["pipeline_v2"][0][
        "future_pass_field"
    ] == {"retain": "yes"}
    assert actual["ins_rules"] == original["ins_rules"]
    assert actual["blk_rules"] == original["blk_rules"]
    assert actual["additional_configuration"]["pipeline_v2_mode"] == "config-v2"


def test_unsupported_generic_field_edits_are_refused(tmp_path: Path):
    project, _ = _runtime_project(tmp_path)
    draft = _service().create_draft(project, destination=tmp_path / "edited.json")

    with pytest.raises(ConfigV2EditError, match="serializer"):
        _service().set_field(draft, "future_top_level", {"destroy": True})


def test_pass_selection_is_ordered_registered_and_can_remain_invalid_as_a_draft(
    tmp_path: Path,
):
    project, _ = _runtime_project(tmp_path)
    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")
    reordered = service.reorder_pass(draft, 0, 2)

    assert service.pipeline_pass_ids(reordered) == (
        "global-constant-inliner",
        "jump-fixer",
        "mba-simplify",
    )
    assert service.validate(reordered).valid is True

    empty = reordered
    while service.pipeline_pass_ids(empty):
        empty = service.remove_pass(empty, 0)
    invalid = service.validate(empty)
    assert invalid.valid is False
    assert any(item.code == "invalid-pipeline" for item in invalid.diagnostics)

    with pytest.raises(ConfigV2EditError, match="unknown pass"):
        service.add_pass(draft, "not-registered")


def test_recipe_materialization_reuses_raw_entries_and_preserves_migration_metadata(
    tmp_path: Path,
):
    project, _ = _runtime_project(tmp_path)
    service = _service()
    config_draft = service.create_draft(project, destination=tmp_path / "recipe.json")
    raw_document = json.loads(config_draft.document_json)
    raw_pipeline = raw_document["additional_configuration"]["pipeline_v2"]
    recipe_items = []
    for index, entry in enumerate(raw_pipeline):
        config = PipelineConfig.from_dict(entry)
        recipe_items.append(
            RecipePass(
                item_id=f"item-{index}",
                pass_id=config.pass_id,
                enabled=True,
                config_json=json.dumps(config.to_dict(), sort_keys=True),
            )
        )
    recipe = PipelineRecipeDraft(
        draft_id="recipe",
        schema_version=1,
        revision=0,
        function_ea=0x401000,
        function_fingerprint="sha256:test",
        workbench_generation=1,
        source_path=str(project.path),
        runtime_path=str(project.path),
        passes=tuple(reversed(recipe_items)),
    )

    materialized = service.materialize_recipe(config_draft, recipe)
    pipeline = json.loads(materialized.document_json)["additional_configuration"][
        "pipeline_v2"
    ]

    assert [entry.get("pass", entry.get("pass_id")) for entry in pipeline] == [
        "jump-fixer",
        "global-constant-inliner",
        "mba-simplify",
    ]
    mba = pipeline[-1]
    assert "migration" in mba
    assert mba["future_pass_field"] == {"retain": "yes"}


def test_routing_policy_and_stale_validation_fail_closed(tmp_path: Path):
    project, _ = _runtime_project(tmp_path)
    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")

    with pytest.raises(ConfigV2EditError, match="unknown family"):
        service.set_routing_override(
            draft,
            prefer={},
            require="unknown-family",
            deny=(),
        )

    validation = service.validate(draft)
    changed = service.set_description(draft, "new revision")
    with pytest.raises(ConfigV2EditError, match="stale"):
        service.save(changed, validation)


def test_forged_unsupported_change_and_source_drift_are_validation_errors(tmp_path: Path):
    project, _ = _runtime_project(tmp_path)
    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")
    document = json.loads(draft.document_json)
    document["future_top_level"] = {"changed": True}
    forged = dataclasses.replace(draft, document_json=json.dumps(document))

    validation = service.validate(forged)
    assert validation.valid is False
    assert any(item.code == "unsupported-field-change" for item in validation.diagnostics)

    project.path.write_text("{}", encoding="utf-8")
    stale = service.validate(draft)
    assert stale.valid is False
    assert any(item.code == "source-drift" for item in stale.diagnostics)
