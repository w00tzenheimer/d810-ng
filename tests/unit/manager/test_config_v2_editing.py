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
    source = tmp_path / "runtime.json"
    source.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return ProjectConfiguration.from_file(source), document


def _service() -> ConfigV2EditingService:
    return ConfigV2EditingService()


def _service_and_draft(tmp_path: Path) -> tuple[ConfigV2EditingService, object]:
    project, _ = _runtime_project(tmp_path)
    service = _service()
    return service, service.create_draft(project, destination=tmp_path / "edited.json")


def _pipeline_entry(draft: object, pass_id: str) -> dict[str, object]:
    document = json.loads(draft.document_json)
    return next(
        entry
        for entry in document["additional_configuration"]["pipeline_v2"]
        if entry["pass_id"] == pass_id
    )


def test_serializer_manifest_is_explicit_immutable_and_bounded():
    serializers = _service().serializer_manifest()

    assert tuple(item.field for item in serializers) == tuple(ConfigV2EditableField)
    assert {item.field.value for item in serializers} == {
        "description",
        "pipeline_selection",
        "pass_options",
        "router_resolution",
    }
    assert all(dataclasses.is_dataclass(item) for item in serializers)
    assert all(item.__dataclass_params__.frozen for item in serializers)
    assert all(not hasattr(item, "__dict__") for item in serializers)


def test_complete_document_edit_save_uses_typed_options_and_config_v2_policy(
    tmp_path: Path,
):
    project, _ = _runtime_project(tmp_path)
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
    draft = service.set_pass_options(
        draft,
        pass_index=1,
        options={"transforms": ["add-xor-1"], "transform_options": {}},
    )
    validation = service.validate(draft)

    assert validation.valid is True
    assert validation.pass_ids == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    )
    saved = service.save(draft, validation)
    actual = json.loads(destination.read_text(encoding="utf-8"))

    assert saved.path == destination
    assert actual["description"] == "edited config-v2"
    mba = next(
        entry
        for entry in actual["additional_configuration"]["pipeline_v2"]
        if entry["pass_id"] == "mba-simplify"
    )
    assert mba["options"] == {
        "transforms": ["add-xor-1"],
        "transform_options": {},
    }
    assert "ins_rules" not in actual
    assert "blk_rules" not in actual
    assert "pipeline_v2_mode" not in actual["additional_configuration"]


def test_editor_accepts_v2_pipeline_without_execution_mode(tmp_path: Path):
    project, document = _runtime_project(tmp_path)
    document["additional_configuration"].pop("pipeline_v2_mode", None)
    source = tmp_path / "mode-less.json"
    source.write_text(json.dumps(document, indent=2), encoding="utf-8")
    project = ProjectConfiguration.from_file(source)

    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")

    assert service.validate(draft).valid is True


@pytest.mark.parametrize("mode", ["legacy", "shadow-check"])
def test_editor_rejects_legacy_execution_modes(tmp_path: Path, mode: str):
    project, document = _runtime_project(tmp_path)
    document["additional_configuration"]["pipeline_v2_mode"] = mode
    source = tmp_path / f"{mode}.json"
    source.write_text(json.dumps(document, indent=2), encoding="utf-8")
    project = ProjectConfiguration.from_file(source)

    with pytest.raises(ConfigV2EditError, match="migrate_project_config_v2.py"):
        _service().create_draft(project, destination=tmp_path / "edited.json")


def test_save_atomically_overwrites_an_existing_writable_user_override(
    tmp_path: Path,
):
    project, _ = _runtime_project(tmp_path)
    destination = tmp_path / "edited.json"
    destination.write_text('{"stale": true}', encoding="utf-8")
    service = _service()
    draft = service.set_description(
        service.create_draft(project, destination=destination),
        "replacement",
    )

    saved = service.save(draft, service.validate(draft))

    actual = json.loads(destination.read_text(encoding="utf-8"))
    assert saved.path == destination
    assert actual["description"] == "replacement"
    assert "stale" not in actual


def test_unsupported_generic_field_edits_are_refused(tmp_path: Path):
    project, _ = _runtime_project(tmp_path)
    draft = _service().create_draft(project, destination=tmp_path / "edited.json")

    with pytest.raises(ConfigV2EditError, match="serializer"):
        _service().set_field(draft, "future_top_level", {"destroy": True})


def test_selecting_mba_transforms_is_ordered_lossless_and_validated(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)
    document = json.loads(draft.document_json)
    options = document["additional_configuration"]["pipeline_v2"][1]["options"]
    options["transform_options"] = {
        "add-xor-1": {"discarded": True},
        "z-3-constant-optimization": {
            "min_nb_opcode": 5,
            "min_nb_constant": 4,
        },
        "example-guessing": {
            "min_nb_var": 1,
            "max_nb_var": 3,
            "min_nb_diff_opcodes": 3,
            "max_nb_diff_opcodes": 6,
        },
    }
    draft = dataclasses.replace(draft, document_json=json.dumps(document))
    changed = service.set_pass_transforms(
        draft,
        pass_index=1,
        transform_ids=("z-3-constant-optimization", "example-guessing"),
    )

    options = _pipeline_entry(changed, "mba-simplify")["options"]
    assert options["transforms"] == [
        "example-guessing",
        "z-3-constant-optimization",
    ]
    assert list(options["transform_options"]) == [
        "example-guessing",
        "z-3-constant-optimization",
    ]
    assert options["transform_options"] == {
        "example-guessing": {
            "min_nb_var": 1,
            "max_nb_var": 3,
            "min_nb_diff_opcodes": 3,
            "max_nb_diff_opcodes": 6,
        },
        "z-3-constant-optimization": {
            "min_nb_opcode": 5,
            "min_nb_constant": 4,
        },
    }
    assert service.validate(changed).valid is True


@pytest.mark.parametrize(
    "transform_ids, error",
    [
        (("add-xor-1", "add-xor-1"), "duplicate"),
        (("not-registered",), "unknown"),
        ((1,), "string"),
    ],
)
def test_selecting_mba_transforms_rejects_invalid_ids(
    tmp_path: Path, transform_ids: tuple[object, ...], error: str
):
    service, draft = _service_and_draft(tmp_path)

    with pytest.raises(ConfigV2EditError, match=error):
        service.set_pass_transforms(draft, pass_index=1, transform_ids=transform_ids)


def test_selecting_transforms_requires_a_list_valued_options_field(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)

    with pytest.raises(ConfigV2EditError, match="list"):
        service.set_pass_transforms(draft, pass_index=2, transform_ids=())


def test_replacing_complete_document_validates_supported_semantic_edits(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)
    document = json.loads(draft.document_json)
    document["description"] = "raw complete-document edit"
    document["additional_configuration"]["pipeline_v2"][1]["options"] = {
        "transforms": ["add-xor-1"],
        "transform_options": {},
    }
    document["additional_configuration"]["router_resolution"] = {
        "prefer": {"approov": 10.0},
        "require": None,
        "deny": ["tigress"],
    }

    changed = service.replace_document(draft, document)

    assert service.validate(changed).valid is True
    assert _pipeline_entry(changed, "mba-simplify")["options"]["transforms"] == [
        "add-xor-1"
    ]


def test_replacing_document_rejects_unsupported_field_changes(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)
    document = json.loads(draft.document_json)
    document["migration_metadata"] = {"revision": 2}

    with pytest.raises(ConfigV2EditError, match="outside declared serializers"):
        service.replace_document(draft, document)


def test_bundled_runtime_project_cannot_be_overwritten_in_place():
    source = (CONF_DIR / "default_instruction_only_config_v2_canary.json").resolve()
    project = ProjectConfiguration.from_file(source)

    with pytest.raises(ConfigV2EditError, match="bundled"):
        _service().create_draft(project, destination=source)


def test_save_rejects_a_retargeted_bundled_source_destination(tmp_path: Path):
    source = (CONF_DIR / "default_instruction_only_config_v2_canary.json").resolve()
    project = ProjectConfiguration.from_file(source)
    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")
    retargeted = dataclasses.replace(draft, destination_path=source)

    with pytest.raises(ConfigV2EditError, match="bundled"):
        service.save(retargeted, service.validate(retargeted))


def test_pass_selection_is_ordered_registered_and_can_remain_invalid_as_a_draft(
    tmp_path: Path,
):
    project, _ = _runtime_project(tmp_path)
    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")
    reordered = service.reorder_pass(draft, 0, 2)

    assert service.pipeline_pass_ids(reordered) == (
        "mba-simplify",
        "jump-fixer",
        "constant-simplification",
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


def test_add_passes_appends_ordered_templates_in_one_revision(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)

    changed = service.add_passes(draft, ("jump-fixer", "mba-simplify"))

    assert service.pipeline_pass_ids(changed) == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
        "jump-fixer",
        "mba-simplify",
    )
    assert changed.revision == draft.revision + 1


def test_add_passes_inserts_consecutive_templates_after_caller_computed_row(
    tmp_path: Path,
):
    service, draft = _service_and_draft(tmp_path)

    changed = service.add_passes(
        draft,
        ("jump-fixer", "constant-simplification"),
        index=2,
    )

    assert service.pipeline_pass_ids(changed) == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
        "constant-simplification",
        "jump-fixer",
    )


def test_add_passes_preserves_duplicate_selected_ids(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)

    changed = service.add_passes(draft, ("jump-fixer", "jump-fixer"))

    assert service.pipeline_pass_ids(changed)[-2:] == (
        "jump-fixer",
        "jump-fixer",
    )


def test_add_passes_rejects_empty_selection(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)

    with pytest.raises(ConfigV2EditError, match="at least one"):
        service.add_passes(draft, ())


def test_add_passes_rejects_invalid_insertion_index(tmp_path: Path):
    service, draft = _service_and_draft(tmp_path)

    with pytest.raises(ConfigV2EditError, match="out of range"):
        service.add_passes(
            draft,
            ("jump-fixer",),
            index=len(service.pipeline_pass_ids(draft)) + 1,
        )


@pytest.mark.parametrize("index", [True, 1.9, "1", object()])
def test_add_passes_rejects_non_integer_insertion_index_without_mutation(
    tmp_path: Path, index: object
):
    service, draft = _service_and_draft(tmp_path)
    original_document = draft.document_json
    original_revision = draft.revision

    with pytest.raises(ConfigV2EditError, match="integer"):
        service.add_passes(draft, ("jump-fixer",), index=index)

    assert draft.document_json == original_document
    assert draft.revision == original_revision


@pytest.mark.parametrize(
    "pass_ids",
    [
        ("",),
        (1,),
        ("jump-fixer", 1),
    ],
)
def test_add_passes_rejects_malformed_public_pass_ids_without_mutation(
    tmp_path: Path, pass_ids: tuple[object, ...]
):
    service, draft = _service_and_draft(tmp_path)
    original_document = draft.document_json
    original_revision = draft.revision

    with pytest.raises(ConfigV2EditError, match="pass IDs"):
        service.add_passes(draft, pass_ids)  # type: ignore[arg-type]

    assert draft.document_json == original_document
    assert draft.revision == original_revision


def test_add_passes_rejects_non_tuple_public_pass_ids_without_mutation(
    tmp_path: Path,
):
    service, draft = _service_and_draft(tmp_path)
    original_document = draft.document_json
    original_revision = draft.revision

    with pytest.raises(ConfigV2EditError, match="tuple"):
        service.add_passes(draft, ["jump-fixer"])  # type: ignore[arg-type]

    assert draft.document_json == original_document
    assert draft.revision == original_revision


def test_add_passes_preserves_unexpected_registry_value_error(tmp_path: Path):
    class UnexpectedRegistry:
        def config_template_for(self, pass_id: str) -> object:
            return object()

        def build_spec(self, template: object) -> object:
            raise ValueError("unexpected factory defect")

    service, draft = _service_and_draft(tmp_path)
    service = ConfigV2EditingService(UnexpectedRegistry())
    original_document = draft.document_json
    original_revision = draft.revision

    with pytest.raises(ValueError, match="unexpected factory defect"):
        service.add_passes(draft, ("jump-fixer",))

    assert draft.document_json == original_document
    assert draft.revision == original_revision


def test_add_passes_validates_every_template_before_mutating_unknown_batch(
    tmp_path: Path,
):
    service, draft = _service_and_draft(tmp_path)
    original_document = draft.document_json
    original_revision = draft.revision

    with pytest.raises(ConfigV2EditError, match="unknown pass"):
        service.add_passes(
            draft,
            ("jump-fixer", "not-registered", "mba-simplify"),
        )

    assert draft.document_json == original_document
    assert draft.revision == original_revision
    assert service.pipeline_pass_ids(draft) == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    )


def test_add_passes_uses_canonical_constant_simplification_template(
    tmp_path: Path,
):
    service, draft = _service_and_draft(tmp_path)
    template = service._registry.config_template_for("constant-simplification")

    changed = service.add_passes(draft, ("constant-simplification",))
    inserted = json.loads(changed.document_json)["additional_configuration"][
        "pipeline_v2"
    ][-1]

    assert inserted["options"] == template.options
    assert set(inserted["options"]) == {"preparation", "stages"}
    assert set(inserted["options"]["stages"]) == {
        "fold-readonly-data",
        "fold-constant-subtree",
        "forward-constants",
    }


def test_recipe_materialization_serializes_only_canonical_entries(
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

    assert [entry["pass_id"] for entry in pipeline] == [
        "jump-fixer",
        "mba-simplify",
        "constant-simplification",
    ]
    assert all(
        set(entry) == set(PipelineConfig.from_dict(entry).to_dict())
        for entry in pipeline
    )
    assert all("rules" not in entry and "migration" not in entry for entry in pipeline)


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


def test_clear_routing_override_removes_only_the_override_and_restores_auto(
    tmp_path: Path,
):
    service, draft = _service_and_draft(tmp_path)
    document = json.loads(draft.document_json)
    document["future_top_level"] = {"retained": ["value"]}
    document["additional_configuration"]["future_additional"] = {"kept": True}
    draft = dataclasses.replace(
        draft,
        original_document_json=json.dumps(document),
        document_json=json.dumps(document),
    )
    overridden = service.set_routing_override(
        draft,
        prefer={"approov": 4.0},
        require=None,
        deny=("tigress",),
    )

    cleared = service.clear_routing_override(overridden)
    cleared_document = json.loads(cleared.document_json)

    assert "router_resolution" not in cleared_document["additional_configuration"]
    assert cleared_document["future_top_level"] == {"retained": ["value"]}
    assert cleared_document["additional_configuration"]["future_additional"] == {
        "kept": True
    }
    assert service.validate(cleared).valid is True


def test_forged_unsupported_change_and_source_drift_are_validation_errors(
    tmp_path: Path,
):
    project, _ = _runtime_project(tmp_path)
    service = _service()
    draft = service.create_draft(project, destination=tmp_path / "edited.json")
    document = json.loads(draft.document_json)
    document["future_top_level"] = {"changed": True}
    forged = dataclasses.replace(draft, document_json=json.dumps(document))

    validation = service.validate(forged)
    assert validation.valid is False
    assert any(
        item.code == "unsupported-field-change" for item in validation.diagnostics
    )

    project.path.write_text("{}", encoding="utf-8")
    stale = service.validate(draft)
    assert stale.valid is False
    assert any(item.code == "source-drift" for item in stale.diagnostics)
