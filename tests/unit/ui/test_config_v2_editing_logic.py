from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from d810.manager.config_v2_edit_models import (
    ConfigV2EditDiagnostic,
    ConfigV2EditableField,
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.core.pass_editor_spec import (
    AdvisoryTone,
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
    RuleEditorSpec,
    TransformCost,
    TransformEditorSpec,
    VerificationStatus,
)
from d810.manager.workbench_recipe_models import PassCatalogEntry
from d810.ui import config_v2_editing_logic as logic


def test_project_description_preview_is_single_line_bounded_and_preserves_empty_state() -> None:
    assert logic.project_description_preview("  Fold\n  proven constants.  ") == (
        "Fold proven constants."
    )
    assert logic.project_description_preview("") == "No description"
    assert logic.project_description_preview(
        "A very long project description that must remain a compact pipeline header.",
        maximum_length=32,
    ) == "A very long project..."


def _draft() -> ConfigV2ProjectDraft:
    return ConfigV2ProjectDraft(
        draft_id="draft",
        revision=2,
        source_path=Path("/source.json"),
        destination_path=Path("/destination.json"),
        source_sha256="abc",
        original_document_json="{}",
        document_json="{}",
    )


def _validation(*, valid: bool = True, revision: int = 2) -> ConfigV2ProjectValidation:
    diagnostics = (
        ()
        if valid
        else (
            ConfigV2EditDiagnostic("invalid-pipeline", "unknown pass", "pipeline_v2"),
        )
    )
    return ConfigV2ProjectValidation(
        draft_id="draft",
        revision=revision,
        valid=valid,
        pass_ids=("mba-simplify",),
        stage_ids=("simplify-mba",),
        transform_ids=("add-xor-1",),
        routing_policy_json="{}",
        diagnostics=diagnostics,
    )


def _transform_catalog_spec() -> PassEditorSpec:
    return PassEditorSpec.transform_catalog(
        tuple(
            TransformEditorSpec(
                transform_id=transform_id,
                label=transform_id,
                family_id="mba",
                family_label="MBA",
                subfamily_id="examples",
                subfamily_label="Examples",
                description="Test-only registered transform.",
                reference="Test catalog",
                maturities=("any",),
                default_selected=True,
                verification=VerificationStatus.UNAVAILABLE,
                verification_reason="Test-only catalog.",
                advisory=AdvisoryTone.NONE,
                advisory_reason="",
                cost=TransformCost.UNKNOWN,
            )
            for transform_id in ("add-xor-1", "sub-xor-1", "and-or-1")
        )
    )


def _catalog() -> tuple[PassCatalogEntry, ...]:
    return (
        PassCatalogEntry(
            pass_id="mba-simplify",
            display_name="MBA simplify",
            contract_json='{"pass":"mba-simplify"}',
            option_template_json="{}",
            granularity="function",
            maturity="MMAT_LOCOPT",
            backend_route="mutation_backend",
            safety_policy="verified",
            transform_ids=("add-xor-1", "sub-xor-1", "and-or-1"),
            stage_ids=("simplify-mba",),
            configured=True,
            editor_spec=_transform_catalog_spec(),
        ),
        PassCatalogEntry(
            pass_id="constant-simplification",
            display_name="Constant simplification",
            contract_json='{"pass":"constant-simplification"}',
            option_template_json="{}",
            granularity="function",
            maturity="MMAT_LOCOPT",
            backend_route="mutation_backend",
            safety_policy="default",
            transform_ids=(),
            stage_ids=("constant-fold",),
            configured=True,
            editor_spec=PassEditorSpec.fields_editor(
                (
                    FieldEditorSpec(
                        field_id="memory_policy",
                        label="Memory policy",
                        path=("memory_policy",),
                        control=FieldControlKind.ENUM,
                        choices=("strict", "aggressive_no_direct_writes"),
                        default="strict",
                    ),
                    FieldEditorSpec(
                        field_id="allow_executable_readonly",
                        label="Allow executable read-only memory",
                        path=("allow_executable_readonly",),
                        control=FieldControlKind.BOOLEAN,
                        default=False,
                    ),
                )
            ),
        ),
        PassCatalogEntry(
            pass_id="jump-fixer",
            display_name="Jump fixer",
            contract_json='{"pass":"jump-fixer"}',
            option_template_json="{}",
            granularity="function",
            maturity="MMAT_GLBOPT1",
            backend_route="mutation_backend",
            safety_policy="conservative",
            transform_ids=(),
            stage_ids=("fix-jumps",),
            configured=True,
            editor_spec=PassEditorSpec.rule_catalog(
                (
                    RuleEditorSpec(
                        rule_id="jump-direct",
                        label="Direct jump",
                        family_id="jump-fixer",
                        family_label="Jump fixer",
                        subfamily_id=None,
                        subfamily_label=None,
                        description="A test-only selectable jump-fixer rule.",
                        verification=VerificationStatus.VERIFIED,
                    ),
                )
            ),
        ),
        PassCatalogEntry(
            pass_id="cleanup-residual-dispatcher",
            display_name="Cleanup residual dispatcher",
            contract_json='{"pass":"cleanup-residual-dispatcher"}',
            option_template_json="{}",
            granularity="function",
            maturity="MMAT_GLBOPT1",
            backend_route="mutation_backend",
            safety_policy="conservative",
            transform_ids=(),
            stage_ids=("cleanup-dispatcher",),
            configured=True,
            editor_spec=PassEditorSpec.summary(),
        ),
    )


def _draft_with_pipeline(
    *, document: dict[str, object] | None = None
) -> ConfigV2ProjectDraft:
    payload = document or {
        "description": "OLLVM profile",
        "migration_metadata": {"schema": 7},
        "additional_configuration": {
            "pipeline_v2": [
                {
                    "pass_id": "mba-simplify",
                    "options": {"transforms": ["add-xor-1", "sub-xor-1", "unknown"]},
                },
                {"pass_id": "jump-fixer", "options": {"transforms": ["add-xor-1"]}},
            ],
            "router_resolution": {
                "require": None,
                "prefer": {"ollvm": 4.0},
                "deny": ["tigress"],
            },
            "analysis_priors": {"opaque": True},
        },
    }
    serialized = json.dumps(payload)
    return ConfigV2ProjectDraft(
        draft_id="draft",
        revision=2,
        source_path=Path("/source.json"),
        destination_path=Path("/destination.json"),
        source_sha256="abc",
        original_document_json=serialized,
        document_json=serialized,
    )


def _inspector_for(pass_id: str) -> logic.ConfigV2PassInspectorView:
    draft = _draft_with_pipeline(
        document={
            "description": "Test profile",
            "additional_configuration": {
                "pipeline_v2": [{"pass_id": pass_id, "options": {}}],
            },
        }
    )
    return logic.project_config_v2_editor_view(
        draft, _validation(), _catalog()
    ).inspectors[0]


def test_serializer_rows_are_manifest_driven_and_preserve_declared_order():
    serializers = (
        ConfigV2FieldSerializer(
            ConfigV2EditableField.DESCRIPTION,
            "Description",
            "string",
            ("description",),
        ),
        ConfigV2FieldSerializer(
            ConfigV2EditableField.PIPELINE_SELECTION,
            "Passes",
            "pipeline",
            ("additional_configuration", "pipeline_v2"),
        ),
    )

    rows = logic.project_serializer_rows(serializers)

    assert [row.field_id for row in rows] == ["description", "pipeline_selection"]
    assert rows[1].path == "additional_configuration.pipeline_v2"


def test_save_action_requires_exact_current_valid_identity():
    ready = {
        item.action_id: item
        for item in logic.config_v2_action_states(_draft(), _validation())
    }
    invalid = {
        item.action_id: item
        for item in logic.config_v2_action_states(_draft(), _validation(valid=False))
    }
    stale = {
        item.action_id: item
        for item in logic.config_v2_action_states(_draft(), _validation(revision=1))
    }

    assert ready["save_project"].enabled is True
    assert invalid["save_project"].enabled is False
    assert "unknown pass" in invalid["save_project"].reason
    assert stale["save_project"].enabled is False
    assert "current draft" in stale["save_project"].reason


def test_document_projection_exposes_typed_fields_and_read_only_complete_payload():
    document = {
        "description": "OLLVM profile",
        "migration_metadata": {"schema": 7},
        "additional_configuration": {
            "pipeline_v2_mode": "config-v2",
            "analysis_priors": {"opaque": True},
            "router_resolution": {
                "prefer": {"approov": 4.0},
                "require": None,
                "deny": ["tigress"],
            },
            "pipeline_v2": [
                {
                    "pass_id": "mba-simplify",
                    "options": {"budget": 3},
                    "unknown_pass_metadata": "preserve-me",
                },
                {"pass_id": "jump-fixer", "options": {}},
            ],
        },
    }
    draft = ConfigV2ProjectDraft(
        draft_id="draft",
        revision=2,
        source_path=Path("/source.json"),
        destination_path=Path("/destination.json"),
        source_sha256="abc",
        original_document_json=json.dumps(document),
        document_json=json.dumps(document),
    )

    view = logic.project_config_v2_document(draft)

    assert view.description == "OLLVM profile"
    assert [row.pass_id for row in view.pipeline_rows] == [
        "mba-simplify",
        "jump-fixer",
    ]
    assert json.loads(view.pipeline_rows[0].options_json) == {"budget": 3}
    assert json.loads(view.routing_json)["deny"] == ["tigress"]
    assert json.loads(view.complete_document_json)["migration_metadata"] == {
        "schema": 7
    }
    unsupported = json.loads(view.unsupported_document_json)
    assert unsupported["migration_metadata"] == {"schema": 7}
    assert unsupported["additional_configuration"]["analysis_priors"] == {
        "opaque": True
    }
    assert "pipeline_v2" not in unsupported["additional_configuration"]


def test_config_v2_logic_has_no_qt_ida_registry_or_persistence_imports():
    path = Path(logic.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )

    assert not any(name.startswith(("ida", "PyQt", "PySide")) for name in imports)
    assert not any(
        token in name for name in imports for token in ("registry", "persistence")
    )


def test_editor_overview_lists_only_configured_passes_and_real_selection():
    view = logic.project_config_v2_editor_view(
        _draft_with_pipeline(), _validation(), _catalog()
    )

    assert [row.pass_id for row in view.overview.rows] == [
        "mba-simplify",
        "jump-fixer",
    ]
    assert view.overview.rows[0].selected_transform_summary == "2 selected transforms"
    assert view.overview.rows[1].selected_transform_summary == "0 selected rules"


def test_editor_overview_omits_selection_summary_without_a_selectable_catalog():
    draft = _draft_with_pipeline(
        document={
            "description": "No-catalog passes",
            "additional_configuration": {
                "pipeline_v2": [
                    {"pass_id": "constant-simplification", "options": {}},
                    {"pass_id": "cleanup-residual-dispatcher", "options": {}},
                ],
            },
        }
    )

    view = logic.project_config_v2_editor_view(draft, _validation(), _catalog())

    assert tuple(
        row.selected_transform_summary for row in view.overview.rows
    ) == ("", "")


def test_editor_inspector_uses_catalog_contract_and_presentation_purpose():
    view = logic.project_config_v2_editor_view(
        _draft_with_pipeline(), _validation(), _catalog()
    )
    inspector = view.inspectors[0]

    assert inspector.runs_during == "MMAT_LOCOPT"
    assert inspector.purpose == "Simplify selected mixed-boolean arithmetic transforms."
    assert inspector.contract_chips == (
        ("Scope", "function"),
        ("Backend", "mutation_backend"),
        ("Safety", "verified"),
    )
    assert inspector.transform_catalog is not None
    assert inspector.transform_catalog.selected_ids == ("add-xor-1", "sub-xor-1")
    assert inspector.transform_catalog.visible_transform_ids == (
        "add-xor-1",
        "sub-xor-1",
        "and-or-1",
    )


def test_editor_inspector_layout_uses_declared_primary_capability() -> None:
    view = logic.project_config_v2_editor_view(
        _draft_with_pipeline(), _validation(), _catalog()
    )
    mba, jump = view.inspectors

    assert mba.layout is not None
    assert (
        mba.layout.primary_section is logic.ConfigV2InspectorPrimarySection.TRANSFORMS
    )
    assert mba.layout.show_transform_catalog is True
    assert mba.layout.show_rule_catalog is False
    assert mba.layout.show_options is False

    assert jump.layout is not None
    assert jump.layout.primary_section is logic.ConfigV2InspectorPrimarySection.RULES
    assert jump.layout.show_rule_catalog is True
    assert jump.layout.show_transform_catalog is False


def test_fields_and_summary_inspector_layouts_do_not_reserve_catalog_space() -> None:
    fields = _inspector_for("constant-simplification")
    summary = _inspector_for("cleanup-residual-dispatcher")

    assert fields.layout is not None
    assert (
        fields.layout.primary_section is logic.ConfigV2InspectorPrimarySection.OPTIONS
    )
    assert fields.layout.show_options is True
    assert fields.layout.show_rule_catalog is False
    assert fields.layout.show_transform_catalog is False

    assert summary.layout is not None
    assert summary.layout.primary_section is logic.ConfigV2InspectorPrimarySection.NONE
    assert summary.layout.show_options is False
    assert summary.layout.show_summary_message is True
    assert summary.layout.summary_message == "This pass exposes no editable controls."


def test_pass_inspector_view_defaults_new_optional_catalogs_for_overview_callers():
    """A new optional inspector surface must not break an existing overview path."""
    inspector = logic.ConfigV2PassInspectorView(
        pass_index=0,
        pass_id="jump-fixer",
        display_name="Jump fixer",
        purpose="Fix configured jumps.",
        runs_during="MMAT_GLBOPT1",
        transform_catalog=None,
        options={},
        contract={},
        contract_chips=(),
    )

    assert inspector.rule_catalog is None
    assert inspector.layout is None


def test_typed_field_actions_normalize_values_without_mutating_other_options():
    field = FieldEditorSpec(
        field_id="maturities",
        label="Maturities",
        path=("runtime", "maturities"),
        control=FieldControlKind.STRING_LIST,
        description="Selected Hex-Rays maturities.",
    )
    original = {"keep": {"this": True}, "runtime": {"other": "value"}}

    updated = logic.apply_typed_field_option(
        original,
        field,
        "MMAT_PREOPTIMIZED, MMAT_LOCOPT",
    )

    assert original == {"keep": {"this": True}, "runtime": {"other": "value"}}
    assert updated == {
        "keep": {"this": True},
        "runtime": {
            "other": "value",
            "maturities": ["MMAT_PREOPTIMIZED", "MMAT_LOCOPT"],
        },
    }


def test_typed_field_actions_reject_out_of_contract_values() -> None:
    field = FieldEditorSpec(
        field_id="max_leaves",
        label="Maximum leaves",
        path=("max_leaves",),
        control=FieldControlKind.INTEGER,
        minimum=1,
        maximum=16,
    )

    with pytest.raises(ValueError, match="Maximum leaves"):
        logic.apply_typed_field_option({}, field, 17)


def test_editor_routing_raw_document_and_footer_are_lossless_and_current():
    document = {
        "description": "profile",
        "unknown_top_level": {"keep": [1, 2]},
        "additional_configuration": {
            "pipeline_v2": [],
            "router_resolution": {"prefer": {"ollvm": 4}},
            "unknown_additional": {"keep": True},
        },
    }
    original = json.dumps(document)
    changed = dict(document)
    changed["description"] = "changed"
    draft = ConfigV2ProjectDraft(
        draft_id="draft",
        revision=2,
        source_path=Path("/source.json"),
        destination_path=Path("/destination.json"),
        source_sha256="abc",
        original_document_json=original,
        document_json=json.dumps(changed),
    )
    view = logic.project_config_v2_editor_view(
        draft, _validation(valid=False), _catalog()
    )

    assert view.routing.is_auto is False
    assert view.routing.require is None
    assert view.routing.preferred == (("ollvm", 4.0),)
    assert view.routing.denied == ()
    assert view.raw_document.document == changed
    assert view.raw_document.preserved_fields == {
        "unknown_top_level": {"keep": [1, 2]},
        "additional_configuration": {"unknown_additional": {"keep": True}},
    }
    assert view.footer.dirty is True
    assert view.footer.validation_label == "Validate before saving."
    assert view.footer.save_enabled is False


def test_editor_missing_routing_is_auto_and_stale_validation_cannot_save():
    document = {
        "description": "profile",
        "additional_configuration": {"pipeline_v2": []},
    }
    view = logic.project_config_v2_editor_view(
        _draft_with_pipeline(document=document), _validation(revision=1), _catalog()
    )

    assert view.routing.is_auto is True
    assert view.routing.require is None
    assert view.routing.preferred == ()
    assert view.routing.denied == ()
    assert view.footer.dirty is False
    assert view.footer.validation_label == "Validate before saving."
    assert view.footer.save_enabled is False
