from __future__ import annotations

import ast
import json
from pathlib import Path

from d810.manager.config_v2_edit_models import (
    ConfigV2EditDiagnostic,
    ConfigV2EditableField,
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.ui import config_v2_editing_logic as logic


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
        else (ConfigV2EditDiagnostic("invalid-pipeline", "unknown pass", "pipeline_v2"),)
    )
    return ConfigV2ProjectValidation(
        draft_id="draft",
        revision=revision,
        valid=valid,
        pass_ids=("mba-simplify",),
        instruction_rule_names=("Rule",),
        block_rule_names=(),
        routing_policy_json="{}",
        diagnostics=diagnostics,
    )


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
    ready = {item.action_id: item for item in logic.config_v2_action_states(_draft(), _validation())}
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
                    "rules": {
                        "include": ["RuleA"],
                        "exclude": [],
                        "options": {"budget": 3},
                    },
                    "unknown_pass_metadata": "preserve-me",
                },
                {"pass": "jump-fixer", "options": {}},
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
    assert json.loads(view.pipeline_rows[0].rules_json)["options"] == {"budget": 3}
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
    assert not any(token in name for name in imports for token in ("registry", "persistence"))
