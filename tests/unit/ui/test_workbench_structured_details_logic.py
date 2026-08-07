from __future__ import annotations

from d810.ui.workbench_build_workspace_logic import FunctionDossier
from d810.ui.workbench_structured_details_logic import (
    apply_json_tree_scalar,
    build_dossier_sections,
    json_value_tree,
    parse_contract_detail,
)


def test_generic_dossier_uses_explicit_field_value_state() -> None:
    dossier = FunctionDossier(
        function_name="test_nested_or",
        function_ea=0x18000D340,
        protection_label="Generic cleanup",
        summary="Generic cleanup - no classified protection-specific case evidence.",
        shape_lines=(),
        evidence_lines=(),
        diagnostic_lines=(),
    )

    sections = build_dossier_sections(dossier)

    assert [section.section_id for section in sections] == [
        "function",
        "protection",
        "evidence",
        "diagnostics",
    ]
    assert [(field.label, field.value) for field in sections[1].fields] == [
        ("Classification", "Generic cleanup"),
        ("Evidence", "Not classified"),
    ]
    assert [(field.label, field.value) for field in sections[2].fields] == [
        ("Records", "0"),
    ]
    assert [(field.label, field.value) for field in sections[3].fields] == [
        ("Records", "0"),
    ]
    assert all("no classified protection" not in field.value for field in sections[1].fields)


def test_json_tree_preserves_mapping_list_and_scalar_identity() -> None:
    roots = json_value_tree(
        {
            "enabled": True,
            "limit": 4,
            "stages": ["preopt", "locopt"],
        },
        editable=True,
    )

    assert [(node.key, node.editable) for node in roots] == [
        ("enabled", True),
        ("limit", True),
        ("stages", True),
    ]
    assert [child.key for child in roots[2].children] == ["0", "1"]


def test_json_tree_scalar_edit_preserves_boolean_and_integer_types() -> None:
    original = {"enabled": False, "limit": 4}

    enabled = apply_json_tree_scalar(original, ("enabled",), "true")
    limited = apply_json_tree_scalar(enabled, ("limit",), "12")

    assert limited == {"enabled": True, "limit": 12}
    assert isinstance(limited["enabled"], bool)
    assert isinstance(limited["limit"], int)


def test_json_tree_scalar_edit_retains_unquoted_text_as_a_string() -> None:
    updated = apply_json_tree_scalar(
        {"memory_policy": "safe"},
        ("memory_policy",),
        "aggressive_no_direct_writes",
    )

    assert updated == {"memory_policy": "aggressive_no_direct_writes"}


def test_contract_detail_exposes_only_the_contract_json_before_annotations() -> None:
    detail = '{"pass":"jump-fixer","runtime":{"scope":"function"}}\nlinked evidence: 2'

    assert parse_contract_detail(detail) == {
        "pass": "jump-fixer",
        "runtime": {"scope": "function"},
    }
