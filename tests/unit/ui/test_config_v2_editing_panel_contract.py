from __future__ import annotations

import ast
from pathlib import Path

PANEL = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_editing_panel.py"
)


def _tree() -> ast.Module:
    return ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))


def _method(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ClassDef) and node.name == "ConfigV2EditingPanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"ConfigV2EditingPanel.{name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def test_panel_is_thin_and_projects_only_through_pure_logic() -> None:
    imports = {
        node.module
        for node in ast.walk(_tree())
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "d810.ui.config_v2_editing_logic" in imports
    assert "d810.manager.config_v2_editing" not in imports
    assert "d810.core.project_config_persistence" not in imports
    assert "project_config_v2_document" in _calls(_method("_render"))
    assert "config_v2_action_states" in _calls(_method("_render"))


def test_panel_forwards_typed_mutations_and_save_to_adapter() -> None:
    methods = (
        "_set_description",
        "_add_pass",
        "_remove_pass",
        "_move_pass",
        "_edit_pass_rules",
        "_edit_routing",
        "_reset",
        "_validate",
        "_save",
    )
    calls = set().union(*(_calls(_method(name)) for name in methods))
    assert {
        "set_description",
        "add_pass",
        "remove_pass",
        "reorder_pass",
        "set_pass_rules",
        "set_routing_override",
        "reset",
        "validate",
        "save",
    }.issubset(calls)


def test_complete_and_unsupported_documents_are_read_only() -> None:
    init_calls = _calls(_method("__init__"))
    assert "setReadOnly" in init_calls


def test_registered_pass_catalog_uses_the_manager_record_display_name() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert "entry.display_name" in source
    assert "entry.label" not in source


def test_description_is_a_wrapped_scrollable_multiline_editor() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_calls = _calls(_method("__init__"))

    assert "QPlainTextEdit" in source
    assert "setLineWrapMode" in init_calls
    assert "setVerticalScrollBarPolicy" in init_calls
    assert "setHorizontalScrollBarPolicy" in init_calls
    assert "toPlainText" in _calls(_method("_set_description"))


def test_empty_status_area_does_not_consume_editor_space() -> None:
    calls = _calls(_method("_set_status"))

    assert "setPlainText" in calls
    assert "setVisible" in calls
