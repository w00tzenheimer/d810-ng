from __future__ import annotations

import ast
from pathlib import Path


IDA_UI = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "ida_ui.py"
TREE = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))


def _method(name: str) -> ast.FunctionDef:
    for node in TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810ConfigForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810ConfigForm_t.{name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def _attributes(method: ast.FunctionDef) -> set[str]:
    return {
        node.attr
        for node in ast.walk(method)
        if isinstance(node, ast.Attribute)
    }


def test_form_opts_into_context_intents_and_disconnects_them_on_close() -> None:
    on_create = ast.unparse(_method("OnCreate"))
    on_close = ast.unparse(_method("OnClose"))

    assert "context_actions_enabled=True" in on_create
    assert "context_action_requested.connect" in on_create
    assert "context_action_requested.disconnect" in on_close


def test_context_handler_owns_legacy_and_config_v2_routing() -> None:
    method = _method("_on_rule_context_action")
    calls = _calls(method)
    attributes = _attributes(method)

    assert "get_project_runtime_snapshot" in calls
    assert "apply_context_action" in calls
    assert "resolve_config_v2_focus_target" in calls
    assert "_enter_edit_mode" in attributes
    assert "_open_config_v2_editor" in attributes


def test_edit_and_duplicate_keep_distinct_config_v2_destination_behavior() -> None:
    chooser = ast.unparse(_method("_choose_config_v2_destination"))

    assert "config_v2_user_destination" in chooser
    assert "getSaveFileName" in chooser
    assert "if not duplicate" in chooser


def test_structured_editor_accepts_focus_metadata() -> None:
    method = _method("_open_config_v2_editor")
    source = ast.unparse(method)

    assert "focus_target" in source
    assert "ConfigV2EditingPanel" in _calls(method)
