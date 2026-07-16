from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[3]


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _method(path: Path, class_name: str, method_name: str) -> ast.FunctionDef:
    for node in _tree(path).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    raise AssertionError(f"{class_name}.{method_name} not found")


def _calls(node: ast.AST) -> set[str]:
    result = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            if isinstance(item.func, ast.Name):
                result.add(item.func.id)
            elif isinstance(item.func, ast.Attribute):
                result.add(item.func.attr)
    return result


def test_manager_owns_config_v2_editor_and_exposes_structured_operations():
    path = _ROOT / "src/d810/manager/manager.py"
    assert "ConfigV2EditingService" in _calls(_method(path, "D810Manager", "__post_init__"))
    expected = {
        "get_config_v2_serializer_manifest": "serializer_manifest",
        "create_config_v2_project_draft": "create_draft",
        "validate_config_v2_project_draft": "validate",
        "set_config_v2_description": "set_description",
        "add_config_v2_pass": "add_pass",
        "remove_config_v2_pass": "remove_pass",
        "reorder_config_v2_pass": "reorder_pass",
        "set_config_v2_pass_rules": "set_pass_rules",
        "set_config_v2_routing_override": "set_routing_override",
        "materialize_recipe_as_config_v2": "materialize_recipe",
        "save_config_v2_project": "save",
    }
    for method_name, call_name in expected.items():
        assert call_name in _calls(_method(path, "D810Manager", method_name))


def test_state_save_registers_and_reloads_through_normal_project_lifecycle():
    path = _ROOT / "src/d810/manager/state.py"
    method = _method(path, "D810State", "save_and_reload_config_v2_project")
    calls = _calls(method)

    assert "save_config_v2_project" in calls
    assert "project_names" in calls
    assert "add_project" in calls
    assert "update_project" in calls
    assert "load_project" in calls
