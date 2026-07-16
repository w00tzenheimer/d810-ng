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


def _assigned_strings(path: Path, name: str) -> set[str]:
    for node in _tree(path).body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            continue
        value = node.value
        if isinstance(value, ast.Call) and value.args:
            value = value.args[0]
        return {
            item.value
            for item in ast.walk(value)
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        }
    raise AssertionError(f"{name} not found")


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


def test_live_block_optimizer_retains_router_resolution_project_config():
    path = _ROOT / "src/d810/hexrays/hooks/optblock_adapter.py"

    assert "router_resolution" in _assigned_strings(path, "_PROJECT_CONFIG_KEYS")


def test_live_unflattener_merges_project_policy_before_family_selection():
    path = (
        _ROOT
        / "src/d810/optimizers/microcode/flow/flattening/state_machine_cff_unflattener.py"
    )
    method = _method(path, "StateMachineCffUnflattener", "run_state_machine_unflatten")

    assert "effective_family_selection_config" in _calls(method)
    select_calls = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_select_family"
    ]
    assert len(select_calls) == 1
    assert any(
        isinstance(argument, ast.Name) and argument.id == "family_config"
        for argument in select_calls[0].args
    )
