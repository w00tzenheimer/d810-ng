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
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def _calls(node: ast.AST) -> set[str]:
    result = set()
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        if isinstance(item.func, ast.Name):
            result.add(item.func.id)
        elif isinstance(item.func, ast.Attribute):
            result.add(item.func.attr)
    return result


def _method_names(path: Path, class_name: str) -> set[str]:
    return {
        item.name
        for node in _tree(path).body
        if isinstance(node, ast.ClassDef) and node.name == class_name
        for item in node.body
        if isinstance(item, ast.FunctionDef)
    }


def test_manager_owns_inventory_and_cleanup_services_and_all_operations():
    path = _ROOT / "src/d810/manager/manager.py"
    post_init_calls = _calls(_method(path, "D810Manager", "__post_init__"))
    assert "DiagnosticInventoryService" in post_init_calls
    assert "DiagnosticCleanupService" in post_init_calls

    expected = {
        "get_diagnostic_databases": "databases",
        "get_diagnostic_snapshots": "snapshots",
        "get_diagnostic_records": "records",
        "get_diagnostic_case_evidence": "load",
        "plan_diagnostic_selected_snapshots": "plan_selected_snapshots",
        "plan_diagnostic_all_snapshots": "plan_all_snapshots",
        "plan_diagnostic_keep_latest": "plan_keep_latest",
        "plan_diagnostic_selected_databases": "plan_selected_databases",
        "plan_diagnostic_all_closed_databases": "plan_all_closed_databases",
        "plan_diagnostic_vacuum": "plan_vacuum",
        "execute_diagnostic_cleanup": "execute",
    }
    for method_name, delegated_call in expected.items():
        assert delegated_call in _calls(_method(path, "D810Manager", method_name))
    assert "plan_diagnostic_older_than" not in _method_names(path, "D810Manager")


def test_state_exposes_the_same_manager_owned_operations_without_sql():
    path = _ROOT / "src/d810/manager/state.py"
    methods = (
        "get_diagnostic_databases",
        "get_diagnostic_snapshots",
        "get_diagnostic_records",
        "get_diagnostic_case_evidence",
        "plan_diagnostic_selected_snapshots",
        "plan_diagnostic_all_snapshots",
        "plan_diagnostic_keep_latest",
        "plan_diagnostic_selected_databases",
        "plan_diagnostic_all_closed_databases",
        "plan_diagnostic_vacuum",
        "execute_diagnostic_cleanup",
    )
    for method_name in methods:
        assert method_name in _calls(_method(path, "D810State", method_name))
    assert "plan_diagnostic_older_than" not in _method_names(path, "D810State")

    imported = {
        alias.name
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "sqlite3" not in imported
