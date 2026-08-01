from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MANAGER = ROOT / "src" / "d810" / "manager" / "manager.py"
OPTIMIZERS_INIT = ROOT / "src" / "d810" / "optimizers" / "__init__.py"


def test_optimizer_registry_loader_scans_the_complete_optimizer_tree() -> None:
    tree = ast.parse(
        OPTIMIZERS_INIT.read_text(encoding="utf-8"), filename=str(OPTIMIZERS_INIT)
    )
    loader = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "load_optimizer_registries"
    )
    scan = next(
        node
        for node in ast.walk(loader)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "scan"
    )

    assert isinstance(scan.args[0], ast.Name)
    assert scan.args[0].id == "__path__"
    keywords = {keyword.arg: keyword.value for keyword in scan.keywords}
    prefix = keywords["prefix"]
    assert isinstance(prefix, ast.JoinedStr)
    assert isinstance(prefix.values[0], ast.FormattedValue)
    assert isinstance(prefix.values[0].value, ast.Name)
    assert prefix.values[0].value.id == "__name__"
    assert isinstance(prefix.values[1], ast.Constant)
    assert prefix.values[1].value == "."
    assert isinstance(keywords["skip_packages"], ast.Constant)
    assert keywords["skip_packages"].value is False


def test_manager_loads_optimizer_registries_before_constructing_hooks() -> None:
    tree = ast.parse(MANAGER.read_text(encoding="utf-8"), filename=str(MANAGER))
    start = next(
        item
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "D810Manager"
        for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name == "start"
    )
    calls = [
        node.func.id
        for node in ast.walk(start)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]

    assert calls.index("load_optimizer_registries") < calls.index(
        "InstructionOptimizerManager"
    )
