from __future__ import annotations

import ast
from pathlib import Path


PANEL = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "workbench_panel.py"


def _method_source(name: str) -> str:
    source = PANEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(PANEL))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DeobfuscationWorkbenchPanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    segment = ast.get_source_segment(source, item)
                    assert segment is not None
                    return segment
    raise AssertionError(f"DeobfuscationWorkbenchPanel.{name} not found")


def test_workbench_constructs_and_injects_one_diagnostics_graph_controller() -> None:
    source = _method_source("_show_diagnostics")

    assert "DiagnosticGraphController" in source
    assert "IdaDiagnosticGraphView" in source
    assert "graph_controller=controller" in source
    assert "function_name=self._func_name or None" in source
