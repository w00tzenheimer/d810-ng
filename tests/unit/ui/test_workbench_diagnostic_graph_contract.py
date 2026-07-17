from __future__ import annotations

import ast
from pathlib import Path


GRAPH = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "workbench_diagnostic_graph.py"
)


def _tree() -> ast.Module:
    return ast.parse(GRAPH.read_text(encoding="utf-8"), filename=str(GRAPH))


def _method(class_name: str, name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"{class_name}.{name} not found")


def _source(name: str) -> str:
    source = GRAPH.read_text(encoding="utf-8")
    segment = ast.get_source_segment(source, _method("_DiagnosticGraphViewer", name))
    assert segment is not None
    return segment


def test_native_graph_adapter_uses_only_the_ida_rendering_boundary() -> None:
    source = GRAPH.read_text(encoding="utf-8")

    assert "import ida_graph" in source
    assert "import ida_kernwin" in source
    assert "GraphViewer" in source
    assert "import sqlite3" not in source
    assert "d810.diagnostics.workbench_inventory" not in source
    assert "get_diagnostic_records" not in source


def test_adapter_declares_refresh_hint_double_click_popup_and_group_paths() -> None:
    source = GRAPH.read_text(encoding="utf-8")

    for required in (
        "def OnRefresh",
        "def OnHint",
        "def OnDblClick",
        "def OnPopup",
        "AddNode",
        "AddEdge",
        "CreateGroups",
        "SetGroupsVisibility",
        "attach_dynamic_action_to_popup",
        "def select_node",
        "def show_or_focus",
    ):
        assert required in source


def test_graphviewer_supplies_its_mandatory_text_callback() -> None:
    source = GRAPH.read_text(encoding="utf-8")

    assert "def OnGetText(self, node_id: int) -> str:" in source
    assert "return str(self[node_id])" in source


def test_hint_callback_defensively_ignores_stale_ida_node_ids() -> None:
    source = _source("OnHint")

    assert "self._id_to_model.get" in source
    assert "return None" in source
