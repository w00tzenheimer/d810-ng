"""Static contracts for the structured Build workspace detail widgets."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DETAILS = ROOT / "src" / "d810" / "ui" / "workbench_structured_details.py"
CANVAS_PANEL = ROOT / "src" / "d810" / "ui" / "workbench_canvas_panel.py"


def _method_source(path: Path, class_name: str, method_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    segment = ast.get_source_segment(source, item)
                    assert segment is not None
                    return segment
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def test_structured_details_use_field_value_groups_not_a_prose_editor() -> None:
    source = DETAILS.read_text(encoding="utf-8")
    render_source = _method_source(DETAILS, "StructuredDetailsView", "set_sections")

    assert "QScrollArea" in source
    assert "QVBoxLayout" in render_source
    assert "QGroupBox" in render_source
    assert "field_layout.addWidget(label)" in render_source
    assert "field_layout.addWidget(value)" in render_source
    assert "widget.hide()" in render_source
    assert "widget.setParent(None)" in render_source
    assert "QPlainTextEdit" not in render_source


def test_node_inspector_has_an_intentional_empty_state_and_property_tree() -> None:
    source = DETAILS.read_text(encoding="utf-8")
    empty_source = _method_source(DETAILS, "NodeInspectorView", "show_empty")

    assert "class NodeInspectorView(QtWidgets.QStackedWidget)" in source
    assert "QTreeWidget" in source
    assert "Select a registered node" in empty_source
    assert "show_node" in source


def test_recipe_options_are_editable_but_pass_contracts_are_read_only() -> None:
    source = DETAILS.read_text(encoding="utf-8")
    node_source = _method_source(DETAILS, "NodeInspectorView", "show_node")
    dialog_source = _method_source(DETAILS, "RawJsonDialog", "__init__")

    assert "self.options_tree.set_json(options, editable=editable_options)" in node_source
    assert "self.contract_tree.set_json(contract, editable=False)" in node_source
    assert "self.editor.setReadOnly(not editable)" in dialog_source
    assert "View raw contract" in source


def test_json_tree_editor_combines_item_flags_through_qt_compatibility() -> None:
    item_source = _method_source(DETAILS, "JsonTreeEditor", "_item_for_node")

    assert "qt_flag_or(item.flags(), _item_editable_flag())" in item_source
    assert "item.flags() | _item_editable_flag()" not in item_source


def test_canvas_panel_uses_structured_inspector_not_plain_text_selection() -> None:
    source = CANVAS_PANEL.read_text(encoding="utf-8")
    init_source = _method_source(CANVAS_PANEL, "WorkbenchCanvasPanel", "__init__")
    select_source = _method_source(CANVAS_PANEL, "WorkbenchCanvasPanel", "_select_node")

    assert "from d810.ui.workbench_structured_details import NodeInspectorView" in source
    assert "self.node_inspector = NodeInspectorView()" in init_source
    assert "self.node_inspector.show_empty()" in select_source
    assert "self.node_inspector.show_node(" in select_source
    assert "self.node_inspector.setPlainText" not in select_source
