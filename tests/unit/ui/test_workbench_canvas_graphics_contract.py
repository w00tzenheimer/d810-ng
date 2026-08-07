"""Static contracts for the read-only native dataflow graphics layer."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
GRAPHICS = ROOT / "src/d810/ui/workbench_canvas_graphics.py"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def test_graphics_module_is_headless_safe_and_uses_only_the_qt_shim() -> None:
    source = GRAPHICS.read_text(encoding="utf-8")
    imports = _imports(GRAPHICS)

    assert "d810.qt_shim" in imports
    assert "PyQt5" not in source
    assert "PySide6" not in source
    assert "ida_" not in source


def test_graphics_surface_has_navigation_but_no_graph_mutation_api() -> None:
    source = GRAPHICS.read_text(encoding="utf-8")

    for required in (
        "wheelEvent",
        "mousePressEvent",
        "mouseMoveEvent",
        "fit_workspace",
    ):
        assert required in source
    for forbidden in (
        "connect_nodes",
        "disconnect_nodes",
        "delete_node",
        "NodeFactory",
        "GraphRegistry",
    ):
        assert forbidden not in source


def test_graphics_node_item_is_selectable_but_never_recipe_movable() -> None:
    source = GRAPHICS.read_text(encoding="utf-8")

    assert "class ReadOnlyCanvasNodeItem(QtWidgets.QGraphicsObject):" in source
    assert "ItemIsSelectable" in source
    assert "ItemIsMovable" not in source
    assert "self.setData(0, node.node_id)" in source
    assert "node_card_lines(self._node)" in source


def test_graphics_connection_item_uses_a_cubic_path_without_editing_edges() -> None:
    source = GRAPHICS.read_text(encoding="utf-8")

    assert "class ReadOnlyCanvasConnectionItem(QtWidgets.QGraphicsPathItem):" in source
    assert "path.cubicTo(" in source
    assert "setData(0, edge)" in source
    assert "mousePressEvent" not in source[source.index("ReadOnlyCanvasConnectionItem") :]
