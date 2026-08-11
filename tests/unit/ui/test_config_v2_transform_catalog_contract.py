from __future__ import annotations

import ast
from pathlib import Path


WIDGET = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_transform_catalog.py"
)


def test_transform_catalog_is_a_fixed_family_tree_with_structured_metadata() -> None:
    source = WIDGET.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(WIDGET))
    classes = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}

    assert "ConfigV2TransformCatalogWidget" in classes
    assert "QTreeWidget" in source
    assert "QLineEdit" in source
    assert "QMenu" in source
    assert "StructuredDetailsView" in source
    assert "Description" in source
    assert "Verification" in source
    assert "Advisory" in source
    assert "Cost" in source
    assert "visible" in source
    assert "all" in source


def test_transform_catalog_does_not_infer_families_or_create_arbitrary_widgets() -> None:
    source = WIDGET.read_text(encoding="utf-8")

    assert "families" in source
    assert "subfamilies" in source
    assert "exec(" not in source
    assert "eval(" not in source
    assert "QPlainTextEdit" not in source


def test_transform_catalog_overflow_uses_the_shared_compact_geometry() -> None:
    source = WIDGET.read_text(encoding="utf-8")

    assert "from d810.ui.qt_layout_policy import configure_overflow_menu_button" in source
    assert "configure_overflow_menu_button(self.overflow_button)" in source
