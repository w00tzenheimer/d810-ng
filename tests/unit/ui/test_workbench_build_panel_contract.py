"""Static contracts for the primary Build Deobfuscator dock."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BUILD_PANEL = ROOT / "src" / "d810" / "ui" / "workbench_build_panel.py"
WORKSPACE_RAIL = ROOT / "src" / "d810" / "ui" / "workbench_workspace_rail.py"


def _method_source(class_name: str, method_name: str) -> str:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(BUILD_PANEL))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    segment = ast.get_source_segment(source, item)
                    assert segment is not None
                    return segment
    raise AssertionError(f"{class_name}.{method_name} not found")


def test_primary_build_panel_owns_header_dossier_timeline_inspector_and_footer() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    create_source = _method_source("BuildDeobfuscatorPanel", "OnCreate")

    assert 'TITLE = "D810-ng Build Deobfuscator"' in source
    for name in (
        "header_layout",
        "dossier_panel",
        "timeline_view",
        "inspector_panel",
        "footer_layout",
    ):
        assert name in source
    assert "QSplitter" in create_source
    assert "setStretchFactor(1, 5)" in create_source


def test_primary_build_panel_protects_timeline_width_at_compact_dock_sizes() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    create_source = _method_source("BuildDeobfuscatorPanel", "OnCreate")

    assert "self.workspace_splitter = panes" in create_source
    assert "CollapsibleWorkspaceRail" in source
    assert "self.left_rail" in create_source
    assert "self.right_rail" in create_source
    assert "splitter_sizes(self._rail_state" in create_source
    assert "self.timeline_view.setMinimumWidth(350)" in source
    assert "panes.setSizes(" in create_source


def test_primary_build_panel_renders_the_dossier_as_structured_field_groups() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    chrome_source = _method_source("BuildDeobfuscatorPanel", "_render_workspace_chrome")

    assert "StructuredDetailsView" in source
    assert "build_dossier_sections" in source
    assert "self.dossier_panel.set_sections(build_dossier_sections(dossier))" in chrome_source
    assert "dossier_panel.setPlainText" not in chrome_source


def test_primary_build_panel_opens_the_timeline_at_readable_scale() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    fit_source = _method_source("BuildDeobfuscatorPanel", "_fit_fresh_session")
    add_source = _method_source("BuildDeobfuscatorPanel", "_add_pass")

    assert "reset_canvas_view_origin" in source
    assert "self.canvas_view.reset_zoom()" in fit_source
    assert "reset_canvas_view_origin(self.canvas_view)" in fit_source
    assert "was_empty = not self._draft.passes" in add_source
    assert "reset_canvas_view_origin(self.canvas_view)" in add_source


def test_primary_build_panel_routes_recipe_mutation_only_through_adapter() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")

    assert "self._adapter.add_canvas_pass" in source
    assert "self._adapter.replace_options" in source
    assert "self._adapter.save_function" in source
    assert "execute_workbench_" not in source


def test_primary_build_panel_delegates_build_deobfuscate_and_diagnostics_to_callbacks() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")

    assert "self._refresh_build" in source
    assert "self._deobfuscate_function" in source
    assert "self._open_diagnostics" in source


def test_primary_build_panel_uses_a_persisted_floating_pluginform_workspace() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    show_source = _method_source("BuildDeobfuscatorPanel", "show")

    assert "QSettings" in source
    assert "WOPN_DP_FLOATING" in show_source
    assert "WOPN_DP_SZHINT" in show_source
    assert "ida_kernwin.DP_FLOATING" in source
    assert "PluginForm.Show" in show_source
    assert "super().show" not in show_source


def test_primary_build_panel_exposes_float_dock_and_layout_reset_actions() -> None:
    source = BUILD_PANEL.read_text(encoding="utf-8")
    create_source = _method_source("BuildDeobfuscatorPanel", "OnCreate")

    assert "Float workspace" in source
    assert "Dock workspace" in source
    assert "Reset workspace layout" in source
    assert "workspace_layout_menu" in create_source
    assert "workspace_layout_button" in create_source


def test_primary_build_panel_groups_canvas_navigation_into_a_dense_rail_grid() -> None:
    create_source = _method_source("BuildDeobfuscatorPanel", "OnCreate")

    assert "canvas_controls = QtWidgets.QGridLayout()" in create_source
    assert "canvas_controls.addWidget(self.stage_selector, 0, 0, 1, 2)" in create_source
    assert "canvas_controls.addWidget(self.collapse_button, 1, 0)" in create_source
    assert "canvas_controls.addWidget(self.add_registered_node_button, 1, 1)" in create_source
    assert "canvas_controls.addWidget(self.fit_workspace_button, 2, 0)" in create_source
    assert "canvas_controls.addWidget(self.reset_zoom_button, 2, 1)" in create_source
    assert 'self.add_registered_node_button.setText("Add node")' in create_source
    assert "navigation_controls = QtWidgets.QHBoxLayout()" not in create_source


def test_workspace_rails_use_painted_hamburger_icons_instead_of_text_chevrons() -> None:
    source = WORKSPACE_RAIL.read_text(encoding="utf-8")

    assert "QtGui.QPainter" in source
    assert "QtGui.QPixmap" in source
    assert "self._toggle_button.setIcon(" in source
    assert 'self._toggle_button.setText("<")' not in source
    assert 'self._toggle_button.setText(">")' not in source
