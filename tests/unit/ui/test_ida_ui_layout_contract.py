from __future__ import annotations

import ast
from pathlib import Path


IDA_UI = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "ida_ui.py"


def _method(name: str) -> ast.FunctionDef:
    tree = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810ConfigForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810ConfigForm_t.{name} not found")


def _plugin_method(name: str) -> ast.FunctionDef:
    tree = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "PluginConfigurationFileForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"PluginConfigurationFileForm_t.{name} not found")


def test_rule_splitter_prefers_the_detail_pane_at_narrow_dock_widths() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "self._rule_tree.setMinimumWidth(" in source
    assert "self._rule_detail.setMinimumWidth(" in source
    assert "self._splitter.setStretchFactor(0, 2)" in source
    assert "self._splitter.setStretchFactor(1, 3)" in source
    assert "self._splitter.setSizes([400, 600])" in source


def test_project_and_engine_groups_keep_compact_local_layouts() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "project_vbox.setContentsMargins(4, 4, 4, 4)" in source
    assert "project_vbox.setSpacing(4)" in source
    assert "engine_layout.setContentsMargins(4, 4, 4, 4)" in source
    assert "engine_layout.setSpacing(4)" in source


def test_project_row_has_a_distinct_diagnostics_capture_indicator() -> None:
    source = ast.unparse(_method("OnCreate"))
    update_source = ast.unparse(_method("_update_diagnostics_capture_indicator"))

    assert "self._diagnostics_capture_indicator" in source
    assert "config_row.addWidget(self._diagnostics_capture_indicator)" in source
    assert "diagnostics-capture-enabled" in update_source
    assert "diagnostics-capture-disabled" in update_source


def test_plugin_settings_expose_explicit_recipe_storage_backend_and_path() -> None:
    source = ast.unparse(_plugin_method("__init__"))

    assert "self.function_storage_backend" in source
    assert "self.function_storage_path" in source
    assert "self.combo_function_storage_backend" in source
    assert "self.button_choose_function_storage_path" in source
    assert "self._update_function_storage_controls" in source


def test_plugin_settings_validate_and_apply_storage_without_restart() -> None:
    save_source = ast.unparse(_plugin_method("save_config"))

    assert "parse_function_recipe_storage" in save_source
    assert "self.state.manager.reconfigure_function_storage" in save_source
    assert "FunctionStorageConfigurationError" in save_source
