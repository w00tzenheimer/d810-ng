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
        if (
            isinstance(node, ast.ClassDef)
            and node.name == "PluginConfigurationFileForm_t"
        ):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"PluginConfigurationFileForm_t.{name} not found")


def test_pass_tree_owns_the_project_pipeline_pane() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "self._pass_tree = PassTreeWidget(" in source
    assert "main_layout.addWidget(self._pass_tree, stretch=1)" in source
    assert "RuleDetailPanel" not in source


def test_panel_is_a_flat_stack_without_group_frames() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "QGroupBox" not in source
    assert "self._header_fixed = QtWidgets.QWidget(" in source
    assert "self._engine_bar = QtWidgets.QWidget(" in source


def test_header_and_engine_bar_keep_compact_local_layouts() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "project_vbox.setContentsMargins(4, 4, 4, 4)" in source
    assert "project_vbox.setSpacing(4)" in source
    assert "engine_layout.setContentsMargins(4, 4, 4, 4)" in source
    assert "engine_layout.setSpacing(4)" in source


def test_identity_form_and_description_live_behind_the_details_disclosure() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "self._details_toggle.setCheckable(True)" in source
    assert "details_layout.addLayout(identity_layout)" in source
    assert "details_layout.addWidget(self.cfg_description)" in source
    assert "self._details_panel.setVisible(False)" in source
    # The fixed-height description box is what the disclosure replaces.
    assert "setFixedHeight(60)" not in source


def test_divergent_identity_forces_and_locks_the_disclosure() -> None:
    density = ast.unparse(_method("_apply_panel_density"))
    apply_view = ast.unparse(_method("_apply_project_config_view"))

    assert "identity_is_divergent=self._identity_is_divergent" in density
    assert "self._details_toggle.setEnabled(not plan.details_locked)" in density
    assert "self._identity_is_divergent = view.identity_is_divergent" in apply_view
    assert "differs from source" in apply_view


def test_density_plan_comes_from_the_pure_logic_layer() -> None:
    source = ast.unparse(_method("OnCreate"))
    density = ast.unparse(_method("_apply_panel_density"))

    assert "self._density_host = _DensityHost(self._apply_panel_density" in source
    assert "plan = plan_panel_density(" in density
    assert "self._pass_tree.set_filter_visible(plan.show_filter)" in density


def test_occasional_engine_controls_live_in_one_overflow_menu() -> None:
    source = ast.unparse(_method("OnCreate"))
    close_source = ast.unparse(_method("OnClose"))

    assert "engine_layout.addWidget(self.btn_start)" in source
    assert "engine_layout.addWidget(self.btn_stop)" in source
    assert "engine_layout.addStretch(1)" in source
    assert "self.btn_engine_overflow.setMenu(self._engine_menu)" in source
    for label in ("Config", "Loggers", "Profile"):
        assert f"self._engine_menu.addAction('{label}')" in source
    # Menu actions need the same finalization teardown as the buttons.
    assert "action.triggered.disconnect()" in close_source


def test_project_row_has_a_distinct_diagnostics_capture_indicator() -> None:
    source = ast.unparse(_method("OnCreate"))
    update_source = ast.unparse(_method("_update_diagnostics_capture_indicator"))

    assert "self._diagnostics_capture_indicator" in source
    assert "config_row.addWidget(self._diagnostics_capture_indicator)" in source
    assert "diagnostics-capture-enabled" in update_source
    assert "diagnostics-capture-disabled" in update_source


def test_project_selector_and_identity_form_use_left_aligned_layout_policy() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "configure_left_aligned_button(self.cfg_select)" in source
    assert "configure_left_aligned_form(identity_layout)" in source


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
