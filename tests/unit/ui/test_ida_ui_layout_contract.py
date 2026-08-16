from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

from d810.core.settings import D810Settings


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


def _compiled_config_form_method(name: str):
    method = _method(name)
    class_node = ast.ClassDef(
        name="ConfigFormHarness",
        bases=[],
        keywords=[],
        body=[method],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))
    namespace = {
        "logger": SimpleNamespace(debug=lambda *args: None),
        "ida_kernwin": SimpleNamespace(
            PluginForm=SimpleNamespace(WCLS_SAVE=1),
        ),
    }
    exec(compile(module, filename=str(IDA_UI), mode="exec"), namespace)
    return getattr(namespace["ConfigFormHarness"], name)


class _Signal:
    def __init__(self) -> None:
        self.disconnect_count = 0

    def disconnect(self) -> None:
        self.disconnect_count += 1


class _Button:
    def __init__(self) -> None:
        self.clicked = _Signal()


class _Action:
    def __init__(self) -> None:
        self.triggered = _Signal()


def test_active_pipeline_overview_owns_the_project_pipeline_pane() -> None:
    source = ast.unparse(_method("OnCreate"))

    assert "self._pipeline_overview = ConfigV2PipelineOverviewWidget(" in source
    assert (
        "self._pipeline_overview.inspect_requested.connect("
        "self._inspect_config_v2_pass)" in source
    )
    assert (
        "self._pipeline_overview.edit_pipeline_requested.connect("
        "self._edit_config)" in source
    )
    assert "main_layout.addWidget(self._pipeline_overview, stretch=1)" in source
    assert "PassTreeWidget" not in source
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
    assert "row_px=self._pipeline_overview.row_height()" in density
    assert "filter_has_text=False" in density


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


def test_close_disconnects_menu_actions_without_treating_them_as_buttons() -> None:
    close = _compiled_config_form_method("OnClose")
    form = SimpleNamespace(
        shown=True,
        cfg_select=None,
        _pipeline_overview=None,
        _config_v2_overview=None,
        _details_toggle=None,
        _engine_menu=object(),
        _density_host=object(),
        _details_panel=object(),
        _config_mode_value=object(),
        _config_source_value=object(),
        _config_runtime_value=object(),
        _config_passes_value=object(),
        btn_new_cfg=None,
        btn_duplicate_cfg=None,
        btn_edit_cfg=None,
        btn_delele_cfg=None,
        btn_start=_Button(),
        btn_stop=None,
        btn_config=_Action(),
        btn_logger_cfg=_Action(),
        btn_start_profiling=_Action(),
        btn_test_runner=None,
        test_runner=None,
        _config_v2_editor=None,
    )
    actions = (
        form.btn_config,
        form.btn_logger_cfg,
        form.btn_start_profiling,
    )
    form._engine_actions = actions

    close(form, None)

    assert form.btn_start.clicked.disconnect_count == 1
    for action in actions:
        assert action.triggered.disconnect_count == 1


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


def test_plugin_settings_expose_callback_evidence_detail() -> None:
    init_source = ast.unparse(_plugin_method("__init__"))

    assert "self.combo_execution_callback_detail" in init_source
    assert "Summary (recommended)" in init_source
    assert "Full per-callback detail (slow)" in init_source
    assert "execution_callback_detail" in init_source


def test_plugin_settings_persist_and_apply_callback_evidence_without_restart() -> None:
    save_source = ast.unparse(_plugin_method("save_config"))

    assert "configure_settings(execution_callback_detail=" in save_source
    assert "self.state.manager.reconfigure_execution_callback_detail" in save_source
    assert "self.state.d810_config.set('execution_callback_detail'" in save_source


def test_every_runtime_setting_has_a_settings_dialog_control_and_save_path() -> None:
    source = ast.unparse(_plugin_method("__init__")) + ast.unparse(
        _plugin_method("save_config")
    )

    missing = [field.name for field in fields(D810Settings) if field.name not in source]

    assert missing == []
