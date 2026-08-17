from __future__ import annotations

import ast
import json
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

from d810.core.config import D810Configuration
from d810.core.settings import (
    D810Settings,
    apply_saved_runtime_settings,
    get_settings,
    reset_settings,
)


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


def _state_method(name: str) -> ast.FunctionDef:
    state_path = (
        Path(__file__).resolve().parents[3] / "src" / "d810" / "manager" / "state.py"
    )
    tree = ast.parse(state_path.read_text(encoding="utf-8"), filename=str(state_path))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810State":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810State.{name} not found")


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


def _compiled_plugin_form_method(name: str):
    method = _plugin_method(name)
    class_node = ast.ClassDef(
        name="PluginFormHarness",
        bases=[],
        keywords=[],
        body=[method],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))

    class _MessageBox:
        @staticmethod
        def critical(*_args):
            raise AssertionError("unexpected settings dialog error")

    namespace = {
        "FunctionStorageConfigurationError": RuntimeError,
        "QtCore": SimpleNamespace(QTimer=SimpleNamespace(singleShot=lambda *_: None)),
        "QtWidgets": SimpleNamespace(QMessageBox=_MessageBox),
        "configure_settings": __import__(
            "d810.core.settings", fromlist=["configure_settings"]
        ).configure_settings,
        "apply_runtime_settings": __import__(
            "d810.core.settings", fromlist=["apply_runtime_settings"]
        ).apply_runtime_settings,
        "ida_kernwin": SimpleNamespace(),
        "parse_function_recipe_storage": lambda payload, *, log_dir: payload,
        "pathlib": __import__("pathlib"),
    }
    exec(compile(module, filename=str(IDA_UI), mode="exec"), namespace)
    return getattr(namespace["PluginFormHarness"], name)


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
    assert "diagnostics_capture_presentation" in update_source
    toggle_source = ast.unparse(_method("_toggle_diagnostics_capture"))
    assert "set_diagnostics_capture_enabled" in toggle_source


def test_plugin_settings_use_shared_path_controls_for_directories() -> None:
    source = ast.unparse(_plugin_method("__init__"))
    choose_source = ast.unparse(_plugin_method("choose_log_dir"))

    assert "DirectoryPathField" in source
    assert "DirectoryPathField" not in choose_source
    assert "QFileDialog.getExistingDirectory" not in choose_source


def test_plugin_settings_use_shared_file_controls_for_file_destinations() -> None:
    source = ast.unparse(_plugin_method("__init__"))
    choose_source = ast.unparse(_plugin_method("choose_function_storage_path"))

    assert "FilePathField" in source
    assert "self.capture_post_file_field = FilePathField(" in source
    assert "self.function_storage_path_field = FilePathField(" in source
    assert "self._update_post_maturity_capture_controls" in source
    assert "QFileDialog.getSaveFileName" not in choose_source


def test_plugin_settings_keep_general_and_developer_controls_compact_at_top() -> None:
    source = ast.unparse(_plugin_method("__init__"))

    assert "general_layout.setAlignment(QtCore.Qt.AlignTop)" in source
    assert "settings_layout.setAlignment(QtCore.Qt.AlignTop)" in source
    assert "general_layout.addStretch(1)" in source
    assert "developer_layout.addStretch(1)" in source


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


def test_plugin_settings_have_general_and_developer_tabs() -> None:
    source = ast.unparse(_plugin_method("__init__"))

    assert "self.tabs = QtWidgets.QTabWidget" in source
    assert "self.tabs.addTab(self.general_tab, 'General')" in source
    assert "self.tabs.addTab(self.developer_tab, 'Developer')" in source


def test_cython_disable_is_session_only_and_uses_exact_unavailable_copy() -> None:
    init_source = ast.unparse(_plugin_method("__init__"))
    save_source = ast.unparse(_plugin_method("save_config"))

    assert "Do not use Cython speedups" in init_source
    assert "Speedups not installed" in init_source
    assert "set_session_cython_disabled" in save_source
    assert "d810_config.set('disable_cython" not in save_source
    assert "d810_config.set('no_cython" not in save_source


def test_developer_runtime_settings_are_serialized_but_cython_is_not() -> None:
    init_source = ast.unparse(_plugin_method("__init__"))
    save_source = ast.unparse(_plugin_method("save_config"))

    assert "self.checkbox_native_perf" in init_source
    assert "self.checkbox_nomut_matching" in init_source
    assert "native_perf=self.checkbox_native_perf.isChecked()" in save_source
    assert "nomut_matching=self.checkbox_nomut_matching.isChecked()" in save_source
    assert "apply_runtime_settings(runtime_overrides)" in save_source
    assert "configure_settings(**runtime_overrides)" not in save_source
    assert "for setting_name, setting_value in runtime_overrides.items()" in save_source
    assert "d810_config.set('disable_cython" not in save_source
    assert "d810_config.set('no_cython" not in save_source


def test_cython_policy_change_schedules_registered_reload_after_accept() -> None:
    source = ast.unparse(_plugin_method("save_config"))

    assert "self.accept()" in source
    assert "QtCore.QTimer.singleShot(0" in source
    assert "ida_kernwin.process_ui_action('D810:reload_plugin')" in source


def test_d810_state_exposes_session_cython_policy_without_ui_action_imports() -> None:
    source = ast.unparse(_state_method("set_session_cython_disabled"))

    assert "apply_session_cython_disabled" in source
    assert "ida_kernwin" not in source


def test_main_title_contains_only_the_three_state_speedup_suffix() -> None:
    source = ast.unparse(_method("Show"))

    assert "probe_speedup_availability" in source
    assert "current_speedup_headline" in source
    assert "speedup_title_suffix" in source
    assert "DEGRADED" not in source
    assert "PARTIAL" not in source


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


def test_plugin_save_preserves_env_precedence_and_persists_checkbox_values(
    monkeypatch, tmp_path
) -> None:
    """Saving conflicting checkboxes cannot change effective env-controlled settings."""
    save_config = _compiled_plugin_form_method("save_config")
    options_path = tmp_path / "options.json"
    config = D810Configuration(options_path)
    events: list[object] = []

    class _Check:
        def __init__(self, checked: bool):
            self.checked = checked

        def isChecked(self) -> bool:
            return self.checked

    class _Edit:
        def __init__(self, value: str):
            self.value = value

        def text(self) -> str:
            return self.value

    class _Combo:
        def __init__(self, value):
            self.value = value

        def currentData(self):
            return self.value

    class _Manager:
        def reconfigure_execution_callback_detail(self, value):
            events.append(("callback", value))

        def reconfigure_function_storage(self, value):
            events.append(("storage", value))

    state = SimpleNamespace(
        log_dir=str(tmp_path),
        d810_config=config,
        manager=_Manager(),
        set_session_cython_disabled=lambda _disabled: False,
    )
    form = SimpleNamespace(
        _function_storage_payload=lambda: {"backend": "netnode"},
        combo_execution_callback_detail=_Combo("summary"),
        log_dir_changed=False,
        state=state,
        checkbox_diag_snapshots=_Check(False),
        checkbox_debug_logging=_Check(False),
        checkbox_verify_capture=_Check(True),
        edit_verify_capture_dir=_Edit(""),
        combo_capture_post_maturity=_Combo(None),
        edit_capture_post_file=_Edit("/tmp/d810_capture.txt"),
        checkbox_fact_lifecycle=_Check(True),
        checkbox_trace_decompile_callers=_Check(False),
        checkbox_native_perf=_Check(False),
        checkbox_nomut_matching=_Check(True),
        checkbox_erase_logs_on_reload=_Check(False),
        checkbox_generate_z3_code=_Check(False),
        checkbox_dump_intermediate_microcode=_Check(False),
        checkbox_disable_cython=_Check(False),
        accept=lambda: events.append("accepted"),
    )

    monkeypatch.setenv("D810_NATIVE_PERF", "1")
    monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
    reset_settings()

    save_config(form)

    assert get_settings().native_perf is True
    assert get_settings().nomut_matching is False
    saved = json.loads(options_path.read_text(encoding="utf-8"))
    assert saved["native_perf"] is False
    assert saved["nomut_matching"] is True

    monkeypatch.delenv("D810_NATIVE_PERF")
    monkeypatch.delenv("D810_NOMUT_MATCHING")
    reset_settings()
    apply_saved_runtime_settings(config)
    assert get_settings().native_perf is False
    assert get_settings().nomut_matching is True
    assert "accepted" in events


def test_every_runtime_setting_has_a_settings_dialog_control_and_save_path() -> None:
    source = ast.unparse(_plugin_method("__init__")) + ast.unparse(
        _plugin_method("save_config")
    )

    missing = [field.name for field in fields(D810Settings) if field.name not in source]

    assert missing == []
