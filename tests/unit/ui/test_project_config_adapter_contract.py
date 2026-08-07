from __future__ import annotations

import ast
from pathlib import Path


IDA_UI = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "ida_ui.py"
ICON_DIR = IDA_UI.parent / "icons"
PASS_TREE = IDA_UI.parent / "pass_tree.py"
PIPELINE_OVERVIEW = IDA_UI.parent / "config_v2_pipeline_overview.py"
WORKBENCH_PANEL = IDA_UI.parent / "workbench_panel.py"
ICON_ASSETS = IDA_UI.parent / "icon_assets.py"
PYPROJECT = IDA_UI.parents[3] / "pyproject.toml"
TREE = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))
WORKBENCH_TREE = ast.parse(
    WORKBENCH_PANEL.read_text(encoding="utf-8"),
    filename=str(WORKBENCH_PANEL),
)


def _method(name: str) -> ast.FunctionDef:
    for node in TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810ConfigForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810ConfigForm_t.{name} not found")


def _call_names(method: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _attribute_names(method: ast.FunctionDef) -> set[str]:
    return {node.attr for node in ast.walk(method) if isinstance(node, ast.Attribute)}


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found")


def _calls(method: ast.FunctionDef, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id == name
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == name
        )
    ]


def _keyword(call: ast.Call, name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return ast.unparse(keyword.value)
    return None


def test_load_config_reads_manager_snapshot_and_pure_view() -> None:
    calls = _call_names(_method("_load_config"))

    assert "get_project_runtime_snapshot" in calls
    assert "build_project_config_view" in calls
    assert "_apply_project_config_view" in calls


def test_form_uses_searchable_popup_without_loading_a_filtered_row_index() -> None:
    calls = _call_names(_method("_open_config_picker"))

    assert "ProjectPickerPopup" in calls
    assert "build_project_picker_entries" in calls
    assert "show_for" in calls
    assert "_load_config" in _attribute_names(_method("_open_config_picker"))


def test_current_configuration_control_has_a_dropdown_affordance() -> None:
    source = IDA_UI.read_text(encoding="utf-8")

    assert "▼" in source


def test_config_actions_use_icons_instead_of_unicode_glyphs() -> None:
    source = IDA_UI.read_text(encoding="utf-8")

    for button_name in (
        "btn_new_cfg",
        "btn_duplicate_cfg",
        "btn_edit_cfg",
        "btn_delele_cfg",
    ):
        assert f"{button_name}.setIcon(" in source
    for glyph in ("⧉", "✎", "🗑"):
        assert glyph not in source


def test_config_action_svg_assets_are_packaged() -> None:
    for icon_name in ("new", "duplicate", "edit", "delete"):
        icon_path = ICON_DIR / f"{icon_name}.svg"
        assert icon_path.is_file()
        assert "<svg" in icon_path.read_text(encoding="utf-8")

    assert "ui/icons/*.svg" in PYPROJECT.read_text(encoding="utf-8")


def test_engine_status_uses_svg_icons_instead_of_text_markers() -> None:
    source = IDA_UI.read_text(encoding="utf-8")
    update_status = ast.get_source_segment(source, _method("_update_status"))

    assert update_status is not None
    assert ".setPixmap(" in update_status
    assert "*>" not in update_status
    assert "●" not in source

    for icon_name in ("status-running", "status-stopped"):
        icon_path = ICON_DIR / f"{icon_name}.svg"
        assert icon_path.is_file()
        assert "<svg" in icon_path.read_text(encoding="utf-8")


def test_pass_tree_uses_public_identity_labels() -> None:
    source = PASS_TREE.read_text(encoding="utf-8")

    assert "*>" not in source
    assert "Pass / child" in source
    assert "Transform:" in source
    assert "Stage:" in source


def test_icon_assets_have_a_qpainter_fallback_for_pyqt5_svg_failures() -> None:
    assert ICON_ASSETS.is_file()

    source = ICON_ASSETS.read_text(encoding="utf-8")
    assert "QPainter" in source
    assert "QIcon(pixmap)" in source
    assert "isNull()" in source
    assert "bundled_icon" in IDA_UI.read_text(encoding="utf-8")


def test_project_view_loads_active_pipeline_through_adapter_and_projection() -> None:
    calls = _call_names(_method("_apply_project_config_view"))

    assert "config_v2_user_destination" in calls
    assert "ConfigV2EditingAdapter" in calls
    assert "load_view" in calls
    assert "catalog" in calls
    assert "project_config_v2_editor_view" in calls
    assert "set_overview" in calls
    assert "read_text" not in calls
    assert "open" not in calls


def test_form_replaces_the_ownership_tree_with_active_pipeline_overview() -> None:
    calls = _call_names(_method("OnCreate"))
    source = ast.get_source_segment(
        IDA_UI.read_text(encoding="utf-8"),
        _method("OnCreate"),
    )

    assert PIPELINE_OVERVIEW.is_file()
    assert "ConfigV2PipelineOverviewWidget" in calls
    assert source is not None
    assert "inspect_requested.connect(self._inspect_config_v2_pass)" in source
    assert "edit_pipeline_requested.connect(self._edit_config)" in source
    assert "PassTreeWidget" not in source
    assert "edit_requested.connect" not in source


def test_private_rule_editor_methods_are_removed() -> None:
    source = IDA_UI.read_text(encoding="utf-8")

    assert "def _save_rules" not in source
    assert "RuleTreeWidget" not in source
    assert "RuleDetailPanel" not in source


def test_edit_and_duplicate_handlers_use_the_pure_policy() -> None:
    assert "select_config_edit_policy" in _call_names(_method("_edit_config"))
    assert "select_config_edit_policy" in _call_names(_method("_duplicate_config"))
    assert "_open_config_v2_editor" in _call_names(_method("_edit_config"))
    assert "_open_config_v2_editor" in _call_names(_method("_duplicate_config"))

    for method_name in ("_edit_config", "_duplicate_config"):
        calls = _calls(_method(method_name), "_open_config_v2_editor")
        assert len(calls) == 1
        assert _keyword(calls[0], "screen") == "ConfigV2EditorScreen.BUILDER"


def test_active_pipeline_inspection_uses_an_exact_indexed_focus_target() -> None:
    method = _method("_inspect_config_v2_pass")
    source = ast.get_source_segment(IDA_UI.read_text(encoding="utf-8"), method)
    resolver_calls = _calls(method, "resolve_config_v2_focus_target")
    editor_calls = _calls(method, "_open_config_v2_editor")

    assert source is not None
    assert "self._config_v2_overview.rows" in source
    assert "rows[index]" in source
    assert len(resolver_calls) == 1
    assert _keyword(resolver_calls[0], "pass_index") == "index"
    assert len(editor_calls) == 1
    assert _keyword(editor_calls[0], "screen") == "ConfigV2EditorScreen.INSPECTOR"
    assert _keyword(editor_calls[0], "focus_target") == "focus_target"


def test_config_v2_destination_chooser_imports_pathlib_for_runtime_paths() -> None:
    imported_modules = {
        alias.name
        for node in TREE.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    chooser_source = ast.get_source_segment(
        IDA_UI.read_text(encoding="utf-8"),
        _method("_choose_config_v2_destination"),
    )

    assert chooser_source is not None
    assert "pathlib.Path(" in chooser_source
    assert "pathlib" in imported_modules


def test_config_v2_editor_is_owned_and_uses_thin_command_adapter() -> None:
    method = _method("_open_config_v2_editor")
    calls = _call_names(method)
    source = ast.get_source_segment(IDA_UI.read_text(encoding="utf-8"), method)

    assert "ConfigV2EditingAdapter" in calls
    assert "ConfigV2EditingPanel" in calls
    assert "show" in calls
    assert [argument.arg for argument in method.args.kwonlyargs] == [
        "screen",
        "focus_target",
    ]
    panel_calls = _calls(method, "ConfigV2EditingPanel")
    assert len(panel_calls) == 1
    assert _keyword(panel_calls[0], "screen") == "screen"
    assert source is not None
    assert source.index("editor = ConfigV2EditingPanel(") < source.index(
        "self._config_v2_editor.close()"
    )


def test_recipe_profile_opens_builder_before_closing_the_previous_editor() -> None:
    method = _function(WORKBENCH_TREE, "_open_recipe_project_profile")
    source = ast.get_source_segment(WORKBENCH_PANEL.read_text(encoding="utf-8"), method)
    panel_calls = _calls(method, "ConfigV2EditingPanel")

    assert len(panel_calls) == 1
    assert _keyword(panel_calls[0], "screen") == "ConfigV2EditorScreen.BUILDER"
    assert source is not None
    assert source.index("editor = ConfigV2EditingPanel(") < source.index(
        "self._config_v2_editor.close()"
    )


def test_config_v2_save_refreshes_the_current_project_view_without_reloading() -> None:
    calls = _call_names(_method("_refresh_config_v2_project_view"))

    assert "update_cfg_select" in calls
    assert "get_project_runtime_snapshot" in calls
    assert "build_project_config_view" in calls
    assert "_apply_project_config_view" in calls
    assert "load_project" not in calls


def test_ida_ui_does_not_import_core_project_persistence() -> None:
    imported_modules = {
        node.module
        for node in ast.walk(TREE)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "d810.core.project_config_persistence" not in imported_modules
