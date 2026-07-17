from __future__ import annotations

import ast
from pathlib import Path


IDA_UI = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "ida_ui.py"
TREE = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))


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


def test_load_config_reads_manager_snapshot_and_pure_view() -> None:
    calls = _call_names(_method("_load_config"))

    assert "get_project_runtime_snapshot" in calls
    assert "build_project_config_view" in calls
    assert "_apply_project_config_view" in calls


def test_form_uses_picker_without_loading_a_filtered_row_index() -> None:
    calls = _call_names(_method("_open_config_picker"))

    assert "ProjectPickerDialog" in calls
    assert "build_project_picker_entries" in calls
    assert "selected_project_index" in calls
    assert "_load_config" in calls


def test_save_rules_delegates_to_edit_policy_and_manager_commands() -> None:
    calls = _call_names(_method("_save_rules"))

    assert "select_config_edit_policy" in calls
    assert "clone_current_runtime_project" in calls
    assert "save_legacy_project" in calls


def test_save_rules_no_longer_constructs_project_configuration_directly() -> None:
    calls = _call_names(_method("_save_rules"))

    assert "ProjectConfiguration" not in calls


def test_edit_and_duplicate_handlers_use_the_pure_policy() -> None:
    assert "select_config_edit_policy" in _call_names(_method("_edit_config"))
    assert "select_config_edit_policy" in _call_names(_method("_duplicate_config"))
    assert "_open_config_v2_editor" in _call_names(_method("_edit_config"))
    assert "_open_config_v2_editor" in _call_names(_method("_duplicate_config"))


def test_config_v2_editor_is_owned_and_uses_thin_command_adapter() -> None:
    calls = _call_names(_method("_open_config_v2_editor"))

    assert "ConfigV2EditingAdapter" in calls
    assert "ConfigV2EditingPanel" in calls
    assert "show" in calls


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
