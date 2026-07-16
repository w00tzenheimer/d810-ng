from __future__ import annotations

import ast
import importlib.util
from pathlib import Path


PANEL = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "workbench_panel.py"


def test_workbench_panel_module_exists() -> None:
    assert importlib.util.find_spec("d810.ui.workbench_panel") is not None


def _tree() -> ast.Module:
    return ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))


def _method(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name != "DeobfuscationWorkbenchPanel":
            continue
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == name:
                return item
    raise AssertionError(f"DeobfuscationWorkbenchPanel.{name} not found")


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


def _assigned_attributes(method: ast.FunctionDef) -> set[str]:
    return {
        node.attr
        for node in ast.walk(method)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
    }


def test_panel_requests_immutable_snapshots_and_delegates_projection() -> None:
    calls = _call_names(_method("refresh"))

    assert "get_workbench_snapshot" in calls
    assert "project_workbench_rows" in calls
    assert "filter_workbench_rows" in calls
    assert "action_states" in calls
    assert "_render_rows" in calls


def test_set_function_retains_identity_and_refreshes() -> None:
    method = _method("set_function")

    assert {"_func_ea", "_func_name", "_fingerprint"}.issubset(
        _assigned_attributes(method)
    )
    assert "refresh" in _call_names(method)


def test_panel_accepts_command_adapter_and_dispatches_through_pure_freshness_logic() -> None:
    setter = _method("set_command_adapter")
    dispatch = _method("_run_command")
    calls = _call_names(dispatch)

    assert "_command_adapter" in _assigned_attributes(setter)
    assert "command_request" in calls
    assert "stale_snapshot" in calls
    assert "should_accept_command_result" in calls
    assert "project_workbench_rows" in calls
    assert "action_states" in calls
    assert "refresh" in calls


def test_panel_exposes_function_override_alongside_scoped_commands() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert '("function_override", "Function override")' in source
    assert 'self._run_command(action_id)' in source


def test_show_uses_persistent_dock_and_accepts_evidence_focus() -> None:
    method = _method("show")
    parameter_names = {argument.arg for argument in method.args.args}
    calls = _call_names(method)

    assert "focus_section" in parameter_names
    assert "Show" in calls
    assert "display_widget" in calls
    assert "set_dock_pos" in calls
    assert "_focus_section" in calls


def test_filter_and_selection_delegate_to_pure_logic() -> None:
    assert "filter_workbench_rows" in _call_names(_method("_on_filter_changed"))
    assert "detail_text" in _call_names(_method("_on_selection_changed"))


def test_export_delegates_payload_and_only_chooses_and_writes_path() -> None:
    calls = _call_names(_method("_export_evidence"))

    assert "export_evidence_json" in calls
    assert "getSaveFileName" in calls
    assert "write_text" in calls


def test_close_marks_panel_closed_and_disconnects_signals() -> None:
    method = _method("OnClose")

    assert "_closed" in _assigned_attributes(method)
    assert "disconnect" in _call_names(method)


def test_adapter_has_no_policy_storage_pass_or_sql_imports() -> None:
    imports: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)

    prohibited = (
        "sqlite3",
        "d810.core.persistence",
        "d810.diagnostics",
        "d810.passes",
        "d810.transforms",
        "d810.backends",
    )
    assert not any(name.startswith(prohibited) for name in imports)
    assert "d810.ui.workbench_logic" in imports
