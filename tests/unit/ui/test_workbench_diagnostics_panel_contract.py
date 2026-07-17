from __future__ import annotations

import ast
from pathlib import Path


PANEL = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "workbench_diagnostics_panel.py"
)


def _tree() -> ast.Module:
    return ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))


def _method(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ClassDef) and node.name == "WorkbenchDiagnosticsPanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"WorkbenchDiagnosticsPanel.{name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def _method_source(name: str) -> str:
    source = PANEL.read_text(encoding="utf-8")
    segment = ast.get_source_segment(source, _method(name))
    assert segment is not None
    return segment


def test_panel_is_thin_and_never_imports_sqlite_or_diagnostic_models() -> None:
    imports: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)

    assert "d810.ui.workbench_diagnostics_logic" in imports
    assert not any(name.startswith(("sqlite3", "d810.diagnostics")) for name in imports)


def test_panel_projects_inventory_records_actions_plans_and_results_through_logic() -> (
    None
):
    calls = set().union(
        _calls(_method("refresh")),
        _calls(_method("_inventory_ready")),
        _calls(_method("_apply_database_projection")),
        _calls(_method("_load_snapshots")),
        _calls(_method("_apply_snapshot_projection")),
        _calls(_method("_load_records")),
        _calls(_method("_apply_record_projection")),
        _calls(_method("_sort_database_rows")),
        _calls(_method("_sort_snapshot_rows")),
        _calls(_method("_render_action_states")),
        _calls(_method("_plan_cleanup")),
        _calls(_method("_execute_cleanup")),
    )

    assert {
        "sort_databases",
        "filter_databases",
        "sort_snapshots",
        "filter_snapshots",
        "filter_records",
        "project_record_rows",
        "diagnostic_action_states",
        "project_cleanup_plan",
        "cleanup_confirmation_matches",
        "project_cleanup_result",
    }.issubset(calls)


def test_panel_exposes_all_approved_cleaner_actions_and_navigation() -> None:
    source = PANEL.read_text(encoding="utf-8")
    calls = set().union(
        _calls(_method("_plan_cleanup")),
        _calls(_method("_jump_to_function")),
        _calls(_method("_jump_to_record")),
    )

    for action_id in (
        "delete_selected_snapshots",
        "delete_all_snapshots",
        "keep_latest",
        "older_than",
        "delete_selected_databases",
        "delete_all_closed_databases",
        "vacuum_selected_databases",
    ):
        assert action_id in source
    assert {"plan", "navigate", "record_jump_ea"}.issubset(calls)


def test_panel_uses_compact_group_layout_and_read_only_detail_views() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_calls = _calls(_method("__init__"))
    create_calls = _calls(_method("OnCreate"))

    assert "QGroupBox" in source
    assert "QFormLayout" in source
    assert "setReadOnly" in init_calls
    assert "setContentsMargins" in create_calls
    assert "setSpacing" in create_calls


def test_panel_uses_equal_outer_split_with_browser_and_cleaner_on_left() -> None:
    source = _method_source("OnCreate")

    assert "self._browser_splitter.addWidget(database_group)" in source
    assert "self._browser_splitter.addWidget(snapshot_group)" in source
    assert "self._left_splitter.addWidget(self._browser_splitter)" in source
    assert "self._left_splitter.addWidget(cleaner_group)" in source
    assert "self._outer_splitter.addWidget(self._left_splitter)" in source
    assert "self._outer_splitter.addWidget(record_group)" in source
    assert "self._outer_splitter.setStretchFactor(0, 1)" in source
    assert "self._outer_splitter.setStretchFactor(1, 1)" in source
    assert "_ignore_size_hint(self._left_splitter, horizontal=True)" in source
    assert "_ignore_size_hint(database_group, horizontal=True)" in source
    assert "_ignore_size_hint(snapshot_group, horizontal=True)" in source
    assert "_ignore_size_hint(cleaner_group, vertical=True)" in source
    assert "self._browser_splitter.setSizes([1_000, 1_000])" in source
    assert "self._left_splitter.setSizes([3_000, 2_000])" in source
    assert "self._outer_splitter.setSizes([1_000, 1_000])" in source
    assert "layout.addWidget(self._outer_splitter, stretch=1)" in source
    assert "confirmation_controls = QtWidgets.QGridLayout()" in source
    assert "self._plan_splitter" in source
    assert (
        "self._plan_splitter.setOrientation(QtCore.Qt.Orientation.Vertical)" in source
    )


def test_real_database_inventory_runs_off_the_ida_ui_thread() -> None:
    source = PANEL.read_text(encoding="utf-8")
    refresh_calls = _calls(_method("refresh"))

    assert "QRunnable" in source
    assert "QThreadPool" in source
    assert "databases" not in refresh_calls
    assert "start" in refresh_calls
