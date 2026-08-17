from __future__ import annotations

import ast
import importlib
import sys
import types
from pathlib import Path

from d810.diagnostics.workbench_models import (
    DiagnosticField,
    DiagnosticRecord,
    DiagnosticViewKind,
)
from d810.ui.workbench_diagnostics_logic import project_record_rows


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
        "project_case_timeline",
        "filter_cleanup_candidate_paths",
    }.issubset(calls)


def test_panel_exposes_an_intent_based_cleaner_composer_and_navigation() -> None:
    source = PANEL.read_text(encoding="utf-8")
    calls = set().union(
        _calls(_method("_plan_cleanup")),
        _calls(_method("_jump_to_function")),
        _calls(_method("_jump_to_record")),
    )

    for action_id in (
        "delete_selected_snapshots",
        "keep_latest",
        "delete_selected_databases",
        "delete_all_closed_databases",
        "vacuum_selected_databases",
    ):
        assert action_id in source
    for retired in ("delete_all_snapshots", "older_than", "Unix timestamp"):
        assert retired not in source
    assert "self.cleanup_action_combo" in source
    assert "Preview cleanup plan" in source
    assert "checkpoint_checkbox" not in source
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
    assert "self.confirmation_controls" in source
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


def test_panel_publishes_graph_context_without_projecting_or_refiltering_it() -> None:
    source = PANEL.read_text(encoding="utf-8")
    load_source = _method_source("_load_records")
    refilter_source = _method_source("_refilter_records")

    assert "Open graph" in source
    for method_name in (
        "_open_graph",
        "_graph_context",
        "_publish_graph_context",
    ):
        assert _method(method_name)
    for call in (
        "self._graph_controller.open",
        "self._graph_controller.update_context",
        "self._graph_controller.select_record",
        "self._graph_controller.clear_for_unsupported_view",
        "self._graph_controller.close",
    ):
        assert call in source
    assert "project_diagnostic_graph" not in source
    assert "_publish_graph_context()" in load_source
    assert "_publish_graph_context" not in refilter_source


def test_panel_exposes_case_timeline_canary_comparison_and_protects_baseline_cleanup() -> (
    None
):
    source = PANEL.read_text(encoding="utf-8")
    load_source = _method_source("_load_records")
    cleanup_source = _method_source("_plan_cleanup")

    assert '"Deobfuscation case", "case"' in source
    assert "Compare selected run" in source
    assert "case_summary" in source
    assert "project_case_timeline" in load_source
    assert "filter_cleanup_candidate_paths" in cleanup_source


def test_case_record_opening_matches_both_stable_identity_and_ea_anchor() -> None:
    panel_module = importlib.import_module("d810.ui.workbench_diagnostics_panel")
    row_index = getattr(panel_module, "_case_record_row_index", None)
    assert callable(row_index), "case record selection must be headless-testable"
    rows = project_record_rows(
        (
            DiagnosticRecord(
                kind=DiagnosticViewKind.FACTS,
                source_table="deobfuscation_case",
                snapshot_id=7,
                ordinal=0,
                fields=(
                    DiagnosticField(
                        "finding",
                        "ir.branch_target:0x401020",
                        "ir.branch_target:0x401020",
                    ),
                ),
                warnings=(),
                anchor_ea=0x401020,
            ),
        )
    )

    assert row_index(rows, "ir.branch_target:0x401020", 0x401020) == 0
    assert row_index(rows, "ir.branch_target:0x401020", 0x401021) is None
    assert row_index(rows, "different:0x401020", 0x401020) is None

    open_source = _method_source("open_case_record")
    select_source = _method_source("_select_pending_case_record")
    assert "self._pending_case_record" in open_source
    assert 'findData("case")' in open_source
    assert "_case_record_row_index" in select_source
    assert "self.record_tree.setCurrentIndex" in select_source


def test_panel_exposes_a_persisted_diagnostics_capture_action_and_state() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_source = _method_source("__init__")
    create_source = _method_source("OnCreate")

    assert "diagnostics_capture_presentation" in source
    assert "self.capture_status_icon" in init_source
    assert "self.enable_capture_button" in init_source
    assert "self._render_capture_state" in source
    assert "self._toggle_capture" in source
    assert "Enable capture" not in create_source


def test_panel_imports_when_idalib_exposes_ida_kernwin_but_qt_is_headless(
    monkeypatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        types.SimpleNamespace(PluginForm=type("PluginForm", (), {})),
    )
    sys.modules.pop("d810.ui.workbench_diagnostics_panel", None)

    try:
        panel = importlib.import_module("d810.ui.workbench_diagnostics_panel")

        assert panel.IDA_AVAILABLE is True
    finally:
        sys.modules.pop("d810.ui.workbench_diagnostics_panel", None)


def test_panel_source_guards_qt_worker_declarations_with_gui_graphics_support() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert "QT_GRAPHICS_AVAILABLE" in source
    assert "if IDA_AVAILABLE and QT_GRAPHICS_AVAILABLE:" in source
