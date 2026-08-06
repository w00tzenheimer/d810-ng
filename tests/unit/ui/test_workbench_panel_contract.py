from __future__ import annotations

import ast
import importlib
from pathlib import Path
from types import SimpleNamespace

from d810.manager.workbench_models import (
    OutcomeStatus,
    SnapshotFreshness,
    WorkbenchCommandResult,
)


PANEL = (
    Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "workbench_panel.py"
)


def _method_source(name: str) -> str:
    source = PANEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(PANEL))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ClassDef)
            and node.name == "DeobfuscationWorkbenchPanel"
        ):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    segment = ast.get_source_segment(source, item)
                    assert segment is not None
                    return segment
    raise AssertionError(f"DeobfuscationWorkbenchPanel.{name} not found")


def test_workbench_composes_diagnostics_graph_outside_the_adapter_boundary() -> None:
    source = _method_source("_show_diagnostics")

    assert "create_ida_diagnostic_graph_controller" in source
    assert "from d810.diagnostics" not in source
    assert "graph_controller=controller" in source
    assert "function_name=self._func_name or None" in source


def test_deobfuscate_function_refreshes_before_automatic_comparison() -> None:
    source = _method_source("_run_deobfuscate_function")

    assert 'self._run_command("deobfuscate", refresh_after=False)' in source
    assert "recommended_attack_transition(snapshot, result)" in source
    assert "self.refresh()" in source
    assert "self._run_comparison()" in source
    assert source.index("if transition.refresh:") < source.index("self.refresh()")
    assert source.index("self.refresh()") < source.index("if transition.compare:")
    assert source.index("if transition.compare:") < source.index(
        "self._run_comparison()"
    )


def test_deobfuscate_function_delegates_transition_to_pure_logic() -> None:
    source = _method_source("_run_deobfuscate_function")
    panel_source = PANEL.read_text(encoding="utf-8")

    assert "recommended_attack_transition" in panel_source
    assert "transition = recommended_attack_transition(snapshot, result)" in source
    assert "should_accept_command_result(snapshot, result)" not in source
    assert "result.refresh_requested" not in source


def test_case_panel_renders_the_pure_workflow_projection() -> None:
    panel_source = PANEL.read_text(encoding="utf-8")
    render_source = _method_source("_render_case_workflow")

    assert (
        "from d810.manager.deobfuscation_case_workflow import project_case_workflow"
        in panel_source
    )
    assert "view = project_case_workflow(" in render_source
    assert "self.case_headline.setText(view.headline)" in render_source
    assert "self.case_detail.setText(view.detail)" in render_source


def test_successful_fresh_build_opens_canvas_through_existing_recipe_adapter() -> None:
    source = _method_source("_run_build_deobfuscator")

    assert 'self._run_command("build_deobfuscator", refresh_after=True)' in source
    assert "_should_open_build_canvas(snapshot, result, current_snapshot)" in source
    assert "recipe(snapshot)" in source
    assert "self._show_build_canvas(recipe_adapter)" in source
    assert source.index("_should_open_build_canvas") < source.index(
        "self._show_build_canvas"
    )


def test_stale_status_never_opens_build_canvas_even_when_result_is_accepted() -> None:
    panel_module = importlib.import_module("d810.ui.workbench_panel")
    should_open = getattr(panel_module, "_should_open_build_canvas", None)
    assert callable(should_open), "Build canvas gate must be headless-testable"
    snapshot = SimpleNamespace(
        generation=7,
        function=SimpleNamespace(ea=0x401000, fingerprint="sha256:build"),
    )
    current_snapshot = SimpleNamespace(freshness=SnapshotFreshness.CURRENT)
    stale_result = WorkbenchCommandResult(
        command="build_deobfuscator",
        function_ea=0x401000,
        requested_generation=7,
        function_fingerprint="sha256:build",
        status=OutcomeStatus.STALE,
        succeeded=True,
        accepted=True,
        refresh_requested=True,
        message="stale",
    )

    assert should_open(snapshot, stale_result, current_snapshot) is False


def test_build_canvas_reuses_one_panel_and_recipe_composer_save_callback() -> None:
    panel_source = PANEL.read_text(encoding="utf-8")
    source = _method_source("_show_build_canvas")

    assert "self._build_canvas_panel" in panel_source
    assert "WorkbenchCanvasPanel" in source
    assert "self._snapshot" in source
    assert "refresh_workbench=self.refresh" in source
    assert "_canvas_panel_can_reuse(panel)" in source
    assert "set_session" in source
    assert "panel.show()" in source


def test_closed_build_canvas_is_replaced_instead_of_reused() -> None:
    panel_module = importlib.import_module("d810.ui.workbench_panel")
    can_reuse = getattr(panel_module, "_canvas_panel_can_reuse", None)
    assert callable(can_reuse), "canvas reuse decision must be headless-testable"

    assert can_reuse(None) is False
    assert can_reuse(SimpleNamespace(closed=True)) is False
    assert can_reuse(SimpleNamespace(closed=False)) is True


def test_build_canvas_injects_existing_diagnostics_explorer_record_path() -> None:
    build_source = _method_source("_show_build_canvas")
    open_source = _method_source("_open_diagnostic_record")

    assert "open_diagnostic_record=self._open_diagnostic_record" in build_source
    assert "WorkbenchDiagnosticsAdapter" in open_source
    assert "self._show_diagnostics(adapter)" in open_source
    assert "panel.open_case_record(finding_id, native_ea)" in open_source


def test_context_and_workflow_summary_use_left_aligned_layout_policy() -> None:
    source = _method_source("OnCreate")

    assert "configure_left_aligned_form(context_layout)" in source
    assert "configure_left_aligned_form(case_summary)" in source
