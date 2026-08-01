from __future__ import annotations

import ast
from pathlib import Path


PANEL = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "workbench_panel.py"


def _method_source(name: str) -> str:
    source = PANEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(PANEL))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DeobfuscationWorkbenchPanel":
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
