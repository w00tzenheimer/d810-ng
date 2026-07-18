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


def test_recommended_attack_refreshes_before_automatic_comparison() -> None:
    source = _method_source("_run_recommended_attack")

    assert 'self._run_command("deobfuscate", refresh_after=False)' in source
    assert "self.refresh()" in source
    assert "self._run_comparison()" in source
    assert source.index("self.refresh()") < source.index("self._run_comparison()")


def test_accepted_nonrefresh_direct_result_refreshes_without_comparison() -> None:
    source = _method_source("_run_recommended_attack")

    accepted_result_branch = source.split("if (", 1)[1].split("self._render_workflow()", 1)[0]
    assert "should_accept_command_result(snapshot, result)" in accepted_result_branch
    assert "result.refresh_requested" not in accepted_result_branch.split(
        "self.refresh()", 1
    )[0]
    assert "if result.refresh_requested:" in accepted_result_branch
    assert accepted_result_branch.index("self.refresh()") < accepted_result_branch.index(
        "if result.refresh_requested:"
    ) < accepted_result_branch.index("self._run_comparison()")


def test_attack_card_renders_the_pure_workflow_projection() -> None:
    panel_source = PANEL.read_text(encoding="utf-8")
    render_source = _method_source("_render_workflow")

    assert (
        "from d810.ui.workbench_workflow_logic import project_workbench_workflow"
        in panel_source
    )
    assert "view = project_workbench_workflow(" in render_source
    assert "self.workflow_headline.setText(view.headline)" in render_source
    assert "self.workflow_detail.setText(view.detail)" in render_source
