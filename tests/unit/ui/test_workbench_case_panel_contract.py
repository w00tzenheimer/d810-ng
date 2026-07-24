from __future__ import annotations

import ast
from pathlib import Path


PANEL = (
    Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "workbench_panel.py"
)
CASE_WORKFLOW = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "manager"
    / "deobfuscation_case_workflow.py"
)


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


def test_panel_renders_case_workflow_from_pure_manager_logic() -> None:
    source = _method_source("_render_case_workflow")

    assert "project_case_workflow" in source
    assert "self.build_deobfuscator_button.setText(view.build.label)" in source
    assert "self.deobfuscate_function_button.setText(view.direct.label)" in source
    assert "snapshot.case" not in source


def test_build_deobfuscator_runs_through_the_existing_command_dispatcher() -> None:
    source = _method_source("_run_build_deobfuscator")

    assert 'self._run_command("build_deobfuscator", refresh_after=True)' in source


def test_deobfuscate_function_preserves_refresh_before_comparison() -> None:
    source = _method_source("_run_deobfuscate_function")

    assert 'self._run_command("deobfuscate", refresh_after=False)' in source
    assert "recommended_attack_transition(snapshot, result)" in source
    assert source.index("if transition.refresh:") < source.index("self.refresh()")
    assert source.index("self.refresh()") < source.index("if transition.compare:")
    assert source.index("if transition.compare:") < source.index(
        "self._run_comparison()"
    )


def test_workbench_uses_algorithm_entry_point_labels() -> None:
    source = CASE_WORKFLOW.read_text(encoding="utf-8")

    assert "Build Deobfuscator" in source
    assert "Deobfuscate Function" in source
    assert "Deobfuscate this function" not in source
