from __future__ import annotations

import ast
from pathlib import Path


PANEL = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "workbench_recipe_panel.py"
)


def _tree() -> ast.Module:
    return ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))


def _method(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ClassDef) and node.name == "WorkbenchRecipePanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"WorkbenchRecipePanel.{name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def test_recipe_panel_is_thin_and_imports_only_pure_recipe_projection() -> None:
    imports: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)

    assert "d810.ui.workbench_recipe_logic" in imports
    prohibited = (
        "sqlite3",
        "d810.core.persistence",
        "d810.passes",
        "d810.transforms",
        "d810.backends",
    )
    assert not any(name.startswith(prohibited) for name in imports)


def test_recipe_panel_projects_catalog_draft_and_action_states_through_pure_logic() -> (
    None
):
    calls = _calls(_method("_render"))

    assert "project_catalog_rows" in calls
    assert "project_draft_rows" in calls
    assert "project_recipe_strategy" in calls
    assert "recipe_action_states" in calls


def test_recipe_panel_groups_catalog_rows_by_display_only_workflow_stage() -> None:
    source = ast.unparse(_method("_render_catalog"))

    assert "workflow_stage" in source
    assert "stage_items" in source


def test_recipe_panel_forwards_all_draft_operations_to_command_adapter() -> None:
    expected = {
        "add_pass",
        "remove_pass",
        "set_enabled",
        "reorder_pass",
        "replace_options",
        "reset",
        "analyze",
        "apply_once",
        "save_function",
    }
    calls = set().union(
        *(
            _calls(_method(name))
            for name in (
                "_add_pass",
                "_remove_pass",
                "_toggle_pass",
                "_move_pass",
                "_edit_options",
                "_reset",
                "_analyze",
                "_apply_once",
                "_save_function",
            )
        )
    )

    assert expected.issubset(calls)


def test_project_profile_save_dispatches_to_owned_config_v2_editor_callback() -> None:
    source = PANEL.read_text(encoding="utf-8")
    calls = _calls(_method("_save_project"))

    assert "save_project" in source
    assert "_open_project_profile" in calls
