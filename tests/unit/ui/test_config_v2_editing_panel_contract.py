from __future__ import annotations

import ast
from pathlib import Path

PANEL = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_editing_panel.py"
)


def _tree() -> ast.Module:
    return ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))


def _method(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ClassDef) and node.name == "ConfigV2EditingPanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"ConfigV2EditingPanel.{name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def _source(name: str) -> str:
    return ast.unparse(_method(name))


def test_panel_projects_one_draft_into_a_stacked_builder_and_inspector() -> None:
    init_source = _source("__init__")
    create_source = _source("OnCreate")
    render_calls = _calls(_method("_render"))

    assert "ConfigV2EditorScreen.BUILDER" in init_source
    assert "self._screen = screen" in init_source
    assert "self._selected_pass_index" in init_source
    assert "self._editor_view" in init_source
    assert "QStackedWidget" in init_source
    assert "builder_page" in create_source
    assert "inspector_page" in create_source
    assert "project_config_v2_editor_view" in render_calls


def test_inspector_uses_structured_identity_options_and_contract_controls() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_calls = _calls(_method("__init__"))

    assert "StructuredDetailsView" in source
    assert "JsonTreeEditor" in source
    assert "RawJsonDialog" in source
    assert "Pass" in source
    assert "Purpose" in source
    assert "Runs during" in source
    assert "Scope" in source
    assert "Backend" in source
    assert "Safety" in source
    assert "QListWidget" in source
    assert "set_on_value_changed" in init_calls
    assert "View raw contract" in source
    assert "Edit raw options" in source
    assert "Edit pipeline..." in source


def test_inspector_transform_picker_is_projection_driven_and_fail_closed() -> None:
    render_source = _source("_render_inspector")

    assert "inspector.transforms_editable" in render_source
    assert "inspector.selected_transforms" in render_source
    assert "No individually selectable transforms." in render_source
    assert "stage_ids" not in render_source
    assert "transform_ids" not in render_source


def test_inspector_callbacks_delegate_typed_edits_and_rerender_rejections() -> None:
    transform_source = _source("_apply_selected_transforms")
    options_source = _source("_apply_inspector_options")
    apply_source = _source("_apply_edit")

    assert "set_pass_transforms" in transform_source
    assert "selected_transforms" in transform_source
    assert "set_pass_options" in options_source
    assert "isinstance(value, dict)" in options_source
    assert "self._render()" in apply_source


def test_screen_switches_preserve_the_current_draft_without_io() -> None:
    for method_name in ("_show_inspector", "_show_builder"):
        source = _source(method_name)
        calls = _calls(_method(method_name))

        assert "self._draft =" not in source
        assert not {"reset", "save", "load_view"} & calls
        assert "_render" in calls


def test_exact_focus_uses_the_requested_row_and_rejects_mismatches() -> None:
    source = _source("_apply_focus_target")

    assert "target.unambiguous" in source
    assert "target.pass_index" in source
    assert "inspector.pass_index" in source
    assert "inspector.pass_id == target.pass_id" in source
    assert "self._selected_pass_index = target.pass_index" in source


def test_panel_remains_a_thin_adapter_and_explicit_save_surface() -> None:
    imports = {
        node.module
        for node in ast.walk(_tree())
        if isinstance(node, ast.ImportFrom) and node.module
    }
    calls = set().union(
        *(
            _calls(_method(name))
            for name in (
                "_set_description",
                "_add_pass",
                "_remove_pass",
                "_move_pass",
                "_edit_routing",
                "_reset",
                "_validate",
                "_save_as",
                "_save",
            )
        )
    )

    assert "d810.ui.config_v2_editing_logic" in imports
    assert "d810.manager.config_v2_editing" not in imports
    assert "d810.core.project_config_persistence" not in imports
    assert {"retarget", "save", "validate"}.issubset(calls)
