from __future__ import annotations

import ast
from pathlib import Path

import d810.ui.project_config_logic as project_config_logic
from d810.manager.project_runtime import (
    ProjectIdentitySnapshot,
    ProjectRuntimeSnapshot,
)
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    build_project_config_view,
    resolve_config_v2_focus_target,
    select_config_edit_policy,
)


def _snapshot(*, pass_ids: tuple[str, ...] = ("pass-a", "pass-b")) -> ProjectRuntimeSnapshot:
    return ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot(
            "project.json", Path("/configs/project.json"), "project"
        ),
        effective_pass_ids=pass_ids,
    )


def test_project_view_exposes_only_public_pass_identity() -> None:
    view = build_project_config_view(_snapshot())

    assert view.mode_text == "Config v2"
    assert view.effective_passes_text == "2 passes: pass-a, pass-b"
    assert view.pass_tree_title == "Pass pipeline (2 active)"
    assert view.effective_pass_ids == ("pass-a", "pass-b")
    assert view.edit_enabled is True


def test_project_view_has_one_identity() -> None:
    view = build_project_config_view(_snapshot())

    assert view.project_text == "project.json"
    assert view.project_tooltip == "/configs/project.json"
    assert view.header_summary_text == "Config v2 . 2 passes"


def test_config_v2_edits_use_the_structured_editor() -> None:
    for mode in (ConfigEditMode.EDIT, ConfigEditMode.DUPLICATE):
        policy = select_config_edit_policy(mode, _snapshot())
        assert policy.allowed is True
        assert policy.save_strategy is ConfigSaveStrategy.STRUCTURED_V2


def test_new_edits_are_refused_but_existing_project_edits_are_allowed() -> None:
    assert select_config_edit_policy(ConfigEditMode.NEW, None).allowed is False
    assert select_config_edit_policy(ConfigEditMode.EDIT, _snapshot()).allowed is True


def test_focus_target_uses_stable_pass_id_without_private_mapping() -> None:
    focus = resolve_config_v2_focus_target("pass-b", ("pass-a", "pass-b"))
    missing = resolve_config_v2_focus_target("missing", ("pass-a", "pass-b"))

    assert focus.unambiguous is True
    assert focus.pass_id == "pass-b"
    assert focus.pass_index == 1
    assert missing.pass_id is None
    assert missing.pass_index is None
    assert missing.unambiguous is False
    assert "not present" in missing.message


def test_focus_target_refuses_duplicate_pipeline_pass_without_row_index() -> None:
    target = resolve_config_v2_focus_target(
        "mba-simplify", ("mba-simplify", "mba-simplify")
    )

    assert target.pass_id is None
    assert target.pass_index is None
    assert target.unambiguous is False
    assert "more than once" in target.message


def test_focus_target_accepts_a_matching_explicit_row_index() -> None:
    target = resolve_config_v2_focus_target(
        "mba-simplify", ("other", "mba-simplify", "mba-simplify"), pass_index=1
    )

    assert target.pass_id == "mba-simplify"
    assert target.pass_index == 1
    assert target.unambiguous is True


def test_focus_target_refuses_an_index_for_another_pass() -> None:
    target = resolve_config_v2_focus_target(
        "mba-simplify", ("other", "mba-simplify"), pass_index=0
    )

    assert target.pass_id is None
    assert target.pass_index is None
    assert target.unambiguous is False
    assert "not present at pipeline row 0" in target.message


def test_logic_module_imports_no_ida_or_qt_modules() -> None:
    module_path = Path(project_config_logic.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])

    assert imported_roots.isdisjoint(
        {"idaapi", "ida_kernwin", "ida_hexrays", "PyQt5", "PySide6"}
    )
