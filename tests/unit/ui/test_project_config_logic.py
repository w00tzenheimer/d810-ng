from __future__ import annotations

import ast
from pathlib import Path

import pytest

import d810.ui.project_config_logic as project_config_logic
from d810.manager.project_runtime import (
    ProjectConfigMode,
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


def _snapshot(*, mode: ProjectConfigMode, routed: bool) -> ProjectRuntimeSnapshot:
    source = ProjectIdentitySnapshot(
        "source.json", Path("/configs/source.json"), "source"
    )
    runtime = ProjectIdentitySnapshot(
        "runtime.json" if routed else "source.json",
        Path("/configs/runtime.json" if routed else "/configs/source.json"),
        "runtime",
    )
    return ProjectRuntimeSnapshot(
        source=source,
        runtime=runtime,
        mode=mode,
        routed=routed,
        hook_mode="config-v2" if mode is ProjectConfigMode.CONFIG_V2 else None,
        effective_pass_ids=("pass-a", "pass-b")
        if mode is ProjectConfigMode.CONFIG_V2
        else (),
    )


def test_routed_v2_view_exposes_only_public_pass_identity() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True)
    )

    assert view.mode_text == "Config v2 (routed)"
    assert view.effective_passes_text == "2 passes: pass-a, pass-b"
    assert view.pass_tree_title == "Pass pipeline (2 active)"
    assert view.effective_pass_ids == ("pass-a", "pass-b")
    assert view.edit_enabled is True


def test_routed_v2_view_reports_divergent_source_and_runtime_identity() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True)
    )

    assert view.identity_is_divergent is True
    assert view.header_summary_text == "Config v2 (routed) . 2 passes"


def test_unrouted_v2_view_reports_agreeing_identity() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=False)
    )

    assert view.identity_is_divergent is False
    assert view.header_summary_text == "Config v2 . 2 passes"


def test_project_without_a_pipeline_summarizes_mode_alone() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.LEGACY, routed=False)
    )

    assert view.header_summary_text == "Unsupported project format"


def test_non_v2_project_is_visible_but_not_editable() -> None:
    snapshot = _snapshot(mode=ProjectConfigMode.LEGACY, routed=False)
    view = build_project_config_view(snapshot)

    assert view.mode_text == "Unsupported project format"
    assert view.effective_pass_ids == ()
    assert view.edit_enabled is False
    assert "strict project editor" in view.edit_tooltip


@pytest.mark.parametrize("mode", (ConfigEditMode.EDIT, ConfigEditMode.DUPLICATE))
def test_config_v2_edits_use_the_structured_editor(mode: ConfigEditMode) -> None:
    policy = select_config_edit_policy(
        mode,
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True),
    )

    assert policy.allowed is True
    assert policy.save_strategy is ConfigSaveStrategy.STRUCTURED_V2


def test_new_and_non_v2_edits_are_refused() -> None:
    assert select_config_edit_policy(ConfigEditMode.NEW, None).allowed is False
    assert (
        select_config_edit_policy(
            ConfigEditMode.EDIT,
            _snapshot(mode=ProjectConfigMode.LEGACY, routed=False),
        ).save_strategy
        is ConfigSaveStrategy.REFUSE
    )


def test_focus_target_uses_stable_pass_id_without_private_mapping() -> None:
    focus = resolve_config_v2_focus_target("pass-b", ("pass-a", "pass-b"))
    missing = resolve_config_v2_focus_target("missing", ("pass-a", "pass-b"))

    assert focus.unambiguous is True
    assert focus.pass_id == "pass-b"
    assert focus.pass_index == 1
    assert missing.unambiguous is False


def test_focus_target_refuses_duplicate_pipeline_pass_without_row_index() -> None:
    target = resolve_config_v2_focus_target(
        "mba-simplify", ("mba-simplify", "mba-simplify")
    )

    assert target.pass_index is None
    assert target.unambiguous is False


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

    assert target.pass_index is None
    assert target.unambiguous is False


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
