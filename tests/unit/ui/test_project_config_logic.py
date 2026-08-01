from __future__ import annotations

import ast
from pathlib import Path

import pytest

import d810.ui.project_config_logic as project_config_logic
from d810.manager.project_runtime import (
    ProjectConfigMode,
    ProjectIdentitySnapshot,
    ProjectRuntimeSnapshot,
    RuleProjectionKind,
)
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    build_project_config_view,
    select_config_edit_policy,
)


def _snapshot(
    *,
    mode: ProjectConfigMode,
    routed: bool,
) -> ProjectRuntimeSnapshot:
    source = ProjectIdentitySnapshot(
        basename="source.json",
        path=Path("/configs/source.json"),
        description="source",
    )
    runtime = ProjectIdentitySnapshot(
        basename="runtime.json" if routed else "source.json",
        path=Path("/configs/runtime.json" if routed else "/configs/source.json"),
        description="runtime" if routed else "source",
    )
    if mode is ProjectConfigMode.CONFIG_V2:
        return ProjectRuntimeSnapshot(
            source=source,
            runtime=runtime,
            mode=mode,
            routed=routed,
            hook_mode="config-v2",
            effective_pass_ids=("pass-a", "pass-b"),
            effective_instruction_rule_names=("InsA", "InsB"),
            effective_block_rule_names=("BlkA",),
            rule_projection=RuleProjectionKind.RUNTIME_EXPANSION,
        )
    return ProjectRuntimeSnapshot(
        source=source,
        runtime=runtime,
        mode=mode,
        routed=False,
        hook_mode=None,
        effective_pass_ids=(),
        effective_instruction_rule_names=("LegacyIns",),
        effective_block_rule_names=("LegacyBlk",),
        rule_projection=RuleProjectionKind.SOURCE_POLICY,
    )


def test_routed_v2_view_shows_both_identities_runtime_rules_and_passes() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True)
    )

    assert view.mode_text == "Config v2 (routed)"
    assert view.source_text == "source.json"
    assert view.runtime_text == "runtime.json"
    assert view.source_tooltip == "/configs/source.json"
    assert view.runtime_tooltip == "/configs/runtime.json"
    assert view.effective_passes_text == "2 passes: pass-a, pass-b"
    assert view.rules_title == "Rules (runtime expansion: 2 instruction, 1 block)"
    assert view.enabled_rule_names == frozenset({"InsA", "InsB", "BlkA"})
    assert view.edit_enabled is True


def test_direct_v2_view_marks_config_v2_without_routed_suffix() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=False)
    )

    assert view.mode_text == "Config v2"
    assert view.source_text == view.runtime_text == "source.json"
    assert view.source_tooltip == view.runtime_tooltip == "/configs/source.json"


def test_legacy_view_marks_source_policy_and_no_effective_pass_manifest() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.LEGACY, routed=False)
    )

    assert view.mode_text == "Legacy"
    assert view.effective_passes_text == "Legacy rule policy"
    assert view.rules_title == "Rules (source policy: 1 instruction, 1 block)"
    assert view.edit_enabled is True


def test_new_config_uses_editable_legacy_strategy() -> None:
    policy = select_config_edit_policy(ConfigEditMode.NEW, None)

    assert policy.allowed is True
    assert policy.rules_editable is True
    assert policy.save_strategy is ConfigSaveStrategy.CREATE_LEGACY


@pytest.mark.parametrize("mode", [ConfigEditMode.EDIT, ConfigEditMode.DUPLICATE])
def test_legacy_edit_and_duplicate_allow_rule_editing(mode: ConfigEditMode) -> None:
    policy = select_config_edit_policy(
        mode,
        _snapshot(mode=ProjectConfigMode.LEGACY, routed=False),
    )

    assert policy.allowed is True
    assert policy.rules_editable is True
    assert policy.save_strategy is ConfigSaveStrategy.SAVE_LEGACY_COPY


def test_config_v2_edit_uses_structured_lossless_editor() -> None:
    policy = select_config_edit_policy(
        ConfigEditMode.EDIT,
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True),
    )

    assert policy.allowed is True
    assert policy.rules_editable is False
    assert policy.save_strategy is ConfigSaveStrategy.STRUCTURED_V2
    assert "structured" in policy.explanation


def test_config_v2_duplicate_uses_structured_runtime_copy() -> None:
    policy = select_config_edit_policy(
        ConfigEditMode.DUPLICATE,
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True),
    )

    assert policy.allowed is True
    assert policy.rules_editable is False
    assert policy.save_strategy is ConfigSaveStrategy.STRUCTURED_V2
    assert "effective runtime" in policy.explanation


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
    assert "qt_shim" not in module_path.read_text(encoding="utf-8")
