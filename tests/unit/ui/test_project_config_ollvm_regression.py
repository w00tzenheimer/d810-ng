from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.manager.project_runtime import (
    clone_project,
    build_project_runtime_snapshot,
)
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    build_project_config_view,
    select_config_edit_policy,
)


CONF_DIR = Path("src/d810/conf")
EXPECTED_PASS_IDS = (
    "constant-simplification",
    "mba-simplify",
    "indirect-call-resolver",
    "mba-state-preconditioner",
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
    "simple-flattening-cleanup-unflattener",
    "jump-fixer",
)


def test_ollvm_project_view_and_lossless_user_duplicate(tmp_path: Path) -> None:
    project = ProjectConfiguration.from_file(
        CONF_DIR / "default_unflattening_ollvm.json"
    )
    schedule = compile_config_v2_hook_schedule(project)
    snapshot = build_project_runtime_snapshot(
        project=project,
        schedule=schedule,
    )
    view = build_project_config_view(snapshot)

    assert snapshot.project.basename == "default_unflattening_ollvm.json"
    assert snapshot.effective_pass_ids == EXPECTED_PASS_IDS
    assert view.mode_text == "Config v2"
    assert view.effective_passes_text.startswith("11 passes: ")
    assert view.pass_tree_title == "Pass pipeline (11 active)"
    assert view.effective_pass_ids == EXPECTED_PASS_IDS

    edit_policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    duplicate_policy = select_config_edit_policy(ConfigEditMode.DUPLICATE, snapshot)
    assert edit_policy.save_strategy is ConfigSaveStrategy.STRUCTURED_V2
    assert edit_policy.allowed is True
    assert duplicate_policy.save_strategy is ConfigSaveStrategy.STRUCTURED_V2

    destination = tmp_path / "ollvm-user-copy.json"
    duplicate = clone_project(
        project=project,
        destination=destination,
        description="OLLVM user copy",
    )
    expected_document = json.loads(
        project.path.read_text(encoding="utf-8")
    )
    expected_document["description"] = "OLLVM user copy"
    assert json.loads(destination.read_text(encoding="utf-8")) == expected_document
    assert duplicate.additional_configuration == (
        project.additional_configuration
    )

    duplicate_schedule = compile_config_v2_hook_schedule(duplicate)
    assert duplicate_schedule.configured_pass_ids == EXPECTED_PASS_IDS
    assert len(duplicate_schedule.instruction_bindings) == 180
    assert len(duplicate_schedule.block_bindings) == 6
