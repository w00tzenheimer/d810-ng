from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import select_config_v2_default_project
from d810.core.project_config_persistence import clone_project_configuration
from d810.manager.project_runtime import (
    ProjectConfigMode,
    RuleProjectionKind,
    build_project_runtime_snapshot,
)
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    build_project_config_view,
    select_config_edit_policy,
)


CONF_DIR = Path("src/d810/conf")
EXPECTED_PASS_IDS = (
    "mba-simplify",
    "materialized-computed-goto-island",
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


def test_ollvm_routing_view_and_lossless_user_duplicate(tmp_path: Path) -> None:
    source = ProjectConfiguration.from_file(
        CONF_DIR / "default_unflattening_ollvm.json"
    )
    selection = select_config_v2_default_project(source)
    assert selection is not None
    activation = pipeline_v2_hook_activation(selection.runtime_project)
    snapshot = build_project_runtime_snapshot(
        source_project=source,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=activation,
        hook_mode="config-v2",
    )
    view = build_project_config_view(snapshot)

    assert snapshot.source.basename == "default_unflattening_ollvm.json"
    assert snapshot.runtime.basename == (
        "default_unflattening_ollvm_config_v2_canary.json"
    )
    assert snapshot.routed is True
    assert snapshot.mode is ProjectConfigMode.CONFIG_V2
    assert snapshot.rule_projection is RuleProjectionKind.RUNTIME_EXPANSION
    assert snapshot.effective_pass_ids == EXPECTED_PASS_IDS
    assert len(snapshot.effective_instruction_rule_names) == 180
    assert len(snapshot.effective_block_rule_names) == 6
    assert view.mode_text == "Config v2 (routed)"
    assert view.effective_passes_text.startswith("11 passes: ")
    assert view.rules_title == "Rules (runtime expansion: 180 instruction, 6 block)"
    assert len(view.enabled_rule_names) == 186

    edit_policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    duplicate_policy = select_config_edit_policy(ConfigEditMode.DUPLICATE, snapshot)
    assert edit_policy.save_strategy is ConfigSaveStrategy.REFUSE
    assert duplicate_policy.save_strategy is ConfigSaveStrategy.CLONE_RUNTIME_V2
    assert duplicate_policy.rules_editable is False

    destination = tmp_path / "ollvm-user-copy.json"
    duplicate = clone_project_configuration(
        source=selection.runtime_project,
        destination=destination,
        description="OLLVM user copy",
    )
    expected_document = json.loads(
        selection.runtime_project.path.read_text(encoding="utf-8")
    )
    expected_document["description"] = "OLLVM user copy"
    assert json.loads(destination.read_text(encoding="utf-8")) == expected_document
    assert duplicate.additional_configuration == (
        selection.runtime_project.additional_configuration
    )
    assert select_config_v2_default_project(duplicate) is None

    duplicate_activation = pipeline_v2_hook_activation(duplicate)
    assert duplicate_activation.enabled is True
    assert duplicate_activation.configured_pass_ids == EXPECTED_PASS_IDS
    assert len(duplicate_activation.instruction_rules) == 180
    assert len(duplicate_activation.block_rules) == 6
