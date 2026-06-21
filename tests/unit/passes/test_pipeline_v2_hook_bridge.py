"""Config-v2 live Hex-Rays hook activation bridge tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_v2_hook_bridge import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    STATE_MACHINE_UNFLATTENER_RULE,
    pipeline_v2_hook_activation,
    pipeline_v2_native_state_machine_configs,
)

_CONF_DIR = Path("src/d810/conf")


def _config_v2_project(name: str) -> ProjectConfiguration:
    shadow = ProjectConfiguration.from_file(_CONF_DIR / f"{name}.pipeline_v2.json")
    additional_configuration = dict(shadow.additional_configuration)
    additional_configuration["pipeline_v2_mode"] = "config-v2"
    return ProjectConfiguration(
        path=Path(f"{name}.runtime-config-v2.json"),
        description=shadow.description,
        ins_rules=[
            RuleConfiguration(
                name="CopiedLegacyInstructionRule",
                is_activated=True,
                config={"must_not": "leak"},
            )
        ],
        blk_rules=[
            RuleConfiguration(
                name="CopiedLegacyBlockRule",
                is_activated=True,
                config={"must_not": "leak"},
            )
        ],
        additional_configuration=additional_configuration,
    )


def test_pipeline_v2_hook_activation_is_inert_for_legacy_mode():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only.pipeline_v2.json"
    )

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is False
    assert activation.instruction_rules == ()
    assert activation.block_rules == ()


def test_default_instruction_only_bridge_derives_rules_from_pipeline_v2_only():
    project = _config_v2_project("default_instruction_only")

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is True
    assert activation.configured_pass_ids == (
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    )
    assert len(activation.instruction_rules) == 179
    assert activation.instruction_rules[0].name == "FoldReadonlyDataRule"
    assert all(
        rule.name != "CopiedLegacyInstructionRule"
        for rule in activation.instruction_rules
    )
    assert [rule.name for rule in activation.block_rules] == [
        "GlobalConstantInliner",
        "JumpFixer",
    ]
    assert all(rule.name != "CopiedLegacyBlockRule" for rule in activation.block_rules)
    jump_fixer = activation.block_rules[-1]
    assert "enabled_rules" in jump_fixer.config


def test_hodur_bridge_derives_unflattener_trigger_and_simple_flow_rule():
    project = _config_v2_project("hodur_flag2")

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is True
    assert activation.configured_pass_ids == (
        *STATE_MACHINE_NATIVE_PASS_IDS,
        "jump-fixer",
    )
    assert activation.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert activation.instruction_rules == ()
    assert [rule.name for rule in activation.block_rules] == [
        STATE_MACHINE_UNFLATTENER_RULE,
        "JumpFixer",
    ]
    unflattener = activation.block_rules[0]
    assert unflattener.config["max_state_constants"] == 100
    assert unflattener.config["min_state_constant"] == 16777216
    assert unflattener.config["enable_transition_validator"] is True
    assert unflattener.config["enable_transition_uddu_validator"] is True


def test_identity_call_bridge_derives_explicit_opt_in_rule_config():
    project = _config_v2_project("identity_call")

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is True
    assert activation.configured_pass_ids == ("identity-call-resolver",)
    assert activation.native_state_machine_pass_ids == ()
    assert activation.instruction_rules == ()
    assert [rule.name for rule in activation.block_rules] == ["IdentityCallResolver"]
    assert activation.block_rules[0].config == {
        "enable_experimental": True,
        "max_trampoline_depth": 32,
        "max_search_instructions": 30,
    }


def test_native_state_machine_config_filter_excludes_live_hook_passes():
    project = _config_v2_project("hodur_flag2")

    configs = pipeline_v2_native_state_machine_configs(project)

    assert [config.pass_id for config in configs] == list(STATE_MACHINE_NATIVE_PASS_IDS)


def test_state_machine_native_spine_rejects_partial_sequence():
    project = _config_v2_project("hodur_flag2")
    payload = list(project.additional_configuration["pipeline_v2"])
    project.additional_configuration["pipeline_v2"] = payload[:-2]

    with pytest.raises(PipelineConfigError, match="complete native pass sequence"):
        pipeline_v2_hook_activation(project)


def test_unsupported_non_spine_pass_fails_closed():
    project = ProjectConfiguration(
        path=Path("unsupported.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass": "block-level-egglog-optimizer",
                    "options": {"legacy_rule": "BlockLevelEgglogOptimizer"},
                }
            ],
        },
    )

    with pytest.raises(PipelineConfigError, match="unsupported legacy flow-rule"):
        pipeline_v2_hook_activation(project)
