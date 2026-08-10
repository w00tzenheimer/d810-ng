"""Config-v2 live Hex-Rays hook activation bridge tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.cleanup_family_adapter import (
    SIMPLE_FLATTENING_CLEANUP_PASS_ID,
    SIMPLE_FLATTENING_CLEANUP_RULE,
)
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_v2_hook_bridge import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    STATE_MACHINE_UNFLATTENER_RULE,
    pipeline_v2_hook_activation,
    pipeline_v2_native_state_machine_configs,
)

_CONF_DIR = Path("src/d810/conf")


def _config_v2_project(name: str) -> ProjectConfiguration:
    canary = ProjectConfiguration.from_file(_CONF_DIR / f"{name}_config_v2_canary.json")
    additional_configuration = dict(canary.additional_configuration)
    additional_configuration["pipeline_v2_mode"] = "config-v2"
    return ProjectConfiguration(
        path=Path(f"{name}.runtime-config-v2.json"),
        description=canary.description,
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
        _CONF_DIR / "default_instruction_only.json"
    )

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is False
    assert activation.instruction_rules == ()
    assert activation.block_rules == ()


def test_constant_simplification_bundle_expands_to_private_live_stages():
    project = ProjectConfiguration(
        path=Path("constant-simplification.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "options": {"memory_policy": "strict"},
                }
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert activation.configured_pass_ids == ("constant-simplification",)
    assert [rule.name for rule in activation.instruction_rules] == [
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
    ]
    assert activation.instruction_rules[0].config == {
        "persist_global_const_annotations": True,
        "rva_guard": True,
    }
    assert [rule.name for rule in activation.block_rules] == [
        "ForwardConstantPropagationRule"
    ]


@pytest.mark.parametrize(
    ("conflict", "message"),
    [
        (
            {
                "pass_id": "forward-constant-propagation",
                "options": {},
            },
            "constant-simplification",
        ),
        (
            {
                "pass_id": "mba-simplify",
                "rules": {
                    "include": ["FoldReadonlyDataRule"],
                    "include_order": ["FoldReadonlyDataRule"],
                },
            },
            "unknown field: rules",
        ),
    ],
)
def test_constant_bundle_rejects_duplicate_or_former_constant_selection(
    conflict, message
):
    project = ProjectConfiguration(
        path=Path("constant-conflict.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "options": {"memory_policy": "strict"},
                },
                conflict,
            ],
        },
    )

    with pytest.raises(PipelineConfigError, match=message):
        pipeline_v2_hook_activation(project)


def test_default_instruction_only_bridge_derives_rules_from_pipeline_v2_only():
    project = _config_v2_project("default_instruction_only")

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is True
    assert activation.configured_pass_ids == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    )
    assert len(activation.instruction_rules) == 180
    assert activation.instruction_rules[0].name == "FoldReadonlyDataRule"
    assert activation.instruction_rules[1].name == "ConstantSubtreeFoldRule"
    assert all(
        rule.name != "CopiedLegacyInstructionRule"
        for rule in activation.instruction_rules
    )
    assert [rule.name for rule in activation.block_rules] == [
        "ForwardConstantPropagationRule",
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
    assert unflattener.config == {"min_state_constant": 16777216}


def test_state_cff_bridge_accepts_typed_direct_threshold_on_the_complete_spine():
    project = ProjectConfiguration(
        path=Path("typed-state-cff.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": pass_id,
                    "options": {"min_state_constant": 0x8000},
                }
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert activation.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert [rule.name for rule in activation.block_rules] == [
        STATE_MACHINE_UNFLATTENER_RULE
    ]
    assert activation.block_rules[0].config == {"min_state_constant": 0x8000}


def test_state_cff_bridge_maps_public_modes_only_at_the_private_hook_boundary():
    project = ProjectConfiguration(
        path=Path("typed-state-cff.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": pass_id,
                    "options": {
                        "min_state_constant": 0x8000,
                        "family": "tigress-indirect",
                        "recovery_strategy": "reduced-product",
                    },
                }
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert activation.block_rules[0].config == {
        "min_state_constant": 0x8000,
        "profile": "tigress_indirect",
        "recovery_engine": "reduced_product",
    }


def test_state_cff_bridge_rejects_disagreeing_typed_thresholds():
    project = ProjectConfiguration(
        path=Path("divergent-state-cff.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": pass_id,
                    "options": {
                        "min_state_constant": 0x8000 + index,
                    },
                }
                for index, pass_id in enumerate(STATE_MACHINE_NATIVE_PASS_IDS)
            ],
        },
    )

    with pytest.raises(PipelineConfigError, match="disagree"):
        pipeline_v2_hook_activation(project)


def test_ollvm_bridge_omits_legacy_materialized_computed_goto_island_rule():
    project = _config_v2_project("default_unflattening_ollvm")

    activation = pipeline_v2_hook_activation(project)

    assert "materialized-computed-goto-island" not in activation.configured_pass_ids
    assert all(
        rule.name != "MaterializedComputedGotoIslandRule"
        for rule in activation.block_rules
    )


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


def test_indirect_branch_call_bridge_derives_explicit_flow_rules():
    project = _config_v2_project("default_indirect_resolution")

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is True
    assert activation.configured_pass_ids == (
        "indirect-branch-resolver",
        "indirect-call-resolver",
    )
    assert activation.native_state_machine_pass_ids == ()
    assert activation.instruction_rules == ()
    assert [rule.name for rule in activation.block_rules] == [
        "IndirectBranchResolver",
        "IndirectCallResolver",
    ]
    assert [rule.config for rule in activation.block_rules] == [{}, {}]
    assert all(rule.name != "CopiedLegacyBlockRule" for rule in activation.block_rules)


def test_cleanup_family_bridge_derives_explicit_cleanup_rule():
    project = _config_v2_project("example_libobfuscated_no_fixprecedessor")

    activation = pipeline_v2_hook_activation(project)

    assert activation.enabled is True
    assert activation.configured_pass_ids == (
        "constant-simplification",
        "mba-simplify",
        SIMPLE_FLATTENING_CLEANUP_PASS_ID,
        "jump-fixer",
    )
    assert activation.native_state_machine_pass_ids == ()
    assert [rule.name for rule in activation.block_rules] == [
        "ForwardConstantPropagationRule",
        SIMPLE_FLATTENING_CLEANUP_RULE,
        "JumpFixer",
    ]
    assert activation.block_rules[1].config == {}
    assert all(rule.name != "CopiedLegacyBlockRule" for rule in activation.block_rules)


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
                    "pass_id": "block-level-egglog-optimizer",
                    "options": {},
                }
            ],
        },
    )

    with pytest.raises(PipelineConfigError, match="unsupported hook-transform pass id"):
        pipeline_v2_hook_activation(project)
