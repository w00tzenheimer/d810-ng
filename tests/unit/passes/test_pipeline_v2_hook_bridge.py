"""Config-v2 live Hex-Rays hook activation bridge tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.ir.maturity import IRMaturity
from d810.passes.cleanup_family_adapter import (
    SIMPLE_FLATTENING_CLEANUP_PASS_ID,
    SIMPLE_FLATTENING_CLEANUP_RULE,
)
from d810.passes.mba_simplify import (
    build_mba_simplify_pass,
    materialize_mba_transform_options,
)
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_v2_hook_bridge import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    STATE_MACHINE_UNFLATTENER_RULE,
    PipelineV2HookActivation,
    pipeline_v2_hook_activation,
    pipeline_v2_native_state_machine_configs,
    requires_native_preanalysis_handlers,
)
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config

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
        "maturities": [
            "MMAT_PREOPTIMIZED",
            "MMAT_LOCOPT",
            "MMAT_CALLS",
            "MMAT_GLBOPT1",
            "MMAT_GLBOPT3",
        ],
        "memory_policy": "strict",
        "rva_guard": True,
        "allow_executable_readonly": False,
    }
    assert activation.global_const_persistence_enabled is False
    assert [rule.name for rule in activation.block_rules] == [
        "ForwardConstantPropagationRule",
    ]
    assert activation.block_rules[0].config == {
        "maturities": [
            "MMAT_CALLS",
            "MMAT_GLBOPT1",
            "MMAT_GLBOPT2",
            "MMAT_GLBOPT3",
        ],
    }


def test_constant_bundle_keeps_memory_policy_as_provenance_and_maps_aggressive_flag():
    project = ProjectConfiguration(
        path=Path("constant-aggressive.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "options": {"memory_policy": "aggressive_no_direct_writes"},
                }
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    readonly_config = activation.instruction_rules[0].config
    assert readonly_config["memory_policy"] == "aggressive_no_direct_writes"
    assert readonly_config["fold_writable_constants"] is True
    assert set(readonly_config) == {
        "maturities",
        "memory_policy",
        "rva_guard",
        "allow_executable_readonly",
        "fold_writable_constants",
    }


def test_constant_simplification_projects_enabled_const_persistence() -> None:
    project = ProjectConfiguration(
        path=Path("constant-persistence.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "options": {
                        "memory_policy": "strict",
                        "persist_global_const_annotations": True,
                    },
                }
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert activation.global_const_persistence_enabled is True
    assert "persist_global_const_annotations" not in activation.instruction_rules[0].config


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


def test_generic_z3_bridge_materializes_defaults_per_selected_transform() -> None:
    project = ProjectConfiguration(
        path=Path("z3-predicate-bounds.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "mba-simplify",
                    "options": {
                        "transforms": [
                            "z-3-setz-generic",
                            "z-3-setnz-generic",
                            "z-3-lnot-generic",
                        ],
                        "transform_options": {
                            "z-3-setz-generic": {
                                "max_expression_nodes": 7,
                            },
                            "z-3-setnz-generic": {
                                "proof_timeout_ms": 125,
                            },
                        },
                    },
                }
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert [rule.name for rule in activation.instruction_rules] == [
        "Z3setzRuleGeneric",
        "Z3setnzRuleGeneric",
        "Z3lnotRuleGeneric",
    ]
    by_name = {rule.name: rule.config for rule in activation.instruction_rules}
    assert by_name["Z3setzRuleGeneric"]["max_expression_nodes"] == 7
    assert by_name["Z3setzRuleGeneric"]["proof_timeout_ms"] == 50
    assert by_name["Z3setnzRuleGeneric"]["max_expression_nodes"] == 256
    assert by_name["Z3setnzRuleGeneric"]["proof_timeout_ms"] == 125
    assert by_name["Z3lnotRuleGeneric"] == {
        "max_expression_nodes": 256,
        "proof_timeout_ms": 50,
        "generate_commutative_permutations": True,
    }

    mba_config = next(
        config
        for config in pipeline_configs_from_project_config(project)
        if config.pass_id == "mba-simplify"
    )
    adapter = build_mba_simplify_pass(mba_config)
    for transform_id, implementation_name in zip(
        adapter.transform_ids,
        adapter.implementation_names,
        strict=True,
    ):
        request_options = materialize_mba_transform_options(
            transform_id,
            adapter.transform_options.get(transform_id),
        )
        live_options = {
            field_name: by_name[implementation_name][field_name]
            for field_name in request_options
        }
        assert live_options == request_options


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


def test_state_machine_plus_constant_bundle_schedules_one_late_flow_fold():
    project = ProjectConfiguration(
        path=Path("state-machine-constant.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                *(
                    {"pass_id": pass_id, "options": {}}
                    for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
                ),
                {
                    "pass_id": "constant-simplification",
                    "options": {"memory_policy": "strict"},
                },
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert [rule.name for rule in activation.block_rules] == [
        STATE_MACHINE_UNFLATTENER_RULE,
        "ForwardConstantPropagationRule",
    ]
    assert activation.block_rules[1].config == {
        "maturities": ["MMAT_GLBOPT2"],
        "cython_enabled": False,
    }
    assert activation.constant_simplification_schedule is not None
    forward = activation.constant_simplification_schedule.stage("forward-constants")
    assert forward.requested_maturities == (
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_OPTIMIZED,
        IRMaturity.STRUCTURED,
    )
    assert forward.effective_maturities == (IRMaturity.GLOBAL_OPTIMIZED,)


def test_state_machine_constant_bundle_rejects_forward_without_safe_window() -> None:
    project = ProjectConfiguration(
        path=Path("state-machine-unsafe-forward.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                *(
                    {"pass_id": pass_id, "options": {}}
                    for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
                ),
                {
                    "pass_id": "constant-simplification",
                    "options": {
                        "stages": {
                            "forward-constants": {
                                "enabled": True,
                                "maturities": ["CALL_MODELED"],
                            }
                        }
                    },
                },
            ],
        },
    )

    with pytest.raises(PipelineConfigError, match="include GLOBAL_OPTIMIZED"):
        pipeline_v2_hook_activation(project)


def test_state_machine_constant_bundle_allows_disabled_forward_stage() -> None:
    project = ProjectConfiguration(
        path=Path("state-machine-disabled-forward.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                *(
                    {"pass_id": pass_id, "options": {}}
                    for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
                ),
                {
                    "pass_id": "constant-simplification",
                    "options": {
                        "stages": {"forward-constants": {"enabled": False}}
                    },
                },
            ],
        },
    )

    activation = pipeline_v2_hook_activation(project)

    assert [rule.name for rule in activation.block_rules] == [
        STATE_MACHINE_UNFLATTENER_RULE
    ]
    assert activation.constant_simplification_schedule is not None
    assert not activation.constant_simplification_schedule.stage(
        "forward-constants"
    ).enabled


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


def test_config_v2_native_state_machine_activation_requires_restart_consumer() -> None:
    """The complete native spine needs the flowchart handler that consumes redo."""
    assert requires_native_preanalysis_handlers(
        PipelineV2HookActivation(
            enabled=True,
            native_state_machine_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
        )
    )
    assert not requires_native_preanalysis_handlers(
        PipelineV2HookActivation(enabled=True)
    )
    assert not requires_native_preanalysis_handlers(
        PipelineV2HookActivation(
            enabled=False,
            native_state_machine_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
        )
    )


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


def _constant_stage_project(
    *,
    readonly_enabled: bool,
    subtree_enabled: bool,
    forward_enabled: bool,
    options: dict[str, object] | None = None,
    maturity_gates: list[str] | None = None,
) -> ProjectConfiguration:
    stage_options: dict[str, object] = {
        "fold-readonly-data": {"enabled": readonly_enabled},
        "fold-constant-subtree": {"enabled": subtree_enabled},
        "forward-constants": {"enabled": forward_enabled},
    }
    if options:
        stage_options.update(options)
    return ProjectConfiguration(
        path=Path("constant-stages.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "maturity_gates": maturity_gates
                    or [
                        "CANONICAL",
                        "LOCAL_OPTIMIZED",
                        "CALL_MODELED",
                        "GLOBAL_ANALYZED",
                        "GLOBAL_OPTIMIZED",
                        "STRUCTURED",
                    ],
                    "options": {
                        "stages": stage_options,
                    },
                }
            ],
        },
    )


@pytest.mark.parametrize(
    ("readonly", "subtree", "forward"),
    [
        (readonly, subtree, forward)
        for readonly in (False, True)
        for subtree in (False, True)
        for forward in (False, True)
    ],
)
def test_constant_stage_activation_emits_only_enabled_rules(
    readonly: bool,
    subtree: bool,
    forward: bool,
) -> None:
    activation = pipeline_v2_hook_activation(
        _constant_stage_project(
            readonly_enabled=readonly,
            subtree_enabled=subtree,
            forward_enabled=forward,
        )
    )

    assert [rule.name for rule in activation.instruction_rules] == [
        name
        for enabled, name in (
            (readonly, "FoldReadonlyDataRule"),
            (subtree, "ConstantSubtreeFoldRule"),
        )
        if enabled
    ]
    assert [rule.name for rule in activation.block_rules] == (
        ["ForwardConstantPropagationRule"] if forward else []
    )
    assert all(rule.is_activated for rule in activation.instruction_rules)
    assert all(rule.is_activated for rule in activation.block_rules)


def test_constant_stage_activation_propagates_exact_effective_maturities() -> None:
    activation = pipeline_v2_hook_activation(
        _constant_stage_project(
            readonly_enabled=True,
            subtree_enabled=True,
            forward_enabled=True,
            options={
                "fold-readonly-data": {
                    "enabled": True,
                    "maturities": ["CANONICAL", "CALL_MODELED", "STRUCTURED"],
                    "memory_policy": "aggressive_no_direct_writes",
                    "rva_guard": False,
                    "allow_executable_readonly": True,
                },
                "fold-constant-subtree": {
                    "enabled": True,
                    "maturities": ["LOCAL_OPTIMIZED", "GLOBAL_OPTIMIZED"],
                },
                "forward-constants": {
                    "enabled": True,
                    "maturities": ["CALL_MODELED", "STRUCTURED"],
                },
            },
            maturity_gates=[
                "CALL_MODELED",
                "GLOBAL_ANALYZED",
                "GLOBAL_OPTIMIZED",
            ],
        )
    )

    assert activation.instruction_rules[0].config == {
        "maturities": ["MMAT_CALLS"],
        "memory_policy": "aggressive_no_direct_writes",
        "fold_writable_constants": True,
        "rva_guard": False,
        "allow_executable_readonly": True,
    }
    assert activation.instruction_rules[1].config == {
        "maturities": ["MMAT_GLBOPT2"],
    }
    assert activation.block_rules[0].config == {
        "maturities": ["MMAT_CALLS"],
    }
    assert activation.constant_simplification_schedule is not None
    assert activation.constant_simplification_schedule.stage(
        "fold-readonly-data"
    ).effective_maturities
