"""Config-v2 hook schedule compiler contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.passes.cleanup_family_adapter import (
    SIMPLE_FLATTENING_CLEANUP_PASS_ID,
    SIMPLE_FLATTENING_CLEANUP_RULE,
)
from d810.passes.config_v2_hook_runtime import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    STATE_MACHINE_RUNTIME_HOST,
    ConfigV2HookSchedule,
    compile_config_v2_hook_schedule,
    config_v2_native_state_machine_configs,
    requires_native_preanalysis_handlers,
)
from d810.passes.pass_pipeline import PipelineConfigError


_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _ROOT / "src/d810/conf"


def _project(name: str) -> ProjectConfiguration:
    path = _CONF_DIR / name
    return ProjectConfiguration(path=path, **json.loads(path.read_text()))


def _v2_project(*entries: dict[str, object]) -> ProjectConfiguration:
    return ProjectConfiguration(
        path=Path("runtime-config-v2.json"),
        additional_configuration={"pipeline_v2": list(entries)},
    )


def test_compile_schedule_requires_nonempty_v2_pipeline() -> None:
    project = ProjectConfiguration(path=Path("legacy.json"))

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2"):
        compile_config_v2_hook_schedule(project)


def test_compile_schedule_rejects_empty_v2_pipeline_with_migration_command() -> None:
    project = ProjectConfiguration(
        path=Path("empty.json"),
        additional_configuration={"pipeline_v2": []},
    )

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2"):
        compile_config_v2_hook_schedule(project)


def test_schedule_has_no_optional_enabled_field() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project({"pass_id": "jump-fixer", "options": {}})
    )

    assert isinstance(schedule, ConfigV2HookSchedule)
    assert not hasattr(schedule, "enabled")
    assert schedule.configured_pass_ids == ("jump-fixer",)


def test_schedule_preserves_declared_order_and_typed_bindings() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            {
                "pass_id": "identity-call-resolver",
                "options": {
                    "enable_experimental": True,
                    "max_trampoline_depth": 7,
                    "max_search_instructions": 9,
                },
            },
            {"pass_id": "indirect-call-resolver", "options": {}},
        )
    )

    assert schedule.configured_pass_ids == (
        "identity-call-resolver",
        "indirect-call-resolver",
    )
    assert [binding.name for binding in schedule.block_bindings] == [
        "IdentityCallResolver",
        "IndirectCallResolver",
    ]
    assert schedule.instruction_bindings == ()


def test_native_spine_compiles_private_runtime_host() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            *(
                {"pass_id": pass_id, "options": {}}
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            )
        )
    )

    assert schedule.configured_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert schedule.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert [binding.name for binding in schedule.block_bindings] == [
        STATE_MACHINE_RUNTIME_HOST
    ]


def test_state_machine_runtime_host_is_not_a_project_visible_class_name():
    assert STATE_MACHINE_RUNTIME_HOST != "StateMachineCffUnflattener"


def test_runtime_rejects_retired_pipeline_mode_metadata():
    project = _v2_project({"pass_id": "jump-fixer", "options": {}})
    project.additional_configuration["pipeline_v2_" + "mode"] = "config-v2"

    with pytest.raises(PipelineConfigError, match="removed compatibility field"):
        compile_config_v2_hook_schedule(project)


def test_native_spine_projection_preserves_typed_options() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            *(
                {
                    "pass_id": pass_id,
                    "options": {"min_state_constant": 0x8000},
                }
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            )
        )
    )

    assert schedule.block_bindings[0].config == {"min_state_constant": 0x8000}


def test_native_state_machine_config_filter_excludes_hook_bindings() -> None:
    project = _project("hodur_flag2.json")

    configs = config_v2_native_state_machine_configs(project)

    assert tuple(config.pass_id for config in configs) == STATE_MACHINE_NATIVE_PASS_IDS


def test_native_spine_requires_preanalysis_handlers() -> None:
    schedule = ConfigV2HookSchedule(
        configured_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
        native_state_machine_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
    )

    assert requires_native_preanalysis_handlers(schedule)
    assert not requires_native_preanalysis_handlers(
        ConfigV2HookSchedule(configured_pass_ids=("jump-fixer",))
    )


def test_state_machine_native_spine_rejects_partial_sequence() -> None:
    project = _project("hodur_flag2.json")
    payload = list(project.additional_configuration["pipeline_v2"])
    project.additional_configuration["pipeline_v2"] = payload[:-2]

    with pytest.raises(PipelineConfigError, match="complete native pass sequence"):
        compile_config_v2_hook_schedule(project)


def test_constant_simplification_bundle_expands_to_live_stages() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            {
                "pass_id": "constant-simplification",
                "options": {"memory_policy": "strict"},
            }
        )
    )

    assert [binding.name for binding in schedule.instruction_bindings] == [
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
    ]
    assert [binding.name for binding in schedule.block_bindings] == [
        "ForwardConstantPropagationRule"
    ]


def test_constant_bundle_rejects_duplicate_or_former_constant_selection() -> None:
    project = _v2_project(
        {
            "pass_id": "constant-simplification",
            "options": {"memory_policy": "strict"},
        },
        {
            "pass_id": "forward-constant-propagation",
            "options": {},
        },
    )

    with pytest.raises(PipelineConfigError, match="constant-simplification"):
        compile_config_v2_hook_schedule(project)


def test_constant_bundle_rejects_unknown_rule_selection_field() -> None:
    project = _v2_project(
        {
            "pass_id": "constant-simplification",
            "options": {"memory_policy": "strict"},
        },
        {
            "pass_id": "mba-simplify",
            "rules": {
                "include": ["FoldReadonlyDataRule"],
                "include_order": ["FoldReadonlyDataRule"],
            },
        },
    )

    with pytest.raises(PipelineConfigError, match="unknown field: rules"):
        compile_config_v2_hook_schedule(project)


def test_instruction_only_schedule_derives_bindings_from_pass_ids() -> None:
    schedule = compile_config_v2_hook_schedule(
        _project("default_instruction_only.json")
    )

    assert schedule.configured_pass_ids == (
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    )
    assert len(schedule.instruction_bindings) == 180
    assert [binding.name for binding in schedule.instruction_bindings[:2]] == [
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
    ]
    assert all(
        binding.name != "UnrelatedInstructionRule"
        for binding in schedule.instruction_bindings
    )
    assert [binding.name for binding in schedule.block_bindings] == [
        "ForwardConstantPropagationRule",
        "JumpFixer",
    ]
    assert all(
        binding.name != "UnrelatedBlockRule" for binding in schedule.block_bindings
    )
    assert "enabled_rules" in schedule.block_bindings[-1].config


def test_hodur_schedule_derives_private_runtime_host_and_jump_fixer() -> None:
    schedule = compile_config_v2_hook_schedule(_project("hodur_flag2.json"))

    assert schedule.configured_pass_ids == (
        *STATE_MACHINE_NATIVE_PASS_IDS,
        "jump-fixer",
    )
    assert schedule.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert schedule.instruction_bindings == ()
    assert [binding.name for binding in schedule.block_bindings] == [
        STATE_MACHINE_RUNTIME_HOST,
        "JumpFixer",
    ]
    assert schedule.block_bindings[0].config == {"min_state_constant": 16777216}


def test_state_machine_plus_constant_schedule_places_late_flow_fold() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            *(
                {"pass_id": pass_id, "options": {}}
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            ),
            {
                "pass_id": "constant-simplification",
                "options": {"memory_policy": "strict"},
            },
        )
    )

    assert [binding.name for binding in schedule.block_bindings] == [
        STATE_MACHINE_RUNTIME_HOST,
        "ForwardConstantPropagationRule",
    ]
    assert schedule.block_bindings[1].config == {
        "maturities": ["MMAT_GLBOPT2"],
        "cython_enabled": False,
    }


def test_state_machine_schedule_accepts_typed_direct_threshold() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            *(
                {
                    "pass_id": pass_id,
                    "options": {"min_state_constant": 0x8000},
                }
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            )
        )
    )

    assert schedule.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert [binding.name for binding in schedule.block_bindings] == [
        STATE_MACHINE_RUNTIME_HOST
    ]
    assert schedule.block_bindings[0].config == {"min_state_constant": 0x8000}


def test_state_machine_schedule_maps_profile_options_at_private_host_boundary() -> None:
    schedule = compile_config_v2_hook_schedule(
        _v2_project(
            *(
                {
                    "pass_id": pass_id,
                    "options": {
                        "min_state_constant": 0x8000,
                        "family": "tigress-indirect",
                        "recovery_strategy": "reduced-product",
                    },
                }
                for pass_id in STATE_MACHINE_NATIVE_PASS_IDS
            )
        )
    )

    assert schedule.block_bindings[0].config == {
        "min_state_constant": 0x8000,
        "profile": "tigress_indirect",
        "recovery_engine": "reduced_product",
    }


def test_state_machine_schedule_rejects_disagreeing_typed_thresholds() -> None:
    project = _v2_project(
        *(
            {
                "pass_id": pass_id,
                "options": {"min_state_constant": 0x8000 + index},
            }
            for index, pass_id in enumerate(STATE_MACHINE_NATIVE_PASS_IDS)
        )
    )

    with pytest.raises(PipelineConfigError, match="disagree"):
        compile_config_v2_hook_schedule(project)


def test_ollvm_schedule_omits_retired_materialized_goto_island_pass() -> None:
    schedule = compile_config_v2_hook_schedule(
        _project("default_unflattening_ollvm.json")
    )

    assert "materialized-computed-goto-island" not in schedule.configured_pass_ids
    assert all(
        binding.name != "MaterializedComputedGotoIslandRule"
        for binding in schedule.block_bindings
    )


def test_identity_call_schedule_derives_explicit_opt_in_rule_config() -> None:
    schedule = compile_config_v2_hook_schedule(_project("identity_call.json"))

    assert schedule.configured_pass_ids == ("identity-call-resolver",)
    assert schedule.native_state_machine_pass_ids == ()
    assert schedule.instruction_bindings == ()
    assert [binding.name for binding in schedule.block_bindings] == [
        "IdentityCallResolver"
    ]
    assert schedule.block_bindings[0].config == {
        "enable_experimental": True,
        "max_trampoline_depth": 32,
        "max_search_instructions": 30,
    }


def test_indirect_branch_call_schedule_derives_explicit_flow_rules() -> None:
    schedule = compile_config_v2_hook_schedule(
        _project("default_indirect_resolution.json")
    )

    assert schedule.configured_pass_ids == (
        "indirect-branch-resolver",
        "indirect-call-resolver",
    )
    assert schedule.native_state_machine_pass_ids == ()
    assert schedule.instruction_bindings == ()
    assert [binding.name for binding in schedule.block_bindings] == [
        "IndirectBranchResolver",
        "IndirectCallResolver",
    ]
    assert [binding.config for binding in schedule.block_bindings] == [{}, {}]
    assert all(
        binding.name != "UnrelatedBlockRule" for binding in schedule.block_bindings
    )


def test_cleanup_family_schedule_derives_explicit_cleanup_rule() -> None:
    schedule = compile_config_v2_hook_schedule(
        _project("example_libobfuscated_no_fixprecedessor.json")
    )

    assert schedule.configured_pass_ids == (
        "constant-simplification",
        "mba-simplify",
        SIMPLE_FLATTENING_CLEANUP_PASS_ID,
        "jump-fixer",
    )
    assert schedule.native_state_machine_pass_ids == ()
    assert [binding.name for binding in schedule.block_bindings] == [
        "ForwardConstantPropagationRule",
        SIMPLE_FLATTENING_CLEANUP_RULE,
        "JumpFixer",
    ]
    assert schedule.block_bindings[1].config == {}
    assert all(
        binding.name != "UnrelatedBlockRule" for binding in schedule.block_bindings
    )


def test_unsupported_non_spine_pass_fails_closed() -> None:
    project = _v2_project(
        {
            "pass_id": "block-level-egglog-optimizer",
            "options": {},
        }
    )

    with pytest.raises(PipelineConfigError, match="unknown pass id"):
        compile_config_v2_hook_schedule(project)
