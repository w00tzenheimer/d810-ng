"""Shadow parsing for optional PipelineConfig v2 project payloads."""
from __future__ import annotations

import json
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.core.config import ProjectConfiguration
from d810.ir.maturity import IRMaturity
from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.passes.contract_vocabulary import ContractVocabularyWarning
from d810.passes.legacy_flow_rules import LEGACY_FLOW_RULE_ADAPTER_CAPABILITY
from d810.passes.pass_pipeline import (
    BackendRoute,
    PassScope,
    PipelineConfig,
    PipelineConfigError,
)
from d810.passes.pipeline_config_parser import (
    PipelineV2Mode,
    pipeline_configs_from_project_config,
    pipeline_v2_mode_from_project_config,
    pipeline_v2_shadow_match_required,
    pass_specs_from_project_config,
)
from d810.passes.pipeline_shadow import (
    PipelineShadowMismatchError,
    compare_pipeline_specs,
    compare_pipeline_v2_shadow,
    require_pipeline_v2_shadow_match,
)
from d810.passes.registry import UnknownPassIdError


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"
_STATE_MACHINE_NATIVE_PIPELINE = [
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
]


def _expand_state_machine_pass_ids(pass_ids):
    expanded = []
    for pass_id in pass_ids:
        if pass_id == "state-machine-cff-unflattener":
            expanded.extend(_STATE_MACHINE_NATIVE_PIPELINE)
        else:
            expanded.append(pass_id)
    return expanded


def _expected_unknown_pass(pass_ids):
    for pass_id in pass_ids:
        if pass_id not in _STATE_MACHINE_NATIVE_PIPELINE:
            return pass_id
    return None


def _unique_active_instruction_rule_names(raw_rules):
    names = []
    seen = set()
    for rule in raw_rules:
        rule_name = rule["name"]
        if not rule["is_activated"] or rule_name in seen:
            continue
        seen.add(rule_name)
        names.append(rule_name)
    return names


def _assert_entry_shape(entry):
    assert "include_groups" not in entry.get("rules", {})
    assert "exclude_groups" not in entry.get("rules", {})
    assert "target" not in entry
    assert "preferred" not in entry.get("maturity", {})
    assert "preferred" not in entry.get("maturity", {}).get("range", {})
    if entry.get("migration", {}).get("expansion") == "native_state_machine_spine":
        assert "safety" in entry
    else:
        assert "safety" not in entry
    assert PipelineConfig.from_dict(entry).to_dict()["pass_id"] == entry["pass"]


def _assert_block_configs_preserve_legacy_rules(
    block_configs,
    active_block_rules,
    *,
    shadow_entries,
    source_config,
):
    cursor = 0
    for rule in active_block_rules:
        if rule["name"] == "StateMachineCffUnflattener":
            config_group = block_configs[
                cursor: cursor + len(_STATE_MACHINE_NATIVE_PIPELINE)
            ]
            entry_group = shadow_entries[
                cursor: cursor + len(_STATE_MACHINE_NATIVE_PIPELINE)
            ]
            assert [config.pass_id for config in config_group] == (
                _STATE_MACHINE_NATIVE_PIPELINE
            )
            for index, (config, entry) in enumerate(zip(config_group, entry_group)):
                options = dict(config.options)
                assert options.pop("legacy_rule") == rule["name"]
                assert options.pop("legacy_rule_options") == rule["config"]
                assert options.pop("native_pipeline") == _STATE_MACHINE_NATIVE_PIPELINE
                assert options == {}
                assert config.contract.scope is PassScope.FUNCTION
                assert entry["migration"] == {
                    "source_config": source_config,
                    "source_section": "blk_rules",
                    "source_rule": "StateMachineCffUnflattener",
                    "expansion": "native_state_machine_spine",
                    "stage_index": index,
                    "stage_count": len(_STATE_MACHINE_NATIVE_PIPELINE),
                }
            cursor += len(_STATE_MACHINE_NATIVE_PIPELINE)
            continue

        config = block_configs[cursor]
        entry = shadow_entries[cursor]
        options = dict(config.options)
        assert options.pop("legacy_rule") == rule["name"]
        assert options == rule["config"]
        assert config.contract.scope is PassScope.BLOCK
        assert config.contract.requires.capabilities == frozenset(
            {LEGACY_FLOW_RULE_ADAPTER_CAPABILITY}
        )
        assert entry["migration"] == {
            "source_config": source_config,
            "source_section": "blk_rules",
            "source_rule": rule["name"],
        }
        cursor += 1

    assert cursor == len(block_configs)
    assert cursor == len(shadow_entries)


_REMAINING_GENERATED_SHADOWS = (
    (
        "bogus_loops",
        0,
        ["MbaStatePreconditioner", "JumpFixer"],
        ["mba-state-preconditioner", "jump-fixer"],
        "mba-state-preconditioner",
    ),
    (
        "default_unflattening_approov",
        178,
        ["MbaStatePreconditioner", "StateMachineCffUnflattener", "JumpFixer"],
        [
            "mba-simplify",
            "mba-state-preconditioner",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ],
        "mba-simplify",
    ),
    (
        "default_unflattening_approov_s1a",
        178,
        ["MbaStatePreconditioner", "StateMachineCffUnflattener", "JumpFixer"],
        [
            "mba-simplify",
            "mba-state-preconditioner",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ],
        "mba-simplify",
    ),
    ("eidolon", 172, [], ["mba-simplify"], "mba-simplify"),
    (
        "example_anel",
        179,
        ["JumpFixer"],
        ["mba-simplify", "jump-fixer"],
        "mba-simplify",
    ),
    (
        "example_hodur",
        185,
        ["ForwardConstantPropagationRule", "StateMachineCffUnflattener", "JumpFixer"],
        [
            "mba-simplify",
            "forward-constant-propagation",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ],
        "mba-simplify",
    ),
    (
        "example_libobfuscated_abc",
        198,
        ["ForwardConstantPropagationRule", "StateMachineCffUnflattener", "JumpFixer"],
        [
            "mba-simplify",
            "forward-constant-propagation",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ],
        "mba-simplify",
    ),
    (
        "flatfold",
        157,
        [
            "MbaStatePreconditioner",
            "GlobalConstantInliner",
            "JumpFixer",
            "StateMachineCffUnflattener",
        ],
        [
            "mba-simplify",
            "mba-state-preconditioner",
            "global-constant-inliner",
            "jump-fixer",
            *_STATE_MACHINE_NATIVE_PIPELINE,
        ],
        "mba-simplify",
    ),
    (
        "flatfold_no_predicate_loop_fix",
        177,
        ["JumpFixer"],
        ["mba-simplify", "jump-fixer"],
        "mba-simplify",
    ),
    (
        "hodur_flag2_with_fcp",
        3,
        ["StateMachineCffUnflattener", "JumpFixer", "ForwardConstantPropagationRule"],
        [
            "mba-simplify",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
            "forward-constant-propagation",
        ],
        "mba-simplify",
    ),
    (
        "hodur_glbopt2_only",
        0,
        ["StateMachineCffUnflattener"],
        [*_STATE_MACHINE_NATIVE_PIPELINE],
        None,
    ),
)


def _legacy_recover_state_machine_contract_payload():
    return {
        "pass": "recover-state-machine",
        "scope": "function",
        "maturity": {
            "min": "ir.call.modeled",
            "max": "ir.global.analyzed",
            "preferred": "ir.call.modeled",
        },
        "requires": {
            "capabilities": ["live_mba", "z3_solver"],
            "analyses": ["def_use", "dominators", "value_ranges"],
            "evidence": [
                "state_variable_writes",
                "dispatcher_predicates",
                "branch_targets",
            ],
            "facts": {
                "optional": ["carrier_store_candidates"],
                "required": [],
            },
        },
        "outputs": {
            "facts": [
                "state_transition",
                "recovered_cfg_edge",
                "dispatcher_family",
            ],
            "evidence": [
                "branch_targets",
            ],
        },
        "preserves": {
            "analyses": ["function_boundaries"],
            "facts": ["raw_instruction_addresses"],
        },
        "invalidates": {
            "analyses": ["dominators", "postdominators", "loop_info", "regions"],
            "facts": ["stale_cfg_shape"],
        },
        "safety": {
            "policy": "guarded-rewrite",
            "requires_oracle": False,
        },
    }


def test_missing_pipeline_v2_is_inert_for_existing_project_configs():
    assert pipeline_configs_from_project_config({}) == ()
    project = SimpleNamespace(additional_configuration={"enable_pass_pipeline": True})
    assert pipeline_configs_from_project_config(project) == ()


def test_pipeline_v2_shadow_match_required_defaults_false_when_missing():
    assert pipeline_v2_shadow_match_required({}) is False
    project = SimpleNamespace(additional_configuration={"enable_pass_pipeline": True})
    assert pipeline_v2_shadow_match_required(project) is False


def test_pipeline_v2_shadow_match_required_reads_plain_mapping_and_project_object():
    assert (
        pipeline_v2_shadow_match_required(
            {"require_pipeline_v2_shadow_match": True}
        )
        is True
    )
    project = SimpleNamespace(
        additional_configuration={"require_pipeline_v2_shadow_match": False}
    )
    assert pipeline_v2_shadow_match_required(project) is False


@pytest.mark.parametrize("value", ["true", 1, [], {}])
def test_pipeline_v2_shadow_match_required_rejects_non_boolean_values(value):
    with pytest.raises(
        PipelineConfigError,
        match="require_pipeline_v2_shadow_match must be a boolean",
    ):
        pipeline_v2_shadow_match_required(
            {"require_pipeline_v2_shadow_match": value}
        )


def test_pipeline_v2_shadow_match_required_rejects_malformed_project_config():
    project = SimpleNamespace(additional_configuration=[])
    with pytest.raises(
        PipelineConfigError,
        match="project additional_configuration must be a mapping",
    ):
        pipeline_v2_shadow_match_required(project)


def test_pipeline_v2_mode_defaults_legacy_without_project_opt_in():
    assert pipeline_v2_mode_from_project_config({}) is PipelineV2Mode.LEGACY
    project = SimpleNamespace(additional_configuration={"enable_pass_pipeline": True})
    assert pipeline_v2_mode_from_project_config(project) is PipelineV2Mode.LEGACY


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("legacy", PipelineV2Mode.LEGACY),
        ("shadow-check", PipelineV2Mode.SHADOW_CHECK),
        ("config-v2", PipelineV2Mode.CONFIG_V2),
    ],
)
def test_pipeline_v2_mode_reads_explicit_project_mode(value, expected):
    assert (
        pipeline_v2_mode_from_project_config({"pipeline_v2_mode": value}) is expected
    )


def test_pipeline_v2_mode_preserves_legacy_shadow_match_boolean():
    assert (
        pipeline_v2_mode_from_project_config(
            {"require_pipeline_v2_shadow_match": True}
        )
        is PipelineV2Mode.SHADOW_CHECK
    )


@pytest.mark.parametrize("value", [True, 1, [], {}])
def test_pipeline_v2_mode_rejects_non_string_values(value):
    with pytest.raises(PipelineConfigError, match="pipeline_v2_mode must be a string"):
        pipeline_v2_mode_from_project_config({"pipeline_v2_mode": value})


def test_pipeline_v2_mode_rejects_unknown_values():
    with pytest.raises(PipelineConfigError, match="pipeline_v2_mode must be one of"):
        pipeline_v2_mode_from_project_config({"pipeline_v2_mode": "execute"})


def test_pipeline_v2_mode_rejects_conflicting_legacy_shadow_boolean():
    with pytest.raises(
        PipelineConfigError,
        match="require_pipeline_v2_shadow_match conflicts",
    ):
        pipeline_v2_mode_from_project_config(
            {
                "pipeline_v2_mode": "config-v2",
                "require_pipeline_v2_shadow_match": True,
            }
        )


def test_pipeline_v2_shadow_parse_from_project_like_object():
    project = SimpleNamespace(
        additional_configuration={
            "pipeline_v2": [
                {
                    "pass_id": "recover_dispatcher",
                    "maturity_gates": ["GLOBAL_ANALYZED"],
                    "backend_route": "analysis_only",
                }
            ]
        }
    )

    configs = pipeline_configs_from_project_config(project)

    assert len(configs) == 1
    assert configs[0].pass_id == "recover_dispatcher"
    assert configs[0].maturity_gates == frozenset({IRMaturity.GLOBAL_ANALYZED})
    assert configs[0].backend_route is BackendRoute.ANALYSIS_ONLY


def test_pipeline_v2_warns_for_legacy_native_deobfuscation_contract_aliases():
    with pytest.warns(ContractVocabularyWarning) as warnings:
        configs = pipeline_configs_from_project_config(
            {"pipeline_v2": [_legacy_recover_state_machine_contract_payload()]}
        )

    assert len(configs) == 1
    warning_text = "\n".join(str(warning.message) for warning in warnings)
    assert "state_variable_writes->ir.state_variable_write" in warning_text
    assert "dispatcher_predicates->role.dispatcher_predicate" in warning_text
    assert "branch_targets->ir.branch_target" in warning_text
    assert "dispatcher_family->role.dispatcher" in warning_text
    assert "carrier_store_candidates->ir.memory_def.candidate" in warning_text
    assert "state_transition->recovered.state_transition" in warning_text
    assert "recovered_cfg_edge->recovered.cfg_edge" in warning_text
    assert "stale_cfg_shape->ir.cfg_shape.stale" in warning_text
    config = configs[0]
    assert config.pass_id == "recover-state-machine"
    assert config.contract.scope.value == "function"
    assert config.contract.maturity.min is IRMaturity.CALL_MODELED
    assert config.contract.maturity.max is IRMaturity.GLOBAL_ANALYZED
    assert config.contract.maturity.preferred is IRMaturity.CALL_MODELED
    assert config.contract.requires.capabilities == frozenset(
        {"live_mba", "z3_solver"}
    )
    assert config.contract.requires.analyses == frozenset(
        {"def_use", "dominators", "value_ranges"}
    )
    assert config.contract.requires.evidence == frozenset(
        {"state_variable_writes", "dispatcher_predicates", "branch_targets"}
    )
    assert config.contract.requires.facts.required == frozenset()
    assert config.contract.requires.facts.optional == frozenset(
        {"carrier_store_candidates"}
    )
    assert config.contract.outputs.facts == frozenset(
        {"state_transition", "recovered_cfg_edge", "dispatcher_family"}
    )
    assert config.contract.outputs.evidence == frozenset({"branch_targets"})
    assert config.contract.preserves.analyses == frozenset({"function_boundaries"})
    assert config.contract.preserves.facts == frozenset({"raw_instruction_addresses"})
    assert config.contract.invalidates.analyses == frozenset(
        {"dominators", "postdominators", "loop_info", "regions"}
    )
    assert config.contract.invalidates.facts == frozenset({"stale_cfg_shape"})
    assert config.contract.safety.policy == "guarded-rewrite"
    assert config.contract.safety.requires_oracle is False


def test_pipeline_v2_canonical_contract_names_do_not_warn():
    payload = _legacy_recover_state_machine_contract_payload()
    payload["requires"]["evidence"] = [
        "ir.state_variable_write",
        "role.dispatcher_predicate",
        "ir.branch_target",
        "ir.memory_def.candidate",
        "ir.branch_cond.candidate",
    ]
    payload["requires"]["facts"]["optional"] = ["effect.memory_def.observable"]
    payload["outputs"]["facts"] = [
        "recovered.state_transition",
        "recovered.cfg_edge",
        "role.dispatcher",
    ]
    payload["outputs"]["evidence"] = [
        "ir.branch_target",
        "ir.induction_var.candidate",
    ]
    payload["invalidates"]["facts"] = ["ir.cfg_shape.stale"]

    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        configs = pipeline_configs_from_project_config({"pipeline_v2": [payload]})

    assert configs[0].contract.requires.evidence == frozenset(
        {
            "ir.state_variable_write",
            "role.dispatcher_predicate",
            "ir.branch_target",
            "ir.memory_def.candidate",
            "ir.branch_cond.candidate",
        }
    )
    assert configs[0].contract.outputs.facts == frozenset(
        {"recovered.state_transition", "recovered.cfg_edge", "role.dispatcher"}
    )
    assert configs[0].contract.outputs.evidence == frozenset(
        {"ir.branch_target", "ir.induction_var.candidate"}
    )
    assert not [
        warning
        for warning in recorded
        if issubclass(warning.category, ContractVocabularyWarning)
    ]


def test_malformed_pipeline_v2_fails_clearly():
    with pytest.raises(PipelineConfigError, match="pipeline_v2"):
        pipeline_configs_from_project_config({"pipeline_v2": {"pass_id": "x"}})
    with pytest.raises(PipelineConfigError, match="at least one pass config"):
        pipeline_configs_from_project_config({"pipeline_v2": []})
    with pytest.raises(PipelineConfigError, match="scheduler_policy"):
        pipeline_configs_from_project_config(
            {
                "pipeline_v2": [
                    {
                        "pass_id": "x",
                        "scheduler_policy": "later",
                    }
                ]
            }
        )


def test_pipeline_v2_shadow_comparison_is_inert_when_missing():
    comparison = compare_pipeline_v2_shadow(
        project_config={},
        registry=state_machine_pass_registry(),
        live_specs=standard_state_machine_passes(),
    )

    assert comparison.enabled is False
    assert comparison.matches is True
    assert comparison.spec_comparison is None
    assert comparison.live_pass_ids == tuple(
        spec.pass_id for spec in standard_state_machine_passes()
    )


def test_pipeline_v2_shadow_requirement_is_inert_when_missing():
    comparison = require_pipeline_v2_shadow_match(
        project_config={},
        registry=state_machine_pass_registry(),
        live_specs=standard_state_machine_passes(),
    )

    assert comparison.enabled is False
    assert comparison.matches is True


def test_pipeline_v2_shadow_comparison_rejects_explicit_empty_config():
    with pytest.raises(PipelineConfigError, match="at least one pass config"):
        compare_pipeline_v2_shadow(
            project_config={"pipeline_v2": []},
            registry=state_machine_pass_registry(),
            live_specs=standard_state_machine_passes(),
        )


def test_pipeline_v2_shadow_comparison_matches_full_live_specs():
    live_specs = standard_state_machine_passes()
    comparison = compare_pipeline_v2_shadow(
        project_config={"pipeline_v2": [spec.config.to_dict() for spec in live_specs]},
        registry=state_machine_pass_registry(),
        live_specs=live_specs,
    )

    assert comparison.enabled is True
    assert comparison.matches is True
    assert comparison.configured_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.spec_comparison is not None
    assert comparison.spec_comparison.matches is True


def test_pipeline_v2_shadow_requirement_accepts_full_live_specs():
    live_specs = standard_state_machine_passes()
    comparison = require_pipeline_v2_shadow_match(
        project_config={"pipeline_v2": [spec.config.to_dict() for spec in live_specs]},
        registry=state_machine_pass_registry(),
        live_specs=live_specs,
    )

    assert comparison.enabled is True
    assert comparison.matches is True


def test_pipeline_v2_configs_build_specs_from_registry():
    live_specs = standard_state_machine_passes()
    rebuilt_specs = pass_specs_from_project_config(
        {"pipeline_v2": [spec.config.to_dict() for spec in live_specs]},
        state_machine_pass_registry(),
    )

    assert tuple(spec.config for spec in rebuilt_specs) == tuple(
        spec.config for spec in live_specs
    )


def test_default_instruction_only_legacy_config_remains_runtime_source():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only.json"
    )

    assert len(project.ins_rules) == 179
    assert [rule.name for rule in project.blk_rules] == [
        "GlobalConstantInliner",
        "JumpFixer",
    ]
    fold = next(rule for rule in project.ins_rules if rule.name == "FoldReadonlyDataRule")
    assert fold.config == {"fold_writable_constants": True}
    assert pipeline_configs_from_project_config(project) == ()


def test_default_instruction_only_pipeline_v2_shadow_parses_and_roundtrips():
    shadow_path = _CONF_DIR / "default_instruction_only.pipeline_v2.json"
    raw = json.loads(shadow_path.read_text())
    project = ProjectConfiguration.from_file(shadow_path)

    configs = pipeline_configs_from_project_config(project)

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert project.additional_configuration["pipeline_v2_shadow"] == {
        "source_config": "default_instruction_only.json",
        "runtime_source": "legacy",
    }
    assert [config.pass_id for config in configs] == [
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    ]
    config = configs[0]
    assert config.pass_id == "mba-simplify"
    assert config.contract.scope is PassScope.EXPRESSION
    assert config.contract.maturity.min is IRMaturity.CANONICAL
    assert config.contract.maturity.max is IRMaturity.GLOBAL_OPTIMIZED
    assert config.contract.maturity.preferred is None
    assert config.contract.requires.capabilities == frozenset(
        {"local_instruction_rewrite", "z3_solver"}
    )
    assert config.rules.include_groups == frozenset()
    assert len(config.rules.include) == 179
    assert {
        "FoldReadonlyDataRule",
        "Add_OllvmRule_1",
        "Z3ConstantOptimization",
        "ExampleGuessingRule",
    } <= config.rules.include
    assert config.rules.exclude_groups == frozenset()
    assert config.rules.exclude == frozenset()
    assert config.rules.options["FoldReadonlyDataRule"] == {
        "fold_writable_constants": True
    }
    assert config.rules.options["Z3ConstantOptimization"] == {
        "min_nb_opcode": 4,
        "min_nb_constant": 3,
    }
    assert config.rules.options["ExampleGuessingRule"] == {
        "min_nb_var": 1,
        "max_nb_var": 3,
        "min_nb_diff_opcodes": 3,
        "max_nb_diff_opcodes": 6,
    }
    assert PipelineConfig.from_dict(config.to_dict()) == config

    pass_payload = raw["additional_configuration"]["pipeline_v2"][0]
    assert "include_groups" not in pass_payload["rules"]
    assert "exclude_groups" not in pass_payload["rules"]
    assert "target" not in pass_payload
    assert "safety" not in pass_payload
    assert "preferred" not in pass_payload["maturity"]

    assert configs[1].pass_id == "global-constant-inliner"
    assert configs[1].contract.scope is PassScope.BLOCK
    assert dict(configs[1].options) == {
        "legacy_rule": "GlobalConstantInliner"
    }
    assert configs[2].pass_id == "jump-fixer"
    assert configs[2].contract.scope is PassScope.BLOCK
    assert configs[2].options["legacy_rule"] == "JumpFixer"
    assert "JmpRuleZ3Const" in configs[2].options["enabled_rules"]


def test_default_instruction_only_pipeline_v2_shadow_is_not_registry_buildable_yet():
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only.pipeline_v2.json"
    )

    with pytest.raises(UnknownPassIdError, match="mba-simplify"):
        pass_specs_from_project_config(shadow, state_machine_pass_registry())


def test_example_libobfuscated_legacy_config_remains_runtime_source():
    project = ProjectConfiguration.from_file(_CONF_DIR / "example_libobfuscated.json")

    assert len([rule for rule in project.ins_rules if rule.is_activated]) == 186
    assert [rule.name for rule in project.blk_rules if rule.is_activated] == [
        "BlockLevelEgglogOptimizer",
        "GlobalConstantInliner",
        "ForwardConstantPropagationRule",
        "MbaStatePreconditioner",
        "StateMachineCffUnflattener",
        "JumpFixer",
    ]
    assert project.additional_configuration == {"enable_pass_pipeline": True}
    assert pipeline_configs_from_project_config(project) == ()


def test_example_libobfuscated_pipeline_v2_shadow_parses_and_roundtrips():
    legacy_path = _CONF_DIR / "example_libobfuscated.json"
    shadow_path = _CONF_DIR / "example_libobfuscated.pipeline_v2.json"
    legacy_raw = json.loads(legacy_path.read_text())
    shadow_raw = json.loads(shadow_path.read_text())
    shadow = ProjectConfiguration.from_file(shadow_path)

    legacy_ins_rules = [
        rule for rule in legacy_raw["ins_rules"] if rule["is_activated"]
    ]
    legacy_blk_rules = [
        rule for rule in legacy_raw["blk_rules"] if rule["is_activated"]
    ]
    configs = pipeline_configs_from_project_config(shadow)

    assert shadow.ins_rules == []
    assert shadow.blk_rules == []
    assert shadow.additional_configuration["pipeline_v2_shadow"] == {
        "source_config": "example_libobfuscated.json",
        "runtime_source": "legacy",
        "enable_pass_pipeline": True,
    }
    assert [config.pass_id for config in configs] == [
        "mba-simplify",
        "block-level-egglog-optimizer",
        "global-constant-inliner",
        "forward-constant-propagation",
        "mba-state-preconditioner",
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]

    mba_config = configs[0]
    assert mba_config.contract.scope is PassScope.EXPRESSION
    assert mba_config.contract.requires.capabilities == frozenset(
        {"local_instruction_rewrite", "z3_solver"}
    )
    assert mba_config.rules.include_groups == frozenset()
    shadow_rule_names = shadow_raw["additional_configuration"]["pipeline_v2"][0][
        "rules"
    ]["include"]
    assert shadow_rule_names == [rule["name"] for rule in legacy_ins_rules]
    assert "include_groups" not in shadow_raw["additional_configuration"][
        "pipeline_v2"
    ][0]["rules"]
    assert "exclude_groups" not in shadow_raw["additional_configuration"][
        "pipeline_v2"
    ][0]["rules"]
    assert mba_config.rules.include == frozenset(
        rule["name"] for rule in legacy_ins_rules
    )
    assert mba_config.rules.options == {
        rule["name"]: rule["config"]
        for rule in legacy_ins_rules
        if rule["config"]
    }

    _assert_block_configs_preserve_legacy_rules(
        configs[1:],
        legacy_blk_rules,
        shadow_entries=shadow_raw["additional_configuration"]["pipeline_v2"][1:],
        source_config="example_libobfuscated.json",
    )

    for entry in shadow_raw["additional_configuration"]["pipeline_v2"]:
        _assert_entry_shape(entry)

    roundtripped_configs = tuple(
        PipelineConfig.from_dict(config.to_dict()) for config in configs
    )
    assert roundtripped_configs == configs


def test_example_libobfuscated_pipeline_v2_shadow_is_not_registry_buildable_yet():
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "example_libobfuscated.pipeline_v2.json"
    )

    with pytest.raises(UnknownPassIdError, match="mba-simplify"):
        pass_specs_from_project_config(shadow, state_machine_pass_registry())


@pytest.mark.parametrize(
    ("config_name", "expected_instruction_rules", "expected_block_rules"),
    [
        (
            "hodur_flag2",
            0,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
        (
            "hodur_flag2_s1a",
            0,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
        (
            "hodur_deobfuscation",
            182,
            ["JumpFixer"],
        ),
    ],
)
def test_hodur_legacy_configs_remain_runtime_source(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert len([rule for rule in project.ins_rules if rule.is_activated]) == (
        expected_instruction_rules
    )
    assert [rule.name for rule in project.blk_rules if rule.is_activated] == (
        expected_block_rules
    )
    assert pipeline_configs_from_project_config(project) == ()


@pytest.mark.parametrize(
    ("config_name", "expected_pass_ids"),
    [
        (
            "hodur_flag2",
            [*_STATE_MACHINE_NATIVE_PIPELINE, "jump-fixer"],
        ),
        (
            "hodur_flag2_s1a",
            [*_STATE_MACHINE_NATIVE_PIPELINE, "jump-fixer"],
        ),
        (
            "hodur_deobfuscation",
            ["mba-simplify", "jump-fixer"],
        ),
    ],
)
def test_hodur_pipeline_v2_shadows_parse_and_roundtrip(
    config_name,
    expected_pass_ids,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    shadow_path = _CONF_DIR / f"{config_name}.pipeline_v2.json"
    legacy_raw = json.loads(legacy_path.read_text())
    shadow_raw = json.loads(shadow_path.read_text())
    shadow = ProjectConfiguration.from_file(shadow_path)

    configs = pipeline_configs_from_project_config(shadow)
    assert shadow.ins_rules == []
    assert shadow.blk_rules == []
    assert shadow.additional_configuration["pipeline_v2_shadow"] == {
        "source_config": f"{config_name}.json",
        "runtime_source": "legacy",
    }
    assert [config.pass_id for config in configs] == expected_pass_ids

    if expected_pass_ids[0] == "mba-simplify":
        active_instruction_rules = [
            rule for rule in legacy_raw["ins_rules"] if rule["is_activated"]
        ]
        instruction_entry = shadow_raw["additional_configuration"]["pipeline_v2"][0]
        assert instruction_entry["rules"]["include"] == (
            _unique_active_instruction_rule_names(active_instruction_rules)
        )
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        assert configs[0].rules.include_groups == frozenset()
        assert configs[0].rules.include == frozenset(
            rule["name"] for rule in active_instruction_rules
        )
        assert configs[0].rules.options == {
            rule["name"]: rule["config"]
            for rule in active_instruction_rules
            if rule["config"]
        }
        block_configs = configs[1:]
    else:
        block_configs = configs

    active_block_rules = [
        rule for rule in legacy_raw["blk_rules"] if rule["is_activated"]
    ]
    _assert_block_configs_preserve_legacy_rules(
        block_configs,
        active_block_rules,
        shadow_entries=shadow_raw["additional_configuration"]["pipeline_v2"][
            len(configs) - len(block_configs):
        ],
        source_config=f"{config_name}.json",
    )

    for entry in shadow_raw["additional_configuration"]["pipeline_v2"]:
        _assert_entry_shape(entry)
    assert tuple(PipelineConfig.from_dict(config.to_dict()) for config in configs) == (
        configs
    )


@pytest.mark.parametrize(
    ("config_name", "expected_unknown_pass"),
    [
        ("hodur_flag2", "jump-fixer"),
        ("hodur_flag2_s1a", "jump-fixer"),
        ("hodur_deobfuscation", "mba-simplify"),
    ],
)
def test_hodur_pipeline_v2_shadows_are_not_registry_buildable_yet(
    config_name,
    expected_unknown_pass,
):
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}.pipeline_v2.json"
    )

    if expected_unknown_pass is None:
        specs = pass_specs_from_project_config(shadow, state_machine_pass_registry())
        assert [spec.pass_id for spec in specs] == _STATE_MACHINE_NATIVE_PIPELINE
    else:
        with pytest.raises(UnknownPassIdError, match=expected_unknown_pass):
            pass_specs_from_project_config(shadow, state_machine_pass_registry())


@pytest.mark.parametrize(
    ("config_name", "expected_instruction_rules", "expected_block_rules"),
    [
        (
            "default_unflattening_tigress_engine",
            0,
            ["StateMachineCffUnflattener"],
        ),
        (
            "default_unflattening_tigress_engine_transition_facts",
            4,
            ["ForwardConstantPropagationRule", "StateMachineCffUnflattener"],
        ),
        (
            "default_unflattening_tigress_indirect",
            7,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
        (
            "default_unflattening_switch_case",
            178,
            ["MbaStatePreconditioner", "JumpFixer"],
        ),
    ],
)
def test_tigress_switch_legacy_configs_remain_runtime_source(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert len([rule for rule in project.ins_rules if rule.is_activated]) == (
        expected_instruction_rules
    )
    assert [rule.name for rule in project.blk_rules if rule.is_activated] == (
        expected_block_rules
    )
    assert pipeline_configs_from_project_config(project) == ()


@pytest.mark.parametrize(
    ("config_name", "expected_pass_ids"),
    [
        (
            "default_unflattening_tigress_engine",
            [*_STATE_MACHINE_NATIVE_PIPELINE],
        ),
        (
            "default_unflattening_tigress_engine_transition_facts",
            [
                "mba-simplify",
                "forward-constant-propagation",
                *_STATE_MACHINE_NATIVE_PIPELINE,
            ],
        ),
        (
            "default_unflattening_tigress_indirect",
            ["mba-simplify", *_STATE_MACHINE_NATIVE_PIPELINE, "jump-fixer"],
        ),
        (
            "default_unflattening_switch_case",
            ["mba-simplify", "mba-state-preconditioner", "jump-fixer"],
        ),
    ],
)
def test_tigress_switch_pipeline_v2_shadows_parse_and_roundtrip(
    config_name,
    expected_pass_ids,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    shadow_path = _CONF_DIR / f"{config_name}.pipeline_v2.json"
    legacy_raw = json.loads(legacy_path.read_text())
    shadow_raw = json.loads(shadow_path.read_text())
    shadow = ProjectConfiguration.from_file(shadow_path)

    configs = pipeline_configs_from_project_config(shadow)
    assert shadow.ins_rules == []
    assert shadow.blk_rules == []
    assert shadow.additional_configuration["pipeline_v2_shadow"] == {
        "source_config": f"{config_name}.json",
        "runtime_source": "legacy",
    }
    assert [config.pass_id for config in configs] == expected_pass_ids

    if expected_pass_ids[0] == "mba-simplify":
        active_instruction_rules = [
            rule for rule in legacy_raw["ins_rules"] if rule["is_activated"]
        ]
        instruction_entry = shadow_raw["additional_configuration"]["pipeline_v2"][0]
        assert instruction_entry["rules"]["include"] == (
            _unique_active_instruction_rule_names(active_instruction_rules)
        )
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        assert configs[0].rules.include_groups == frozenset()
        assert configs[0].rules.include == frozenset(
            rule["name"] for rule in active_instruction_rules
        )
        assert configs[0].rules.options == {
            rule["name"]: rule["config"]
            for rule in active_instruction_rules
            if rule["config"]
        }
        block_configs = configs[1:]
    else:
        block_configs = configs

    active_block_rules = [
        rule for rule in legacy_raw["blk_rules"] if rule["is_activated"]
    ]
    _assert_block_configs_preserve_legacy_rules(
        block_configs,
        active_block_rules,
        shadow_entries=shadow_raw["additional_configuration"]["pipeline_v2"][
            len(configs) - len(block_configs):
        ],
        source_config=f"{config_name}.json",
    )

    for entry in shadow_raw["additional_configuration"]["pipeline_v2"]:
        _assert_entry_shape(entry)
    assert tuple(PipelineConfig.from_dict(config.to_dict()) for config in configs) == (
        configs
    )


@pytest.mark.parametrize(
    ("config_name", "expected_unknown_pass"),
    [
        ("default_unflattening_tigress_engine", None),
        ("default_unflattening_tigress_engine_transition_facts", "mba-simplify"),
        ("default_unflattening_tigress_indirect", "mba-simplify"),
        ("default_unflattening_switch_case", "mba-simplify"),
    ],
)
def test_tigress_switch_pipeline_v2_shadows_are_not_registry_buildable_yet(
    config_name,
    expected_unknown_pass,
):
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}.pipeline_v2.json"
    )

    if expected_unknown_pass is None:
        specs = pass_specs_from_project_config(shadow, state_machine_pass_registry())
        assert [spec.pass_id for spec in specs] == _STATE_MACHINE_NATIVE_PIPELINE
    else:
        with pytest.raises(UnknownPassIdError, match=expected_unknown_pass):
            pass_specs_from_project_config(shadow, state_machine_pass_registry())


@pytest.mark.parametrize(
    (
        "config_name",
        "expected_instruction_rules",
        "expected_block_rules",
        "expected_pass_ids",
        "expected_unknown_pass",
    ),
    _REMAINING_GENERATED_SHADOWS,
)
def test_remaining_legacy_configs_remain_runtime_source(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
    expected_pass_ids,
    expected_unknown_pass,
):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert len([rule for rule in project.ins_rules if rule.is_activated]) == (
        expected_instruction_rules
    )
    assert [rule.name for rule in project.blk_rules if rule.is_activated] == (
        expected_block_rules
    )
    assert pipeline_configs_from_project_config(project) == ()


@pytest.mark.parametrize(
    (
        "config_name",
        "expected_instruction_rules",
        "expected_block_rules",
        "expected_pass_ids",
        "expected_unknown_pass",
    ),
    _REMAINING_GENERATED_SHADOWS,
)
def test_remaining_pipeline_v2_shadows_parse_and_roundtrip(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
    expected_pass_ids,
    expected_unknown_pass,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    shadow_path = _CONF_DIR / f"{config_name}.pipeline_v2.json"
    legacy_raw = json.loads(legacy_path.read_text())
    shadow_raw = json.loads(shadow_path.read_text())
    shadow = ProjectConfiguration.from_file(shadow_path)

    configs = pipeline_configs_from_project_config(shadow)
    assert shadow.ins_rules == []
    assert shadow.blk_rules == []
    assert shadow.additional_configuration["pipeline_v2_shadow"] == {
        "source_config": f"{config_name}.json",
        "runtime_source": "legacy",
    }
    assert [config.pass_id for config in configs] == expected_pass_ids

    if expected_pass_ids[0] == "mba-simplify":
        active_instruction_rules = [
            rule for rule in legacy_raw["ins_rules"] if rule["is_activated"]
        ]
        instruction_entry = shadow_raw["additional_configuration"]["pipeline_v2"][0]
        assert len(active_instruction_rules) == expected_instruction_rules
        assert instruction_entry["rules"]["include"] == (
            _unique_active_instruction_rule_names(active_instruction_rules)
        )
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        assert configs[0].rules.include_groups == frozenset()
        assert configs[0].rules.include == frozenset(
            rule["name"] for rule in active_instruction_rules
        )
        assert configs[0].rules.options == {
            rule["name"]: rule["config"]
            for rule in active_instruction_rules
            if rule["config"]
        }
        block_configs = configs[1:]
    else:
        block_configs = configs

    active_block_rules = [
        rule for rule in legacy_raw["blk_rules"] if rule["is_activated"]
    ]
    assert [rule["name"] for rule in active_block_rules] == expected_block_rules
    _assert_block_configs_preserve_legacy_rules(
        block_configs,
        active_block_rules,
        shadow_entries=shadow_raw["additional_configuration"]["pipeline_v2"][
            len(configs) - len(block_configs):
        ],
        source_config=f"{config_name}.json",
    )

    for entry in shadow_raw["additional_configuration"]["pipeline_v2"]:
        _assert_entry_shape(entry)
    assert tuple(PipelineConfig.from_dict(config.to_dict()) for config in configs) == (
        configs
    )


@pytest.mark.parametrize(
    (
        "config_name",
        "expected_instruction_rules",
        "expected_block_rules",
        "expected_pass_ids",
        "expected_unknown_pass",
    ),
    _REMAINING_GENERATED_SHADOWS,
)
def test_remaining_pipeline_v2_shadows_are_not_registry_buildable_yet(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
    expected_pass_ids,
    expected_unknown_pass,
):
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}.pipeline_v2.json"
    )

    if expected_unknown_pass is None:
        specs = pass_specs_from_project_config(shadow, state_machine_pass_registry())
        assert [spec.pass_id for spec in specs] == _STATE_MACHINE_NATIVE_PIPELINE
    else:
        with pytest.raises(UnknownPassIdError, match=expected_unknown_pass):
            pass_specs_from_project_config(shadow, state_machine_pass_registry())


def test_pipeline_spec_comparison_reports_ordered_differences():
    live_specs = standard_state_machine_passes()
    short_specs = live_specs[:1]

    comparison = compare_pipeline_specs(short_specs, live_specs)

    assert comparison.matches is False
    assert comparison.pass_ids_match is False
    assert comparison.configs_match is False
    assert comparison.left_pass_ids == ("recover_dispatcher",)
    assert comparison.right_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.missing_pass_ids == tuple(
        spec.pass_id for spec in live_specs[1:]
    )
    assert comparison.extra_pass_ids == ()


def test_pipeline_v2_shadow_comparison_reports_mismatch_without_cutover():
    live_specs = standard_state_machine_passes()
    comparison = compare_pipeline_v2_shadow(
        project_config={"pipeline_v2": [{"pass_id": "recover_dispatcher"}]},
        registry=state_machine_pass_registry(),
        live_specs=live_specs,
    )

    assert comparison.enabled is True
    assert comparison.matches is False
    assert comparison.configured_pass_ids == ("recover_dispatcher",)
    assert comparison.live_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.spec_comparison is not None
    assert comparison.spec_comparison.missing_pass_ids == tuple(
        spec.pass_id for spec in live_specs[1:]
    )


def test_pipeline_v2_shadow_requirement_raises_for_short_config():
    live_specs = standard_state_machine_passes()

    with pytest.raises(PipelineShadowMismatchError) as excinfo:
        require_pipeline_v2_shadow_match(
            project_config={"pipeline_v2": [{"pass_id": "recover_dispatcher"}]},
            registry=state_machine_pass_registry(),
            live_specs=live_specs,
        )

    comparison = excinfo.value.comparison
    assert comparison.configured_pass_ids == ("recover_dispatcher",)
    assert comparison.live_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.spec_comparison is not None
    assert comparison.spec_comparison.missing_pass_ids == tuple(
        spec.pass_id for spec in live_specs[1:]
    )
    assert "missing=" in str(excinfo.value)
    assert "configs_match=False" in str(excinfo.value)


def test_pipeline_v2_shadow_requirement_raises_for_config_drift():
    live_specs = standard_state_machine_passes()
    configs = [spec.config.to_dict() for spec in live_specs]
    configs[0]["contract"]["safety"]["policy"] = "guarded-rewrite"

    with pytest.raises(PipelineShadowMismatchError) as excinfo:
        require_pipeline_v2_shadow_match(
            project_config={"pipeline_v2": configs},
            registry=state_machine_pass_registry(),
            live_specs=live_specs,
        )

    comparison = excinfo.value.comparison
    assert comparison.configured_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.live_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.spec_comparison is not None
    assert comparison.spec_comparison.pass_ids_match is True
    assert comparison.spec_comparison.configs_match is False
    assert "configs_match=False" in str(excinfo.value)


def test_pipeline_v2_shadow_comparison_rejects_unknown_pass_id():
    with pytest.raises(UnknownPassIdError, match="unknown pass id"):
        compare_pipeline_v2_shadow(
            project_config={"pipeline_v2": [{"pass_id": "not_registered"}]},
            registry=state_machine_pass_registry(),
            live_specs=standard_state_machine_passes(),
        )


def test_pipeline_v2_shadow_requirement_rejects_unknown_pass_id():
    with pytest.raises(UnknownPassIdError, match="unknown pass id"):
        require_pipeline_v2_shadow_match(
            project_config={"pipeline_v2": [{"pass_id": "not_registered"}]},
            registry=state_machine_pass_registry(),
            live_specs=standard_state_machine_passes(),
        )
