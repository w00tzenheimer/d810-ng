"""Legacy ProjectConfiguration to PipelineConfig v2 shadow migration tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_migrator import (
    LegacyBlockRuleAdapterKind,
    LegacyConfigMigrationStatus,
    inventory_legacy_config_directory,
    inventory_legacy_project_config,
    legacy_block_rule_adapter_boundary,
    legacy_project_config_to_pipeline_v2_shadow,
    legacy_project_file_to_pipeline_v2_shadow,
)


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"
_OLLVM_CONFIGS = (
    "default_unflattening_ollvm",
    "default_unflattening_ollvm_s1a_fair",
)
_OLLVM_BLOCK_RULES = (
    "IndirectCallResolver",
    "MbaStatePreconditioner",
    "StateMachineCffUnflattener",
    "SimpleFlatteningCleanupUnflattener",
    "JumpFixer",
)
_STATE_MACHINE_NATIVE_PIPELINE = (
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)
_GENERATED_SHADOW_CONFIGS = (
    "bogus_loops",
    "default_instruction_only",
    "default_unflattening_approov",
    "default_unflattening_approov_s1a",
    "default_unflattening_switch_case",
    "default_unflattening_tigress_engine",
    "default_unflattening_tigress_engine_transition_facts",
    "default_unflattening_tigress_indirect",
    "eidolon",
    "example_anel",
    "example_hodur",
    "example_libobfuscated",
    "example_libobfuscated_abc",
    "flatfold",
    "flatfold_no_predicate_loop_fix",
    "hodur_deobfuscation",
    "hodur_flag2",
    "hodur_flag2_s1a",
    "hodur_flag2_with_fcp",
    "hodur_glbopt2_only",
)
_REMAINING_GENERATED_SHADOWS = (
    ("bogus_loops", 0, ("MbaStatePreconditioner", "JumpFixer")),
    (
        "default_unflattening_approov",
        178,
        ("MbaStatePreconditioner", "StateMachineCffUnflattener", "JumpFixer"),
    ),
    (
        "default_unflattening_approov_s1a",
        178,
        ("MbaStatePreconditioner", "StateMachineCffUnflattener", "JumpFixer"),
    ),
    ("eidolon", 172, ()),
    ("example_anel", 179, ("JumpFixer",)),
    (
        "example_hodur",
        185,
        ("ForwardConstantPropagationRule", "StateMachineCffUnflattener", "JumpFixer"),
    ),
    (
        "example_libobfuscated_abc",
        198,
        ("ForwardConstantPropagationRule", "StateMachineCffUnflattener", "JumpFixer"),
    ),
    (
        "flatfold",
        157,
        (
            "MbaStatePreconditioner",
            "GlobalConstantInliner",
            "JumpFixer",
            "StateMachineCffUnflattener",
        ),
    ),
    ("flatfold_no_predicate_loop_fix", 177, ("JumpFixer",)),
    (
        "hodur_flag2_with_fcp",
        3,
        ("StateMachineCffUnflattener", "JumpFixer", "ForwardConstantPropagationRule"),
    ),
    ("hodur_glbopt2_only", 0, ("StateMachineCffUnflattener",)),
)


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _inventory_by_name():
    return {
        item.config_name: item
        for item in inventory_legacy_config_directory(_CONF_DIR)
    }


def _unique_active_instruction_rule_names(rules):
    names = []
    seen = set()
    for rule in rules:
        if not rule.is_activated or rule.name in seen:
            continue
        seen.add(rule.name)
        names.append(rule.name)
    return names


def _assert_block_entries_preserve_legacy_rules(
    block_entries,
    active_block_rules,
    *,
    source_config,
):
    cursor = 0
    for rule in active_block_rules:
        if rule.name == "StateMachineCffUnflattener":
            expanded = block_entries[
                cursor: cursor + len(_STATE_MACHINE_NATIVE_PIPELINE)
            ]
            assert [entry["pass"] for entry in expanded] == list(
                _STATE_MACHINE_NATIVE_PIPELINE
            )
            for index, entry in enumerate(expanded):
                assert entry["migration"] == {
                    "source_config": source_config,
                    "source_section": "blk_rules",
                    "source_rule": "StateMachineCffUnflattener",
                    "expansion": "native_state_machine_spine",
                    "stage_index": index,
                    "stage_count": len(_STATE_MACHINE_NATIVE_PIPELINE),
                }
                options = dict(entry["options"])
                assert options.pop("legacy_rule") == rule.name
                assert options.pop("legacy_rule_options") == rule.config
                assert options.pop("native_pipeline") == list(
                    _STATE_MACHINE_NATIVE_PIPELINE
                )
                assert options == {}
            cursor += len(_STATE_MACHINE_NATIVE_PIPELINE)
            continue

        entry = block_entries[cursor]
        assert entry["migration"]["source_rule"] == rule.name
        options = dict(entry["options"])
        assert options.pop("legacy_rule") == rule.name
        assert options == rule.config
        cursor += 1

    assert cursor == len(block_entries)


@pytest.mark.parametrize(
    ("rule_name", "pass_id"),
    [
        ("BlockLevelEgglogOptimizer", "block-level-egglog-optimizer"),
        ("GlobalConstantInliner", "global-constant-inliner"),
        ("ForwardConstantPropagationRule", "forward-constant-propagation"),
        ("MbaStatePreconditioner", "mba-state-preconditioner"),
        ("JumpFixer", "jump-fixer"),
    ],
)
def test_legacy_block_rule_adapter_boundary_classifies_shadow_passes(
    rule_name,
    pass_id,
):
    boundary = legacy_block_rule_adapter_boundary(rule_name)

    assert boundary.rule_name == rule_name
    assert boundary.adapter_kind is (
        LegacyBlockRuleAdapterKind.PIPELINE_V2_SHADOW_PASS
    )
    assert boundary.supported is True
    assert boundary.pass_id == pass_id
    assert boundary.reason == ""
    assert boundary.to_dict() == {
        "rule": rule_name,
        "adapter_kind": "pipeline_v2_shadow_pass",
        "supported": True,
        "pass_id": pass_id,
        "reason": "",
    }


def test_legacy_block_rule_adapter_boundary_classifies_state_machine_spine():
    boundary = legacy_block_rule_adapter_boundary("StateMachineCffUnflattener")

    assert boundary.rule_name == "StateMachineCffUnflattener"
    assert boundary.adapter_kind is LegacyBlockRuleAdapterKind.NATIVE_STATE_MACHINE_SPINE
    assert boundary.supported is True
    assert boundary.pass_id is None
    assert boundary.reason == "expands to the native state-machine spine"
    assert boundary.to_dict() == {
        "rule": "StateMachineCffUnflattener",
        "adapter_kind": "native_state_machine_spine",
        "supported": True,
        "pass_id": None,
        "reason": "expands to the native state-machine spine",
    }


@pytest.mark.parametrize(
    ("rule_name", "adapter_kind", "reason"),
    [
        (
            "IndirectCallResolver",
            LegacyBlockRuleAdapterKind.LEGACY_FLOW_RULE_ADAPTER,
            "IDA-backed indirect-call FlowOptimizationRule adapter",
        ),
        (
            "SimpleFlatteningCleanupUnflattener",
            LegacyBlockRuleAdapterKind.CLEANUP_FAMILY_ADAPTER,
            "cleanup-family planner/executor adapter",
        ),
    ],
)
def test_legacy_block_rule_adapter_boundary_classifies_ollvm_blockers(
    rule_name,
    adapter_kind,
    reason,
):
    boundary = legacy_block_rule_adapter_boundary(rule_name)

    assert boundary.rule_name == rule_name
    assert boundary.adapter_kind is adapter_kind
    assert boundary.supported is False
    assert boundary.pass_id is None
    assert reason in boundary.reason


def test_legacy_block_rule_adapter_boundary_fails_unknown_rules_closed():
    boundary = legacy_block_rule_adapter_boundary("UnsupportedLegacyRule")

    assert boundary.rule_name == "UnsupportedLegacyRule"
    assert boundary.adapter_kind is LegacyBlockRuleAdapterKind.UNKNOWN
    assert boundary.supported is False
    assert boundary.pass_id is None
    assert boundary.reason == "no config-v2 adapter boundary registered"


@pytest.mark.parametrize(
    "config_name",
    _GENERATED_SHADOW_CONFIGS,
)
def test_legacy_migrator_matches_checked_in_shadow(config_name):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    shadow_path = _CONF_DIR / f"{config_name}.pipeline_v2.json"

    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)

    assert generated == _load_json(shadow_path)


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_uses_explicit_instruction_rule_includes(config_name):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    rules = instruction_entry["rules"]

    assert "include_groups" not in rules
    assert "exclude_groups" not in rules
    assert rules["include"] == [
        rule.name
        for rule in legacy.ins_rules
        if rule.is_activated
    ]
    assert rules["exclude"] == []


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_preserves_non_empty_instruction_rule_options(config_name):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]

    assert instruction_entry["rules"]["options"] == {
        rule.name: rule.config
        for rule in legacy.ins_rules
        if rule.is_activated and rule.config
    }


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_keeps_z3_capability_for_current_shadow_configs(config_name):
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / f"{config_name}.json"
    )

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]

    assert instruction_entry["requires"]["capabilities"] == [
        "local_instruction_rewrite",
        "z3_solver",
    ]


def test_legacy_migrator_omits_z3_capability_without_solver_backed_rules():
    project = ProjectConfiguration(
        path=Path("no_z3.json"),
        ins_rules=[
            RuleConfiguration(
                name="FoldReadonlyDataRule",
                is_activated=True,
            ),
            RuleConfiguration(
                name="Z3ConstantOptimization",
                is_activated=False,
            ),
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    assert instruction_entry["requires"]["capabilities"] == [
        "local_instruction_rewrite"
    ]


@pytest.mark.parametrize("rule_name", ["Z3ConstantOptimization", "Z3setzRuleGeneric"])
def test_legacy_migrator_adds_z3_capability_for_solver_backed_rules(rule_name):
    project = ProjectConfiguration(
        path=Path("with_z3.json"),
        ins_rules=[
            RuleConfiguration(
                name="FoldReadonlyDataRule",
                is_activated=True,
            ),
            RuleConfiguration(
                name=rule_name,
                is_activated=True,
            ),
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    assert instruction_entry["requires"]["capabilities"] == [
        "local_instruction_rewrite",
        "z3_solver",
    ]


def test_legacy_migrator_collapses_exact_duplicate_instruction_rules():
    project = ProjectConfiguration(
        path=Path("duplicate_rules.json"),
        ins_rules=[
            RuleConfiguration(
                name="Add_OllvmRule_1",
                is_activated=True,
                config={"dump_intermediate_microcode": None},
            ),
            RuleConfiguration(
                name="Add_OllvmRule_1",
                is_activated=True,
                config={"dump_intermediate_microcode": None},
            ),
            RuleConfiguration(
                name="Add_OllvmRule_2",
                is_activated=True,
            ),
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    assert instruction_entry["rules"]["include"] == [
        "Add_OllvmRule_1",
        "Add_OllvmRule_2",
    ]
    assert instruction_entry["rules"]["options"] == {
        "Add_OllvmRule_1": {"dump_intermediate_microcode": None}
    }


def test_legacy_migrator_rejects_conflicting_duplicate_instruction_rules():
    project = ProjectConfiguration(
        path=Path("duplicate_rules.json"),
        ins_rules=[
            RuleConfiguration(
                name="Add_OllvmRule_1",
                is_activated=True,
                config={"dump_intermediate_microcode": None},
            ),
            RuleConfiguration(
                name="Add_OllvmRule_1",
                is_activated=True,
                config={"dump_intermediate_microcode": True},
            ),
        ],
    )

    with pytest.raises(
        PipelineConfigError,
        match="duplicate active instruction rule has conflicting config: Add_OllvmRule_1",
    ):
        legacy_project_config_to_pipeline_v2_shadow(project)


def test_legacy_migrator_preserves_example_additional_pipeline_metadata():
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / "example_libobfuscated.json"
    )

    assert generated["additional_configuration"]["pipeline_v2_shadow"] == {
        "source_config": "example_libobfuscated.json",
        "runtime_source": "legacy",
        "enable_pass_pipeline": True,
    }


def test_legacy_migrator_maps_default_instruction_block_rules_explicitly():
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / "default_instruction_only.json"
    )
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]

    assert [entry["pass"] for entry in pipeline_v2] == [
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    ]
    assert pipeline_v2[1]["migration"] == {
        "source_config": "default_instruction_only.json",
        "source_section": "blk_rules",
        "source_rule": "GlobalConstantInliner",
    }
    assert pipeline_v2[2]["options"]["legacy_rule"] == "JumpFixer"
    assert "JmpRuleZ3Const" in pipeline_v2[2]["options"]["enabled_rules"]


def test_legacy_migrator_rejects_unknown_active_block_rules():
    project = ProjectConfiguration(
        path=Path("unknown.json"),
        blk_rules=[
            RuleConfiguration(
                name="UnsupportedLegacyRule",
                is_activated=True,
            )
        ],
    )

    with pytest.raises(
        PipelineConfigError,
        match="unsupported legacy block rule",
    ):
        legacy_project_config_to_pipeline_v2_shadow(project)


def test_legacy_inventory_reports_unknown_active_block_rules_structurally():
    project = ProjectConfiguration(
        path=Path("unknown.json"),
        blk_rules=[
            RuleConfiguration(
                name="UnsupportedLegacyRule",
                is_activated=True,
            )
        ],
    )

    item = inventory_legacy_project_config(project)

    assert item.status is LegacyConfigMigrationStatus.UNSUPPORTED
    assert item.config_name == "unknown.json"
    assert item.active_instruction_rules == 0
    assert item.active_block_rules == ("UnsupportedLegacyRule",)
    assert "UnsupportedLegacyRule" in item.reason
    assert item.to_dict()["status"] == "unsupported"


def test_legacy_migrator_ignores_unknown_inactive_block_rules():
    project = ProjectConfiguration(
        path=Path("inactive.json"),
        ins_rules=[
            RuleConfiguration(
                name="FoldReadonlyDataRule",
                is_activated=True,
            )
        ],
        blk_rules=[
            RuleConfiguration(
                name="UnsupportedLegacyRule",
                is_activated=False,
            )
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    assert [entry["pass"] for entry in pipeline_v2] == ["mba-simplify"]


def test_empty_legacy_config_is_inventory_empty_and_not_generated():
    project = ProjectConfiguration(path=Path("empty.json"))

    item = inventory_legacy_project_config(project)

    assert item.status is LegacyConfigMigrationStatus.EMPTY
    assert item.active_instruction_rules == 0
    assert item.active_block_rules == ()
    assert item.reason == "no active legacy rules"
    with pytest.raises(PipelineConfigError, match="no active legacy rules"):
        legacy_project_config_to_pipeline_v2_shadow(project)


def test_checked_in_pipeline_v2_shadows_are_not_empty_pipeline_payloads():
    for path in sorted(_CONF_DIR.glob("*.pipeline_v2.json")):
        payload = _load_json(path)
        assert payload["additional_configuration"]["pipeline_v2"]


def test_repo_legacy_config_inventory_reports_current_state():
    inventory = _inventory_by_name()

    assert len(inventory) == 26
    assert [
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.EMPTY
    ] == []
    assert {
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.UNSUPPORTED
    } == {
        "default.json",
        "default_indirect_resolution.json",
        "default_unflattening_ollvm.json",
        "default_unflattening_ollvm_s1a_fair.json",
        "example_libobfuscated_no_fixprecedessor.json",
        "identity_call.json",
    }
    assert {
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.MIGRATABLE
    } == {
        "bogus_loops.json",
        "default_instruction_only.json",
        "default_unflattening_approov.json",
        "default_unflattening_approov_s1a.json",
        "default_unflattening_switch_case.json",
        "default_unflattening_tigress_engine.json",
        "default_unflattening_tigress_engine_transition_facts.json",
        "default_unflattening_tigress_indirect.json",
        "eidolon.json",
        "example_anel.json",
        "example_hodur.json",
        "example_libobfuscated.json",
        "example_libobfuscated_abc.json",
        "flatfold.json",
        "flatfold_no_predicate_loop_fix.json",
        "hodur_deobfuscation.json",
        "hodur_flag2.json",
        "hodur_flag2_s1a.json",
        "hodur_flag2_with_fcp.json",
        "hodur_glbopt2_only.json",
    }


def test_repo_inventory_excludes_options_and_existing_shadow_configs():
    inventory = _inventory_by_name()

    assert "options.json" not in inventory
    assert "default_instruction_only.pipeline_v2.json" not in inventory
    assert "example_libobfuscated.pipeline_v2.json" not in inventory


def test_repo_inventory_surfaces_unsupported_reasons():
    inventory = _inventory_by_name()

    assert "IndirectCallResolver" in inventory["default.json"].reason
    assert inventory["default_unflattening_ollvm.json"].status is (
        LegacyConfigMigrationStatus.UNSUPPORTED
    )
    assert (
        "SimpleFlatteningCleanupUnflattener"
        in inventory["default_unflattening_ollvm.json"].reason
    )
    assert (
        "SimpleFlatteningCleanupUnflattener"
        in inventory["example_libobfuscated_no_fixprecedessor.json"].reason
    )
    assert "IdentityCallResolver" in inventory["identity_call.json"].reason


@pytest.mark.parametrize("config_name", _OLLVM_CONFIGS)
def test_ollvm_configs_remain_inventory_unsupported_pending_adapters(config_name):
    inventory = _inventory_by_name()
    item = inventory[f"{config_name}.json"]

    assert item.status is LegacyConfigMigrationStatus.UNSUPPORTED
    assert item.active_instruction_rules == 180
    assert item.active_block_rules == _OLLVM_BLOCK_RULES
    assert (
        "IndirectCallResolver "
        "(requires an IDA-backed indirect-call FlowOptimizationRule adapter)"
        in item.reason
    )
    assert (
        "SimpleFlatteningCleanupUnflattener "
        "(requires a cleanup-family planner/executor adapter)"
        in item.reason
    )

    with pytest.raises(
        PipelineConfigError,
        match="IndirectCallResolver",
    ):
        legacy_project_file_to_pipeline_v2_shadow(_CONF_DIR / f"{config_name}.json")


def test_ollvm_pipeline_v2_shadows_are_not_generated_while_unsupported():
    for config_name in _OLLVM_CONFIGS:
        assert not (_CONF_DIR / f"{config_name}.pipeline_v2.json").exists()


@pytest.mark.parametrize(
    ("config_name", "expected_instruction_rules", "expected_block_rules"),
    _REMAINING_GENERATED_SHADOWS,
)
def test_remaining_generated_shadows_preserve_legacy_rule_shape(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    active_instruction_rules = [
        rule for rule in legacy.ins_rules if rule.is_activated
    ]
    active_block_rules = [
        rule for rule in legacy.blk_rules if rule.is_activated
    ]

    assert len(active_instruction_rules) == expected_instruction_rules
    assert tuple(rule.name for rule in active_block_rules) == expected_block_rules
    if active_instruction_rules:
        instruction_entry = pipeline_v2[0]
        assert instruction_entry["pass"] == "mba-simplify"
        assert instruction_entry["rules"]["include"] == (
            _unique_active_instruction_rule_names(active_instruction_rules)
        )
        assert instruction_entry["rules"]["options"] == {
            rule.name: rule.config
            for rule in active_instruction_rules
            if rule.config
        }
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        block_entries = pipeline_v2[1:]
    else:
        block_entries = pipeline_v2

    _assert_block_entries_preserve_legacy_rules(
        block_entries,
        active_block_rules,
        source_config=f"{config_name}.json",
    )


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
def test_hodur_generated_shadows_preserve_legacy_rule_shape(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    active_instruction_rules = [
        rule for rule in legacy.ins_rules if rule.is_activated
    ]
    active_block_rules = [
        rule for rule in legacy.blk_rules if rule.is_activated
    ]

    assert len(active_instruction_rules) == expected_instruction_rules
    assert [rule.name for rule in active_block_rules] == expected_block_rules
    if active_instruction_rules:
        instruction_entry = pipeline_v2[0]
        assert instruction_entry["pass"] == "mba-simplify"
        assert instruction_entry["rules"]["include"] == (
            _unique_active_instruction_rule_names(active_instruction_rules)
        )
        assert instruction_entry["rules"]["options"] == {
            rule.name: rule.config
            for rule in active_instruction_rules
            if rule.config
        }
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        block_entries = pipeline_v2[1:]
    else:
        block_entries = pipeline_v2

    _assert_block_entries_preserve_legacy_rules(
        block_entries,
        active_block_rules,
        source_config=f"{config_name}.json",
    )


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
def test_tigress_switch_generated_shadows_preserve_legacy_rule_shape(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    active_instruction_rules = [
        rule for rule in legacy.ins_rules if rule.is_activated
    ]
    active_block_rules = [
        rule for rule in legacy.blk_rules if rule.is_activated
    ]

    assert len(active_instruction_rules) == expected_instruction_rules
    assert [rule.name for rule in active_block_rules] == expected_block_rules
    if active_instruction_rules:
        instruction_entry = pipeline_v2[0]
        assert instruction_entry["pass"] == "mba-simplify"
        assert instruction_entry["rules"]["include"] == (
            _unique_active_instruction_rule_names(active_instruction_rules)
        )
        assert instruction_entry["rules"]["options"] == {
            rule.name: rule.config
            for rule in active_instruction_rules
            if rule.config
        }
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        block_entries = pipeline_v2[1:]
    else:
        block_entries = pipeline_v2

    _assert_block_entries_preserve_legacy_rules(
        block_entries,
        active_block_rules,
        source_config=f"{config_name}.json",
    )
