"""Legacy ProjectConfiguration to PipelineConfig v2 shadow migration tests."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.legacy_flow_rules import LEGACY_FLOW_RULE_ADAPTER_CAPABILITY
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_migrator import (
    LegacyBlockRuleAdapterKind,
    LegacyConfigMigrationStatus,
    inventory_legacy_config_directory,
    inventory_legacy_project_config,
    is_config_v2_runtime_project,
    legacy_block_rule_adapter_boundary,
    legacy_project_config_to_pipeline_v2_shadow,
    legacy_project_file_to_pipeline_v2_shadow,
)
from d810.passes.pipeline_config_parser import pass_specs_from_project_config
from d810.passes.registry import UnknownPassIdError


_REPO_ROOT = Path(__file__).resolve().parents[3]
_README = _REPO_ROOT / "README.md"
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"
_RUNTIME_SUPPORT_MATRIX = (
    _REPO_ROOT / "src" / "d810" / "passes" / "config_v2_runtime_support_matrix.json"
)
_RUNTIME_PARITY_TEST = _REPO_ROOT / "tests" / "system" / "e2e" / (
    "test_config_v2_runtime_parity.py"
)
_OLLVM_CONFIGS = (
    "default_unflattening_ollvm",
    "default_unflattening_ollvm_s1a_fair",
)
_CONFIG_V2_CANARY_CONFIGS = (
    "hodur_flag2_config_v2_canary",
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
    "identity_call",
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
    ("identity_call", 0, ("IdentityCallResolver",)),
)


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_runtime_support_matrix() -> dict[str, object]:
    return _load_json(_RUNTIME_SUPPORT_MATRIX)


def _inventory_by_name():
    return {
        item.config_name: item
        for item in inventory_legacy_config_directory(_CONF_DIR)
    }


def _parity_test_row_ids() -> set[str]:
    tree = ast.parse(_RUNTIME_PARITY_TEST.read_text(encoding="utf-8"))
    row_ids: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "ConfigV2ParityRow":
            continue
        for keyword in node.keywords:
            if keyword.arg != "row_id":
                continue
            if isinstance(keyword.value, ast.Constant) and isinstance(
                keyword.value.value, str
            ):
                row_ids.add(keyword.value.value)
    return row_ids


def _assert_builds_with_operational_registry(config_name: str):
    project = ProjectConfiguration.from_file(_CONF_DIR / config_name)
    specs = pass_specs_from_project_config(project, operational_config_v2_pass_registry())

    assert specs
    return specs


def _expected_unsupported_reason_tokens(config_name: str) -> tuple[str, ...]:
    if config_name in {"default.json", "default_indirect_resolution.json"}:
        return ("IndirectBranchResolver", "IndirectCallResolver")
    if config_name in {
        "default_unflattening_ollvm.json",
        "default_unflattening_ollvm_s1a_fair.json",
    }:
        return ("IndirectCallResolver", "SimpleFlatteningCleanupUnflattener")
    if config_name == "example_libobfuscated_no_fixprecedessor.json":
        return ("SimpleFlatteningCleanupUnflattener",)
    raise AssertionError(f"unsupported config lacks explicit matrix expectation: {config_name}")


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
        ("IdentityCallResolver", "identity-call-resolver"),
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
            "IndirectBranchResolver",
            LegacyBlockRuleAdapterKind.LEGACY_FLOW_RULE_ADAPTER,
            "IDA-backed indirect-branch FlowOptimizationRule adapter",
        ),
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
def test_legacy_block_rule_adapter_boundary_classifies_unsupported_boundaries(
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
    _GENERATED_SHADOW_CONFIGS,
)
def test_generated_shadow_description_uses_default_runtime_wording(config_name):
    shadow = _load_json(_CONF_DIR / f"{config_name}.pipeline_v2.json")
    description = shadow["description"]

    assert "source project JSON remains the default runtime source" in description
    assert "legacy JSON remains" not in description


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


def test_legacy_migrator_marks_simple_block_rules_with_adapter_capability():
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / "hodur_flag2.json"
    )

    jump_entry = generated["additional_configuration"]["pipeline_v2"][-1]

    assert jump_entry["pass"] == "jump-fixer"
    assert jump_entry["requires"]["capabilities"] == [
        LEGACY_FLOW_RULE_ADAPTER_CAPABILITY
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
        "identity_call.json",
    }


def test_repo_inventory_excludes_options_and_existing_shadow_configs():
    inventory = _inventory_by_name()

    assert "options.json" not in inventory
    assert "default_instruction_only.pipeline_v2.json" not in inventory
    assert "example_libobfuscated.pipeline_v2.json" not in inventory
    assert "hodur_flag2_config_v2_canary.json" not in inventory


@pytest.mark.parametrize("config_name", _CONFIG_V2_CANARY_CONFIGS)
def test_config_v2_canaries_are_not_legacy_migration_inputs(config_name):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")
    inventory = _inventory_by_name()

    assert is_config_v2_runtime_project(project)
    assert f"{config_name}.json" not in inventory
    assert project.ins_rules == []
    assert project.blk_rules == []
    assert project.additional_configuration["pipeline_v2_mode"] == "config-v2"
    assert project.additional_configuration["pipeline_v2"]


def test_repo_inventory_surfaces_unsupported_reasons():
    inventory = _inventory_by_name()

    assert (
        "IndirectBranchResolver "
        "(requires an IDA-backed indirect-branch FlowOptimizationRule adapter)"
        in inventory["default.json"].reason
    )
    assert (
        "IndirectCallResolver "
        "(requires an IDA-backed indirect-call FlowOptimizationRule adapter)"
        in inventory["default.json"].reason
    )
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
    assert inventory["identity_call.json"].status is LegacyConfigMigrationStatus.MIGRATABLE


def test_config_v2_runtime_support_matrix_matches_inventory_and_evidence():
    matrix = _load_runtime_support_matrix()
    inventory = _inventory_by_name()

    migratable = {
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.MIGRATABLE
    }
    unsupported = {
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.UNSUPPORTED
    }

    assert matrix["default_runtime_mode"] == "legacy"
    assert matrix["explicit_runtime_mode"] == "config-v2"
    assert matrix["source_of_truth"] == "pipeline_v2"
    assert set(matrix["generated_shadows"]["migratable_configs"]) == migratable
    assert matrix["generated_shadows"]["legacy_config_count"] == len(inventory)
    assert matrix["generated_shadows"]["migratable_count"] == len(migratable)
    assert matrix["generated_shadows"]["unsupported_count"] == len(unsupported)
    assert matrix["generated_shadows"]["migratable_missing_shadow_count"] == 0

    parity_rows = {
        row["id"]: row for row in matrix["parity_evidence"]["rows"]
    }
    assert set(parity_rows) == {
        "default_instruction_only_mba",
        "eidolon_mba_instruction_heavy",
        "tigress_engine_spine",
        "approov_mixed_spine_flow",
        "hodur_glbopt2_only_spine",
        "hodur_flag2_mixed",
        "hodur_flag2_s1a_mixed",
        "hodur_flag2_with_fcp_mixed",
        "hodur_flag2_config_v2_canary_mixed",
        "identity_call_explicit_adapter",
    }
    assert parity_rows["eidolon_mba_instruction_heavy"] == {
        "id": "eidolon_mba_instruction_heavy",
        "legacy_config": "eidolon.json",
        "shadow_config": "eidolon.pipeline_v2.json",
        "ast_stats_match": True,
        "stable_diag_parity": True,
        "allowed_diag_drift": [],
    }
    assert parity_rows["tigress_engine_spine"] == {
        "id": "tigress_engine_spine",
        "legacy_config": "default_unflattening_tigress_engine.json",
        "shadow_config": "default_unflattening_tigress_engine.pipeline_v2.json",
        "ast_stats_match": True,
        "stable_diag_parity": True,
        "allowed_diag_drift": [],
    }
    assert parity_rows["approov_mixed_spine_flow"] == {
        "id": "approov_mixed_spine_flow",
        "legacy_config": "default_unflattening_approov.json",
        "shadow_config": "default_unflattening_approov.pipeline_v2.json",
        "ast_stats_match": True,
        "stable_diag_parity": True,
        "allowed_diag_drift": [],
    }
    assert parity_rows["hodur_flag2_mixed"]["allowed_diag_drift"] == []
    assert parity_rows["hodur_flag2_s1a_mixed"]["allowed_diag_drift"] == []
    assert parity_rows["hodur_flag2_with_fcp_mixed"]["allowed_diag_drift"] == []
    assert parity_rows["hodur_flag2_config_v2_canary_mixed"] == {
        "id": "hodur_flag2_config_v2_canary_mixed",
        "legacy_config": "hodur_flag2.json",
        "runtime_config": "hodur_flag2_config_v2_canary.json",
        "shadow_config": "hodur_flag2.pipeline_v2.json",
        "ast_stats_match": True,
        "stable_diag_parity": True,
        "allowed_diag_drift": [],
    }
    assert parity_rows["identity_call_explicit_adapter"] == {
        "id": "identity_call_explicit_adapter",
        "legacy_config": "identity_call.json",
        "shadow_config": "identity_call.pipeline_v2.json",
        "ast_stats_match": True,
        "stable_diag_parity": True,
        "allowed_diag_drift": [],
    }
    assert matrix["parity_evidence"]["summary"].startswith(
        f"{len(parity_rows)} passed,"
    )
    assert matrix["parity_evidence"]["docker_log"].endswith(
        "config-v2-identity-call-adapter-v1-parity.log"
    )

    canaries = {
        item["config"]: item for item in matrix["canary_configs"]
    }
    assert canaries == {
        "hodur_flag2_config_v2_canary.json": {
            "id": "hodur_flag2_config_v2_canary",
            "config": "hodur_flag2_config_v2_canary.json",
            "source_config": "hodur_flag2.json",
            "source_shadow": "hodur_flag2.pipeline_v2.json",
            "representative_row": "hodur_flag2_config_v2_canary_mixed",
            "runtime_mode": "config-v2",
        }
    }
    assert matrix["opt_in_rollout"]["status"] == "supported-canary"
    assert matrix["opt_in_rollout"]["default_runtime_mode"] == "legacy"
    assert matrix["opt_in_rollout"]["required_mode"] == "config-v2"
    assert matrix["opt_in_rollout"]["user_selectable_configs"] == [
        {
            "config": "hodur_flag2_config_v2_canary.json",
            "source_config": "hodur_flag2.json",
            "source_shadow": "hodur_flag2.pipeline_v2.json",
            "parity_row": "hodur_flag2_config_v2_canary_mixed",
            "normal_project_config_loading_path": True,
            "lanes": [
                "native_state_machine_spine",
                "mixed_spine_simple_flow_rule",
            ],
        }
    ]

    lane_ids = {lane["id"] for lane in matrix["runtime_lanes"]}
    assert lane_ids == {
        "mba_instruction_hook",
        "native_state_machine_spine",
        "mixed_spine_simple_flow_rule",
        "mixed_spine_instruction_simple_flow_rule",
        "identity_call_flow_rule",
    }
    assert {
        item["config"] for item in matrix["unsupported_adapter_boundaries"]
    } == unsupported


def test_config_v2_runtime_support_matrix_opt_in_configs_are_selectable():
    matrix = _load_runtime_support_matrix()
    parity_rows = {row["id"]: row for row in matrix["parity_evidence"]["rows"]}
    lane_ids = {lane["id"] for lane in matrix["runtime_lanes"]}
    canary_configs = {item["config"] for item in matrix["canary_configs"]}

    rollout = matrix["opt_in_rollout"]
    assert rollout["default_runtime_mode"] == matrix["default_runtime_mode"]
    assert rollout["required_mode"] == matrix["explicit_runtime_mode"]
    assert "default runtime source" in rollout["selection_model"]
    assert "existing project configs remain" in rollout["selection_model"]
    assert "legacy configs remain" not in rollout["selection_model"]
    assert "Unsupported adapter boundaries stay fail-closed" in (
        rollout["unsupported_policy"]
    )
    rollout_log_path = Path(rollout["docker_log"])
    assert rollout_log_path.parts[:2] == (".tmp", "logs")
    assert rollout_log_path.name.endswith(".log")
    assert re.fullmatch(
        r"\d+ passed, \d+ skipped, \d+ deselected, \d+ warnings",
        rollout["summary"],
    )

    user_selectable_configs = rollout["user_selectable_configs"]
    assert user_selectable_configs
    for config in user_selectable_configs:
        assert config["config"] in canary_configs
        assert set(config["lanes"]) <= lane_ids
        assert config["normal_project_config_loading_path"] is True

        project = ProjectConfiguration.from_file(_CONF_DIR / config["config"])
        assert is_config_v2_runtime_project(project)
        assert project.ins_rules == []
        assert project.blk_rules == []

        row = parity_rows[config["parity_row"]]
        assert row["legacy_config"] == config["source_config"]
        assert row["shadow_config"] == config["source_shadow"]
        assert row["runtime_config"] == config["config"]

        specs = _assert_builds_with_operational_registry(config["config"])
        assert tuple(spec.pass_id for spec in specs)


def test_readme_documents_config_v2_canary_selection_note():
    matrix = _load_runtime_support_matrix()
    readme = _README.read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    rollout = matrix["opt_in_rollout"]

    assert "Config-v2 opt-in canary" in readme
    assert rollout["default_runtime_mode"] == "legacy"
    assert "default runtime remains the existing project configuration path" in (
        normalized_readme
    )
    assert f"pipeline_v2_mode: {rollout['required_mode']}" in normalized_readme

    for config in rollout["user_selectable_configs"]:
        assert config["config"] in readme
    for boundary in ("OLLVM", "indirect branch/call", "cleanup-family"):
        assert boundary in normalized_readme
    assert "identity-call remains unsupported" not in normalized_readme


def test_config_v2_runtime_support_matrix_parity_rows_are_executable_contracts():
    matrix = _load_runtime_support_matrix()
    parity_rows = matrix["parity_evidence"]["rows"]
    parity_test_row_ids = _parity_test_row_ids()

    assert parity_rows
    for row in parity_rows:
        assert row["id"] in parity_test_row_ids
        assert row["ast_stats_match"] is True
        assert row["stable_diag_parity"] is True
        assert set(row["allowed_diag_drift"]) <= {"fact_observations"}

        legacy_path = _CONF_DIR / row["legacy_config"]
        shadow_path = _CONF_DIR / row["shadow_config"]
        assert legacy_path.exists()
        assert shadow_path.exists()
        _assert_builds_with_operational_registry(row["shadow_config"])

        runtime_config = row.get("runtime_config")
        if runtime_config is not None:
            runtime_path = _CONF_DIR / runtime_config
            assert runtime_path.exists()
            _assert_builds_with_operational_registry(runtime_config)


def test_config_v2_runtime_support_matrix_supported_shadows_build():
    matrix = _load_runtime_support_matrix()
    operational_exceptions = {
        exception["shadow_config"]
        for exception in matrix["generated_shadows"]["operational_exceptions"]
    }
    supported_shadows = {
        row["shadow_config"] for row in matrix["parity_evidence"]["rows"]
    }
    supported_shadows.update(
        lane["representative_shadow"] for lane in matrix["runtime_lanes"]
    )
    supported_shadows.update(
        canary["source_shadow"] for canary in matrix["canary_configs"]
    )
    supported_shadows.update(
        config_name.replace(".json", ".pipeline_v2.json")
        for config_name in matrix["generated_shadows"]["migratable_configs"]
        if config_name.replace(".json", ".pipeline_v2.json")
        not in operational_exceptions
    )

    for shadow_config in sorted(supported_shadows):
        specs = _assert_builds_with_operational_registry(shadow_config)
        assert tuple(spec.pass_id for spec in specs)

    for shadow_config in sorted(operational_exceptions):
        with pytest.raises(UnknownPassIdError):
            _assert_builds_with_operational_registry(shadow_config)


def test_config_v2_runtime_support_matrix_unsupported_configs_fail_closed():
    matrix = _load_runtime_support_matrix()
    inventory = _inventory_by_name()

    for entry in matrix["unsupported_adapter_boundaries"]:
        config_name = entry["config"]
        item = inventory[config_name]

        assert item.status is LegacyConfigMigrationStatus.UNSUPPORTED
        assert entry["blocked_boundary"]
        for token in _expected_unsupported_reason_tokens(config_name):
            assert token in item.reason
        assert not (_CONF_DIR / config_name.replace(".json", ".pipeline_v2.json")).exists()
        with pytest.raises(PipelineConfigError):
            legacy_project_file_to_pipeline_v2_shadow(_CONF_DIR / config_name)


def test_config_v2_runtime_support_matrix_docker_evidence_metadata_is_well_formed():
    matrix = _load_runtime_support_matrix()
    evidence = matrix["parity_evidence"]
    log_path = Path(evidence["docker_log"])
    summary = evidence["summary"]

    assert log_path.parts[:2] == (".tmp", "logs")
    assert log_path.name.endswith(".log")
    assert re.fullmatch(
        r"\d+ passed, \d+ skipped, \d+ deselected, \d+ warnings",
        summary,
    )


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
