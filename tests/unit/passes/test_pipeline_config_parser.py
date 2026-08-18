"""Shadow parsing for optional PipelineConfig v2 project payloads."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.core.config import ProjectConfiguration
from d810.core.config import RuleConfiguration
from d810.ir.maturity import IRMaturity
from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.passes.pass_pipeline import (
    BackendRoute,
    PipelineConfigError,
)
from d810.passes.function_prior_config import (
    load_function_analysis_priors_from_config,
)
from d810.passes.pipeline_config_parser import (
    PipelineV2Mode,
    pipeline_configs_from_project_config,
    pipeline_v2_mode_from_project_config,
    pass_specs_from_project_config,
    require_config_v2_project,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
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


_REMAINING_GENERATED_SHADOWS = (
    (
        "bogus_loops",
        0,
        ["SingleTripLoopPeel", "MbaStatePreconditioner", "JumpFixer"],
        ["single-trip-loop-peel", "mba-state-preconditioner", "jump-fixer"],
        "single-trip-loop-peel",
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
    (Path("eidolon.json").stem, 172, [], ["mba-simplify"], "mba-simplify"),
    (
        "example_hodur",
        185,
        ["ForwardConstantPropagationRule", "StateMachineCffUnflattener", "JumpFixer"],
        [
            "constant-simplification",
            "mba-simplify",
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
            "constant-simplification",
            "mba-simplify",
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
            "JumpFixer",
            "StateMachineCffUnflattener",
        ],
        [
            "constant-simplification",
            "mba-simplify",
            "mba-state-preconditioner",
            "jump-fixer",
            *_STATE_MACHINE_NATIVE_PIPELINE,
        ],
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
            "constant-simplification",
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


def test_missing_pipeline_v2_is_inert_for_existing_project_configs():
    assert pipeline_configs_from_project_config({}) == ()
    project = SimpleNamespace(additional_configuration={"enable_pass_pipeline": True})
    assert pipeline_configs_from_project_config(project) == ()


def test_require_config_v2_project_rejects_active_legacy_rules_with_migration_command():
    project = SimpleNamespace(
        path=Path("/tmp/legacy-project.json"),
        ins_rules=[SimpleNamespace(is_activated=True)],
        blk_rules=[],
        additional_configuration={},
    )

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(project)


@pytest.mark.parametrize(
    "rule",
    [
        {"name": "inactive", "is_activated": 0, "config": {}},
        {"name": "inactive", "is_activated": False, "config": []},
        {"is_activated": False, "config": {}},
        {"name": None, "is_activated": False, "config": {}},
        {"name": "inactive", "is_activated": False, "config": {}, "extra": 1},
    ],
)
def test_require_config_v2_project_rejects_malformed_inactive_raw_rules(rule):
    document = {
        "ins_rules": [rule],
        "blk_rules": [],
        "additional_configuration": {"pipeline_v2": [{"pass_id": "recover_dispatcher"}]},
    }

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(document)


@pytest.mark.parametrize(
    "rule",
    [
        RuleConfiguration(name="inactive", is_activated=0, config={}),
        RuleConfiguration(name=None, is_activated=False, config={}),
        RuleConfiguration(name="inactive", is_activated=False, config=[]),
    ],
)
def test_require_config_v2_project_rejects_malformed_loaded_rule_objects(rule):
    project = SimpleNamespace(
        path=Path("/tmp/malformed-project.json"),
        ins_rules=[rule],
        blk_rules=[],
        additional_configuration={"pipeline_v2": [{"pass_id": "recover_dispatcher"}]},
    )

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(project)


def test_require_config_v2_project_rejects_explicit_non_mapping_additional_configuration():
    document = {
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": [],
        # This must not be treated as a bare additional-configuration mapping.
        "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
    }

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(document)


@pytest.mark.parametrize("field", ["ins_rules", "blk_rules"])
def test_require_config_v2_project_rejects_null_legacy_rule_arrays(field):
    document = {
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
        },
    }
    document[field] = None

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(document)


def test_require_config_v2_project_wraps_malformed_project_like_additional_configuration():
    project = SimpleNamespace(
        path=Path("/tmp/malformed-project-like.json"),
        ins_rules=[],
        blk_rules=[],
        additional_configuration=[],
    )

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(project)


def test_require_config_v2_project_does_not_accept_bare_additional_mapping():
    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project({"pipeline_v2": [{"pass_id": "recover_dispatcher"}]})


def test_require_config_v2_project_rejects_unknown_pass_ids():
    document = {
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "not-a-registered-pass"}]
        },
    }

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(document)


def test_require_config_v2_project_tolerates_empty_legacy_arrays_when_pipeline_exists():
    project = {
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2": [
                {
                    "pass_id": "recover_dispatcher",
                    "maturity_gates": ["GLOBAL_ANALYZED"],
                    "backend_route": "analysis_only",
                }
            ]
        },
    }

    configs = require_config_v2_project(project)

    assert tuple(config.pass_id for config in configs) == ("recover_dispatcher",)


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"additional_configuration": {"pipeline_v2": []}},
        {"additional_configuration": {"pipeline_v2": {"pass_id": "x"}}},
    ],
)
def test_require_config_v2_project_rejects_missing_empty_or_malformed_pipeline(
    document,
):
    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(document)


@pytest.mark.parametrize("mode", ["legacy", "shadow-check"])
def test_require_config_v2_project_rejects_legacy_execution_modes(mode):
    document = {
        "additional_configuration": {
            "pipeline_v2_mode": mode,
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
        }
    }

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        require_config_v2_project(document)


def test_require_config_v2_project_accepts_config_v2_mode_and_mode_omission():
    payload = [{"pass_id": "recover_dispatcher"}]

    assert require_config_v2_project(
        {"additional_configuration": {"pipeline_v2": payload}}
    )[0].pass_id == "recover_dispatcher"
    assert require_config_v2_project(
        {
            "additional_configuration": {
                "pipeline_v2_mode": "config-v2",
                "pipeline_v2": payload,
            }
        }
    )[0].pass_id == "recover_dispatcher"


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
    assert pipeline_v2_mode_from_project_config({"pipeline_v2_mode": value}) is expected


def test_pipeline_v2_mode_rejects_former_shadow_match_boolean():
    with pytest.raises(PipelineConfigError, match="former field"):
        pipeline_v2_mode_from_project_config({"require_pipeline_v2_shadow_match": True})


@pytest.mark.parametrize("value", [True, 1, [], {}])
def test_pipeline_v2_mode_rejects_non_string_values(value):
    with pytest.raises(PipelineConfigError, match="pipeline_v2_mode must be a string"):
        pipeline_v2_mode_from_project_config({"pipeline_v2_mode": value})


def test_pipeline_v2_mode_rejects_unknown_values():
    with pytest.raises(PipelineConfigError, match="pipeline_v2_mode must be one of"):
        pipeline_v2_mode_from_project_config({"pipeline_v2_mode": "execute"})


def test_pipeline_v2_mode_rejects_former_shadow_boolean_even_with_explicit_mode():
    with pytest.raises(PipelineConfigError, match="former field"):
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


def test_removed_direct_contract_schema_reports_the_project_path():
    project = SimpleNamespace(
        path=Path("C:/IDA/cfg/d810/stale_config_v2.json"),
        additional_configuration={
            "pipeline_v2": [
                {
                    "pass": "recover_dispatcher",
                    "scope": "function",
                    "maturity": {},
                    "requires": {},
                    "outputs": {},
                    "preserves": {},
                    "invalidates": {},
                    "safety": {},
                    "migration": {},
                }
            ]
        },
    )

    with pytest.raises(
        PipelineConfigError,
        match=(
            r"stale_config_v2\.json: pipeline_v2\[0\] uses the removed "
            r"direct-contract schema"
        ),
    ):
        pipeline_configs_from_project_config(project)


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


def test_default_instruction_only_bundled_project_is_canonical_v2():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only.json"
    )

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert [config.pass_id for config in pipeline_configs_from_project_config(project)] == [
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    ]


def test_example_libobfuscated_bundled_project_is_canonical_v2():
    project = ProjectConfiguration.from_file(_CONF_DIR / "example_libobfuscated.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert project.additional_configuration["enable_pass_pipeline"] is True
    assert [config.pass_id for config in pipeline_configs_from_project_config(project)] == [
        "constant-simplification",
        "mba-simplify",
        "mba-state-preconditioner",
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]


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
    ],
)
def test_hodur_bundled_projects_are_canonical_v2(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert [config.pass_id for config in pipeline_configs_from_project_config(project)] == [
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]


def test_hodur_config_v2_project_is_operational():
    project = ProjectConfiguration.from_file(_CONF_DIR / "hodur_flag2.json")

    project_configs = pipeline_configs_from_project_config(project)

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert "canary" not in project.description.lower()
    assert "pipeline_v2_mode" not in project.additional_configuration
    assert "config_v2_canary" not in project.additional_configuration
    priors_by_key = load_function_analysis_priors_from_config(
        project.additional_configuration["function_analysis_priors"]
    )
    priors = priors_by_key["sub_7ffd3338c040"]
    assert priors_by_key["0x180014be0"] == priors
    assert priors_by_key["sub_180014be0"] == priors
    assert priors.return_frontier_artifacts.known_impossible_return_constants == (
        frozenset({0xC5FB34A1D9A6E315})
    )
    assert len(priors.return_frontier_artifacts.impossible_return_artifact_edges) == 1
    terminal_priors = priors.terminal_tail_cascade_egress
    assert terminal_priors.is_empty
    assert [config.pass_id for config in project_configs] == [
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]

    specs = pass_specs_from_project_config(
        project,
        operational_config_v2_pass_registry(),
    )
    assert [spec.pass_id for spec in specs] == [
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]


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
            3,
            ["ForwardConstantPropagationRule", "StateMachineCffUnflattener"],
        ),
        (
            "default_unflattening_tigress_indirect",
            7,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
    ],
)
def test_tigress_bundled_projects_are_canonical_v2(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert pipeline_configs_from_project_config(project)


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
def test_remaining_bundled_projects_are_canonical_v2(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
    expected_pass_ids,
    expected_unknown_pass,
):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert [config.pass_id for config in pipeline_configs_from_project_config(project)] == (
        expected_pass_ids
    )


def test_pipeline_spec_comparison_reports_ordered_differences():
    live_specs = standard_state_machine_passes()
    short_specs = live_specs[:1]

    comparison = compare_pipeline_specs(short_specs, live_specs)

    assert comparison.matches is False
    assert comparison.pass_ids_match is False
    assert comparison.configs_match is False
    assert comparison.left_pass_ids == ("recover_dispatcher",)
    assert comparison.right_pass_ids == tuple(spec.pass_id for spec in live_specs)
    assert comparison.missing_pass_ids == tuple(spec.pass_id for spec in live_specs[1:])
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
