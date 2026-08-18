"""Canonical parsing for PipelineConfig v2 project payloads."""

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
    pipeline_configs_from_project_config,
    pass_specs_from_project_config,
    require_config_v2_project,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
import d810.passes.pipeline_config_parser as pipeline_config_parser_module


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"
_STATE_MACHINE_NATIVE_PIPELINE = [
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
]


_REMAINING_CANONICAL_PROJECTS = (
    (
        "bogus_loops",
        ("single-trip-loop-peel", "mba-state-preconditioner", "jump-fixer"),
    ),
    (
        "default_unflattening_approov",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ),
    ),
    (
        "default_unflattening_approov_s1a",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ),
    ),
    ("eidolon", ("mba-simplify",)),
    (
        "example_hodur",
        (
            "constant-simplification",
            "mba-simplify",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ),
    ),
    (
        "example_libobfuscated_abc",
        (
            "constant-simplification",
            "mba-simplify",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
        ),
    ),
    (
        "flatfold",
        (
            "constant-simplification",
            "mba-simplify",
            "mba-state-preconditioner",
            "jump-fixer",
            *_STATE_MACHINE_NATIVE_PIPELINE,
        ),
    ),
    (
        "hodur_flag2_with_fcp",
        (
            "mba-simplify",
            *_STATE_MACHINE_NATIVE_PIPELINE,
            "jump-fixer",
            "constant-simplification",
        ),
    ),
    ("hodur_glbopt2_only", tuple(_STATE_MACHINE_NATIVE_PIPELINE)),
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
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
        },
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


@pytest.mark.parametrize("value", ["legacy", "shadow-check", "config-v2", None])
def test_require_config_v2_project_rejects_retired_pipeline_mode(value):
    retired_mode_key = "pipeline_v2_" + "mode"
    document = {
        "additional_configuration": {
            retired_mode_key: value,
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
        }
    }

    with pytest.raises(PipelineConfigError, match="removed compatibility field"):
        require_config_v2_project(document)


def test_require_config_v2_project_rejects_retired_shadow_match_field():
    retired_shadow_key = "require_" + "pipeline_v2_" + "shadow_match"
    document = {
        "additional_configuration": {
            retired_shadow_key: True,
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}],
        }
    }

    with pytest.raises(PipelineConfigError, match="removed compatibility field"):
        require_config_v2_project(document)


def test_runtime_parser_has_no_legacy_or_shadow_mode_api():
    """Runtime parsing exposes typed v2 specs, not a selectable mode API."""
    retired_mode_type = "Pipeline" + "V2Mode"
    retired_mode_parser = "pipeline_v2_" + "mode_from_project_config"
    assert not hasattr(pipeline_config_parser_module, retired_mode_type)
    assert not hasattr(
        pipeline_config_parser_module,
        retired_mode_parser,
    )


def test_pipeline_config_parse_from_project_like_object():
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
    assert [
        config.pass_id for config in pipeline_configs_from_project_config(project)
    ] == [
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    ]


def test_example_libobfuscated_bundled_project_is_canonical_v2():
    project = ProjectConfiguration.from_file(_CONF_DIR / "example_libobfuscated.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert project.additional_configuration["enable_pass_pipeline"] is True
    assert [
        config.pass_id for config in pipeline_configs_from_project_config(project)
    ] == [
        "constant-simplification",
        "mba-simplify",
        "mba-state-preconditioner",
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]


@pytest.mark.parametrize(
    "config_name",
    [
        "hodur_flag2",
        "hodur_flag2_s1a",
    ],
)
def test_hodur_bundled_projects_are_canonical_v2(config_name):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert [
        config.pass_id for config in pipeline_configs_from_project_config(project)
    ] == [
        *_STATE_MACHINE_NATIVE_PIPELINE,
        "jump-fixer",
    ]


def test_hodur_config_v2_project_is_operational():
    project = ProjectConfiguration.from_file(_CONF_DIR / "hodur_flag2.json")

    project_configs = pipeline_configs_from_project_config(project)

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert "canary" not in project.description.lower()
    assert "pipeline_v2_" + "mode" not in project.additional_configuration
    assert not any(
        "canary" in str(key).casefold() for key in project.additional_configuration
    )
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
    "config_name",
    [
        "default_unflattening_tigress_engine",
        "default_unflattening_tigress_engine_transition_facts",
        "default_unflattening_tigress_indirect",
    ],
)
def test_tigress_bundled_projects_are_canonical_v2(config_name):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert pipeline_configs_from_project_config(project)


@pytest.mark.parametrize(
    ("config_name", "expected_pass_ids"), _REMAINING_CANONICAL_PROJECTS
)
def test_remaining_bundled_projects_are_canonical_v2(config_name, expected_pass_ids):
    project = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.json")

    assert project.ins_rules == []
    assert project.blk_rules == []
    assert (
        tuple(
            config.pass_id for config in pipeline_configs_from_project_config(project)
        )
        == expected_pass_ids
    )
