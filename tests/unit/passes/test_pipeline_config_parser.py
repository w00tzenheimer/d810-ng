"""Shadow parsing for optional PipelineConfig v2 project payloads."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.ir.maturity import IRMaturity
from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.passes.pass_pipeline import BackendRoute, PipelineConfigError
from d810.passes.pipeline_config_parser import (
    pipeline_configs_from_project_config,
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


def _recover_state_machine_contract_payload():
    return {
        "pass": "recover-state-machine",
        "scope": "function",
        "maturity": {
            "min": "ir.call.modeled",
            "max": "ir.global.analyzed",
            "preferred": "ir.call.modeled",
        },
        "requires": {
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


def test_pipeline_v2_parses_native_deobfuscation_contract_shape():
    configs = pipeline_configs_from_project_config(
        {"pipeline_v2": [_recover_state_machine_contract_payload()]}
    )

    assert len(configs) == 1
    config = configs[0]
    assert config.pass_id == "recover-state-machine"
    assert config.contract.scope.value == "function"
    assert config.contract.maturity.min is IRMaturity.CALL_MODELED
    assert config.contract.maturity.max is IRMaturity.GLOBAL_ANALYZED
    assert config.contract.maturity.preferred is IRMaturity.CALL_MODELED
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
    assert config.contract.preserves.analyses == frozenset({"function_boundaries"})
    assert config.contract.preserves.facts == frozenset({"raw_instruction_addresses"})
    assert config.contract.invalidates.analyses == frozenset(
        {"dominators", "postdominators", "loop_info", "regions"}
    )
    assert config.contract.invalidates.facts == frozenset({"stale_cfg_shape"})
    assert config.contract.safety.policy == "guarded-rewrite"
    assert config.contract.safety.requires_oracle is False


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
