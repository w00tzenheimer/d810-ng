"""The public constant-simplification bundle and its private hook stages."""

from __future__ import annotations

import pytest

from d810.passes.constant_simplification import (
    CONSTANT_SIMPLIFICATION_PASS_ID,
    build_constant_simplification_pass,
    constant_simplification_hook_rules,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError, PassResult


def _config(**options) -> PipelineConfig:
    return PipelineConfig(
        pass_id=CONSTANT_SIMPLIFICATION_PASS_ID,
        options=options or {"memory_policy": "strict"},
    )


def test_default_bundle_expands_to_one_ordered_memory_fold_flow_pipeline():
    rules = constant_simplification_hook_rules(_config())

    assert [rule.name for rule in rules.instruction_rules] == [
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
    ]
    assert [rule.name for rule in rules.block_rules] == [
        "ForwardConstantPropagationRule"
    ]
    assert rules.instruction_rules[0].config == {
        "persist_global_const_annotations": True,
        "rva_guard": True,
    }
    assert rules.instruction_rules[1].config == {}
    assert rules.block_rules[0].config == {}


def test_state_machine_bundle_configures_one_post_unflatten_flow_rule():
    rules = constant_simplification_hook_rules(
        _config(),
        forward_constant_options={
            "maturities": ["MMAT_GLBOPT2"],
            "cython_enabled": False,
        },
    )

    assert [rule.name for rule in rules.block_rules] == ["ForwardConstantPropagationRule"]
    assert rules.block_rules[0].config == {
        "maturities": ["MMAT_GLBOPT2"],
        "cython_enabled": False,
    }


def test_bundle_maps_aggressive_and_dangerous_options_only_to_memory_stage():
    rules = constant_simplification_hook_rules(
        _config(
            memory_policy="aggressive_no_direct_writes",
            allow_executable_readonly=True,
        )
    )

    assert rules.instruction_rules[0].config == {
        "fold_writable_constants": True,
        "allow_executable_readonly": True,
        "persist_global_const_annotations": True,
        "rva_guard": True,
    }
    assert rules.instruction_rules[1].config == {}
    assert rules.block_rules[0].config == {}


@pytest.mark.parametrize(
    "options",
    [
        {"memory_policy": "guess"},
        {"memory_policy": True},
        {"memory_policy": "strict", "allow_executable_readonly": "yes"},
        {"memory_policy": "strict", "extra": False},
    ],
)
def test_bundle_rejects_unknown_and_wrongly_typed_options(options):
    with pytest.raises(PipelineConfigError):
        build_constant_simplification_pass(_config(**options))


def test_bundle_descriptor_is_a_noop_for_portable_execution():
    configured = build_constant_simplification_pass(_config())
    result = configured.run(None)

    assert configured.name == CONSTANT_SIMPLIFICATION_PASS_ID
    assert isinstance(result, PassResult)
    assert result.facts == ()
    assert result.rewrite_plan.steps == ()
