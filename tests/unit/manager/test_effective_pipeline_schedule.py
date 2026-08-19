from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.core.execution_scope import ExecutionPipeline
from d810.ir.maturity import IRMaturity
from d810.manager.effective_pipeline_schedule import build_effective_maturity_schedule
from d810.passes.constant_simplification import constant_simplification_stage_descriptors
from d810.passes.constant_simplification_options import (
    compile_constant_simplification_schedule,
)
from d810.passes.execution_stages import ExecutionStageDescriptor
from d810.passes.pass_pipeline import (
    FactRequirement,
    MaturityRange,
    PassContract,
    PassRequires,
    PipelineConfig,
)


pytestmark = pytest.mark.pure_python


class _Registry:
    def __init__(self, configs, stages):
        self._configs = {config.pass_id: config for config in configs}
        self._stages = stages

    def build_spec(self, config):
        return SimpleNamespace(contract=config.contract)

    def stages_for(self, pass_id):
        return self._stages[pass_id]


def _config(pass_id, *, required=(), maturity=None, options=None):
    return PipelineConfig(
        pass_id=pass_id,
        contract=PassContract(
            maturity=maturity or MaturityRange(),
            requires=PassRequires(
                analyses=frozenset(required),
                facts=FactRequirement(),
            ),
        ),
        options=options or {},
    )


def _stage(pass_id, implementation):
    return ExecutionStageDescriptor(
        pass_id,
        pass_id.replace("_", "-"),
        ExecutionPipeline.FLOW,
        implementation,
    )


def test_configured_order_does_not_change_dependency_or_maturity_projection() -> None:
    configs = (
        _config(
            "recover_dispatcher",
            maturity=MaturityRange(
                min=IRMaturity.CALL_MODELED,
                max=IRMaturity.GLOBAL_ANALYZED,
            ),
        ),
        _config(
            "recover_state_transitions",
            required=("recover_dispatcher",),
            maturity=MaturityRange(
                min=IRMaturity.CALL_MODELED,
                max=IRMaturity.GLOBAL_ANALYZED,
            ),
        ),
    )
    registry = _Registry(
        configs,
        {
            "recover_dispatcher": (_stage("recover_dispatcher", "Recover"),),
            "recover_state_transitions": (
                _stage("recover_state_transitions", "Transitions"),
            ),
        },
    )

    schedule = build_effective_maturity_schedule(
        configs,
        registry=registry,
        implementations={ExecutionPipeline.FLOW: ()},
    )

    dispatcher = schedule.stage("recover-dispatcher")
    transitions = schedule.stage("recover-state-transitions")
    assert dispatcher.configured_index == 0
    assert transitions.requirements == ("recover_dispatcher",)
    assert schedule.at("MMAT_CALLS").contains("recover-dispatcher")
    assert schedule.at("MMAT_GLBOPT1").contains("recover-state-transitions")


def test_private_rule_maturities_override_unbounded_public_contract() -> None:
    configs = (_config("constant-simplification"), _config("mba-simplify"))
    stages = {
        "constant-simplification": (
            _stage("constant-simplification", "FoldReadonlyDataRule"),
        ),
        "mba-simplify": (_stage("mba-simplify", "MbaRule"),),
    }
    implementations = {
        ExecutionPipeline.FLOW: (
            SimpleNamespace(name="FoldReadonlyDataRule", maturities=(2, 5)),
            SimpleNamespace(name="MbaRule", maturities=(3, 4, 5)),
        )
    }

    schedule = build_effective_maturity_schedule(
        configs,
        registry=_Registry(configs, stages),
        implementations=implementations,
        maturity_name_provider=lambda value: {
            2: "MMAT_PREOPTIMIZED",
            3: "MMAT_LOCOPT",
            4: "MMAT_CALLS",
            5: "MMAT_GLBOPT1",
        }[value],
    )

    assert schedule.stage("constant-simplification").maturity_source == "private-rule"
    assert schedule.stage("mba-simplify").maturity_source == "private-rule"
    assert schedule.at("MMAT_PREOPTIMIZED").contains("constant-simplification")
    assert schedule.at("MMAT_LOCOPT").contains("mba-simplify")


def test_configured_mba_solver_runs_at_global_optimized_only() -> None:
    config = _config(
        "mba-solve",
        options={"maturities": ["GLOBAL_OPTIMIZED"]},
    )
    schedule = build_effective_maturity_schedule(
        (config,),
        registry=_Registry(
            (config,),
            {"mba-solve": (_stage("mba-solve", "CobraSolveRule"),)},
        ),
        implementations={ExecutionPipeline.FLOW: ()},
    )

    assert schedule.at("MMAT_GLBOPT2").contains("mba-solve")
    assert not schedule.at("MMAT_GLBOPT1").contains("mba-solve")


def test_constant_bundle_projection_uses_compiled_schedule_over_live_rules() -> None:
    config = _config(
        "constant-simplification",
        options={
            "stages": {
                "fold-readonly-data": {
                    "maturities": ["CANONICAL"],
                },
                "fold-constant-subtree": {"enabled": False},
                "forward-constants": {
                    "maturities": ["CALL_MODELED"],
                },
            },
        },
    )
    compiled = compile_constant_simplification_schedule(
        config,
        constant_simplification_stage_descriptors(),
    )
    descriptors = constant_simplification_stage_descriptors()
    registry = _Registry((config,), {config.pass_id: descriptors})
    schedule = build_effective_maturity_schedule(
        (config,),
        registry=registry,
        implementations={
            ExecutionPipeline.INSTRUCTION: (
                SimpleNamespace(
                    name="FoldReadonlyDataRule",
                    maturities=("MMAT_GLBOPT2",),
                ),
                SimpleNamespace(
                    name="ConstantSubtreeFoldRule",
                    maturities=("MMAT_GLBOPT3",),
                ),
            ),
            ExecutionPipeline.FLOW: (
                SimpleNamespace(
                    name="ForwardConstantPropagationRule",
                    maturities=("MMAT_GLBOPT3",),
                ),
            ),
        },
        constant_simplification_schedule=compiled,
    )

    readonly = schedule.stage("fold-readonly-data")
    subtree = schedule.stage("fold-constant-subtree")
    forward = schedule.stage("forward-constants")
    assert readonly.provider_maturities == ("MMAT_PREOPTIMIZED",)
    assert readonly.schedule_source == "compiled stage contract"
    assert subtree.enabled is False
    assert subtree.provider_maturities == ()
    assert subtree.inactive_reason == "disabled by configuration"
    assert forward.provider_maturities == ("MMAT_CALLS",)


def test_compiled_constant_stage_orders_are_independent_per_pipeline() -> None:
    config = _config("constant-simplification")
    compiled = compile_constant_simplification_schedule(
        config,
        constant_simplification_stage_descriptors(),
    )
    schedule = build_effective_maturity_schedule(
        (config,),
        registry=_Registry(
            (config,),
            {config.pass_id: constant_simplification_stage_descriptors()},
        ),
        implementations={
            ExecutionPipeline.INSTRUCTION: (),
            ExecutionPipeline.FLOW: (),
        },
        constant_simplification_schedule=compiled,
    )

    readonly = schedule.stage("fold-readonly-data")
    subtree = schedule.stage("fold-constant-subtree")
    forward = schedule.stage("forward-constants")
    assert (readonly.pipeline, readonly.runtime_order) == ("instruction", 0)
    assert (subtree.pipeline, subtree.runtime_order) == ("instruction", 1)
    assert (forward.pipeline, forward.runtime_order) == ("flow", 0)
    at_calls = schedule.at("MMAT_CALLS")
    assert tuple(
        (stage.pipeline, stage.runtime_order) for stage in at_calls.stages
    ) == (("instruction", 0), ("instruction", 1), ("flow", 0))
