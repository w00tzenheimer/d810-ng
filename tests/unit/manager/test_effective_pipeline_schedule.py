from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.core.execution_scope import ExecutionPipeline
from d810.ir.maturity import IRMaturity
from d810.manager.effective_pipeline_schedule import build_effective_maturity_schedule
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
