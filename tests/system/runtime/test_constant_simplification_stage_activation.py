"""Live Hex-Rays activation of the compiled constant-stage schedule."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.hexrays.utils.hexrays_formatters import string_to_maturity
from d810.optimizers.microcode.flow.constant_prop.forward_const_prop import (
    ForwardConstantPropagationRule,
)
from d810.optimizers.microcode.handler import validate_rule_maturity_contract
from d810.optimizers.microcode.instructions.peephole.fold_constant_subtree import (
    ConstantSubtreeFoldRule,
)
from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    FoldReadonlyDataRule,
)
from d810.passes.constant_simplification import (
    constant_simplification_provider_maturities,
)
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_RULE_TYPES = {
    "FoldReadonlyDataRule": FoldReadonlyDataRule,
    "ConstantSubtreeFoldRule": ConstantSubtreeFoldRule,
    "ForwardConstantPropagationRule": ForwardConstantPropagationRule,
}


def _project() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=Path("constant-stage-activation.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "maturity_gates": [
                        "CANONICAL",
                        "LOCAL_OPTIMIZED",
                        "CALL_MODELED",
                        "GLOBAL_ANALYZED",
                        "GLOBAL_OPTIMIZED",
                        "STRUCTURED",
                    ],
                    "options": {
                        "stages": {
                            "fold-readonly-data": {
                                "enabled": True,
                                "maturities": ["CANONICAL", "GLOBAL_ANALYZED"],
                            },
                            "fold-constant-subtree": {
                                "enabled": True,
                                "maturities": ["LOCAL_OPTIMIZED", "STRUCTURED"],
                            },
                            "forward-constants": {
                                "enabled": True,
                                "maturities": ["CALL_MODELED", "GLOBAL_OPTIMIZED"],
                            },
                        }
                    },
                }
            ],
        },
    )


@pytest.mark.ida_required
def test_live_rules_receive_exact_compiled_provider_maturities() -> None:
    activation = pipeline_v2_hook_activation(_project())
    schedule = activation.constant_simplification_schedule
    assert schedule is not None

    for rule_config in (
        *activation.instruction_rules,
        *activation.block_rules,
    ):
        rule = _RULE_TYPES[rule_config.name]()
        rule.configure(dict(rule_config.config))
        stage = next(
            stage
            for stage in schedule.stages
            if stage.implementation_name == rule_config.name
        )
        supported = tuple(
            string_to_maturity(name)
            for name in constant_simplification_provider_maturities(
                stage.supported_maturities
            )
        )
        effective = tuple(
            string_to_maturity(name)
            for name in constant_simplification_provider_maturities(
                stage.effective_maturities
            )
        )
        assert None not in supported
        assert None not in effective
        assert set(rule.maturities) == set(effective)
        validate_rule_maturity_contract(
            rule,
            pass_id=stage.pass_id,
            stage_id=stage.stage_id,
            expected_supported=tuple(value for value in supported if value is not None),
            expected_effective=tuple(value for value in effective if value is not None),
        )


@pytest.mark.ida_required
def test_live_default_support_drift_fails_closed_with_stage_and_implementation() -> None:
    class DriftedRule:
        name = "FoldReadonlyDataRule"
        default_maturities = (1, 2)
        maturities = (1,)

    with pytest.raises(
        ValueError,
        match=(
            "constant-simplification stage fold-readonly-data implementation "
            "FoldReadonlyDataRule default maturity support drift"
        ),
    ):
        validate_rule_maturity_contract(
            DriftedRule(),
            pass_id="constant-simplification",
            stage_id="fold-readonly-data",
            expected_supported=(1, 2, 3),
            expected_effective=(1,),
        )
