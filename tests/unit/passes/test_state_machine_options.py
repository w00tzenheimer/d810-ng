from __future__ import annotations

import pytest

from d810.analyses.control_flow.dispatcher_recovery import MIN_STATE_CONSTANT
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.state_machine_options import (
    MAX_STATE_CONSTANT,
    StateMachineCffOptions,
    replace_state_machine_cff_options,
    state_machine_cff_options_from_config,
)


def _config(options: dict[str, object]) -> PipelineConfig:
    return PipelineConfig(pass_id="recover_dispatcher", options=options)


def test_state_cff_options_accept_default_direct_and_legacy_thresholds() -> None:
    assert state_machine_cff_options_from_config(_config({})) == StateMachineCffOptions(
        min_state_constant=MIN_STATE_CONSTANT
    )
    assert state_machine_cff_options_from_config(
        _config({"min_state_constant": 0x1234})
    ) == StateMachineCffOptions(min_state_constant=0x1234)
    assert state_machine_cff_options_from_config(
        _config(
            {
                "legacy_rule": "StateMachineCffUnflattener",
                "legacy_rule_options": {
                    "min_state_constant": 0x4567,
                    "profile": "hodur",
                },
                "native_pipeline": ["recover_dispatcher"],
            }
        )
    ) == StateMachineCffOptions(min_state_constant=0x4567)


@pytest.mark.parametrize(
    "value",
    (True, False, "4096", 1.5, -1, MAX_STATE_CONSTANT + 1),
)
def test_state_cff_options_reject_non_integer_or_out_of_range_thresholds(
    value: object,
) -> None:
    with pytest.raises(
        PipelineConfigError,
        match="options.min_state_constant must be an integer",
    ):
        state_machine_cff_options_from_config(
            _config({"min_state_constant": value})
        )


def test_replace_state_cff_options_preserves_legacy_sibling_options() -> None:
    original = _config(
        {
            "legacy_rule": "StateMachineCffUnflattener",
            "legacy_rule_options": {
                "min_state_constant": 0x1000000,
                "profile": "hodur",
                "recovery_engine": "reduced_product",
            },
            "native_pipeline": ["recover_dispatcher"],
        }
    )

    replaced = replace_state_machine_cff_options(
        original,
        StateMachineCffOptions(min_state_constant=0x8000),
    )

    assert replaced.options == {
        "legacy_rule": "StateMachineCffUnflattener",
        "legacy_rule_options": {
            "min_state_constant": 0x8000,
            "profile": "hodur",
            "recovery_engine": "reduced_product",
        },
        "native_pipeline": ["recover_dispatcher"],
    }


def test_replace_state_cff_options_uses_direct_shape_for_modern_config() -> None:
    replaced = replace_state_machine_cff_options(
        _config({}),
        StateMachineCffOptions(min_state_constant=0x8000),
    )

    assert replaced.options == {"min_state_constant": 0x8000}
