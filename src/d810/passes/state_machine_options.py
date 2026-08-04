"""Typed public options for the state-machine CFF pass spine."""

from __future__ import annotations

import dataclasses

from d810.analyses.control_flow.dispatcher_recovery import MIN_STATE_CONSTANT
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError

STATE_MACHINE_NATIVE_PASS_IDS = (
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)
MAX_STATE_CONSTANT = (1 << 64) - 1


def _validated_min_state_constant(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_STATE_CONSTANT
    ):
        raise PipelineConfigError(
            "state-CFF options.min_state_constant must be an integer "
            f"between 0 and {MAX_STATE_CONSTANT}"
        )
    return value


@dataclasses.dataclass(frozen=True, slots=True)
class StateMachineCffOptions:
    """Function-authorable state-machine CFF recovery options."""

    min_state_constant: int = MIN_STATE_CONSTANT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "min_state_constant",
            _validated_min_state_constant(self.min_state_constant),
        )


def state_machine_cff_options_from_config(
    config: PipelineConfig,
) -> StateMachineCffOptions:
    """Read the one typed public threshold from strict config-v2."""
    if config.pass_id not in STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(
            f"{config.pass_id!r} is not a state-machine CFF pass"
        )
    unknown = tuple(sorted(set(config.options) - {"min_state_constant"}))
    if unknown:
        raise PipelineConfigError(
            f"state-CFF has unknown options: {list(unknown)}"
        )
    value = config.options.get("min_state_constant", MIN_STATE_CONSTANT)
    return StateMachineCffOptions(
        min_state_constant=_validated_min_state_constant(value)
    )


def replace_state_machine_cff_options(
    config: PipelineConfig,
    options: StateMachineCffOptions,
) -> PipelineConfig:
    """Replace the public threshold using the strict typed option shape."""
    if config.pass_id not in STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(
            f"{config.pass_id!r} is not a state-machine CFF pass"
        )
    value = _validated_min_state_constant(options.min_state_constant)
    return dataclasses.replace(config, options={"min_state_constant": value})


__all__ = [
    "MAX_STATE_CONSTANT",
    "STATE_MACHINE_NATIVE_PASS_IDS",
    "StateMachineCffOptions",
    "replace_state_machine_cff_options",
    "state_machine_cff_options_from_config",
]
