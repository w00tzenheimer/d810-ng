"""Typed public options for the state-machine CFF pass spine."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping

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


def _legacy_rule_options(config: PipelineConfig) -> Mapping[str, object] | None:
    payload = config.options.get("legacy_rule_options")
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise PipelineConfigError(
            "state-CFF options.legacy_rule_options must be a mapping"
        )
    return payload


def state_machine_cff_options_from_config(
    config: PipelineConfig,
) -> StateMachineCffOptions:
    """Read the typed public threshold from modern or migrated config-v2."""
    if config.pass_id not in STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(
            f"{config.pass_id!r} is not a state-machine CFF pass"
        )
    legacy = _legacy_rule_options(config)
    source = legacy if legacy is not None else config.options
    value = source.get("min_state_constant", MIN_STATE_CONSTANT)
    return StateMachineCffOptions(
        min_state_constant=_validated_min_state_constant(value)
    )


def replace_state_machine_cff_options(
    config: PipelineConfig,
    options: StateMachineCffOptions,
) -> PipelineConfig:
    """Replace the public threshold without losing migrated private options."""
    if config.pass_id not in STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(
            f"{config.pass_id!r} is not a state-machine CFF pass"
        )
    value = _validated_min_state_constant(options.min_state_constant)
    payload = dict(config.options)
    legacy = _legacy_rule_options(config)
    if legacy is None:
        payload["min_state_constant"] = value
    else:
        migrated = dict(legacy)
        migrated["min_state_constant"] = value
        payload["legacy_rule_options"] = migrated
    return dataclasses.replace(config, options=payload)


__all__ = [
    "MAX_STATE_CONSTANT",
    "STATE_MACHINE_NATIVE_PASS_IDS",
    "StateMachineCffOptions",
    "replace_state_machine_cff_options",
    "state_machine_cff_options_from_config",
]
