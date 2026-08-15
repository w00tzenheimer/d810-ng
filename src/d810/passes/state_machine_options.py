"""Typed public options for the state-machine CFF pass spine."""

from __future__ import annotations

import dataclasses
import enum

from d810.analyses.control_flow.dispatcher_recovery import MIN_STATE_CONSTANT
from d810.core.pass_ids import PassId
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError

#: The native spine, in the order the runtime requires. Back-references to the
#: shared vocabulary; see :mod:`d810.core.pass_ids`.
STATE_MACHINE_NATIVE_PASS_IDS = (
    PassId.RECOVER_DISPATCHER,
    PassId.RECOVER_STATE_TRANSITIONS,
    PassId.PLAN_SEMANTIC_REGIONS,
    PassId.LOWER_STATE_MACHINE,
    PassId.CLEANUP_RESIDUAL_DISPATCHER,
)
MAX_STATE_CONSTANT = (1 << 64) - 1


class StateMachineCffFamily(enum.StrEnum):
    """Public state-machine family selection for the canonical pass spine."""

    AUTO = "auto"
    TIGRESS_INDIRECT = "tigress-indirect"


class StateMachineRecoveryStrategy(enum.StrEnum):
    """Public dispatcher-recovery strategy used by the canonical spine."""

    FAMILY = "family"
    REDUCED_PRODUCT = "reduced-product"


def _validated_mode(value: object, mode_type: type[enum.StrEnum], field: str):
    if isinstance(value, mode_type):
        return value
    if not isinstance(value, str):
        raise PipelineConfigError(f"state-CFF options.{field} must be a string")
    try:
        return mode_type(value)
    except ValueError as exc:
        choices = [item.value for item in mode_type]
        raise PipelineConfigError(
            f"state-CFF options.{field} must be one of {choices}"
        ) from exc


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
    family: StateMachineCffFamily = StateMachineCffFamily.AUTO
    recovery_strategy: StateMachineRecoveryStrategy = (
        StateMachineRecoveryStrategy.FAMILY
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "min_state_constant",
            _validated_min_state_constant(self.min_state_constant),
        )
        object.__setattr__(
            self,
            "family",
            _validated_mode(self.family, StateMachineCffFamily, "family"),
        )
        object.__setattr__(
            self,
            "recovery_strategy",
            _validated_mode(
                self.recovery_strategy,
                StateMachineRecoveryStrategy,
                "recovery_strategy",
            ),
        )


def state_machine_cff_options_from_config(
    config: PipelineConfig,
) -> StateMachineCffOptions:
    """Read strict public state-machine options from config-v2."""
    if config.pass_id not in STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(f"{config.pass_id!r} is not a state-machine CFF pass")
    unknown = tuple(
        sorted(
            set(config.options)
            - {
                "min_state_constant",
                "family",
                "recovery_strategy",
                "native_cfg_persistence",
            }
        )
    )
    if unknown:
        raise PipelineConfigError(f"state-CFF has unknown options: {list(unknown)}")
    value = config.options.get("min_state_constant", MIN_STATE_CONSTANT)
    return StateMachineCffOptions(
        min_state_constant=_validated_min_state_constant(value),
        family=_validated_mode(
            config.options.get("family", StateMachineCffFamily.AUTO.value),
            StateMachineCffFamily,
            "family",
        ),
        recovery_strategy=_validated_mode(
            config.options.get(
                "recovery_strategy",
                StateMachineRecoveryStrategy.FAMILY.value,
            ),
            StateMachineRecoveryStrategy,
            "recovery_strategy",
        ),
    )


def replace_state_machine_cff_options(
    config: PipelineConfig,
    options: StateMachineCffOptions,
) -> PipelineConfig:
    """Replace public state-machine options using the strict typed shape."""
    if config.pass_id not in STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(f"{config.pass_id!r} is not a state-machine CFF pass")
    normalized = StateMachineCffOptions(
        min_state_constant=options.min_state_constant,
        family=options.family,
        recovery_strategy=options.recovery_strategy,
    )
    serialized: dict[str, object] = {
        "min_state_constant": normalized.min_state_constant
    }
    if normalized.family is not StateMachineCffFamily.AUTO:
        serialized["family"] = normalized.family.value
    if normalized.recovery_strategy is not StateMachineRecoveryStrategy.FAMILY:
        serialized["recovery_strategy"] = normalized.recovery_strategy.value
    return dataclasses.replace(config, options=serialized)


__all__ = [
    "MAX_STATE_CONSTANT",
    "STATE_MACHINE_NATIVE_PASS_IDS",
    "StateMachineCffFamily",
    "StateMachineCffOptions",
    "StateMachineRecoveryStrategy",
    "replace_state_machine_cff_options",
    "state_machine_cff_options_from_config",
]
