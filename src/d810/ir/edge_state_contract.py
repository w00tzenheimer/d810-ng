"""Portable positive evidence for native control-flow relinking."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "EdgeStateContract",
    "MachineStateLocation",
    "MachineStateLocationKind",
]


class MachineStateLocationKind(str, Enum):
    REGISTER = "register"
    FLAGS = "flags"
    STACK = "stack"
    MEMORY = "memory"


@dataclass(frozen=True, slots=True, order=True)
class MachineStateLocation:
    kind: MachineStateLocationKind
    identity: str
    bit_offset: int
    bit_width: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, MachineStateLocationKind):
            raise TypeError("kind must be a MachineStateLocationKind")
        if not isinstance(self.identity, str):
            raise TypeError("identity must be a string")
        if not self.identity.strip():
            raise ValueError("identity must not be blank")
        if not isinstance(self.bit_offset, int) or isinstance(self.bit_offset, bool):
            raise TypeError("bit_offset must be an int")
        if self.bit_offset < 0:
            raise ValueError("bit_offset must be non-negative")
        if not isinstance(self.bit_width, int) or isinstance(self.bit_width, bool):
            raise TypeError("bit_width must be an int")
        if self.bit_width <= 0:
            raise ValueError("bit_width must be positive")


def _location_key(
    location: MachineStateLocation,
) -> tuple[str, str, int, int]:
    return (
        location.kind.value,
        location.identity,
        location.bit_offset,
        location.bit_width,
    )


def _canonical_locations(
    value: object,
    field_name: str,
) -> tuple[MachineStateLocation, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{field_name} must be a tuple")
    if not all(isinstance(item, MachineStateLocation) for item in value):
        raise TypeError(f"{field_name} must contain MachineStateLocation values")
    return tuple(sorted(set(value), key=_location_key))


def _canonical_proof_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise TypeError("proof_ids must be a tuple of strings")
    if any(not item.strip() for item in value):
        raise ValueError("proof_ids must not contain blank values")
    return tuple(sorted(set(value)))


def _validate_stack_delta(value: object, field_name: str) -> None:
    if value is not None and (
        not isinstance(value, int) or isinstance(value, bool)
    ):
        raise TypeError(f"{field_name} must be an int or None")


@dataclass(frozen=True, slots=True)
class EdgeStateContract:
    required_target_inputs: tuple[MachineStateLocation, ...] = ()
    proven_equivalent_inputs: tuple[MachineStateLocation, ...] = ()
    skipped_observable_effects: tuple[MachineStateLocation, ...] = ()
    unpersisted_body_effects: tuple[MachineStateLocation, ...] = ()
    proven_dead_body_effects: tuple[MachineStateLocation, ...] = ()
    source_stack_delta: int | None = None
    target_stack_delta: int | None = None
    proof_ids: tuple[str, ...] = ()
    unresolved_aliases: bool = False
    unresolved_call_effects: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "required_target_inputs",
            "proven_equivalent_inputs",
            "skipped_observable_effects",
            "unpersisted_body_effects",
            "proven_dead_body_effects",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_locations(getattr(self, field_name), field_name),
            )
        _validate_stack_delta(self.source_stack_delta, "source_stack_delta")
        _validate_stack_delta(self.target_stack_delta, "target_stack_delta")
        object.__setattr__(self, "proof_ids", _canonical_proof_ids(self.proof_ids))
        if not isinstance(self.unresolved_aliases, bool):
            raise TypeError("unresolved_aliases must be a bool")
        if not isinstance(self.unresolved_call_effects, bool):
            raise TypeError("unresolved_call_effects must be a bool")

    @property
    def permits_control_only_relink(self) -> bool:
        return (
            set(self.required_target_inputs)
            <= set(self.proven_equivalent_inputs)
            and not self.skipped_observable_effects
            and set(self.unpersisted_body_effects)
            <= set(self.proven_dead_body_effects)
            and self.source_stack_delta is not None
            and self.source_stack_delta == self.target_stack_delta
            and bool(self.proof_ids)
            and not self.unresolved_aliases
            and not self.unresolved_call_effects
        )
