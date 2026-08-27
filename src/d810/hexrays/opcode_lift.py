"""Hex-Rays opcode lift table for portable operation vocabulary."""

from __future__ import annotations

import ida_hexrays

from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import (
    CallKind,
    ControlTransferKind,
    LiftedOpcode,
    PredicateKind,
)
from d810.hexrays.instruction_vocabulary import (
    branch_opcode_name_for_predicate,
    branch_predicate_for_opcode_name,
    call_kind_for_opcode_name,
    control_transfer_kind_for_opcode_name,
    live_known_opcode_names,
    predicate_for_opcode_name,
    set_predicate_for_opcode_name,
    value_op_kind_for_opcode_name,
)

HEX_RAYS_BACKEND_ID = "hexrays"

_KNOWN_OPCODE_NAMES = live_known_opcode_names()


def opcode_value(name: str) -> int | None:
    """Return a Hex-Rays opcode integer by SDK name, if present."""

    value = getattr(ida_hexrays, name, None)
    if value is None:
        return None
    return int(value)


def is_hexrays_opcode(opcode: int, name: str) -> bool:
    value = opcode_value(name)
    return value is not None and int(opcode) == value


def opcode_name(opcode: int) -> str | None:
    """Return the known Hex-Rays SDK opcode name for ``opcode``.

    Unknown opcodes return ``None`` instead of fabricating ``op_<N>``. The raw
    integer remains available in attrs.
    """

    opcode_int = int(opcode)
    for name in _KNOWN_OPCODE_NAMES:
        if opcode_value(name) == opcode_int:
            return name
    return None


def raw_opcode_attrs(opcode: int) -> dict[str, object]:
    attrs: dict[str, object] = {
        "backend": HEX_RAYS_BACKEND_ID,
        "raw_opcode_int": int(opcode),
    }
    name = opcode_name(opcode)
    if name is not None:
        attrs["raw_opcode_name"] = name
    return attrs


def _name_semantics(opcode: int) -> str | None:
    return opcode_name(int(opcode))


def value_op_from_opcode(opcode: int) -> ValueOpKind | None:
    name = _name_semantics(opcode)
    return value_op_kind_for_opcode_name(name) if name is not None else None


def branch_predicate_from_opcode(opcode: int) -> PredicateKind | None:
    name = _name_semantics(opcode)
    return branch_predicate_for_opcode_name(name) if name is not None else None


def branch_opcode_for_predicate(predicate: PredicateKind) -> int | None:
    """Return the Hex-Rays branch opcode for one portable predicate."""
    if not isinstance(predicate, PredicateKind):
        raise TypeError("branch opcode lookup requires a PredicateKind")
    name = branch_opcode_name_for_predicate(predicate)
    value = opcode_value(name) if name is not None else None
    return None if value is None else int(value)


def set_predicate_from_opcode(opcode: int) -> PredicateKind | None:
    name = _name_semantics(opcode)
    return set_predicate_for_opcode_name(name) if name is not None else None


def predicate_from_opcode(opcode: int) -> PredicateKind | None:
    name = _name_semantics(opcode)
    return predicate_for_opcode_name(name) if name is not None else None


def control_transfer_from_opcode(opcode: int) -> ControlTransferKind | None:
    name = _name_semantics(opcode)
    return control_transfer_kind_for_opcode_name(name) if name is not None else None


def call_kind_from_opcode(opcode: int) -> CallKind | None:
    name = _name_semantics(opcode)
    return call_kind_for_opcode_name(name) if name is not None else None


def lift_opcode(opcode: int) -> LiftedOpcode:
    """Lift a raw Hex-Rays opcode into the canonical operation vocabulary."""

    opcode_int = int(opcode)
    kind = (
        control_transfer_from_opcode(opcode_int)
        or call_kind_from_opcode(opcode_int)
        or predicate_from_opcode(opcode_int)
        or value_op_from_opcode(opcode_int)
        or ValueOpKind.VENDOR
    )
    attrs = raw_opcode_attrs(opcode_int)
    if kind is ValueOpKind.VENDOR:
        attrs["vendor_semantics"] = "unmodeled_opcode"
    return LiftedOpcode(kind=kind, attrs=attrs)
