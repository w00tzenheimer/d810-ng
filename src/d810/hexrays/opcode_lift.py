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

HEX_RAYS_BACKEND_ID = "hexrays"

_VALUE_OPS: tuple[tuple[str, ValueOpKind], ...] = (
    ("m_ldc", ValueOpKind.CONST),
    ("m_mov", ValueOpKind.MOVE),
    ("m_ldx", ValueOpKind.LOAD),
    ("m_stx", ValueOpKind.STORE),
    ("m_add", ValueOpKind.ADD),
    ("m_sub", ValueOpKind.SUB),
    ("m_mul", ValueOpKind.MUL),
    ("m_udiv", ValueOpKind.UDIV),
    ("m_sdiv", ValueOpKind.SDIV),
    ("m_umod", ValueOpKind.UMOD),
    ("m_smod", ValueOpKind.SMOD),
    ("m_or", ValueOpKind.OR),
    ("m_and", ValueOpKind.AND),
    ("m_xor", ValueOpKind.XOR),
    ("m_bnot", ValueOpKind.NOT),
    ("m_lnot", ValueOpKind.LNOT),
    ("m_neg", ValueOpKind.NEG),
    ("m_shl", ValueOpKind.SHL),
    ("m_shr", ValueOpKind.SHR),
    ("m_sar", ValueOpKind.SAR),
    ("m_xdu", ValueOpKind.ZEXT),
    ("m_xds", ValueOpKind.SEXT),
    ("m_low", ValueOpKind.LOW),
    ("m_high", ValueOpKind.HIGH),
    ("m_cfadd", ValueOpKind.CARRY_ADD),
    ("m_ofadd", ValueOpKind.OVERFLOW_ADD),
    ("m_cfshl", ValueOpKind.CARRY_SHL),
    ("m_cfshr", ValueOpKind.CARRY_SHR),
    ("m_sets", ValueOpKind.SIGN_BIT),
    ("m_seto", ValueOpKind.OVERFLOW_FLAG),
    ("m_setp", ValueOpKind.PARITY),
)

_BRANCH_PREDICATES: tuple[tuple[str, PredicateKind], ...] = (
    ("m_jz", PredicateKind.EQ),
    ("m_jnz", PredicateKind.NE),
    ("m_jae", PredicateKind.UGE),
    ("m_ja", PredicateKind.UGT),
    ("m_jbe", PredicateKind.ULE),
    ("m_jb", PredicateKind.ULT),
    ("m_jge", PredicateKind.SGE),
    ("m_jg", PredicateKind.SGT),
    ("m_jle", PredicateKind.SLE),
    ("m_jl", PredicateKind.SLT),
    ("m_jcnd", PredicateKind.TRUTHY),
)

_SET_PREDICATES: tuple[tuple[str, PredicateKind], ...] = (
    ("m_setz", PredicateKind.EQ),
    ("m_setnz", PredicateKind.NE),
    ("m_setae", PredicateKind.UGE),
    ("m_seta", PredicateKind.UGT),
    ("m_setbe", PredicateKind.ULE),
    ("m_setb", PredicateKind.ULT),
    ("m_setge", PredicateKind.SGE),
    ("m_setg", PredicateKind.SGT),
    ("m_setle", PredicateKind.SLE),
    ("m_setl", PredicateKind.SLT),
)

_CONTROL_TRANSFERS: tuple[tuple[str, ControlTransferKind], ...] = (
    ("m_goto", ControlTransferKind.GOTO),
    ("m_jtbl", ControlTransferKind.TABLE_BRANCH),
    ("m_ijmp", ControlTransferKind.INDIRECT_BRANCH),
    ("m_ret", ControlTransferKind.RETURN),
)

_CALLS: tuple[tuple[str, CallKind], ...] = (
    ("m_call", CallKind.DIRECT),
    ("m_icall", CallKind.INDIRECT),
)

_KNOWN_OPCODE_NAMES: tuple[str, ...] = tuple(
    dict.fromkeys(
        name
        for name, _kind in (
            _VALUE_OPS
            + _BRANCH_PREDICATES
            + _SET_PREDICATES
            + _CONTROL_TRANSFERS
            + _CALLS
            + (("m_nop", ValueOpKind.VENDOR),)
        )
    )
)


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


def _lookup(opcode: int, rows):
    for name, kind in rows:
        if is_hexrays_opcode(opcode, name):
            return kind
    return None


def value_op_from_opcode(opcode: int) -> ValueOpKind | None:
    return _lookup(int(opcode), _VALUE_OPS)


def branch_predicate_from_opcode(opcode: int) -> PredicateKind | None:
    return _lookup(int(opcode), _BRANCH_PREDICATES)


def set_predicate_from_opcode(opcode: int) -> PredicateKind | None:
    return _lookup(int(opcode), _SET_PREDICATES)


def predicate_from_opcode(opcode: int) -> PredicateKind | None:
    return branch_predicate_from_opcode(opcode) or set_predicate_from_opcode(opcode)


def control_transfer_from_opcode(opcode: int) -> ControlTransferKind | None:
    control = _lookup(int(opcode), _CONTROL_TRANSFERS)
    if control is not None:
        return control
    if branch_predicate_from_opcode(opcode) is not None:
        return ControlTransferKind.CONDITIONAL_BRANCH
    return None


def call_kind_from_opcode(opcode: int) -> CallKind | None:
    return _lookup(int(opcode), _CALLS)


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
