"""Portable operation vocabulary + concrete modular word semantics.

The `*Op` enums are the backend-neutral operation set the ValueDomain evaluates
(a Hex-Rays backend maps `m_add`/`m_xor`/… onto these). The `eval_const_*`
functions are the **concrete calculator**: exact modular `2^width` arithmetic.
This is the engine that folds MBA-*over-constants* (`(0x77535232 ^ 0x71D1654B) -
0xDC240D83`) to a single value — no abstract approximation needed once the
operands are known, which is the OLLVM next-state case.

Pure integer, portable, no IDA.
"""
from __future__ import annotations

from enum import Enum

__all__ = [
    "BinaryOp",
    "UnaryOp",
    "CompareOp",
    "eval_const_binary",
    "eval_const_unary",
    "eval_const_compare",
]


class BinaryOp(Enum):
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    AND = "and"
    OR = "or"
    XOR = "xor"
    SHL = "shl"
    SHR_U = "shr_u"  # logical right shift
    SHR_S = "shr_s"  # arithmetic right shift


class UnaryOp(Enum):
    NOT = "not"   # bitwise complement
    NEG = "neg"   # two's-complement negation


class CompareOp(Enum):
    EQ = "eq"
    NE = "ne"
    ULT = "ult"
    ULE = "ule"
    UGT = "ugt"
    UGE = "uge"
    SLT = "slt"
    SLE = "sle"
    SGT = "sgt"
    SGE = "sge"


def _mask(width: int) -> int:
    return (1 << width) - 1


def _to_signed(value: int, width: int) -> int:
    value &= _mask(width)
    if value & (1 << (width - 1)):
        return value - (1 << width)
    return value


def eval_const_binary(op: BinaryOp, left: int, right: int, width: int) -> int:
    """Exact modular `2^width` result of a binary op on two concrete values."""
    m = _mask(width)
    a, b = left & m, right & m
    if op is BinaryOp.ADD:
        return (a + b) & m
    if op is BinaryOp.SUB:
        return (a - b) & m
    if op is BinaryOp.MUL:
        return (a * b) & m
    if op is BinaryOp.AND:
        return a & b
    if op is BinaryOp.OR:
        return a | b
    if op is BinaryOp.XOR:
        return a ^ b
    if op is BinaryOp.SHL:
        return (a << (b % width)) & m
    if op is BinaryOp.SHR_U:
        return a >> (b % width)
    if op is BinaryOp.SHR_S:
        return (_to_signed(a, width) >> (b % width)) & m
    raise ValueError(f"unhandled binary op {op!r}")


def eval_const_unary(op: UnaryOp, value: int, width: int) -> int:
    m = _mask(width)
    v = value & m
    if op is UnaryOp.NOT:
        return (~v) & m
    if op is UnaryOp.NEG:
        return (-v) & m
    raise ValueError(f"unhandled unary op {op!r}")


def eval_const_compare(op: CompareOp, left: int, right: int, width: int) -> bool:
    m = _mask(width)
    a, b = left & m, right & m
    sa, sb = _to_signed(a, width), _to_signed(b, width)
    if op is CompareOp.EQ:
        return a == b
    if op is CompareOp.NE:
        return a != b
    if op is CompareOp.ULT:
        return a < b
    if op is CompareOp.ULE:
        return a <= b
    if op is CompareOp.UGT:
        return a > b
    if op is CompareOp.UGE:
        return a >= b
    if op is CompareOp.SLT:
        return sa < sb
    if op is CompareOp.SLE:
        return sa <= sb
    if op is CompareOp.SGT:
        return sa > sb
    if op is CompareOp.SGE:
        return sa >= sb
    raise ValueError(f"unhandled compare op {op!r}")
