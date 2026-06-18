"""Portable expression substrate (LLVM / LiSA-style).

Backend-neutral expression trees over the value substrate, so portable analyses
(recurrence, induction, strength-reduction) can model update expressions without
vendor instruction objects (Landing Sequence LS8 substrate front-load).

``ExprRef`` is the closed union over the concrete expression nodes implemented
today.  ``ValueOpKind`` is broader: it is the stable, backend-neutral operation
vocabulary a lifter can use before every operation has a dedicated expression
node.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Union
from d810.ir.value_refs import ValueRef

__all__ = [
    "Add",
    "And",
    "Const",
    "ExprRef",
    "Load",
    "Move",
    "Store",
    "Sub",
    "ValueOpKind",
]


class ValueOpKind(str, Enum):
    """Machine-near value operation family.

    Width is intentionally not encoded here; it belongs to the value/varnode.
    Signedness is encoded when it changes the operation algorithm.
    """

    CONST = "const"
    MOVE = "move"
    LOAD = "load"
    STORE = "store"
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    UDIV = "udiv"
    SDIV = "sdiv"
    UMOD = "umod"
    SMOD = "smod"
    OR = "or"
    AND = "and"
    XOR = "xor"
    NOT = "not"
    LNOT = "lnot"
    NEG = "neg"
    SHL = "shl"
    SHR = "shr"
    SAR = "sar"
    ROL = "rol"
    ROR = "ror"
    ZEXT = "zext"
    SEXT = "sext"
    TRUNC = "trunc"
    LOW = "low"
    HIGH = "high"
    CARRY_ADD = "carry_add"
    OVERFLOW_ADD = "overflow_add"
    OVERFLOW_FLAG = "overflow_flag"
    CARRY_SHL = "carry_shl"
    CARRY_SHR = "carry_shr"
    SIGN_BIT = "sign_bit"
    PARITY = "parity"
    VENDOR = "vendor"


@dataclass(frozen=True)
class Const:
    """An integer literal."""

    value: int


@dataclass(frozen=True)
class Move:
    """A copy / use of an existing value."""

    source: ValueRef


@dataclass(frozen=True)
class Add:
    """Two-operand addition."""

    left: "ExprRef"
    right: "ExprRef"


@dataclass(frozen=True)
class Sub:
    """Two-operand subtraction."""

    left: "ExprRef"
    right: "ExprRef"


@dataclass(frozen=True)
class And:
    """Two-operand bitwise AND (the common MBA-mask shape)."""

    left: "ExprRef"
    right: "ExprRef"


@dataclass(frozen=True)
class Load:
    """A memory load from a computed address."""

    address: "ExprRef"


@dataclass(frozen=True)
class Store:
    """A memory store of ``value`` to a computed ``address``."""

    address: "ExprRef"
    value: "ExprRef"


ExprRef = Union[Const, Move, Add, Sub, And, Load, Store]
"""Closed union of the concrete expression-node families."""
