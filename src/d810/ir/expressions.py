"""Portable expression substrate (LLVM / LiSA-style).

Backend-neutral expression trees over the value substrate, so portable analyses
(recurrence, induction, strength-reduction) can model update expressions without
vendor instruction objects (Landing Sequence LS8 substrate front-load).

Minimum viable scope: the operation families the recurrence / induction analyses
need (``Const``, ``Move``, ``Add``, ``Sub``, ``Load``, ``Store``).  ``ExprRef``
is the closed union over them; ``ValueOpKind`` is the parallel operation-family
enum for consumers that switch on op kind.  Extend on demand -- do NOT preload
the full microcode operation space (see ``d810.ir.semantics`` for the planned
families).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from d810.core.typing import Union
from d810.ir.value_refs import ValueRef

__all__ = [
    "Add",
    "Const",
    "ExprRef",
    "Load",
    "Move",
    "Store",
    "Sub",
    "ValueOpKind",
]


class ValueOpKind(Enum):
    """Operation family for a portable expression node."""

    CONST = auto()
    MOVE = auto()
    ADD = auto()
    SUB = auto()
    LOAD = auto()
    STORE = auto()


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
class Load:
    """A memory load from a computed address."""

    address: "ExprRef"


@dataclass(frozen=True)
class Store:
    """A memory store of ``value`` to a computed ``address``."""

    address: "ExprRef"
    value: "ExprRef"


ExprRef = Union[Const, Move, Add, Sub, Load, Store]
"""Closed union of the concrete expression-node families."""
