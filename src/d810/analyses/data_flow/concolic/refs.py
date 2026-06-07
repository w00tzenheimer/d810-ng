"""Portable value/location references for the concolic store (no IDA, no z3).

* :class:`LocationRef` -- a storage cell the analysis tracks: a stack slot
  (frame offset) or a register, plus its byte ``width``.  This is what
  :class:`~d810.analyses.data_flow.concolic.store.ConcolicStore` keys on, so the
  store stays portable -- the Hex-Rays backend translates live ``mop_t`` <->
  ``LocationRef`` at the seam (a later slice), the value layer never sees a mop.
* :class:`ValueRef` -- a *stub* for S5: a location-anchored, def-site-keyed
  identity for an SSA-ish produced value (the leaf identity the relocated
  ``SymbolicExpression.Var`` will carry).  No expression logic here yet.

Ticket llr-xvkt (S1); full ``ValueRef``/``ExprRef`` design lands in S5.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class LocationKind(enum.Enum):
    """Where a tracked cell lives.  S1-S4 model only stack slots + registers."""

    STACK = enum.auto()
    REGISTER = enum.auto()


@dataclass(frozen=True, slots=True)
class LocationRef:
    """A storage cell: ``(kind, key, width)``.

    ``key`` is the frame offset for :attr:`LocationKind.STACK` or the register id
    for :attr:`LocationKind.REGISTER`.  Frozen + hashable so it can key the
    store's cell map; equality is structural.
    """

    kind: LocationKind
    key: int
    width: int

    @staticmethod
    def stack(offset: int, width: int) -> "LocationRef":
        """A stack slot at frame ``offset`` of ``width`` bytes."""
        return LocationRef(LocationKind.STACK, int(offset), int(width))

    @staticmethod
    def reg(reg_id: int, width: int) -> "LocationRef":
        """A register ``reg_id`` of ``width`` bytes."""
        return LocationRef(LocationKind.REGISTER, int(reg_id), int(width))

    def __repr__(self) -> str:
        if self.kind is LocationKind.STACK:
            return f"stack[{self.key:#x}]:{self.width}"
        return f"reg({self.key}):{self.width}"


@dataclass(frozen=True, slots=True)
class ValueRef:
    """Stub (S5): a def-site-anchored handle for a produced value.

    ``location`` is where the value is written; ``def_site`` identifies the
    defining program point (block/insn id), ``None`` for an entry / unknown
    definition.  In S5 this becomes the leaf identity of the relocated
    ``SymbolicExpression.Var`` so symbolic terms are location-anchored rather
    than string-keyed.  Carried here only so the package shape is final.
    """

    location: LocationRef
    def_site: int | None = None
