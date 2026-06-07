"""``ConcolicStore`` -- a per-location map of :class:`ConcolicValue` (S1).

The *value-precision* half of the trace-partitioned reduced-product domain: a
``LocationRef -> ConcolicValue`` map over stack slots + registers.  Trace
partitioning (path-sensitivity) is kept SEPARATE -- it lives in a later
``PartitionedState`` (``PathPredicate -> ConcolicStore``), not here.  Today's
``StateTransitionDomain`` is the degenerate one-partition, ``StateValue``-cell
case this generalises (the S4 migration swaps ``StateValue`` for ``ConcolicStore``).

A *missing* cell concretizes to ⊤ (no information) -- the sound choice for a
forward may-store: a location not yet written holds an unknown value, and a
merge where only one side defines a cell cannot prove anything about it.

Immutable (copy-on-write): :meth:`assign` / :meth:`join` / :meth:`widen` return
new stores.  Ticket llr-xvkt / epic llr-7ouc.  Portable: no IDA, no z3.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Iterable, Mapping

from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus

__all__ = ["ConcolicStore"]


@dataclass(frozen=True, slots=True)
class ConcolicStore:
    """``LocationRef -> ConcolicValue`` (missing key ⇒ ⊤)."""

    cells: Mapping[LocationRef, ConcolicValue] = field(default_factory=dict)

    def assign(self, loc: LocationRef, val: ConcolicValue) -> "ConcolicStore":
        """Strong update of ``loc`` to ``val`` (copy-on-write)."""
        updated = dict(self.cells)
        updated[loc] = val
        return ConcolicStore(updated)

    def eval(self, loc: LocationRef) -> ConcolicValue:
        """The value at ``loc``; ⊤ (of ``loc``'s width) when the cell is unset."""
        existing = self.cells.get(loc)
        if existing is not None:
            return existing
        return ConcolicValue.top(loc.width)

    def join(self, other: "ConcolicStore") -> "ConcolicStore":
        """Pointwise least upper bound; a key present on only one side ⇒ ⊤."""
        return self._merge(other, widen=False)

    def widen(self, other: "ConcolicStore") -> "ConcolicStore":
        """Pointwise widen (terminating); a key present on only one side ⇒ ⊤."""
        return self._merge(other, widen=True)

    def is_concrete_enough(self, locs: Iterable[LocationRef]) -> bool:
        """``True`` iff every queried location holds a ``CONCRETE`` value."""
        return all(
            self.eval(loc).status is PrecisionStatus.CONCRETE for loc in locs
        )

    # -- internal ----------------------------------------------------------
    def _merge(self, other: "ConcolicStore", *, widen: bool) -> "ConcolicStore":
        merged: dict[LocationRef, ConcolicValue] = {}
        for key in self.cells.keys() | other.cells.keys():
            left = self.cells.get(key)
            right = other.cells.get(key)
            if left is None or right is None:
                # Defined on only one path -> ⊤ (cannot prove anything sound).
                merged[key] = ConcolicValue.top(key.width)
            else:
                merged[key] = left.widen(right) if widen else left.join(right)
        return ConcolicStore(merged)
