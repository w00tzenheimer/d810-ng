"""``ConcolicValue`` -- the trace-partitioned reduced-product *value* (S1).

A single abstracted value carried as **three independent evidence components**
kept mutually consistent by :func:`reduce` -- NOT a ``Concrete < Symbolic <
Abstract`` ladder (symbolic and abstract are incomparable):

* ``concrete``  -- a proven singleton (width-masked) when known, else ``None``.
* ``symbolic``  -- a portable :class:`~d810.ir.expr.SymbolicExpression` term
  (the S0-relocated BV algebra), or ``None``.  **Always ``None`` in S1** -- the
  field is present so the dataclass shape is final; the symbolic refiner + MBA
  fold land in S5.
* ``abstract``  -- a sound :class:`~d810.analyses.data_flow.concolic.abstract_evidence.AbstractEvidence`
  over-approximation (``KnownBits x WrappedInterval``).  The floor: never wrong.

Lattice ops act componentwise, then :func:`reduce` re-establishes consistency and
recomputes :class:`PrecisionStatus`.  Soundness lives in :func:`reduce`: it only
ever *tightens* the abstract component, so a missing/weaker reducer costs
precision, never soundness.  Ticket llr-xvkt / epic llr-7ouc.

Portable: no IDA, no z3 import (the S5 symbolic capability crosses a seam).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.ir.expr import SymbolicExpression

from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence

__all__ = ["PrecisionStatus", "ConcolicValue", "reduce"]


class PrecisionStatus(enum.Enum):
    """How precisely a :class:`ConcolicValue` is currently known."""

    CONCRETE = enum.auto()  # singleton proven
    SYMBOLIC = enum.auto()  # structural term known, not folded to a constant
    ABSTRACT = enum.auto()  # only a sound over-approximation
    BOTTOM = enum.auto()    # unreachable / infeasible
    TOP = enum.auto()       # no information


@dataclass(frozen=True, slots=True)
class ConcolicValue:
    """A value as ``(concrete, symbolic, abstract)`` evidence + a status tag.

    Construct via :meth:`top` / :meth:`bottom` / :meth:`of` (which reduce), not
    the raw constructor, so ``status`` and the reduced invariant always hold.
    """

    concrete: int | None
    symbolic: SymbolicExpression | None
    abstract: AbstractEvidence
    width: int
    status: PrecisionStatus

    # -- constructors ------------------------------------------------------
    @staticmethod
    def top(width: int) -> "ConcolicValue":
        """No information."""
        return reduce(
            ConcolicValue(None, None, AbstractEvidence.top(width), width, PrecisionStatus.TOP)
        )

    @staticmethod
    def bottom(width: int) -> "ConcolicValue":
        """Unreachable / infeasible."""
        return reduce(
            ConcolicValue(
                None, None, AbstractEvidence.bottom(width), width, PrecisionStatus.BOTTOM
            )
        )

    @staticmethod
    def of(value: int, width: int) -> "ConcolicValue":
        """A proven concrete singleton ``{value}`` (width-masked)."""
        c = int(value) & ((1 << width) - 1)
        return reduce(
            ConcolicValue(
                c, None, AbstractEvidence.singleton(c, width), width, PrecisionStatus.CONCRETE
            )
        )

    # -- lattice (componentwise, then reduce) ------------------------------
    def join(self, other: "ConcolicValue") -> "ConcolicValue":
        """Least upper bound: concrete agree-or-drop, symbolic structural-eq-or-drop,
        abstract join.  Status becomes the least-precise consistent with the merge."""
        self._check_width(other)
        c = self.concrete if self._concrete_agrees(other) else None
        s = self.symbolic if self._symbolic_agrees(other) else None
        a = self.abstract.join(other.abstract)
        return reduce(ConcolicValue(c, s, a, self.width, PrecisionStatus.TOP))

    def meet(self, other: "ConcolicValue") -> "ConcolicValue":
        """Greatest lower bound (the ``assume`` combinator): componentwise meet.

        Two *different* proven concretes meet to ⊥ (no value is both)."""
        self._check_width(other)
        if (
            self.concrete is not None
            and other.concrete is not None
            and self.concrete != other.concrete
        ):
            return ConcolicValue.bottom(self.width)
        c = self.concrete if self.concrete is not None else other.concrete
        s = self.symbolic if self.symbolic is not None else other.symbolic
        a = self.abstract.meet(other.abstract)
        return reduce(ConcolicValue(c, s, a, self.width, PrecisionStatus.TOP))

    def widen(self, other: "ConcolicValue") -> "ConcolicValue":
        """Widen the *abstract* component (terminating); drop symbolic/concrete that
        changed.  Never re-narrows (delegates to the components' widen)."""
        self._check_width(other)
        c = self.concrete if self._concrete_agrees(other) else None
        s = self.symbolic if self._symbolic_agrees(other) else None
        a = self.abstract.widen(other.abstract)
        return reduce(ConcolicValue(c, s, a, self.width, PrecisionStatus.TOP))

    def leq(self, other: "ConcolicValue") -> bool:
        """Partial order via concretization inclusion (the abstract floor decides;
        ``concrete`` is reflected into ``abstract`` by :func:`reduce`)."""
        return self.abstract.leq(other.abstract)

    # -- helpers -----------------------------------------------------------
    def _check_width(self, other: "ConcolicValue") -> None:
        if self.width != other.width:
            raise ValueError(
                f"width mismatch: {self.width} vs {other.width} (no implicit resize)"
            )

    def _concrete_agrees(self, other: "ConcolicValue") -> bool:
        return self.concrete is not None and self.concrete == other.concrete

    def _symbolic_agrees(self, other: "ConcolicValue") -> bool:
        return self.symbolic is not None and self.symbolic == other.symbolic


def reduce(value: ConcolicValue, sym: object | None = None) -> ConcolicValue:
    """Reduction operator ρ of the reduced product (Cousot & Cousot 1979, S10).

    Re-establishes consistency between the evidence components and recomputes
    :class:`PrecisionStatus`, **tightening only** (the concretization is
    unchanged):

    * a known ``concrete`` meets the abstract floor with its singleton;
    * ``status`` = ``BOTTOM`` if the abstract floor is ⊥, else ``CONCRETE`` /
      ``SYMBOLIC`` / ``TOP`` / ``ABSTRACT`` in precedence order.

    ``sym`` is the S5 ``SymbolicEvalCapability`` seam (symbolic→concrete fold);
    it is unused in S1 because :attr:`ConcolicValue.symbolic` is always ``None``.
    Soundness: only ever ``meet``s the abstract component and only sets
    ``concrete`` from a proven fact -- a missing reducer costs precision, not
    soundness.
    """
    _ = sym  # S5 seam; inert while symbolic is always None
    c = value.concrete
    s = value.symbolic
    a = value.abstract

    if c is not None:
        a = a.meet(AbstractEvidence.singleton(c, value.width))

    if a.is_bottom():
        return ConcolicValue(None, None, a, value.width, PrecisionStatus.BOTTOM)
    if c is not None:
        status = PrecisionStatus.CONCRETE
    elif s is not None:
        status = PrecisionStatus.SYMBOLIC
    elif a.is_top():
        status = PrecisionStatus.TOP
    else:
        status = PrecisionStatus.ABSTRACT
    return ConcolicValue(c, s, a, value.width, status)
