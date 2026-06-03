"""Wrapped (modular) interval domain for machine words.

Unlike a naive ``[low, high]`` over the integers, a *wrapped* interval is closed
under machine arithmetic: it is an arc over the circle ``Z / 2^width``. This is
the only sound interval representation for word analysis — e.g. unsigned 8-bit
``[254,255] + [1,1]`` is the wrapped set ``{255, 0}`` (the arc ``[255, 0]``),
which a non-wrapping ``[low,high]`` would mis-handle by dropping ``0``.

Representation (Gange/Navas "interval analysis & machine arithmetic"): a
non-trivial element is ``[lo, hi]`` meaning ``{lo, lo+1, …, hi}`` counted by
incrementing mod ``2^width`` (so ``lo > hi`` wraps). Plus explicit ``⊤`` (all
``2^width`` values) and ``⊥`` (empty).

Lattice ops: ``join`` is the precise wrapped least-upper-bound (fill the larger
gap); ``meet`` and ``widen`` are sound (``meet`` over-approximates the
intersection so ``assume`` never drops a feasible value; ``widen`` jumps to ⊤
when the arc grows, guaranteeing termination). Portable: pure integer, no IDA.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.data_flow.abstract_value import TOP, AbstractValue, Const, OneOf

__all__ = ["WrappedInterval"]

#: Enumerate an interval as a finite ``OneOf`` only while it is no wider than
#: this; broader arcs project to ``⊤`` (no silent enumeration of huge ranges).
#: Matches ``StateValue.MAX_CONSTS`` so the two powerset seams stay aligned.
_ONEOF_PROJECTION_CAP = 256


@dataclass(frozen=True, slots=True)
class WrappedInterval:
    width: int
    lo: int = 0
    hi: int = 0
    kind: str = "range"  # "range" | "top" | "bottom"

    @property
    def _mod(self) -> int:
        return 1 << self.width

    # -- constructors ------------------------------------------------------
    @staticmethod
    def of(value: int, width: int) -> "WrappedInterval":
        v = value & ((1 << width) - 1)
        return WrappedInterval(width, v, v, "range")

    @staticmethod
    def top(width: int) -> "WrappedInterval":
        return WrappedInterval(width, 0, 0, "top")

    @staticmethod
    def bottom(width: int) -> "WrappedInterval":
        return WrappedInterval(width, 0, 0, "bottom")

    # -- queries -----------------------------------------------------------
    def is_top(self) -> bool:
        return self.kind == "top"

    def is_bottom(self) -> bool:
        return self.kind == "bottom"

    def cardinality(self) -> int:
        if self.is_bottom():
            return 0
        if self.is_top():
            return self._mod
        return ((self.hi - self.lo) % self._mod) + 1

    def contains(self, value: int) -> bool:
        if self.is_bottom():
            return False
        if self.is_top():
            return True
        v = value & (self._mod - 1)
        return (v - self.lo) % self._mod <= (self.hi - self.lo) % self._mod

    def to_const(self) -> int | None:
        return self.lo if self.kind == "range" and self.lo == self.hi else None

    # -- projection into the router value-side seam (S0) --------------------
    def project(self) -> AbstractValue:
        """Project this arc into an :class:`AbstractValue`.

        Singleton arc → :class:`Const` (byte ``size`` is ``width // 8``, min 1);
        a bounded arc of at most :data:`_ONEOF_PROJECTION_CAP` values → an
        enumerated :class:`OneOf`; ⊤ or a broader arc → :data:`TOP` (no silent
        enumeration of a huge range).
        """
        c = self.to_const()
        if c is not None:
            return Const(c, max(1, self.width // 8))
        if self.is_top() or self.is_bottom():
            return TOP
        card = self.cardinality()
        if card > _ONEOF_PROJECTION_CAP:
            return TOP
        m = self._mod
        return OneOf(frozenset((self.lo + i) % m for i in range(card)))

    # -- lattice order -----------------------------------------------------
    def leq(self, other: "WrappedInterval") -> bool:
        """⊑ : every value of ``self`` is in ``other``."""
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        if other.is_top():
            return True
        if self.is_top():
            return False
        m = self._mod
        # self's start offset into other + self's length <= other's length
        off = (self.lo - other.lo) % m
        len_self = (self.hi - self.lo) % m
        len_other = (other.hi - other.lo) % m
        return off + len_self <= len_other

    # -- combinators -------------------------------------------------------
    def join(self, other: "WrappedInterval") -> "WrappedInterval":
        """Precise wrapped least-upper-bound: cover both, filling the wider gap."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return WrappedInterval.top(self.width)
        if self.leq(other):
            return other
        if other.leq(self):
            return self
        a, b, c, d = self.lo, self.hi, other.lo, other.hi
        # Two candidate hulls: [a,d] and [c,b]. Pick whichever (a) covers both
        # and (b) is smaller; if both fail to cover, the union wraps fully.
        cand = []
        for lo, hi in ((a, d), (c, b)):
            h = WrappedInterval(self.width, lo, hi, "range")
            if self.leq(h) and other.leq(h):  # h covers both
                cand.append(h)
        if not cand:
            return WrappedInterval.top(self.width)
        return min(cand, key=lambda h: h.cardinality())

    def meet(self, other: "WrappedInterval") -> "WrappedInterval":
        """Sound (over-approximating) greatest-lower-bound for ``assume``.

        Disjoint -> ⊥ (the only precise, refutation-relevant case). Containment
        -> the smaller. Otherwise the smaller-cardinality operand, which always
        ⊇ the true intersection (A∩B ⊆ A and ⊆ B), so this never drops a
        feasible value. Imprecise on partial overlap; refinement is a later add.
        """
        if self.is_bottom() or other.is_bottom():
            return WrappedInterval.bottom(self.width)
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.leq(other):
            return self
        if other.leq(self):
            return other
        if self._disjoint(other):
            return WrappedInterval.bottom(self.width)
        return self if self.cardinality() <= other.cardinality() else other

    def _disjoint(self, other: "WrappedInterval") -> bool:
        if self.is_bottom() or other.is_bottom():
            return True
        if self.is_top() or other.is_top():
            return False
        # disjoint iff neither contains any of the other's endpoints
        return not (
            self.contains(other.lo)
            or self.contains(other.hi)
            or other.contains(self.lo)
            or other.contains(self.hi)
        )

    def widen(self, other: "WrappedInterval") -> "WrappedInterval":
        """Sound, terminating: jump to ⊤ if the arc grows under join."""
        j = self.join(other)
        if j.leq(self):  # not growing
            return self
        if j.cardinality() > self.cardinality():
            return WrappedInterval.top(self.width)
        return j

    # -- modular arithmetic transfer functions -----------------------------
    def _binop_guard(self, other: "WrappedInterval") -> "WrappedInterval | None":
        if self.is_bottom() or other.is_bottom():
            return WrappedInterval.bottom(self.width)
        if self.is_top() or other.is_top():
            return WrappedInterval.top(self.width)
        m = self._mod
        # result arc length = len_self + len_other; if it fills the word, ⊤.
        if ((self.hi - self.lo) % m) + ((other.hi - other.lo) % m) >= m - 1:
            return WrappedInterval.top(self.width)
        return None

    def add(self, other: "WrappedInterval") -> "WrappedInterval":
        """[a,b] + [c,d]  =  [a+c, b+d]  (mod 2^width)."""
        guarded = self._binop_guard(other)
        if guarded is not None:
            return guarded
        m = self._mod
        return WrappedInterval(
            self.width, (self.lo + other.lo) % m, (self.hi + other.hi) % m, "range"
        )

    def sub(self, other: "WrappedInterval") -> "WrappedInterval":
        """[a,b] - [c,d]  =  [a-d, b-c]  (mod 2^width)."""
        guarded = self._binop_guard(other)
        if guarded is not None:
            return guarded
        m = self._mod
        return WrappedInterval(
            self.width, (self.lo - other.hi) % m, (self.hi - other.lo) % m, "range"
        )

    def __repr__(self) -> str:
        if self.is_bottom():
            return f"WrappedInterval.bottom(w{self.width})"
        if self.is_top():
            return f"WrappedInterval.top(w{self.width})"
        return f"[{self.lo:#x}, {self.hi:#x}]_w{self.width}"
