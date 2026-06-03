"""Non-relational interval *box* — a per-variable map of wrapped intervals.

This is the honest name for what a per-variable interval projection actually is:
a Cartesian product of independent intervals, with **no inter-variable
constraints**. (The pasted "Polyhedra" whose ``join`` projected to per-variable
intervals was, in fact, exactly this box — so it is named accordingly rather
than implying relational power it does not have. Genuine relational reasoning
lives behind :mod:`d810.analyses.abstract_domains.relational`.)

A missing variable is implicitly ⊤ (unconstrained). The box is ⊥ if any
variable's interval is ⊥. Lattice ops are pointwise over the union of keys.
Portable: no IDA.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval

__all__ = ["IntervalBox"]


@dataclass(frozen=True, slots=True)
class IntervalBox:
    width: int
    intervals: dict = field(default_factory=dict)  # var name -> WrappedInterval
    _bottom: bool = False

    @staticmethod
    def top(width: int) -> "IntervalBox":
        return IntervalBox(width, {}, False)

    @staticmethod
    def bottom(width: int) -> "IntervalBox":
        return IntervalBox(width, {}, True)

    def is_top(self) -> bool:
        return not self._bottom and all(v.is_top() for v in self.intervals.values())

    def is_bottom(self) -> bool:
        return self._bottom or any(v.is_bottom() for v in self.intervals.values())

    def get(self, var: str) -> WrappedInterval:
        return self.intervals.get(var, WrappedInterval.top(self.width))

    def assign(self, var: str, value: WrappedInterval) -> "IntervalBox":
        if value.is_bottom():
            return IntervalBox.bottom(self.width)
        nxt = dict(self.intervals)
        nxt[var] = value
        return IntervalBox(self.width, nxt, self._bottom)

    def _keys(self, other: "IntervalBox") -> set:
        return set(self.intervals) | set(other.intervals)

    def leq(self, other: "IntervalBox") -> bool:
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        return all(self.get(v).leq(other.get(v)) for v in self._keys(other))

    def join(self, other: "IntervalBox") -> "IntervalBox":
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return IntervalBox(
            self.width,
            {v: self.get(v).join(other.get(v)) for v in self._keys(other)},
            False,
        )

    def meet(self, other: "IntervalBox") -> "IntervalBox":
        if self.is_bottom() or other.is_bottom():
            return IntervalBox.bottom(self.width)
        merged = {}
        for v in self._keys(other):
            m = self.get(v).meet(other.get(v))
            if m.is_bottom():
                return IntervalBox.bottom(self.width)
            merged[v] = m
        return IntervalBox(self.width, merged, False)

    def widen(self, other: "IntervalBox") -> "IntervalBox":
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return IntervalBox(
            self.width,
            {v: self.get(v).widen(other.get(v)) for v in self._keys(other)},
            False,
        )

    def __repr__(self) -> str:
        if self.is_bottom():
            return f"IntervalBox.bottom(w{self.width})"
        if not self.intervals:
            return f"IntervalBox.top(w{self.width})"
        body = ", ".join(f"{k}={v!r}" for k, v in sorted(self.intervals.items()))
        return f"IntervalBox({body})"
