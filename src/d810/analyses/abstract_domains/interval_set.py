"""Disjunctive interval domain: an exact disjoint union of integer intervals.

The LiSA-shaped abstract domain for a *set* of concrete machine-word values --
the disjunctive completion of a single :class:`WrappedInterval`.  Where
:class:`WrappedInterval` carries one (possibly wrapping) range,
:class:`IntervalSet` carries an exact, canonicalised disjoint union of closed
ranges over ``[0, 2**width)``, so split-range / multi-interval value sets (e.g.
a dispatcher handler reached through several disjoint state ranges) are
represented losslessly.

This is the single canonical interval-set type for the project: the decision-DAG
route oracle (``analyses.control_flow.route_predicate``) and the comparison
dispatcher router both build their partitions from it.  All set ops return a
fresh :class:`IntervalSet`.  Portable (no IDA).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Iterable, Tuple

__all__ = ["Interval", "IntervalSet"]


@dataclass(frozen=True)
class Interval:
    """A closed integer interval ``[low, high]`` (both inclusive)."""

    low: int
    high: int

    def contains(self, value: int) -> bool:
        return self.low <= value <= self.high


class IntervalSet:
    """Exact disjoint union of intervals over the unsigned space ``[0, 2**width)``.

    Canonicalised (sorted, merged, adjacency-collapsed since the domain is
    integers) and clamped to the bitwidth on construction, so equal sets have
    equal :attr:`intervals`. All set ops return a fresh :class:`IntervalSet`.
    """

    __slots__ = ("width", "mod", "intervals")

    def __init__(self, width: int, intervals: Iterable[Interval] = ()):
        self.width = int(width)
        self.mod = 1 << self.width
        self.intervals = self._canonicalise(intervals)

    def _canonicalise(self, intervals: Iterable[Interval]) -> Tuple[Interval, ...]:
        clamped = []
        for iv in intervals:
            low = max(0, int(iv.low))
            high = min(self.mod - 1, int(iv.high))
            if low <= high:
                clamped.append(Interval(low, high))
        clamped.sort(key=lambda i: (i.low, i.high))
        merged: list[Interval] = []
        for cur in clamped:
            if merged and cur.low <= merged[-1].high + 1:
                merged[-1] = Interval(merged[-1].low, max(merged[-1].high, cur.high))
            else:
                merged.append(cur)
        return tuple(merged)

    @classmethod
    def universe(cls, width: int) -> "IntervalSet":
        return cls(width, [Interval(0, (1 << width) - 1)])

    @classmethod
    def empty(cls, width: int) -> "IntervalSet":
        return cls(width, [])

    def is_empty(self) -> bool:
        return not self.intervals

    def contains(self, value: int) -> bool:
        v = int(value) & (self.mod - 1)
        return any(iv.contains(v) for iv in self.intervals)

    def intersect(self, other: "IntervalSet") -> "IntervalSet":
        out = []
        for a in self.intervals:
            for b in other.intervals:
                low = max(a.low, b.low)
                high = min(a.high, b.high)
                if low <= high:
                    out.append(Interval(low, high))
        return IntervalSet(self.width, out)

    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet(self.width, list(self.intervals) + list(other.intervals))

    def complement(self) -> "IntervalSet":
        out = []
        cursor = 0
        for iv in self.intervals:
            if iv.low > cursor:
                out.append(Interval(cursor, iv.low - 1))
            cursor = iv.high + 1
        if cursor <= self.mod - 1:
            out.append(Interval(cursor, self.mod - 1))
        return IntervalSet(self.width, out)

    def difference(self, other: "IntervalSet") -> "IntervalSet":
        return self.intersect(other.complement())

    def _xor_high_bit(self) -> "IntervalSet":
        """Remap every element ``x -> x ^ 2**(width-1)`` (splits at the sign bit).

        XOR by the high bit swaps the lower half ``[0, sb)`` with the upper half
        ``[sb, mod)`` (order-preserving within each half), so each interval is
        split at ``sb`` and each piece shifted by ``+sb`` / ``-sb``. This realises
        the signed<->unsigned reduction at the set level.
        """
        sb = self.mod >> 1
        out = []
        for iv in self.intervals:
            if iv.low <= sb - 1:  # lower-half piece -> +sb
                lo, hi = iv.low, min(iv.high, sb - 1)
                out.append(Interval(lo + sb, hi + sb))
            if iv.high >= sb:  # upper-half piece -> -sb
                lo, hi = max(iv.low, sb), iv.high
                out.append(Interval(lo - sb, hi - sb))
        return IntervalSet(self.width, out)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, IntervalSet)
            and self.width == other.width
            and self.intervals == other.intervals
        )

    def __hash__(self) -> int:
        return hash((self.width, self.intervals))

    def __repr__(self) -> str:
        if self.is_empty():
            return "{}"
        return " U ".join(f"[{i.low:#x},{i.high:#x}]" for i in self.intervals)
