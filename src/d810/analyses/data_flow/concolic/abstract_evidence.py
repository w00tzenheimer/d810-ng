"""``AbstractEvidence`` -- the reduced product ``KnownBits x WrappedInterval``.

The *abstract* evidence component of a :class:`~d810.analyses.data_flow.concolic.values.ConcolicValue`:
a sound over-approximation of one value, carried as a **reduced product** (Cousot
& Cousot, *Systematic design of program analysis frameworks*, POPL 1979, S10) of
the two per-value lattices already in :mod:`d810.analyses.abstract_domains`:

* :class:`~d810.analyses.abstract_domains.known_bits.KnownBits` -- bit-precise
  ({0,1,unknown} per bit); the MBA / bitwise-opaque-predicate workhorse.
* :class:`~d810.analyses.abstract_domains.wrapped_interval.WrappedInterval` --
  modular range; the branch / comparison workhorse.

The two are *incomparable* (known-bits proves ``x & 1 == 0`` where an interval
cannot; an interval bounds ``x < 10`` where bits cannot), so a product keeps both
strengths and the **reduction operator** :meth:`_reduce` propagates a fact proven
by one component into the other (a singleton in either fixes the other), staying
mutually consistent without changing the concretization.

Naming: this is the value-level *element* (LiSA ``Lattice``) -- it carries the
lattice-theoretic ``meet`` (glb), ``join`` (lub), ``widen``, ``leq``.  It is the
``abstract`` field of ``ConcolicValue``; it is NOT the router-seam
:class:`d810.analyses.data_flow.abstract_value.AbstractValue` (a sum-type
projection ``Const | Guarded | OneOf | Top``).  See ticket llr-xvkt / epic
llr-7ouc, and memory ``lattice_meet_vs_confluence_convention``.

Portable: pure delegation to the two integer lattices -- no IDA, no z3.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval

__all__ = ["AbstractEvidence"]


@dataclass(frozen=True, slots=True)
class AbstractEvidence:
    """Reduced product of a :class:`KnownBits` and a :class:`WrappedInterval`.

    Both components share ``width``; the dataclass keeps it explicit so the
    constructors do not have to reach into a component.  Constructed elements are
    always *reduced* (the static factories and every lattice op run
    :meth:`_reduce`), so the invariant "either component ⊥ ⇒ both ⊥, and a
    singleton in one is reflected in the other" holds for every value a caller
    sees.
    """

    width: int
    bits: KnownBits
    interval: WrappedInterval

    # -- constructors ------------------------------------------------------
    @staticmethod
    def top(width: int) -> "AbstractEvidence":
        """No information about the value (⊤ in both components)."""
        return AbstractEvidence(width, KnownBits.top(width), WrappedInterval.top(width))

    @staticmethod
    def bottom(width: int) -> "AbstractEvidence":
        """Infeasible / unreachable (⊥ in both components)."""
        return AbstractEvidence(
            width, KnownBits.bottom(width), WrappedInterval.bottom(width)
        )

    @staticmethod
    def singleton(value: int, width: int) -> "AbstractEvidence":
        """The fully-known element ``{value}`` (a proven concrete)."""
        return AbstractEvidence(
            width, KnownBits.of(value, width), WrappedInterval.of(value, width)
        )

    # -- queries -----------------------------------------------------------
    def is_bottom(self) -> bool:
        return self.bits.is_bottom() or self.interval.is_bottom()

    def is_top(self) -> bool:
        return self.bits.is_top() and self.interval.is_top()

    def to_const(self) -> int | None:
        """Concrete value iff either component proves a singleton (else ``None``)."""
        cb = self.bits.to_const()
        if cb is not None:
            return cb
        return self.interval.to_const()

    def contains(self, value: int) -> bool:
        """``True`` iff ``value`` is feasible in *both* components (γ membership)."""
        if self.is_bottom():
            return False
        v = value & ((1 << self.width) - 1)
        bits_ok = not self.bits.meet(KnownBits.of(v, self.width)).is_bottom()
        return bits_ok and self.interval.contains(v)

    # -- lattice (LiSA Lattice element: glb meet / lub join / widen / leq) --
    def leq(self, other: "AbstractEvidence") -> bool:
        return self.bits.leq(other.bits) and self.interval.leq(other.interval)

    def join(self, other: "AbstractEvidence") -> "AbstractEvidence":
        """Least upper bound ⊔ -- componentwise join, then reduce."""
        return AbstractEvidence(
            self.width,
            self.bits.join(other.bits),
            self.interval.join(other.interval),
        )._reduce()

    def meet(self, other: "AbstractEvidence") -> "AbstractEvidence":
        """Greatest lower bound ⊓ -- componentwise meet, then reduce."""
        return AbstractEvidence(
            self.width,
            self.bits.meet(other.bits),
            self.interval.meet(other.interval),
        )._reduce()

    def widen(self, other: "AbstractEvidence") -> "AbstractEvidence":
        """Widen ▽ -- componentwise widen, then reduce (terminating, never re-narrows)."""
        return AbstractEvidence(
            self.width,
            self.bits.widen(other.bits),
            self.interval.widen(other.interval),
        )._reduce()

    # -- reduction operator ρ (the "reduced" in reduced product) -----------
    def _reduce(self) -> "AbstractEvidence":
        """Propagate each component's singleton into the other (Cousot ρ).

        Tightening only -- the concretization is unchanged.  ``⊥`` in either
        component canonicalises the whole element to ``⊥``.  Calls the
        *components'* ``meet`` (``KnownBits``/``WrappedInterval``), never
        :meth:`AbstractEvidence.meet`, so there is no recursion.
        """
        bits, interval = self.bits, self.interval
        if bits.is_bottom() or interval.is_bottom():
            return AbstractEvidence.bottom(self.width)
        cb = bits.to_const()
        if cb is not None:
            interval = interval.meet(WrappedInterval.of(cb, self.width))
        ci = interval.to_const()
        if ci is not None:
            bits = bits.meet(KnownBits.of(ci, self.width))
        if bits.is_bottom() or interval.is_bottom():
            return AbstractEvidence.bottom(self.width)
        return AbstractEvidence(self.width, bits, interval)
