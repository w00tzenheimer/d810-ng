"""Known-bits (bitfield) abstract domain — the MBA workhorse.

A per-bit three-valued lattice over machine words: each bit is known-0,
known-1, or unknown (⊤). This is the LLVM ``KnownBits`` representation (two
masks: ``zero`` = bits proven 0, ``one`` = bits proven 1), which is the right
domain for the *bitwise* mixed-boolean-arithmetic OLLVM uses — it folds
``&``/``|``/``^``/``~`` precisely, and it refutes the bitwise opaque predicates
that linear relational domains (Octagon/Polyhedra) structurally cannot.

LiSA-shaped lattice (``it.unive.lisa.analysis.Lattice`` / ``BaseLattice``):

* ``top(w)``  — every bit unknown.
* ``bottom(w)`` — infeasible (a bit proven both 0 and 1 = a contradiction).
* ``join`` (lub ⊔): a bit stays known only where both agree.
* ``meet`` (glb ⊓): union the knowledge; a 0/1 clash collapses to ⊥.
* ``widen``: identity-as-``join`` — the lattice has finite height (≤ 2·width),
  so the ascending chain condition holds and no real widening is needed.

Portable: pure integer masks, no IDA, no float.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["KnownBits"]


@dataclass(frozen=True, slots=True)
class KnownBits:
    """A machine word abstracted bit-by-bit as {0, 1, unknown}.

    Invariant for a non-⊥ element: ``zero & one == 0`` (no bit is both). A bit
    is *unknown* when it is set in neither mask.
    """

    width: int
    zero: int = 0  # bits proven to be 0
    one: int = 0   # bits proven to be 1

    @property
    def _mask(self) -> int:
        return (1 << self.width) - 1

    # -- constructors ------------------------------------------------------
    @staticmethod
    def top(width: int) -> "KnownBits":
        """Every bit unknown — no information."""
        return KnownBits(width, 0, 0)

    @staticmethod
    def bottom(width: int) -> "KnownBits":
        """Infeasible — represented canonically as every bit in conflict."""
        mask = (1 << width) - 1
        return KnownBits(width, mask, mask)

    @staticmethod
    def of(value: int, width: int) -> "KnownBits":
        """Lift a concrete value to the fully-known element."""
        mask = (1 << width) - 1
        v = value & mask
        return KnownBits(width, (~v) & mask, v)

    # -- lattice queries ---------------------------------------------------
    def is_top(self) -> bool:
        return self.zero == 0 and self.one == 0

    def is_bottom(self) -> bool:
        # any bit asserted both 0 and 1 is a contradiction
        return (self.zero & self.one) != 0

    def to_const(self) -> int | None:
        """Return the concrete value iff every bit is known (and feasible)."""
        if self.is_bottom():
            return None
        if (self.zero | self.one) & self._mask != self._mask:
            return None
        return self.one & self._mask

    # -- lattice order + combinators (LiSA Lattice) ------------------------
    def leq(self, other: "KnownBits") -> bool:
        """Partial order ⊑: ``self`` is at least as precise as ``other``."""
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        # every bit other proves, self proves identically
        return (
            self.zero & other.zero == other.zero
            and self.one & other.one == other.one
        )

    def join(self, other: "KnownBits") -> "KnownBits":
        """Least upper bound ⊔: keep only the bits both agree on."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return KnownBits(self.width, self.zero & other.zero, self.one & other.one)

    def meet(self, other: "KnownBits") -> "KnownBits":
        """Greatest lower bound ⊓: union the knowledge (may go ⊥ on clash)."""
        if self.is_bottom() or other.is_bottom():
            return KnownBits.bottom(self.width)
        return KnownBits(self.width, self.zero | other.zero, self.one | other.one)

    def widen(self, other: "KnownBits") -> "KnownBits":
        # finite height -> join suffices (no infinite ascending chains)
        return self.join(other)

    # -- bitwise transfer functions (the MBA-relevant part) ----------------
    def band(self, other: "KnownBits") -> "KnownBits":
        # 0 if either is 0; 1 only if both are 1
        zero = self.zero | other.zero
        one = self.one & other.one
        return KnownBits(self.width, zero, one)

    def bor(self, other: "KnownBits") -> "KnownBits":
        # 1 if either is 1; 0 only if both are 0
        zero = self.zero & other.zero
        one = self.one | other.one
        return KnownBits(self.width, zero, one)

    def bxor(self, other: "KnownBits") -> "KnownBits":
        # known only where BOTH inputs know the bit
        known = (self.zero | self.one) & (other.zero | other.one)
        one = ((self.one & other.zero) | (self.zero & other.one)) & known
        zero = ((self.zero & other.zero) | (self.one & other.one)) & known
        return KnownBits(self.width, zero, one)

    def bnot(self) -> "KnownBits":
        # swap proven-0 and proven-1; unknown stays unknown
        return KnownBits(self.width, self.one, self.zero)

    def __repr__(self) -> str:
        if self.is_bottom():
            return f"KnownBits.bottom({self.width})"
        chars = []
        for i in range(self.width - 1, -1, -1):
            bit = 1 << i
            if self.one & bit:
                chars.append("1")
            elif self.zero & bit:
                chars.append("0")
            else:
                chars.append("?")
        return "0b" + "".join(chars)
