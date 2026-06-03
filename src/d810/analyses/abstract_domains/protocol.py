"""``AbstractDomain`` — the LiSA-shaped lattice-element protocol (typed stub).

Mirrors LiSA's ``it.unive.lisa.analysis.Lattice<L>`` / ``BaseLattice<L>``: a
lattice *element* exposing the order (``leq``) and the combinators
(``join`` = lub ⊔, ``meet`` = glb ⊓, ``widen`` = ▽) plus the ⊤/⊥ queries.
:class:`KnownBits`, :class:`WrappedInterval`, and :class:`IntervalBox` all
satisfy this structurally.

Layering note: this is the per-*value* lattice element. The fixpoint engine's
whole-state view is :class:`d810.analyses.data_flow.domain.FlowDomain`
(``bottom``/``meet``/``transfer``/``equals``/``widen``); a non-relational value
analysis maps variables → ``AbstractDomain`` elements and is itself driven as a
``FlowDomain`` over ``run_fixpoint``. Keeping the two protocols distinct (element
vs flow-state) is the LiSA ``Lattice`` vs ``AbstractState`` split.

Soundness contract every implementer MUST honour (this is the invariant that
makes the recovery gap *visible* rather than a silent wrong edge):
* ``join``/``meet``/``widen`` over-approximate (never drop a feasible value);
* an unrepresentable result returns ⊤, never a wrong concrete value;
* ``widen`` guarantees termination (ascending chains stabilise).
"""
from __future__ import annotations

from d810.core.typing import Protocol, TypeVar, runtime_checkable

__all__ = ["AbstractDomain"]

L = TypeVar("L", bound="AbstractDomain")


@runtime_checkable
class AbstractDomain(Protocol):
    """A lattice element (LiSA ``Lattice<L>``)."""

    def is_bottom(self) -> bool:
        """``True`` iff this is ⊥ (the infeasible / empty element)."""
        ...

    def is_top(self) -> bool:
        """``True`` iff this is ⊤ (no information)."""
        ...

    def leq(self: L, other: L) -> bool:
        """Partial order ⊑: ``self`` is at least as precise as ``other``."""
        ...

    def join(self: L, other: L) -> L:
        """Least upper bound ⊔ (over-approximating)."""
        ...

    def meet(self: L, other: L) -> L:
        """Greatest lower bound ⊓ (over-approximating; sound for ``assume``)."""
        ...

    def widen(self: L, other: L) -> L:
        """Widening ▽ — must guarantee termination of ascending chains."""
        ...
