"""Relational numeric domain — seam for Octagon / Polyhedra (deliberately a stub).

Relational domains track inter-variable *linear* invariants (Octagon:
``±x ± y ≤ c``; Polyhedra: ``A·x ≤ b``). Their value here is **opaque-predicate /
bogus-control-flow refutation**: proving a guard infeasible from accumulated
path constraints so the dead arm can be pruned. They are the right tool for
*linear* opaque predicates — but NOT for the bitwise/MBA ones OLLVM favours,
which belong to :mod:`known_bits` and to SMT/term-rewriting. So this is a
deliberately-deferred backend, exposed only as a typed seam.

``NullRelational`` is the safe default: it asserts nothing and refutes nothing
(``classify`` always ``UNKNOWN``), so wiring it in can never wrongly prune a
real branch. Swapping in a real (closed Octagon / LP-backed Polyhedra) backend
is a backend change behind :class:`RelationalDomain` — not an architecture
change. We do NOT ship a per-variable "box" mislabelled as relational, because a
silent under-pruner is worse than an honest ``UNKNOWN``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Protocol, runtime_checkable

__all__ = ["Satisfiability", "LinearConstraint", "RelationalDomain", "NullRelational"]


class Satisfiability(Enum):
    """LiSA-style three-valued guard verdict (``BaseNonRelationalValueDomain``)."""

    SATISFIED = "satisfied"  # guard is a tautology  -> unconditional edge
    NOT_SATISFIED = "unsatisfied"  # guard is a contradiction -> drop the arm
    UNKNOWN = "unknown"  # both feasible -> a real conditional


@dataclass(frozen=True, slots=True)
class LinearConstraint:
    """``sum(coeff_i * var_i) <= rhs`` — a single linear inequality."""

    coeffs: tuple  # tuple[(str, int), ...]
    rhs: int


@runtime_checkable
class RelationalDomain(Protocol):
    """A relational numeric abstract element (Octagon / Polyhedra backend)."""

    def is_bottom(self) -> bool: ...
    def is_top(self) -> bool: ...
    def leq(self, other: "RelationalDomain") -> bool: ...
    def join(self, other: "RelationalDomain") -> "RelationalDomain": ...
    def meet(self, other: "RelationalDomain") -> "RelationalDomain": ...
    def widen(self, other: "RelationalDomain") -> "RelationalDomain": ...
    def assume(self, constraint: LinearConstraint) -> "RelationalDomain": ...
    def classify(self, constraint: LinearConstraint) -> Satisfiability: ...


@dataclass(frozen=True, slots=True)
class NullRelational:
    """Sound no-op backend: knows nothing, refutes nothing. Always ⊤."""

    def is_bottom(self) -> bool:
        return False

    def is_top(self) -> bool:
        return True

    def leq(self, other: "RelationalDomain") -> bool:
        return bool(other.is_top())

    def join(self, other: "RelationalDomain") -> "RelationalDomain":
        return self

    def meet(self, other: "RelationalDomain") -> "RelationalDomain":
        return other

    def assume(self, constraint: LinearConstraint) -> "RelationalDomain":
        # cannot record relational facts -> stays ⊤ (sound: never refutes)
        return self

    def widen(self, other: "RelationalDomain") -> "RelationalDomain":
        return self

    def classify(self, constraint: LinearConstraint) -> Satisfiability:
        return Satisfiability.UNKNOWN
