"""PredicateOracle — prove an OLLVM/Tigress branch guard constant (BCF defeat).

Control-flow flattening (FLA) survives our unflatten only when each handler's
next-state write folds to a *single* dispatcher state.  Bogus control flow (BCF)
breaks that: it guards the real next-state write with an **opaque predicate** ::

    v7 = A;
    if ( y < 0xA != (((((x - 1) * x) & 1) == 0) )   # always-true junk
        v7 = B;
    # v7 is now A-or-B to a constant fold -> the back-edge folds to BOTTOM
    # -> the handler is "unresolved" -> the dispatcher can't be severed.

The fix is to decide the guard *before* the next-state fold runs.  A guard the
oracle proves is a tautology collapses ``v7 = cond ? A : B`` to a single state
(a Case-1 singleton the existing region-partitioned fixpoint folds and the C3b
emitter routes); a guard it proves is a contradiction drops the dead arm.  A
guard it cannot decide is a *genuine* conditional and must be left alone (the two
arms are kept and later trace-partitioned).

This module is the **seam**: a ranked list of prove-exact-or-abstain oracles.
The first, solver-free oracle evaluates the guard over the ``KnownBits`` value
domain with every free variable at ``TOP`` -- so any verdict other than
``UNKNOWN`` holds for *all* inputs.  It folds the *constant-forced* bitwise
family OLLVM emits (``(x | 1) & 1`` etc.).  It deliberately **abstains** on the
non-relational arithmetic family (``x * (x - 1) & 1 == 0`` -- it loses the
``x`` / ``x - 1`` correlation): that is the Z3 tautology oracle's job, and an
emulation oracle handles concrete-input guards.  Both rank *behind* KnownBits
here and slot into :class:`RankedPredicateOracle` without touching callers.

Portable: pure abstract-domain evaluation, no IDA, no Hex-Rays.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.abstract_domains.operations import (
    BinaryOp,
    CompareOp,
    UnaryOp,
)
from d810.analyses.abstract_domains.relational import Satisfiability
from d810.analyses.abstract_domains.value_domain import (
    KnownBitsValueDomain,
    ValueDomain,
)
from d810.core.typing import Mapping, Protocol, Union, runtime_checkable

__all__ = [
    "Var",
    "Const",
    "BinExpr",
    "UnExpr",
    "Expr",
    "BranchGuard",
    "PredicateVerdict",
    "PredicateOracle",
    "AbstractDomainPredicateOracle",
    "RankedPredicateOracle",
    "known_bits_predicate_oracle",
    "default_predicate_oracle",
]


# --- portable guard expression AST ----------------------------------------
#
# A closed, vendor-neutral expression tree.  An adapter (a later increment)
# lifts a microcode 2-way branch (``jcc l, r`` plus the ``setX``/MBA tree that
# feeds it) into this shape; the oracle logic stays decoupled from the lifter.


@dataclass(frozen=True, slots=True)
class Var:
    """A free variable (an unknown input). Evaluates to the domain ``TOP``."""

    name: str


@dataclass(frozen=True, slots=True)
class Const:
    """A literal machine-word constant."""

    value: int


@dataclass(frozen=True, slots=True)
class BinExpr:
    """A binary operation node (``BinaryOp`` over two subexpressions)."""

    op: BinaryOp
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True, slots=True)
class UnExpr:
    """A unary operation node (``UnaryOp`` over one subexpression)."""

    op: UnaryOp
    operand: "Expr"


Expr = Union[Var, Const, BinExpr, UnExpr]


@dataclass(frozen=True, slots=True)
class BranchGuard:
    """A 2-way branch condition: ``compare(left, right)`` at a given bit width.

    ``op`` is the comparison the *taken* (true) arm tests.  ``width`` is the
    operand width in **bits** (the abstract domains are width-parametric).
    """

    op: CompareOp
    left: Expr
    right: Expr
    width: int = 32


class PredicateVerdict(Enum):
    """The decision for a branch guard, from the consumer's point of view."""

    #: Tautology -- the taken arm is unconditional; drop the other arm.
    ALWAYS_TRUE = "always_true"
    #: Contradiction -- the taken arm is dead; keep only the fall-through.
    ALWAYS_FALSE = "always_false"
    #: Both arms feasible -- a genuine conditional; keep both (partition later).
    UNKNOWN = "unknown"


@runtime_checkable
class PredicateOracle(Protocol):
    """Prove a guard constant or abstain. A non-``UNKNOWN`` verdict must be sound
    for *all* inputs (the oracle never guesses)."""

    def decide(self, guard: BranchGuard) -> PredicateVerdict: ...


# --- abstract-evaluation oracle -------------------------------------------


def _eval_expr(
    expr: Expr,
    domain: ValueDomain,
    width: int,
    env: Mapping[str, object],
):
    """Recursively evaluate ``expr`` to an abstract element of ``domain``.

    Free variables resolve to ``env[name]`` when supplied, else the domain
    ``TOP`` (no information).  Operations the domain cannot model precisely fall
    back to ``TOP`` inside the domain's own transfer functions -- a sound
    over-approximation, which is exactly what makes a non-``UNKNOWN`` verdict
    trustworthy.
    """
    if isinstance(expr, Const):
        return domain.const(expr.value, width)
    if isinstance(expr, Var):
        bound = env.get(expr.name)
        return bound if bound is not None else domain.top(width)
    if isinstance(expr, UnExpr):
        return domain.eval_unary(
            expr.op, _eval_expr(expr.operand, domain, width, env), width
        )
    if isinstance(expr, BinExpr):
        left = _eval_expr(expr.left, domain, width, env)
        right = _eval_expr(expr.right, domain, width, env)
        return domain.eval_binary(expr.op, left, right, width)
    raise TypeError(f"not a guard expression: {expr!r}")


_SATISFIABILITY_TO_VERDICT = {
    Satisfiability.SATISFIED: PredicateVerdict.ALWAYS_TRUE,
    Satisfiability.NOT_SATISFIED: PredicateVerdict.ALWAYS_FALSE,
    Satisfiability.UNKNOWN: PredicateVerdict.UNKNOWN,
}


@dataclass(frozen=True, slots=True)
class AbstractDomainPredicateOracle:
    """Decide a guard by abstract evaluation over a :class:`ValueDomain`.

    Evaluates both comparison operands with all free variables at ``TOP`` and
    asks ``domain.satisfies`` (the LiSA guard-oracle primitive) whether the
    comparison is a tautology / contradiction / undecidable.  Because the inputs
    are ``TOP``, ``SATISFIED`` / ``NOT_SATISFIED`` are universal facts.
    """

    domain: ValueDomain
    name: str = "abstract"

    def decide(self, guard: BranchGuard) -> PredicateVerdict:
        env: Mapping[str, object] = {}
        left = _eval_expr(guard.left, self.domain, guard.width, env)
        right = _eval_expr(guard.right, self.domain, guard.width, env)
        sat = self.domain.satisfies(guard.op, left, right, guard.width)
        return _SATISFIABILITY_TO_VERDICT[sat]


@dataclass(frozen=True, slots=True)
class RankedPredicateOracle:
    """The seam: try oracles in rank order; the first decisive verdict wins.

    Cheap-and-sound first (``KnownBits``, no solver), heavier oracles behind it
    (Z3 tautology proof, concrete emulation).  Every oracle is prove-or-abstain,
    so the order affects only cost, never correctness.
    """

    oracles: tuple[PredicateOracle, ...]

    def decide(self, guard: BranchGuard) -> PredicateVerdict:
        for oracle in self.oracles:
            verdict = oracle.decide(guard)
            if verdict is not PredicateVerdict.UNKNOWN:
                return verdict
        return PredicateVerdict.UNKNOWN


def known_bits_predicate_oracle() -> AbstractDomainPredicateOracle:
    """The solver-free first-rank oracle (folds constant-forced bitwise BCF)."""
    return AbstractDomainPredicateOracle(KnownBitsValueDomain(), name="known_bits")


def default_predicate_oracle() -> RankedPredicateOracle:
    """The default seam.

    KnownBits-only for now; the Z3 tautology oracle (arithmetic opaque
    predicates) and the emulation oracle (concrete-input guards) append here as
    they land, with no change to call sites.
    """
    return RankedPredicateOracle((known_bits_predicate_oracle(),))
