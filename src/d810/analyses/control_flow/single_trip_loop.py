"""Single-trip loop-peel: proven decision gate + fact model (pure logic, NO IDA).

A loop may be peeled to straight-line code ONLY when it is *proven* to execute
its body exactly once -- never on a heuristic.  This module holds the fact model
and the proof gate; the IDA-facing extractor (``single_trip_loop_extract.py``)
enumerates the facts from live microcode.

The gate is sound given two structural preconditions the extractor enforces by
exact def-use / dominance enumeration (NOT proven here):

* **P1**: the guard variable's *sole* in-loop definition assigns the constant
  ``inloop_const`` (the recurrence value).
* **P2**: the guard is not redefined between that def and the header re-test
  (the def dominates the latch), so every back-edge entry sees ``inloop_const``.

Given P1,P2 the peel is sound iff Z3 discharges, for the header CONTINUE
predicate ``C``:

* **ob2 (enters)**:     ``C(entry_const)``       -- first entry takes the loop
* **ob1 (terminates)**: ``not C(inloop_const)``  -- recurrence forces the exit

``proved := ob1 and ob2`` (the body runs exactly once).  For the equality
predicate this is precisely
``loop_prover.prove_single_iteration(init=entry, check=imm, update=inloop)``;
we DELEGATE to it so that case has a single source of truth, and extend the
proof to the remaining comparison kinds here.

Soundness proof + discrimination + operational equivalence:
``tests/unit/analyses/control_flow/test_single_trip_peel_soundness.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from z3 import BitVecVal, BoolRef, Not, Solver, UGE, UGT, ULE, ULT, unsat

from d810.analyses.control_flow.loop_prover import prove_single_iteration


class CmpKind(Enum):
    """Normalized integer comparison for a header CONTINUE predicate.

    ``C(g) = compare(g, imm)`` under this kind.  Unsigned kinds use Z3's
    unsigned bitvector relations; signed kinds use the signed relations.
    """

    EQ = "eq"
    NE = "ne"
    ULT = "ult"
    ULE = "ule"
    UGT = "ugt"
    UGE = "uge"
    SLT = "slt"
    SLE = "sle"
    SGT = "sgt"
    SGE = "sge"


@dataclass(frozen=True)
class LoopFacts:
    """Facts for one natural loop, sufficient to PROVE (or refute) single-trip.

    Plain ints/enums only -- no IDA objects -- so the gate is pure logic.  This
    record exists only when the extractor has established P1 and P2.

    Attributes:
        guard_size: guard width in bytes.
        entry_const: ``c0`` -- guard value entering the loop (out-of-loop def).
        inloop_const: ``c1`` -- the sole in-loop constant def (the recurrence).
        continue_cmp: kind of the header CONTINUE predicate (True => stay).
        continue_imm: immediate the guard is compared against.
    """

    guard_size: int
    entry_const: int
    inloop_const: int
    continue_cmp: CmpKind
    continue_imm: int


@dataclass(frozen=True)
class PeelVerdict:
    """Result of the peel gate.  ``proved`` is only True on a discharged proof."""

    proved: bool
    reason: str
    trip_count: int | None = None
    facts: "LoopFacts | None" = None


def _valid(claim: BoolRef) -> bool:
    """True iff *claim* holds for all models (``Not(claim)`` is unsat)."""
    s = Solver()
    s.add(Not(claim))
    return s.check() == unsat


def _predicate(kind: CmpKind, imm_bv):
    """Build the Z3 CONTINUE predicate ``g -> BoolRef`` for *kind* vs *imm_bv*."""
    return {
        CmpKind.EQ: lambda g: g == imm_bv,
        CmpKind.NE: lambda g: g != imm_bv,
        CmpKind.ULT: lambda g: ULT(g, imm_bv),
        CmpKind.ULE: lambda g: ULE(g, imm_bv),
        CmpKind.UGT: lambda g: UGT(g, imm_bv),
        CmpKind.UGE: lambda g: UGE(g, imm_bv),
        CmpKind.SLT: lambda g: g < imm_bv,   # z3 BitVec relations are signed
        CmpKind.SLE: lambda g: g <= imm_bv,
        CmpKind.SGT: lambda g: g > imm_bv,
        CmpKind.SGE: lambda g: g >= imm_bv,
    }[kind]


def prove_single_trip(facts: LoopFacts) -> PeelVerdict:
    """Discharge the peel gate for *facts*.

    Returns ``proved=True`` only when Z3 proves both obligations (body runs
    exactly once).  Given P1/P2, ``proved=True`` implies peeling to
    ``body-once; exit`` is semantics-preserving.
    """
    bw = facts.guard_size * 8
    if bw <= 0:
        return PeelVerdict(False, "invalid guard size", None, facts)

    # Equality pattern: single source of truth is the existing loop_prover.
    if facts.continue_cmp is CmpKind.EQ:
        proved = prove_single_iteration(
            init_value=facts.entry_const,
            check_value=facts.continue_imm,
            update_value=facts.inloop_const,
            bit_width=bw,
        )
        return PeelVerdict(
            proved,
            "proved via loop_prover (eq)" if proved else "unproved (eq)",
            1 if proved else None,
            facts,
        )

    cond = _predicate(facts.continue_cmp, BitVecVal(facts.continue_imm, bw))
    enters = _valid(cond(BitVecVal(facts.entry_const, bw)))          # ob2
    exits = _valid(Not(cond(BitVecVal(facts.inloop_const, bw))))     # ob1
    proved = enters and exits
    return PeelVerdict(
        proved,
        f"enters(ob2)={enters} exits(ob1)={exits}",
        1 if proved else None,
        facts,
    )


__all__ = ["CmpKind", "LoopFacts", "PeelVerdict", "prove_single_trip"]
