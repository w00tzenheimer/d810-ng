"""Z3 soundness proof for the single-trip loop-peel GATE (pure logic, no IDA).

The peel must be PROVEN sound, never heuristic.  Two structural preconditions
are established by exact DU/liveness enumeration in the recognizer (not here):

  P1: the guard var's SOLE in-loop definition assigns a loop-invariant constant
      ``c1`` (so every back-edge entry sees ``G == c1``).
  P2: the guard is not redefined between that def and the header re-test.

Given P1,P2 the peel is sound iff Z3 discharges two arithmetic obligations over
the header CONTINUE predicate ``C``:

  ob1 (termination):   ``¬C(c1)``  -- the recurrence value forces EXIT, so the
                       back-edge is provably dead (body runs at most once).
  ob2 (non-degenerate): ``C(c0)``  -- the entry value takes the loop, so the
                       trip count is exactly 1 (not 0).

Real ``bogus_loops`` facts (samples/src/c/unwrap_loops.c), verified on live
microcode in tests/system/runtime/evaluator/test_du_reaching_defs_single_trip.py
and test_valrange_single_trip.py:
    c0 = 0 (entry def ``mov #0, var_18``), c1 = 1 (sole in-loop ``mov #1``),
    header CONTINUE predicate ``C(g) = (g == 0)``.
"""
from __future__ import annotations

from z3 import (
    And,
    BitVec,
    BitVecVal,
    BoolRef,
    If,
    Implies,
    Not,
    Solver,
    ULT,
    sat,
    unsat,
)

BW = 32  # guard width .4 (32-bit), per the DU / valrange dumps


def _is_valid(claim: BoolRef) -> bool:
    """True iff *claim* holds for all models (``Not(claim)`` is unsat)."""
    s = Solver()
    s.add(Not(claim))
    return s.check() == unsat


def peel_gate_obligations(c0, c1, cond):
    """The peel gate's two Z3 obligations.

    Args:
        c0: entry (out-of-loop) guard value.
        c1: sole in-loop constant guard value (the recurrence).
        cond: header CONTINUE predicate, a callable ``BitVec -> BoolRef``.

    Returns:
        ``(ob1_termination, ob2_enters)`` booleans.  A single-trip peel is
        sound iff both are ``True``.
    """
    ob1 = _is_valid(Not(cond(c1)))  # recurrence forces EXIT => back-edge dead
    ob2 = _is_valid(cond(c0))       # first entry takes the loop => exactly 1 trip
    return ob1, ob2


# --- the real target ---------------------------------------------------------


def test_bogus_loops_single_trip_is_proved():
    c0, c1 = BitVecVal(0, BW), BitVecVal(1, BW)
    ob1, ob2 = peel_gate_obligations(c0, c1, lambda g: g == 0)
    assert ob1 and ob2  # peel FIRES


# --- discrimination: the gate must REFUSE unsound peels ----------------------


def test_bounded_multitrip_loop_is_refused():
    # CONTINUE iff g <u 5; recurrence c1 = 1 still satisfies it -> not single-trip.
    ob1, _ = peel_gate_obligations(BitVecVal(0, BW), BitVecVal(1, BW), lambda g: ULT(g, 5))
    assert not ob1  # ob1 fails -> gate ABSTAINS


def test_infinite_loop_is_refused():
    # CONTINUE iff g == 1; recurrence c1 = 1 keeps the loop alive forever.
    ob1, _ = peel_gate_obligations(BitVecVal(1, BW), BitVecVal(1, BW), lambda g: g == 1)
    assert not ob1  # gate ABSTAINS


# --- generality: the termination obligation holds for the whole family -------


def test_eq_zero_predicate_family_termination_is_general():
    # For CONTINUE = (g == 0), ANY nonzero recurrence constant forces exit.
    c1 = BitVec("c1", BW)
    assert _is_valid(Implies(c1 != 0, Not(c1 == 0)))


# --- operational equivalence: ob1 collapses the loop to the peeled form ------


def test_peel_is_semantics_preserving_under_ob1():
    """2-unroll equivalence, complete because after one body exec the guard is
    permanently ``c1`` (P1) so any later visit re-tests ``C(c1)``.

    Claim: assuming ob1 (``¬C(c1)``), the original loop and the peeled program
    (run body iff ``C(c0)``, then exit) execute the body the same number of
    times and leave the guard at the same value -- for ALL ``c0, c1``.
    """
    c0, c1 = BitVec("c0", BW), BitVec("c1", BW)
    C = lambda g: g == 0

    enter1 = C(c0)
    enter2 = And(enter1, C(c1))  # would a 2nd visit continue?
    body_execs_orig = If(enter1, If(enter2, 2, 1), 0)
    exit_g_orig = If(enter1, c1, c0)

    body_execs_peel = If(C(c0), 1, 0)
    exit_g_peel = If(C(c0), c1, c0)

    equiv = And(body_execs_orig == body_execs_peel, exit_g_orig == exit_g_peel)

    # Under the termination obligation, loop and peel are provably equivalent.
    assert _is_valid(Implies(Not(C(c1)), equiv))

    # ob1 is load-bearing: WITHOUT it the equivalence is not valid in general
    # (when C(c1) holds the loop runs the body twice in the 2-unroll).
    s = Solver()
    s.add(Not(equiv))
    assert s.check() == sat
