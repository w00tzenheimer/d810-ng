"""Unit tests for the single-trip peel GATE (pure logic, no IDA).

Exercises the source gate ``prove_single_trip(LoopFacts)`` on the REAL
bogus_loops facts and on discriminating controls, and pins that the equality
path AGREES with the legacy ``loop_prover.prove_single_iteration`` (single
source of truth for that case).  The general soundness/discrimination proof is
in ``test_single_trip_peel_soundness.py``.
"""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.loop_prover import prove_single_iteration
from d810.analyses.control_flow.single_trip_loop import (
    CmpKind,
    LoopFacts,
    prove_single_trip,
)


def _facts(cmp_kind, imm, c0, c1, size=4):
    return LoopFacts(
        guard_size=size,
        entry_const=c0,
        inloop_const=c1,
        continue_cmp=cmp_kind,
        continue_imm=imm,
    )


def test_bogus_loops_facts_prove_single_trip():
    # for (i=0; !i; i=1)  ==  continue iff (i == 0); c0=0, c1=1.
    v = prove_single_trip(_facts(CmpKind.EQ, 0, 0, 1))
    assert v.proved and v.trip_count == 1


def test_bounded_multitrip_is_refused():
    # continue iff (i <u 5); recurrence c1=1 still satisfies it -> multi-trip.
    assert not prove_single_trip(_facts(CmpKind.ULT, 5, 0, 1)).proved


def test_infinite_loop_is_refused():
    # continue iff (i == 1); recurrence c1=1 keeps the loop alive forever.
    assert not prove_single_trip(_facts(CmpKind.EQ, 1, 1, 1)).proved


def test_zero_trip_is_not_single_trip():
    # continue iff (i == 0) but entry c0=7 -> never enters -> not trip==1.
    assert not prove_single_trip(_facts(CmpKind.EQ, 0, 7, 1)).proved


def test_ne_predicate_single_trip():
    # continue iff (i != 5); entry 0 enters (0!=5), recurrence 5 exits.
    v = prove_single_trip(_facts(CmpKind.NE, 5, 0, 5))
    assert v.proved and v.trip_count == 1


def test_signed_predicate_single_trip():
    # continue iff (i s< 0); entry 0xFFFFFFFF (=-1) enters, recurrence 0 exits.
    v = prove_single_trip(_facts(CmpKind.SLT, 0, 0xFFFFFFFF, 0))
    assert v.proved and v.trip_count == 1


def test_unsigned_vs_signed_are_distinguished():
    # continue iff (i s< 0): recurrence 0x7FFFFFFF is NOT s< 0 -> exits (proved).
    assert prove_single_trip(_facts(CmpKind.SLT, 0, 0xFFFFFFFF, 0x7FFFFFFF)).proved
    # continue iff (i <u 0x80000000): 0xFFFFFFFF is NOT <u that -> exits; entry
    # 0 is <u that -> enters -> single-trip.
    assert prove_single_trip(_facts(CmpKind.ULT, 0x80000000, 0, 0xFFFFFFFF)).proved


@pytest.mark.parametrize(
    "c0,imm,c1",
    [(0, 0, 1), (5, 5, 9), (0xF6A1F, 0xF6A1F, 0xF6A20), (3, 3, 3)],
)
def test_eq_gate_agrees_with_loop_prover(c0, imm, c1):
    # The equality path must never diverge from the legacy proven gate.
    v = prove_single_trip(_facts(CmpKind.EQ, imm, c0, c1))
    assert v.proved == prove_single_iteration(c0, imm, c1, bit_width=32)
