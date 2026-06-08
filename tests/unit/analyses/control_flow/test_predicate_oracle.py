"""Unit tests for the PredicateOracle seam (ticket llr-nr6x).

The KnownBits-first oracle proves a guard constant or abstains -- it must fold
the *constant-forced* bitwise opaque predicates OLLVM/Tigress BCF emits, and it
must honestly ABSTAIN on the non-relational arithmetic family (that is the Z3
tautology oracle, ranked behind).  A wrong "always-true" here would gut a real
branch, so every non-UNKNOWN verdict must be sound for all inputs.
"""
from __future__ import annotations

from d810.analyses.abstract_domains.operations import BinaryOp, CompareOp, UnaryOp
from d810.analyses.control_flow.predicate_oracle import (
    BinExpr,
    BranchGuard,
    Const,
    PredicateOracle,
    PredicateVerdict,
    RankedPredicateOracle,
    UnExpr,
    Var,
    default_predicate_oracle,
    known_bits_predicate_oracle,
)


def _decide(guard: BranchGuard) -> PredicateVerdict:
    return known_bits_predicate_oracle().decide(guard)


# --- constant-forced bitwise opaque predicates KnownBits CAN fold ----------


def test_known_bits_folds_or_one_and_one_tautology() -> None:
    # ((x | 1) & 1) == 1 is ALWAYS TRUE: OR forces bit0=1, AND isolates it.
    # x is free (TOP) yet the result is fully known -> universal fact.
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(
            BinaryOp.AND,
            BinExpr(BinaryOp.OR, Var("x"), Const(1)),
            Const(1),
        ),
        right=Const(1),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.ALWAYS_TRUE


def test_known_bits_folds_or_one_and_one_contradiction() -> None:
    # ((x | 1) & 1) == 0 is ALWAYS FALSE -- the BCF "dead arm" form.
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(
            BinaryOp.AND,
            BinExpr(BinaryOp.OR, Var("x"), Const(1)),
            Const(1),
        ),
        right=Const(0),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.ALWAYS_FALSE


def test_known_bits_folds_and_zero_is_zero() -> None:
    # (x & 0) != 0 is ALWAYS FALSE: masking by 0 forces every bit to 0.
    guard = BranchGuard(
        op=CompareOp.NE,
        left=BinExpr(BinaryOp.AND, Var("x"), Const(0)),
        right=Const(0),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.ALWAYS_FALSE


def test_known_bits_refutes_forced_bit_equality() -> None:
    # (x | 1) == 0: bit0 is proven 1 on the left, 0 on the right -> they can
    # never be equal (bitwise refutation, no full constant needed).
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(BinaryOp.OR, Var("x"), Const(1)),
        right=Const(0),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.ALWAYS_FALSE


# --- the honest abstentions (Z3 / emulation territory) ---------------------


def test_known_bits_abstains_on_arithmetic_opaque_predicate() -> None:
    # (x * (x - 1)) & 1 == 0 is a TRUE opaque predicate (product of consecutive
    # integers is even), but KnownBits is non-relational: it loses the
    # x / (x-1) correlation, models MUL as TOP, and so cannot prove bit0=0.
    # It MUST abstain (UNKNOWN) -- this is precisely what the ranked-behind Z3
    # tautology oracle exists to decide.
    x = Var("x")
    product = BinExpr(BinaryOp.MUL, x, BinExpr(BinaryOp.SUB, x, Const(1)))
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(BinaryOp.AND, product, Const(1)),
        right=Const(0),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.UNKNOWN


def test_known_bits_abstains_on_self_xor() -> None:
    # x ^ x == 0 is true, but non-relational KnownBits sees two independent TOPs
    # -> TOP -> undecidable. Abstain (term-rewriting / Z3 handles this).
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(BinaryOp.XOR, Var("x"), Var("x")),
        right=Const(0),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.UNKNOWN


def test_known_bits_abstains_on_genuine_conditional() -> None:
    # y < 0xA is a REAL branch (depends on y). Must stay UNKNOWN so the consumer
    # keeps both arms -- folding it would destroy semantics.
    guard = BranchGuard(
        op=CompareOp.ULT, left=Var("y"), right=Const(0xA), width=32
    )
    assert _decide(guard) is PredicateVerdict.UNKNOWN


def test_not_is_modelled_bitwise() -> None:
    # (~x | x) low bit known? ~x and x are independent TOPs here, so this is an
    # abstain too -- documents that complement-cancellation needs a relational
    # oracle, not KnownBits.
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(BinaryOp.OR, UnExpr(UnaryOp.NOT, Var("x")), Var("x")),
        right=Const(0xFFFFFFFF),
        width=32,
    )
    assert _decide(guard) is PredicateVerdict.UNKNOWN


# --- the ranked seam -------------------------------------------------------


class _AlwaysAbstain:
    def decide(self, guard: BranchGuard) -> PredicateVerdict:
        return PredicateVerdict.UNKNOWN


class _AlwaysTrue:
    def decide(self, guard: BranchGuard) -> PredicateVerdict:
        return PredicateVerdict.ALWAYS_TRUE


def _trivial_guard() -> BranchGuard:
    return BranchGuard(CompareOp.EQ, Var("x"), Const(0), 32)


def test_ranked_oracle_skips_abstainers_to_first_decisive() -> None:
    ranked = RankedPredicateOracle((_AlwaysAbstain(), _AlwaysTrue()))
    assert ranked.decide(_trivial_guard()) is PredicateVerdict.ALWAYS_TRUE


def test_ranked_oracle_returns_unknown_when_all_abstain() -> None:
    ranked = RankedPredicateOracle((_AlwaysAbstain(), _AlwaysAbstain()))
    assert ranked.decide(_trivial_guard()) is PredicateVerdict.UNKNOWN


def test_ranked_oracle_first_rank_wins_over_later() -> None:
    # First decisive oracle short-circuits; a later contradictory oracle is
    # never consulted (verifies ordering, not just any-decisive).
    ranked = RankedPredicateOracle((_AlwaysTrue(), _AlwaysAbstain()))
    assert ranked.decide(_trivial_guard()) is PredicateVerdict.ALWAYS_TRUE


def test_default_oracle_is_known_bits_only_and_protocol_typed() -> None:
    oracle = default_predicate_oracle()
    assert isinstance(oracle, RankedPredicateOracle)
    assert len(oracle.oracles) == 1
    assert isinstance(oracle.oracles[0], PredicateOracle)
    # End-to-end through the default seam: the constant-forced tautology folds.
    guard = BranchGuard(
        op=CompareOp.EQ,
        left=BinExpr(
            BinaryOp.AND, BinExpr(BinaryOp.OR, Var("x"), Const(1)), Const(1)
        ),
        right=Const(1),
        width=32,
    )
    assert oracle.decide(guard) is PredicateVerdict.ALWAYS_TRUE
