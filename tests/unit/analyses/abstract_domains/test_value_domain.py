"""Tests for the ValueDomain semantic layer (eval / satisfies / assume)."""

from __future__ import annotations

from d810.analyses.abstract_domains import KnownBits, WrappedInterval, Satisfiability
from d810.analyses.abstract_domains.operations import (
    BinaryOp,
    CompareOp,
    eval_const_binary,
)
from d810.analyses.abstract_domains.value_domain import (
    KnownBitsValueDomain,
    WrappedIntervalValueDomain,
    ValueDomain,
)

W = 32
MASK = (1 << W) - 1


def test_protocol_conformance():
    assert isinstance(KnownBitsValueDomain(), ValueDomain)
    assert isinstance(WrappedIntervalValueDomain(), ValueDomain)


def test_known_bits_folds_real_sub7ffd_mba_next_state():
    # The actual flattened next-state: var_64 = (var_770 ^ var_778) - var_780
    a, b, c = 0x77535232, 0x71D1654B, 0xDC240D83
    d = KnownBitsValueDomain()
    xor = d.eval_binary(BinaryOp.XOR, d.const(a, W), d.const(b, W), W)
    res = d.eval_binary(BinaryOp.SUB, xor, d.const(c, W), W)
    assert res.to_const() == (((a ^ b) - c) & MASK)  # exact modular fold


def test_known_bits_fold_matches_python_for_all_ops():
    d = KnownBitsValueDomain()
    a, b = 0xDEADBEEF, 0x0F0F1234
    import operator

    for op, ref in [
        (BinaryOp.ADD, lambda x, y: (x + y) & MASK),
        (BinaryOp.SUB, lambda x, y: (x - y) & MASK),
        (BinaryOp.MUL, lambda x, y: (x * y) & MASK),
        (BinaryOp.AND, operator.and_),
        (BinaryOp.OR, operator.or_),
        (BinaryOp.XOR, operator.xor),
    ]:
        got = d.eval_binary(op, d.const(a, W), d.const(b, W), W).to_const()
        assert got == ref(a, b), op


def test_known_bits_bitwise_on_unknowns_stays_precise():
    d = KnownBitsValueDomain()
    # unknown & 0x0F: high bits proven 0 even though value unknown
    masked = d.eval_binary(BinaryOp.AND, d.top(W), d.const(0x0F, W), W)
    assert masked.to_const() is None
    assert masked.zero == (MASK & ~0x0F)  # all but low nibble known-0


def test_known_bits_arithmetic_on_unknowns_is_top():
    d = KnownBitsValueDomain()
    res = d.eval_binary(BinaryOp.ADD, d.top(W), d.const(1, W), W)
    assert res.is_top()  # sound: add of unknown -> ⊤


def test_known_bits_shift_by_constant_is_precise():
    d = KnownBitsValueDomain()
    shl = d.eval_binary(BinaryOp.SHL, d.const(1, W), d.const(4, W), W)
    assert shl.to_const() == (1 << 4)


def test_concrete_rotates_are_width_aware_without_symbolic_solving():
    assert eval_const_binary(BinaryOp.ROL, 0x81, 1, 8) == 0x03
    assert eval_const_binary(BinaryOp.ROR, 0x81, 1, 8) == 0xC0
    assert eval_const_binary(BinaryOp.ROL, 0x12345678, 8, 32) == 0x34567812
    assert (
        eval_const_binary(BinaryOp.ROR, 0x0123456789ABCDEF, 8, 64) == 0xEF0123456789ABCD
    )


def test_concrete_rotates_reduce_counts_modulo_result_width():
    value = 0x0123456789ABCDEF
    assert eval_const_binary(BinaryOp.ROL, value, 0, 64) == value
    assert eval_const_binary(BinaryOp.ROL, value, 64, 64) == value
    assert eval_const_binary(BinaryOp.ROL, value, 65, 64) == 0x02468ACF13579BDE
    assert eval_const_binary(BinaryOp.ROR, value, 63, 64) == 0x02468ACF13579BDE


def test_satisfies_constant_compare():
    d = KnownBitsValueDomain()
    assert (
        d.satisfies(CompareOp.EQ, d.const(5, W), d.const(5, W), W)
        is Satisfiability.SATISFIED
    )
    assert (
        d.satisfies(CompareOp.EQ, d.const(5, W), d.const(6, W), W)
        is Satisfiability.NOT_SATISFIED
    )
    assert (
        d.satisfies(CompareOp.ULT, d.const(3, W), d.const(9, W), W)
        is Satisfiability.SATISFIED
    )


def test_satisfies_bitwise_refutation_on_unknowns():
    d = KnownBitsValueDomain()
    # low bit proven 1 vs proven 0 -> can never be equal, even though rest unknown
    one_lsb = KnownBits(W, zero=0, one=1)  # ...???1
    zero_lsb = KnownBits(W, zero=1, one=0)  # ...???0
    assert (
        d.satisfies(CompareOp.EQ, one_lsb, zero_lsb, W) is Satisfiability.NOT_SATISFIED
    )
    assert d.satisfies(CompareOp.NE, one_lsb, zero_lsb, W) is Satisfiability.SATISFIED


def test_assume_eq_refines_via_meet():
    d = KnownBitsValueDomain()
    lo, hi = d.const(0x12, W), d.top(W)
    l2, r2 = d.assume_compare(CompareOp.EQ, lo, hi, W, taken=True)
    assert l2.to_const() == 0x12 and r2.to_const() == 0x12


def test_wrapped_interval_value_domain_folds_and_ranges():
    d = WrappedIntervalValueDomain()
    a, b = 0xFFFFFFF0, 0x20
    assert d.eval_binary(BinaryOp.ADD, d.const(a, W), d.const(b, W), W).to_const() == (
        (a + b) & MASK
    )
    # range + const stays a range (word-correct)
    r = d.eval_binary(BinaryOp.ADD, WrappedInterval(W, 0, 10), d.const(5, W), W)
    assert r.contains(5) and r.contains(15)
