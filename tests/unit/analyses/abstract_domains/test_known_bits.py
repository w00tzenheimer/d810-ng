"""Tests for the KnownBits (bitfield) abstract domain."""
from __future__ import annotations

from d810.analyses.abstract_domains import AbstractDomain, KnownBits


def test_satisfies_abstract_domain_protocol():
    assert isinstance(KnownBits.of(5, 8), AbstractDomain)


def test_top_bottom_const():
    assert KnownBits.top(8).is_top()
    assert KnownBits.bottom(8).is_bottom()
    assert KnownBits.of(0xA5, 8).to_const() == 0xA5
    assert KnownBits.top(8).to_const() is None


def test_join_keeps_only_agreeing_bits():
    # 0b1010 ⊔ 0b1000 -> bit0..: agree on 1,_,_,0? compare per bit
    a = KnownBits.of(0b1010, 4)
    b = KnownBits.of(0b1000, 4)
    j = a.join(b)
    assert j.to_const() is None            # they differ -> not fully known
    assert a.leq(j) and b.leq(j)           # join is an upper bound
    # bit1 differs (1 vs 0) -> unknown; bits 3,2,0 agree (1,0,0)
    assert j.one == 0b1000 and j.zero == 0b0101


def test_meet_clash_is_bottom():
    a = KnownBits.of(0b01, 2)
    b = KnownBits.of(0b10, 2)
    assert a.meet(b).is_bottom()           # bit0: 1 vs 0 -> infeasible


def test_meet_refines():
    # top ⊓ known = known
    assert KnownBits.top(8).meet(KnownBits.of(7, 8)).to_const() == 7


def test_leq_order():
    known = KnownBits.of(5, 8)
    top = KnownBits.top(8)
    assert known.leq(top) and not top.leq(known)
    assert KnownBits.bottom(8).leq(known)


def test_bitwise_and_or_xor_fold_constants():
    a, b = KnownBits.of(0xF0, 8), KnownBits.of(0x3C, 8)
    assert a.band(b).to_const() == (0xF0 & 0x3C)
    assert a.bor(b).to_const() == (0xF0 | 0x3C)
    assert a.bxor(b).to_const() == (0xF0 ^ 0x3C)
    assert a.bnot().to_const() == (~0xF0 & 0xFF)


def test_xor_self_is_known_zero_even_when_value_unknown():
    # MBA-relevant: x ^ x == 0 is provable bit-wise when both sides share bits.
    x = KnownBits.of(0x5A, 8)
    assert x.bxor(x).to_const() == 0


def test_and_with_known_zero_mask_resolves_bits():
    # unknown & 0x0F -> top nibble proven 0 even though low nibble unknown
    unknown = KnownBits.top(8)
    masked = unknown.band(KnownBits.of(0x0F, 8))
    assert masked.zero == 0xF0 and masked.one == 0  # high nibble known-0
