"""Unit tests for data-driven division MBA rules."""

from __future__ import annotations

from types import SimpleNamespace

from d810.mba.rules import VerifiableRule
from d810.mba.rules.division import UnsignedMagicModulo3Rule


class _Candidate(SimpleNamespace):
    def __init__(self, *, x_leaf, magic_leaf, **kwargs):
        super().__init__(**kwargs)
        self._leafs = {
            "x_0": x_leaf,
            "magic": magic_leaf,
        }

    def __getitem__(self, key):
        return self._leafs[key]


def _mop(size: int, value: int | None = None):
    if value is None:
        return SimpleNamespace(size=size)
    return SimpleNamespace(size=size, value=value)


def _leaf(size: int, value: int | None = None):
    return SimpleNamespace(size=size, mop=_mop(size, value), value=value)


def _node(size: int, *, left=None, right=None, dst_mop=None):
    return SimpleNamespace(size=size, dest_size=size, left=left, right=right, dst_mop=dst_mop)


def _candidate(*, dst_size=4, high_size=4, magic_size=8):
    x_leaf = _leaf(4)
    magic_leaf = _leaf(magic_size)
    zext = _node(8, left=x_leaf)
    product = _node(8, left=zext, right=magic_leaf)
    high = _node(high_size, left=product)
    shift = _node(4, left=high, right=_leaf(1, 1))
    divisor_mul = _node(4, left=_leaf(4, 3), right=shift)
    return _Candidate(
        x_leaf=x_leaf,
        magic_leaf=magic_leaf,
        left=x_leaf,
        right=divisor_mul,
        dst_mop=_mop(dst_size),
    )


def test_unsigned_magic_modulo3_rule_is_registered_without_modulo5():
    assert VerifiableRule.find("UnsignedMagicModulo3Rule") is UnsignedMagicModulo3Rule
    assert VerifiableRule.find("UnsignedMagicModulo5Rule") is None


def test_unsigned_magic_modulo3_runtime_proof_accepts_exact_widths():
    rule = UnsignedMagicModulo3Rule()
    rule._runtime_constant_evaluator = lambda _mop, *, bits: 0xAAAAAAAB

    assert rule.check_candidate(_candidate())


def test_unsigned_magic_modulo3_runtime_proof_rejects_wrong_widths():
    rule = UnsignedMagicModulo3Rule()
    rule._runtime_constant_evaluator = lambda _mop, *, bits: 0xAAAAAAAB

    assert not rule.check_candidate(_candidate(dst_size=8))
    assert not rule.check_candidate(_candidate(high_size=8))
    assert not rule.check_candidate(_candidate(magic_size=4))


def test_unsigned_magic_modulo3_runtime_proof_rejects_wrong_magic():
    rule = UnsignedMagicModulo3Rule()
    rule._runtime_constant_evaluator = lambda _mop, *, bits: 0xCCCCCCCD

    assert not rule.check_candidate(_candidate())
