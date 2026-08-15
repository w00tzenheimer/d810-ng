"""Regression tests for the cheap affine opaque-jump recognizer."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.jumps import opaque


def _const(value: int, size: int = 8):
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=size,
        nnn=SimpleNamespace(value=value),
        d=None,
        dstr=lambda: f"#{value:#x}",
    )


def _var(name: str, size: int = 8):
    return SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        d=None,
        dstr=lambda: name,
    )


def _expr(opcode: int, left, right=None, size: int = 8):
    return SimpleNamespace(
        t=ida_hexrays.mop_d,
        size=size,
        d=SimpleNamespace(opcode=opcode, l=left, r=right),
        dstr=lambda: f"<{opcode}>",
    )


def _mul(left, right):
    return _expr(ida_hexrays.m_mul, left, right)


def _add(left, right):
    return _expr(ida_hexrays.m_add, left, right)


def _sub(left, right):
    return _expr(ida_hexrays.m_sub, left, right)


def _bnot(value):
    return _expr(ida_hexrays.m_bnot, value)


def test_affine_extract_normalizes_constant_multiply_and_two_complement_not():
    mask = (1 << 64) - 1
    expression = _mul(_const(524), _bnot(_var("x")))

    assert opaque._affine_extract(expression, size=8) == (
        {"x": (-524) & mask},
        (-524) & mask,
    )


def test_affine_equality_decides_different_constants_without_z3():
    lhs = _mul(_const(604), _var("x"))
    rhs = _sub(_mul(_const(604), _var("x")), _const(768))

    assert opaque._affine_decide_equality(ida_hexrays.m_jz, lhs, rhs) is False
    assert opaque._affine_decide_equality(ida_hexrays.m_jnz, lhs, rhs) is True


def test_affine_equality_normalizes_ssa_tags_before_comparing_terms():
    tagged_x = _var("x19.8{4003}")
    plain_x = _var("x19.8")
    lhs = _add(_mul(_const(630), tagged_x), _const(630))
    rhs = _sub(_mul(_const(630), plain_x), _const(218))

    assert opaque._affine_decide_equality(ida_hexrays.m_jz, lhs, rhs) is False


def test_affine_equality_abstains_when_the_opaque_terms_differ():
    assert (
        opaque._affine_decide_equality(
            ida_hexrays.m_jz,
            _mul(_const(604), _var("x")),
            _mul(_const(604), _var("y")),
        )
        is None
    )


def test_affine_rule_selects_fallthrough_for_an_always_false_jz():
    rule = opaque.JmpRuleAffineEq()
    rule.jump_original_block_serial = 100
    rule.direct_block_serial = 200
    left = SimpleNamespace(mop=_mul(_const(604), _var("x")))
    right = SimpleNamespace(mop=_sub(_mul(_const(604), _var("x")), _const(768)))

    assert rule.check_candidate(ida_hexrays.m_jz, left, right) is True
    assert rule.jump_replacement_block_serial == 200
