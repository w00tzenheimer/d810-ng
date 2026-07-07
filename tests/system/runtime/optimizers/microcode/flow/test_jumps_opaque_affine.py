"""Unit tests for JmpRuleAffineEq / _affine_extract.

Tests are unittest.TestCase based so they show up in the d810 in-IDA testbed
UI (which uses ``unittest.defaultTestLoader.discover`` and ignores pytest-style
module-level functions).
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.jumps import opaque


def _const(value: int, size: int = 8):
    """Build a fake mop_n carrying ``value``."""
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=size,
        nnn=SimpleNamespace(value=value),
        d=None,
        dstr=lambda: f"#{value:#x}",
    )


def _var(name: str, size: int = 8):
    """Build a fake mop_r (or any non-mop_n / non-mop_d leaf)."""
    return SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        d=None,
        dstr=lambda n=name: n,
    )


def _ins(op: int, l=None, r=None, size: int = 8):
    """Build a fake mop_d wrapping a sub-instruction with opcode ``op``."""
    sub = SimpleNamespace(opcode=op, l=l, r=r)
    return SimpleNamespace(
        t=ida_hexrays.mop_d,
        size=size,
        d=sub,
        dstr=lambda: f"<{op}>",
    )


def _mul(l, r):
    return _ins(ida_hexrays.m_mul, l, r)


def _add(l, r):
    return _ins(ida_hexrays.m_add, l, r)


def _sub(l, r):
    return _ins(ida_hexrays.m_sub, l, r)


def _neg(x):
    return _ins(ida_hexrays.m_neg, x, None)


def _bnot(x):
    return _ins(ida_hexrays.m_bnot, x, None)


class TestAffineExtract(unittest.TestCase):
    """Direct tests of the affine-form extractor."""

    def test_pure_constant(self):
        result = opaque._affine_extract(_const(42), size=8)
        self.assertEqual(result, ({}, 42))

    def test_pure_variable(self):
        term_map, const = opaque._affine_extract(_var("x"), size=8)
        self.assertEqual(const, 0)
        self.assertEqual(term_map, {"x": 1})

    def test_const_times_var(self):
        # 604 * x
        m = _mul(_const(604), _var("x"))
        term_map, const = opaque._affine_extract(m, size=8)
        self.assertEqual(const, 0)
        self.assertEqual(term_map, {"x": 604})

    def test_var_times_const_commuted(self):
        # x * 604 must give same result as 604 * x
        m = _mul(_var("x"), _const(604))
        term_map, const = opaque._affine_extract(m, size=8)
        self.assertEqual(term_map, {"x": 604})

    def test_bnot_two_complement(self):
        # ~x = -x - 1
        m = _bnot(_var("x"))
        mask = (1 << 64) - 1
        term_map, const = opaque._affine_extract(m, size=8)
        self.assertEqual(term_map, {"x": (-1) & mask})
        self.assertEqual(const, (-1) & mask)

    def test_c_times_bnot_distributes(self):
        # 524 * ~x = -524 * x - 524
        m = _mul(_const(524), _bnot(_var("x")))
        mask = (1 << 64) - 1
        term_map, const = opaque._affine_extract(m, size=8)
        self.assertEqual(term_map, {"x": (-524) & mask})
        self.assertEqual(const, (-524) & mask)

    def test_sub_with_shared_term_cancels(self):
        # (604 * x) - (604 * x) = 0
        lhs = _mul(_const(604), _var("x"))
        rhs = _mul(_const(604), _var("x"))
        diff = _sub(lhs, rhs)
        term_map, const = opaque._affine_extract(diff, size=8)
        self.assertEqual(term_map, {})
        self.assertEqual(const, 0)

    def test_modular_wraparound(self):
        # (1 << 64) + 5  collapses to 5 in 8-byte arithmetic.
        m = _add(_const(1 << 64), _const(5))
        _, const = opaque._affine_extract(m, size=8)
        self.assertEqual(const, 5)

    def test_ssa_tag_stripped_from_key(self):
        # In real microcode, the SAME semantic operand can carry different
        # SSA version tags on each side of a comparison
        # (e.g. `c*x22.8{3992}` vs `c*x22.8`).
        # _serialize_mop_key must normalise to the same key so the term-map
        # entries collapse.
        mop_with = SimpleNamespace(
            t=ida_hexrays.mop_r, size=8, d=None,
            dstr=lambda: "x22.8{3992}",
        )
        mop_without = SimpleNamespace(
            t=ida_hexrays.mop_r, size=8, d=None,
            dstr=lambda: "x22.8",
        )
        self.assertEqual(
            opaque._serialize_mop_key(mop_with),
            opaque._serialize_mop_key(mop_without),
        )

    def test_affine_decide_with_ssa_tagged_operands(self):
        # 630*x_tagged + 630  ==  630*x_plain - 218
        # where the two `x` operands carry different SSA tags. Should still
        # cancel and report not-equal.
        x_tagged = SimpleNamespace(
            t=ida_hexrays.mop_r, size=8, d=None,
            dstr=lambda: "x19.8{4003}",
        )
        x_plain = SimpleNamespace(
            t=ida_hexrays.mop_r, size=8, d=None,
            dstr=lambda: "x19.8",
        )
        lhs = _add(_mul(_const(630), x_tagged), _const(630))
        rhs = _sub(_mul(_const(630), x_plain), _const(218))
        self.assertFalse(
            opaque._affine_decide_equality(ida_hexrays.m_jz, lhs, rhs),
            "constants differ (630 vs -218) so sides are not equal",
        )


class TestAffineDecideEquality(unittest.TestCase):
    """Tests of the jump-taken decision over extracted affine forms."""

    def test_constants_differ_means_not_equal(self):
        # 604*x == 604*x - 768   -> NOT equal
        lhs = _mul(_const(604), _var("x"))
        rhs = _sub(_mul(_const(604), _var("x")), _const(768))
        taken_jz = opaque._affine_decide_equality(ida_hexrays.m_jz, lhs, rhs)
        taken_jnz = opaque._affine_decide_equality(ida_hexrays.m_jnz, lhs, rhs)
        self.assertFalse(taken_jz, "m_jz should NOT take the jump (sides not equal)")
        self.assertTrue(taken_jnz, "m_jnz SHOULD take the jump (sides not equal)")

    def test_constants_match_means_equal(self):
        # 524*~x  vs  -524*x - 524     -> ALWAYS equal
        lhs = _mul(_const(524), _bnot(_var("x")))
        rhs = _sub(_mul(_const((-524) & ((1 << 64) - 1)), _var("x")), _const(524))
        taken_jz = opaque._affine_decide_equality(ida_hexrays.m_jz, lhs, rhs)
        taken_jnz = opaque._affine_decide_equality(ida_hexrays.m_jnz, lhs, rhs)
        self.assertTrue(taken_jz, "m_jz SHOULD take the jump (sides equal)")
        self.assertFalse(taken_jnz, "m_jnz should NOT take (sides equal)")

    def test_two_sided_constants_with_shared_term(self):
        # 630*x + 630  ==  630*x - 218   -> NOT equal
        lhs = _add(_mul(_const(630), _var("x")), _const(630))
        rhs = _sub(_mul(_const(630), _var("x")), _const(218))
        self.assertFalse(opaque._affine_decide_equality(ida_hexrays.m_jz, lhs, rhs))

    def test_different_terms_returns_none(self):
        # x  vs  y         -> different opaque terms, rule does not apply
        self.assertIsNone(
            opaque._affine_decide_equality(ida_hexrays.m_jz, _var("x"), _var("y"))
        )

    def test_non_equality_opcode_returns_none(self):
        # m_jb is unsigned-less-than, not equality — affine rule must abstain.
        lhs = _var("x")
        rhs = _var("x")
        self.assertIsNone(
            opaque._affine_decide_equality(ida_hexrays.m_jb, lhs, rhs)
        )


class TestJmpRuleAffineEqCandidate(unittest.TestCase):
    """End-to-end test of the rule's check_candidate via Candidate mocks."""

    def _make_rule(self):
        rule = opaque.JmpRuleAffineEq()
        rule.jump_original_block_serial = 100
        rule.direct_block_serial = 200
        return rule

    def test_jz_opaque_false_picks_fallthrough(self):
        # 604*x == 604*x - 768 is FALSE, so m_jz does NOT jump.
        # Replacement target must be the fallthrough block (direct_block_serial).
        rule = self._make_rule()
        lhs_mop = _mul(_const(604), _var("x"))
        rhs_mop = _sub(_mul(_const(604), _var("x")), _const(768))
        left = SimpleNamespace(mop=lhs_mop)
        right = SimpleNamespace(mop=rhs_mop)
        self.assertTrue(rule.check_candidate(ida_hexrays.m_jz, left, right))
        self.assertEqual(rule.jump_replacement_block_serial, 200)

    def test_jnz_opaque_true_picks_fallthrough(self):
        # 524*~x == -524*x - 524 is TRUE, so m_jnz does NOT jump.
        rule = self._make_rule()
        lhs_mop = _mul(_const(524), _bnot(_var("x")))
        rhs_mop = _sub(
            _mul(_const((-524) & ((1 << 64) - 1)), _var("x")),
            _const(524),
        )
        left = SimpleNamespace(mop=lhs_mop)
        right = SimpleNamespace(mop=rhs_mop)
        self.assertTrue(rule.check_candidate(ida_hexrays.m_jnz, left, right))
        self.assertEqual(rule.jump_replacement_block_serial, 200)

    def test_rule_abstains_on_different_terms(self):
        rule = self._make_rule()
        left = SimpleNamespace(mop=_var("x"))
        right = SimpleNamespace(mop=_var("y"))
        self.assertFalse(rule.check_candidate(ida_hexrays.m_jz, left, right))


if __name__ == "__main__":
    unittest.main()
