"""Contract tests for JumpFixer opaque-predicate fallback behavior."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.jumps import opaque


class _ConstAst:
    def __init__(self, value: int):
        self._value = value

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return True

    def evaluate(self, _env: dict) -> int:
        return self._value


class _VarAst:
    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return False

    def evaluate(self, _env: dict) -> int:
        return 0


def test_constant_relation_true_when_both_constant(monkeypatch):
    monkeypatch.setattr(
        opaque, "mop_to_ast", lambda mop: _ConstAst(0x1234 if mop == "L" else 0x1234)
    )
    assert opaque._constant_relation("L", "R") is True


def test_constant_relation_none_when_not_constant(monkeypatch):
    monkeypatch.setattr(
        opaque, "mop_to_ast", lambda mop: _VarAst() if mop == "L" else _ConstAst(1)
    )
    assert opaque._constant_relation("L", "R") is None


def test_jmp_rule_z3_const_uses_constant_fallback_for_jnz(monkeypatch):
    rule = opaque.JmpRuleZ3Const()
    rule.jump_original_block_serial = 17
    rule.direct_block_serial = 19

    monkeypatch.setattr(opaque, "z3_check_mop_equality", lambda _l, _r: False)
    monkeypatch.setattr(opaque, "z3_check_mop_inequality", lambda _l, _r: False)
    monkeypatch.setattr(opaque, "_constant_jump_taken", lambda _op, _l, _r: False)

    left = SimpleNamespace(mop=object())
    right = SimpleNamespace(mop=object())
    assert rule.check_candidate(ida_hexrays.m_jnz, left, right) is True
    # jump not taken => fall-through block.
    assert rule.jump_replacement_block_serial == 19


def test_jmp_rule_z3_const_uses_constant_fallback_for_jz(monkeypatch):
    rule = opaque.JmpRuleZ3Const()
    rule.jump_original_block_serial = 17
    rule.direct_block_serial = 19

    monkeypatch.setattr(opaque, "z3_check_mop_equality", lambda _l, _r: False)
    monkeypatch.setattr(opaque, "z3_check_mop_inequality", lambda _l, _r: False)
    monkeypatch.setattr(opaque, "_constant_jump_taken", lambda _op, _l, _r: True)

    left = SimpleNamespace(mop=object())
    right = SimpleNamespace(mop=object())
    assert rule.check_candidate(ida_hexrays.m_jz, left, right) is True
    # jump taken => jump target block.
    assert rule.jump_replacement_block_serial == 17


def test_jmp_rule_z3_const_returns_false_when_no_solver_or_constant_result(monkeypatch):
    rule = opaque.JmpRuleZ3Const()
    rule.jump_original_block_serial = 17
    rule.direct_block_serial = 19

    monkeypatch.setattr(opaque, "z3_check_mop_equality", lambda _l, _r: False)
    monkeypatch.setattr(opaque, "z3_check_mop_inequality", lambda _l, _r: False)
    monkeypatch.setattr(opaque, "_constant_jump_taken", lambda _op, _l, _r: None)

    left = SimpleNamespace(mop=object())
    right = SimpleNamespace(mop=object())
    assert rule.check_candidate(ida_hexrays.m_jnz, left, right) is False


def test_cond_jump_pair_enum_contains_both_directions():
    expected = {
        (ida_hexrays.m_jnz, ida_hexrays.m_jz),
        (ida_hexrays.m_jz, ida_hexrays.m_jnz),
        (ida_hexrays.m_jb, ida_hexrays.m_jae),
        (ida_hexrays.m_jae, ida_hexrays.m_jb),
        (ida_hexrays.m_ja, ida_hexrays.m_jbe),
        (ida_hexrays.m_jbe, ida_hexrays.m_ja),
        (ida_hexrays.m_jl, ida_hexrays.m_jge),
        (ida_hexrays.m_jge, ida_hexrays.m_jl),
        (ida_hexrays.m_jg, ida_hexrays.m_jle),
        (ida_hexrays.m_jle, ida_hexrays.m_jg),
    }
    assert set(opaque.COND_JUMP_PAIR_ENUM) == expected


def test_jmp_rule_z3_const_folds_jcnd_true(monkeypatch):
    rule = opaque.JmpRuleZ3Const()
    monkeypatch.setattr(rule, "_make_goto_ins", lambda _ins, target: ("goto", target))
    monkeypatch.setattr(opaque, "_eval_constant_mop", lambda _mop: 1)

    blk = SimpleNamespace(nextb=SimpleNamespace(serial=41))
    ins = SimpleNamespace(
        opcode=ida_hexrays.m_jcnd,
        l=object(),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=17),
    )
    assert rule.check_pattern_and_replace(blk, ins, None, None) == ("goto", 17)


def test_jmp_rule_z3_const_folds_jcnd_false(monkeypatch):
    rule = opaque.JmpRuleZ3Const()
    monkeypatch.setattr(rule, "_make_goto_ins", lambda _ins, target: ("goto", target))
    monkeypatch.setattr(opaque, "_eval_constant_mop", lambda _mop: 0)

    blk = SimpleNamespace(nextb=SimpleNamespace(serial=41))
    ins = SimpleNamespace(
        opcode=ida_hexrays.m_jcnd,
        l=object(),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=17),
    )
    assert rule.check_pattern_and_replace(blk, ins, None, None) == ("goto", 41)


def test_jmp_rule_z3_const_skips_jcnd_when_not_constant(monkeypatch):
    rule = opaque.JmpRuleZ3Const()
    monkeypatch.setattr(opaque, "_eval_constant_mop", lambda _mop: None)

    blk = SimpleNamespace(nextb=SimpleNamespace(serial=41))
    ins = SimpleNamespace(
        opcode=ida_hexrays.m_jcnd,
        l=object(),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=17),
    )
    assert rule.check_pattern_and_replace(blk, ins, None, None) is None
