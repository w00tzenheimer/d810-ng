"""Contract tests for JumpFixer opaque-predicate fallback behavior."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.backends.ast.z3 import Z3MopProver
from d810.optimizers.microcode.flow.jumps import opaque


def _num(value: int, size: int = 4):
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        nnn=SimpleNamespace(value=value),
        size=size,
    )


def _reg(register: int, size: int = 4):
    return SimpleNamespace(t=ida_hexrays.mop_r, r=register, size=size)


def _blkref(serial: int):
    return SimpleNamespace(t=ida_hexrays.mop_b, b=serial)


def _insn(opcode: int, *, left=None, right=None, dest=None):
    return SimpleNamespace(opcode=opcode, l=left, r=right, d=dest, next=None)


class _FakeMba:
    def __init__(self):
        self._blocks = {}

    def add(self, block):
        self._blocks[int(block.serial)] = block
        block.mba = self
        return block

    def get_mblock(self, serial: int):
        return self._blocks.get(int(serial))


class _FakeBlock:
    def __init__(
        self,
        serial: int,
        *,
        head=None,
        preds=(),
        succs=(),
        next_serial: int | None = None,
    ):
        self.serial = int(serial)
        self.head = head
        self.tail = head
        self.preds = tuple(int(pred) for pred in preds)
        self.succs = tuple(int(succ) for succ in succs)
        self.nextb = (
            None
            if next_serial is None
            else SimpleNamespace(serial=int(next_serial))
        )
        self.mba = None

    def npred(self) -> int:
        return len(self.preds)

    def pred(self, idx: int) -> int:
        return self.preds[idx]

    def nsucc(self) -> int:
        return len(self.succs)

    def succ(self, idx: int) -> int:
        return self.succs[idx]


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

    monkeypatch.setattr(Z3MopProver, "are_equal", lambda _self, _l, _r: False)
    monkeypatch.setattr(Z3MopProver, "are_unequal", lambda _self, _l, _r: False)
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

    monkeypatch.setattr(Z3MopProver, "are_equal", lambda _self, _l, _r: False)
    monkeypatch.setattr(Z3MopProver, "are_unequal", lambda _self, _l, _r: False)
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

    monkeypatch.setattr(Z3MopProver, "are_equal", lambda _self, _l, _r: False)
    monkeypatch.setattr(Z3MopProver, "are_unequal", lambda _self, _l, _r: False)
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


def test_jmp_rule_reaching_const_folds_predecessor_mov_to_fallthrough(monkeypatch):
    rule = opaque.JmpRuleReachingConst()
    monkeypatch.setattr(rule, "_make_goto_ins", lambda _ins, target: ("goto", target))

    pred_mov = _insn(ida_hexrays.m_mov, left=_num(0xBAD3ACF7), dest=_reg(8))
    pred = _FakeBlock(19, head=pred_mov, succs=(20,))

    copy = _insn(ida_hexrays.m_mov, left=_reg(8), dest=_reg(2))
    tail = _insn(
        ida_hexrays.m_jz,
        left=_reg(2),
        right=_num(0xE739ACEB),
        dest=_blkref(20),
    )
    copy.next = tail
    blk = _FakeBlock(20, head=copy, preds=(19,), succs=(21, 20), next_serial=21)

    mba = _FakeMba()
    mba.add(pred)
    mba.add(blk)

    assert rule.check_pattern_and_replace(blk, tail, None, None) == ("goto", 21)


def test_jmp_rule_reaching_const_uses_signed_relation_for_jle(monkeypatch):
    rule = opaque.JmpRuleReachingConst()
    monkeypatch.setattr(rule, "_make_goto_ins", lambda _ins, target: ("goto", target))

    pred_mov = _insn(ida_hexrays.m_mov, left=_num(0xE9FD9EC4), dest=_reg(1))
    pred = _FakeBlock(19, head=pred_mov, succs=(20,))

    tail = _insn(
        ida_hexrays.m_jle,
        left=_reg(1),
        right=_num(0x0FCD789E),
        dest=_blkref(18),
    )
    blk = _FakeBlock(20, head=tail, preds=(19,), succs=(18, 21), next_serial=21)

    mba = _FakeMba()
    mba.add(pred)
    mba.add(blk)

    assert rule.check_pattern_and_replace(blk, tail, None, None) == ("goto", 18)


def test_jmp_rule_reaching_const_rejects_ambiguous_predecessors(monkeypatch):
    rule = opaque.JmpRuleReachingConst()
    monkeypatch.setattr(rule, "_make_goto_ins", lambda _ins, target: ("goto", target))

    pred_a = _FakeBlock(
        18,
        head=_insn(ida_hexrays.m_mov, left=_num(1), dest=_reg(1)),
        succs=(20,),
    )
    pred_b = _FakeBlock(
        19,
        head=_insn(ida_hexrays.m_mov, left=_num(2), dest=_reg(1)),
        succs=(20,),
    )
    tail = _insn(
        ida_hexrays.m_jz,
        left=_reg(1),
        right=_num(1),
        dest=_blkref(30),
    )
    blk = _FakeBlock(20, head=tail, preds=(18, 19), succs=(30, 21), next_serial=21)

    mba = _FakeMba()
    mba.add(pred_a)
    mba.add(pred_b)
    mba.add(blk)

    assert rule.check_pattern_and_replace(blk, tail, None, None) is None
