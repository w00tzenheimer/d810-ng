"""Contract tests for JumpFixer opaque-predicate fallback behavior."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.backends.ast.z3 import Z3MopProver
from d810.hexrays.mutation.cfg_verify import (
    clear_resolver_proven_live_predicates,
    register_resolver_proven_live_predicate,
)
from d810.optimizers.microcode.flow.jumps import handler
from d810.optimizers.microcode.flow.jumps import opaque
from d810.transforms.graph_modification import ConvertToGoto


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
            None if next_serial is None else SimpleNamespace(serial=int(next_serial))
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


def test_jump_fixer_preserves_resolver_proven_live_predicate(monkeypatch):
    predicate_ea = 0x40D987
    mba = SimpleNamespace()
    branch = _insn(
        ida_hexrays.m_jz,
        left=_reg(20),
        right=_num(0),
        dest=_blkref(11),
    )
    branch.ea = predicate_ea
    block = SimpleNamespace(
        mba=mba,
        serial=7,
        start=0x40D8FF,
        tail=branch,
        nextb=SimpleNamespace(serial=8),
    )
    folded = _insn(ida_hexrays.m_goto, dest=_blkref(11))
    folding_rule = SimpleNamespace(
        name="JmpRuleReachingConst",
        check_pattern_and_replace=lambda *_args: folded,
    )
    fixer = handler.JumpFixer()
    fixer.rules = [folding_rule]

    monkeypatch.setattr(handler, "is_conditional_jump", lambda _block: True)
    monkeypatch.setattr(handler, "mop_to_ast", lambda _mop: object())

    def unexpected_transaction(_mba, _modifications):
        raise AssertionError("resolver-proven predicate must not be folded")

    monkeypatch.setattr(fixer, "execute_graph_modifications", unexpected_transaction)
    clear_resolver_proven_live_predicates()
    register_resolver_proven_live_predicate(mba, predicate_ea)
    try:
        assert fixer.optimize(block) is False
    finally:
        clear_resolver_proven_live_predicates()


def test_jump_fixer_executes_goto_fold_through_typed_transaction(monkeypatch):
    mba = SimpleNamespace()
    branch = _insn(
        ida_hexrays.m_jz,
        left=_reg(20),
        right=_num(0),
        dest=_blkref(11),
    )
    branch.ea = 0x40C115
    block = SimpleNamespace(
        mba=mba,
        serial=247,
        start=0x40C115,
        tail=branch,
        nextb=SimpleNamespace(serial=248),
    )
    folded = _insn(ida_hexrays.m_goto, dest=_blkref(299))
    folding_rule = SimpleNamespace(
        name="JmpRuleZ3Const",
        check_pattern_and_replace=lambda *_args: folded,
    )
    fixer = handler.JumpFixer()
    fixer.rules = [folding_rule]
    observed: list[tuple[object, tuple[ConvertToGoto, ...]]] = []

    monkeypatch.setattr(handler, "is_conditional_jump", lambda _block: True)
    monkeypatch.setattr(handler, "mop_to_ast", lambda _mop: object())
    monkeypatch.setattr(handler, "format_minsn_t", lambda _insn: "insn")
    monkeypatch.setattr(
        fixer,
        "execute_graph_modifications",
        lambda live_mba, modifications: (
            observed.append((live_mba, tuple(modifications))) or 1
        ),
    )

    assert fixer.optimize(block) is True
    assert observed == [
        (
            mba,
            (ConvertToGoto(block_serial=247, goto_target=299),),
        )
    ]


def test_jump_fixer_does_not_claim_rejected_typed_transaction(monkeypatch):
    mba = SimpleNamespace()
    branch = _insn(
        ida_hexrays.m_jz,
        left=_reg(20),
        right=_num(0),
        dest=_blkref(11),
    )
    branch.ea = 0x40C217
    block = SimpleNamespace(
        mba=mba,
        serial=254,
        start=0x40C217,
        tail=branch,
        nextb=SimpleNamespace(serial=255),
    )
    folded = _insn(ida_hexrays.m_goto, dest=_blkref(300))
    fixer = handler.JumpFixer()
    fixer.rules = [
        SimpleNamespace(
            name="JmpRuleZ3Const",
            check_pattern_and_replace=lambda *_args: folded,
        )
    ]

    monkeypatch.setattr(handler, "is_conditional_jump", lambda _block: True)
    monkeypatch.setattr(handler, "mop_to_ast", lambda _mop: object())
    monkeypatch.setattr(handler, "format_minsn_t", lambda _insn: "insn")
    monkeypatch.setattr(
        fixer,
        "execute_graph_modifications",
        lambda _live_mba, _modifications: 0,
    )

    assert fixer.optimize(block) is False


def test_flow_rule_transaction_port_preserves_immutable_authority(monkeypatch):
    from d810.backends.hexrays.mutation import backend as backend_module
    from d810.ir.maturity import MaturityEnvelope
    from d810.transforms import plan as plan_module

    source_refs = {7: object(), 11: object()}
    identity_index = SimpleNamespace(
        snapshot_id="snapshot-7",
        generation=3,
        maturity=ida_hexrays.MMAT_LOCOPT,
        plan_refs_by_serial=lambda: source_refs,
    )
    gateway = SimpleNamespace(identity_index=identity_index)
    flow_context = SimpleNamespace(new_mba_mutation_gateway=lambda: gateway)
    live_mba = object()
    pre_cfg = object()
    patch_plan = object()
    calls: list[tuple] = []

    class _Runtime:
        def lift(self, state):
            calls.append(("lift", state))
            return pre_cfg

        def execute_patch_plan(
            self,
            plan,
            state,
            *,
            mutation_gateway,
            pre_cfg: object,
        ):
            calls.append(
                (
                    "execute",
                    plan,
                    state,
                    mutation_gateway,
                    pre_cfg,
                )
            )
            return SimpleNamespace(applied_count=1)

    def _compile(
        modifications,
        cfg,
        *,
        snapshot_id,
        source_maturity,
        source_generation,
        block_refs_by_serial,
    ):
        calls.append(
            (
                "compile",
                tuple(modifications),
                cfg,
                snapshot_id,
                source_maturity,
                source_generation,
                block_refs_by_serial,
            )
        )
        return patch_plan

    monkeypatch.setattr(backend_module, "HexRaysPatchPlanRuntime", _Runtime)
    monkeypatch.setattr(plan_module, "compile_patch_plan", _compile)

    fixer = handler.JumpFixer()
    fixer.set_flow_context(flow_context)
    modification = ConvertToGoto(block_serial=7, goto_target=11)

    assert fixer.execute_graph_modifications(live_mba, (modification,)) == 1
    assert calls == [
        ("lift", live_mba),
        (
            "compile",
            (modification,),
            pre_cfg,
            "snapshot-7",
            MaturityEnvelope(
                ir=None,
                provider="hexrays",
                provider_id=ida_hexrays.MMAT_LOCOPT,
            ),
            3,
            source_refs,
        ),
        ("execute", patch_plan, live_mba, gateway, pre_cfg),
    ]


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
