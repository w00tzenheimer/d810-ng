"""llr-2biq: _InductionInsn.src_l_expr / src_r_expr populated from Instruction.input_exprs.

Covers:
- Production (projection) branch: _induction_insn_from_canonical sets src_l_expr/src_r_expr
  from the canonical Instruction.input_exprs tuple.
- Diag (legacy) branch: _iter_induction_carrier_insns with a plain diag-style object yields
  src_l_expr=None / src_r_expr=None (no canonical Instruction / input_exprs).
"""

from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.value_flow.induction_carrier import (
    _induction_insn_from_canonical,
    _iter_induction_carrier_insns,
)
from d810.ir.expressions import Add, Const, Move, Mul
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.insn_projection import project_instruction
from d810.ir.locations import StackSlot
from d810.ir.value_refs import DefinitionRef

M_ADD = 0x12
M_MOV = 0x04


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _subinsn_mul(l: MopSnapshot, r: MopSnapshot, size: int = 4) -> MopSnapshot:
    """A SUBINSN operand representing ``l * r``."""
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.MUL,
        sub_l=l,
        sub_r=r,
        size=size,
    )


def _add_insn(l: MopSnapshot, r: MopSnapshot, d: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_ADD,
        ea=0x1000,
        operands=(),
        kind=InsnKind.ADD,
        l=l,
        r=r,
        d=d,
    )


# ---------------------------------------------------------------------------
# Production (projection) branch
# ---------------------------------------------------------------------------


def test_src_l_expr_populated_from_input_exprs_slot0() -> None:
    """src_l_expr equals input_exprs[0] from the projected Instruction."""
    # ADD  (var_20 * 4), #8  -> var_30
    mul_op = _subinsn_mul(_stk(0x20), _num(4))
    insn_snap = _add_insn(l=mul_op, r=_num(8), d=_stk(0x30))
    instruction = project_instruction(insn_snap)

    # Verify the projection itself has a non-trivial input_exprs[0]
    assert len(instruction.input_exprs) >= 1
    assert isinstance(instruction.input_exprs[0], Mul)

    view = _induction_insn_from_canonical(
        block_serial=1, index=0, instruction=instruction
    )

    # src_l_expr must equal input_exprs[0]
    assert view.src_l_expr == instruction.input_exprs[0]
    expected = Mul(
        left=Move(source=DefinitionRef(location=StackSlot(offset=0x20, size=4))),
        right=Const(value=4),
    )
    assert view.src_l_expr == expected


def test_src_r_expr_populated_from_input_exprs_slot1() -> None:
    """src_r_expr equals input_exprs[1] from the projected Instruction."""
    mul_op = _subinsn_mul(_stk(0x20), _num(4))
    insn_snap = _add_insn(l=mul_op, r=_num(8), d=_stk(0x30))
    instruction = project_instruction(insn_snap)

    view = _induction_insn_from_canonical(
        block_serial=1, index=0, instruction=instruction
    )

    assert view.src_r_expr == instruction.input_exprs[1]
    assert view.src_r_expr == Const(value=8)


def test_src_l_expr_is_add_node_when_left_operand_is_add_subinsn() -> None:
    """An Add sub-expression on the left operand is exposed in src_l_expr."""
    add_sub = MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.ADD,
        sub_l=_stk(0x10),
        sub_r=_num(1),
        size=4,
    )
    insn_snap = InsnSnapshot(
        opcode=M_MOV,
        ea=0x2000,
        operands=(),
        kind=InsnKind.MOV,
        l=add_sub,
        d=_stk(0x40),
    )
    instruction = project_instruction(insn_snap)
    view = _induction_insn_from_canonical(
        block_serial=2, index=0, instruction=instruction
    )

    assert isinstance(view.src_l_expr, Add)
    assert view.src_l_expr == Add(
        left=Move(source=DefinitionRef(location=StackSlot(offset=0x10, size=4))),
        right=Const(value=1),
    )


def test_flat_operands_produce_const_expr_not_none() -> None:
    """A plain NUMBER operand yields a Const ExprRef (not None) in src_l_expr."""
    insn_snap = InsnSnapshot(
        opcode=M_MOV,
        ea=0x3000,
        operands=(),
        kind=InsnKind.MOV,
        l=_num(0x41),
        d=_stk(0x50),
    )
    instruction = project_instruction(insn_snap)
    view = _induction_insn_from_canonical(
        block_serial=3, index=0, instruction=instruction
    )

    assert view.src_l_expr == Const(value=0x41)
    # No right operand for a MOV
    assert view.src_r_expr is None


# ---------------------------------------------------------------------------
# Diag (legacy) branch — src_l_expr / src_r_expr must default to None
# ---------------------------------------------------------------------------


def test_diag_path_leaves_src_l_expr_none() -> None:
    """The diag/legacy branch yields _InductionInsn with src_l_expr=None."""
    insn = SimpleNamespace(
        opcode_name="add",
        dest_stkoff=0x20,
        src_l_stkoff=0x20,
        src_r_value=1,
        ea=0x180010000,
        index=0,
        dstr="add %var_20, 1",
    )
    block = SimpleNamespace(serial=1, instructions=[insn])
    target = SimpleNamespace(blocks=[block])

    views = list(_iter_induction_carrier_insns(target))
    assert views, "expected at least one view from the diag path"
    view = views[0]

    assert view.src_l_expr is None
    assert view.src_r_expr is None
