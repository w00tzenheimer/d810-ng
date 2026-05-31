"""Proof-of-shape tests for ``ir.insn_projection`` (first cut of llr-lxas).

These pin the behaviour-exact MOV-family projection onto the portable
expression/value/location substrate, and in particular the selectivity
guarantee the dispatcher re-point relies on: ``isinstance(value, Const)`` is
true exactly when the live source operand was a number.
"""
from __future__ import annotations

from d810.ir.expressions import Const, Move
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.insn_projection import LiftedAssignment, project_assignment
from d810.ir.locations import RegisterLocation, StackSlot
from d810.ir.value_refs import DefinitionRef

M_MOV = 0x4


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _reg(register_id: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _mov(l: MopSnapshot | None, d: MopSnapshot | None) -> InsnSnapshot:
    return InsnSnapshot(opcode=M_MOV, ea=0x1000, operands=(), kind=InsnKind.MOV, l=l, d=d)


def test_mov_const_to_stack_projects_const_and_stackslot():
    a = project_assignment(_mov(_num(0x41FB8FBB), _stk(0x3C)))
    assert a == LiftedAssignment(
        target=DefinitionRef(location=StackSlot(offset=0x3C, size=4)),
        value=Const(value=0x41FB8FBB),
    )


def test_mov_stack_to_register_projects_move_of_definition():
    a = project_assignment(_mov(_stk(0x3C, size=4), _reg(0)))
    assert a is not None
    assert a.target == DefinitionRef(location=RegisterLocation(register_id=0, size=4))
    assert a.value == Move(source=DefinitionRef(location=StackSlot(offset=0x3C, size=4)))


def test_mov_register_to_stack_projects_move_into_stackslot():
    a = project_assignment(_mov(_reg(8), _stk(0x7F0)))
    assert a is not None
    assert a.target == DefinitionRef(location=StackSlot(offset=0x7F0, size=4))
    assert a.value == Move(source=DefinitionRef(location=RegisterLocation(register_id=8, size=4)))


def test_non_mov_returns_none():
    add = InsnSnapshot(opcode=0x12, ea=0x1000, operands=(), kind=InsnKind.ADD,
                       l=_num(1), d=_stk(0x3C))
    assert project_assignment(add) is None


def test_const_selectivity_matches_number_source_guard():
    # The dispatcher re-point tests ``isinstance(value, Const)`` in place of
    # ``insn.l.kind is OperandKind.NUMBER`` -- they must agree exactly.
    assert isinstance(project_assignment(_mov(_num(7), _stk(0x10))).value, Const)
    non_number = project_assignment(_mov(_stk(0x20), _stk(0x10)))
    assert non_number is not None and not isinstance(non_number.value, Const)


def test_number_source_with_no_value_does_not_fabricate_const():
    # A NUMBER operand whose decoded value is missing must NOT become Const(0);
    # it falls to None so the dispatcher skips it (matching the live read where
    # ``None in state_constants`` was False).
    a = project_assignment(_mov(MopSnapshot(kind=OperandKind.NUMBER, value=None), _stk(0x10)))
    assert a is not None and a.value is None


def test_unprojectable_source_and_dest_returns_none():
    lvar = MopSnapshot(kind=OperandKind.LVAR, lvar_off=4)
    assert project_assignment(_mov(lvar, lvar)) is None
