"""Proof-of-shape tests for ``ir.insn_projection`` (first cut of llr-lxas).

These pin the behaviour-exact MOV-family projection onto the portable
expression/value/location substrate, and in particular the selectivity
guarantee the dispatcher re-point relies on: ``isinstance(value, Const)`` is
true exactly when the live source operand was a number.
"""
from __future__ import annotations

from dataclasses import fields

from d810.ir.expressions import Add, And, Const, Move, Mul, Sub, ValueOpKind
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.insn_projection import (
    iter_operand_exprs,
    operand_kinds,
    operand_stack_offsets,
    operand_stack_refs,
    operand_storages,
    primary_source_operand_kind,
    primary_source_storage,
    project_assignment,
    project_conditional_branch,
    project_instruction,
    project_instruction_sequence,
    project_operand_expr,
    result_storage,
)
from d810.ir.instructions import (
    Instruction,
    InstructionControl,
    InstructionEffect,
    InstructionEffectKind,
    InstructionMemoryAccess,
    InstructionMemoryAccessKind,
    InstructionSwitchCase,
)
from d810.ir.locations import RegisterLocation, StackSlot, WeakStackSlot
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.ir.statements import Assignment, ConditionalBranch
from d810.ir.value_refs import DefinitionRef
from d810.ir.varnode import Space, Varnode

M_MOV = 0x4


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _reg(register_id: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _glob(address: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.GLOBAL, gaddr=address, size=size)


def _args(*args: MopSnapshot) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.ARG_LIST, args=args)


def _lvar(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.LVAR, lvar_off=offset, size=size)


def _block(serial: int) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.BLOCK, block_ref=serial)


def _mov(l: MopSnapshot | None, d: MopSnapshot | None) -> InsnSnapshot:
    return InsnSnapshot(opcode=M_MOV, ea=0x1000, operands=(), kind=InsnKind.MOV, l=l, d=d)


def test_instruction_record_pins_operation_as_field_not_whole_record():
    instruction = project_instruction(_mov(_num(1), _stk(0x10)))

    assert isinstance(instruction, Instruction)
    assert instruction.operation is not instruction
    assert [field.name for field in fields(Instruction)] == [
        "operation",
        "inputs",
        "result",
        "effects",
        "control",
        "memory",
        "attrs",
        "input_exprs",
        "operand_expr_fragments",
    ]


def test_instruction_projection_value_op_keeps_raw_opcode_in_attrs_only():
    insn = InsnSnapshot(
        opcode=M_MOV,
        ea=0x1000,
        operands=(),
        kind=InsnKind.MOV,
        l=_num(0x41),
        d=_stk(0x10),
        opcode_attrs={
            "backend": "hexrays",
            "raw_opcode_name": "m_mov",
            "producer_stage_id": 14,
            "producer_stage_name": "MMAT_GLBOPT1",
        },
    )

    instruction = project_instruction(insn)

    assert instruction.operation is insn.value_op_kind
    assert instruction.inputs == (Varnode(Space.CONST, 0x41, 4),)
    assert instruction.result == Varnode(Space.STACK, 0x10, 4)
    assert instruction.effects == ()
    assert instruction.control is None
    assert instruction.attrs["ea"] == 0x1000
    assert instruction.attrs["backend"] == "hexrays"
    assert instruction.attrs["raw_opcode_int"] == M_MOV
    assert instruction.attrs["raw_opcode_name"] == "m_mov"
    assert instruction.attrs["producer_stage_id"] == 14
    assert not hasattr(instruction, "raw_opcode")


def test_instruction_projection_preserves_register_stack_global_lvar_varnodes():
    add = InsnSnapshot(
        opcode=0x12,
        ea=0x1000,
        operands=(),
        kind=InsnKind.ADD,
        l=_reg(1, size=8),
        r=_glob(0x180012340, size=8),
        d=_lvar(0x28, size=8),
    )

    instruction = project_instruction(add)

    assert instruction.operation is add.value_op_kind
    assert instruction.inputs == (
        Varnode(Space.REGISTER, 1, 8),
        Varnode(Space.GLOBAL, 0x180012340, 8),
    )
    assert instruction.result == Varnode(Space.LVAR, 0x28, 8)


def test_instruction_projection_skips_unknown_operands():
    weak_stack = MopSnapshot(kind=OperandKind.STACK, stkoff=None, size=4)
    number_without_value = MopSnapshot(kind=OperandKind.NUMBER, value=None, size=4)
    insn = InsnSnapshot(
        opcode=0x12,
        ea=0x1000,
        operands=(),
        kind=InsnKind.ADD,
        l=weak_stack,
        r=number_without_value,
        d=weak_stack,
    )

    instruction = project_instruction(insn)

    assert instruction.inputs == ()
    assert instruction.result is None


def test_mov_const_to_stack_projects_const_and_stackslot():
    a = project_assignment(_mov(_num(0x41FB8FBB), _stk(0x3C)))
    assert a == Assignment(
        target=DefinitionRef(location=StackSlot(offset=0x3C, size=4)),
        value=Const(value=0x41FB8FBB),
    )


def test_mov_to_unknown_offset_stack_projects_weak_slot():
    # A stack destination whose offset is unrecovered becomes a WeakStackSlot
    # (LiSA weak identifier) -- imprecise, never dropped to None.
    weak_dst = MopSnapshot(kind=OperandKind.STACK, stkoff=None, size=4)
    a = project_assignment(_mov(_num(0x55), weak_dst))
    assert a == Assignment(
        target=DefinitionRef(location=WeakStackSlot(size=4)),
        value=Const(value=0x55),
    )


def test_mov_from_unknown_offset_stack_projects_move_of_weak_slot():
    weak_src = MopSnapshot(kind=OperandKind.STACK, stkoff=None, size=8)
    a = project_assignment(_mov(weak_src, _reg(0)))
    assert a is not None
    assert a.value == Move(source=DefinitionRef(location=WeakStackSlot(size=8)))


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


def _jcc(predicate: PredicateKind, l: MopSnapshot, r: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x2C, ea=0x1000, operands=(), kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=predicate, l=l, r=r,
    )


def test_conditional_branch_projects_predicate_operands_and_edges():
    insn = _jcc(PredicateKind.EQ, _stk(0x3C), _num(7))
    cb = project_conditional_branch(insn, taken=12, fallthrough=13)
    assert cb == ConditionalBranch(
        predicate=PredicateKind.EQ,
        lhs=Move(source=DefinitionRef(location=StackSlot(offset=0x3C, size=4))),
        rhs=Const(value=7),
        taken=12,
        fallthrough=13,
    )


def test_instruction_projection_conditional_branch_uses_control_operation():
    instruction = project_instruction(_jcc(PredicateKind.EQ, _stk(0x3C), _num(7)))

    assert instruction.operation is ControlTransferKind.CONDITIONAL_BRANCH
    assert instruction.inputs == (
        Varnode(Space.STACK, 0x3C, 4),
        Varnode(Space.CONST, 7, 4),
    )
    assert instruction.result is None
    assert instruction.control == InstructionControl(
        transfer=ControlTransferKind.CONDITIONAL_BRANCH,
        predicate=PredicateKind.EQ,
    )


def test_instruction_projection_conditional_branch_preserves_block_target():
    insn = InsnSnapshot(
        opcode=0x2C,
        ea=0x1000,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.EQ,
        l=_stk(0x3C),
        r=_num(7),
        d=_block(12),
    )

    instruction = project_instruction(insn)

    assert instruction.operation is ControlTransferKind.CONDITIONAL_BRANCH
    assert instruction.control == InstructionControl(
        transfer=ControlTransferKind.CONDITIONAL_BRANCH,
        predicate=PredicateKind.EQ,
        target=12,
    )


def test_conditional_branch_none_for_non_branch():
    assert project_conditional_branch(_mov(_num(1), _stk(0x10))) is None


def test_conditional_branch_predicate_passthrough():
    # The predicate is the already-portable PredicateKind carried on the snapshot.
    cb = project_conditional_branch(_jcc(PredicateKind.TRUTHY, _stk(0x10), _num(0)))
    assert cb is not None and cb.predicate is PredicateKind.TRUTHY
    assert cb.taken is None and cb.fallthrough is None


def test_instruction_projection_predicate_materialization_uses_predicate_operation():
    insn = InsnSnapshot(
        opcode=0x34,
        ea=0x1000,
        operands=(),
        kind=InsnKind.UNKNOWN,
        predicate_kind=PredicateKind.EQ,
        opcode_attrs={"backend": "hexrays", "raw_opcode_name": "m_setz"},
    )

    instruction = project_instruction(insn)

    assert instruction.operation is PredicateKind.EQ
    assert instruction.inputs == ()
    assert instruction.result is None
    assert instruction.control is None
    assert instruction.attrs["raw_opcode_name"] == "m_setz"


def test_instruction_projection_predicate_materialization_uses_destination_result():
    insn = InsnSnapshot(
        opcode=0x34,
        ea=0x1000,
        operands=(),
        kind=InsnKind.UNKNOWN,
        l=_reg(1),
        r=_num(0),
        d=_reg(2, size=1),
        predicate_kind=PredicateKind.EQ,
        opcode_attrs={"backend": "hexrays", "raw_opcode_name": "m_setz"},
    )

    instruction = project_instruction(insn)

    assert instruction.operation is PredicateKind.EQ
    assert instruction.inputs == (
        Varnode(Space.REGISTER, 1, 4),
        Varnode(Space.CONST, 0, 4),
    )
    assert instruction.result == Varnode(Space.REGISTER, 2, 1)


def test_instruction_projection_predicate_materialization_preserves_duplicate_operands():
    repeated = _reg(0)
    insn = InsnSnapshot(
        opcode=0x34,
        ea=0x1000,
        operands=(),
        kind=InsnKind.UNKNOWN,
        l=repeated,
        r=repeated,
        d=_reg(1, size=1),
        predicate_kind=PredicateKind.EQ,
        opcode_attrs={"backend": "hexrays", "raw_opcode_name": "m_setz"},
    )

    instruction = project_instruction(insn)

    assert instruction.operation is PredicateKind.EQ
    assert instruction.inputs == (
        Varnode(Space.REGISTER, 0, 4),
        Varnode(Space.REGISTER, 0, 4),
    )
    assert instruction.result == Varnode(Space.REGISTER, 1, 1)


def test_instruction_projection_value_op_preserves_duplicate_operands():
    repeated = _reg(0)
    add = InsnSnapshot(
        opcode=0x12,
        ea=0x1000,
        operands=(),
        kind=InsnKind.ADD,
        l=repeated,
        r=repeated,
        d=_reg(1),
    )

    instruction = project_instruction(add)

    assert instruction.operation is ValueOpKind.ADD
    assert instruction.inputs == (
        Varnode(Space.REGISTER, 0, 4),
        Varnode(Space.REGISTER, 0, 4),
    )
    assert instruction.result == Varnode(Space.REGISTER, 1, 4)


def test_instruction_projection_raw_opcode_name_does_not_authorize_semantics():
    insn = InsnSnapshot(
        opcode=0x2C,
        ea=0x1000,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"backend": "hexrays", "raw_opcode_name": "m_jz"},
    )

    instruction = project_instruction(insn)

    assert instruction.operation is not ControlTransferKind.CONDITIONAL_BRANCH
    assert instruction.control is None


def test_instruction_projection_call_and_return_operations():
    call = project_instruction(
        InsnSnapshot(
            opcode=0x41,
            ea=0x1000,
            operands=(),
            kind=InsnKind.CALL,
            l=_glob(0x180010000),
            d=_reg(0, size=8),
            call_kind=CallKind.DIRECT,
        )
    )
    ret = project_instruction(
        InsnSnapshot(opcode=0x42, ea=0x1004, operands=(), kind=InsnKind.RET, l=_reg(0, size=8))
    )

    assert call.operation is CallKind.DIRECT
    assert call.inputs == (Varnode(Space.GLOBAL, 0x180010000, 8),)
    assert call.result == Varnode(Space.REGISTER, 0, 8)
    assert call.effects == (
        InstructionEffect(
            kind=InstructionEffectKind.CALL,
            target=Varnode(Space.GLOBAL, 0x180010000, 8),
            value=Varnode(Space.REGISTER, 0, 8),
        ),
    )
    assert call.control == InstructionControl(
        call_kind=CallKind.DIRECT,
        call_target=Varnode(Space.GLOBAL, 0x180010000, 8),
    )
    assert ret.operation is ControlTransferKind.RETURN
    assert ret.inputs == (Varnode(Space.REGISTER, 0, 8),)
    assert ret.result is None
    assert ret.control == InstructionControl(
        transfer=ControlTransferKind.RETURN,
        return_value=Varnode(Space.REGISTER, 0, 8),
    )


def test_instruction_projection_call_argument_list_becomes_call_args():
    call = project_instruction(
        InsnSnapshot(
            opcode=0x41,
            ea=0x1000,
            operands=(),
            kind=InsnKind.CALL,
            l=_glob(0x180010000),
            d=_args(_stk(0x20, size=8), _glob(0x180020000), _num(0x10, size=8)),
            call_kind=CallKind.DIRECT,
        )
    )

    expected_args = (
        Varnode(Space.STACK, 0x20, 8),
        Varnode(Space.GLOBAL, 0x180020000, 8),
        Varnode(Space.CONST, 0x10, 8),
    )
    assert call.inputs == (
        Varnode(Space.GLOBAL, 0x180010000, 8),
        *expected_args,
    )
    assert call.result is None
    assert call.effects == (
        InstructionEffect(
            kind=InstructionEffectKind.CALL,
            target=Varnode(Space.GLOBAL, 0x180010000, 8),
            args=expected_args,
        ),
    )
    assert call.control == InstructionControl(
        call_kind=CallKind.DIRECT,
        call_target=Varnode(Space.GLOBAL, 0x180010000, 8),
        call_args=expected_args,
    )


def test_instruction_projection_call_argument_list_from_r_is_not_call_target():
    call = project_instruction(
        InsnSnapshot(
            opcode=0x41,
            ea=0x1000,
            operands=(),
            kind=InsnKind.CALL,
            l=_glob(0x180010000),
            r=_args(_reg(2, size=8), _num(4, size=8)),
            call_kind=CallKind.DIRECT,
        )
    )

    assert call.control == InstructionControl(
        call_kind=CallKind.DIRECT,
        call_target=Varnode(Space.GLOBAL, 0x180010000, 8),
        call_args=(Varnode(Space.REGISTER, 2, 8), Varnode(Space.CONST, 4, 8)),
    )


def test_instruction_projection_store_has_typed_effect_not_result():
    store = project_instruction(
        InsnSnapshot(
            opcode=0x21,
            ea=0x1000,
            operands=(),
            kind=InsnKind.STORE,
            l=_reg(1, size=8),
            r=_reg(2, size=4),
            d=_glob(0x180020000, size=4),
        )
    )

    assert store.operation is ValueOpKind.STORE
    assert store.inputs == (
        Varnode(Space.REGISTER, 1, 8),
        Varnode(Space.REGISTER, 2, 4),
        Varnode(Space.GLOBAL, 0x180020000, 4),
    )
    assert store.result is None
    assert store.effects == (
        InstructionEffect(
            kind=InstructionEffectKind.STORE,
            target=Varnode(Space.GLOBAL, 0x180020000, 4),
            segment=Varnode(Space.REGISTER, 2, 4),
            value=Varnode(Space.REGISTER, 1, 8),
        ),
    )
    assert store.memory == InstructionMemoryAccess(
        kind=InstructionMemoryAccessKind.INDIRECT,
        target=Varnode(Space.GLOBAL, 0x180020000, 4),
        segment=Varnode(Space.REGISTER, 2, 4),
        value=Varnode(Space.REGISTER, 1, 8),
        width=8,
    )


def test_instruction_projection_records_address_constants_as_attrs():
    address = MopSnapshot(
        kind=OperandKind.ADDRESS,
        size=8,
        stack_refs=(0x190,),
        sub_l=_subinsn(InsnKind.ADD, _stk(0x190, size=8), _num(6, size=8)),
    )

    store = project_instruction(
        InsnSnapshot(
            opcode=0x21,
            ea=0x1000,
            operands=(),
            kind=InsnKind.STORE,
            l=_reg(1, size=8),
            r=_reg(2, size=4),
            d=address,
        )
    )

    assert store.attrs["address_stack_refs"] == (0x190,)
    assert store.attrs["address_const_values"] == (6,)


def test_instruction_projection_load_has_indirect_memory_contract():
    load = project_instruction(
        InsnSnapshot(
            opcode=0x20,
            ea=0x1000,
            operands=(),
            kind=InsnKind.LOAD,
            l=_reg(2, size=2),
            r=_glob(0x180020000, size=4),
            d=_reg(1, size=4),
        )
    )

    assert load.operation is ValueOpKind.LOAD
    assert load.inputs == (
        Varnode(Space.REGISTER, 2, 2),
        Varnode(Space.GLOBAL, 0x180020000, 4),
    )
    assert load.result == Varnode(Space.REGISTER, 1, 4)
    assert load.effects == ()
    assert load.memory == InstructionMemoryAccess(
        kind=InstructionMemoryAccessKind.INDIRECT,
        target=Varnode(Space.GLOBAL, 0x180020000, 4),
        segment=Varnode(Space.REGISTER, 2, 2),
        width=4,
    )


def test_instruction_projection_goto_indirect_and_switch_control_payloads():
    goto = project_instruction(
        InsnSnapshot(opcode=0x30, ea=0x1000, operands=(), kind=InsnKind.GOTO, l=_block(7))
    )
    ijmp = project_instruction(
        InsnSnapshot(
            opcode=0x31,
            ea=0x1004,
            operands=(),
            kind=InsnKind.INDIRECT_JUMP,
            l=_reg(9, size=8),
        )
    )
    cases = (((1, 2), 10), ((), 11))
    table = project_instruction(
        InsnSnapshot(
            opcode=0x32,
            ea=0x1008,
            operands=(),
            kind=InsnKind.TABLE_JUMP,
            l=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=cases),
            r=_reg(3, size=4),
        )
    )

    assert goto.control == InstructionControl(transfer=ControlTransferKind.GOTO, target=7)
    assert ijmp.control == InstructionControl(
        transfer=ControlTransferKind.INDIRECT_BRANCH,
        indirect_target=Varnode(Space.REGISTER, 9, 8),
    )
    assert table.operation is ControlTransferKind.TABLE_BRANCH
    assert table.inputs == (Varnode(Space.REGISTER, 3, 4),)
    assert table.control == InstructionControl(
        transfer=ControlTransferKind.TABLE_BRANCH,
        switch_cases=(
            InstructionSwitchCase(values=(1, 2), target=10),
            InstructionSwitchCase(values=(), target=11),
        ),
    )


def test_subinsn_indirect_target_reuses_input_temp():
    nested = _subinsn(InsnKind.ADD, _reg(1, size=8), _num(4, size=8))
    instruction = project_instruction(
        InsnSnapshot(
            opcode=0x31,
            ea=0x1000,
            operands=(),
            kind=InsnKind.INDIRECT_JUMP,
            l=nested,
        )
    )

    assert instruction.inputs == (
        Varnode(Space.TEMP, 0, 0),
        Varnode(Space.REGISTER, 1, 8),
        Varnode(Space.CONST, 4, 8),
    )
    assert instruction.control == InstructionControl(
        transfer=ControlTransferKind.INDIRECT_BRANCH,
        indirect_target=Varnode(Space.TEMP, 0, 0),
    )


def test_assignment_and_conditional_branch_are_statement_views_not_instructions():
    assert not issubclass(Assignment, Instruction)
    assert not issubclass(ConditionalBranch, Instruction)


def test_assignment_view_reuses_canonical_instruction_boundary():
    insn = _mov(_num(0x41), _stk(0x10))
    instruction = project_instruction(insn)
    assignment = project_assignment(insn)

    assert instruction.operation is ValueOpKind.MOVE
    assert instruction.inputs == (Varnode(Space.CONST, 0x41, 4),)
    assert instruction.result == Varnode(Space.STACK, 0x10, 4)
    assert assignment == Assignment(
        target=DefinitionRef(location=StackSlot(offset=0x10, size=4)),
        value=Const(value=0x41),
    )


def _subinsn(sub_kind, sub_l: MopSnapshot, sub_r: MopSnapshot) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.SUBINSN, sub_kind=sub_kind, sub_l=sub_l, sub_r=sub_r)


def _semantic_subinsn(
    value_op_kind: ValueOpKind,
    sub_l: MopSnapshot,
    sub_r: MopSnapshot,
) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_value_op_kind=value_op_kind,
        sub_l=sub_l,
        sub_r=sub_r,
    )


def test_nested_mop_d_and_lifts_to_And_expression():
    # ``jz (var & 0x3F), #0`` -- the compared operand is a nested m_and.
    nested = _subinsn(InsnKind.AND, _stk(0x3C), _num(0x3F))
    instruction = project_instruction(_jcc(PredicateKind.EQ, nested, _num(0)))
    cb = project_conditional_branch(_jcc(PredicateKind.EQ, nested, _num(0)))
    assert instruction.inputs == (
        Varnode(Space.TEMP, 0, 0),
        Varnode(Space.STACK, 0x3C, 4),
        Varnode(Space.CONST, 0x3F, 4),
        Varnode(Space.CONST, 0, 4),
    )
    assert cb.lhs == And(
        left=Move(source=DefinitionRef(location=StackSlot(offset=0x3C, size=4))),
        right=Const(value=0x3F),
    )


def test_instruction_sequence_lowers_nested_and_before_branch():
    nested = _subinsn(InsnKind.AND, _stk(0x3C), _num(0x3F))
    sequence = project_instruction_sequence(_jcc(PredicateKind.EQ, nested, _num(0)))

    assert len(sequence) == 2
    and_temp, branch = sequence
    assert and_temp.operation is ValueOpKind.AND
    assert and_temp.inputs == (
        Varnode(Space.STACK, 0x3C, 4),
        Varnode(Space.CONST, 0x3F, 4),
    )
    assert and_temp.result == Varnode(Space.TEMP, 0, 4)
    assert branch.operation is ControlTransferKind.CONDITIONAL_BRANCH
    assert branch.inputs == (
        Varnode(Space.TEMP, 0, 4),
        Varnode(Space.CONST, 0, 4),
    )


def test_nested_mop_d_recurses_two_levels():
    # ``((var - 1) & 0x3F)``
    outer = _subinsn(InsnKind.AND, _subinsn(InsnKind.SUB, _stk(0x10), _num(1)), _num(0x3F))
    instruction = project_instruction(_jcc(PredicateKind.NE, outer, _num(0)))
    cb = project_conditional_branch(_jcc(PredicateKind.NE, outer, _num(0)))
    assert instruction.inputs == (
        Varnode(Space.TEMP, 0, 0),
        Varnode(Space.TEMP, 1, 0),
        Varnode(Space.STACK, 0x10, 4),
        Varnode(Space.CONST, 1, 4),
        Varnode(Space.CONST, 0x3F, 4),
        Varnode(Space.CONST, 0, 4),
    )
    assert cb.lhs == And(
        left=Sub(
            left=Move(source=DefinitionRef(location=StackSlot(offset=0x10, size=4))),
            right=Const(value=1),
        ),
        right=Const(value=0x3F),
    )


def test_instruction_sequence_lowers_nested_two_level_expression_child_first():
    outer = _subinsn(InsnKind.AND, _subinsn(InsnKind.SUB, _stk(0x10), _num(1)), _num(0x3F))
    sequence = project_instruction_sequence(_jcc(PredicateKind.NE, outer, _num(0)))

    assert len(sequence) == 3
    sub_temp, and_temp, branch = sequence
    assert sub_temp.operation is ValueOpKind.SUB
    assert sub_temp.inputs == (
        Varnode(Space.STACK, 0x10, 4),
        Varnode(Space.CONST, 1, 4),
    )
    assert sub_temp.result == Varnode(Space.TEMP, 0, 4)
    assert and_temp.operation is ValueOpKind.AND
    assert and_temp.inputs == (
        Varnode(Space.TEMP, 0, 4),
        Varnode(Space.CONST, 0x3F, 4),
    )
    assert and_temp.result == Varnode(Space.TEMP, 1, 4)
    assert branch.operation is ControlTransferKind.CONDITIONAL_BRANCH
    assert branch.inputs == (
        Varnode(Space.TEMP, 1, 4),
        Varnode(Space.CONST, 0, 4),
    )


def test_instruction_sequence_uses_nested_value_op_kind_for_extended_ops():
    nested = _semantic_subinsn(ValueOpKind.XOR, _stk(0x10), _num(0xFF))
    sequence = project_instruction_sequence(_jcc(PredicateKind.NE, nested, _num(0)))

    assert len(sequence) == 2
    xor_temp, branch = sequence
    assert xor_temp.operation is ValueOpKind.XOR
    assert xor_temp.inputs == (
        Varnode(Space.STACK, 0x10, 4),
        Varnode(Space.CONST, 0xFF, 4),
    )
    assert xor_temp.result == Varnode(Space.TEMP, 0, 4)
    assert xor_temp.attrs["nested_sub_value_op_kind"] == "xor"
    assert branch.inputs == (
        Varnode(Space.TEMP, 0, 4),
        Varnode(Space.CONST, 0, 4),
    )


def test_unmapped_nested_op_projects_none_not_wrong():
    # An unmapped sub-op kind -> None (lossy), never a wrong expression.
    nested = _subinsn(InsnKind.UNKNOWN, _stk(0x10), _num(1))
    cb = project_conditional_branch(_jcc(PredicateKind.EQ, nested, _num(0)))
    assert cb is not None and cb.lhs is None


def test_operand_expr_fragments_include_supported_children_below_vendor_wrapper():
    sub = _subinsn(InsnKind.SUB, _stk(0x10), _num(1))
    nested = _subinsn(InsnKind.UNKNOWN, sub, _num(0xFF))

    assert project_operand_expr(nested) is None
    assert iter_operand_exprs(nested) == (
        Sub(
            left=Move(source=DefinitionRef(location=StackSlot(offset=0x10, size=4))),
            right=Const(value=1),
        ),
        Move(source=DefinitionRef(location=StackSlot(offset=0x10, size=4))),
        Const(value=1),
        Const(value=0xFF),
    )


def test_instruction_sequence_keeps_unsupported_nested_op_explicit():
    nested = _subinsn(InsnKind.UNKNOWN, _stk(0x10), _num(1))
    sequence = project_instruction_sequence(_jcc(PredicateKind.EQ, nested, _num(0)))

    assert len(sequence) == 2
    unsupported, branch = sequence
    assert unsupported.operation is ValueOpKind.VENDOR
    assert unsupported.result == Varnode(Space.TEMP, 0, 4)
    assert unsupported.attrs["unsupported_nested_sub_kind"] == "unknown"
    assert branch.inputs == (
        Varnode(Space.TEMP, 0, 4),
        Varnode(Space.CONST, 0, 4),
    )


# ---------------------------------------------------------------------------
# Weak-stack-preserving storage views (llr-ykmh): register / stack-known / lvar
# / const project to a Varnode, an unknown-offset stack operand projects to a
# WeakStackSlot rather than collapsing to Varnode(UNKNOWN).
# ---------------------------------------------------------------------------


def _weak_stk(size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=None, size=size)


def test_result_storage_register():
    insn = _mov(_stk(0x10), _reg(0, size=8))
    assert result_storage(insn) == Varnode(Space.REGISTER, 0, 8)


def test_result_storage_known_stack():
    insn = _mov(_reg(0), _stk(0x7F0, size=8))
    assert result_storage(insn) == Varnode(Space.STACK, 0x7F0, 8)


def test_result_storage_unknown_stack_is_weak_slot():
    insn = _mov(_reg(0), _weak_stk(size=8))
    view = result_storage(insn)
    assert isinstance(view, WeakStackSlot)
    assert view.size == 8


def test_result_storage_lvar():
    insn = _mov(_reg(0), _lvar(0x20, size=8))
    assert result_storage(insn) == Varnode(Space.LVAR, 0x20, 8)


def test_primary_source_storage_const():
    insn = _mov(_num(0xABCD, size=8), _reg(0))
    assert primary_source_storage(insn) == Varnode(Space.CONST, 0xABCD, 8)


def test_primary_source_storage_unknown_stack_is_weak_slot():
    insn = _mov(_weak_stk(size=4), _reg(0))
    view = primary_source_storage(insn)
    assert isinstance(view, WeakStackSlot)
    assert view.size == 4


def test_operand_storages_ordered_lrd():
    insn = InsnSnapshot(
        opcode=M_MOV,
        ea=0x1000,
        operands=(),
        kind=InsnKind.MOV,
        l=_stk(0x10, size=8),
        r=_num(7, size=8),
        d=_reg(0, size=8),
    )
    left, right, dest = operand_storages(insn)
    assert left == Varnode(Space.STACK, 0x10, 8)
    assert right == Varnode(Space.CONST, 7, 8)
    assert dest == Varnode(Space.REGISTER, 0, 8)


def test_storage_views_none_for_missing_operand():
    insn = _mov(None, None)
    assert result_storage(insn) is None
    assert primary_source_storage(insn) is None
    assert operand_storages(insn) == (None, None, None)


def test_primary_source_operand_kind_distinguishes_address_from_value():
    # d81-qlal -- pin the lift-boundary source-kind accessor the exit-path
    # carrier classifier consumes.  ``operand_storages`` collapses both ADDRESS
    # and a nested value-producing source to ``Space.UNKNOWN``, so a
    # carrier-source classifier that must keep ``cursor_or_ptr`` (ADDRESS) apart
    # from ``expr`` (any other present source) and ``real_const`` (NUMBER) reads
    # the portable operand kind here instead.
    assert primary_source_operand_kind(_mov(_num(7), _stk(0x10))) is OperandKind.NUMBER
    address_src = MopSnapshot(kind=OperandKind.ADDRESS, stack_refs=(0x40,))
    assert primary_source_operand_kind(_mov(address_src, _stk(0x10))) is OperandKind.ADDRESS
    assert primary_source_operand_kind(_mov(_reg(0), _stk(0x10))) is OperandKind.REGISTER
    assert primary_source_operand_kind(_mov(_glob(0x401000), _stk(0x10))) is OperandKind.GLOBAL
    assert primary_source_operand_kind(_mov(None, _stk(0x10))) is None


def test_operand_kinds_l_r_d_slot_classification():
    # d81-qlal -- pin the slot-aligned operand-kind accessor the
    # minimal_state_recovery destination locator consumes.  ``operand_storages``
    # collapses an LVAR carrying a frame offset to a ``Space.STACK`` view (the
    # ``varnode_from_mop_snapshot`` promotion), so the kind-gated locator MUST
    # read the original ``OperandKind`` here to keep an LVAR destination apart
    # from a genuine STACK destination (legacy ``_is_stack_operand`` gate).
    insn = InsnSnapshot(
        opcode=M_MOV,
        ea=0x1000,
        operands=(),
        kind=InsnKind.MOV,
        l=_num(7),
        r=_reg(3),
        d=_stk(0x20),
    )
    assert operand_kinds(insn) == (
        OperandKind.NUMBER,
        OperandKind.REGISTER,
        OperandKind.STACK,
    )
    # An LVAR destination keeps OperandKind.LVAR even though its storage view may
    # promote to a STACK Varnode when a frame offset was lifted.
    lvar_dst = MopSnapshot(kind=OperandKind.LVAR, lvar_off=0x8, lvar_stkoff=0x30, size=4)
    assert operand_kinds(_mov(_num(1), lvar_dst))[2] is OperandKind.LVAR
    assert operand_kinds(_mov(None, None)) == (None, None, None)


def test_operand_stack_offsets_decodes_direct_address_and_single_ref():
    # d81-qlal -- pin the per-slot referenced-stack-offset accessor the
    # stack-address-alias resolver consumes.  The ``Varnode`` storage view
    # collapses ADDRESS / multi-stack-ref operands to ``Space.UNKNOWN``; this
    # accessor recovers the SINGLE stack slot an operand names (direct stack,
    # address-of-stack, or a sole ``stack_ref``), matching the legacy
    # ``_stack_offset_from_address`` decode.
    direct = _stk(0x40, size=8)
    address_of_stack = MopSnapshot(kind=OperandKind.ADDRESS, sub_l=_stk(0x48, size=8))
    sole_ref = MopSnapshot(kind=OperandKind.ADDRESS, stack_refs=(0x50,))
    multi_ref = MopSnapshot(kind=OperandKind.ADDRESS, stack_refs=(0x60, 0x68))
    insn = InsnSnapshot(
        opcode=M_MOV,
        ea=0x1000,
        operands=(),
        kind=InsnKind.MOV,
        l=address_of_stack,
        r=sole_ref,
        d=direct,
    )
    assert operand_stack_offsets(insn) == (0x48, 0x50, 0x40)
    # A multi-ref ADDRESS operand names no single slot.
    assert operand_stack_offsets(_mov(multi_ref, _reg(0)))[0] is None
    # NUMBER / REGISTER operands reference no stack slot.
    assert operand_stack_offsets(_mov(_num(7), _reg(1))) == (None, None, None)
    assert operand_stack_offsets(_mov(None, None)) == (None, None, None)


def test_operand_stack_refs_per_slot_membership_sets():
    # d81-qlal -- pin the per-slot stack-ref set accessor the terminal-guard
    # successor analysis membership-tests (``state_var_stkoff in refs``).  It
    # reads the operand's lifted ``stack_refs`` set exactly as the legacy
    # ``getattr(left, "stack_refs", ())`` read did: a compared sub-expression
    # exposes EVERY referenced slot (the membership the single-offset
    # ``operand_stack_offsets`` cannot express), an operand carrying no lifted
    # ``stack_refs`` yields the empty set, and an absent slot yields the empty
    # set.
    state_with_refs = MopSnapshot(kind=OperandKind.STACK, stkoff=0x3C, size=8, stack_refs=(0x3C,))
    multi = MopSnapshot(kind=OperandKind.ADDRESS, stack_refs=(0x3C, 0x40))
    insn = InsnSnapshot(
        opcode=0x12,
        ea=0x1000,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        l=multi,
        r=_num(0x22),
        is_conditional_jump=True,
        branch_predicate=PredicateKind.EQ,
    )
    left_refs, right_refs, dest_refs = operand_stack_refs(insn)
    assert 0x3C in left_refs and 0x40 in left_refs
    assert right_refs == frozenset()
    assert dest_refs == frozenset()
    # A lifted direct-stack operand carries its own offset in ``stack_refs``.
    assert operand_stack_refs(_mov(state_with_refs, _reg(0)))[0] == frozenset({0x3C})
    # No lifted ``stack_refs`` (and absent slots) -> empty sets (legacy
    # ``getattr(..., "stack_refs", ())`` returned the operand's own empty tuple).
    assert operand_stack_refs(_mov(_stk(0x3C, size=8), _reg(0)))[0] == frozenset()
    assert operand_stack_refs(_mov(None, None)) == (
        frozenset(),
        frozenset(),
        frozenset(),
    )




def test_input_exprs_slot0_is_lifted_tree_for_subinsn_source():
    # ``jz (var * 5 + var), #0`` -- insn.l is a nested add(mul(var,5), var).
    mul_node = _subinsn(InsnKind.MUL, _stk(0x3C), _num(5))
    add_node = _subinsn(InsnKind.ADD, mul_node, _stk(0x3C))
    insn = _jcc(PredicateKind.EQ, add_node, _num(0))

    instruction = project_instruction(insn)

    expected_tree = Add(
        left=Mul(
            left=Move(source=DefinitionRef(location=StackSlot(offset=0x3C, size=4))),
            right=Const(value=5),
        ),
        right=Move(source=DefinitionRef(location=StackSlot(offset=0x3C, size=4))),
    )
    assert instruction.input_exprs[0] == expected_tree
    # slot[1] = insn.r = #0
    assert instruction.input_exprs[1] == Const(value=0)


def test_input_exprs_flat_instruction_yields_shallow_expr():
    # A plain mov #const -> stack: insn.l is a NUMBER, insn.r is absent.
    insn = _mov(_num(0x41), _stk(0x10))
    instruction = project_instruction(insn)

    # slot[0] = Const (shallow), slot[1] = None (no r operand)
    assert instruction.input_exprs[0] == Const(value=0x41)
    assert instruction.input_exprs[1] is None


def test_operand_expr_fragments_expose_buried_sub_under_non_binop_wrapper():
    # ``jge xdu(i - #0x64), #0`` -- the (i - #0x64) Sub is buried under an
    # UNKNOWN (non-binop / vendor) wrapper. ``_value_of`` of the top operand is
    # None (returns None on a non-binop SUBINSN, insn_projection.py:613-614), so
    # input_exprs[0] is None -- but the DEEP iter_operand_exprs walk still surfaces
    # the Sub on operand_expr_fragments (the contract folded_loop_guard relies on).
    sub = _subinsn(InsnKind.SUB, _stk(0x1E0), _num(0x64))
    nested = _subinsn(InsnKind.UNKNOWN, sub, _num(0xFF))
    insn = _jcc(PredicateKind.SGE, nested, _num(0))

    instruction = project_instruction(insn)

    # The shallow slot is None: _value_of can't lift the non-binop wrapper.
    assert instruction.input_exprs[0] is None
    # The DEEP fragments DO contain the buried (i - #0x64) Sub.
    buried_sub = Sub(
        left=Move(source=DefinitionRef(location=StackSlot(offset=0x1E0, size=4))),
        right=Const(value=0x64),
    )
    assert buried_sub in instruction.operand_expr_fragments
    # No fragment is ever None; the walk is the concat of both operand walks
    # (slot0 fragments ++ slot1 fragments == iter_operand_exprs(l) ++ (r-const)).
    assert None not in instruction.operand_expr_fragments
    assert instruction.operand_expr_fragments == (
        iter_operand_exprs(nested) + (Const(value=0),)
    )


def test_attrs_preserve_snapshot_kind_distinguishing_branch_kinds():
    # EQUALITY_JUMP (m_jnz/m_jz) and COND_JUMP (m_jcnd) both project to the
    # same operation enum (ControlTransferKind.CONDITIONAL_BRANCH), so the
    # distinguishing portable InsnKind must survive in provenance attrs
    # (llr-0s2n: loop_bound_writer_guard gates its loop-test on EQUALITY_JUMP).
    equality = InsnSnapshot(
        opcode=-1, ea=0x2000, operands=(), kind=InsnKind.EQUALITY_JUMP,
        l=_stk(0x10), r=_stk(0x20),
    )
    cond = InsnSnapshot(
        opcode=-1, ea=0x2004, operands=(), kind=InsnKind.COND_JUMP,
        l=_stk(0x10), r=_stk(0x20),
    )

    eq_instr = project_instruction(equality)
    cond_instr = project_instruction(cond)

    assert eq_instr.operation is ControlTransferKind.CONDITIONAL_BRANCH
    assert cond_instr.operation is ControlTransferKind.CONDITIONAL_BRANCH
    # Same operation, but the snapshot_kind attr keeps them distinguishable.
    assert eq_instr.attrs.get("snapshot_kind") == InsnKind.EQUALITY_JUMP.value
    assert cond_instr.attrs.get("snapshot_kind") == InsnKind.COND_JUMP.value


def test_attrs_omit_snapshot_kind_for_unknown_insn_kind():
    # An UNKNOWN-kind snapshot carries no snapshot_kind attr (additive only).
    insn = InsnSnapshot(opcode=0x12, ea=0x1000, operands=(), kind=InsnKind.UNKNOWN)
    instruction = project_instruction(insn)
    assert "snapshot_kind" not in instruction.attrs
