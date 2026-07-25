"""Canonical state-write evaluator tests."""

from __future__ import annotations

from d810.analyses.value_flow.state_write import (
    forward_eval_insn,
    forward_eval_instruction,
    get_mop_const_value,
    resolve_mop_from_maps,
    resolve_varnode_from_maps,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.instructions import (
    Instruction,
    InstructionMemoryAccess,
    InstructionMemoryAccessKind,
)
from d810.ir.varnode import Space, Varnode

_STATE_STKOFF = 0x64


def _const(value: int, *, size: int = 4) -> Varnode:
    return Varnode(Space.CONST, value, size)


def _stack(offset: int, *, size: int = 4) -> Varnode:
    return Varnode(Space.STACK, offset, size)


def _reg(register_id: int, *, size: int = 4) -> Varnode:
    return Varnode(Space.REGISTER, register_id, size)


def _global(address: int, *, size: int = 4) -> Varnode:
    return Varnode(Space.GLOBAL, address, size)


def _num_mop(value: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(size=size, value=value, kind=OperandKind.NUMBER)


def _stk_mop(offset: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(size=size, stkoff=offset, kind=OperandKind.STACK)


def _reg_mop(register_id: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(size=size, reg=register_id, kind=OperandKind.REGISTER)


def test_canonical_move_const_to_state_stack_slot() -> None:
    stk: dict[int, int] = {}
    reg: dict[int, int] = {}
    instruction = Instruction(
        ValueOpKind.MOVE,
        inputs=(_const(0x5A21D9DB),),
        result=_stack(_STATE_STKOFF),
        attrs={"ea": 0x180014155},
    )

    result = forward_eval_instruction(instruction, stk, reg, _STATE_STKOFF)

    assert result == 0x5A21D9DB
    assert stk[_STATE_STKOFF] == 0x5A21D9DB
    assert reg == {}


def test_public_forward_eval_accepts_canonical_instruction_without_seams() -> None:
    stk: dict[int, int] = {}
    reg = {1: 0xAA00AA00}
    instruction = Instruction(
        ValueOpKind.XOR,
        inputs=(_reg(1), _const(0x00FF00FF)),
        result=_stack(_STATE_STKOFF),
    )

    result = forward_eval_insn(instruction, stk, reg, _STATE_STKOFF)

    assert result == 0xAAFFAAFF
    assert stk[_STATE_STKOFF] == 0xAAFFAAFF


def test_public_forward_eval_accepts_lifted_instruction_snapshot_without_seams() -> (
    None
):
    stk: dict[int, int] = {}
    reg = {1: 0xAA00AA00}
    snapshot = InsnSnapshot(
        opcode=0,
        ea=0x180012340,
        operands=(),
        kind=InsnKind.UNKNOWN,
        value_op_kind=ValueOpKind.XOR,
        l=_reg_mop(1),
        r=_num_mop(0x00FF00FF),
        d=_stk_mop(_STATE_STKOFF),
    )

    result = forward_eval_insn(snapshot, stk, reg, _STATE_STKOFF)

    assert result == 0xAAFFAAFF
    assert stk[_STATE_STKOFF] == 0xAAFFAAFF


def test_public_forward_eval_uses_projected_subinstruction_sequence() -> None:
    stk: dict[int, int] = {}
    reg = {1: 0x92738C89}
    nested = MopSnapshot(
        size=4,
        kind=OperandKind.SUBINSN,
        sub_value_op_kind=ValueOpKind.XOR,
        sub_l=_reg_mop(1),
        sub_r=_num_mop(0xBB63718C),
    )
    snapshot = InsnSnapshot(
        opcode=0,
        ea=0x180012344,
        operands=(),
        kind=InsnKind.MOV,
        l=nested,
        d=_stk_mop(_STATE_STKOFF),
    )

    result = forward_eval_insn(snapshot, stk, reg, _STATE_STKOFF)

    assert result == 0x2910FD05
    assert stk[_STATE_STKOFF] == 0x2910FD05


def test_canonical_store_to_global_state_cell() -> None:
    global_state = 0x180020000
    stk: dict[int, int] = {}
    reg: dict[int, int] = {}
    instruction = Instruction(
        ValueOpKind.STORE,
        inputs=(_const(0x12345678), _global(global_state)),
        memory=InstructionMemoryAccess(
            InstructionMemoryAccessKind.DIRECT_CELL,
            target=_global(global_state),
            value=_const(0x12345678),
            width=4,
        ),
    )

    result = forward_eval_instruction(
        instruction,
        stk,
        reg,
        _STATE_STKOFF,
        state_var_gaddr=global_state,
    )

    assert result == 0x12345678
    assert stk[global_state] == 0x12345678


def test_canonical_global_read_can_use_reaching_initializer() -> None:
    global_cell = 0x180030000
    stk: dict[int, int] = {}
    reg: dict[int, int] = {}
    instruction = Instruction(
        ValueOpKind.MOVE,
        inputs=(_global(global_cell),),
        result=_stack(_STATE_STKOFF),
        attrs={"ea": 0x180010000},
    )

    result = forward_eval_instruction(
        instruction,
        stk,
        reg,
        _STATE_STKOFF,
        foldable_global_reads={0x180010000: {global_cell: 0xCAFEBABE}},
    )

    assert result == 0xCAFEBABE
    assert stk[_STATE_STKOFF] == 0xCAFEBABE


def test_resolve_varnode_does_not_require_hexrays_mop_type_names() -> None:
    assert resolve_varnode_from_maps(_const(7), {}, {}) == 7
    assert resolve_varnode_from_maps(_stack(0x40), {0x40: 9}, {}) == 9
    assert resolve_varnode_from_maps(_reg(2), {}, {2: 11}) == 11


class _NoRawOperandTypeConst:
    kind = OperandKind.NUMBER
    size = 4
    value = 0x44
    reg = None
    stkoff = None
    gaddr = None
    lvar_off = None

    @property
    def t(self):  # pragma: no cover - reached only on regression
        raise AssertionError("raw operand type should not be read")


def test_operand_resolution_uses_lifted_identity_not_raw_type_fields() -> None:
    operand = _NoRawOperandTypeConst()

    assert get_mop_const_value(operand) == 0x44
    assert resolve_mop_from_maps(operand, {}, {}) == 0x44
