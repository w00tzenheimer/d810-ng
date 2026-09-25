"""Canonical state-write evaluator tests."""

from __future__ import annotations

import pytest

from d810.analyses.value_flow.state_write import (
    _forward_eval_instruction_sequence,
    forward_eval_insn,
    forward_eval_instruction,
    get_mop_const_value,
    resolve_mop_from_maps,
    resolve_varnode_from_maps,
)
from d810.backends.hexrays.evidence.condition_chain_analysis import (
    build_condition_chain_walker_provider,
)
from d810.backends.hexrays.evidence import condition_chain_analysis
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


@pytest.mark.parametrize(
    ("operation", "left", "count", "expected"),
    (
        (ValueOpKind.SHL, 0x80000001, 0, 0x80000001),
        (ValueOpKind.SHL, 1, 31, 0x80000000),
        (ValueOpKind.SHL, 0x12345678, 32, 0x12345678),
        (ValueOpKind.SHL, 0x12345678, 33, 0x2468ACF0),
        (ValueOpKind.SHR, 0x80000001, 0, 0x80000001),
        (ValueOpKind.SHR, 0x80000001, 31, 1),
        (ValueOpKind.SHR, 0x92345678, 32, 0x92345678),
        (ValueOpKind.SHR, 0x80000001, 33, 0x40000000),
        (ValueOpKind.SAR, 0x80000001, 0, 0x80000001),
        (ValueOpKind.SAR, 0x80000001, 31, 0xFFFFFFFF),
        (ValueOpKind.SAR, 0x92345678, 32, 0x92345678),
        (ValueOpKind.SAR, 0x92345678, 33, 0xC91A2B3C),
    ),
)
def test_canonical_u32_shifts_use_modulo_width_counts(
    operation: ValueOpKind,
    left: int,
    count: int,
    expected: int,
) -> None:
    stk: dict[int, int] = {}
    instruction = Instruction(
        operation,
        inputs=(_const(left), _const(count, size=1)),
        result=_stack(_STATE_STKOFF),
    )

    result = forward_eval_instruction(instruction, stk, {}, _STATE_STKOFF)

    assert result == expected
    assert stk[_STATE_STKOFF] == expected


@pytest.mark.parametrize(
    ("operation", "count", "expected"),
    (
        (ValueOpKind.ROL, 0, 0x0123456789ABCDEF),
        (ValueOpKind.ROL, 8, 0x23456789ABCDEF01),
        (ValueOpKind.ROL, 64, 0x0123456789ABCDEF),
        (ValueOpKind.ROL, 65, 0x02468ACF13579BDE),
        (ValueOpKind.ROR, 8, 0xEF0123456789ABCD),
        (ValueOpKind.ROR, 63, 0x02468ACF13579BDE),
    ),
)
def test_canonical_u64_rotates_use_the_result_width(
    operation: ValueOpKind,
    count: int,
    expected: int,
) -> None:
    stk: dict[int, int] = {}
    instruction = Instruction(
        operation,
        inputs=(_const(0x0123456789ABCDEF, size=8), _const(count, size=1)),
        result=_stack(_STATE_STKOFF, size=8),
    )

    result = forward_eval_instruction(instruction, stk, {}, _STATE_STKOFF)

    assert result == expected
    assert stk[_STATE_STKOFF] == expected


def test_registered_backend_provider_accepts_canonical_instruction() -> None:
    stk: dict[int, int] = {}
    reg = {1: 0xAA00AA00}
    instruction = Instruction(
        ValueOpKind.XOR,
        inputs=(_reg(1), _const(0x00FF00FF)),
        result=_stack(_STATE_STKOFF),
    )

    result = build_condition_chain_walker_provider().forward_eval_insn(
        instruction,
        stk,
        reg,
        _STATE_STKOFF,
    )

    assert result == 0xAAFFAAFF
    assert stk[_STATE_STKOFF] == 0xAAFFAAFF


def test_registered_backend_provider_propagates_runtime_error(monkeypatch) -> None:
    instruction = Instruction(
        ValueOpKind.MOVE,
        inputs=(_const(1),),
        result=_stack(_STATE_STKOFF),
    )

    def fail_provider(*_args, **_kwargs):
        raise RuntimeError("portable evaluator failed")

    monkeypatch.setattr(
        condition_chain_analysis.state_write,
        "forward_eval_insn",
        fail_provider,
    )

    with pytest.raises(RuntimeError, match="portable evaluator failed"):
        build_condition_chain_walker_provider().forward_eval_insn(
            instruction,
            {},
            {},
            _STATE_STKOFF,
        )


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


def test_public_forward_eval_uses_projected_u64_rotate_subinstruction() -> None:
    stk: dict[int, int] = {}
    nested = MopSnapshot(
        size=8,
        kind=OperandKind.SUBINSN,
        sub_value_op_kind=ValueOpKind.ROR,
        sub_l=_num_mop(0x0123456789ABCDEF, size=8),
        sub_r=_num_mop(8, size=1),
    )
    snapshot = InsnSnapshot(
        opcode=0,
        ea=0x180012348,
        operands=(),
        kind=InsnKind.MOV,
        l=nested,
        d=_stk_mop(_STATE_STKOFF, size=8),
    )

    result = forward_eval_insn(snapshot, stk, {}, _STATE_STKOFF)

    assert result == 0xEF0123456789ABCD
    assert stk[_STATE_STKOFF] == 0xEF0123456789ABCD


def test_projected_rotate_temp_does_not_alias_source_register_zero() -> None:
    stk: dict[int, int] = {}
    reg = {0: 0x0123456789ABCDEF}
    nested = MopSnapshot(
        size=8,
        kind=OperandKind.SUBINSN,
        sub_value_op_kind=ValueOpKind.ROR,
        sub_l=_reg_mop(0, size=8),
        sub_r=_num_mop(8, size=1),
    )
    snapshot = InsnSnapshot(
        opcode=0,
        ea=0x18001234C,
        operands=(),
        kind=InsnKind.MOV,
        l=nested,
        d=_stk_mop(_STATE_STKOFF, size=8),
    )

    result = forward_eval_insn(snapshot, stk, reg, _STATE_STKOFF)

    assert result == 0xEF0123456789ABCD
    assert stk[_STATE_STKOFF] == 0xEF0123456789ABCD


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


def test_indirect_store_invalidates_stack_facts_instead_of_writing_pointer_slot() -> None:
    pointer_slot = 0x70
    stk = {_STATE_STKOFF: 0x12345678, pointer_slot: 0x4000}
    reg = {32: 0xCAFEBABE}
    instruction = Instruction(
        ValueOpKind.STORE,
        inputs=(_const(0x5A, size=1), _reg(256, size=2), _stack(pointer_slot, size=8)),
        memory=InstructionMemoryAccess(
            InstructionMemoryAccessKind.INDIRECT,
            target=_stack(pointer_slot, size=8),
            segment=_reg(256, size=2),
            value=_const(0x5A, size=1),
            width=1,
        ),
    )

    result = forward_eval_instruction(instruction, stk, reg, _STATE_STKOFF)

    assert result is None
    assert stk == {}
    assert reg == {32: 0xCAFEBABE}


def test_lifted_indirect_store_invalidates_state_fact() -> None:
    pointer_slot = 0x70
    stk = {_STATE_STKOFF: 0x12345678, pointer_slot: 0x4000}
    snapshot = InsnSnapshot(
        opcode=0,
        ea=0x7FFF99AD0E97,
        operands=(),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
        l=_num_mop(0x5A, size=1),
        r=_reg_mop(256, size=2),
        d=_stk_mop(pointer_slot, size=8),
    )

    result = forward_eval_insn(snapshot, stk, {}, _STATE_STKOFF)

    assert result is None
    assert stk == {}


def test_lifted_store_without_segment_still_writes_through_address() -> None:
    pointer_slot = 0x70
    stk = {_STATE_STKOFF: 0x12345678, pointer_slot: 0x4000}
    snapshot = InsnSnapshot(
        opcode=0,
        ea=0x7FFF99AD0E97,
        operands=(),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
        l=_num_mop(0x5A, size=1),
        d=_stk_mop(pointer_slot, size=8),
    )

    result = forward_eval_insn(snapshot, stk, {}, _STATE_STKOFF)

    assert result is None
    assert stk == {}


def test_unknown_store_target_invalidates_stack_facts() -> None:
    stk = {_STATE_STKOFF: 0x12345678}
    instruction = Instruction(
        ValueOpKind.STORE,
        inputs=(_const(0x5A, size=1),),
        memory=InstructionMemoryAccess(
            InstructionMemoryAccessKind.UNKNOWN,
            target=None,
            value=_const(0x5A, size=1),
            width=1,
        ),
    )

    result = forward_eval_instruction(instruction, stk, {}, _STATE_STKOFF)

    assert result is None
    assert stk == {}


def test_store_without_memory_access_metadata_invalidates_stack_facts() -> None:
    stk = {_STATE_STKOFF: 0x12345678}
    instruction = Instruction(
        ValueOpKind.STORE,
        inputs=(_const(0x5A, size=1),),
        result=_stack(0x70, size=8),
    )

    result = forward_eval_instruction(instruction, stk, {}, _STATE_STKOFF)

    assert result is None
    assert stk == {}


def test_sequence_forgets_state_result_after_unknown_alias_store() -> None:
    stk: dict[int, int] = {}
    reg: dict[int, int] = {}
    sequence = (
        Instruction(
            ValueOpKind.MOVE,
            inputs=(_const(0x12345678),),
            result=_stack(_STATE_STKOFF),
        ),
        Instruction(
            ValueOpKind.STORE,
            inputs=(_const(0x5A, size=1),),
            memory=InstructionMemoryAccess(
                InstructionMemoryAccessKind.INDIRECT,
                target=_reg(16, size=8),
                value=_const(0x5A, size=1),
                width=1,
            ),
        ),
    )

    result = _forward_eval_instruction_sequence(sequence, stk, reg, _STATE_STKOFF)

    assert result is None
    assert _STATE_STKOFF not in stk


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
