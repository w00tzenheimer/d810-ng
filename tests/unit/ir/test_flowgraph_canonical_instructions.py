"""Canonical instruction-stream projection tests (InstructionProjection).

``BlockSnapshot.insn_snapshots`` is lift provenance; the portable ``Instruction``
stream is an explicit *projection* of it, produced by
:class:`d810.ir.insn_projection.InstructionProjection` rather than exposed as a
block attribute.  That keeps ``flowgraph`` a leaf the projection layer consumes.
"""
from __future__ import annotations

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.insn_projection import InstructionProjection
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.varnode import Space, Varnode


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _reg(register_id: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _block(
    serial: int,
    *insns: InsnSnapshot,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=tuple(insns),
    )


def test_projection_from_block_exposes_canonical_instruction_stream():
    insn = InsnSnapshot(
        opcode=0x4,
        ea=0x401000,
        operands=(),
        kind=InsnKind.MOV,
        l=_num(0x41),
        d=_stk(0x30),
    )
    block = _block(3, insn)

    stream = InstructionProjection.from_block(block)

    assert len(stream) == 1
    instruction = stream[0]
    assert instruction.operation is ValueOpKind.MOVE
    assert instruction.inputs == (Varnode(Space.CONST, 0x41, 4),)
    assert instruction.result == Varnode(Space.STACK, 0x30, 4)
    assert instruction.attrs["ea"] == 0x401000


def test_projection_from_block_lowers_nested_subinsns_first():
    nested = MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.AND,
        sub_l=_stk(0x20),
        sub_r=_num(0xFF),
    )
    branch = InsnSnapshot(
        opcode=0x2C,
        ea=0x401004,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        l=nested,
        r=_num(0),
    )
    block = _block(4, branch)

    stream = InstructionProjection.from_block(block)

    assert len(stream) == 2
    and_temp, branch_instruction = stream
    assert and_temp.operation is ValueOpKind.AND
    assert and_temp.inputs == (
        Varnode(Space.STACK, 0x20, 4),
        Varnode(Space.CONST, 0xFF, 4),
    )
    assert and_temp.result == Varnode(Space.TEMP, 0, 4)
    assert branch_instruction.operation is ControlTransferKind.CONDITIONAL_BRANCH
    assert branch_instruction.inputs == (
        Varnode(Space.TEMP, 0, 4),
        Varnode(Space.CONST, 0, 4),
    )


def test_projection_from_block_preserves_opaque_nested_stack_refs():
    nested = MopSnapshot(
        kind=OperandKind.SUBINSN,
        stack_refs=(0x44,),
        size=4,
    )
    branch = InsnSnapshot(
        opcode=0x2C,
        ea=0x401008,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        l=nested,
        r=_num(0x10000001),
    )
    block = _block(5, branch)

    stream = InstructionProjection.from_block(block)

    assert len(stream) == 2
    vendor_temp, branch_instruction = stream
    assert vendor_temp.operation is ValueOpKind.VENDOR
    assert vendor_temp.inputs == (Varnode(Space.STACK, 0x44, 4),)
    assert vendor_temp.result == Varnode(Space.TEMP, 0, 4)
    assert branch_instruction.inputs == (
        Varnode(Space.TEMP, 0, 4),
        Varnode(Space.CONST, 0x10000001, 4),
    )


def test_projection_from_flowgraph_streams_each_block():
    entry = _block(
        1,
        InsnSnapshot(
            opcode=0x4,
            ea=0x401000,
            operands=(),
            kind=InsnKind.MOV,
            l=_reg(0),
            d=_stk(0x18),
        ),
        succs=(2,),
    )
    exit_block = _block(
        2,
        InsnSnapshot(
            opcode=0x42,
            ea=0x401010,
            operands=(),
            kind=InsnKind.RET,
            l=_reg(0),
        ),
        preds=(1,),
    )
    graph = FlowGraph(blocks={1: entry, 2: exit_block}, entry_serial=1, func_ea=0x401000)

    by_block = InstructionProjection.from_flowgraph(graph)

    assert tuple(by_block) == (1, 2)
    assert by_block[1][0].operation is ValueOpKind.MOVE
    assert by_block[2][0].operation is ControlTransferKind.RETURN
    assert [
        (serial, instruction.operation)
        for serial, stream in by_block.items()
        for instruction in stream
    ] == [
        (1, ValueOpKind.MOVE),
        (2, ControlTransferKind.RETURN),
    ]
