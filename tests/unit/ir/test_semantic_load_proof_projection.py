"""A load-address proof must not lose a predecessor write or source."""

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.insn_projection import InstructionProjection
from d810.ir.varnode import Space, Varnode


def _block(insn: InsnSnapshot) -> BlockSnapshot:
    return BlockSnapshot(
        serial=1,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x1000,
        insn_snapshots=(insn,),
    )


def test_unknown_opcode_write_keeps_destination_visible_to_reaching_proof() -> None:
    insn = InsnSnapshot(
        opcode=123,
        ea=0x1000,
        operands=(),
        kind=InsnKind.UNKNOWN,
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=96, size=8),
    )
    projected = InstructionProjection.from_block_for_semantic_load_proof(_block(insn))
    assert projected[-1].result == Varnode(Space.REGISTER, 96, 8)
    assert projected[-1].operation is ValueOpKind.VENDOR
    assert projected[-1].attrs["unprojected_write"] is True


def test_unknown_source_is_marked_even_for_a_known_move() -> None:
    insn = InsnSnapshot(
        opcode=4,
        ea=0x1000,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.UNKNOWN, size=8),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=96, size=8),
    )
    projected = InstructionProjection.from_block_for_semantic_load_proof(_block(insn))
    assert projected[-1].attrs["unprojected_source"] is True


def test_known_move_remains_usable_for_reaching_proof() -> None:
    insn = InsnSnapshot(
        opcode=4,
        ea=0x1000,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, reg=64, size=8),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=96, size=8),
    )
    projected = InstructionProjection.from_block_for_semantic_load_proof(_block(insn))
    assert projected[-1].result == Varnode(Space.REGISTER, 96, 8)
    assert projected[-1].operation is ValueOpKind.MOVE
    assert "unprojected_write" not in projected[-1].attrs
    assert "unprojected_source" not in projected[-1].attrs
