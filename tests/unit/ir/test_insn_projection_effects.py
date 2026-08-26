"""Effect classification for canonical nested value operations."""

from __future__ import annotations

import pytest

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnKind, MopSnapshot, OperandKind
from d810.ir.insn_projection import is_effect_free_operand_tree


def _num(value: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _reg(register_id: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _binary_subinstruction(operation: ValueOpKind) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        size=4,
        sub_kind=InsnKind.UNKNOWN,
        sub_value_op_kind=operation,
        sub_l=_reg(8),
        sub_r=_num(3, size=1),
    )


@pytest.mark.parametrize(
    "operation",
    (ValueOpKind.SHL, ValueOpKind.SHR, ValueOpKind.SAR),
)
def test_effect_free_operand_tree_accepts_supported_shift_subinstructions(
    operation: ValueOpKind,
) -> None:
    assert is_effect_free_operand_tree(_binary_subinstruction(operation))


@pytest.mark.parametrize("operation", (ValueOpKind.ROL, ValueOpKind.ROR))
def test_effect_free_operand_tree_accepts_pure_rotate_subinstructions(
    operation: ValueOpKind,
) -> None:
    assert is_effect_free_operand_tree(_binary_subinstruction(operation))
