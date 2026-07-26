from __future__ import annotations

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.predicate_expressions import exact_branch_predicate_kind
from d810.ir.semantics import PredicateKind


def _reg(number: int) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=number, size=1)


def _value(
    *,
    ea: int,
    operation: ValueOpKind,
    left: MopSnapshot,
    destination: MopSnapshot,
    right: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=1,
        ea=ea,
        operands=(),
        l=left,
        r=right,
        d=destination,
        value_op_kind=operation,
    )


def test_exact_branch_predicate_accepts_sequential_signed_flag_complement() -> None:
    sign = _reg(2)
    overflow = _reg(3)
    temporary = _reg(4)

    assert exact_branch_predicate_kind(
        (
            _value(
                ea=0x40A5F0,
                operation=ValueOpKind.OVERFLOW_FLAG,
                left=_reg(10),
                right=_reg(11),
                destination=overflow,
            ),
            _value(
                ea=0x40A5F0,
                operation=ValueOpKind.SIGN_BIT,
                left=_reg(10),
                destination=sign,
            ),
            _value(
                ea=0x40A5FE,
                operation=ValueOpKind.XOR,
                left=sign,
                right=overflow,
                destination=temporary,
            ),
            _value(
                ea=0x40A5FE,
                operation=ValueOpKind.LNOT,
                left=temporary,
                destination=temporary,
            ),
            InsnSnapshot(
                opcode=2,
                ea=0x40A5FE,
                operands=(),
                l=temporary,
                predicate_kind=PredicateKind.TRUTHY,
                branch_predicate=PredicateKind.TRUTHY,
                is_conditional_jump=True,
            ),
        ),
        condition_producer_ea=0x40A5F0,
    ) is PredicateKind.SGE


def test_exact_branch_predicate_rejects_sequential_mismatched_flag_register() -> None:
    sign = _reg(2)
    overflow = _reg(3)
    temporary = _reg(4)

    assert exact_branch_predicate_kind(
        (
            _value(
                ea=0x40A5F0,
                operation=ValueOpKind.OVERFLOW_FLAG,
                left=_reg(10),
                right=_reg(11),
                destination=overflow,
            ),
            _value(
                ea=0x40A5F0,
                operation=ValueOpKind.SIGN_BIT,
                left=_reg(10),
                destination=sign,
            ),
            _value(
                ea=0x40A5FE,
                operation=ValueOpKind.XOR,
                left=sign,
                right=_reg(99),
                destination=temporary,
            ),
            _value(
                ea=0x40A5FE,
                operation=ValueOpKind.LNOT,
                left=temporary,
                destination=temporary,
            ),
            InsnSnapshot(
                opcode=2,
                ea=0x40A5FE,
                operands=(),
                l=temporary,
                predicate_kind=PredicateKind.TRUTHY,
                branch_predicate=PredicateKind.TRUTHY,
                is_conditional_jump=True,
            ),
        ),
        condition_producer_ea=0x40A5F0,
    ) is None
