"""Exact portable classification of lowered branch-predicate expressions."""

from __future__ import annotations

from collections.abc import Sequence

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import PredicateKind


def _one_byte_register(operand: MopSnapshot | None) -> int | None:
    if (
        operand is None
        or operand.kind is not OperandKind.REGISTER
        or int(operand.size) != 1
        or operand.reg is None
    ):
        return None
    return int(operand.reg)


def _exact_flag_result_register(
    instructions: Sequence[InsnSnapshot],
    *,
    condition_producer_ea: int,
    value_kind: ValueOpKind,
) -> int | None:
    producers = tuple(
        instruction
        for instruction in instructions
        if int(instruction.ea) == int(condition_producer_ea)
        and instruction.value_op_kind is value_kind
    )
    if len(producers) != 1:
        return None
    return _one_byte_register(producers[0].d)


def _exact_signed_flag_xor(
    expression: MopSnapshot | None,
    *,
    sign_register: int,
    overflow_register: int,
) -> bool:
    if (
        expression is None
        or expression.kind is not OperandKind.SUBINSN
        or int(expression.size) != 1
        or expression.sub_value_op_kind is not ValueOpKind.XOR
    ):
        return False
    left_register = _one_byte_register(expression.sub_l)
    right_register = _one_byte_register(expression.sub_r)
    return (
        left_register is not None
        and right_register is not None
        and left_register != right_register
        and {left_register, right_register}
        == {int(sign_register), int(overflow_register)}
    )


def exact_branch_predicate_kind(
    instructions: Sequence[InsnSnapshot],
    *,
    condition_producer_ea: int,
) -> PredicateKind | None:
    """Resolve one branch predicate only from exact portable expression shape.

    Direct comparison branches retain their lifted predicate.  A truthiness
    branch is accepted only for the exact one-byte ``SF xor OF`` expression
    whose input registers are the unique sign/overflow results emitted at the
    declared condition producer.  A logical-not wrapper is the exact
    complement, ``SGE``.
    """

    if not instructions:
        return None
    branch = instructions[-1]
    predicate = branch.predicate_kind
    if predicate is not PredicateKind.TRUTHY:
        return predicate
    if not branch.is_conditional_jump:
        return None

    sign_register = _exact_flag_result_register(
        instructions,
        condition_producer_ea=condition_producer_ea,
        value_kind=ValueOpKind.SIGN_BIT,
    )
    overflow_register = _exact_flag_result_register(
        instructions,
        condition_producer_ea=condition_producer_ea,
        value_kind=ValueOpKind.OVERFLOW_FLAG,
    )
    if (
        sign_register is None
        or overflow_register is None
        or sign_register == overflow_register
    ):
        return None

    expression = branch.l
    if _exact_signed_flag_xor(
        expression,
        sign_register=sign_register,
        overflow_register=overflow_register,
    ):
        return PredicateKind.SLT
    if (
        expression is not None
        and expression.kind is OperandKind.SUBINSN
        and int(expression.size) == 1
        and expression.sub_value_op_kind is ValueOpKind.LNOT
        and expression.sub_r is None
        and _exact_signed_flag_xor(
            expression.sub_l,
            sign_register=sign_register,
            overflow_register=overflow_register,
        )
    ):
        return PredicateKind.SGE
    return None
