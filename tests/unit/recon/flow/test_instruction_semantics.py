"""Tests for backend-neutral instruction semantic helpers."""
from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import (
    BranchPredicate,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow.instruction_semantics import (
    comparison_width,
    evaluate_branch_predicate,
    is_branch,
)


def _reg(reg: int, size: int) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, reg=reg, kind=OperandKind.REGISTER)


def test_is_branch_honors_conditional_kinds_without_predicate_flags() -> None:
    assert is_branch(SimpleNamespace(kind=InsnKind.COND_JUMP)) is True
    assert is_branch(SimpleNamespace(kind=InsnKind.EQUALITY_JUMP)) is True
    assert is_branch(SimpleNamespace(kind="cond_jump")) is True
    assert is_branch(SimpleNamespace(kind="equality_jump")) is True


def test_insn_snapshot_derives_branch_flag_and_compare_width() -> None:
    insn = InsnSnapshot(
        opcode=999,
        ea=0x1000,
        operands=(),
        l=_reg(1, 8),
        r=_reg(2, 4),
        kind=InsnKind.COND_JUMP,
    )

    assert insn.is_conditional_jump is True
    assert insn.compare_width == 8
    assert comparison_width(insn) == 8


def test_signed_branch_predicate_respects_64_bit_compare_width() -> None:
    left = 0xFFFFFFFF00000000
    right = 0

    assert (
        evaluate_branch_predicate(
            BranchPredicate.SIGNED_LT,
            left,
            right,
            compare_width=8,
        )
        is True
    )
    assert (
        evaluate_branch_predicate(
            BranchPredicate.SIGNED_LT,
            left,
            right,
            compare_width=4,
        )
        is False
    )


def test_equality_predicates_respect_compare_width_mask() -> None:
    assert (
        evaluate_branch_predicate(
            BranchPredicate.EQUAL,
            0x1_0000_0000,
            0,
            compare_width=4,
        )
        is True
    )
    assert (
        evaluate_branch_predicate(
            BranchPredicate.NOT_EQUAL,
            0x1_0000_0000,
            0,
            compare_width=4,
        )
        is False
    )
    assert (
        evaluate_branch_predicate(
            BranchPredicate.EQUAL,
            0x1_0000_0000,
            0,
            compare_width=None,
        )
        is False
    )


def test_ordering_predicate_without_width_is_not_proven() -> None:
    assert (
        evaluate_branch_predicate(
            BranchPredicate.SIGNED_LT,
            0xFFFFFFFF00000000,
            0,
            compare_width=None,
        )
        is None
    )
