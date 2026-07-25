"""Tests for backend-neutral instruction semantic helpers."""

from __future__ import annotations

from types import SimpleNamespace

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    PredicateKind,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.instructions import Instruction, InstructionControl
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.ir.varnode import Space, Varnode
from d810.analyses.control_flow.instruction_semantics import (
    branch_predicate,
    comparison_width,
    evaluate_branch_predicate,
    is_branch,
    split_const_storage_identity_from_branch,
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


def test_comparison_width_does_not_read_raw_operand_slots() -> None:
    class RawSlotTrap:
        compare_width = None

        @property
        def l(self):  # pragma: no cover - test fails if accessed
            raise AssertionError("comparison_width read raw .l")

        @property
        def r(self):  # pragma: no cover - test fails if accessed
            raise AssertionError("comparison_width read raw .r")

    assert comparison_width(RawSlotTrap()) is None


def test_canonical_instruction_branch_semantics() -> None:
    instruction = Instruction(
        operation=ControlTransferKind.CONDITIONAL_BRANCH,
        inputs=(
            Varnode(Space.REGISTER, 1, 8),
            Varnode(Space.CONST, 0x42, 4),
        ),
        control=InstructionControl(
            transfer=ControlTransferKind.CONDITIONAL_BRANCH,
            predicate=PredicateKind.NE,
            target=12,
        ),
    )

    assert is_branch(instruction) is True
    assert branch_predicate(instruction) is PredicateKind.NE
    assert comparison_width(instruction) == 8


def test_canonical_branch_identity_resolves_through_temp_producer() -> None:
    temp_source = Instruction(
        operation=ValueOpKind.VENDOR,
        inputs=(Varnode(Space.STACK, 0x44, 4),),
        result=Varnode(Space.TEMP, 0, 4),
    )
    branch = Instruction(
        operation=ControlTransferKind.CONDITIONAL_BRANCH,
        inputs=(
            Varnode(Space.TEMP, 0, 4),
            Varnode(Space.CONST, 0x10000001, 4),
        ),
        control=InstructionControl(
            transfer=ControlTransferKind.CONDITIONAL_BRANCH,
            predicate=PredicateKind.NE,
            target=12,
        ),
    )

    const, identity = split_const_storage_identity_from_branch(
        (temp_source, branch),
        1,
        min_const=0x100,
    )

    assert const == 0x10000001
    assert identity == StorageIdentity(StorageIdentityKind.STACK, 0x44)


def test_signed_branch_predicate_respects_64_bit_compare_width() -> None:
    left = 0xFFFFFFFF00000000
    right = 0

    assert (
        evaluate_branch_predicate(
            PredicateKind.SLT,
            left,
            right,
            compare_width=8,
        )
        is True
    )
    assert (
        evaluate_branch_predicate(
            PredicateKind.SLT,
            left,
            right,
            compare_width=4,
        )
        is False
    )


def test_equality_predicates_respect_compare_width_mask() -> None:
    assert (
        evaluate_branch_predicate(
            PredicateKind.EQ,
            0x1_0000_0000,
            0,
            compare_width=4,
        )
        is True
    )
    assert (
        evaluate_branch_predicate(
            PredicateKind.NE,
            0x1_0000_0000,
            0,
            compare_width=4,
        )
        is False
    )
    assert (
        evaluate_branch_predicate(
            PredicateKind.EQ,
            0x1_0000_0000,
            0,
            compare_width=None,
        )
        is False
    )


def test_ordering_predicate_without_width_is_not_proven() -> None:
    assert (
        evaluate_branch_predicate(
            PredicateKind.SLT,
            0xFFFFFFFF00000000,
            0,
            compare_width=None,
        )
        is None
    )
