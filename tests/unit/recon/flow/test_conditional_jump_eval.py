from __future__ import annotations

from d810.analyses.control_flow.conditional_jump_eval import (
    conditional_jump_opcode_name,
    conditional_jump_outcome_for_predicate,
    conditional_jump_outcome_for_values,
    conditional_jump_taken,
    predicate_jump_taken,
)
from d810.ir.flowgraph import PredicateKind


def test_normalizes_string_and_numeric_jump_opcodes() -> None:
    assert conditional_jump_opcode_name("jz") == "jz"
    assert conditional_jump_opcode_name("op_49") == "jg"
    assert conditional_jump_opcode_name(50) == "jge"
    assert conditional_jump_opcode_name(9001) is None


def test_evaluates_unsigned_jump_conditions() -> None:
    assert conditional_jump_taken("jae", 0xFFFFFFFF, 1, operand_size=4) is True
    assert conditional_jump_taken("jb", 0, 1, operand_size=4) is True
    assert conditional_jump_taken("ja", 7, 7, operand_size=4) is False
    assert conditional_jump_taken("jbe", 7, 7, operand_size=4) is True


def test_evaluates_signed_jump_conditions() -> None:
    assert conditional_jump_taken("jl", 0xFFFFFFFF, 0, operand_size=4) is True
    assert conditional_jump_taken("jg", 0xFFFFFFFF, 0, operand_size=4) is False
    assert conditional_jump_taken("jge", 0x80000000, 0, operand_size=4) is False
    assert conditional_jump_taken("jle", 0x80000000, 0, operand_size=4) is True


def test_classifies_path_constant_outcomes() -> None:
    always_taken = conditional_jump_outcome_for_values(
        "jae",
        [9, 10, 11],
        9,
        operand_size=4,
    )
    assert always_taken is not None
    assert always_taken.always_taken is True
    assert always_taken.always_not_taken is False

    always_not_taken = conditional_jump_outcome_for_values(
        "jl",
        [0, 1, 2],
        0xFFFFFFFF,
        operand_size=4,
    )
    assert always_not_taken is not None
    assert always_not_taken.always_taken is False
    assert always_not_taken.always_not_taken is True

    mixed = conditional_jump_outcome_for_values(
        "jb",
        [0, 2],
        1,
        operand_size=4,
    )
    assert mixed is not None
    assert mixed.always_taken is False
    assert mixed.always_not_taken is False


def test_evaluates_portable_predicate_conditions() -> None:
    assert predicate_jump_taken(PredicateKind.EQ, 7, 7) is True
    assert predicate_jump_taken(PredicateKind.NE, 7, 7) is False
    assert predicate_jump_taken(PredicateKind.UGE, 0xFFFFFFFF, 1) is True
    assert predicate_jump_taken(PredicateKind.ULT, 0, 1) is True
    assert predicate_jump_taken(PredicateKind.SLT, 0xFFFFFFFF, 0) is True
    assert predicate_jump_taken(PredicateKind.SGE, 0x80000000, 0) is False
    assert predicate_jump_taken(PredicateKind.TRUTHY, 1, 0) is True
    assert predicate_jump_taken(PredicateKind.TRUTHY, 0, 99) is False


def test_classifies_path_constant_outcomes_from_portable_predicate() -> None:
    always_taken = conditional_jump_outcome_for_predicate(
        PredicateKind.UGE,
        [9, 10, 11],
        9,
        operand_size=4,
    )
    assert always_taken is not None
    assert always_taken.always_taken is True
    assert always_taken.always_not_taken is False

    mixed = conditional_jump_outcome_for_predicate(
        PredicateKind.ULT,
        [0, 2],
        1,
        operand_size=4,
    )
    assert mixed is not None
    assert mixed.always_taken is False
    assert mixed.always_not_taken is False
