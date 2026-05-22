from __future__ import annotations

from d810.recon.flow.conditional_jump_eval import (
    conditional_jump_opcode_name,
    conditional_jump_outcome_for_values,
    conditional_jump_taken,
)


def test_normalizes_string_and_numeric_jump_opcodes() -> None:
    assert conditional_jump_opcode_name("m_jz") == "jz"
    assert conditional_jump_opcode_name("op_49") == "jg"
    assert conditional_jump_opcode_name(50) == "jge"
    assert conditional_jump_opcode_name(9001) is None


def test_evaluates_unsigned_jump_conditions() -> None:
    assert conditional_jump_taken("m_jae", 0xFFFFFFFF, 1, operand_size=4) is True
    assert conditional_jump_taken("m_jb", 0, 1, operand_size=4) is True
    assert conditional_jump_taken("m_ja", 7, 7, operand_size=4) is False
    assert conditional_jump_taken("m_jbe", 7, 7, operand_size=4) is True


def test_evaluates_signed_jump_conditions() -> None:
    assert conditional_jump_taken("m_jl", 0xFFFFFFFF, 0, operand_size=4) is True
    assert conditional_jump_taken("m_jg", 0xFFFFFFFF, 0, operand_size=4) is False
    assert conditional_jump_taken("m_jge", 0x80000000, 0, operand_size=4) is False
    assert conditional_jump_taken("m_jle", 0x80000000, 0, operand_size=4) is True


def test_classifies_path_constant_outcomes() -> None:
    always_taken = conditional_jump_outcome_for_values(
        "m_jae",
        [9, 10, 11],
        9,
        operand_size=4,
    )
    assert always_taken is not None
    assert always_taken.always_taken is True
    assert always_taken.always_not_taken is False

    always_not_taken = conditional_jump_outcome_for_values(
        "m_jl",
        [0, 1, 2],
        0xFFFFFFFF,
        operand_size=4,
    )
    assert always_not_taken is not None
    assert always_not_taken.always_taken is False
    assert always_not_taken.always_not_taken is True

    mixed = conditional_jump_outcome_for_values(
        "m_jb",
        [0, 2],
        1,
        operand_size=4,
    )
    assert mixed is not None
    assert mixed.always_taken is False
    assert mixed.always_not_taken is False
