"""Tests for width-aware pure binary microcode semantics."""

from __future__ import annotations

import pytest

from d810.core import bits


def test_binary_fold_uses_operand_width_for_flag_results() -> None:
    """A one-byte condition result must not truncate its 32-bit inputs."""

    assert (
        bits.fold_binary_opcode(
            "setb", 0x100, 0xFF, left_bytes=4, right_bytes=4, result_bytes=1
        )
        == 0
    )
    assert (
        bits.fold_binary_opcode(
            "seto",
            0x7FFFFFFF,
            0xFFFFFFFF,
            left_bytes=4,
            right_bytes=4,
            result_bytes=1,
        )
        == 1
    )


@pytest.mark.parametrize(
    ("opcode", "left", "right", "expected"),
    [
        ("cfadd", 0xFFFFFFFF, 1, 1),
        ("ofadd", 0x7FFFFFFF, 1, 1),
        ("setz", 7, 7, 1),
        ("setnz", 7, 7, 0),
        ("setae", 7, 6, 1),
        ("setb", 6, 7, 1),
        ("seta", 7, 6, 1),
        ("setbe", 7, 6, 0),
        ("setg", 0xFFFFFFFF, 1, 0),
        ("setge", 0xFFFFFFFF, 1, 0),
        ("setl", 0xFFFFFFFF, 1, 1),
        ("setle", 0xFFFFFFFF, 1, 1),
        ("setp", 0, 0, 1),
    ],
)
def test_binary_fold_covers_the_remaining_flag_and_setcc_opcodes(
    opcode: str, left: int, right: int, expected: int
) -> None:
    assert (
        bits.fold_binary_opcode(
            opcode, left, right, left_bytes=4, right_bytes=4, result_bytes=1
        )
        == expected
    )


@pytest.mark.parametrize(
    ("opcode", "left", "right", "expected"),
    [
        ("udiv", 20, 4, 5),
        ("sdiv", 0xFFFFFFF9, 3, 0xFFFFFFFE),
        ("umod", 17, 5, 2),
        ("smod", 0xFFFFFFF9, 3, 0xFFFFFFFF),
    ],
)
def test_binary_fold_covers_division_and_modulo(
    opcode: str, left: int, right: int, expected: int
) -> None:
    assert (
        bits.fold_binary_opcode(
            opcode, left, right, left_bytes=4, right_bytes=4, result_bytes=4
        )
        == expected
    )


@pytest.mark.parametrize(
    ("opcode", "value", "input_bytes", "result_bytes", "expected"),
    [
        ("mov", 0x1234, 2, 1, 0x34),
        ("neg", 5, 1, 1, 0xFB),
        ("lnot", 0, 4, 1, 1),
        ("bnot", 0xAA, 1, 1, 0x55),
        ("xdu", 0xFF, 1, 4, 0xFF),
        ("xds", 0xFF, 1, 4, 0xFFFFFFFF),
        ("low", 0x1234, 2, 1, 0x34),
        ("high", 0x1234, 2, 1, 0x12),
        ("sets", 0xFF, 1, 1, 1),
    ],
)
def test_unary_fold_covers_pure_width_sensitive_operations(
    opcode: str, value: int, input_bytes: int, result_bytes: int, expected: int
) -> None:
    assert (
        bits.fold_unary_opcode(
            opcode, value, input_bytes=input_bytes, result_bytes=result_bytes
        )
        == expected
    )
