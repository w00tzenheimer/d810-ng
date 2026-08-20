"""Native regressions for set-condition constant folding."""

from __future__ import annotations

import ida_hexrays

from d810.optimizers.microcode.instructions.peephole.normalise_helpers import _fold


def test_fold_setb_and_seto_match_the_reported_byte_operands() -> None:
    """The peephole evaluator handles the two setcc opcodes from the live log."""

    assert _fold(ida_hexrays.m_setb, 109, 249, 8) == 1
    assert _fold(ida_hexrays.m_seto, 109, 249, 8) == 0


def test_fold_setcc_uses_source_width_not_the_flag_width() -> None:
    """Flag results are bytes, but their inputs retain their native width."""

    assert _fold(
        ida_hexrays.m_setb, 0x100, 0xFF, 8, left_bits=32, right_bits=32
    ) == 0
    assert _fold(
        ida_hexrays.m_seto,
        0x7FFFFFFF,
        0xFFFFFFFF,
        8,
        left_bits=32,
        right_bits=32,
    ) == 1


def test_fold_carry_shift_handles_constant_operands_without_error() -> None:
    """Carry-shift flags use the source width and return a byte result."""

    assert _fold(
        ida_hexrays.m_cfshl,
        0x8000000000000000,
        1,
        8,
        left_bits=64,
        right_bits=8,
    ) == 1
    assert _fold(
        ida_hexrays.m_cfshr,
        0x20,
        6,
        8,
        left_bits=8,
        right_bits=8,
    ) == 1
