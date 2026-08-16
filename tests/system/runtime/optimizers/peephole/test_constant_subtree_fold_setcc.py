"""Native regressions for set-condition constant folding."""

from __future__ import annotations

import ida_hexrays

from d810.optimizers.microcode.instructions.peephole.normalise_helpers import _fold


def test_fold_setb_and_seto_match_the_reported_byte_operands() -> None:
    """The peephole evaluator handles the two setcc opcodes from the live log."""

    assert _fold(ida_hexrays.m_setb, 109, 249, 8) == 1
    assert _fold(ida_hexrays.m_seto, 109, 249, 8) == 0
