"""Logging regression tests for the emulated-dispatcher engine."""

import ida_hexrays

from d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine import (
    _maturity_text,
)


def test_engine_maturity_log_text_uses_friendly_name() -> None:
    assert _maturity_text(ida_hexrays.MMAT_GLBOPT2) == "MMAT_GLBOPT2"


def test_engine_maturity_log_text_falls_back_to_mmat_number() -> None:
    assert _maturity_text(99) == "MMAT_99"
