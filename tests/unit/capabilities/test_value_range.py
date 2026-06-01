"""Portable contract tests for ValRangeCapability + ValRange (no IDA)."""
from __future__ import annotations

from d810.capabilities import ValRange, ValRangeCapability


def test_valrange_singleton():
    vr = ValRange(lo=5, hi=5, width=4)
    assert vr.is_singleton
    assert vr.single() == 5
    assert vr.contains(5)
    assert not vr.contains(6)


def test_valrange_multi():
    vr = ValRange(lo=2, hi=10, width=4)
    assert not vr.is_singleton
    assert vr.single() is None
    assert vr.contains(2) and vr.contains(6) and vr.contains(10)
    assert not vr.contains(11)
    assert not vr.contains(1)


def test_protocol_structural_satisfaction():
    # A pure-Python fake (no IDA) structurally satisfies the capability contract,
    # proving the Protocol stays portable.
    class FakeCap:
        def resolve_state_value(self, block_serial, state_var_stkoff, *, at_insn=None):
            return 0x1234 if block_serial == 1 else None

        def probe_dispatcher_target(
            self, block_serial, state_var_stkoff, dispatcher, *, at_insn=None
        ):
            return 42 if block_serial == 1 else None

        def state_value_range(self, block_serial, state_var_stkoff, *, at_insn=None):
            return ValRange(0, 7, 4)

    cap: ValRangeCapability = FakeCap()
    assert cap.resolve_state_value(1, 0x3C) == 0x1234
    assert cap.resolve_state_value(2, 0x3C) is None
    assert cap.probe_dispatcher_target(1, 0x3C, object()) == 42
    assert cap.state_value_range(1, 0x3C).contains(3)
