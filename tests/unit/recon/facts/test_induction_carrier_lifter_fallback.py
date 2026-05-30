"""LS10 C2: the induction collector delegates instruction iteration to a
registered SourceLifter, and is byte-identical to the legacy default path when
no lifter is registered. Pure-Python, no IDA.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.capabilities.source_lifter import (
    register_live_lifter,
    reset_live_lifters_for_tests,
)
from d810.analyses.value_flow import induction_carrier


def _portable_target():
    """A flow-graph-like target the default _iter_portable_instructions handles."""
    insn = SimpleNamespace(
        opcode_name="m_add",
        dest_stkoff=0x20,
        src_l_stkoff=0x20,
        src_r_value=1,
        ea=0x180010000,
        index=0,
        dstr="add %var_20, 1",
    )
    block = SimpleNamespace(serial=1, instructions=[insn])
    return SimpleNamespace(blocks=[block])


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_live_lifters_for_tests()
    yield
    reset_live_lifters_for_tests()


def test_no_lifter_is_byte_identical_to_default_path() -> None:
    target = _portable_target()
    via_wrapper = list(induction_carrier._iter_instruction_views(target))
    via_default = list(induction_carrier._iter_portable_instructions(target))
    assert via_wrapper == via_default  # fallback == legacy default
    assert via_wrapper  # non-empty sanity (one induction-shaped view)


def test_registered_lifter_lifts_source_before_iteration() -> None:
    raw_source = object()  # a "live" source the default path cannot iterate
    lifted = _portable_target()

    class _FakeLifter:
        def __init__(self) -> None:
            self.lifted = 0

        def matches(self, source: object) -> bool:
            return source is raw_source

        def lift(self, source: object) -> object:
            self.lifted += 1
            return lifted

    lifter = _FakeLifter()
    register_live_lifter(lifter)

    views = list(induction_carrier._iter_instruction_views(raw_source))
    assert lifter.lifted == 1
    assert views == list(induction_carrier._iter_portable_instructions(lifted))


def test_non_matching_lifter_falls_back_to_default() -> None:
    class _NeverMatches:
        def matches(self, source: object) -> bool:
            return False

        def lift(self, source: object) -> object:  # pragma: no cover - never called
            raise AssertionError("lift must not be called when matches() is False")

    register_live_lifter(_NeverMatches())
    target = _portable_target()
    assert list(induction_carrier._iter_instruction_views(target)) == list(
        induction_carrier._iter_portable_instructions(target)
    )
