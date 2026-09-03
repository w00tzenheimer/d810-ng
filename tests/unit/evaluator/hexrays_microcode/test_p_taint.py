"""Unit tests for the pure synthetic-return taint decisions (ticket d81-0xzp).

IDA-free: the helpers take plain operand keys, so the rule "a value derived from
a synthetic call return is not a proven value" is testable without a live
``mba_t``.  The Hex-Rays wiring is covered by ``tests/system/runtime/evaluator``.
"""

from __future__ import annotations

import dataclasses
import sys
import types
from pathlib import Path

import pytest

_package_name = "d810.evaluator.hexrays_microcode"
if _package_name not in sys.modules:
    _package = types.ModuleType(_package_name)
    _package.__path__ = [
        str(
            Path(__file__).resolve().parents[4]
            / "src"
            / "d810"
            / "evaluator"
            / "hexrays_microcode"
        )
    ]
    sys.modules[_package_name] = _package

from d810.evaluator.hexrays_microcode.p_taint import (  # noqa: E402
    EvalResult,
    Exactness,
    any_tainted,
    taint_location_key,
    taint_result,
)

RAX = ("r", 8, 4)
RCX = ("r", 24, 4)
STK = ("S", 0x3C, 4)


class TestTaintResult:
    def test_a_synthetic_producer_taints_its_destination(self):
        assert taint_result(produces_synthetic=True, source_keys=(), tainted_keys=set())

    def test_a_tainted_source_taints_the_destination(self):
        assert taint_result(
            produces_synthetic=False, source_keys=(RAX, RCX), tainted_keys={RCX}
        )

    def test_clean_sources_leave_the_destination_clean(self):
        assert not taint_result(
            produces_synthetic=False, source_keys=(RAX, RCX), tainted_keys={STK}
        )

    def test_no_sources_and_no_synthetic_is_clean(self):
        assert not taint_result(
            produces_synthetic=False, source_keys=(), tainted_keys={RAX}
        )

    def test_taint_is_not_inferred_from_the_value_bits(self):
        # A 4-byte mask destroys the high synthetic tag, so a masked synthetic
        # value is indistinguishable by its bits: only the key-set decides.
        assert not taint_result(
            produces_synthetic=False, source_keys=(RAX,), tainted_keys=set()
        )


class TestAnyTainted:
    def test_reports_a_tainted_key(self):
        assert any_tainted((RAX, STK), {STK})

    def test_reports_clean_keys(self):
        assert not any_tainted((RAX, STK), {RCX})

    def test_empty_keys_are_clean(self):
        assert not any_tainted((), {RAX})

    def test_empty_taint_set_is_clean(self):
        assert not any_tainted((RAX, RCX, STK), set())


class TestEvalResult:
    """The evaluator's RESULT carries exactness (ticket d81-1t9x).

    A consumer that only accepts ``int`` must receive ``None`` for a tainted or
    unknown evaluation; asking for the raw value has to be an explicit act.
    """

    def test_an_exact_result_exposes_its_value(self):
        result = EvalResult.exact(0x1234)
        assert result.exactness is Exactness.EXACT
        assert result.is_exact
        assert result.exact_value == 0x1234

    def test_a_tainted_result_hides_its_value_from_exact_consumers(self):
        result = EvalResult.tainted(0x1234)
        assert result.exactness is Exactness.TAINTED
        assert not result.is_exact
        assert result.exact_value is None
        # The value is still reachable for propagation -- explicitly.
        assert result.value == 0x1234

    def test_an_unknown_result_has_no_value_at_all(self):
        result = EvalResult.unknown()
        assert result.exactness is Exactness.UNKNOWN
        assert not result.is_exact
        assert result.exact_value is None
        assert result.value is None

    def test_exact_with_no_value_is_not_exact(self):
        # Defensive: a caller that builds the dataclass directly cannot smuggle
        # a ``None`` through ``exact_value``.
        assert EvalResult(value=None, exactness=Exactness.EXACT).exact_value is None

    def test_results_are_immutable(self):
        result = EvalResult.exact(1)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.value = 2  # type: ignore[misc]


class TestTaintLocationKey:
    """Taint keys must classify locations exactly as the VALUE store does.

    ``MicroCodeEnvironment`` matches stored values with
    ``equal_mops_ignore_size`` (``lo.r == ro.r`` for a register, ``s.off`` for a
    stack slot), so a taint key that includes the operand SIZE loses the taint
    the moment the value is read back at another width -- ``rax.8`` tainted,
    ``rax.4`` clean (ticket d81-1t9x).
    """

    def test_the_same_register_at_two_widths_shares_one_key(self):
        assert taint_location_key(1, 8) == taint_location_key(1, 8)

    def test_different_registers_do_not_share_a_key(self):
        assert taint_location_key(1, 8) != taint_location_key(1, 24)

    def test_registers_and_stack_slots_do_not_collide(self):
        assert taint_location_key(1, 8) != taint_location_key(2, 8)
