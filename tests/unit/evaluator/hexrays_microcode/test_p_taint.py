"""Unit tests for the pure synthetic-return taint decisions (ticket d81-0xzp).

IDA-free: the helpers take plain operand keys, so the rule "a value derived from
a synthetic call return is not a proven value" is testable without a live
``mba_t``.  The Hex-Rays wiring is covered by ``tests/system/runtime/evaluator``.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

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
    any_tainted,
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
