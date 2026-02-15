"""Runtime tests for MbaStatePreconditioner contract."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.context import FlowGateDecision
from d810.optimizers.microcode.flow.mba_state_preconditioner import (
    MbaStatePreconditioner,
)


class _FakeMba:
    def __init__(self, maturity: int, returns: list[int], entry_ea: int = 0x401000):
        self.maturity = maturity
        self.entry_ea = entry_ea
        self._returns = list(returns)
        self.calls = 0

    def optimize_local(self, _flags: int) -> int:
        self.calls += 1
        if self._returns:
            return int(self._returns.pop(0))
        return 0


class _FlowContextAllow:
    def evaluate_unflattening_gate(self) -> FlowGateDecision:
        return FlowGateDecision(True, "ok")


class _FlowContextDeny:
    def evaluate_unflattening_gate(self) -> FlowGateDecision:
        return FlowGateDecision(False, "no dispatcher")


def _make_block(mba: _FakeMba, serial: int = 1):
    return SimpleNamespace(mba=mba, serial=serial)


def test_preconditioner_runs_once_per_maturity_and_aggregates_rounds():
    rule = MbaStatePreconditioner()
    rule.configure(
        {
            "max_optimize_local_rounds": 4,
            "verify_after_round": False,
            "require_unflattening_gate": False,
        }
    )
    rule.current_maturity = ida_hexrays.MMAT_CALLS
    mba = _FakeMba(ida_hexrays.MMAT_CALLS, [3, 1, 0, 9])
    blk = _make_block(mba, serial=1)

    assert rule.optimize(blk) == 4
    assert mba.calls == 3

    # Same maturity + same mba should be skipped.
    assert rule.optimize(blk) == 0
    assert mba.calls == 3


def test_preconditioner_skips_when_flow_gate_denies():
    rule = MbaStatePreconditioner()
    rule.configure(
        {
            "max_optimize_local_rounds": 2,
            "verify_after_round": False,
            "require_unflattening_gate": True,
        }
    )
    rule.set_flow_context(_FlowContextDeny())
    rule.current_maturity = ida_hexrays.MMAT_CALLS
    mba = _FakeMba(ida_hexrays.MMAT_CALLS, [5, 5, 5])
    blk = _make_block(mba, serial=1)

    assert rule.optimize(blk) == 0
    assert mba.calls == 0


def test_preconditioner_can_run_without_gate_context():
    rule = MbaStatePreconditioner()
    rule.configure(
        {
            "max_optimize_local_rounds": 2,
            "verify_after_round": False,
            "require_unflattening_gate": True,
        }
    )
    rule.set_flow_context(_FlowContextAllow())
    rule.current_maturity = ida_hexrays.MMAT_GLBOPT1
    mba = _FakeMba(ida_hexrays.MMAT_GLBOPT1, [2, 0])
    blk = _make_block(mba, serial=1)

    assert rule.optimize(blk) == 2
    assert mba.calls == 2
