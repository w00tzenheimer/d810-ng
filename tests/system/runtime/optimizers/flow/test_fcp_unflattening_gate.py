"""Runtime tests for ForwardConstantPropagationRule MMAT_CALLS gate.

Verifies that FCP skips at MMAT_CALLS for UNKNOWN-dispatcher functions
but runs normally at GLBOPT1+, when the gate denies, and for
SWITCH_TABLE/CONDITIONAL_CHAIN dispatchers.

These tests require IDA runtime for ida_hexrays constants.
Uses manual stubs instead of unittest.mock (forbidden in system tests).
"""
import unittest

import ida_hexrays

from d810.optimizers.microcode.flow.constant_prop.forward_const_prop import (
    ForwardConstantPropagationRule,
)
from d810.optimizers.microcode.flow.context import FlowGateDecision


class _StubFlowContext:
    """Minimal flow_context that returns a fixed early-FCP gate decision."""

    def __init__(self, allowed: bool, reason: str = "test"):
        self._decision = FlowGateDecision(allowed=allowed, reason=reason)

    def evaluate_early_fcp_gate(self) -> FlowGateDecision:
        return self._decision


class _StubMba:
    """Weakly-referenceable mba stub (SimpleNamespace is not)."""

    def __init__(self, maturity: int):
        self.maturity = maturity


class _StubBlk:
    """Weakly-referenceable mblock_t stub."""

    def __init__(self, serial: int, mba: _StubMba):
        self.serial = serial
        self.mba = mba


class _TrackingFCP(ForwardConstantPropagationRule):
    """FCP subclass that tracks _run_on_function calls without executing."""

    def __init__(self):
        super().__init__()
        self.run_call_count = 0

    def _run_on_function(self, blk):
        self.run_call_count += 1
        return 0


def _make_stub_blk(serial: int, maturity: int):
    return _StubBlk(serial, _StubMba(maturity))


class TestFCPUnflatteningGate(unittest.TestCase):
    """Test the MMAT_CALLS unflattening gate in FCP.optimize()."""

    def _make_rule(self, maturity: int, flow_context=None):
        rule = _TrackingFCP()
        rule.current_maturity = maturity
        rule.current_generation = 0
        if flow_context is not None:
            rule.flow_context = flow_context
        return rule

    def test_skips_at_mmat_calls_when_gate_allows(self):
        """FCP must skip at MMAT_CALLS when function is unflatten-eligible."""
        ctx = _StubFlowContext(allowed=True, reason="switch-table dispatcher")
        rule = self._make_rule(ida_hexrays.MMAT_CALLS, flow_context=ctx)
        blk = _make_stub_blk(serial=1, maturity=ida_hexrays.MMAT_CALLS)

        result = rule.optimize(blk)

        self.assertEqual(result, 0)
        self.assertEqual(rule.run_call_count, 0, "_run_on_function should not be called")

    def test_does_not_skip_at_glbopt1_when_gate_allows(self):
        """FCP must NOT skip at GLBOPT1 even if function is unflatten-eligible."""
        ctx = _StubFlowContext(allowed=True, reason="switch-table dispatcher")
        rule = self._make_rule(ida_hexrays.MMAT_GLBOPT1, flow_context=ctx)
        blk = _make_stub_blk(serial=1, maturity=ida_hexrays.MMAT_GLBOPT1)

        rule.optimize(blk)

        self.assertEqual(rule.run_call_count, 1, "_run_on_function should be called at GLBOPT1")

    def test_does_not_skip_when_gate_denies(self):
        """FCP must NOT skip when the unflattening gate denies."""
        ctx = _StubFlowContext(allowed=False, reason="no dispatcher candidates")
        rule = self._make_rule(ida_hexrays.MMAT_CALLS, flow_context=ctx)
        blk = _make_stub_blk(serial=1, maturity=ida_hexrays.MMAT_CALLS)

        rule.optimize(blk)

        self.assertEqual(rule.run_call_count, 1, "_run_on_function should be called when gate denies")

    def test_does_not_skip_when_no_flow_context(self):
        """FCP must NOT skip when flow_context is None."""
        rule = self._make_rule(ida_hexrays.MMAT_CALLS, flow_context=None)
        blk = _make_stub_blk(serial=1, maturity=ida_hexrays.MMAT_CALLS)

        rule.optimize(blk)

        self.assertEqual(rule.run_call_count, 1, "_run_on_function should be called without flow_context")


if __name__ == "__main__":
    unittest.main()
