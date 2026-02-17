"""Tests for optimizer pre-filtering layers (maturity gate, active list, operand check)."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.core.stats import OptimizationStatistics
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer


class _StubRule:
    """Minimal rule stub that records check_and_replace calls."""

    def __init__(self, name: str, maturities: list[int] | None = None):
        self.name = name
        self.maturities = maturities or [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        ]
        self.calls = 0

    def check_and_replace(self, blk, ins):
        self.calls += 1
        return None


class _ConcreteOptimizer(InstructionOptimizer):
    """Concrete subclass for testing (InstructionOptimizer is generic)."""
    RULE_CLASSES = [object]  # Accept any rule via isinstance

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _make_blk(maturity: int) -> SimpleNamespace:
    return SimpleNamespace(mba=SimpleNamespace(maturity=maturity))


def _make_ins(opcode: int = ida_hexrays.m_mov) -> SimpleNamespace:
    return SimpleNamespace(opcode=opcode, ea=0x1000)


def test_maturity_gate_blocks_optimizer_at_wrong_maturity():
    """Layer 1: optimizer-level maturity gate skips entire optimizer."""
    stats = OptimizationStatistics()
    opt = _ConcreteOptimizer(
        maturities=[ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED],
        stats=stats,
    )
    rule = _StubRule("EarlyRule", maturities=[ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED])
    opt.add_rule(rule)

    blk = _make_blk(ida_hexrays.MMAT_LOCOPT)
    ins = _make_ins()

    result = opt.get_optimized_instruction(blk, ins)

    assert result is None
    assert rule.calls == 0, f"Rule was called {rule.calls} times at wrong maturity"


def test_maturity_gate_allows_optimizer_at_correct_maturity():
    """Layer 1: optimizer passes through at correct maturity."""
    stats = OptimizationStatistics()
    opt = _ConcreteOptimizer(
        maturities=[ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1],
        stats=stats,
    )
    rule = _StubRule("LocoptRule")
    opt.add_rule(rule)

    blk = _make_blk(ida_hexrays.MMAT_LOCOPT)
    ins = _make_ins()

    result = opt.get_optimized_instruction(blk, ins)

    assert result is None  # Rule returns None
    assert rule.calls == 1, f"Rule was not called at correct maturity"
