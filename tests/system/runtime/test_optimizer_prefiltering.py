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


from d810.hexrays.hexrays_hooks import InstructionOptimizerManager


class _MockOptimizer:
    """Mock optimizer with maturities and a call counter."""

    def __init__(self, name: str, maturities: list[int]):
        self.name = name
        self.maturities = maturities
        self.calls = 0
        self.cur_maturity = ida_hexrays.MMAT_PREOPTIMIZED

    def get_optimized_instruction(self, blk, ins, *, allowed_rule_names=None):
        self.calls += 1
        return None


def test_active_optimizer_list_filters_by_maturity():
    """Layer 2: only maturity-relevant optimizers are iterated in optimize()."""
    early_opt = _MockOptimizer(
        "EarlyOpt",
        [ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED],
    )
    locopt_opt = _MockOptimizer(
        "LocoptOpt",
        [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1],
    )

    mgr = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    # Minimal initialization for the test
    mgr.instruction_optimizers = [early_opt, locopt_opt]
    mgr.current_maturity = None
    mgr.current_blk_serial = None
    mgr._rewrite_seen = {}
    mgr._rule_scope_service = None
    mgr._rule_scope_project_name = ""
    mgr._rule_scope_idb_key = ""
    mgr.analyzer = SimpleNamespace(set_maturity=lambda m: None)
    mgr.event_emitter = None
    mgr.dump_intermediate_microcode = False
    mgr.stats = None
    mgr._active_instruction_rule_names_by_maturity = {}
    mgr.instruction_visitor = None
    mgr._last_optimizer_tried = None
    mgr.log_dir = None

    # Simulate maturity change to MMAT_LOCOPT
    blk = _make_blk(ida_hexrays.MMAT_LOCOPT)
    ins = _make_ins()
    mgr.log_info_on_input(blk, ins)

    # Now call optimize — only locopt_opt should be called
    mgr.optimize(blk, ins)

    assert early_opt.calls == 0, f"EarlyOpt was called {early_opt.calls} times at LOCOPT"
    assert locopt_opt.calls == 1, f"LocoptOpt was not called at LOCOPT"
