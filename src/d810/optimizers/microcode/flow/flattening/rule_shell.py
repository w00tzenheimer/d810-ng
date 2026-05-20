"""Composition-oriented unflattening rule shell.

This module owns the reusable optimizer lifecycle shared by strategy-family
unflatteners: maturity gating, pass accounting, and lightweight flow-context
gates.

It intentionally does not own dispatcher discovery, value solving, CFG planning,
or live Hex-Rays materialization policy.  Families compose those capabilities
through their profile, recon/evaluator inputs, planner, and executor.
"""
from __future__ import annotations

import abc

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.handler import (
    FlowOptimizationRule,
    FlowRulePriority,
)

unflat_logger = getLogger("D810.unflat")


class ComposedUnflatteningRule(FlowOptimizationRule):
    """Small reusable shell for composed unflattening families.

    This is the lifecycle-only base for modern family/profile unflatteners.
    Concrete families are expected to compose their own evidence producers,
    evaluator services, planners, and materializers instead of inheriting a
    dispatcher-specific algorithm.
    """

    CATEGORY = "Control Flow Unflattening"
    PRIORITY = FlowRulePriority.UNFLATTEN
    REQUIRES_DISPATCHER_ANALYSIS = True

    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_LOCOPT,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]

    def __init__(self) -> None:
        super().__init__()
        self.mba: ida_hexrays.mba_t
        self.cur_maturity = ida_hexrays.MMAT_ZERO
        self.cur_maturity_pass = 0
        self.last_pass_nb_patch_done = 0
        self.maturities = self.DEFAULT_UNFLATTENING_MATURITIES

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        if self.cur_maturity == self.mba.maturity:
            self.cur_maturity_pass += 1
        else:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Gate skipped [maturity_filter]: %s at maturity %s not in %s",
                    self.__class__.__name__,
                    maturity_to_string(self.cur_maturity),
                    self.maturities,
                )
            return False
        if not getattr(self, "HAS_OWN_DISPATCHER_COLLECTOR", False):
            if self.flow_context is not None:
                gate = self.flow_context.evaluate_unflattening_gate()
                if hasattr(self.flow_context, "report_outcome"):
                    self.flow_context.report_outcome(gate, "unflattening_gate")
                if not gate.allowed:
                    unflat_logger.debug(
                        "Skipping %s via flow context gate: %s",
                        self.__class__.__name__,
                        gate.reason,
                    )
                    return False
        return True

    @abc.abstractmethod
    def optimize(self, blk):
        """Perform the optimization on *blk* and return the number of changes."""
        raise NotImplementedError


__all__ = ["ComposedUnflatteningRule"]
