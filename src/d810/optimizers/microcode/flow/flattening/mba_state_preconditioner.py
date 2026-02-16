from __future__ import annotations

"""MBA state preconditioning before flow unflattening.

Why this pass exists
====================
Control-flow unflatteners make CFG decisions from dispatcher state values. In
practice those values are often still wrapped in MBA/bitwise noise at
``MMAT_CALLS`` and early ``MMAT_GLBOPT1``.

When that happens, unflatteners either:
1. cannot resolve fathers confidently, or
2. resolve with partial state and must defer structural rewrites.

This rule provides a bounded, function-level "preconditioning" phase that runs
*before* unflatteners (higher priority) and asks Hex-Rays to perform another
local optimization sweep. That gives instruction-level simplifiers and
constant-propagation rules another chance to normalize dispatcher state
expressions before CFG rewrites begin.

Design constraints
==================
- No direct CFG rewrites are performed by this rule.
- Run once per function per maturity to avoid callback thrashing.
- Bounded rounds to avoid unbounded re-optimization loops.
- Optional gating through ``FlowMaturityContext`` so we only spend time on
  functions that look flattening-related.
"""

import weakref
from dataclasses import dataclass

import ida_hexrays

from d810.core import getLogger, typing
from d810.hexrays.cfg_utils import safe_verify
from d810.hexrays.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule, FlowRulePriority
from d810.optimizers.microcode.handler import ConfigParam

logger = getLogger(__name__)


@dataclass(frozen=True)
class _RunKey:
    """Per-maturity execution marker for an mba instance."""

    maturity: int


class MbaStatePreconditioner(FlowOptimizationRule):
    """Bounded function-level preconditioning pass for MBA-heavy dispatchers."""

    CATEGORY = "Flow Preconditioning"
    DESCRIPTION = (
        "Runs bounded local optimization rounds before unflatteners to normalize "
        "dispatcher MBA state expressions."
    )
    # Keep this after strict constant prep (500) but before unflattening (300).
    PRIORITY = int(FlowRulePriority.PREPARE_CONSTANTS) - 50
    CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam(
            "max_optimize_local_rounds",
            int,
            2,
            "Maximum local optimization rounds per function/maturity.",
        ),
        ConfigParam(
            "require_unflattening_gate",
            bool,
            True,
            "Only run when flow context says unflattening gate is allowed.",
        ),
        ConfigParam(
            "verify_after_round",
            bool,
            True,
            "Run safe_verify() after each optimization round.",
        ),
    )

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]
        self.max_optimize_local_rounds = 2
        self.require_unflattening_gate = True
        self.verify_after_round = True
        self._seen: weakref.WeakKeyDictionary[
            ida_hexrays.mba_t, set[_RunKey]
        ] = weakref.WeakKeyDictionary()
        self._in_progress: weakref.WeakSet[ida_hexrays.mba_t] = weakref.WeakSet()

    @typing.override
    def configure(self, kwargs):
        super().configure(kwargs)
        self.max_optimize_local_rounds = int(
            self.config.get("max_optimize_local_rounds", self.max_optimize_local_rounds)
        )
        self.require_unflattening_gate = bool(
            self.config.get("require_unflattening_gate", self.require_unflattening_gate)
        )
        self.verify_after_round = bool(
            self.config.get("verify_after_round", self.verify_after_round)
        )

    def _should_run_for_block(self, blk: ida_hexrays.mblock_t) -> bool:
        mba = blk.mba
        if mba is None:
            return False
        if self.current_maturity not in self.maturities:
            return False
        if blk.serial != 1:
            return False
        if mba in self._in_progress:
            return False
        marker = _RunKey(self.current_maturity)
        seen = self._seen.get(mba)
        if seen is not None and marker in seen:
            return False
        if self.require_unflattening_gate and self.flow_context is not None:
            gate = self.flow_context.evaluate_unflattening_gate()
            if not gate.allowed:
                if logger.debug_on:
                    logger.debug(
                        "Skipping %s for 0x%x at %s: %s",
                        self.__class__.__name__,
                        int(mba.entry_ea or 0),
                        maturity_to_string(self.current_maturity),
                        gate.reason,
                    )
                return False
        return True

    @typing.override
    def optimize(self, blk: ida_hexrays.mblock_t):
        mba = blk.mba
        if mba is None:
            return 0
        if not self._should_run_for_block(blk):
            return 0

        marker = _RunKey(self.current_maturity)
        self._in_progress.add(mba)
        total_changes = 0
        rounds_run = 0
        try:
            for _ in range(max(0, self.max_optimize_local_rounds)):
                rounds_run += 1
                nb_changes = int(mba.optimize_local(0))
                if nb_changes <= 0:
                    break
                total_changes += nb_changes
                if self.verify_after_round:
                    safe_verify(
                        mba,
                        f"{self.__class__.__name__} round {rounds_run}",
                        logger_func=logger.error,
                    )
        finally:
            seen = self._seen.setdefault(mba, set())
            seen.add(marker)
            self._in_progress.discard(mba)

        if logger.debug_on:
            logger.debug(
                "%s at %s ran %d round(s), total_changes=%d",
                self.__class__.__name__,
                maturity_to_string(self.current_maturity),
                rounds_run,
                total_changes,
            )
        return total_changes

