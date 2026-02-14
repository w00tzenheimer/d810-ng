from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger
from d810.optimizers.microcode.flow.analysis_stats import (
    FlowProfileStats,
    compute_flow_profile_stats,
)
from d810.optimizers.microcode.flow.flattening.dispatcher_detection import (
    DispatcherCache,
    DispatcherType,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.dispatcher_detection import (
        BlockAnalysis,
        DispatcherAnalysis,
    )
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule


logger = getLogger("D810.flow.context")


@dataclass(frozen=True)
class FlowGateDecision:
    allowed: bool
    reason: str


class FlowMaturityContext:
    """Shared function+maturity analysis context for flow optimizers."""

    MIN_FIXPRED_DISPATCHER_PREDS = 3

    def __init__(self, mba: ida_hexrays.mba_t, func_ea: int, maturity: int):
        self.mba = mba
        self.func_ea = int(func_ea)
        self.maturity = int(maturity)
        self.phase_priority: int | None = None
        self.phase_index: int = 0
        self._dispatcher_analysis: DispatcherAnalysis | None = None
        self._dispatcher_analysis_error: Exception | None = None
        self._profile_stats: FlowProfileStats | None = None
        self._profile_stats_error: Exception | None = None
        self._active_rule_names: tuple[str, ...] = tuple()

    def refresh_mba(self, mba: ida_hexrays.mba_t) -> None:
        self.mba = mba
        self._profile_stats = None
        self._profile_stats_error = None

    def set_phase(
        self,
        *,
        priority: int,
        phase_index: int,
        active_rule_names: tuple[str, ...],
    ) -> None:
        self.phase_priority = int(priority)
        self.phase_index = int(phase_index)
        self._active_rule_names = active_rule_names

    @property
    def active_rule_names(self) -> tuple[str, ...]:
        return self._active_rule_names

    def prime_for_rules(self, rules: tuple[FlowOptimizationRule, ...]) -> None:
        if any(getattr(rule, "REQUIRES_DISPATCHER_ANALYSIS", False) for rule in rules):
            self.ensure_dispatcher_analysis()

    def ensure_dispatcher_analysis(self) -> DispatcherAnalysis | None:
        if self._dispatcher_analysis is not None:
            return self._dispatcher_analysis
        if self._dispatcher_analysis_error is not None:
            return None
        try:
            cache = DispatcherCache.get_or_create(self.mba)
            self._dispatcher_analysis = cache.analyze()
            return self._dispatcher_analysis
        except Exception as exc:  # pragma: no cover - defensive; IDA runtime edge
            self._dispatcher_analysis_error = exc
            logger.warning(
                "Dispatcher analysis failed for 0x%x at maturity %d: %s",
                self.func_ea,
                self.maturity,
                exc,
            )
            return None

    def get_profile_stats(self) -> FlowProfileStats | None:
        if self._profile_stats is not None:
            return self._profile_stats
        if self._profile_stats_error is not None:
            return None

        analysis = self.ensure_dispatcher_analysis()
        if analysis is None:
            return None

        try:
            self._profile_stats = compute_flow_profile_stats(self.mba, analysis)
            return self._profile_stats
        except Exception as exc:  # pragma: no cover - defensive; IDA runtime edge
            self._profile_stats_error = exc
            logger.warning(
                "Profile stats failed for 0x%x at maturity %d: %s",
                self.func_ea,
                self.maturity,
                exc,
            )
            return None

    def _dispatcher_blocks(self, analysis: DispatcherAnalysis) -> list[BlockAnalysis]:
        blocks: list[BlockAnalysis] = []
        for serial in analysis.dispatchers:
            info = analysis.blocks.get(serial)
            if info is not None:
                blocks.append(info)
        return blocks

    def _strong_dispatcher_count(self, analysis: DispatcherAnalysis) -> int:
        return sum(1 for info in self._dispatcher_blocks(analysis) if info.is_strong_dispatcher)

    def _max_dispatcher_predecessors(self, analysis: DispatcherAnalysis) -> int:
        max_preds = 0
        for info in self._dispatcher_blocks(analysis):
            if info.predecessor_count > max_preds:
                max_preds = info.predecessor_count
        return max_preds

    def evaluate_unflattening_gate(self) -> FlowGateDecision:
        analysis = self.ensure_dispatcher_analysis()
        if analysis is None:
            return FlowGateDecision(False, "dispatcher analysis unavailable")
        if analysis.dispatcher_type == DispatcherType.SWITCH_TABLE:
            return FlowGateDecision(True, "switch-table dispatcher")
        if len(analysis.dispatchers) == 0:
            return FlowGateDecision(False, "no dispatcher candidates")
        strong_dispatchers = self._strong_dispatcher_count(analysis)
        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            if strong_dispatchers == 0:
                return FlowGateDecision(False, "no strong dispatcher candidates")
            return FlowGateDecision(True, "conditional-chain dispatcher")
        if analysis.dispatcher_type == DispatcherType.UNKNOWN:
            if strong_dispatchers > 0:
                return FlowGateDecision(True, "unknown dispatcher with strong candidates")
            profile = self.get_profile_stats()
            if profile is None:
                return FlowGateDecision(False, "unknown dispatcher without profile stats")
            if profile.has_nested_dispatch:
                return FlowGateDecision(True, "unknown dispatcher with nested dispatch profile")
            if profile.dispatch_scc_n >= 2 and profile.flattening_score >= 0.35:
                return FlowGateDecision(
                    True,
                    (
                        "unknown dispatcher with cyclic dispatch profile "
                        f"(scc={profile.dispatch_scc_n}, score={profile.flattening_score:.2f})"
                    ),
                )
            return FlowGateDecision(
                False,
                (
                    "unknown dispatcher profile too weak "
                    f"(scc={profile.dispatch_scc_n}, score={profile.flattening_score:.2f})"
                ),
            )
        return FlowGateDecision(False, f"dispatcher_type={analysis.dispatcher_type.name}")

    def evaluate_fix_predecessor_gate(self) -> FlowGateDecision:
        analysis = self.ensure_dispatcher_analysis()
        if analysis is None:
            return FlowGateDecision(False, "dispatcher analysis unavailable")
        if analysis.dispatcher_type == DispatcherType.SWITCH_TABLE:
            return FlowGateDecision(False, f"dispatcher_type={analysis.dispatcher_type.name}")
        if analysis.dispatcher_type not in (
            DispatcherType.CONDITIONAL_CHAIN,
            DispatcherType.UNKNOWN,
        ):
            return FlowGateDecision(False, f"dispatcher_type={analysis.dispatcher_type.name}")
        if len(analysis.dispatchers) == 0:
            return FlowGateDecision(False, "no dispatcher candidates")
        strong_dispatchers = self._strong_dispatcher_count(analysis)
        if strong_dispatchers == 0:
            return FlowGateDecision(False, "no strong dispatcher candidates")
        max_preds = self._max_dispatcher_predecessors(analysis)
        if max_preds < self.MIN_FIXPRED_DISPATCHER_PREDS:
            return FlowGateDecision(
                False,
                (
                    f"max dispatcher predecessors {max_preds} "
                    f"< {self.MIN_FIXPRED_DISPATCHER_PREDS}"
                ),
            )
        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            return FlowGateDecision(True, "conditional-chain dispatcher with strong signals")
        return FlowGateDecision(True, "unknown dispatcher with strong signals")
