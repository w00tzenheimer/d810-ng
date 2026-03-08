"""ReconAnalysisRuntime - thin coordinator for the recon-analysis lifecycle.

Wires together ``ReconPhase``, ``AnalysisPhase``, and ``ReconStore`` into
a single facade: collect -> persist -> analyze -> (optionally persist hints)
-> return hints.

Does NOT own: rule activation, planner scoring, CFG mutation.
No IDA imports - fully unit-testable.

Stale-hint policy: ``reset_for_func(func_ea)`` is called at the start of
each decompilation (when the optimizer managers detect a new func_ea).  This
clears the in-memory fired guard **and** persisted raw results / analyzed
hints so every decompilation pass starts from a clean slate.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING, Any

from d810.recon.analysis import AnalysisPhase
from d810.recon.models import DeobfuscationHints
from d810.recon.outcome import (
    ConsumerOutcomeReport,
    FlowGateOutcomeAdapter,
    PlannerOutcomeAdapter,
    ReconOutcomeLog,
    RuleScopeOutcomeAdapter,
)
from d810.recon.phase import ReconPhase
from d810.recon.flow_hints import derive_flow_context_summary
from d810.recon.store import ReconStore

if TYPE_CHECKING:
    from d810.core.rule_scope import ApplyHintsResult, RuleScopeService
    from d810.recon.flow_hints import FlowContextHintSummary

logger = getLogger("D810.recon.runtime")


@dataclass(frozen=True, slots=True)
class ReconOutcome:
    """Records what the lifecycle produced and what the consumer did.

    Attributes:
        func_ea: Function effective address.
        hints: Resolved hints, or ``None`` if unavailable.
        apply_result: Result from ``RuleScopeService.apply_hints()``, or
            ``None`` if hints were unavailable.
        source: How the hints were obtained: ``"cached"``, ``"analyzed"``,
            or ``"unavailable"``.
    """
    func_ea: int
    hints: DeobfuscationHints | None
    apply_result: ApplyHintsResult | None
    source: str  # "cached" | "analyzed" | "unavailable"


class ReconAnalysisRuntime:
    """Thin coordinator for the generic recon-analysis-consumer lifecycle.

    Lifecycle: collect -> persist canonical artifacts -> analyze into
    consumer-specific summaries -> optionally persist summaries -> feed consumer.

    Does NOT own: rule activation, planner scoring, CFG mutation.

    Example:
        >>> store = ReconStore("/tmp/recon.db")
        >>> phase = ReconPhase(store=store)
        >>> analysis = AnalysisPhase()
        >>> rt = ReconAnalysisRuntime(phase, analysis, store)
        >>> hints = rt.load_or_analyze(func_ea=0x401000, target=None, maturity=5)
    """

    def __init__(
        self,
        phase: ReconPhase,
        analysis: AnalysisPhase,
        store: ReconStore,
    ) -> None:
        self._phase = phase
        self._analysis = analysis
        self._store = store
        self._current_func_ea: int = -1
        self._outcome_log: ReconOutcomeLog = ReconOutcomeLog()

    def reset_for_func(self, func_ea: int) -> bool:
        """Reset recon state -- deduplicates across managers.

        Only the first call per decompilation actually clears state.
        Subsequent calls with the same *func_ea* are no-ops.

        Returns:
            ``True`` if the reset actually fired, ``False`` if deduplicated.
        """
        if func_ea == self._current_func_ea:
            return False  # already reset for this decompilation
        self._current_func_ea = func_ea
        self._phase.reset(func_ea=func_ea)
        self._store.clear_func(func_ea=func_ea)
        self._outcome_log.reset_for_func(func_ea)
        logger.debug("reset_for_func: cleared recon state for func=0x%x", func_ea)
        return True

    def mark_decompilation_finished(self) -> None:
        """Called at decompilation end -- resets the guard so next decompile triggers reset."""
        if self._current_func_ea != -1:
            summary = self._outcome_log.summary(self._current_func_ea)
            if summary.get("consumers"):
                logger.info(
                    "decompilation_finished: func=0x%x outcome_summary=%s",
                    self._current_func_ea, summary,
                )
        self._current_func_ea = -1

    # ------------------------------------------------------------------
    # Outcome recording
    # ------------------------------------------------------------------

    @property
    def outcome_log(self) -> ReconOutcomeLog:
        """Read-only access to the outcome log."""
        return self._outcome_log

    def record_outcome(self, report: ConsumerOutcomeReport) -> None:
        """Record a consumer outcome report and log it at INFO level."""
        self._outcome_log.record(report)
        logger.info(
            "outcome: func=0x%x consumer=%s artifacts=%s summary=%s verdict=%s",
            report.func_ea, report.consumer_name,
            report.source_artifacts_available,
            report.summary_available,
            report.consumer_verdict_applied,
        )

    def record_rule_scope_outcome(
        self,
        func_ea: int,
        hints: DeobfuscationHints | None,
        apply_result: ApplyHintsResult | None,
        source: str,
    ) -> None:
        """Convenience: build a :class:`RuleScopeOutcomeAdapter` and record it.

        Keeps the :class:`ReconOutcome` / adapter construction in the recon
        layer so that ``d810.hexrays`` hooks do not need to import recon types.
        """
        outcome = ReconOutcome(
            func_ea=func_ea,
            hints=hints,
            apply_result=apply_result,
            source=source,
        )
        adapter = RuleScopeOutcomeAdapter(outcome)
        self.record_outcome(adapter)

    def record_planner_outcome(
        self,
        func_ea: int,
        provenance: Any,
    ) -> None:
        """Convenience: build a :class:`PlannerOutcomeAdapter` and record it."""
        adapter = PlannerOutcomeAdapter(provenance=provenance, func_ea=func_ea)
        self.record_outcome(adapter)

    def record_flow_gate_outcome(
        self,
        func_ea: int,
        decision: Any,
        gate_name: str = "flow_gate",
    ) -> None:
        """Convenience: build a :class:`FlowGateOutcomeAdapter` and record it."""
        adapter = FlowGateOutcomeAdapter(decision=decision, func_ea=func_ea, gate_name=gate_name)
        self.record_outcome(adapter)

    def get_outcome_summary(self, func_ea: int) -> dict:
        """One-line summary per consumer for a function."""
        return self._outcome_log.summary(func_ea)

    def collect_and_analyze(
        self,
        func_ea: int,
        target: Any,
        maturity: int,
        *,
        persist_hints: bool = True,
    ) -> DeobfuscationHints:
        """Run collectors, interpret results, optionally persist hints.

        Args:
            func_ea: Function effective address.
            target: Live ``mba_t`` passed through to collectors.
            maturity: Current microcode maturity level.
            persist_hints: When True, save the resulting hints to the store.

        Returns:
            DeobfuscationHints summarising the classification and recommendations.
        """
        results = self._phase.run_microcode_collectors(
            target, func_ea=func_ea, maturity=maturity,
        )
        logger.debug(
            "collect_and_analyze: func=0x%x maturity=%d collectors_fired=%d",
            func_ea, maturity, len(results),
        )

        hints = self._analysis.interpret(func_ea=func_ea, results=results)

        if persist_hints:
            self._store.save_hints(hints)
            logger.debug(
                "collect_and_analyze: persisted hints for func=0x%x type=%s conf=%.2f",
                func_ea, hints.obfuscation_type, hints.confidence,
            )

        return hints

    def analyze_and_persist(self, func_ea: int) -> DeobfuscationHints | None:
        """Run analysis on current store contents and persist hints.

        Called eagerly after each collector pass. Returns None if no
        recon results are available yet.
        """
        results = self._store.load_all_recon_results(func_ea=func_ea)
        if not results:
            return None
        hints = self._analysis.interpret(func_ea=func_ea, results=results)
        self._store.save_hints(hints)
        logger.info(
            "analyze_and_persist: persisted hints for func=0x%x (type=%s, confidence=%.2f)",
            func_ea, hints.obfuscation_type, hints.confidence,
        )
        return hints

    def load_hints(self, func_ea: int) -> DeobfuscationHints | None:
        """Load previously persisted hints from the store.

        Args:
            func_ea: Function effective address.

        Returns:
            Stored hints, or ``None`` if no hints have been persisted for this
            function.
        """
        return self._store.load_hints(func_ea=func_ea)

    def load_flow_context_summary(self, func_ea: int) -> FlowContextHintSummary | None:
        """Load hints and derive a flow-context summary, or ``None``.

        This keeps the derivation in the recon layer so that hexrays hooks
        do not need to import ``d810.recon.flow_hints`` directly.
        """
        hints = self.load_hints(func_ea)
        if hints is None:
            return None
        return derive_flow_context_summary(hints)

    def load_or_analyze(
        self,
        func_ea: int,
        target: Any,
        maturity: int,
        *,
        persist_hints: bool = True,
    ) -> DeobfuscationHints:
        """Load hints if available, otherwise collect and analyze.

        .. deprecated::
            Analysis is now eager -- hints are persisted by
            :meth:`analyze_and_persist` after each collector pass.
            Consumers should call :meth:`load_hints` instead.
            This method is kept for backward compatibility and simply
            delegates to :meth:`load_hints`, falling back to
            :meth:`collect_and_analyze` only when no hints exist.

        Args:
            func_ea: Function effective address.
            target: Live ``mba_t`` passed through to collectors.
            maturity: Current microcode maturity level.
            persist_hints: When True and collection runs, save resulting hints.

        Returns:
            DeobfuscationHints from store or freshly computed.
        """
        existing = self.load_hints(func_ea)
        if existing is not None:
            logger.debug(
                "load_or_analyze: cache hit for func=0x%x type=%s",
                func_ea, existing.obfuscation_type,
            )
            return existing

        return self.collect_and_analyze(
            func_ea, target, maturity, persist_hints=persist_hints,
        )

    def apply_to_rule_scope(
        self,
        func_ea: int,
        rule_scope: RuleScopeService,
        target: Any = None,
        maturity: int | None = None,
        *,
        persist_hints: bool = True,
    ) -> ReconOutcome:
        """Convenience helper: load-or-analyze hints, apply to rule scope, record outcome.

        .. note::
            The primary hint-application path is now **hook-driven (push)**:
            after :meth:`analyze_and_persist` returns hints in the optimizer
            manager hooks, they are applied to ``RuleScopeService`` immediately.
            This method remains available for manual/script use and standalone
            workflows where the hook wiring is not active.

        Checks the store for cached hints first. When a cache miss occurs
        and *target* / *maturity* are provided, runs collectors and analysis.
        If hints are resolved, they are applied to *rule_scope* via
        ``apply_hints()``.

        Args:
            func_ea: Function effective address.
            rule_scope: Consumer rule-scope service (not stored).
            target: Live ``mba_t`` for collectors (may be ``None``).
            maturity: Current microcode maturity level (may be ``None``).
            persist_hints: When True and collection runs, save resulting hints.

        Returns:
            ``ReconOutcome`` recording hints, apply result, and provenance.
        """
        from d810.core.rule_scope import RuleScopeService as _RSS  # noqa: F811

        # --- 1. Resolve hints (cached or fresh) ---
        hints: DeobfuscationHints | None = None
        source: str = "unavailable"

        existing = self.load_hints(func_ea)
        if existing is not None:
            hints = existing
            source = "cached"
            logger.info(
                "apply_to_rule_scope: func=0x%x using cached hints "
                "(type=%s confidence=%.2f)",
                func_ea, hints.obfuscation_type, hints.confidence,
            )
        elif target is not None and maturity is not None:
            hints = self.collect_and_analyze(
                func_ea, target, maturity, persist_hints=persist_hints,
            )
            source = "analyzed"
            logger.info(
                "apply_to_rule_scope: func=0x%x freshly analyzed hints "
                "(type=%s confidence=%.2f)",
                func_ea, hints.obfuscation_type, hints.confidence,
            )
        else:
            logger.info(
                "apply_to_rule_scope: func=0x%x no hints available "
                "(no cached hints and no target/maturity provided)",
                func_ea,
            )

        # --- 2. Apply to rule scope if we have hints ---
        apply_result = None
        if hints is not None:
            apply_result = rule_scope.apply_hints(hints)
            logger.info(
                "apply_to_rule_scope: func=0x%x applied -> "
                "recipes=%s suppressed=%s gen=%d->%d",
                func_ea,
                apply_result.recipes_applied,
                apply_result.rules_suppressed,
                apply_result.generation_before,
                apply_result.generation_after,
            )

        return ReconOutcome(
            func_ea=func_ea,
            hints=hints,
            apply_result=apply_result,
            source=source,
        )
