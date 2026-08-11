"""Consumer analysis and outcome runtime for one decompilation session.

Reads persisted preanalysis results, derives consumer summaries, records
outcomes, and returns hints. Raw evidence collection and fact lifecycle state
belong to :mod:`d810.passes.preanalysis_runtime`.

Does NOT own: rule activation, planner scoring, CFG mutation.
No IDA imports - fully unit-testable.

Stale-hint policy: the manager lifecycle coordinator calls
``begin_session(func_ea)`` at top-level decompilation start. This clears the
in-memory fired guard **and** persisted raw results / analyzed hints so every
decompilation pass starts from a clean slate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.decompilation_session import DecompilationSessionEvent
from d810.passes.store import get_preanalysis_writer
from d810.core.typing import TYPE_CHECKING, Any, Callable

from d810.passes.analysis import AnalysisPhase
from d810.analyses.control_flow.models import DeobfuscationHints
from d810.passes.outcome import (
    ConsumerOutcomeReport,
    FlowGateOutcomeAdapter,
    PlannerOutcomeAdapter,
    AnalysisOutcomeLog,
    ExecutionScopeOutcomeAdapter,
)
from d810.passes.flow_hints import derive_flow_context_summary
from d810.analyses.value_flow.model import FactConsumerRecord
from d810.passes.store import PreanalysisStore

if TYPE_CHECKING:
    from d810.analyses.value_flow.model import ValidatedFactView
    from d810.core.execution_scope import (
        ApplyExecutionHintsResult,
        ExecutionScopeService,
    )
    from d810.passes.flow_hints import FlowContextHintSummary

logger = getLogger("d810.passes.runtime")


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    """Records what the lifecycle produced and what the consumer did.

    Attributes:
        func_ea: Function effective address.
        hints: Resolved hints, or ``None`` if unavailable.
        apply_result: Result from ``ExecutionScopeService.apply_hints()``, or
            ``None`` if hints were unavailable.
        source: How the hints were obtained: ``"cached"``, ``"analyzed"``,
            or ``"unavailable"``.
    """

    func_ea: int
    hints: DeobfuscationHints | None
    apply_result: ApplyExecutionHintsResult | None
    source: str  # "cached" | "analyzed" | "unavailable"


class DecompilationAnalysisRuntime:
    """Derive consumer summaries and record outcomes from persisted evidence.

    Does NOT own: rule activation, planner scoring, CFG mutation.

    This runtime never receives a live MBA or invokes a raw fact collector.
    """

    def __init__(
        self,
        analysis: AnalysisPhase,
        store: PreanalysisStore,
        *,
        validated_fact_view_provider: Callable[[int, int | str], "ValidatedFactView"]
        | None = None,
    ) -> None:
        self._analysis = analysis
        self._store = store
        self._validated_fact_view_provider = validated_fact_view_provider
        self._current_func_ea: int = -1
        self._outcome_log: AnalysisOutcomeLog = AnalysisOutcomeLog()
        self._outcome_seen_by_func: dict[int, set[tuple[str, bool]]] = {}

    def validated_fact_view(
        self,
        func_ea: int,
        provider_level: int | str,
    ) -> "ValidatedFactView | None":
        """Return the analysis-facing validated view of captured raw facts."""
        provider = self._validated_fact_view_provider
        if provider is None:
            return None
        return provider(int(func_ea), provider_level)

    def begin_session(
        self,
        event: DecompilationSessionEvent,
        *,
        preserve_active_session: bool = False,
    ) -> bool:
        """Begin one analysis session, deduplicated across managers.

        Only the first call per decompilation actually clears state. Subsequent
        calls with the same *func_ea* are no-ops. ``preserve_active_session``
        is reserved for the manager coordinator's nested-session bridge: it
        prevents an inner decompilation from flushing its still-active parent.

        Returns:
            ``True`` if initialization fired, ``False`` if deduplicated.
        """
        func_ea = int(event.function_ea)
        if func_ea == self._current_func_ea:
            return False  # already reset for this decompilation
        # A normal function switch means the old callback chain ended without
        # a structural finish; preserve that historical flush behavior. A
        # manager-declared nested session instead keeps the parent live so it
        # can resume after the inner decompilation finishes.
        prev_ea = self._current_func_ea
        if prev_ea != -1 and not preserve_active_session:
            self._persist_outcomes(prev_ea)
        self._current_func_ea = func_ea
        self._outcome_log.reset_for_func(func_ea)
        self._outcome_seen_by_func.pop(func_ea, None)
        logger.debug(
            "begin_session: func=0x%x prev=0x%x flushed=%s nested=%s",
            func_ea,
            prev_ea,
            prev_ea != -1 and not preserve_active_session,
            preserve_active_session,
        )
        return True

    def finish_session(
        self,
        event: DecompilationSessionEvent,
        *,
        resume_event: DecompilationSessionEvent | None = None,
    ) -> None:
        """Persist the finished session and optionally resume its parent."""
        self._persist_outcomes(int(event.function_ea))
        self._current_func_ea = (
            int(resume_event.function_ea) if resume_event is not None else -1
        )

    def flush_active_session(self) -> bool:
        """Durably finish the active outcome session during manager shutdown.

        Hex-Rays does not guarantee an ``hxe_structural`` callback for every
        successful decompilation.  A manager stop is therefore also a session
        boundary: persist the outcomes already observed before the runtime and
        its writer are discarded.
        """
        func_ea = self._current_func_ea
        if func_ea == -1:
            return False
        self._persist_outcomes(func_ea)
        get_preanalysis_writer(self._store.db_path).flush()
        self._current_func_ea = -1
        return True

    def _persist_outcomes(self, func_ea: int) -> None:
        """Persist consumer outcomes to store.

        Session summaries are persisted eagerly by ``analyze``
        and ``collect_and_analyze``, so this method only handles the
        consumer-outcome rows.
        """
        # Consumer outcomes
        reports = self._outcome_log.get_func_reports(func_ea)
        for report in reports:
            prov_dict = report.provenance_dict
            if prov_dict is not None:
                try:
                    provenance = json.dumps(prov_dict)
                except (TypeError, ValueError):
                    provenance = ""
            else:
                provenance = ""
            _func_ea = func_ea
            _consumer = report.consumer_name
            _arts = report.source_artifacts_available
            _summ = report.summary_available
            _verdict = report.consumer_verdict_applied
            _detail = report.detail
            _prov = provenance
            get_preanalysis_writer(self._store.db_path).submit(
                lambda store: store.save_consumer_outcome(
                    func_ea=_func_ea,
                    consumer_name=_consumer,
                    artifacts_available=_arts,
                    summary_available=_summ,
                    verdict_applied=_verdict,
                    detail=_detail,
                    provenance_json=_prov,
                )
            )

        summary = self._outcome_log.summary(func_ea)
        if summary.get("consumers"):
            logger.info(
                "decompilation_finished: func=0x%x outcome_summary=%s",
                func_ea,
                summary,
            )

    # ------------------------------------------------------------------
    # Outcome recording
    # ------------------------------------------------------------------

    @property
    def outcome_log(self) -> AnalysisOutcomeLog:
        """Read-only access to the outcome log."""
        return self._outcome_log

    def record_outcome(self, report: ConsumerOutcomeReport) -> None:
        """Record a consumer outcome report and log it at INFO level.

        Deduplicates: only logs once per (func_ea, consumer, verdict) to
        avoid per-block spam when gates evaluate identically on every block.
        """
        self._outcome_log.record(report)
        dedup_key = (report.consumer_name, report.consumer_verdict_applied)
        seen = self._outcome_seen_by_func.setdefault(report.func_ea, set())
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        logger.info(
            "outcome: func=0x%x consumer=%s artifacts=%s summary=%s verdict=%s",
            report.func_ea,
            report.consumer_name,
            report.source_artifacts_available,
            report.summary_available,
            report.consumer_verdict_applied,
        )

    def record_execution_scope_outcome(
        self,
        func_ea: int,
        hints: DeobfuscationHints | None,
        apply_result: ApplyExecutionHintsResult | None,
        source: str,
    ) -> None:
        """Convenience: build a :class:`ExecutionScopeOutcomeAdapter` and record it.

        Keeps :class:`AnalysisOutcome` adapter construction in the analysis
        layer so ``d810.hexrays`` hooks need no outcome-model imports.
        """
        outcome = AnalysisOutcome(
            func_ea=func_ea,
            hints=hints,
            apply_result=apply_result,
            source=source,
        )
        adapter = ExecutionScopeOutcomeAdapter(outcome)
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
        adapter = FlowGateOutcomeAdapter(
            decision=decision, func_ea=func_ea, gate_name=gate_name
        )
        self.record_outcome(adapter)

    def get_outcome_summary(self, func_ea: int) -> dict:
        """One-line summary per consumer for a function."""
        return self._outcome_log.summary(func_ea)

    def record_fact_consumers(
        self,
        func_ea: int,
        consumers: tuple[FactConsumerRecord, ...],
    ) -> int:
        """Publish fact-consumer records for late-binding persistence.

        Emits a :class:`FactConsumersForLatestSnapshot` event; the diag
        subscriber (if installed) finds the latest ``snapshots`` row
        for ``func_ea`` and writes deduplicated ``fact_consumers``
        rows. Returns the count of consumers passed in (the subscriber
        may dedup; this method does not have visibility into how many
        the subscriber actually persisted).
        """
        if not consumers:
            return 0
        try:
            from d810.core.observability import emit
            from d810.core.observability_events import (
                FactConsumersForLatestSnapshot,
            )

            emit(
                FactConsumersForLatestSnapshot(
                    func_ea=int(func_ea),
                    consumers=tuple(consumers),
                )
            )
            return len(consumers)
        except Exception:
            logger.exception(
                "FACT_CONSUMERS_DROPPED func=0x%x consumers=%d reason=exception",
                func_ea,
                len(consumers),
            )
            return 0

    def analyze(self, func_ea: int) -> DeobfuscationHints | None:
        """Run analysis on current store contents and persist hints.

        Called eagerly after each collector pass. Returns None if no
        preanalysis results are available yet.
        """
        writer = get_preanalysis_writer(self._store.db_path)
        writer.flush()  # ensure collector writes are visible
        results = self._store.load_all_preanalysis_results(func_ea=func_ea)
        if not results:
            return None
        hints = self._analysis.interpret(
            func_ea=func_ea,
            results=results,
            store=self._store,
        )
        writer.submit(lambda store, h=hints: store.save_hints(h))
        # Eagerly persist session summary alongside hints so it survives
        # interrupted decompilations (plugin stop, no hxe_structural).
        _n = len({r.collector_name for r in results})
        writer.submit(
            lambda store, h=hints: store.save_session_summary(
                func_ea=func_ea,
                collectors_fired=_n,
                classification=h.obfuscation_type or "",
                confidence=h.confidence,
                inferences=list(h.recommended_inferences),
                suppress_stages=list(h.suppress_stages),
            )
        )
        logger.info(
            "analyze: persisted hints for func=0x%x (type=%s, confidence=%.2f)",
            func_ea,
            hints.obfuscation_type,
            hints.confidence,
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

        This keeps derivation in the analysis layer so Hex-Rays hooks
        do not need to import ``d810.passes.flow_hints`` directly.
        """
        hints = self.load_hints(func_ea)
        if hints is None:
            return None
        return derive_flow_context_summary(hints)

    def apply_to_execution_scope(
        self,
        func_ea: int,
        execution_scope: ExecutionScopeService,
    ) -> AnalysisOutcome:
        """Analyze persisted evidence and apply available hints."""
        hints = self.load_hints(func_ea)
        if hints is not None:
            source = "cached"
            logger.info(
                "apply_to_execution_scope: func=0x%x using cached hints "
                "(type=%s confidence=%.2f)",
                func_ea,
                hints.obfuscation_type,
                hints.confidence,
            )
        else:
            hints = self.analyze(func_ea)
            source = "analyzed" if hints is not None else "unavailable"

        apply_result = None
        if hints is not None:
            apply_result = execution_scope.apply_hints(hints)
            logger.info(
                "apply_to_execution_scope: func=0x%x applied -> "
                "inferences=%s suppressed=%s gen=%d->%d",
                func_ea,
                apply_result.inferences_applied,
                apply_result.stages_suppressed,
                apply_result.generation_before,
                apply_result.generation_after,
            )

        return AnalysisOutcome(
            func_ea=func_ea,
            hints=hints,
            apply_result=apply_result,
            source=source,
        )
