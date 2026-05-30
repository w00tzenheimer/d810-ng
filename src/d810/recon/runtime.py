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

import json
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.observability import emit as _emit
from d810.core.observability_events import (
    FactConflictsObserved,
    FactMappingsObserved,
    FactObservationsObserved,
)
from d810.core.provider_phase import ProviderPhase
from d810.recon.store import get_recon_writer
from d810.core.typing import TYPE_CHECKING, Any, Protocol

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
from d810.analyses.value_flow.model import (
    FactConflict,
    FactConsumerRecord,
    FactMapping,
    FactObservation,
)
from d810.analyses.value_flow.model import ValidatedFactView
from d810.recon.facts.runtime import (
    FactCaptureSummary,
    FactCollector,
    FactLifecycleRuntime,
)
from d810.recon.store import ReconStore

if TYPE_CHECKING:
    from d810.core.observability import SnapshotRef
    from d810.core.rule_scope import ApplyHintsResult, RuleScopeService
    from d810.recon.flow_hints import FlowContextHintSummary

logger = getLogger("D810.recon.runtime")


class FactObservationSink(Protocol):
    """Diagnostic sink for maturity-fact observations.

    The runtime coordinator emits collected facts through this seam instead
    of importing a diagnostics-layer wrapper directly. The default
    implementation (:class:`_CoreObservabilitySink`) publishes the events on
    the core observability bus (a DOWN dependency); a backend subscriber
    listens. Injecting the sink keeps the coordinator (a passes-layer module)
    free of any upward dependency on the diagnostics layer.
    """

    def observe_fact_observation(
        self, snapshot: "SnapshotRef", func_ea: int, observations: tuple
    ) -> None: ...

    def observe_fact_mapping(
        self, snapshot: "SnapshotRef", func_ea: int, mappings: tuple
    ) -> None: ...

    def observe_fact_conflict(
        self, snapshot: "SnapshotRef", func_ea: int, conflicts: tuple
    ) -> None: ...


class _CoreObservabilitySink:
    """Default :class:`FactObservationSink` bound to the core event bus.

    Behaviour-identical to the former ``d810.recon.observability``
    ``observe_fact_*`` wrappers: each method publishes the corresponding
    ``Fact*Observed`` event from :mod:`d810.core.observability_events` on the
    :func:`d810.core.observability.emit` bus. Pure DOWN (passes -> core).
    """

    @staticmethod
    def observe_fact_observation(
        snapshot: "SnapshotRef", func_ea: int, observations: tuple
    ) -> None:
        _emit(FactObservationsObserved(
            snapshot=snapshot,
            func_ea=int(func_ea),
            observations=tuple(observations),
        ))

    @staticmethod
    def observe_fact_mapping(
        snapshot: "SnapshotRef", func_ea: int, mappings: tuple
    ) -> None:
        _emit(FactMappingsObserved(
            snapshot=snapshot,
            func_ea=int(func_ea),
            mappings=tuple(mappings),
        ))

    @staticmethod
    def observe_fact_conflict(
        snapshot: "SnapshotRef", func_ea: int, conflicts: tuple
    ) -> None:
        _emit(FactConflictsObserved(
            snapshot=snapshot,
            func_ea=int(func_ea),
            conflicts=tuple(conflicts),
        ))


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
        >>> hints = rt.load_or_analyze(
        ...     func_ea=0x401000,
        ...     target=None,
        ...     provider_phase=provider_phase,
        ... )
    """

    def __init__(
        self,
        phase: ReconPhase,
        analysis: AnalysisPhase,
        store: ReconStore,
        fact_sink: FactObservationSink | None = None,
    ) -> None:
        self._phase = phase
        self._analysis = analysis
        self._store = store
        # Injected diagnostic seam: defaults to the core observability bus so
        # the coordinator never imports a diagnostics-layer wrapper.
        self._fact_sink: FactObservationSink = fact_sink or _CoreObservabilitySink()
        self._current_func_ea: int = -1
        self._outcome_log: ReconOutcomeLog = ReconOutcomeLog()
        self._outcome_seen: set[tuple] = set()
        self._fact_lifecycle = FactLifecycleRuntime(
            persistence_callback=self._persist_maturity_facts,
        )

    def reset_for_func(self, func_ea: int) -> bool:
        """Reset recon state -- deduplicates across managers.

        Only the first call per decompilation actually clears state.
        Subsequent calls with the same *func_ea* are no-ops.

        Returns:
            ``True`` if the reset actually fired, ``False`` if deduplicated.
        """
        if func_ea == self._current_func_ea:
            return False  # already reset for this decompilation
        # Flush previous function's outcomes if not finalized
        prev_ea = self._current_func_ea
        if prev_ea != -1:
            self._persist_outcomes(prev_ea)
        self._current_func_ea = func_ea
        self._phase.reset(func_ea=func_ea)
        self._fact_lifecycle.reset_for_func(func_ea)
        get_recon_writer(self._store.db_path).submit_sync(
            lambda store: store.clear_func(func_ea=func_ea)
        )
        self._outcome_log.reset_for_func(func_ea)
        self._outcome_seen.clear()
        logger.debug("reset_for_func: func=0x%x prev=0x%x flushed=%s", func_ea, prev_ea, prev_ea != -1)
        return True

    def mark_decompilation_finished(self) -> None:
        """Called at decompilation end -- persist outcomes, then reset guard."""
        if self._current_func_ea != -1:
            self._persist_outcomes(self._current_func_ea)
        self._current_func_ea = -1

    def _persist_outcomes(self, func_ea: int) -> None:
        """Persist consumer outcomes to store.

        Session summaries are persisted eagerly by ``analyze_and_persist``
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
            get_recon_writer(self._store.db_path).submit(
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
                func_ea, summary,
            )

    # ------------------------------------------------------------------
    # Outcome recording
    # ------------------------------------------------------------------

    @property
    def outcome_log(self) -> ReconOutcomeLog:
        """Read-only access to the outcome log."""
        return self._outcome_log

    def record_outcome(self, report: ConsumerOutcomeReport) -> None:
        """Record a consumer outcome report and log it at INFO level.

        Deduplicates: only logs once per (func_ea, consumer, verdict) to
        avoid per-block spam when gates evaluate identically on every block.
        """
        self._outcome_log.record(report)
        dedup_key = (report.func_ea, report.consumer_name, report.consumer_verdict_applied)
        if dedup_key in self._outcome_seen:
            return
        self._outcome_seen.add(dedup_key)
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
        provider_phase: ProviderPhase,
        *,
        persist_hints: bool = True,
    ) -> DeobfuscationHints:
        """Run collectors, interpret results, optionally persist hints.

        Args:
            func_ea: Function effective address.
            target: Live ``mba_t`` passed through to collectors.
            provider_phase: Current provider phase supplied by the adapter.
            persist_hints: When True, save the resulting hints to the store.

        Returns:
            DeobfuscationHints summarising the classification and recommendations.
        """
        maturity_text = str(provider_phase.friendly_provider_level)
        results = self._phase.run_microcode_collectors(
            target, func_ea=func_ea, provider_phase=provider_phase,
        )
        logger.debug(
            "collect_and_analyze: func=0x%x maturity=%s collectors_fired=%d",
            func_ea, maturity_text, len(results),
        )

        hints = self._analysis.interpret(
            func_ea=func_ea, results=results, store=self._store,
        )

        if persist_hints:
            _hints = hints
            _n_collectors = len({r.collector_name for r in results})
            writer = get_recon_writer(self._store.db_path)
            writer.submit(lambda store: store.save_hints(_hints))
            writer.submit(lambda store: store.save_session_summary(
                func_ea=func_ea,
                collectors_fired=_n_collectors,
                classification=_hints.obfuscation_type or "",
                confidence=_hints.confidence,
                inferences=list(_hints.recommended_inferences),
                suppress_rules=list(_hints.suppress_rules),
            ))
            logger.debug(
                "collect_and_analyze: persisted hints for func=0x%x type=%s conf=%.2f",
                func_ea, hints.obfuscation_type, hints.confidence,
            )

        return hints

    def capture_maturity_facts(
        self,
        target: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
        phase: str = "pre_d810",
        snapshot: "SnapshotRef | None" = None,
    ) -> FactCaptureSummary:
        """Invoke maturity fact collection.

        With the initial empty registry this is an observability hook only.
        ``snapshot`` is the SnapshotRef bound to the current capture (e.g.
        from :func:`request_capture_mba_snapshot`); the persistence
        callback emits ``observe_fact_*`` events against it.
        """
        return self._fact_lifecycle.capture(
            target,
            func_ea=func_ea,
            provider_phase=provider_phase,
            phase=phase,
            snapshot=snapshot,
        )

    def register_fact_collector(self, collector: FactCollector) -> None:
        """Register a maturity fact collector."""
        self._fact_lifecycle.register(collector)

    def validated_fact_view(self, func_ea: int, maturity: int | str) -> ValidatedFactView:
        """Return the current validated fact view for one function."""
        return self._fact_lifecycle.validated_view(func_ea, maturity)

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
            emit(FactConsumersForLatestSnapshot(
                func_ea=int(func_ea),
                consumers=tuple(consumers),
            ))
            return len(consumers)
        except Exception:
            logger.exception(
                "FACT_CONSUMERS_DROPPED func=0x%x consumers=%d reason=exception",
                func_ea,
                len(consumers),
            )
            return 0

    def _persist_maturity_facts(
        self,
        snapshot: "SnapshotRef | None",
        func_ea: int,
        observations: tuple[FactObservation, ...],
        mappings: tuple[FactMapping, ...],
        conflicts: tuple[FactConflict, ...] = (),
    ) -> None:
        """Persist collected maturity facts via the injected fact sink.

        Emits typed observation events bound to ``snapshot`` through
        :attr:`_fact_sink` (defaulting to the core observability bus); the
        diag subscriber (if installed) writes them under the corresponding
        SQLite ``snapshot_id``. When ``snapshot`` is ``None`` (no
        capture in flight or diagnostics disabled), the facts go
        nowhere -- behaviour-identical to the legacy "diag_conn is
        None" short-circuit.
        """
        if snapshot is None:
            return

        if observations:
            self._fact_sink.observe_fact_observation(snapshot, func_ea, observations)
        if mappings:
            self._fact_sink.observe_fact_mapping(snapshot, func_ea, mappings)
        if conflicts:
            self._fact_sink.observe_fact_conflict(snapshot, func_ea, conflicts)

    def analyze_and_persist(self, func_ea: int) -> DeobfuscationHints | None:
        """Run analysis on current store contents and persist hints.

        Called eagerly after each collector pass. Returns None if no
        recon results are available yet.
        """
        writer = get_recon_writer(self._store.db_path)
        writer.flush()  # ensure collector writes are visible
        results = self._store.load_all_recon_results(func_ea=func_ea)
        if not results:
            return None
        hints = self._analysis.interpret(
            func_ea=func_ea, results=results, store=self._store,
        )
        writer.submit(lambda store, h=hints: store.save_hints(h))
        # Eagerly persist session summary alongside hints so it survives
        # interrupted decompilations (plugin stop, no hxe_structural).
        _n = len({r.collector_name for r in results})
        writer.submit(lambda store, h=hints: store.save_session_summary(
            func_ea=func_ea,
            collectors_fired=_n,
            classification=h.obfuscation_type or "",
            confidence=h.confidence,
            inferences=list(h.recommended_inferences),
            suppress_rules=list(h.suppress_rules),
        ))
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
        provider_phase: ProviderPhase,
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
            provider_phase: Current provider phase supplied by the adapter.
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
            func_ea, target, provider_phase, persist_hints=persist_hints,
        )

    def apply_to_rule_scope(
        self,
        func_ea: int,
        rule_scope: RuleScopeService,
        target: Any = None,
        provider_phase: ProviderPhase | None = None,
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
        and *target* / *provider_phase* are provided, runs collectors and analysis.
        If hints are resolved, they are applied to *rule_scope* via
        ``apply_hints()``.

        Args:
            func_ea: Function effective address.
            rule_scope: Consumer rule-scope service (not stored).
            target: Live ``mba_t`` for collectors (may be ``None``).
            provider_phase: Current provider phase (may be ``None``).
            persist_hints: When True and collection runs, save resulting hints.

        Returns:
            ``ReconOutcome`` recording hints, apply result, and provenance.
        """
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
        elif target is not None and provider_phase is not None:
            hints = self.collect_and_analyze(
                func_ea, target, provider_phase, persist_hints=persist_hints,
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
                "(no cached hints and no target/provider_phase provided)",
                func_ea,
            )

        # --- 2. Apply to rule scope if we have hints ---
        apply_result = None
        if hints is not None:
            apply_result = rule_scope.apply_hints(hints)
            logger.info(
                "apply_to_rule_scope: func=0x%x applied -> "
                "inferences=%s suppressed=%s gen=%d->%d",
                func_ea,
                apply_result.inferences_applied,
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
