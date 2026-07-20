"""Raw preanalysis collection, deduplication, and persistence authority.

This runtime owns the stage-local collector phase and maturity-fact runtime.
It accepts only portable targets and provider metadata; it never derives
consumer hints, activates rules, or mutates microcode.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.decompilation_session import DecompilationSessionEvent
from d810.core.logging import getLogger
from d810.core.observability import emit as _emit
from d810.core.observability_events import (
    FactConflictsObserved,
    FactMappingsObserved,
    FactObservationsObserved,
)
from d810.core.provider_phase import ProviderPhase
from d810.core.typing import Any, Protocol, TYPE_CHECKING
from d810.passes.fact_runtime import (
    FactCaptureSummary,
    FactCollector,
    PreanalysisFactRuntime,
)
from d810.passes.phase import PreanalysisPhase
from d810.passes.store import PreanalysisStore, get_preanalysis_writer

if TYPE_CHECKING:
    from d810.analyses.value_flow.model import (
        FactConflict,
        FactMapping,
        FactObservation,
        ValidatedFactView,
    )
    from d810.core.observability import SnapshotRef

logger = getLogger("D810.passes.preanalysis.runtime")


class FactObservationSink(Protocol):
    """Narrow diagnostic sink for collected maturity facts."""

    def observe_fact_observation(
        self, snapshot: "SnapshotRef", func_ea: int, observations: tuple
    ) -> None: ...

    def observe_fact_mapping(
        self, snapshot: "SnapshotRef", func_ea: int, mappings: tuple
    ) -> None: ...

    def observe_fact_conflict(
        self, snapshot: "SnapshotRef", func_ea: int, conflicts: tuple
    ) -> None: ...


class CoreFactObservationSink:
    """Publish fact diagnostics on the core observability bus."""

    @staticmethod
    def observe_fact_observation(
        snapshot: "SnapshotRef", func_ea: int, observations: tuple
    ) -> None:
        _emit(
            FactObservationsObserved(
                snapshot=snapshot,
                func_ea=int(func_ea),
                observations=tuple(observations),
            )
        )

    @staticmethod
    def observe_fact_mapping(
        snapshot: "SnapshotRef", func_ea: int, mappings: tuple
    ) -> None:
        _emit(
            FactMappingsObserved(
                snapshot=snapshot,
                func_ea=int(func_ea),
                mappings=tuple(mappings),
            )
        )

    @staticmethod
    def observe_fact_conflict(
        snapshot: "SnapshotRef", func_ea: int, conflicts: tuple
    ) -> None:
        _emit(
            FactConflictsObserved(
                snapshot=snapshot,
                func_ea=int(func_ea),
                conflicts=tuple(conflicts),
            )
        )


@dataclass(slots=True)
class PreanalysisRuntime:
    """Own raw collection and fact persistence for decompilation sessions."""

    phase: PreanalysisPhase
    store: PreanalysisStore
    fact_sink: FactObservationSink = field(
        default_factory=CoreFactObservationSink
    )
    _facts: PreanalysisFactRuntime = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._facts = PreanalysisFactRuntime(
            persistence_callback=self._persist_maturity_facts,
        )

    @property
    def fact_collector_count(self) -> int:
        return self._facts.collector_count

    def begin_session(self, event: DecompilationSessionEvent) -> None:
        """Reset raw evidence for one newly-created top-level session."""
        func_ea = int(event.function_ea)
        self.phase.reset(func_ea=func_ea)
        self._facts.reset_for_func(func_ea)
        get_preanalysis_writer(self.store.db_path).submit_sync(
            lambda store: store.clear_func(func_ea=func_ea)
        )

    def finish_session(self, event: DecompilationSessionEvent) -> None:
        """Finish a session without retaining callback-local objects."""
        del event

    def register_fact_collector(self, collector: FactCollector) -> None:
        self._facts.register(collector)

    def capture_flowgraph(
        self,
        flow_graph: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
        snapshot: "SnapshotRef | None" = None,
    ) -> FactCaptureSummary:
        """Capture portable graph collectors, then maturity facts."""
        try:
            self.phase.run_microcode_collectors(
                flow_graph,
                func_ea=int(func_ea),
                provider_phase=provider_phase,
            )
        except Exception:
            logger.exception(
                "preanalysis flowgraph collection failed for func=0x%x maturity=%s",
                int(func_ea),
                provider_phase.friendly_provider_level,
            )
        return self.capture_facts(
            flow_graph,
            func_ea=int(func_ea),
            provider_phase=provider_phase,
            phase="pre_d810",
            snapshot=snapshot,
        )

    def capture_ctree(
        self,
        cfunc: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
    ) -> None:
        self.phase.run_ctree_collectors(
            cfunc,
            func_ea=int(func_ea),
            provider_phase=provider_phase,
        )

    def capture_facts(
        self,
        target: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
        phase: str,
        snapshot: "SnapshotRef | None" = None,
    ) -> FactCaptureSummary:
        return self._facts.capture(
            target,
            func_ea=int(func_ea),
            provider_phase=provider_phase,
            phase=str(phase),
            snapshot=snapshot,
        )

    def _validated_fact_view(
        self,
        func_ea: int,
        provider_level: int | str,
    ) -> "ValidatedFactView":
        return self._facts.validated_view(int(func_ea), provider_level)

    def _persist_maturity_facts(
        self,
        snapshot: "SnapshotRef | None",
        func_ea: int,
        observations: tuple["FactObservation", ...],
        mappings: tuple["FactMapping", ...],
        conflicts: tuple["FactConflict", ...] = (),
    ) -> None:
        if snapshot is None:
            return
        if observations:
            self.fact_sink.observe_fact_observation(
                snapshot, int(func_ea), observations
            )
        if mappings:
            self.fact_sink.observe_fact_mapping(snapshot, int(func_ea), mappings)
        if conflicts:
            self.fact_sink.observe_fact_conflict(
                snapshot, int(func_ea), conflicts
            )


__all__ = [
    "CoreFactObservationSink",
    "FactObservationSink",
    "PreanalysisRuntime",
]
