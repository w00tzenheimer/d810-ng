"""PreanalysisPhase orchestrator.

Manages a registry of ``PreanalysisCollector`` instances and dispatches them
to the appropriate maturities. Results are persisted via ``PreanalysisStore``.

No IDA imports at module level - collectors that need IDA guard their own
imports. This module is fully unit-testable.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.provider_phase import ProviderPhase
from d810.core.typing import Any, Protocol, runtime_checkable

from d810.analyses.control_flow.collection_context import PreanalysisCollectionContext
from d810.analyses.control_flow.models import PreanalysisResult
from d810.passes.store import PreanalysisStore, get_preanalysis_writer

logger = getLogger("D810.passes.phase")

ALL_MATURITIES: frozenset[int] | None = None


@runtime_checkable
class PreanalysisCollector(Protocol):
    """Protocol for all preanalysis collectors.

    Implementations must be read-only - they observe but never modify
    the microcode (``mba_t``) or ctree (``cfunc_t``).

    Attributes:
        name: Unique collector identifier, used as primary key in the store.
        maturities: Set of maturity levels at which this collector fires.
        level: ``"microcode"`` or ``"ctree"``.
    """

    name: str
    maturities: frozenset[int] | None
    level: str

    def collect(
        self,
        target: Any,
        context: PreanalysisCollectionContext,
    ) -> PreanalysisResult:
        """Collect observations from ``target`` at ``context``.

        :param target: ``mba_t`` for microcode collectors, ``cfunc_t`` for ctree.
        :param context: Current provider-neutral collection context.
        :return: Immutable ``PreanalysisResult`` with metrics and candidates.
        """
        ...


class PreanalysisPhase:
    """Orchestrates preanalysis collectors across microcode and ctree maturities.

    Maintains a per-function maturity guard so each collector fires at most
    once per (func_ea, maturity) pair per decompilation.

    Example:
        >>> store = PreanalysisStore("/tmp/analysis.db")
        >>> phase = PreanalysisPhase(store=store)
        >>> phase.register(CFGShapeCollector())
        >>> phase.run_microcode_collectors(
        ...     mba, func_ea=0x401000, provider_phase=provider_phase,
        ... )
    """

    def __init__(self, store: PreanalysisStore) -> None:
        self._store = store
        self._collectors: list[PreanalysisCollector] = []
        # Per-function set of provider levels already processed.
        # Ctree collection uses a tagged key so microcode and ctree passes at
        # the same provider level do not block each other.
        self._fired: dict[int, set[int | tuple[int, str]]] = {}

    @property
    def collector_count(self) -> int:
        return len(self._collectors)

    def register(self, collector: PreanalysisCollector) -> None:
        """Register a collector. Raises ValueError if already registered."""
        for existing in self._collectors:
            if existing.name == collector.name:
                raise ValueError(
                    f"PreanalysisCollector '{collector.name}' already registered"
                )
        self._collectors.append(collector)
        logger.debug("Registered preanalysis collector: %s", collector.name)

    @staticmethod
    def _collector_runs_at_provider_level(
        collector: PreanalysisCollector,
        provider_level: int,
    ) -> bool:
        """Return True when *collector* should fire at *provider_level*."""
        return (
            collector.maturities is ALL_MATURITIES
            or provider_level in collector.maturities
        )

    @staticmethod
    def _collect(
        collector: PreanalysisCollector,
        target: Any,
        context: PreanalysisCollectionContext,
    ) -> PreanalysisResult:
        try:
            return collector.collect(target, context)
        except TypeError as exc:
            if "positional" not in str(exc) and "context" not in str(exc):
                raise
            return collector.collect(  # type: ignore[misc,call-arg]
                target,
                context.func_ea,
                context.provider_level,
            )

    def reset(self, *, func_ea: int) -> None:
        """Clear the maturity guard for a function (call on new decompilation)."""
        self._fired.pop(func_ea, None)

    def run_microcode_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
    ) -> list[PreanalysisResult]:
        """Dispatch all microcode collectors registered for ``provider_phase``.

        Protected by a per-(func_ea, maturity) guard so each collector fires
        at most once per decompilation pass.

        :param target: Live ``mba_t`` (passed through to collectors).
        :param func_ea: Function EA.
        :param provider_phase: Current provider phase supplied by the adapter.
        :return: List of ``PreanalysisResult`` values (may be empty).
        """
        provider_level = int(provider_phase.provider_level)
        maturity_text = str(provider_phase.friendly_provider_level)
        fired_maturities = self._fired.setdefault(func_ea, set())
        if provider_level in fired_maturities:
            return []
        context = PreanalysisCollectionContext(
            func_ea=int(func_ea),
            provider_phase=provider_phase,
        )

        results: list[PreanalysisResult] = []
        for collector in self._collectors:
            if collector.level != "microcode":
                continue
            if not self._collector_runs_at_provider_level(collector, provider_level):
                continue
            try:
                result = self._collect(collector, target, context)
                writer = get_preanalysis_writer(self._store.db_path)
                writer.submit(lambda store, r=result: store.save_preanalysis_result(r))
                writer.flush()
                results.append(result)
            except Exception:
                logger.exception(
                    "PreanalysisCollector '%s' failed at func=0x%x maturity=%s",
                    collector.name,
                    func_ea,
                    maturity_text,
                )

        fired_maturities.add(provider_level)
        return results

    def run_ctree_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
    ) -> list[PreanalysisResult]:
        """Dispatch all ctree collectors registered for ``provider_phase``."""
        provider_level = int(provider_phase.provider_level)
        maturity_text = str(provider_phase.friendly_provider_level)
        fired_maturities = self._fired.setdefault(func_ea, set())
        ctree_key = (provider_level, "ctree")
        if ctree_key in fired_maturities:
            return []
        context = PreanalysisCollectionContext(
            func_ea=int(func_ea),
            provider_phase=provider_phase,
        )

        results: list[PreanalysisResult] = []
        for collector in self._collectors:
            if collector.level != "ctree":
                continue
            if not self._collector_runs_at_provider_level(collector, provider_level):
                continue
            try:
                result = self._collect(collector, target, context)
                get_preanalysis_writer(self._store.db_path).submit(
                    lambda store, r=result: store.save_preanalysis_result(r)
                )
                results.append(result)
            except Exception:
                logger.exception(
                    "PreanalysisCollector '%s' (ctree) failed at func=0x%x maturity=%s",
                    collector.name,
                    func_ea,
                    maturity_text,
                )

        fired_maturities.add(ctree_key)
        return results
