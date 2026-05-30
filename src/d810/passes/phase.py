"""ReconPhase orchestrator.

Manages a registry of ``ReconCollector`` instances and dispatches them to
the appropriate maturities. Results are persisted via ``ReconStore``.

No IDA imports at module level - collectors that need IDA guard their own
imports. This module is fully unit-testable.
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.provider_phase import ProviderPhase
from d810.core.typing import Any, Protocol, runtime_checkable

from d810.analyses.control_flow.models import ReconResult
from d810.passes.store import ReconStore, get_recon_writer

logger = getLogger("D810.recon.phase")

ALL_MATURITIES: frozenset[int] | None = None


@runtime_checkable
class ReconCollector(Protocol):
    """Protocol for all recon collectors.

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

    def collect(self, target: Any, func_ea: int, maturity: int) -> ReconResult:
        """Collect observations from ``target`` at ``maturity``.

        :param target: ``mba_t`` for microcode collectors, ``cfunc_t`` for ctree.
        :param func_ea: Function effective address.
        :param maturity: Current maturity level.
        :return: Immutable ``ReconResult`` with metrics and candidate flags.
        """
        ...


class ReconPhase:
    """Orchestrates ReconCollectors across microcode and ctree maturities.

    Maintains a per-function maturity guard so each collector fires at most
    once per (func_ea, maturity) pair per decompilation.

    Example:
        >>> store = ReconStore("/tmp/recon.db")
        >>> phase = ReconPhase(store=store)
        >>> phase.register(CFGShapeCollector())
        >>> phase.run_microcode_collectors(
        ...     mba, func_ea=0x401000, provider_phase=provider_phase,
        ... )
    """

    def __init__(self, store: ReconStore) -> None:
        self._store = store
        self._collectors: list[ReconCollector] = []
        # Per-function set of provider levels already processed.
        # Ctree collection uses a tagged key so microcode and ctree passes at
        # the same provider level do not block each other.
        self._fired: dict[int, set[int | tuple[int, str]]] = {}

    @property
    def collector_count(self) -> int:
        return len(self._collectors)

    def register(self, collector: ReconCollector) -> None:
        """Register a collector. Raises ValueError if already registered."""
        for existing in self._collectors:
            if existing.name == collector.name:
                raise ValueError(
                    f"ReconCollector '{collector.name}' already registered"
                )
        self._collectors.append(collector)
        logger.debug("Registered recon collector: %s", collector.name)

    @staticmethod
    def _collector_runs_at_maturity(
        collector: ReconCollector,
        maturity: int,
    ) -> bool:
        """Return True when *collector* should fire at *maturity*."""
        return collector.maturities is ALL_MATURITIES or maturity in collector.maturities

    def reset(self, *, func_ea: int) -> None:
        """Clear the maturity guard for a function (call on new decompilation)."""
        self._fired.pop(func_ea, None)

    def run_microcode_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
    ) -> list[ReconResult]:
        """Dispatch all microcode collectors registered for ``provider_phase``.

        Protected by a per-(func_ea, maturity) guard so each collector fires
        at most once per decompilation pass.

        :param target: Live ``mba_t`` (passed through to collectors).
        :param func_ea: Function EA.
        :param provider_phase: Current provider phase supplied by the adapter.
        :return: List of ``ReconResult`` produced this call (may be empty).
        """
        maturity = int(provider_phase.provider_level)
        maturity_text = str(provider_phase.friendly_provider_level)
        fired_maturities = self._fired.setdefault(func_ea, set())
        if maturity in fired_maturities:
            return []

        results: list[ReconResult] = []
        for collector in self._collectors:
            if collector.level != "microcode":
                continue
            if not self._collector_runs_at_maturity(collector, maturity):
                continue
            try:
                result = collector.collect(target, func_ea, maturity)
                writer = get_recon_writer(self._store.db_path)
                writer.submit(
                    lambda store, r=result: store.save_recon_result(r)
                )
                writer.flush()
                results.append(result)
            except Exception:
                logger.exception(
                    "ReconCollector '%s' failed at func=0x%x maturity=%s",
                    collector.name, func_ea, maturity_text,
                )

        fired_maturities.add(maturity)
        return results

    def run_ctree_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhase,
    ) -> list[ReconResult]:
        """Dispatch all ctree collectors registered for ``provider_phase``."""
        maturity = int(provider_phase.provider_level)
        maturity_text = str(provider_phase.friendly_provider_level)
        fired_maturities = self._fired.setdefault(func_ea, set())
        ctree_key = (maturity, "ctree")
        if ctree_key in fired_maturities:
            return []

        results: list[ReconResult] = []
        for collector in self._collectors:
            if collector.level != "ctree":
                continue
            if not self._collector_runs_at_maturity(collector, maturity):
                continue
            try:
                result = collector.collect(target, func_ea, maturity)
                get_recon_writer(self._store.db_path).submit(
                    lambda store, r=result: store.save_recon_result(r)
                )
                results.append(result)
            except Exception:
                logger.exception(
                    "ReconCollector '%s' (ctree) failed at func=0x%x maturity=%s",
                    collector.name, func_ea, maturity_text,
                )

        fired_maturities.add(ctree_key)
        return results
