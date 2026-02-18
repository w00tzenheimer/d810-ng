"""ReconPhase orchestrator.

Manages a registry of ``ReconCollector`` instances and dispatches them to
the appropriate maturities. Results are persisted via ``ReconStore``.

No IDA imports at module level - collectors that need IDA guard their own
imports. This module is fully unit-testable.
"""
from __future__ import annotations

import logging
from d810.core.typing import Any, Protocol, runtime_checkable

from d810.recon.models import ReconResult
from d810.recon.store import ReconStore

logger = logging.getLogger("D810.recon.phase")


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
    maturities: frozenset[int]
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
        >>> phase.run_microcode_collectors(mba, func_ea=0x401000, maturity=5)
    """

    def __init__(self, store: ReconStore) -> None:
        self._store = store
        self._collectors: list[ReconCollector] = []
        # Per-function set of maturities already processed.
        # Key: func_ea, Value: set of maturity ints already fired.
        self._fired: dict[int, set[int]] = {}

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

    def reset(self, *, func_ea: int) -> None:
        """Clear the maturity guard for a function (call on new decompilation)."""
        self._fired.pop(func_ea, None)

    def run_microcode_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
    ) -> list[ReconResult]:
        """Dispatch all microcode collectors registered for ``maturity``.

        Protected by a per-(func_ea, maturity) guard so each collector fires
        at most once per decompilation pass.

        :param target: Live ``mba_t`` (passed through to collectors).
        :param func_ea: Function EA.
        :param maturity: Current microcode maturity level.
        :return: List of ``ReconResult`` produced this call (may be empty).
        """
        fired_maturities = self._fired.setdefault(func_ea, set())
        if maturity in fired_maturities:
            return []

        results: list[ReconResult] = []
        for collector in self._collectors:
            if collector.level != "microcode":
                continue
            if maturity not in collector.maturities:
                continue
            try:
                result = collector.collect(target, func_ea, maturity)
                self._store.save_recon_result(result)
                results.append(result)
            except Exception:
                logger.exception(
                    "ReconCollector '%s' failed at func=0x%x maturity=%d",
                    collector.name, func_ea, maturity,
                )

        fired_maturities.add(maturity)
        return results

    def run_ctree_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
    ) -> list[ReconResult]:
        """Dispatch all ctree collectors registered for ``maturity``."""
        fired_maturities = self._fired.setdefault(func_ea, set())
        ctree_key = (maturity, "ctree")
        if ctree_key in fired_maturities:  # type: ignore[operator]
            return []

        results: list[ReconResult] = []
        for collector in self._collectors:
            if collector.level != "ctree":
                continue
            if maturity not in collector.maturities:
                continue
            try:
                result = collector.collect(target, func_ea, maturity)
                self._store.save_recon_result(result)
                results.append(result)
            except Exception:
                logger.exception(
                    "ReconCollector '%s' (ctree) failed at func=0x%x maturity=%d",
                    collector.name, func_ea, maturity,
                )

        fired_maturities.add(ctree_key)  # type: ignore[arg-type]
        return results
