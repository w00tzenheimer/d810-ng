"""Return frontier recon collector.

Generic collector that audits return site preservation across
unflattening pipeline stages. Consumes return_sites and planned_mods
from FlowGraph metadata (populated by the active unflattener).

IMPORTANT: This collector is generic — it must NOT import any
unflattener-specific code (no hodur imports).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import MappingProxyType
from d810.core.logging import getLogger
from d810.core.typing import Any

from d810.cfg.flow.return_frontier import (
    ReturnFrontierAudit,
    ReturnSite,
    ReturnSiteStatus,
)
from d810.recon.models import CandidateFlag, ReconResult
from d810.recon.phase import ALL_MATURITIES

logger = getLogger(__name__)


class ReturnFrontierCollector:
    """Recon collector for return frontier audit.

    Satisfies ReconCollector protocol structurally.

    Expected FlowGraph metadata keys:
        - "return_sites": tuple[ReturnSite, ...]
        - "cfg_successors": Mapping[int, Sequence[int]]
        - "cfg_entry": int
        - "cfg_exits": frozenset[int]
        - "stage_name": str (current pipeline stage)
    """

    name: str = "return_frontier"
    maturities: frozenset[int] | None = ALL_MATURITIES
    level: str = "microcode"

    def __init__(self) -> None:
        self._audit: ReturnFrontierAudit | None = None
        self._artifact_dir = Path(".tmp/recon")

    @classmethod
    def build_result_from_audit(
        cls,
        audit: ReturnFrontierAudit,
        *,
        func_ea: int,
        maturity: int,
        timestamp: float | None = None,
        stage_results: tuple[ReturnSiteStatus, ...] | None = None,
    ) -> ReconResult:
        """Persist the latest audit state as a recon result."""
        latest_results = stage_results
        if latest_results is None and audit._stage_results:
            latest_results = tuple(next(reversed(audit._stage_results.values())))
        elif latest_results is None:
            latest_results = ()

        candidates: list[CandidateFlag] = []
        for status in latest_results:
            if status.break_classification != "intact":
                candidates.append(
                    CandidateFlag(
                        kind=f"return_break_{status.break_classification}",
                        block_serial=status.site.origin_block,
                        confidence=0.9,
                        detail=(
                            f"site={status.site.site_id} "
                            f"stage={status.stage} "
                            f"reachable={status.reachable_from_entry} "
                            f"postdom={status.postdominated_by_exit}"
                        ),
                    )
                )

        report = audit.report()
        return ReconResult(
            collector_name=cls.name,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time() if timestamp is None else timestamp,
            metrics=MappingProxyType({
                "total_sites": report["total_sites"],
                "intact_count": report["intact_count"],
                "broken_count": report["broken_count"],
                "stages_audited": len(report["stages_audited"]),
                "audit_report": report,
            }),
            candidates=tuple(candidates),
        )

    def collect(
        self, target: Any, func_ea: int, maturity: int
    ) -> ReconResult:
        """Collect return frontier audit data.

        ``target`` is expected to be a FlowGraph (or any object with
        a ``metadata`` mapping containing the required keys).

        Called once per stage by the unflattener after populating metadata.

        :param target: Object with a ``metadata`` mapping.
        :param func_ea: Function effective address.
        :param maturity: Current maturity level.
        :return: Frozen ``ReconResult`` with return frontier metrics.
        """
        metadata = getattr(target, "metadata", {})

        return_sites = metadata.get("return_sites", ())
        successors = metadata.get("cfg_successors")
        entry = metadata.get("cfg_entry")
        exits = metadata.get("cfg_exits", frozenset())
        stage_name = metadata.get("stage_name", "unknown")

        if not return_sites or successors is None or entry is None:
            return ReconResult(
                collector_name=self.name,
                func_ea=func_ea,
                maturity=maturity,
                timestamp=time.time(),
                metrics=MappingProxyType({}),
                candidates=(),
            )

        # Initialize audit on first call
        if self._audit is None:
            self._audit = ReturnFrontierAudit(return_sites=return_sites)

        # Record this stage
        results = self._audit.record_stage(
            stage_name=stage_name,
            successors=successors,
            entry=entry,
            exits=exits,
        )

        return self.build_result_from_audit(
            self._audit,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time(),
            stage_results=tuple(results),
        )

    def write_artifact(self, func_ea: int) -> Path | None:
        """Write JSON audit artifact. Call after all stages recorded.

        :param func_ea: Function effective address (used to name the file).
        :return: Path to the written file, or ``None`` if no audit recorded.
        """
        if self._audit is None:
            return None

        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        path = self._artifact_dir / f"{func_ea:#x}_return_frontier_audit.json"

        report = self._audit.report()
        path.write_text(json.dumps(report, indent=2))

        logger.info("Return frontier audit written to %s", path)
        return path

    def reset(self) -> None:
        """Reset for next function."""
        self._audit = None
