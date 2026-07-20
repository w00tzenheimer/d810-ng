"Return frontier preanalysis collector.\n\nGeneric collector that audits return site preservation across\nunflattening pipeline stages. Consumes return_sites and planned_mods\nfrom FlowGraph metadata (populated by the active unflattener).\n\nIMPORTANT: This collector is generic \u2014 it must NOT import any\nunflattener-specific code (no hodur imports).\n"
from __future__ import annotations

import json
import time
from pathlib import Path
from types import MappingProxyType
from d810.core.logging import getLogger
from d810.core.typing import Any

from d810.analyses.control_flow.collection_context import (
    PreanalysisCollectionContext,
    coerce_preanalysis_collection_context,
)
from d810.analyses.control_flow.return_frontier import (
    ReturnFrontierAudit,
    ReturnSite,
    ReturnSiteStatus,
)
from d810.analyses.control_flow.models import CandidateFlag, PreanalysisResult

logger = getLogger(__name__)


class ReturnFrontierCollector:
    "Preanalysis collector for return frontier audit.\n\n    Satisfies PreanalysisCollector protocol structurally.\n\n    Expected FlowGraph metadata keys:\n        - \"return_sites\": tuple[ReturnSite, ...]\n        - \"cfg_successors\": Mapping[int, Sequence[int]]\n        - \"cfg_entry\": int\n        - \"cfg_exits\": frozenset[int]\n        - \"stage_name\": str (current pipeline stage)\n    "

    name: str = "return_frontier"
    # ``None`` == "fire at all maturities" (the PreanalysisPhase ALL_MATURITIES
    # sentinel is itself ``None``). The phase id/maturity reaches collect()
    # as an int arg, so this collector no longer imports the orchestrator.
    maturities: frozenset[int] | None = None
    level: str = "microcode"

    def __init__(self) -> None:
        self._audit: ReturnFrontierAudit | None = None
        self._artifact_dir = Path(".tmp/preanalysis")

    @classmethod
    def build_result_from_audit(
        cls,
        audit: ReturnFrontierAudit,
        *,
        func_ea: int,
        provider_level: int,
        timestamp: float | None = None,
        stage_results: tuple[ReturnSiteStatus, ...] | None = None,
    ) -> PreanalysisResult:
        "Persist the latest audit state as a preanalysis result."
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
        return PreanalysisResult(
            collector_name=cls.name,
            func_ea=func_ea,
            provider_level=provider_level,
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
        self,
        target: Any,
        context: PreanalysisCollectionContext | None = None,
        func_ea: int | None = None,
        **legacy_fields: object,
    ) -> PreanalysisResult:
        "Collect return frontier audit data.\n\n        ``target`` is expected to be a FlowGraph (or any object with\n        a ``metadata`` mapping containing the required keys).\n\n        Called once per stage by the unflattener after populating metadata.\n\n        :param target: Object with a ``metadata`` mapping.\n        :param func_ea: Function effective address.\n        :param maturity: Current maturity level.\n        :return: Frozen ``PreanalysisResult`` with return frontier metrics.\n        "
        context = coerce_preanalysis_collection_context(
            context,
            func_ea=func_ea,
            legacy_fields=legacy_fields,
        )
        metadata = getattr(target, "metadata", {})

        return_sites = metadata.get("return_sites", ())
        successors = metadata.get("cfg_successors")
        entry = metadata.get("cfg_entry")
        exits = metadata.get("cfg_exits", frozenset())
        stage_name = metadata.get("stage_name", "unknown")

        if not return_sites or successors is None or entry is None:
            return PreanalysisResult(
                collector_name=self.name,
                func_ea=context.func_ea,
                provider_level=context.provider_level,
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
            func_ea=context.func_ea,
            provider_level=context.provider_level,
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
