"""Return frontier audit engine.

Identifies at which pipeline stage each expected return site
loses postdomination by a function exit, enabling precise
diagnosis of structural quality regressions.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from d810.cfg.postdominator import compute_postdom_tree

logger = logging.getLogger(__name__)

__all__ = [
    "ReturnSite",
    "ReturnSiteStatus",
    "BreakKind",
    "ReturnFrontierAudit",
]


@dataclass(frozen=True)
class ReturnSite:
    """Descriptor for an expected function return / exit point.

    Attributes:
        site_id: Unique identifier for this return site.
        origin_block: Block serial where the return occurs (handler entry serial
            when built from a transition report).
        expected_terminal_kind: One of ``"return"``, ``"exit"``, ``"noreturn"``.
        guard_hash: Stable hash for matching sites across pipeline stages.
        provenance: Human-readable source (e.g. which analysis produced this).
        metadata: Arbitrary key/value metadata attached by the provider.
    """

    site_id: str
    origin_block: int
    expected_terminal_kind: str  # "return", "exit", "noreturn"
    guard_hash: str = ""
    provenance: str = ""
    metadata: dict = field(default_factory=dict, hash=False, compare=False)


@dataclass(frozen=True)
class ReturnSiteStatus:
    """Status of a return site at a given audit stage."""

    site: ReturnSite
    stage: str
    reachable_from_entry: bool
    postdominated_by_exit: bool
    break_classification: str  # see BreakKind
    detail: str = ""


class BreakKind:
    """Classification of why a return site was lost."""

    INTACT = "intact"
    COALESCE_DROP = "coalesce_drop"
    EDGE_CONFLICT = "edge_conflict"
    APPLY_FAILURE = "apply_failure"
    LATER_PASS_REWRITE = "later_pass_rewrite"
    LOST_POSTDOM = "lost_postdom"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


@dataclass
class ReturnFrontierAudit:
    """Tracks return site status across pipeline stages.

    Usage:
        audit = ReturnFrontierAudit(return_sites)
        audit.record_stage("pre_plan", successors, entry, exits)
        audit.record_stage("post_plan", successors, entry, exits)
        audit.record_stage("post_apply", successors, entry, exits)
        audit.record_stage("post_pipeline", successors, entry, exits)
        report = audit.report()
    """

    return_sites: tuple[ReturnSite, ...]
    _stage_results: dict[str, list[ReturnSiteStatus]] = field(
        default_factory=dict, init=False
    )

    def record_stage(
        self,
        stage_name: str,
        successors: Mapping[int, Sequence[int]],
        entry: int,
        exits: frozenset[int],
    ) -> list[ReturnSiteStatus]:
        """Audit all return sites against the current CFG state.

        Args:
            stage_name: One of "pre_plan", "post_plan", "post_apply", "post_pipeline"
            successors: node -> list of successor nodes
            entry: entry node serial
            exits: set of exit/return node serials

        Returns:
            List of ReturnSiteStatus for this stage.
        """
        tree = compute_postdom_tree(successors, entry, exits)
        reachable = self._bfs_reachable(successors, entry)

        results: list[ReturnSiteStatus] = []
        for site in self.return_sites:
            is_reachable = site.origin_block in reachable
            is_postdom = False
            if is_reachable and site.origin_block in successors:
                is_postdom = any(
                    tree.postdominates(ex, site.origin_block) for ex in exits
                )

            classification = self._classify(
                site, stage_name, is_reachable, is_postdom
            )

            status = ReturnSiteStatus(
                site=site,
                stage=stage_name,
                reachable_from_entry=is_reachable,
                postdominated_by_exit=is_postdom,
                break_classification=classification,
                detail=self._detail(site, stage_name, is_reachable, is_postdom),
            )
            results.append(status)

        self._stage_results[stage_name] = results
        return results

    def first_break_stage(self, site_id: str) -> str | None:
        """Return the first stage where a site lost postdomination or reachability."""
        for stage_name, results in self._stage_results.items():
            for status in results:
                if status.site.site_id == site_id:
                    if status.break_classification != BreakKind.INTACT:
                        return stage_name
        return None

    def report(self) -> dict:
        """Generate JSON-serializable audit report."""
        stages = list(self._stage_results.keys())
        site_reports: list[dict] = []
        for site in self.return_sites:
            site_data: dict = {
                "site_id": site.site_id,
                "origin_block": site.origin_block,
                "expected_terminal_kind": site.expected_terminal_kind,
                "provenance": site.provenance,
                "first_break_stage": self.first_break_stage(site.site_id),
                "stages": {},
            }
            for stage_name, results in self._stage_results.items():
                for status in results:
                    if status.site.site_id == site.site_id:
                        site_data["stages"][stage_name] = {
                            "reachable": status.reachable_from_entry,
                            "postdominated": status.postdominated_by_exit,
                            "classification": status.break_classification,
                            "detail": status.detail,
                        }
            site_reports.append(site_data)

        return {
            "stages_audited": stages,
            "total_sites": len(self.return_sites),
            "intact_count": sum(
                1 for s in site_reports if s["first_break_stage"] is None
            ),
            "broken_count": sum(
                1 for s in site_reports if s["first_break_stage"] is not None
            ),
            "sites": site_reports,
        }

    def summary_log(self) -> None:
        """Log a concise summary of the audit."""
        report = self.report()
        logger.info(
            "RETURN_FRONTIER_AUDIT: %d sites, %d intact, %d broken",
            report["total_sites"],
            report["intact_count"],
            report["broken_count"],
        )
        for site in report["sites"]:
            if site["first_break_stage"]:
                logger.info(
                    "  BREAK: site=%s origin_blk=%d first_break=%s",
                    site["site_id"],
                    site["origin_block"],
                    site["first_break_stage"],
                )

    @staticmethod
    def _bfs_reachable(
        successors: Mapping[int, Sequence[int]], start: int
    ) -> frozenset[int]:
        """BFS reachability from start node."""
        visited: set[int] = set()
        queue = [start]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            for succ in successors.get(node, ()):
                if succ not in visited:
                    queue.append(succ)
        return frozenset(visited)

    def _classify(
        self,
        site: ReturnSite,
        stage: str,
        reachable: bool,
        postdom: bool,
    ) -> str:
        """Classify the break type by comparing with previous stage."""
        if not reachable:
            return BreakKind.NOT_REACHABLE
        if postdom:
            return BreakKind.INTACT

        # Check if it was intact in previous stage
        stages = list(self._stage_results.keys())
        if not stages:
            return BreakKind.LOST_POSTDOM

        prev_stage = stages[-1]  # Most recent recorded stage before current
        prev_results = self._stage_results.get(prev_stage, [])
        for prev in prev_results:
            if prev.site.site_id == site.site_id:
                if prev.break_classification == BreakKind.INTACT:
                    # Was intact, now broken — classify by stage
                    if stage == "post_plan":
                        return BreakKind.COALESCE_DROP
                    elif stage == "post_apply":
                        return BreakKind.APPLY_FAILURE
                    elif stage == "post_pipeline":
                        return BreakKind.LATER_PASS_REWRITE
                    return BreakKind.LOST_POSTDOM
                else:
                    # Already broken in previous stage — propagate classification
                    return prev.break_classification

        return BreakKind.UNKNOWN

    def _detail(
        self,
        site: ReturnSite,
        stage: str,
        reachable: bool,
        postdom: bool,
    ) -> str:
        if not reachable:
            return f"blk[{site.origin_block}] not reachable from entry at {stage}"
        if not postdom:
            return (
                f"blk[{site.origin_block}] not postdominated by any exit at {stage}"
            )
        return ""
