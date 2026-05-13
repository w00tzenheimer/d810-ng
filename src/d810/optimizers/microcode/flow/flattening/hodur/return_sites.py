"""Hodur-specific return site provider.

Extracts expected return sites from Hodur's analysis data
(handler path results, BST analysis, state machine) and provides
them in the generic ReturnSite format for frontier audit.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.cfg.flow.return_frontier import ReturnSite
from d810.recon.flow.return_sites import (
    compute_legacy_return_site_guard_hash,
    compute_transition_row_guard_hash,
    legacy_handler_path_return_sites,
    transition_report_return_sites,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
        DispatcherStateMachine,
        HandlerPathResult,
    )
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import AnalysisSnapshot
    from d810.recon.flow.transition_report import (
        DispatcherTransitionReport,
        TransitionRow,
    )

logger = logging.getLogger(__name__)


__all__ = ["HodurReturnSiteProvider"]


def _compute_guard_hash_from_row(row: "TransitionRow") -> str:
    """Compute stable hash for matching sites across pipeline stages.

    Args:
        row: A TransitionRow from the dispatcher transition report.

    Returns:
        First 16 hex characters of the SHA-256 digest.
    """
    return compute_transition_row_guard_hash(row)


class HodurReturnSiteProvider:
    """Extracts return sites from Hodur analysis data.

    Return sites are handler paths that terminate at function exits
    (m_ret blocks, stop blocks) rather than transitioning to another handler.
    """

    def collect_return_sites(
        self,
        report: "DispatcherTransitionReport",
    ) -> tuple[ReturnSite, ...]:
        """Build one ReturnSite per EXIT handler in the transition report.

        Uses strict mode: only TransitionKind.EXIT rows produce sites.

        Args:
            report: Dispatcher transition report with classified rows.

        Returns:
            Tuple of ReturnSite, sorted by (origin_block, site_id).
        """
        sites = transition_report_return_sites(report)

        logger.info(
            "HodurReturnSiteProvider: collected %d return sites from transition report "
            "(%d total rows)",
            len(sites),
            len(report.rows),
        )
        return tuple(sites)

    def collect_return_sites_legacy(
        self,
        snapshot: "AnalysisSnapshot",
        handler_paths: "dict[int, list[HandlerPathResult]]",
    ) -> tuple[ReturnSite, ...]:
        """Extract return sites from Hodur handler path analysis (legacy API).

        A return site is a handler path where:
        - ``final_state`` is ``None`` (terminal path, doesn't transition to
          another handler)
        - The exit block has 0 successors (m_ret/stop) or flows to function exit

        Args:
            snapshot: Current analysis snapshot with state machine, BST info.
            handler_paths: Mapping of handler entry serial to list of evaluated
                paths for that handler.

        Returns:
            Tuple of :class:`ReturnSite` descriptors, deduplicated by exit block.
        """
        sites = legacy_handler_path_return_sites(handler_paths)

        logger.info(
            "HodurReturnSiteProvider: collected %d return sites from %d handlers",
            len(sites),
            len(handler_paths),
        )
        return tuple(sites)

    @staticmethod
    def _compute_guard_hash_legacy(
        entry_serial: int,
        path: "HandlerPathResult",
    ) -> str:
        """Compute a stable hash for matching return sites across stages (legacy).

        Uses entry serial + exit block + state writes as the discriminator.

        Args:
            entry_serial: Serial of the handler entry block.
            path: The evaluated handler path result.

        Returns:
            First 16 hex characters of the SHA-256 digest.
        """
        return compute_legacy_return_site_guard_hash(entry_serial, path)

    # Keep old name as alias for existing callers during transition
    @staticmethod
    def _compute_guard_hash(
        entry_serial: int,
        path: "HandlerPathResult",
    ) -> str:
        """Alias for _compute_guard_hash_legacy — kept for backward compatibility."""
        return compute_legacy_return_site_guard_hash(entry_serial, path)
