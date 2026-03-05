"""Hodur-specific return site provider.

Extracts expected return sites from Hodur's analysis data
(handler path results, BST analysis, state machine) and provides
them in the generic ReturnSite format for frontier audit.
"""
from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

from d810.cfg.flow.return_frontier import ReturnSite

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
        HandlerPathResult,
        HodurStateMachine,
    )
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import AnalysisSnapshot

logger = logging.getLogger(__name__)


__all__ = ["HodurReturnSiteProvider"]


class HodurReturnSiteProvider:
    """Extracts return sites from Hodur analysis data.

    Return sites are handler paths that terminate at function exits
    (m_ret blocks, stop blocks) rather than transitioning to another handler.
    """

    def collect_return_sites(
        self,
        snapshot: AnalysisSnapshot,
        handler_paths: dict[int, list[HandlerPathResult]],
    ) -> tuple[ReturnSite, ...]:
        """Extract return sites from Hodur handler path analysis.

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
        sites: list[ReturnSite] = []
        seen_blocks: set[int] = set()

        for entry_serial, paths in handler_paths.items():
            for i, path in enumerate(paths):
                if path.final_state is not None:
                    continue  # Not a terminal path

                exit_block = path.exit_block
                if exit_block in seen_blocks:
                    continue
                seen_blocks.add(exit_block)

                guard_hash = self._compute_guard_hash(entry_serial, path)

                site = ReturnSite(
                    site_id=f"hodur_ret_{entry_serial}_{exit_block}",
                    origin_block=exit_block,
                    guard_hash=guard_hash,
                    expected_terminal_kind="return",
                    provenance=f"handler_{entry_serial}_path_{i}",
                )
                sites.append(site)

        logger.info(
            "HodurReturnSiteProvider: collected %d return sites from %d handlers",
            len(sites),
            len(handler_paths),
        )
        return tuple(sites)

    @staticmethod
    def _compute_guard_hash(
        entry_serial: int,
        path: HandlerPathResult,
    ) -> str:
        """Compute a stable hash for matching return sites across stages.

        Uses entry serial + exit block + state writes as the discriminator.

        Args:
            entry_serial: Serial of the handler entry block.
            path: The evaluated handler path result.

        Returns:
            First 16 hex characters of the SHA-256 digest.
        """
        parts = [str(entry_serial), str(path.exit_block)]
        for write in path.state_writes:
            parts.append(str(write))
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
