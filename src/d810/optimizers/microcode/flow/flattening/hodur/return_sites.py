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
    h = hashlib.sha256()
    h.update(str(row.handler_serial).encode())
    if row.state_const is not None:
        h.update(str(row.state_const).encode())
    if row.chain_preview:
        for blk in row.chain_preview:
            h.update(str(blk).encode())
    return h.hexdigest()[:16]


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
        from d810.recon.flow.transition_report import TransitionKind

        sites: list[ReturnSite] = []
        seen_ids: set[str] = set()

        for row in report.rows:
            # 1) Candidate selection
            # Require both EXIT classification AND confirmed exit block reachability.
            is_terminal_candidate = (
                row.kind == TransitionKind.EXIT
                and row.path.reaches_exit_block
            )

            # Optional debug mode (include uncertain terminals to investigate):
            # is_terminal_candidate = (
            #     row.kind in {TransitionKind.EXIT, TransitionKind.UNKNOWN}
            #     or (row.path is not None and row.path.reaches_exit_block)
            # )

            if not is_terminal_candidate:
                continue

            # 2) Stable per-handler identity (NO dedup by shared exit block)
            if row.state_const is not None:
                state_tag = f"{row.state_const:08x}"
            elif row.state_range_lo is not None and row.state_range_hi is not None:
                state_tag = f"range_{row.state_range_lo:08x}_{row.state_range_hi:08x}"
            else:
                state_tag = "unknown"
            site_id = f"hodur_handler_{row.handler_serial}_state_{state_tag}"

            if site_id in seen_ids:
                continue
            seen_ids.add(site_id)

            # 3) Origin must be handler entry, not shared m_ret/stop block
            origin_block = row.handler_serial

            # 4) Keep witness chain as metadata for localization
            metadata = {
                "dispatcher_entry": report.dispatcher_entry_serial,
                "state_const": row.state_const,
                "state_range_lo": row.state_range_lo,
                "state_range_hi": row.state_range_hi,
                "transition_kind": row.kind.name,
                "transition_label": row.transition_label,
                "path_chain": list(row.path.chain),
                "path_back_edge": row.path.back_edge,
                "path_reaches_exit_block": row.path.reaches_exit_block,
                "path_classified_exit": row.path.classified_exit,
                "path_unresolved": row.path.unresolved,
            }

            sites.append(
                ReturnSite(
                    site_id=site_id,
                    origin_block=origin_block,
                    expected_terminal_kind="return",
                    metadata=metadata,
                )
            )

        # 5) Deterministic order
        sites.sort(key=lambda s: (s.origin_block, s.site_id))

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

                guard_hash = self._compute_guard_hash_legacy(entry_serial, path)

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
        parts = [str(entry_serial), str(path.exit_block)]
        for write in path.state_writes:
            parts.append(str(write))
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # Keep old name as alias for existing callers during transition
    @staticmethod
    def _compute_guard_hash(
        entry_serial: int,
        path: "HandlerPathResult",
    ) -> str:
        """Alias for _compute_guard_hash_legacy — kept for backward compatibility."""
        parts = [str(entry_serial), str(path.exit_block)]
        for write in path.state_writes:
            parts.append(str(write))
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
