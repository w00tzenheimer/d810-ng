"""EdgeSplitConflictResolutionStrategy — placeholder for conflict splitting.

When two strategies claim the same block (e.g., a shared exit block that two
different handler paths route through), the long-term plan is to split the
shared block symbolically. DuplicateBlock materialization is still disabled in
Phase B, so this strategy currently emits an explicit diagnostic and no plan.

This is a meta-strategy invoked by the plan-merger when it detects ownership
conflicts between other strategies' plan fragments.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.edge_split_conflict")

__all__ = ["EdgeSplitConflictResolutionStrategy"]


class EdgeSplitConflictResolutionStrategy:
    """Placeholder strategy until symbolic duplicate materialization exists.

    This strategy is invoked by the plan-merger when two strategies claim the
    same block for different redirects. The long-term plan is still symbolic
    duplication/splitting, but that path remains disabled for now.

    The conflict information is supplied via constructor arguments or via the
    snapshot's ``handler_graph`` metadata dict.  The strategy is stateless in
    its ``plan()`` method — all mutable context flows through the snapshot.
    """

    def __init__(self, conflict_blocks: set[int] | None = None) -> None:
        """Initialise with an optional pre-computed conflict set.

        Args:
            conflict_blocks: Set of block serials that have ownership conflicts.
                When None, the strategy uses the snapshot's ``handler_graph``
                to discover conflicts.
        """
        self._conflict_blocks: set[int] = conflict_blocks or set()

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "edge_split_conflict_resolution"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when conflict blocks are known or discoverable.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if there are pre-supplied conflict blocks or the snapshot
            contains conflict metadata.
        """
        if self._conflict_blocks:
            return True
        hg = snapshot.handler_graph or {}
        return bool(hg.get("conflict_blocks"))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Return no fragment while duplicate materialization remains disabled.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            ``None``. Conflict metadata is logged explicitly so the planner can
            be revisited once symbolic duplicate materialization exists.
        """
        if not self.is_applicable(snapshot):
            return None

        # Resolve conflict blocks from constructor arg or snapshot metadata.
        conflict_blocks: set[int] = set(self._conflict_blocks)
        hg = snapshot.handler_graph or {}
        extra = hg.get("conflict_blocks")
        if extra:
            conflict_blocks.update(extra)

        if not conflict_blocks:
            return None

        logger.warning(
            "EdgeSplitConflictResolutionStrategy: skipping conflict blocks %s "
            "because DuplicateBlock materialization is disabled in Phase B",
            sorted(conflict_blocks),
        )
        return None
