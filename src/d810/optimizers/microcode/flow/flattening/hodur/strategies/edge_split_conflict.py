"""EdgeSplitConflictResolutionStrategy — resolve ownership conflicts via block duplication.

When two strategies claim the same block (e.g., a shared exit block that two
different handler paths route through), this strategy proposes a BLOCK_DUPLICATE
edit to split the shared block so each strategy can modify its own copy.

This is a meta-strategy invoked by the plan-merger when it detects ownership
conflicts between other strategies' plan fragments.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    EditType,
    OwnershipScope,
    PlanFragment,
    ProposedEdit,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.edge_split_conflict")

__all__ = ["EdgeSplitConflictResolutionStrategy"]


class EdgeSplitConflictResolutionStrategy:
    """Propose BLOCK_DUPLICATE edits to resolve shared-block ownership conflicts.

    This strategy is invoked by the plan-merger when two strategies claim the
    same block for different redirects.  Rather than letting the first claimant
    win silently, it proposes block duplication so both strategies can redirect
    their own copy of the block.

    The conflict information is supplied via constructor arguments or via the
    snapshot's ``handler_graph`` metadata dict.  The strategy is stateless in
    its ``plan()`` method — all mutable context flows through the snapshot.
    """

    def __init__(self, conflict_blocks: set[int] | None = None) -> None:
        """Initialise with an optional pre-computed conflict set.

        Args:
            conflict_blocks: Set of block serials that have ownership conflicts.
                When provided, ``plan()`` generates BLOCK_DUPLICATE edits for
                each block.  When None, the strategy uses the snapshot's
                ``handler_graph`` to discover conflicts.
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
        """Produce a PlanFragment with BLOCK_DUPLICATE edits for conflict blocks.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with BLOCK_DUPLICATE edits, or None when no
            conflicts are known.
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

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        for blk_serial in sorted(conflict_blocks):
            owned_blocks.add(blk_serial)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.BLOCK_DUPLICATE,
                    source_block=blk_serial,
                    target_block=None,
                    metadata={
                        "role": "conflict_split",
                        "strategy": self.name,
                    },
                )
            )

        if not edits:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=len(conflict_blocks) * 0.1,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.4,
        )
