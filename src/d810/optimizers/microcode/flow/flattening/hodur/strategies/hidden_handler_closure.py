"""HiddenHandlerClosureStrategy — MERGED into DirectHandlerLinearizationStrategy.

The hidden handler fixpoint closure (Pass 2) has been merged into
DirectHandlerLinearizationStrategy.plan() as of the hodur-strategy-refactor.
This class is kept as a no-op so that the strategy registry does not break.

The original heuristic (transition-map based) has been replaced by the exact
port from commit 4313af46: a worklist/fixpoint DFS over bst_rootwalk_targets
collected during Pass 1, using evaluate_handler_paths + resolve_target_via_bst.
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

logger = logging.getLogger("D810.hodur.strategy.hidden_handler_closure")

__all__ = ["HiddenHandlerClosureStrategy"]


class HiddenHandlerClosureStrategy:
    """No-op placeholder — hidden handler closure is now done inside DirectHandlerLinearizationStrategy.

    The second pass (worklist/fixpoint closure over BST root-walk targets) was
    merged into G1's plan() so that the same claimed_exits / claimed_edges
    conflict-tracking state is shared across both passes.  Keeping this class
    ensures the strategy registry and any prerequisite references remain intact.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "hidden_handler_closure"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Always returns False — work is done by DirectHandlerLinearizationStrategy.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            False unconditionally.
        """
        return False

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Return None — no-op since Pass 2 is merged into G1.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            None always.
        """
        return None
