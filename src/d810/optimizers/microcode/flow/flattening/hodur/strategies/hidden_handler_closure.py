"""HiddenHandlerClosureStrategy — retired hidden-handler placeholder.

The old direct-linearization shell that used to own the hidden-handler
fixpoint was deleted after the terminal-corridor harvest. This class remains
as a no-op placeholder so the current experimental pipeline shape and
historical strategy names stay stable while the live work continues to happen
through reconstruction/LFG.
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
    """No-op placeholder for the retired hidden-handler closure phase."""

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "hidden_handler_closure"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Always returns False.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            False unconditionally.
        """
        return False

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Return None — no-op placeholder.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            None always.
        """
        return None
