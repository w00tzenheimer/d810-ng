"""PredPatchFallbackStrategy — MopTracker-based predecessor patching.

For dispatcher predecessors where direct linearization couldn't resolve the
state value, this fallback strategy traces state values backward using
MopTracker.  If a unique state is inferred, it proposes a GOTO_REDIRECT.
If multiple predecessors disagree, it may propose BLOCK_DUPLICATE.

Corresponds to ``HodurUnflattener._resolve_and_patch`` and
``_infer_unique_state_at_block_end``.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
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

logger = logging.getLogger("D810.hodur.strategy.pred_patch_fallback")

__all__ = ["PredPatchFallbackStrategy"]


class PredPatchFallbackStrategy:
    """Propose GOTO_REDIRECT or BLOCK_DUPLICATE edits for remaining dispatcher preds.

    After direct linearization, some blocks still point to dispatcher check
    blocks.  This strategy uses MopTracker backward tracing to identify the
    state value at the predecessor and proposes the appropriate redirect.

    Prerequisites: ``direct_handler_linearization`` must have run so that
    already-resolved blocks are not re-processed.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "pred_patch_fallback"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a state machine with handlers is present.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot describes a state machine that may have
            unresolved predecessor edges.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        handlers = getattr(sm, "handlers", None)
        state_var = getattr(sm, "state_var", None)
        return bool(handlers) and state_var is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment for predecessor-based patching.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with GOTO_REDIRECT or BLOCK_DUPLICATE edits, or
            None when no unresolved predecessors exist.
        """
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        handlers = getattr(sm, "handlers", {}) or {}

        if not handlers:
            return None

        # Collect all check blocks (dispatcher entry blocks).
        check_blocks: set[int] = set()
        for h in handlers.values():
            cb = getattr(h, "check_block", None)
            if cb is not None:
                check_blocks.add(cb)

        # Propose GOTO_REDIRECT edits for each check block's predecessors.
        # The actual MopTracker resolution happens at execution time.
        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        for cb_serial in check_blocks:
            owned_blocks.add(cb_serial)
            # One placeholder edit per check block indicating it needs
            # predecessor-based resolution.
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=cb_serial,
                    target_block=None,
                    metadata={
                        "role": "pred_patch_check_block",
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
            transitions_resolved=len(edits),
            blocks_freed=0,
            conflict_density=0.3,  # may overlap with direct strategy's block claims
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.35,
        )
