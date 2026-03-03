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

        # Build handler lookup: state_value -> check_block serial.
        handlers_by_state: dict[int, int] = {}
        for state_val, handler_obj in handlers.items():
            cb = getattr(handler_obj, "check_block", None)
            if cb is not None:
                handlers_by_state[state_val] = cb

        # Propose GOTO_REDIRECT edits for each transition whose target can be
        # resolved to a concrete check block.  Edits with target_block=None are
        # skipped — the executor cannot apply them safely.
        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()
        transitions = getattr(sm, "transitions", []) or []

        seen_sources: set[int] = set()
        for t in transitions:
            from_block = getattr(t, "from_block", None)
            to_state = getattr(t, "to_state", None)
            if from_block is None or to_state is None:
                continue
            target_block = handlers_by_state.get(to_state)
            if target_block is None:
                logger.debug(
                    "pred_patch_fallback: no check_block for to_state=0x%x"
                    " from_block=%d — skipping",
                    to_state,
                    from_block,
                )
                continue
            if from_block in seen_sources:
                continue
            seen_sources.add(from_block)
            owned_blocks.add(from_block)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=from_block,
                    target_block=target_block,
                    metadata={
                        "role": "pred_patch_redirect",
                        "to_state": to_state,
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
