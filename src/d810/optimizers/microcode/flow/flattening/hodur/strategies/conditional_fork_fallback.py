"""ConditionalForkFallbackStrategy — resolve 2-way conditional state forks.

When a block has two outgoing edges and each arm writes a different state value,
this strategy walks the BST check chain to determine which handler each arm
targets.  It proposes CONVERT_TO_GOTO or GOTO_REDIRECT edits for each arm.

Corresponds to ``HodurUnflattener._resolve_conditional_forks_via_predecessors``
and ``_resolve_conditional_chain_target``.
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

logger = logging.getLogger("D810.hodur.strategy.conditional_fork_fallback")

__all__ = ["ConditionalForkFallbackStrategy"]


class ConditionalForkFallbackStrategy:
    """Propose CONVERT_TO_GOTO edits for conditional state fork blocks.

    When a single block (from_block) drives two distinct state transitions,
    the dispatcher check chain must be walked for each state value to find
    the corresponding handler entry.  The executor then rewires both edges.

    Prerequisites: ``direct_handler_linearization`` must have run to ensure
    the main transition set is established before conditional forks are
    attempted.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "conditional_fork_fallback"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when conditional transitions exist in the state machine.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if any transition is marked conditional.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        transitions = getattr(sm, "transitions", None) or []
        return any(getattr(t, "is_conditional", False) for t in transitions)

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment for conditional fork resolution.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with CONVERT_TO_GOTO edits for each conditional
            fork, or None when no conditional transitions exist.
        """
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        transitions = getattr(sm, "transitions", []) or []

        # Group conditional transitions by from_block.
        conditional_groups: dict[int, list] = {}
        for t in transitions:
            if not getattr(t, "is_conditional", False):
                continue
            from_block = getattr(t, "from_block", None)
            if from_block is None:
                continue
            conditional_groups.setdefault(from_block, []).append(t)

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()
        owned_transitions: set[tuple[int, int]] = set()

        for from_blk_serial, group_transitions in conditional_groups.items():
            unique_states = list({getattr(t, "to_state", None) for t in group_transitions})
            if len(unique_states) != 2:
                continue

            owned_blocks.add(from_blk_serial)
            state_a, state_b = unique_states[0], unique_states[1]

            edits.append(
                ProposedEdit(
                    edit_type=EditType.CONVERT_TO_GOTO,
                    source_block=from_blk_serial,
                    target_block=None,
                    metadata={
                        "role": "conditional_fork",
                        "state_a": state_a,
                        "state_b": state_b,
                        "strategy": self.name,
                    },
                )
            )
            # Record transitions as owned.
            for t in group_transitions:
                from_s = getattr(t, "from_state", None)
                to_s = getattr(t, "to_state", None)
                if from_s is not None and to_s is not None:
                    owned_transitions.add((from_s, to_s))

        if not edits:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=len(owned_transitions),
            blocks_freed=0,
            conflict_density=0.2,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.3,
        )
