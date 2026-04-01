"""ConditionalForkFallbackStrategy — conditional redirect wrapper over recon."""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.modification_builder import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    HODUR_STATE_CHECK_OPCODES,
    HodurStateMachineDetector,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.conditional_chain_resolution import (
    collect_conditional_fork_resolution_candidates,
)
if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.conditional_fork_fallback")

__all__ = ["ConditionalForkFallbackStrategy"]


class ConditionalForkFallbackStrategy:
    """Propose CONDITIONAL_REDIRECT edits for conditional state fork blocks.

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
            A PlanFragment with CONDITIONAL_REDIRECT edits for each conditional
            fork, or None when no conditional transitions exist.
        """
        if not self.is_applicable(snapshot):
            return None

        candidates = collect_conditional_fork_resolution_candidates(
            snapshot,
            conditional_opcodes=HODUR_STATE_CHECK_OPCODES,
            normalize_reversed_jump_opcode=(
                HodurStateMachineDetector._swap_jump_opcode_for_reversed_operands
            ),
            is_jump_taken_for_state=HodurStateMachineDetector._is_jump_taken_for_state,
        )
        if not candidates:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_transitions: set[tuple[int, int]] = set()

        for candidate in candidates:
            modifications.append(
                builder.conditional_redirect(
                    source_block=int(candidate.from_block),
                    conditional_target=int(candidate.taken_target),
                    fallthrough_target=int(candidate.fallthrough_target),
                    ref_block=int(candidate.cond_block),
                )
            )
            owned_blocks.add(int(candidate.from_block))
            owned_transitions.update(
                (int(from_s), int(to_s))
                for from_s, to_s in candidate.owned_transitions
            )

            if logger.debug_on:
                logger.debug(
                    "Resolved conditional fork at block %d: "
                    "taken->%d, fall->%d (states 0x%x/0x%x)",
                    int(candidate.cond_block),
                    int(candidate.taken_target),
                    int(candidate.fallthrough_target),
                    int(candidate.states[0]),
                    int(candidate.states[1]),
                )

        if not modifications:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=len(candidates),
            blocks_freed=0,
            conflict_density=0.2,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.3,
        )
