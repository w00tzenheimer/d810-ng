"""TerminalLoopCleanupStrategy — fix residual infinite-loop artifacts.

After linearization, some handler exit blocks may still loop back to the
dispatcher via lightweight transition blocks, or form degenerate single-block
self-loops.  This strategy proposes GOTO_REDIRECT edits that cut those loops
and redirect to the nearest function exit or return block.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
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

logger = logging.getLogger("D810.hodur.strategy.terminal_loop_cleanup")

__all__ = ["TerminalLoopCleanupStrategy"]


class TerminalLoopCleanupStrategy:
    """Propose GOTO_REDIRECT edits to break residual terminal back-edge loops.

    Corresponds to the logic in
    ``HodurUnflattener._find_terminal_loopback_transition``,
    ``_is_lightweight_terminal_transition_block``,
    ``_find_terminal_exit_target``,
    ``_can_reach_return``,
    ``_queue_terminal_backedge_fix``,
    ``_queue_legacy_terminal_backedge_fix``,
    ``_fix_degenerate_terminal_loops``,
    ``_collect_nearby_blocks``, and
    ``_is_degenerate_loop_block``.

    This strategy runs after direct linearization and is therefore in
    FAMILY_CLEANUP.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "terminal_loop_cleanup"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a state machine with transitions is detected.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot describes a non-empty state machine.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        has_handlers = bool(getattr(sm, "handlers", None))
        has_transitions = bool(getattr(sm, "transitions", None))
        return has_handlers or has_transitions

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with GOTO_REDIRECT edits for terminal loop blocks.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with terminal-loop redirect edits, or None when the
            strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        handlers = getattr(sm, "handlers", {}) or {}
        transitions = getattr(sm, "transitions", []) or []
        initial_state = getattr(sm, "initial_state", None)

        if not handlers:
            return None

        # Collect check blocks (dispatcher entry blocks) from all handlers.
        check_blocks: set[int] = set()
        for h in handlers.values():
            cb = getattr(h, "check_block", None)
            if cb is not None:
                check_blocks.add(cb)

        # Identify loopback transitions: transitions that go back to initial_state.
        loopback_blocks: set[int] = set()
        if initial_state is not None:
            for t in transitions:
                from_state = getattr(t, "from_state", None)
                to_state = getattr(t, "to_state", None)
                from_block = getattr(t, "from_block", None)
                if (
                    to_state == initial_state
                    and from_state != initial_state
                    and from_block is not None
                ):
                    loopback_blocks.add(from_block)

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        # Propose GOTO_REDIRECT for each loopback block.
        for blk_serial in loopback_blocks:
            owned_blocks.add(blk_serial)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=blk_serial,
                    target_block=None,  # resolved at execution time (terminal exit)
                    metadata={
                        "role": "loopback_redirect",
                        "strategy": self.name,
                        "check_blocks": list(check_blocks),
                    },
                )
            )

        # Propose GOTO_REDIRECT for degenerate self-loop blocks nearby check blocks.
        # These are nop/goto-only blocks that loop to themselves.
        # We claim all check blocks as potential degenerate loop sources.
        for cb_serial in check_blocks:
            owned_blocks.add(cb_serial)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=cb_serial,
                    target_block=None,
                    metadata={
                        "role": "degenerate_loop_candidate",
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
            transitions_resolved=len(loopback_blocks),
            blocks_freed=len(loopback_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.15,
        )
