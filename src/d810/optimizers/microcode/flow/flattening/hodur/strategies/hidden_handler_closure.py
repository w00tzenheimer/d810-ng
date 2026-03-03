"""HiddenHandlerClosureStrategy — second-pass linearization of BST root-walk targets.

After direct linearization resolves main handlers, some handler exits resolve
to "hidden handlers" that live in the BST default region.  Their own exits
may still go to the dispatcher.  This strategy runs a fixpoint closure over
those hidden handlers and proposes GOTO_REDIRECT edits for their exits.
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

logger = logging.getLogger("D810.hodur.strategy.hidden_handler_closure")

__all__ = ["HiddenHandlerClosureStrategy"]


class HiddenHandlerClosureStrategy:
    """Propose GOTO_REDIRECT edits for hidden handlers reachable via BST root-walk.

    Hidden handlers are blocks that are not in the direct handler map but are
    reachable from the BST root when forward-evaluating a specific state value
    that falls through all direct comparisons.  They often have their own exits
    back to the dispatcher that must be linearized in a second pass.

    This strategy has ``direct_handler_linearization`` as a prerequisite because
    it needs the first pass to have already identified BST root-walk targets.
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
        """Return True when the snapshot has hidden handler transitions to resolve.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the state machine has range handlers (BST default region)
            that may have unlinearized exit paths.
        """
        if snapshot.bst_result is None:
            return False
        bst = snapshot.bst_result
        handler_range_map = getattr(bst, "handler_range_map", None) or {}
        # Also need a state machine with handlers to resolve targets.
        sm = snapshot.state_machine
        has_handlers = bool(sm is not None and getattr(sm, "handlers", None))
        return bool(handler_range_map) and has_handlers

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment for hidden handler exit redirects.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with GOTO_REDIRECT edits for hidden handlers, or
            None when no hidden handlers are detected.
        """
        if not self.is_applicable(snapshot):
            return None

        bst = snapshot.bst_result
        bst_node_blocks: set = getattr(bst, "bst_node_blocks", set()) or set()
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        bst_node_blocks = bst_node_blocks | {dispatcher_serial}

        # Hidden handlers are blocks that resolve via BST root-walk (not exact map).
        # We propose a GOTO_REDIRECT placeholder for each BST node block that could
        # be a hidden handler entry.  The executor resolves the actual DFS paths.
        handler_range_map: dict = getattr(bst, "handler_range_map", {}) or {}
        handler_state_map: dict = getattr(bst, "handler_state_map", {}) or {}
        all_known_handlers = set(handler_state_map.keys()) | set(handler_range_map.keys())

        # Build handler lookup: state_value -> check_block serial (ENTRY block).
        sm = snapshot.state_machine
        handlers_by_state: dict[int, int] = {}
        if sm is not None and hasattr(sm, "handlers"):
            for state_val, handler_obj in sm.handlers.items():
                handlers_by_state[state_val] = handler_obj.check_block

        # Build set of states that are range (hidden) handler states.
        range_states: set = set()
        for serial, (low, high) in handler_range_map.items():
            if low is not None:
                range_states.add(low)
            if high is not None:
                range_states.add(high)

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        # Iterate transitions whose from_state corresponds to a range/hidden handler.
        # The correct source_block is transition.from_block (the EXIT block where
        # the state is written), matching the same semantics as direct_linearization.
        transitions = []
        if sm is not None and hasattr(sm, "transitions"):
            transitions = list(sm.transitions)

        seen_sources: set[int] = set()
        for transition in transitions:
            from_block = getattr(transition, "from_block", None)
            from_state = getattr(transition, "from_state", None)
            to_state = getattr(transition, "to_state", None)
            if from_block is None or to_state is None:
                continue

            # Only process transitions that originate from hidden/range handler states.
            if from_state not in range_states:
                continue

            # Skip BST internal blocks as redirect sources.
            if from_block in bst_node_blocks:
                continue

            target_block: int | None = handlers_by_state.get(to_state)
            if target_block is None:
                logger.debug(
                    "hidden_handler_closure: no handler entry for to_state=0x%x"
                    " from_block=%d — skipping",
                    to_state,
                    from_block,
                )
                continue

            # Deduplicate per source block.
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
                        "role": "hidden_handler_exit",
                        "from_state": from_state,
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
            handlers_resolved=len(edits),
            transitions_resolved=len(edits),
            blocks_freed=0,
            conflict_density=0.1,  # slight risk of overlap with direct strategy
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.2,
        )
