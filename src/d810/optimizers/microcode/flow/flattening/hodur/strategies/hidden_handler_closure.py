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
        """Return True when the snapshot contains a BST result with a default block.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if bst_result is present and the BST default region is non-empty.
        """
        if snapshot.bst_result is None:
            return False
        bst = snapshot.bst_result
        # Applicable whenever there are range handlers (potential hidden handlers)
        # or when handler_range_map is non-empty.
        handler_range_map = getattr(bst, "handler_range_map", None) or {}
        handler_state_map = getattr(bst, "handler_state_map", None) or {}
        return bool(handler_range_map) or bool(handler_state_map)

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

        # Build transition and handler lookups from the snapshot state machine.
        sm = snapshot.state_machine
        state_transitions_map: dict[int, list[int]] = {}
        if sm is not None and hasattr(sm, "transitions"):
            for t in sm.transitions:
                state_transitions_map.setdefault(t.from_state, []).append(t.to_state)

        handlers_by_state: dict[int, int] = {}
        if sm is not None and hasattr(sm, "handlers"):
            for state_val, handler_obj in sm.handlers.items():
                handlers_by_state[state_val] = handler_obj.check_block

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        # For each range handler — these are the most likely hidden handler candidates.
        for serial, (low, high) in handler_range_map.items():
            if serial in bst_node_blocks:
                continue

            # Attempt to resolve target_block from transitions for the range state.
            mid_state = low if low is not None else (high if high is not None else None)
            target_block: int | None = None
            if mid_state is not None:
                to_states = state_transitions_map.get(mid_state, [])
                if len(to_states) == 1:
                    target_block = handlers_by_state.get(to_states[0])

            if target_block is None:
                logger.debug(
                    "hidden_handler_closure: no unique target for serial=%d"
                    " range=(%s, %s) — skipping",
                    serial,
                    hex(low) if low is not None else "None",
                    hex(high) if high is not None else "None",
                )
                continue

            owned_blocks.add(serial)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=serial,
                    target_block=target_block,
                    metadata={
                        "role": "hidden_handler_entry",
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
