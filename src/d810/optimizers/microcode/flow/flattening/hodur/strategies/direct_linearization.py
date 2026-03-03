"""DirectHandlerLinearizationStrategy — core BST-based linearization.

Iterates all detected state machine handlers, runs DFS forward evaluation to
find handler exit paths and their final state values, then proposes
GOTO_REDIRECT edits that bypass the dispatcher entirely.
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

logger = logging.getLogger("D810.hodur.strategy.direct_linearization")

__all__ = ["DirectHandlerLinearizationStrategy"]


class DirectHandlerLinearizationStrategy:
    """Propose GOTO_REDIRECT edits for every resolved handler exit path.

    Reads the BST analysis result from the snapshot and, for each handler
    entry, proposes redirects from handler exit blocks to target handler
    entries.  No CFG mutations are performed — all work is encoded as
    :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.ProposedEdit`
    objects inside a :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "direct_handler_linearization"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a state machine with transitions and handlers.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if state_machine is populated with transitions and handlers so
            that from_block -> target handler redirects can be constructed.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        has_transitions = bool(getattr(sm, "transitions", None))
        has_handlers = bool(getattr(sm, "handlers", None))
        return has_transitions and has_handlers

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with GOTO_REDIRECT edits for all resolvable handlers.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with at least one edit, or None when no work can
            be done.
        """
        if not self.is_applicable(snapshot):
            return None

        bst = snapshot.bst_result
        bst_node_blocks: set = getattr(bst, "bst_node_blocks", set()) or set()
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        bst_node_blocks = bst_node_blocks | {dispatcher_serial}

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        handlers_resolved = 0
        transitions_resolved = 0

        # Build a lookup: state_value -> check_block serial (handler ENTRY).
        sm = snapshot.state_machine
        handlers_by_state: dict[int, int] = {}
        if sm is not None and hasattr(sm, "handlers"):
            for state_val, handler_obj in sm.handlers.items():
                handlers_by_state[state_val] = handler_obj.check_block

        # Iterate detected transitions: source is transition.from_block (EXIT block
        # where the state variable is written), target is the ENTRY of to_state handler.
        transitions = []
        if sm is not None and hasattr(sm, "transitions"):
            transitions = list(sm.transitions)

        seen_sources: set[int] = set()
        for transition in transitions:
            from_block = getattr(transition, "from_block", None)
            to_state = getattr(transition, "to_state", None)
            if from_block is None or to_state is None:
                continue

            # Skip BST internal blocks as redirect sources.
            if from_block in bst_node_blocks:
                continue

            target_block: int | None = handlers_by_state.get(to_state)
            if target_block is None:
                logger.debug(
                    "direct_linearization: no handler entry for to_state=0x%x"
                    " from_block=%d — skipping",
                    to_state,
                    from_block,
                )
                continue

            # Deduplicate: one redirect per from_block (first transition wins).
            if from_block in seen_sources:
                logger.debug(
                    "direct_linearization: duplicate source from_block=%d"
                    " (already queued) — skipping",
                    from_block,
                )
                continue
            seen_sources.add(from_block)

            # Claim ownership of the EXIT block (where state write lives).
            owned_blocks.add(from_block)

            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=from_block,
                    target_block=target_block,
                    metadata={
                        "from_state": getattr(transition, "from_state", None),
                        "to_state": to_state,
                        "bst_dispatcher_serial": dispatcher_serial,
                        "strategy": self.name,
                    },
                )
            )
            handlers_resolved += 1
            transitions_resolved += 1

        # Also claim the BST node blocks as "influenced" (not owned exclusively).
        if edits:
            owned_blocks.update(bst_node_blocks)

        # Claim pre-header redirect if available.
        pre_header: int | None = getattr(bst, "pre_header_serial", None)
        initial_state: int | None = getattr(sm, "initial_state", None) if sm is not None else None
        pre_header_target: int | None = None
        if initial_state is not None:
            pre_header_target = handlers_by_state.get(initial_state)
        if pre_header is not None and pre_header != -1 and pre_header_target is not None:
            owned_blocks.add(pre_header)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=pre_header,
                    target_block=pre_header_target,
                    metadata={
                        "role": "pre_header",
                        "strategy": self.name,
                    },
                )
            )

        if not edits:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=handlers_resolved,
            transitions_resolved=transitions_resolved,
            blocks_freed=len(bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.1,
        )
