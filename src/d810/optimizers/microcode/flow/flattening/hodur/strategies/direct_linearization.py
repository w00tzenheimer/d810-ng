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
        """Return True when the snapshot contains a usable BST result.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if bst_result is populated and at least one handler is known.
        """
        if snapshot.bst_result is None:
            return False
        bst = snapshot.bst_result
        has_handlers = bool(
            getattr(bst, "handler_state_map", None)
            or getattr(bst, "handler_range_map", None)
        )
        return has_handlers

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
        handler_state_map: dict = getattr(bst, "handler_state_map", {}) or {}
        handler_range_map: dict = getattr(bst, "handler_range_map", {}) or {}
        bst_node_blocks: set = getattr(bst, "bst_node_blocks", set()) or set()
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        bst_node_blocks = bst_node_blocks | {dispatcher_serial}

        # Collect all handlers (exact + range).
        all_handlers: dict[int, int] = {}
        for serial, state in handler_state_map.items():
            all_handlers[serial] = state
        for serial, (low, high) in handler_range_map.items():
            if serial not in all_handlers:
                mid = low if low is not None else (high if high is not None else 0)
                all_handlers[serial] = mid

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        handlers_resolved = 0
        transitions_resolved = 0

        # Build a lookup: from_state -> set of to_state values from detected transitions.
        sm = snapshot.state_machine
        state_transitions_map: dict[int, list[int]] = {}
        if sm is not None and hasattr(sm, "transitions"):
            for t in sm.transitions:
                state_transitions_map.setdefault(t.from_state, []).append(t.to_state)

        # Build a lookup: state_value -> check_block serial.
        handlers_by_state: dict[int, int] = {}
        if sm is not None and hasattr(sm, "handlers"):
            for state_val, handler_obj in sm.handlers.items():
                handlers_by_state[state_val] = handler_obj.check_block

        for handler_serial, incoming_state in all_handlers.items():
            if handler_serial in bst_node_blocks:
                continue

            # Attempt to resolve target_block from detected transitions.
            target_block: int | None = None
            to_states = state_transitions_map.get(incoming_state, [])
            if len(to_states) == 1:
                target_block = handlers_by_state.get(to_states[0])

            if target_block is None:
                logger.debug(
                    "direct_linearization: no unique target for handler serial=%d"
                    " incoming_state=0x%x (to_states=%s) — skipping",
                    handler_serial,
                    incoming_state,
                    to_states,
                )
                continue

            # Claim ownership of the handler entry block.
            owned_blocks.add(handler_serial)

            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=handler_serial,
                    target_block=target_block,
                    metadata={
                        "incoming_state": incoming_state,
                        "bst_dispatcher_serial": dispatcher_serial,
                        "strategy": self.name,
                    },
                )
            )
            handlers_resolved += 1
            transitions_resolved += 1

            # Also claim the BST node blocks as "influenced" (not owned exclusively).
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
