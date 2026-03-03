"""AssignmentMapFallbackStrategy — resolve remaining back-edges via assignment_map.

After all transition patches, some handler exit blocks may still have back-edges
to the dispatcher.  These blocks contain state assignments that identify their
target handler.  This strategy uses ``state_machine.assignment_map`` to find
those assignments and proposes NOP_INSN edits for dead state writes plus
GOTO_REDIRECT edits for the remaining back-edges.

Corresponds to ``HodurUnflattener._resolve_remaining_via_assignment_map`` and
``_queue_state_assignment_removals``.
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

logger = logging.getLogger("D810.hodur.strategy.assignment_map_fallback")

__all__ = ["AssignmentMapFallbackStrategy"]


class AssignmentMapFallbackStrategy:
    """Propose NOP_INSN edits for dead state variable assignments.

    After direct linearization has bypassed the dispatcher, the ``mov
    STATE_CONSTANT, state_var`` instructions in handler blocks become dead
    code.  This strategy finds those assignments and proposes NOP_INSN edits
    to remove them, allowing IDA's dead-code elimination to clean up the
    dispatcher blocks.

    It also proposes GOTO_REDIRECT edits for any remaining predecessor edges
    to dispatcher check blocks that can be resolved via ``assignment_map``.

    Prerequisites: ``direct_handler_linearization`` must have run first.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "assignment_map_fallback"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the state machine has an assignment_map.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if ``state_machine.assignment_map`` is non-empty.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        assignment_map = getattr(sm, "assignment_map", None)
        state_var = getattr(sm, "state_var", None)
        return bool(assignment_map) and state_var is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with NOP_INSN and GOTO_REDIRECT edits.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with dead-assignment NOP edits and remaining
            back-edge redirects, or None when no assignment_map data exists.
        """
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        handlers = getattr(sm, "handlers", {}) or {}
        state_constants: set = getattr(sm, "state_constants", set()) or set()
        assignment_map: dict = getattr(sm, "assignment_map", {}) or {}

        if not handlers:
            return None

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        # Propose NOP_INSN edits for all handler body blocks that contain
        # state constant assignments.  The actual instruction EA is resolved
        # at execution time; here we just claim the blocks.
        for handler in handlers.values():
            handler_blocks = getattr(handler, "handler_blocks", []) or []
            for blk_serial in handler_blocks:
                owned_blocks.add(blk_serial)
                # One placeholder NOP_INSN per handler block.
                edits.append(
                    ProposedEdit(
                        edit_type=EditType.NOP_INSN,
                        source_block=blk_serial,
                        target_block=None,
                        metadata={
                            "role": "dead_state_assignment",
                            "strategy": self.name,
                            "state_constants": list(state_constants)[:8],
                        },
                    )
                )

        # Propose GOTO_REDIRECT for blocks in assignment_map that still have
        # check-block back-edges.
        check_blocks: set[int] = set()
        for h in handlers.values():
            cb = getattr(h, "check_block", None)
            if cb is not None:
                check_blocks.add(cb)

        for src_serial in assignment_map:
            owned_blocks.add(src_serial)
            edits.append(
                ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=src_serial,
                    target_block=None,
                    metadata={
                        "role": "assignment_map_redirect",
                        "check_blocks": list(check_blocks),
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
            transitions_resolved=len(assignment_map),
            blocks_freed=len(assignment_map),
            conflict_density=0.2,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.25,
        )
