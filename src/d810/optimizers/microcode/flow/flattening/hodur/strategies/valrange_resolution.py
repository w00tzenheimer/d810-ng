"""ValrangeResolutionStrategy -- IDA value-range fallback for unresolved exits.

After DirectLinearization resolves the majority of handler transitions via
forward evaluation, some handler exits remain unresolved (e.g. MBA-obfuscated
state computations).  This strategy queries IDA's pre-computed value range
analysis (``get_valranges``) for the state variable at each unresolved exit
block.  If a single concrete value is obtained, BST lookup determines the
target handler and a redirect is emitted.

This mirrors hrtng's ``get_valranges(VR_EXACT)`` fallback in ``unflat.cpp``.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.evaluator.hexrays_microcode.valranges import resolve_state_via_valranges
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.valrange_resolution")

__all__ = ["ValrangeResolutionStrategy"]


class ValrangeResolutionStrategy:
    """Query IDA's value-range analysis to resolve remaining handler exits.

    For each handler whose exit transition was *not* resolved by prior
    strategies (e.g. DirectLinearization), this strategy:

    1. Retrieves the live ``mblock_t`` for the exit block.
    2. Queries ``resolve_state_via_valranges`` for the state variable at the
       block tail instruction.
    3. If a single concrete value is returned, performs a BST lookup to find
       the target handler and emits a ``RedirectGoto`` modification.

    Family: ``FAMILY_FALLBACK`` -- runs after the primary direct strategies.
    Risk: LOW -- read-only IDA query, no speculation.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "valrange_resolution"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a state machine and BST result are present.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot describes a state machine with handlers,
            a BST result for target resolution, and unresolved transitions.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        handlers = getattr(sm, "handlers", None)
        state_var = getattr(sm, "state_var", None)
        if not handlers or state_var is None:
            return False
        if snapshot.bst_result is None:
            return False
        return snapshot.unresolved_transition_count > 0

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment for valrange-based exit resolution.

        For each handler with unresolved exit transitions, query IDA's value
        range analysis for the state variable at the exit block's tail
        instruction.  If a single concrete value is obtained, BST lookup
        determines the target handler and a redirect is emitted.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with redirect modifications, or None when no
            exits could be resolved via valranges.
        """
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        sm = snapshot.state_machine
        bst_result = snapshot.bst_result
        if mba is None or sm is None or bst_result is None:
            return None

        handlers = getattr(sm, "handlers", {}) or {}
        state_var = getattr(sm, "state_var", None)
        if not handlers or state_var is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_transitions: set[tuple[int, int]] = set()
        resolved_count = 0
        total_unresolved = 0

        # Identify already-resolved transitions
        already_resolved = snapshot.resolved_transitions

        for state_val, handler in handlers.items():
            # Check each transition from this handler
            for transition in handler.transitions:
                key = (transition.from_state, transition.to_state)
                if key in already_resolved:
                    continue

                total_unresolved += 1

                # Get exit block from transition
                exit_serial = transition.from_block
                exit_blk = mba.get_mblock(exit_serial)
                if exit_blk is None:
                    continue

                tail_ins = exit_blk.tail
                if tail_ins is None:
                    continue

                # Query valranges for the state variable at exit block tail
                val = resolve_state_via_valranges(exit_blk, state_var, tail_ins)
                if val is None:
                    logger.debug(
                        "ValrangeResolution: block %d — valranges returned no "
                        "single value for state var",
                        exit_serial,
                    )
                    continue

                # BST lookup to find target handler
                target_serial = resolve_target_via_bst(bst_result, val)
                if target_serial is None:
                    logger.debug(
                        "ValrangeResolution: block %d — resolved value %s but "
                        "BST lookup found no target",
                        exit_serial,
                        hex(val),
                    )
                    continue

                logger.debug(
                    "ValrangeResolution: block %d — resolved state %s -> "
                    "handler block %d",
                    exit_serial,
                    hex(val),
                    target_serial,
                )

                modifications.append(
                    builder.goto_redirect(
                        source_block=exit_serial,
                        target_block=target_serial,
                    )
                )
                owned_blocks.add(exit_serial)
                owned_transitions.add(key)
                resolved_count += 1

        logger.info(
            "ValrangeResolution: resolved %d/%d unresolved exits",
            resolved_count,
            total_unresolved,
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
            transitions_resolved=resolved_count,
            blocks_freed=0,
            conflict_density=0.1,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.15,
        )
