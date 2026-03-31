"""PrivateTerminalSuffixStrategy -- clone shared epilogue suffix per handler.

Runs AFTER direct linearization (pass > 0).  Identifies terminal handler
paths that share a common epilogue suffix, classifies carriers, and emits
PrivateTerminalSuffix modifications for eligible suffix groups.

Eligibility (all must be true per suffix group):

1. ``semantic_action == PRIVATE_TERMINAL_SUFFIX``
2. ``carrier_bucket == suffix_ambiguous``
3. ``clonable == True``
4. ``handler_count >= 2``
5. ``resolved_count == 0``
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.terminal_corridor_execution import (
    plan_private_terminal_suffix_execution,
)
from d810.cfg.terminal_corridor_planning import (
    compute_suffix_group_decision,
)
from d810.cfg.modification_builder import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.terminal_corridor_discovery import (
    discover_terminal_corridor_group,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.private_terminal_suffix")

__all__ = ["PrivateTerminalSuffixStrategy"]


class PrivateTerminalSuffixStrategy:
    """Clone shared terminal suffix per handler entry.

    Runs AFTER direct linearization.  Identifies terminal handler paths
    that share a common epilogue suffix, classifies carriers, and emits
    :class:`~d810.cfg.modification_builder.PrivateTerminalSuffix`
    modifications for eligible suffix groups.

    Eligibility (all must be true per suffix group):

    1. ``semantic_action == PRIVATE_TERMINAL_SUFFIX``
    2. ``carrier_bucket == suffix_ambiguous``
    3. ``clonable == True``
    4. ``handler_count >= 2``
    5. ``resolved_count == 0``
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "private_terminal_suffix"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when direct linearization has already run.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if ``pass_number >= 1`` and both ``bst_result`` and
            ``state_machine`` are populated.
        """
        if snapshot.pass_number < 1:
            return False
        if snapshot.bst_result is None:
            return False
        if snapshot.state_machine is None:
            return False
        if snapshot.flow_graph is None:
            return False
        return True

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with PTS edits for eligible suffix groups.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with PrivateTerminalSuffix modifications, or
            ``None`` when the strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        discovery = discover_terminal_corridor_group(
            snapshot,
            anchor_note="pts-strategy-anchor",
        )
        if discovery.group is None:
            logger.info("[pts-strategy] %s, skipping", discovery.failure_reason)
            return None
        group = discovery.group
        fg = snapshot.flow_graph

        if group.semantic_action.value != "private_terminal_suffix":
            logger.info(
                "[pts-strategy] semantic_action=%s, not PTS eligible",
                group.semantic_action.value,
            )
            return None

        # ---- Per-anchor return audit diagnostic ----
        dtl_count = 0
        for entry in group.forward_entries:
            is_leak = (
                entry.state_const_written is not None
                and entry.state_const_written in group.known_state_constants
            )
            if entry.requires_dtl:
                dtl_count += 1
            logger.info(
                "PTS_ANCHOR_AUDIT anchor=%d carrier=%s "
                "state_const_written=%s is_state_leak=%s requires_dtl=%s",
                entry.handler_entry,
                entry.carrier_source_kind.value,
                hex(entry.state_const_written)
                if entry.state_const_written is not None
                else "None",
                is_leak,
                entry.requires_dtl,
            )
        leak_count = sum(
            1
            for e in group.forward_entries
            if e.state_const_written is not None
            and e.state_const_written in group.known_state_constants
        )
        logger.info(
            "PTS_ANCHOR_AUDIT_SUMMARY total=%d leaking=%d clean=%d dtl_candidates=%d",
            len(group.forward_entries),
            leak_count,
            len(group.forward_entries) - leak_count,
            dtl_count,
        )

        # ---- Build corridor info and compute decision ----
        corridor_info = group.corridor_info
        decision = compute_suffix_group_decision(
            forward_entries=group.forward_entries,
            corridor_info=corridor_info,
            semantic_action=group.semantic_action,
        )

        logger.info(
            "[pts-strategy] pass=%d shared_entry=blk[%d] handlers=%d "
            "bucket=%s should_emit=%s reasons=%s",
            snapshot.pass_number,
            decision.shared_entry,
            decision.handler_count,
            decision.carrier_bucket.value,
            decision.should_emit,
            decision.rejection_reasons,
        )

        if not decision.should_emit:
            return None

        # ==== EMIT PTS MODIFICATIONS ====
        builder = ModificationBuilder.from_snapshot(snapshot)
        execution = plan_private_terminal_suffix_execution(
            flow_graph=fg,
            builder=builder,
            anchors=group.anchors,
            shared_entry_serial=group.shared_entry,
            return_block_serial=group.return_block,
            suffix_serials=group.suffix_serials,
        )

        logger.info(
            "[pts-strategy] emitting %d PTS modifications for %d anchors",
            len(execution.modifications),
            len(group.anchors),
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=list(execution.modifications),
            ownership=OwnershipScope(
                blocks=execution.owned_blocks,
                edges=execution.owned_edges,
                transitions=frozenset(),
            ),
            prerequisites=["direct_handler_linearization"],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=len(group.anchors),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.3,
            metadata={
                "suffix_group_decision": decision,
                "corridor_info": corridor_info,
                "anchor_count": len(group.anchors),
                "carrier_bucket": decision.carrier_bucket.value,
                "safeguard_min_required": execution.safeguard_min_required,
            },
        )
