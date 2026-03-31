"""DirectTerminalLowering strategy -- materialize per-anchor return values.

Runs AFTER both direct linearization AND private terminal suffix.  Handles
terminal handler paths classified as ``needs_direct_lowering`` (carrier bucket
contains ``state_const`` -- a dispatcher semantic leak that PTS cannot clone
away).

For each such anchor the strategy will:

1. Prove the concrete return value via :func:`prove_terminal_returns`.
2. Classify the proof into a :class:`DirectTerminalLoweringKind`.
3. Emit a :class:`DirectTerminalLoweringGroup` modification that the backend
   will materialise as per-anchor private return blocks with the proven value.

v1 skeleton: proof integration returns ``None`` (no sites emitted) until the
MBA-level proof call is connected.  The architecture and registration are
complete so the strategy participates in the plan pipeline but produces no
modifications.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.terminal_corridor_execution import (
    plan_direct_terminal_lowering_execution,
)
from d810.cfg.terminal_corridor_planning import (
    CarrierBucket,
    compute_suffix_group_decision,
    select_direct_terminal_lowering_anchors,
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

logger = logging.getLogger("D810.hodur.strategy.direct_terminal_lowering")

__all__ = ["DirectTerminalLoweringStrategy"]


class DirectTerminalLoweringStrategy:
    """Materialize per-anchor private return blocks for needs_direct_lowering sites.

    Runs AFTER direct linearization AND private terminal suffix.  Identifies
    terminal handler paths classified as ``needs_direct_lowering`` (carrier
    bucket contains ``state_const``), proves the concrete return value for
    each anchor, and emits :class:`DirectTerminalLoweringGroup` modifications.

    Prerequisites:

    * ``direct_handler_linearization`` -- handlers must be linearized first.
    * ``private_terminal_suffix`` -- PTS must run first to handle
      ``suffix_ambiguous`` sites; DTL handles the remaining
      ``needs_direct_lowering`` sites.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "direct_terminal_lowering"

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
        """Produce a PlanFragment with DTL edits for needs_direct_lowering groups.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with DirectTerminalLoweringGroup modifications, or
            ``None`` when the strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        discovery = discover_terminal_corridor_group(
            snapshot,
            anchor_note="dtl-strategy-anchor",
        )
        if discovery.group is None:
            logger.info("[dtl-strategy] %s, skipping", discovery.failure_reason)
            return None
        group = discovery.group

        if group.semantic_action.value != "private_terminal_suffix":
            logger.info(
                "[dtl-strategy] semantic_action=%s, not eligible",
                group.semantic_action.value,
            )
            return None

        corridor_info = group.corridor_info
        decision = compute_suffix_group_decision(
            forward_entries=group.forward_entries,
            corridor_info=corridor_info,
            semantic_action=group.semantic_action,
        )

        logger.info(
            "[dtl-strategy] pass=%d shared_entry=blk[%d] handlers=%d "
            "bucket=%s rejection_reasons=%s",
            snapshot.pass_number,
            decision.shared_entry,
            decision.handler_count,
            decision.carrier_bucket.value,
            decision.rejection_reasons,
        )

        # DTL acts on needs_direct_lowering groups, OR per-anchor DTL
        # overrides when the group bucket is suffix_ambiguous but individual
        # anchors leak known state constants.
        dtl_anchors = select_direct_terminal_lowering_anchors(
            decision=decision,
            anchors=group.anchors,
        )
        if decision.carrier_bucket == CarrierBucket.NEEDS_DIRECT_LOWERING:
            pass
        elif dtl_anchors:
            logger.info(
                "[dtl-strategy] per-anchor DTL override: bucket=%s "
                "dtl_anchor_serials=%s",
                decision.carrier_bucket.value,
                dtl_anchors,
            )
        else:
            logger.info(
                "[dtl-strategy] bucket=%s, no per-anchor DTL candidates, skipping",
                decision.carrier_bucket.value,
            )
            return None

        execution = plan_direct_terminal_lowering_execution(
            mba=snapshot.mba,
            builder=ModificationBuilder.from_snapshot(snapshot),
            anchors=dtl_anchors,
            shared_entry_serial=group.shared_entry,
            return_block_serial=group.return_block,
            suffix_serials=group.suffix_serials,
        )
        if not execution.supported_sites:
            logger.info(
                "[dtl-strategy] %d/%d anchors proved but none have supported "
                "kind (or proof not yet connected)",
                len(execution.sites),
                len(group.anchors),
            )
            return None

        logger.info(
            "[dtl-strategy] emitting DTL group with %d sites (anchors=%s)",
            len(execution.supported_sites),
            [site.anchor_serial for site in execution.supported_sites],
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
            prerequisites=[
                "direct_handler_linearization",
                "private_terminal_suffix",
            ],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=len(execution.supported_sites),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.4,
            metadata={
                "suffix_group_decision": decision,
                "corridor_info": corridor_info,
                "anchor_count": len(group.anchors),
                "carrier_bucket": decision.carrier_bucket.value,
                "proven_sites": len(execution.supported_sites),
                "total_anchors": len(group.anchors),
            },
        )
