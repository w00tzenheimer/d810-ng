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

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.flow.terminal_return import (
    TerminalLoweringAction,
    classify_cfg_suffix_action,
    compute_terminal_cfg_suffix_frontier,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    collect_state_machine_blocks,
    find_terminal_exit_target_snapshot,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.direct_linearization import (
    CarrierSourceKind,
    ForwardFrontierEntry,
    _classify_carrier_source,
    _compute_suffix_group_decision,
    _discover_shared_corridor,
)
from d810.recon.flow.transition_builder import (
    _get_state_var_stkoff,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.private_terminal_suffix")

__all__ = ["PrivateTerminalSuffixStrategy"]


def _resolve_state_var_stkoff(snapshot: AnalysisSnapshot) -> int | None:
    """Resolve state variable stack offset from snapshot.

    Mirrors the resolution logic in
    :meth:`DirectHandlerLinearizationStrategy.plan` -- first tries the
    detector, then falls back to reading ``mop_S.s.off`` from the state
    machine's ``state_var``.

    Args:
        snapshot: Immutable analysis snapshot.

    Returns:
        Stack offset of the state variable, or ``None`` if unresolvable.
    """
    state_var_stkoff: int | None = None
    detector = snapshot.detector
    if detector is not None:
        try:
            state_var_stkoff = _get_state_var_stkoff(detector)
        except Exception:
            pass
    if (
        state_var_stkoff is None
        and snapshot.state_machine is not None
        and snapshot.state_machine.state_var is not None
    ):
        sv = snapshot.state_machine.state_var
        try:
            if sv.t == ida_hexrays.mop_S:
                state_var_stkoff = sv.s.off
        except Exception:
            pass
    return state_var_stkoff


class PrivateTerminalSuffixStrategy:
    """Clone shared terminal suffix per handler entry.

    Runs AFTER direct linearization.  Identifies terminal handler paths
    that share a common epilogue suffix, classifies carriers, and emits
    :class:`~d810.optimizers.microcode.flow.flattening.hodur._modification_bridge.PrivateTerminalSuffix`
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

        fg: FlowGraph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        state_machine = snapshot.state_machine

        # ---- Resolve state_var_stkoff ----
        state_var_stkoff = _resolve_state_var_stkoff(snapshot)
        if state_var_stkoff is None:
            logger.info("[pts-strategy] state_var_stkoff is None, skipping")
            return None

        # ---- Collect infrastructure blocks ----
        sm_blocks = collect_state_machine_blocks(state_machine)

        # BST node blocks -- same approach as DirectHandlerLinearizationStrategy
        bst_node_blocks: set[int] = set(
            getattr(bst_result, "bst_node_blocks", set()) or set()
        )
        bst_node_blocks.add(dispatcher_serial)

        # ---- Find terminal exit target (return/stop block) ----
        # Use first handler check_block as first_check_block -- same as
        # terminal_loop_cleanup.py
        handlers = getattr(state_machine, "handlers", {}) or {}
        if not handlers:
            logger.info("[pts-strategy] no handlers in state machine")
            return None

        terminal_target = find_terminal_exit_target_snapshot(
            fg, dispatcher_serial, sm_blocks
        )
        if terminal_target is None:
            logger.info("[pts-strategy] no terminal exit target found")
            return None

        # ---- Compute CFG suffix frontier ----
        cfg_frontier = compute_terminal_cfg_suffix_frontier(
            return_block_serial=terminal_target,
            predecessors_of=fg.predecessors,
        )
        if cfg_frontier is None:
            logger.info("[pts-strategy] no CFG suffix frontier")
            return None

        shared_entry = cfg_frontier.shared_entry_serial
        return_block = cfg_frontier.return_block_serial
        suffix_serials = cfg_frontier.suffix_serials

        # ---- Compute semantic frontier ----
        semantic_frontier = classify_cfg_suffix_action(cfg_frontier)
        if semantic_frontier.action != TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX:
            logger.info(
                "[pts-strategy] semantic_action=%s, not PTS eligible",
                semantic_frontier.action.value,
            )
            return None

        # ---- Build full infrastructure set ----
        # Check for pre-header (block 0's single successor into dispatcher/BST)
        pre_header_serial: int | None = None
        blk0 = fg.get_block(0)
        if blk0 is not None and blk0.nsucc == 1:
            succ0 = blk0.succs[0] if blk0.succs else None
            if succ0 is not None and (
                succ0 == dispatcher_serial or succ0 in bst_node_blocks
            ):
                pre_header_serial = 0

        full_infra = frozenset(
            bst_node_blocks
            | {dispatcher_serial}
            | set(suffix_serials)
            | ({pre_header_serial} if pre_header_serial is not None else set())
        )

        # ---- Find handler terminal paths reaching shared suffix ----
        # Post-linearization: find all 1-way predecessors of shared_entry
        # that are NOT infrastructure blocks.
        shared_entry_blk = fg.get_block(shared_entry)
        if shared_entry_blk is None:
            return None

        anchors: list[int] = []
        for pred_serial in shared_entry_blk.preds:
            if pred_serial in full_infra:
                continue
            pred_blk = fg.get_block(pred_serial)
            if pred_blk is not None and pred_blk.nsucc == 1:
                anchors.append(pred_serial)

        if len(anchors) < 2:
            logger.info(
                "[pts-strategy] only %d anchors, need >= 2", len(anchors)
            )
            return None

        # ---- Classify carriers per anchor ----
        forward_entries: list[ForwardFrontierEntry] = []
        for anchor_serial in anchors:
            carrier = _classify_carrier_source(
                fg, anchor_serial, state_var_stkoff, full_infra
            )

            entry = ForwardFrontierEntry(
                handler_entry=anchor_serial,
                terminal_path=(anchor_serial,),
                forward_candidate=anchor_serial,
                candidate_succ=shared_entry,
                shared_entry=shared_entry,
                return_block=return_block,
                suffix_serials=suffix_serials,
                semantic_action=semantic_frontier.action,
                carrier_source_kind=carrier,
                proof_status="unresolved",
                notes="pts-strategy-anchor",
            )
            forward_entries.append(entry)

        # ---- Build corridor info and compute decision ----
        corridor_info = _discover_shared_corridor(
            fg=fg,
            shared_entry_serial=shared_entry,
            suffix_serials=suffix_serials,
            full_infra=full_infra,
            forward_entries=forward_entries,
        )

        decision = _compute_suffix_group_decision(
            forward_entries=forward_entries,
            corridor_info=corridor_info,
            semantic_action=semantic_frontier.action,
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
        modifications = []
        owned_blocks: set[int] = set()

        # Fix: Convert any fallthrough predecessor of the stop block to an
        # explicit goto.  Stop-block relocation changes the return_block
        # serial but the invariant checker derives outs from serial+1 for
        # fallthrough blocks → CFG_50860_SUCC_MISMATCH.  This also covers
        # the case where shared_entry == return_block (BLT_STOP has
        # multiple predecessors, suffix is just the stop block itself).
        return_blk = fg.get_block(return_block)
        if return_blk is not None:
            for pred_serial in return_blk.preds:
                pred_blk = fg.get_block(pred_serial)
                if (
                    pred_blk is not None
                    and pred_blk.nsucc == 1
                    and pred_blk.tail_opcode != ida_hexrays.m_goto
                ):
                    modifications.append(
                        builder.convert_to_goto(
                            source_block=pred_serial,
                            target_block=return_block,
                        )
                    )
                    logger.info(
                        "[pts-strategy] converting blk[%d] fallthrough to "
                        "explicit goto -> blk[%d]",
                        pred_serial,
                        return_block,
                    )

        # Fix: Convert any fallthrough ANCHOR to explicit goto.
        # PTS redirect changes the anchor's successor, but fallthrough blocks
        # derive their target from serial+1. Without explicit goto, the
        # invariant checker fires CFG_50860_SUCC_MISMATCH.
        for anchor_serial in anchors:
            anchor_blk = fg.get_block(anchor_serial)
            if (
                anchor_blk is not None
                and anchor_blk.nsucc == 1
                and anchor_blk.tail_opcode != ida_hexrays.m_goto
            ):
                modifications.append(
                    builder.convert_to_goto(
                        source_block=anchor_serial,
                        target_block=shared_entry,
                    )
                )
                logger.info(
                    "[pts-strategy] converting anchor blk[%d] fallthrough to "
                    "explicit goto -> blk[%d]",
                    anchor_serial,
                    shared_entry,
                )

        mod = builder.private_terminal_suffix_group(
            anchors=tuple(anchors),
            shared_entry_serial=shared_entry,
            return_block_serial=return_block,
            suffix_serials=suffix_serials,
        )
        modifications.append(mod)
        owned_blocks.update(anchors)

        # Claim suffix blocks as owned
        owned_blocks.update(suffix_serials)
        owned_blocks.add(shared_entry)
        owned_blocks.add(return_block)

        logger.info(
            "[pts-strategy] emitting %d PTS modifications for %d anchors",
            len(modifications),
            len(anchors),
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset((a, shared_entry) for a in anchors),
                transitions=frozenset(),
            ),
            prerequisites=["direct_handler_linearization"],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=len(anchors),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.3,
            metadata={
                "suffix_group_decision": decision,
                "corridor_info": corridor_info,
                "anchor_count": len(anchors),
                "carrier_bucket": decision.carrier_bucket.value,
                "safeguard_min_required": len(modifications),
            },
        )
