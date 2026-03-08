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

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.graph_modification import (
    DirectTerminalLoweringGroup,
    DirectTerminalLoweringKind,
    DirectTerminalLoweringSite,
)
from d810.cfg.flow.terminal_return import (
    TerminalLoweringAction,
    classify_cfg_suffix_action,
    compute_terminal_cfg_suffix_frontier,
)
from d810.evaluator.hexrays_microcode.terminal_return_proof import (
    CarrierValueKind,
    classify_carrier_value,
    prove_terminal_returns,
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
    CarrierBucket,
    CarrierSourceKind,
    ForwardFrontierEntry,
    SuffixGroupDecision,
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

logger = logging.getLogger("D810.hodur.strategy.direct_terminal_lowering")

__all__ = ["DirectTerminalLoweringStrategy"]


def _resolve_state_var_stkoff(snapshot: AnalysisSnapshot) -> int | None:
    """Resolve state variable stack offset from snapshot.

    Mirrors the resolution logic in
    :class:`PrivateTerminalSuffixStrategy` -- first tries the
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

        fg: FlowGraph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        state_machine = snapshot.state_machine

        # ---- Resolve state_var_stkoff ----
        state_var_stkoff = _resolve_state_var_stkoff(snapshot)
        if state_var_stkoff is None:
            logger.info("[dtl-strategy] state_var_stkoff is None, skipping")
            return None

        # ---- Collect infrastructure blocks ----
        sm_blocks = collect_state_machine_blocks(state_machine)

        bst_node_blocks: set[int] = set(
            getattr(bst_result, "bst_node_blocks", set()) or set()
        )
        bst_node_blocks.add(dispatcher_serial)

        # ---- Handlers ----
        handlers = getattr(state_machine, "handlers", {}) or {}
        if not handlers:
            logger.info("[dtl-strategy] no handlers in state machine")
            return None

        # ---- Find terminal exit target (return/stop block) ----
        terminal_target = find_terminal_exit_target_snapshot(
            fg, dispatcher_serial, sm_blocks
        )
        if terminal_target is None:
            logger.info("[dtl-strategy] no terminal exit target found")
            return None

        # ---- Compute CFG suffix frontier ----
        cfg_frontier = compute_terminal_cfg_suffix_frontier(
            return_block_serial=terminal_target,
            predecessors_of=fg.predecessors,
        )
        if cfg_frontier is None:
            logger.info("[dtl-strategy] no CFG suffix frontier")
            return None

        shared_entry = cfg_frontier.shared_entry_serial
        return_block = cfg_frontier.return_block_serial
        suffix_serials = cfg_frontier.suffix_serials

        # ---- Compute semantic frontier ----
        semantic_frontier = classify_cfg_suffix_action(cfg_frontier)
        if semantic_frontier.action != TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX:
            logger.info(
                "[dtl-strategy] semantic_action=%s, not eligible",
                semantic_frontier.action.value,
            )
            return None

        # ---- Build full infrastructure set ----
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
                "[dtl-strategy] only %d anchors, need >= 2", len(anchors)
            )
            return None

        # ---- Resolve known state constants for per-anchor DTL detection ----
        known_state_constants: set[int] = set()
        try:
            sc = snapshot.state_constants
            if sc is not None:
                known_state_constants = set(sc)
        except Exception:
            pass

        # ---- Classify carriers per anchor ----
        forward_entries: list[ForwardFrontierEntry] = []
        for anchor_serial in anchors:
            carrier, carrier_const = _classify_carrier_source(
                fg, anchor_serial, state_var_stkoff, full_infra
            )

            requires_dtl = (
                carrier_const is not None
                and carrier_const in known_state_constants
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
                notes="dtl-strategy-anchor",
                state_const_written=carrier_const,
                requires_dtl=requires_dtl,
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
        dtl_anchors: tuple[int, ...] = ()
        if decision.carrier_bucket == CarrierBucket.NEEDS_DIRECT_LOWERING:
            # Group-level: all anchors are DTL candidates.
            dtl_anchors = tuple(anchors)
        elif decision.dtl_anchor_serials:
            # Per-anchor override: only anchors that leak state constants.
            dtl_anchors = decision.dtl_anchor_serials
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

        # ---- Prove return values per DTL anchor ----
        sites: list[DirectTerminalLoweringSite] = []
        for anchor_serial in dtl_anchors:
            site = self._prove_and_classify_anchor(
                mba=snapshot.mba,
                anchor_serial=anchor_serial,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix_serials,
            )
            if site is not None:
                sites.append(site)

        # Filter to supported kinds (v1: RETURN_CONST, CLONE_MATERIALIZER)
        supported = [s for s in sites if s.kind in (
            DirectTerminalLoweringKind.RETURN_CONST,
            DirectTerminalLoweringKind.CLONE_MATERIALIZER,
        )]

        if not supported:
            logger.info(
                "[dtl-strategy] %d/%d anchors proved but none have supported "
                "kind (or proof not yet connected)",
                len(sites), len(anchors),
            )
            return None

        # ---- Emit DTL modification ----
        group = DirectTerminalLoweringGroup(
            shared_entry_serial=shared_entry,
            return_block_serial=return_block,
            suffix_serials=tuple(suffix_serials),
            sites=tuple(supported),
            reason="direct_terminal_lowering",
        )

        owned_blocks: set[int] = set(anchors)
        owned_blocks.update(suffix_serials)
        owned_blocks.add(shared_entry)
        owned_blocks.add(return_block)

        logger.info(
            "[dtl-strategy] emitting DTL group with %d sites (anchors=%s)",
            len(supported),
            [s.anchor_serial for s in supported],
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=[group],
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset((a, shared_entry) for a in anchors),
                transitions=frozenset(),
            ),
            prerequisites=[
                "direct_handler_linearization",
                "private_terminal_suffix",
            ],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=len(supported),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.4,
            metadata={
                "suffix_group_decision": decision,
                "corridor_info": corridor_info,
                "anchor_count": len(anchors),
                "carrier_bucket": decision.carrier_bucket.value,
                "proven_sites": len(supported),
                "total_anchors": len(anchors),
            },
        )

    def _prove_and_classify_anchor(
        self,
        mba: object,
        anchor_serial: int,
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
    ) -> DirectTerminalLoweringSite | None:
        """v1: classify all needs_direct_lowering anchors as CLONE_MATERIALIZER.

        Clone the shared materializer blocks (suffix minus BLT_STOP) per anchor.
        Each clone inherits the anchor's path-local state, letting IDA's subsequent
        optimization passes resolve the correct return value.

        Args:
            mba: The current ``mba_t`` (IDA microcode array).
            anchor_serial: Block serial of the anchor (handler exit).
            shared_entry_serial: Block serial of the shared suffix entry.
            return_block_serial: Block serial of the return/stop block.
            suffix_serials: Tuple of block serials in the shared suffix.

        Returns:
            A :class:`DirectTerminalLoweringSite` if the anchor is valid,
            or ``None`` if validation fails.
        """
        # Validate anchor exists and points to shared entry
        anchor_blk = mba.get_mblock(anchor_serial)
        if anchor_blk is None or anchor_blk.nsucc() != 1:
            logger.debug("DTL: anchor %d invalid (None or nsucc!=1)", anchor_serial)
            return None

        if anchor_blk.succ(0) != shared_entry_serial:
            logger.debug("DTL: anchor %d succ(0)=%d != shared_entry=%d",
                         anchor_serial, anchor_blk.succ(0), shared_entry_serial)
            return None

        # v1: all anchors get CLONE_MATERIALIZER
        # Interior suffix = suffix_serials minus the last one (BLT_STOP/return_block)
        interior_serials = tuple(s for s in suffix_serials if s != return_block_serial)
        if not interior_serials:
            logger.debug("DTL: no interior suffix blocks for anchor %d", anchor_serial)
            return None

        return DirectTerminalLoweringSite(
            anchor_serial=anchor_serial,
            kind=DirectTerminalLoweringKind.CLONE_MATERIALIZER,
            materializer_serials=interior_serials,
        )
