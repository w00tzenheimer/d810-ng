"""Hodur live-MBA services for post-pipeline hooks."""
from __future__ import annotations

import ida_hexrays

from d810.core import logging
from d810.transforms.dispatcher_residue_cleanup_planning import (
    plan_dispatcher_residue_cleanup,
    plan_unreachable_region_cleanup,
)
from d810.transforms.mbl_keep_selection import (
    TerminalByteKeepTarget,
    select_terminal_byte_keep_targets,
)
from d810.hexrays.mutation.dispatcher_residue_cleanup import (
    apply_dispatcher_residue_cleanup_plan,
    apply_unreachable_region_cleanup_plan,
)
from d810.hexrays.mutation.ir_translator import lift
from d810.hexrays.utils.hexrays_formatters import format_mop_t
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.transforms.plan_fragment import (
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.state_machine_rule_services import (
    StateMachineRuleServices,
)
from d810.analyses.control_flow.dispatcher_residue_cleanup_discovery import (
    discover_dispatcher_residue_cleanup_facts,
    discover_unreachable_region_cleanup_facts,
)

__all__ = [
    "TerminalByteMblKeepServices",
    "LiveMbaTopologyServices",
    "DiagnosticSnapshotServices",
    "FragmentMetadataServices",
    "PipelineReportServices",
    "MayOnlyProbeServices",
    "DispatcherRegionCleanupServices",
    "StateWriteResolutionServices",
    "HodurLiveRuleServices",
]

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)
MBL_KEEP = getattr(ida_hexrays, "MBL_KEEP", 0x10000)


def _mlist_text(value) -> str | None:
    dstr = getattr(value, "dstr", None)
    if dstr is None:
        return None
    try:
        text = dstr()
    except Exception:
        return None
    return text or None


def _mblock_int_attr(blk, *names: str) -> int | None:
    for name in names:
        value = getattr(blk, name, None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _ea_in_block(blk, ea: int) -> bool:
    start = _mblock_int_attr(blk, "start", "start_ea")
    if start is None:
        return False
    end = _mblock_int_attr(blk, "end", "end_ea")
    if end is None or end <= start:
        return int(ea) == start
    return start <= int(ea) < end


def _block_matches_terminal_byte_target(
    blk,
    targets: tuple[TerminalByteKeepTarget, ...],
) -> bool:
    serial = _mblock_int_attr(blk, "serial")
    start = _mblock_int_attr(blk, "start", "start_ea")
    for target in targets:
        if target.block_ea is not None and start == target.block_ea:
            return True
        if target.source_ea is not None and _ea_in_block(blk, target.source_ea):
            return True
        if (
            target.block_serial is not None
            and target.block_ea is None
            and target.source_ea is None
            and serial == target.block_serial
        ):
            return True
    return False


class TerminalByteMblKeepServices:
    def _tag_terminal_byte_mbl_keep(self, snapshot: AnalysisSnapshot) -> int:
        fact_view = getattr(snapshot, "diagnostic_fact_view", None)
        if fact_view is None and self.flow_context is not None:
            try:
                fact_view = self.flow_context.validated_fact_view(self.cur_maturity)
            except Exception:
                unflat_logger.debug(
                    "MBL_KEEP_TERMINAL_BYTE fact view lookup failed",
                    exc_info=True,
                )
                fact_view = None
        if fact_view is None:
            unflat_logger.info("MBL_KEEP_TERMINAL_BYTE skipped reason=no_fact_view")
            return 0

        targets = select_terminal_byte_keep_targets(fact_view)
        if not targets:
            unflat_logger.info("MBL_KEEP_TERMINAL_BYTE skipped reason=no_targets")
            return 0

        qty = int(getattr(self.mba, "qty", 0) or 0)
        tagged_serials: list[int] = []
        for serial in range(qty):
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            if not _block_matches_terminal_byte_target(blk, targets):
                continue
            try:
                pre_flags = int(blk.flags)
                blk.flags |= MBL_KEEP
                post_flags = int(blk.flags)
            except Exception:
                continue
            tagged_serials.append(serial)
            if pre_flags != post_flags:
                unflat_logger.info(
                    "MBL_KEEP_TERMINAL_BYTE blk[%d] flags 0x%05x -> 0x%05x",
                    serial,
                    pre_flags,
                    post_flags,
                )

        bytes_kept = sorted(
            {
                int(t.byte_index)
                for t in targets
                if t.byte_index is not None
            }
        )
        unflat_logger.info(
            "MBL_KEEP_TERMINAL_BYTE targets=%d bytes=%s tagged=%d serials=%s",
            len(targets),
            bytes_kept,
            len(tagged_serials),
            tagged_serials[:30],
        )
        return len(tagged_serials)



class LiveMbaTopologyServices:
    def _build_successor_map(self) -> dict[int, list[int]]:
        """Build successor map from current MBA state."""
        succs: dict[int, list[int]] = {}
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            succs[i] = [blk.succ(j) for j in range(blk.nsucc())]
        return succs


    def _find_exit_blocks(self) -> frozenset[int]:
        """Find blocks with 0 successors (function exits)."""
        exits: set[int] = set()
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.nsucc() == 0:
                exits.add(i)
        return frozenset(exits)


    def _find_stop_serial(self) -> int | None:
        """Return the live BLT_STOP serial, falling back only if none is typed."""
        mba = self.mba
        qty = int(getattr(mba, "qty", 0) or 0) if mba is not None else 0
        for serial in range(qty):
            blk = mba.get_mblock(serial)
            if (
                blk is not None
                and int(getattr(blk, "type", -1)) == int(ida_hexrays.BLT_STOP)
            ):
                return serial
        if qty > 0:
            unflat_logger.warning(
                "UnreachableRegionCleanup: no BLT_STOP block found; "
                "falling back to last serial %d",
                qty - 1,
            )
            return qty - 1
        return None



class DiagnosticSnapshotServices:
    def _capture_post_pipeline_diagnostic_snapshot(self) -> None:
        """Persist a post-pipeline MBA snapshot for recon-only/manual inspection."""
        try:
            from d810.hexrays.mba_serializer import mba_to_block_snapshots
            from d810.hexrays.observability import request_capture_mba_snapshot
            request_capture_mba_snapshot(
                blocks=mba_to_block_snapshots(self.mba),
                label="post_pipeline",
                func_ea=self.mba.entry_ea,
                maturity="MMAT_GLBOPT1",
                phase="post_pipeline",
            )
        except Exception:
            unflat_logger.debug(
                "post_pipeline diagnostic snapshot failed (non-critical)",
                exc_info=True,
            )


    def _capture_intermediate_snapshot(
        self, label: str, *, phase: str = "post_apply"
    ) -> None:
        """Take a labeled MBA snapshot at an arbitrary intermediate point.

        Best-effort: failure is logged debug-only and never gates the pipeline.
        Used to bisect the post-HCC/pre-post_pipeline window when investigating
        which pass kills which block.
        """
        try:
            from d810.hexrays.mba_serializer import mba_to_block_snapshots
            from d810.hexrays.observability import request_capture_mba_snapshot
            request_capture_mba_snapshot(
                blocks=mba_to_block_snapshots(self.mba),
                label=label,
                func_ea=self.mba.entry_ea,
                maturity="MMAT_GLBOPT1",
                phase=phase,
            )
        except Exception:
            unflat_logger.debug(
                "intermediate snapshot %s failed (non-critical)",
                label,
                exc_info=True,
            )



class FragmentMetadataServices:
    def _extract_handler_paths_from_fragments(
        self, fragments: list
    ) -> dict[int, list[object]]:
        """Extract handler_paths from the DirectLinearization fragment metadata.

        Iterates collected fragments and returns the handler_paths dict from
        the first fragment that contains it (direct_handler_linearization strategy).
        Falls back to empty dict when no fragment provides handler_paths.

        Args:
            fragments: List of PlanFragment objects collected from strategies.

        Returns:
            Mapping of handler_serial -> list[HandlerPathResult], or empty dict.
        """
        for fragment in fragments:
            hp = fragment.metadata.get("handler_paths")
            if hp:
                unflat_logger.info(
                    "Extracted handler_paths from fragment '%s': %d handlers",
                    fragment.strategy_name,
                    len(hp),
                )
                return hp
        return {}



class PipelineReportServices:
    def _log_state_machine(self) -> None:
        """Log the detected state machine structure."""
        if self.state_machine is None:
            return

        unflat_logger.info("=== State Machine ===")
        unflat_logger.info(
            "State variable: %s",
            (
                format_mop_t(self.state_machine.state_var)
                if self.state_machine.state_var
                else "unknown"
            ),
        )
        unflat_logger.info(
            "Initial state: %s",
            (
                hex(self.state_machine.initial_state)
                if self.state_machine.initial_state
                else "unknown"
            ),
        )
        unflat_logger.info(
            "State constants: %s",
            ", ".join(hex(c) for c in sorted(self.state_machine.state_constants)),
        )
        unflat_logger.info("Transitions:")
        for t in self.state_machine.transitions:
            unflat_logger.info(
                "  %s -> %s (block %d)",
                hex(t.from_state) if t.from_state is not None else "None",
                hex(t.to_state),
                t.from_block,
            )


    def _log_pipeline_results(
        self, results: list[StageResult], nb_changes: int
    ) -> None:
        """Log a summary of the pipeline execution results."""
        stages_ok = sum(1 for r in results if r.success)
        stages_fail = sum(1 for r in results if not r.success)
        unflat_logger.info(
            "Pipeline results: %d changes, %d stages ok, %d stages failed",
            nb_changes,
            stages_ok,
            stages_fail,
        )
        for result in results:
            if not result.success:
                unflat_logger.warning(
                    "Stage %s failed: %s", result.strategy_name, result.error
                )
            else:
                unflat_logger.debug(
                    "Stage %s: %d edits, reachability=%.2f",
                    result.strategy_name,
                    result.edits_applied,
                    result.reachability_after,
                )



class MayOnlyProbeServices:
    def _collect_post_apply_may_only_probe_blocks(
        self, pipeline: list, results: list[StageResult]
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        block_serials: set[int] = set()
        target_blocks: set[int] = set()
        for fragment, result in zip(pipeline, results):
            if fragment.strategy_name != "state_write_reconstruction":
                continue
            if not result.success or result.edits_applied <= 0:
                continue
            fidelity = fragment.metadata.get("structured_region_fidelity", {})
            if not isinstance(fidelity, dict):
                continue
            for serial in fidelity.get("post_apply_may_only_probe_blocks", ()):
                if isinstance(serial, int):
                    block_serials.add(serial)
            for serial in fidelity.get("post_apply_may_only_probe_targets", ()):
                if isinstance(serial, int):
                    target_blocks.add(serial)
        return tuple(sorted(block_serials)), tuple(sorted(target_blocks))


    def _apply_post_apply_may_only_probe(
        self,
        *,
        block_serials: tuple[int, ...],
        target_blocks: tuple[int, ...] = (),
    ) -> None:
        probe_targets = {
            serial for serial in target_blocks if 0 <= serial < self.mba.qty
        }
        expanded_serials = set(block_serials)
        if probe_targets:
            for serial in range(self.mba.qty):
                blk = self.mba.get_mblock(serial)
                if blk is None:
                    continue
                try:
                    succs = [int(blk.succ(i)) for i in range(blk.nsucc)]
                except Exception:
                    continue
                if any(target in probe_targets for target in succs):
                    expanded_serials.add(serial)
        if not expanded_serials:
            return

        applied = 0
        for serial in sorted(expanded_serials):
            if serial < 0 or serial >= self.mba.qty:
                continue
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            try:
                blk.make_lists_ready()
            except Exception:
                unflat_logger.debug(
                    "may-only probe: make_lists_ready failed for blk[%d]",
                    serial,
                    exc_info=True,
                )
                continue

            changed_attrs: list[str] = []
            for may_attr, must_attr in (
                ("maybuse", "mustbuse"),
                ("maybdef", "mustbdef"),
            ):
                may_list = getattr(blk, may_attr, None)
                must_list = getattr(blk, must_attr, None)
                clear = getattr(may_list, "clear", None)
                add = getattr(may_list, "add", None)
                if (
                    may_list is None
                    or must_list is None
                    or clear is None
                    or add is None
                ):
                    continue

                may_only = ida_hexrays.mlist_t()
                try:
                    may_only.add(may_list)
                    may_only.sub(must_list)
                    clear()
                    add(may_only)
                except Exception:
                    unflat_logger.debug(
                        "may-only probe: failed to shrink %s for blk[%d]",
                        may_attr,
                        serial,
                        exc_info=True,
                    )
                    continue

                changed_attrs.append(
                    f"{may_attr}={_mlist_text(may_only) or '<empty>'}"
                )

            if not changed_attrs:
                continue

            applied += 1
            unflat_logger.info(
                "Applied may-only liveness probe to blk[%d]: %s",
                serial,
                ", ".join(changed_attrs),
            )

        if applied:
            unflat_logger.info(
                "Applied may-only liveness probe to %d leaked frontier blocks",
                applied,
            )



class DispatcherRegionCleanupServices:
    def _dump_post_apply_cfg_dot(
        self,
        dispatcher_serial: int,
        bst_node_blocks: object,
    ) -> None:
        """Dump post-apply CFG as DOT graph for linearization verification."""
        mba = self.mba
        bst_serials = set(bst_node_blocks) | {dispatcher_serial}

        lines: list[str] = ["--- POST_APPLY_CFG_DOT_START ---"]
        lines.append("digraph post_apply_cfg {")
        lines.append("  rankdir=TB;")

        dispatcher_preds: list[int] = []
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue

            # Color: BST=red, handler=lightblue, dispatcher=orange
            if i == dispatcher_serial:
                color = "orange"
                label = f"DISPATCHER\\nblk[{i}]"
            elif i in bst_serials:
                color = "lightcoral"
                label = f"BST\\nblk[{i}]"
            else:
                color = "lightblue"
                label = f"blk[{i}]"

            # Check if any successor is dispatcher
            goes_to_disp = False
            for si in range(blk.nsucc()):
                if blk.succ(si) == dispatcher_serial:
                    goes_to_disp = True

            if goes_to_disp and i not in bst_serials:
                color = "yellow"  # handler block still pointing to dispatcher
                dispatcher_preds.append(i)

            lines.append(
                f'  blk{i} [label="{label}" style=filled fillcolor={color}];'
            )

            for si in range(blk.nsucc()):
                succ = blk.succ(si)
                edge_color = "red" if succ == dispatcher_serial else "black"
                lines.append(f"  blk{i} -> blk{succ} [color={edge_color}];")

        lines.append("}")
        lines.append("--- POST_APPLY_CFG_DOT_END ---")

        for line in lines:
            unflat_logger.info(line)

        unflat_logger.info(
            "POST_APPLY_CFG: %d blocks, %d BST, %d still->dispatcher: %s",
            mba.qty, len(bst_serials), len(dispatcher_preds), dispatcher_preds,
        )


    def _post_apply_bst_cleanup(
        self,
        bst_node_blocks: object,
        dispatcher_serial: int,
        bst_result: object | None = None,
    ) -> int:
        """Sever handler->dispatcher back-edges to eliminate the dispatcher as loop header.

        After linearization, handler exits that couldn't be resolved still have
        edges to the dispatcher (despite NOP'd goto instructions). These edges
        keep the dispatcher as a loop header, creating while loops.

        Phase 0 backward predecessor mutation is retired here; active
        resolution belongs in the backward_pred strategy pipeline.

        Phase 1 severs 1-way handler->dispatcher edges through the Hex-Rays
        cleanup materialization backend.

        Phase 2 converts 2-way blocks with one arm going to dispatcher into 1-way
        gotos keeping the non-dispatcher successor.

        Handler entries keep their BST predecessors for reachability.
        """
        mba = self.mba
        # Lift the live mba to a portable FlowGraph at the HIGH boundary; the
        # portable discovery pass consumes the snapshot (llr-zeyu upstream-lift).
        facts = discover_dispatcher_residue_cleanup_facts(
            lift(mba),
            dispatcher_region=bst_node_blocks,
            dispatcher_serial=dispatcher_serial,
        )
        plan = plan_dispatcher_residue_cleanup(facts)
        bst_serials: set[int] = set(facts.dispatcher_region)

        # --- DOT dump: post-apply CFG before any edge severing ---
        self._dump_post_apply_cfg_dot(dispatcher_serial, bst_node_blocks)

        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return 0

        # --- Phase 0: backward-resolve dispatcher predecessors ---
        # DISABLED: backward_resolve does direct MBA manipulation outside
        # CfgTransactionEngine. All resolution should go through the
        # backward_pred strategy via the pipeline.
        backward_resolved = 0
        # if bst_result is not None:
        #     state_var = getattr(self, "state_machine", None)
        #     sv = getattr(state_var, "state_var", None) if state_var else None
        #     if sv is not None and sv.t == ida_hexrays.mop_S and sv.s is not None:
        #         backward_resolved = self._backward_resolve_dispatcher_preds(
        #             dispatcher_serial, bst_node_blocks, bst_result,
        #             state_var_stkoff=sv.s.off,
        #             state_var_mop=sv,
        #         )

        # --- Diagnostic: dispatcher predecessors BEFORE Phase 1 cleanup ---
        unflat_logger.info(
            "Dispatcher blk[%d] npred=%d BEFORE cleanup (backward_resolved=%d)",
            dispatcher_serial, disp_blk.npred(), backward_resolved,
        )
        for i in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(i)
            pred_blk = mba.get_mblock(pred_serial)
            in_bst = pred_serial in bst_serials
            nsucc = pred_blk.nsucc() if pred_blk else -1
            succ_info: list[str] = []
            if pred_blk and nsucc > 0:
                for si in range(nsucc):
                    succ_info.append(str(pred_blk.succ(si)))
            tail_op = "none"
            if pred_blk and pred_blk.tail:
                tail_op = pred_blk.tail.dstr()
            unflat_logger.info(
                "  pred blk[%d] nsucc=%d in_bst=%s succs=[%s] tail=%s",
                pred_serial, nsucc, in_bst,
                ",".join(succ_info), tail_op,
            )

        apply_result = apply_dispatcher_residue_cleanup_plan(
            mba,
            plan,
            logger=unflat_logger,
        )
        severed = apply_result.severed_1way
        severed_2way = apply_result.converted_2way

        # Phase 3 (old, DISABLED): NOP'ing BST/dispatcher block instructions to
        # prevent IDA from regenerating conditional branches at later
        # maturities was attempted but all variants fail:
        #   - NOP BST blocks + sever edges -> INTERR 52719 (orphaned blocks)
        #   - NOP BST blocks, keep edges -> segfault (2-way with no jcc)
        #   - NOP BST body only (keep tail jcc) -> segfault (broken DU chains)
        #   - NOP dispatcher only -> massive handler DCE (state var defs lost)
        #   - NOP tail goto on severed handler blocks -> DCE (0-way dead-ends)
        # IDA's def-use chains depend on BST variable definitions; any NOP
        # in these blocks cascades into handler body elimination.

        # --- Diagnostic: dispatcher predecessors AFTER cleanup ---
        unflat_logger.info(
            "Dispatcher blk[%d] npred=%d AFTER cleanup "
            "(severed_1way=%d, severed_2way=%d)",
            dispatcher_serial, disp_blk.npred(), severed, severed_2way,
        )
        for i in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(i)
            pred_blk = mba.get_mblock(pred_serial)
            in_bst = pred_serial in bst_serials
            nsucc = pred_blk.nsucc() if pred_blk else -1
            succ_info_after: list[str] = []
            if pred_blk and nsucc > 0:
                for si in range(nsucc):
                    succ_info_after.append(str(pred_blk.succ(si)))
            unflat_logger.info(
                "  remaining pred blk[%d] nsucc=%d in_bst=%s succs=[%s]",
                pred_serial, nsucc, in_bst,
                ",".join(succ_info_after),
            )

        total_severed = severed + severed_2way + backward_resolved
        unflat_logger.info(
            "BST cleanup: severed %d handler->dispatcher back-edges "
            "(%d backward-resolved, %d 1-way, %d 2-way converted to goto)",
            total_severed, backward_resolved, severed, severed_2way,
        )

        return total_severed


    def _prune_unreachable_bst_blocks(self, bst_serials: set[int]) -> int:
        """Remove unreachable BST/dispatcher blocks after linearization.

        Performs a forward BFS from block 0, identifies unreachable BST blocks,
        and removes them using hrtng's DeleteBlock pattern: sever outgoing edges,
        remove instructions via ``remove_from_block`` (NOT ``make_nop``!), set
        block type to ``BLT_NONE``, then ``remove_block``.

        Args:
            bst_serials: Set of BST comparison block serials + dispatcher serial.

        Returns:
            Number of blocks successfully removed.
        """
        from collections import deque

        mba = self.mba

        # Forward BFS from block 0
        visited: set[int] = set()
        queue: deque[int] = deque([0])
        while queue:
            serial = queue.popleft()
            if serial in visited:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for si in range(blk.nsucc()):
                succ = blk.succ(si)
                if succ not in visited:
                    queue.append(succ)

        # Identify unreachable BST blocks
        all_serials = set(range(mba.qty))
        unreachable = all_serials - visited
        unreachable_bst = unreachable & bst_serials

        unflat_logger.info(
            "PruneUnreachable: %d/%d blocks reachable, %d unreachable total, "
            "%d unreachable BST blocks",
            len(visited), mba.qty, len(unreachable), len(unreachable_bst),
        )

        # NOTE: remove_block at GLBOPT1 fails with INTERR 51920 regardless
        # of preparation (edge severing, remove_from_block, forward order).
        # Block removal requires MMAT_LOCOPT maturity (see hrtng).
        # Keeping diagnostic BFS only for now.
        return 0


    def _nop_unreachable_blocks_after_bst_cleanup(
        self,
        *,
        dispatcher_serial: int,
        bst_serials: set[int],
        reconstruction_live: set[int] | None = None,
    ) -> int:
        """Gut-and-Wire soft-kill of unreachable blocks after BST cleanup.

        ``mba.remove_empty_and_unreachable_blocks()`` segfaults at GLBOPT1.
        Instead of removing blocks, this pass "soft-kills" them: NOP payload
        instructions and leave blocks as 1-way goto shells (empty
        passthroughs).  2-way conditional blocks are converted to 1-way by
        replacing the conditional tail with ``m_goto`` to the first successor.
        Hex-Rays' later maturity passes (MMAT_CALLS+) safely fold them out.

        Blocks in *reconstruction_live* (source/target serials from applied
        pipeline modifications) are protected: they and their BFS-forward
        reachable successors are excluded from cleanup even when not reachable
        from block 0.  This prevents Gut-and-Wire from destroying corridors
        wired by the reconstruction strategy.
        """
        mba = self.mba
        qty = int(getattr(mba, "qty", 0) or 0) if mba is not None else 0
        if qty <= 1:
            return 0
        stop_serial = self._find_stop_serial()
        if stop_serial is None:
            return 0

        # Lift the live mba to a portable FlowGraph at the HIGH boundary; the
        # portable discovery pass consumes the snapshot (llr-zeyu upstream-lift).
        facts = discover_unreachable_region_cleanup_facts(
            lift(mba),
            dispatcher_serial=dispatcher_serial,
            dispatcher_region=bst_serials,
            stop_serial=stop_serial,
            reconstruction_live=reconstruction_live,
        )
        if facts.protected:
            unflat_logger.info(
                "GutAndWire: protecting %d reconstruction-owned corridor "
                "blocks from cleanup (seeds=%s)",
                len(facts.protected),
                sorted(facts.corridor_seeds)[:20],
            )

        if not facts.cleanup_candidates:
            unflat_logger.info(
                "DeadBlockElimination: no unreachable live blocks after BST cleanup"
            )
            return 0

        # REMOVED: return frontier gate was checking the wrong domain —
        # _audit_return_sites tracks pre-linearization return sites whose
        # origin_block serials belong to BST/dispatcher blocks that SHOULD
        # be eliminated.  The gate incorrectly prevented dead block cleanup
        # for blocks that are legitimately unreachable after linearization.

        if facts.orphaned:
            unflat_logger.info(
                "DeadBlockElimination: %d dispatcher-island + %d orphaned unreachable blocks "
                "(total %d)",
                len(facts.dispatcher_component),
                len(facts.orphaned),
                len(facts.cleanup_candidates),
            )

        if not facts.blocks:
            unflat_logger.info(
                "DeadBlockElimination: no unreachable dispatcher component after BST cleanup"
            )
            return 0

        # ----- Gut-and-Wire soft-kill pass -----
        # mba.remove_empty_and_unreachable_blocks() segfaults at GLBOPT1.
        # Instead of removing blocks or converting to 0-way shells (which
        # triggers INTERR 50846), NOP payload instructions and leave blocks
        # as 1-way goto shells.  Hex-Rays' later maturity passes safely
        # fold these empty passthrough blocks out.
        plan = plan_unreachable_region_cleanup(facts)
        apply_result = apply_unreachable_region_cleanup_plan(
            mba,
            plan,
            logger=unflat_logger,
        )
        if apply_result.gutted == 0:
            unflat_logger.info(
                "GutAndWire: no blocks gutted (all candidates were None)"
            )
            return 0

        return apply_result.gutted



class StateWriteResolutionServices:
    def _eval_mba_expression(
        self,
        mop: "ida_hexrays.mop_t",
        blk: "ida_hexrays.mblock_t",
        mba: "ida_hexrays.mbl_array_t",
        bst_serials: set[int],
        depth: int = 0,
    ) -> int | None:
        """Recursively evaluate a microcode operand to a constant.

        Handles: ``mop_n`` (literal), ``mop_S``/``mop_r`` (resolve from
        predecessor blocks), ``mop_d`` (sub-expression with binary ops).

        Args:
            mop: The operand to evaluate.
            blk: The block containing the instruction that uses *mop*.
            mba: The microcode block array.
            bst_serials: Set of BST-internal block serials to avoid walking into.
            depth: Recursion depth guard (max 8).

        Returns:
            Resolved 32-bit constant value, or ``None`` if unresolvable.
        """
        if depth > 8:
            return None
        if mop is None:
            return None

        # --- Literal constant -------------------------------------------------
        if mop.t == ida_hexrays.mop_n:
            return mop.nnn.value

        # --- Stack variable or register — backward-scan for literal def -------
        if mop.t in (ida_hexrays.mop_S, ida_hexrays.mop_r):
            target_stkoff = mop.s.off if mop.t == ida_hexrays.mop_S else None
            target_reg = mop.r if mop.t == ida_hexrays.mop_r else None

            search_blk = blk
            for _ in range(8):
                insn = search_blk.tail
                while insn is not None:
                    if insn.d is not None:
                        match = False
                        if (
                            target_stkoff is not None
                            and insn.d.t == ida_hexrays.mop_S
                            and insn.d.s is not None
                            and insn.d.s.off == target_stkoff
                        ):
                            match = True
                        elif (
                            target_reg is not None
                            and insn.d.t == ida_hexrays.mop_r
                            and insn.d.r == target_reg
                        ):
                            match = True

                        if match and insn.l is not None:
                            if insn.l.t == ida_hexrays.mop_n:
                                return insn.l.nnn.value
                            # Recurse for non-literal source
                            return self._eval_mba_expression(
                                insn.l, search_blk, mba, bst_serials,
                                depth + 1,
                            )
                    insn = insn.prev

                # Walk to single predecessor
                if search_blk.npred() != 1:
                    break
                pred_serial = search_blk.pred(0)
                if pred_serial in bst_serials:
                    break
                search_blk = mba.get_mblock(pred_serial)
                if search_blk is None:
                    break

            return None

        # --- Sub-expression (result of another instruction) -------------------
        if mop.t == ida_hexrays.mop_d:
            sub_insn = mop.d
            if sub_insn is None:
                return None

            # Binary operations
            _BINARY_OPS = {
                ida_hexrays.m_xor, ida_hexrays.m_sub, ida_hexrays.m_add,
                ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_mul,
            }
            if sub_insn.opcode in _BINARY_OPS:
                left = self._eval_mba_expression(
                    sub_insn.l, blk, mba, bst_serials, depth + 1,
                )
                right = self._eval_mba_expression(
                    sub_insn.r, blk, mba, bst_serials, depth + 1,
                )
                if left is not None and right is not None:
                    mask = 0xFFFFFFFF  # 32-bit state variable
                    if sub_insn.opcode == ida_hexrays.m_xor:
                        return (left ^ right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_sub:
                        return (left - right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_add:
                        return (left + right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_and:
                        return (left & right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_or:
                        return (left | right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_mul:
                        return (left * right) & mask

            # Unary: m_xdu (zero-extend), m_xds (sign-extend)
            m_xdu = getattr(ida_hexrays, "m_xdu", -1)
            m_xds = getattr(ida_hexrays, "m_xds", -1)
            if sub_insn.opcode in (m_xdu, m_xds):
                return self._eval_mba_expression(
                    sub_insn.l, blk, mba, bst_serials, depth + 1,
                )

            return None

        return None

    # Binary opcodes for 3-operand state var writes (d = op(l, r))
    _STATE_WRITE_BINARY_OPS: frozenset[int] = frozenset()  # populated at import


    @staticmethod
    def _init_binary_ops() -> frozenset[int]:
        """Lazily initialize binary op set (ida_hexrays may not be loaded)."""
        return frozenset({
            ida_hexrays.m_xor, ida_hexrays.m_sub, ida_hexrays.m_add,
            ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_mul,
        })


    def _resolve_state_write_insn(
        self,
        insn: "ida_hexrays.minsn_t",
        blk: "ida_hexrays.mblock_t",
        mba: "ida_hexrays.mbl_array_t",
        bst_serials: set[int],
    ) -> int | None:
        """Resolve the value written by *insn* to the state variable.

        Handles:
        - ``m_mov d = l``: simple copy, resolve ``l``.
        - 3-operand binary ops (``m_sub``, ``m_xor``, ``m_add``, etc.):
          resolve both ``l`` and ``r``, apply the operation.
        - Fallback: try ``_eval_mba_expression`` on ``l`` alone (legacy).

        Returns:
            Resolved 32-bit constant, or ``None`` if unresolvable.
        """
        # Lazy-init the binary ops frozenset
        if not self._STATE_WRITE_BINARY_OPS:
            type(self)._STATE_WRITE_BINARY_OPS = self._init_binary_ops()

        mask = 0xFFFFFFFF  # 32-bit state variable

        # --- m_mov: d = l ---
        if insn.opcode == ida_hexrays.m_mov:
            if insn.l is not None and insn.l.t == ida_hexrays.mop_n:
                return insn.l.nnn.value
            # Try recursive MBA eval on source operand
            return self._eval_mba_expression(
                insn.l, blk, mba, bst_serials,
            )

        # --- 3-operand binary ops: d = op(l, r) ---
        if insn.opcode in self._STATE_WRITE_BINARY_OPS:
            left = self._eval_mba_expression(
                insn.l, blk, mba, bst_serials,
            )
            right = self._eval_mba_expression(
                insn.r, blk, mba, bst_serials,
            )
            if left is not None and right is not None:
                if insn.opcode == ida_hexrays.m_xor:
                    return (left ^ right) & mask
                elif insn.opcode == ida_hexrays.m_sub:
                    return (left - right) & mask
                elif insn.opcode == ida_hexrays.m_add:
                    return (left + right) & mask
                elif insn.opcode == ida_hexrays.m_and:
                    return (left & right) & mask
                elif insn.opcode == ida_hexrays.m_or:
                    return (left | right) & mask
                elif insn.opcode == ida_hexrays.m_mul:
                    return (left * right) & mask
                unflat_logger.info(
                    "BACKWARD_RESOLVE: 3-op %d(0x%X, 0x%X) -> resolved",
                    insn.opcode, left, right,
                )
            return None

        # --- Fallback: try MBA eval on l only (covers mop_d sub-expressions) ---
        if insn.l is not None and insn.l.t == ida_hexrays.mop_n:
            return insn.l.nnn.value
        return self._eval_mba_expression(
            insn.l, blk, mba, bst_serials,
        )


    def _backward_resolve_dispatcher_preds(
        self,
        dispatcher_serial: int,
        bst_node_blocks: object,
        bst_result: object,
        state_var_stkoff: int,
        state_var_mop: object,
    ) -> int:
        """Backward-resolve handler exits that still target the dispatcher.

        For each dispatcher predecessor that is NOT a BST-internal node,
        walk instructions backward from the block tail looking for a write to
        the state variable.  When a literal constant (or depth-1 copy chain,
        or valrange fallback) resolves the value, look up the target handler
        via BST and report the candidate. Direct live redirection is retired;
        active handling belongs in the backward_pred strategy pipeline.

        This diagnostic path is intentionally read-only. It returns zero
        changes and does not mutate CFG state.

        Args:
            dispatcher_serial: Serial of the dispatcher block.
            bst_node_blocks: BST node block map from analysis.
            bst_result: ``BSTAnalysisResult`` for BST target resolution.
            state_var_stkoff: Stack offset of the state variable.
            state_var_mop: ``mop_t`` for the state variable (``mop_S``).

        Returns:
            Number of blocks successfully redirected.
        """
        from d810.evaluator.hexrays_microcode.valranges import (
            resolve_state_via_valranges,
        )
        from d810.analyses.control_flow.bst_model import resolve_target_via_bst

        mba = self.mba
        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return 0

        for pi in range(disp_blk.npred()):
            ps = disp_blk.pred(pi)
            pb = mba.get_mblock(ps)
            if pb is None:
                continue
            # Count instructions
            ic = 0
            ins = pb.head
            while ins:
                ic += 1
                ins = ins.next
            unflat_logger.info(
                "BACKWARD_RESOLVE: dispatcher pred blk[%d] start_ea=0x%X ninsn=%d npred=%d nsucc=%d",
                ps, pb.start, ic, pb.npred(), pb.nsucc(),
            )

        unflat_logger.info(
            "BACKWARD_RESOLVE: mop_S=%d mop_n=%d mop_r=%d mop_d=%d",
            ida_hexrays.mop_S, ida_hexrays.mop_n,
            ida_hexrays.mop_r, ida_hexrays.mop_d,
        )

        bst_serials: set[int] = set(bst_node_blocks)
        bst_serials.add(dispatcher_serial)

        pred_serials = [disp_blk.pred(i) for i in range(disp_blk.npred())]

        redirected = 0
        _diag_pred_count = 0  # counter for per-insn diagnostic (first 3 preds)
        for pred_serial in pred_serials:
            # Skip BST-internal nodes
            if pred_serial in bst_serials:
                unflat_logger.info(
                    "BACKWARD_RESOLVE: skipping blk[%d] — in bst_serials",
                    pred_serial,
                )
                continue

            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                continue

            # Only handle 1-way blocks targeting the dispatcher
            if pred_blk.nsucc() != 1 or pred_blk.succ(0) != dispatcher_serial:
                continue

            _diag_pred_count += 1
            _diag_verbose = _diag_pred_count <= 3

            # Try backward resolution: walk instructions backward from tail
            resolved_value: int | None = None
            _diag_found_write = False

            cur_ins = pred_blk.tail
            while cur_ins is not None:
                # Per-instruction destination diagnostic (first 3 preds only)
                if _diag_verbose:
                    unflat_logger.info(
                        "BACKWARD_RESOLVE: blk[%d] insn opcode=%d d.t=%d "
                        "d.s.off=0x%X (looking for 0x%X)",
                        pred_serial,
                        cur_ins.opcode,
                        cur_ins.d.t if cur_ins.d else -1,
                        cur_ins.d.s.off
                        if (
                            cur_ins.d
                            and cur_ins.d.t == ida_hexrays.mop_S
                            and cur_ins.d.s
                        )
                        else 0,
                        state_var_stkoff,
                    )
                if (
                    cur_ins.d is not None
                    and cur_ins.d.t == ida_hexrays.mop_S
                    and cur_ins.d.s is not None
                    and cur_ins.d.s.off == state_var_stkoff
                ):
                    _diag_found_write = True
                    # Found a write to the state variable — evaluate
                    # using full instruction semantics
                    resolved_value = self._resolve_state_write_insn(
                        cur_ins, pred_blk, mba, bst_serials,
                    )
                    if resolved_value is not None:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] resolved state write "
                            "-> 0x%X (opcode=%d)",
                            pred_serial,
                            resolved_value & 0xFFFFFFFF,
                            cur_ins.opcode,
                        )
                    elif cur_ins.l is not None and cur_ins.l.t in (
                        ida_hexrays.mop_r, ida_hexrays.mop_S,
                    ):
                        _MOP_TYPE_NAMES = {
                            1: "mop_r(reg)", 12: "mop_S(stkvar)",
                        }
                        _src_desc = _MOP_TYPE_NAMES.get(
                            cur_ins.l.t, "mop_%d" % cur_ins.l.t,
                        )
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] state_var_write: "
                            "opcode=%d src_type=%d(%s) src=%s "
                            "-> trying depth-1 copy chain",
                            pred_serial, cur_ins.opcode, cur_ins.l.t,
                            _src_desc, str(cur_ins.l),
                        )
                        resolved_value = self._backward_scan_depth1(
                            pred_blk, cur_ins.l,
                        )
                        if resolved_value is None:
                            unflat_logger.info(
                                "BACKWARD_RESOLVE: blk[%d] depth-1 copy chain "
                                "FAILED to resolve",
                                pred_serial,
                            )
                    else:
                        _src_t = cur_ins.l.t if cur_ins.l is not None else -1
                        _src_str = str(cur_ins.l) if cur_ins.l is not None else "None"
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] state_var_write: "
                            "opcode=%d src_type=%d src=%s "
                            "-> NOT resolvable (unhandled)",
                            pred_serial, cur_ins.opcode, _src_t, _src_str,
                        )
                    break
                cur_ins = cur_ins.prev

            if not _diag_found_write:
                unflat_logger.info(
                    "BACKWARD_RESOLVE: blk[%d] NO state_var_write found "
                    "(stkoff=0x%X) in any instruction — trying cross-block walk",
                    pred_serial, state_var_stkoff,
                )
                # Cross-block predecessor walking: when the current dispatcher
                # predecessor has no state_var write (OLLVM shared-tail pattern),
                # walk the single-predecessor chain up to 8 blocks deep looking
                # for the state variable write in an ancestor block.
                walk_blk = pred_blk
                for _xb_depth in range(1, 9):
                    # Per-depth diagnostic: log each block visited
                    if _diag_verbose:
                        _insn_count = 0
                        _cnt_ins = walk_blk.head
                        while _cnt_ins:
                            _insn_count += 1
                            _cnt_ins = _cnt_ins.next
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: visiting blk[%d] "
                            "start_ea=0x%X ninsn=%d npred=%d",
                            pred_serial, _xb_depth, walk_blk.serial,
                            walk_blk.start, _insn_count, walk_blk.npred(),
                        )
                        if walk_blk.serial in bst_serials:
                            unflat_logger.info(
                                "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: blk[%d] is BST — skipping",
                                pred_serial, _xb_depth, walk_blk.serial,
                            )
                    if walk_blk.npred() > 1:
                        # Multi-predecessor: resolve each arm independently
                        # (hrtng Tier 3 pattern)
                        if _diag_verbose:
                            pred_list = [walk_blk.pred(i) for i in range(walk_blk.npred())]
                            unflat_logger.info(
                                "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: multi-pred blk[%d] "
                                "npred=%d preds=%s, trying per-arm",
                                pred_serial, _xb_depth, walk_blk.serial,
                                walk_blk.npred(), pred_list,
                            )
                        per_pred_results: list[tuple[int, int]] = []
                        for _arm_idx in range(walk_blk.npred()):
                            arm_pred_serial = walk_blk.pred(_arm_idx)
                            if arm_pred_serial in bst_serials:
                                continue
                            arm_blk = mba.get_mblock(arm_pred_serial)
                            if arm_blk is None:
                                continue

                            if _diag_verbose:
                                arm_insn_summary = []
                                _tmp = arm_blk.tail
                                for _ in range(3):
                                    if _tmp is None:
                                        break
                                    arm_insn_summary.append(
                                        f"op={_tmp.opcode} d.t={_tmp.d.t if _tmp.d else -1}"
                                    )
                                    _tmp = _tmp.prev
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arm blk[%d] npred=%d insns=[%s]",
                                    pred_serial, arm_pred_serial, arm_blk.npred(),
                                    ", ".join(arm_insn_summary),
                                )

                            # Walk this arm backward looking for state var write
                            arm_value: int | None = None
                            arm_walk = arm_blk
                            for _arm_depth in range(8):
                                _arm_insn = arm_walk.tail
                                while _arm_insn is not None:
                                    if _diag_verbose:
                                        unflat_logger.info(
                                            "BACKWARD_RESOLVE: blk[%d] arm blk[%d] "
                                            "depth-%d insn op=%d d.t=%d d.s.off=0x%X",
                                            pred_serial, arm_walk.serial,
                                            _arm_depth, _arm_insn.opcode,
                                            _arm_insn.d.t if _arm_insn.d else -1,
                                            _arm_insn.d.s.off
                                            if (
                                                _arm_insn.d
                                                and _arm_insn.d.t == ida_hexrays.mop_S
                                                and _arm_insn.d.s
                                            )
                                            else 0,
                                        )
                                    # Same state_var_write check as existing code
                                    if (
                                        _arm_insn.d is not None
                                        and _arm_insn.d.t == ida_hexrays.mop_S
                                        and _arm_insn.d.s is not None
                                        and _arm_insn.d.s.off == state_var_stkoff
                                    ):
                                        arm_value = self._resolve_state_write_insn(
                                            _arm_insn, arm_walk, mba,
                                            bst_serials,
                                        )
                                        if arm_value is not None:
                                            unflat_logger.info(
                                                "BACKWARD_RESOLVE: blk[%d] "
                                                "arm blk[%d] resolved "
                                                "-> 0x%X (opcode=%d)",
                                                pred_serial,
                                                arm_pred_serial,
                                                arm_value & 0xFFFFFFFF,
                                                _arm_insn.opcode,
                                            )
                                        break  # found write
                                    _arm_insn = _arm_insn.prev

                                if arm_value is not None:
                                    break
                                # Continue if single-pred
                                if arm_walk.npred() != 1:
                                    break
                                _next = arm_walk.pred(0)
                                if _next in bst_serials:
                                    break
                                arm_walk = mba.get_mblock(_next)
                                if arm_walk is None:
                                    break

                            if arm_value is not None:
                                per_pred_results.append(
                                    (arm_pred_serial, arm_value),
                                )
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arm blk[%d] "
                                    "-> literal 0x%X",
                                    pred_serial, arm_pred_serial, arm_value,
                                )
                            else:
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arm blk[%d] "
                                    "-> UNRESOLVED",
                                    pred_serial, arm_pred_serial,
                                )

                        # Check if all arms agree on one BST target
                        if per_pred_results:
                            targets: set[int] = set()
                            for _, val in per_pred_results:
                                t = resolve_target_via_bst(bst_result, val)
                                if t is not None:
                                    targets.add(t)

                            if len(targets) == 1:
                                target_serial = next(iter(targets))
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] candidate "
                                    "-> blk[%d] (all %d arms agree); "
                                    "not materialized in legacy path",
                                    pred_serial,
                                    target_serial,
                                    len(per_pred_results),
                                )
                                break  # candidate found — exit xblock loop
                            elif len(targets) > 1:
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arms DISAGREE: "
                                    "targets=%s (needs block duplication "
                                    "— not yet implemented)",
                                    pred_serial,
                                    {hex(t) for t in targets},
                                )
                        break  # multi-pred — done with this xblock walk
                    if walk_blk.npred() == 0:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                            "npred=0, stopping walk",
                            pred_serial, _xb_depth,
                        )
                        break
                    _xb_pred_serial = walk_blk.pred(0)
                    if _xb_pred_serial in bst_serials:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                            "reached BST blk[%d], stopping",
                            pred_serial, _xb_depth, _xb_pred_serial,
                        )
                        break
                    _xb_pred_blk = mba.get_mblock(_xb_pred_serial)
                    if _xb_pred_blk is None:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                            "pred blk[%d] is None, stopping",
                            pred_serial, _xb_depth, _xb_pred_serial,
                        )
                        break

                    # Walk instructions backward in predecessor looking for
                    # state var write (same pattern as the current-block scan)
                    _xb_insn = _xb_pred_blk.tail
                    while _xb_insn is not None:
                        if (
                            _xb_insn.d is not None
                            and _xb_insn.d.t == ida_hexrays.mop_S
                            and _xb_insn.d.s is not None
                            and _xb_insn.d.s.off == state_var_stkoff
                        ):
                            _diag_found_write = True
                            # Found state var write — evaluate full
                            # instruction semantics
                            _xb_resolved = self._resolve_state_write_insn(
                                _xb_insn, _xb_pred_blk, mba, bst_serials,
                            )
                            if _xb_resolved is not None:
                                resolved_value = _xb_resolved
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                                    "resolved 0x%X in pred blk[%d] (opcode=%d)",
                                    pred_serial, _xb_depth,
                                    resolved_value & 0xFFFFFFFF,
                                    _xb_pred_serial, _xb_insn.opcode,
                                )
                            elif _xb_insn.l is not None and _xb_insn.l.t in (
                                ida_hexrays.mop_r, ida_hexrays.mop_S,
                            ):
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                                    "state_var_write in pred blk[%d] "
                                    "src_type=%d (reg/stkvar copy — continue walk)",
                                    pred_serial, _xb_depth,
                                    _xb_pred_serial, _xb_insn.l.t,
                                )
                                # Reset flag so we continue walking from this
                                # predecessor to resolve the copy chain
                                _diag_found_write = False
                            else:
                                _xb_src_t = (
                                    _xb_insn.l.t
                                    if _xb_insn.l is not None
                                    else -1
                                )
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] "
                                    "xblock-depth-%d: "
                                    "state_var_write in pred blk[%d] "
                                    "src_type=%d opcode=%d (unhandled)",
                                    pred_serial, _xb_depth,
                                    _xb_pred_serial, _xb_src_t,
                                    _xb_insn.opcode,
                                )
                            break
                        _xb_insn = _xb_insn.prev

                    if _diag_found_write:
                        # Either resolved a literal or hit an unhandled type
                        break

                    # No write in this predecessor — continue walking
                    walk_blk = _xb_pred_blk
                else:
                    # Exhausted max depth without finding write
                    unflat_logger.info(
                        "BACKWARD_RESOLVE: blk[%d] xblock walk exhausted "
                        "max depth (8) without finding state_var_write",
                        pred_serial,
                    )

            # Fallback: valrange resolution
            if resolved_value is None and pred_blk.tail is not None and state_var_mop is not None:
                try:
                    val = resolve_state_via_valranges(
                        pred_blk, state_var_mop, pred_blk.tail,
                    )
                    if val is not None:
                        resolved_value = val
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] valrange fallback "
                            "resolved state=0x%X",
                            pred_serial, val & 0xFFFFFFFF,
                        )
                except Exception:
                    pass

            if resolved_value is None:
                unflat_logger.info(
                    "BACKWARD_RESOLVE: blk[%d] UNRESOLVED after all attempts",
                    pred_serial,
                )
                continue

            # Look up target handler via BST
            try:
                target = resolve_target_via_bst(bst_result, resolved_value)
            except Exception:
                target = None

            if target is None:
                continue

            unflat_logger.info(
                "backward resolved blk[%d] state=0x%X -> handler blk[%d] "
                "candidate; not materialized in legacy path",
                pred_serial, resolved_value & 0xFFFFFFFF, target,
            )

        if redirected > 0:
            unflat_logger.info(
                "backward_resolve: redirected %d/%d dispatcher predecessors",
                redirected, len(pred_serials),
            )

        return redirected


    def _diagnostic_backward_scan(
        self,
        dispatcher_serial: int,
        bst_node_blocks: object,
        state_var_stkoff: int,
        bst_result: object,
        state_var_mop: object,
    ) -> None:
        """Diagnostic: backward-resolve state constants from dispatcher predecessors.

        Iterates all remaining dispatcher predecessors AFTER linearization +
        BST cleanup, tries to backward-resolve the state constant each one
        writes, and logs coverage.  This tells us how many unresolved handler
        exits could potentially be chained via a backward-scan approach.

        **This is diagnostic only — no CFG modifications are emitted.**

        Args:
            dispatcher_serial: Serial of the dispatcher block.
            bst_node_blocks: BST node block map from analysis.
            state_var_stkoff: Stack offset of the state variable.
            bst_result: ``BSTAnalysisResult`` for BST target resolution.
            state_var_mop: ``mop_t`` for the state variable (``mop_S``).
        """
        from d810.evaluator.hexrays_microcode.valranges import (
            resolve_state_via_valranges,
        )
        from d810.analyses.control_flow.bst_model import resolve_target_via_bst

        mba = self.mba
        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return

        bst_serials: set[int] = set(bst_node_blocks)
        bst_serials.add(dispatcher_serial)

        pred_serials = [disp_blk.pred(i) for i in range(disp_blk.npred())]

        # Counters
        already_redirected = 0
        literal_count = 0
        copy_chain_count = 0
        valrange_count = 0
        unresolved_count = 0
        target_found = 0
        unresolved_details: list[str] = []

        for pred_serial in pred_serials:
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                unresolved_count += 1
                unresolved_details.append(
                    f"blk[{pred_serial}]: block is None"
                )
                continue

            # Check if already redirected (successor is NOT dispatcher and
            # NOT in BST node set)
            is_redirected = True
            for si in range(pred_blk.nsucc()):
                s = pred_blk.succ(si)
                if s == dispatcher_serial or s in bst_serials:
                    is_redirected = False
                    break
            if pred_blk.nsucc() == 0:
                # 0-way blocks (severed) — check if they were BST nodes
                is_redirected = pred_serial not in bst_serials

            if is_redirected:
                already_redirected += 1
                continue

            # Skip BST-internal nodes — they are part of the comparison tree,
            # not handler exits.
            if pred_serial in bst_serials:
                already_redirected += 1
                continue

            # Try backward resolution: walk instructions backward from tail
            resolved_value: int | None = None
            resolution_method: str = "UNRESOLVED"

            cur_ins = pred_blk.tail
            while cur_ins is not None:
                # Check if this instruction writes to the state variable
                if (
                    cur_ins.d is not None
                    and cur_ins.d.t == ida_hexrays.mop_S
                    and cur_ins.d.s is not None
                    and cur_ins.d.s.off == state_var_stkoff
                ):
                    # Found a write to the state variable
                    if cur_ins.l is not None and cur_ins.l.t == ida_hexrays.mop_n:
                        # Source is a literal constant
                        resolved_value = cur_ins.l.nnn.value
                        resolution_method = "LITERAL"
                        break
                    elif cur_ins.l is not None and cur_ins.l.t in (
                        ida_hexrays.mop_r, ida_hexrays.mop_S,
                    ):
                        # Source is a register or stack copy — try depth-1
                        src_op = cur_ins.l
                        resolved_value = self._backward_scan_depth1(
                            pred_blk, src_op,
                        )
                        if resolved_value is not None:
                            resolution_method = "COPY_CHAIN"
                            break
                    # Write found but source not resolvable here
                    break
                cur_ins = cur_ins.prev

            # Fallback: try valrange resolution
            if resolved_value is None and pred_blk.tail is not None:
                try:
                    val = resolve_state_via_valranges(
                        pred_blk, state_var_mop, pred_blk.tail,
                    )
                    if val is not None:
                        resolved_value = val
                        resolution_method = "VALRANGE"
                except Exception:
                    pass

            # Tally results
            if resolved_value is not None:
                if resolution_method == "LITERAL":
                    literal_count += 1
                elif resolution_method == "COPY_CHAIN":
                    copy_chain_count += 1
                elif resolution_method == "VALRANGE":
                    valrange_count += 1

                # Try BST lookup
                try:
                    target = resolve_target_via_bst(bst_result, resolved_value)
                    if target is not None:
                        target_found += 1
                        unflat_logger.debug(
                            "BACKWARD_SCAN: blk[%d] %s value=0x%X -> target blk[%d]",
                            pred_serial, resolution_method,
                            resolved_value & 0xFFFFFFFF, target,
                        )
                    else:
                        unflat_logger.debug(
                            "BACKWARD_SCAN: blk[%d] %s value=0x%X -> NO BST target",
                            pred_serial, resolution_method,
                            resolved_value & 0xFFFFFFFF,
                        )
                except Exception:
                    unflat_logger.debug(
                        "BACKWARD_SCAN: blk[%d] %s value=0x%X -> BST lookup error",
                        pred_serial, resolution_method,
                        resolved_value & 0xFFFFFFFF,
                    )
            else:
                unresolved_count += 1
                # Gather detail for debug
                tail_str = pred_blk.tail.dstr() if pred_blk.tail else "none"
                unresolved_details.append(
                    f"blk[{pred_serial}]: nsucc={pred_blk.nsucc()} tail={tail_str}"
                )

        # Summary log
        total_preds = len(pred_serials)
        resolved_total = literal_count + copy_chain_count + valrange_count
        unflat_logger.info(
            "BACKWARD_SCAN: dispatcher has %d predecessors: "
            "%d already redirected, %d literal, %d copy-chain, "
            "%d valrange, %d unresolved. %d with valid BST targets.",
            total_preds, already_redirected, literal_count,
            copy_chain_count, valrange_count, unresolved_count,
            target_found,
        )

        # Log unresolved details at DEBUG
        for detail in unresolved_details:
            unflat_logger.debug("BACKWARD_SCAN unresolved: %s", detail)


    def _backward_scan_depth1(
        self,
        origin_blk: object,
        src_op: object,
    ) -> int | None:
        """Try one level of copy-chain resolution for a register/stack source.

        If *origin_blk* has exactly one predecessor, walk that predecessor's
        instructions backward looking for a write to *src_op* with an ``mop_n``
        (literal) source.

        Args:
            origin_blk: The block whose tail writes src_op to state var.
            src_op: The source operand (``mop_r`` or ``mop_S``) to trace.

        Returns:
            Concrete integer value if found, otherwise ``None``.
        """
        if origin_blk.npred() != 1:
            return None

        pred_serial = origin_blk.pred(0)
        pred_blk = self.mba.get_mblock(pred_serial)
        if pred_blk is None:
            return None

        cur_ins = pred_blk.tail
        while cur_ins is not None:
            if cur_ins.d is not None and cur_ins.d.t == src_op.t:
                # Match by type-specific identity
                match = False
                if src_op.t == ida_hexrays.mop_r:
                    match = cur_ins.d.r == src_op.r
                elif src_op.t == ida_hexrays.mop_S:
                    match = (
                        cur_ins.d.s is not None
                        and src_op.s is not None
                        and cur_ins.d.s.off == src_op.s.off
                    )
                if match and cur_ins.l is not None and cur_ins.l.t == ida_hexrays.mop_n:
                    return cur_ins.l.nnn.value
            cur_ins = cur_ins.prev

        return None



class HodurLiveRuleServices(
    StateMachineRuleServices,
    TerminalByteMblKeepServices,
    LiveMbaTopologyServices,
    DiagnosticSnapshotServices,
    FragmentMetadataServices,
    PipelineReportServices,
    MayOnlyProbeServices,
    DispatcherRegionCleanupServices,
    StateWriteResolutionServices,
):
    """Hodur service surface for live state-machine family hooks."""
