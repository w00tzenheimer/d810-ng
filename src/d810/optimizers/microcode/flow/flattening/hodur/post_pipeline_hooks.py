"""Profile-owned Hodur post-pipeline hook implementations."""
from __future__ import annotations

import os
from pathlib import Path

import ida_hexrays

from d810.core.typing import Callable
from d810.core import logging
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    FamilyPassResult,
    FamilyPostPipelineContext,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.audit_runtime import (
    finalize_return_frontier_audit,
)
from d810.optimizers.microcode.flow.flattening.hodur.post_apply_runtime import (
    collect_post_apply_bst_cleanup_blockers,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.dispatcher.return_frontier_carrier_audit import (
    audit_return_frontier_carriers,
    is_audit_enabled as is_return_carrier_audit_enabled,
)
from d810.passes.function_priors import FunctionAnalysisPriors

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)
MBL_KEEP = getattr(ida_hexrays, "MBL_KEEP", 0x10000)


class HodurPostPipelineHooks:
    """Run profile-declared Hodur post-pipeline hooks outside the rule class."""

    def __init__(
        self,
        owner,
        *,
        hook_runner,
    ) -> None:
        self.owner = owner
        self.hook_runner = hook_runner

    def run(self, family_result: FamilyPassResult) -> int:
        """Run the configured post-pipeline hooks and return final changes."""
        hook_context = FamilyPostPipelineContext(
            analysis=family_result.analysis,
            planned=family_result.planned,
            executed=family_result.executed,
            total_changes=family_result.total_changes,
            state={
                "bst_cleanup_ran": False,
                "live_residual_dispatcher_preds_by_strategy": (
                    self.owner._last_live_residual_dispatcher_preds_by_strategy
                ),
                "probe_blocks": (),
                "probe_targets": (),
            },
        )
        self.hook_runner(
            self.owner._profile.post_apply_hooks,
            self.handlers(),
            hook_context,
        )
        return hook_context.total_changes

    def handlers(self) -> dict[str, Callable[[FamilyPostPipelineContext], None]]:
        """Return Hodur hook handlers keyed by profile hook name."""
        return {
            "bst_cleanup": self._hook_bst_cleanup,
            "pipeline_summary": self._hook_pipeline_summary,
            "post_pipeline_audit": self._hook_post_pipeline_audit,
            "reachability_snapshot": self._hook_nested_bst_cleanup_capability,
            "dispatcher_residue_cache": self._hook_nested_bst_cleanup_capability,
            "post_pipeline_diagnostic_snapshot": (
                self._hook_post_pipeline_diagnostic_snapshot
            ),
            "inline_add_stkvar_canonicalization": (
                self._hook_inline_add_stkvar_canonicalization
            ),
            "terminal_byte_mbl_keep": self._hook_terminal_byte_mbl_keep,
            "tag_all_mbl_keep": self._hook_tag_all_mbl_keep,
            "tail_shaping": self._hook_tail_shaping,
            "may_only_probe": self._hook_may_only_probe,
            "bst_cleanup_reiteration_suppression": (
                self._hook_bst_cleanup_reiteration_suppression
            ),
            "may_only_probe_rerun": self._hook_may_only_probe_rerun,
            "reachable_mbl_keep": self._hook_reachable_mbl_keep,
        }

    def _post_apply_hook_enabled(self, hook_name: str) -> bool:
        """Return whether this profile declares a named post-apply hook."""
        return self.owner._profile.enables_post_apply_hook(hook_name)

    def _return_frontier_audit_enabled(self, hook_name: str) -> bool:
        """Return whether a named return-frontier audit hook is active."""
        return (
            self.owner.RETURN_FRONTIER_AUDIT_ENABLED
            and self.owner._profile.enables_audit_hook(hook_name)
        )

    def _hook_nested_bst_cleanup_capability(
        self,
        _context: FamilyPostPipelineContext,
    ) -> None:
        """Profile marker for work executed inside the BST cleanup hook."""

    def _hook_bst_cleanup(self, context: FamilyPostPipelineContext) -> None:
        context.total_changes, bst_cleanup_ran = self._run_post_apply_bst_cleanup_hook(
            context.snapshot,
            context.pipeline,
            context.results,
            context.total_changes,
            context.state.get("live_residual_dispatcher_preds_by_strategy", {}),
        )
        context.state["bst_cleanup_ran"] = bst_cleanup_ran

    def _hook_pipeline_summary(self, context: FamilyPostPipelineContext) -> None:
        self._record_family_pipeline_summary(
            context.results,
            context.provenance,
            context.total_changes,
        )

    def _hook_post_pipeline_audit(self, context: FamilyPostPipelineContext) -> None:
        self._run_post_pipeline_audit_hooks(context.snapshot)

    def _hook_post_pipeline_diagnostic_snapshot(
        self,
        _context: FamilyPostPipelineContext,
    ) -> None:
        self.owner._capture_post_pipeline_diagnostic_snapshot()

    def _hook_inline_add_stkvar_canonicalization(
        self,
        context: FamilyPostPipelineContext,
    ) -> None:
        if context.pipeline:
            self._run_inline_add_stkvar_canonicalization_hook()

    def _hook_terminal_byte_mbl_keep(
        self,
        context: FamilyPostPipelineContext,
    ) -> None:
        if context.pipeline:
            self._run_terminal_byte_mbl_keep_hook(context.snapshot)

    def _hook_tag_all_mbl_keep(self, context: FamilyPostPipelineContext) -> None:
        if context.pipeline:
            self._run_tag_all_mbl_keep_hook()

    def _hook_tail_shaping(self, context: FamilyPostPipelineContext) -> None:
        if context.pipeline:
            self._run_tail_shaping_hook(context.snapshot)

    def _hook_may_only_probe(self, context: FamilyPostPipelineContext) -> None:
        if not context.pipeline:
            return
        probe_blocks, probe_targets = self._run_may_only_probe_hook(
            context.pipeline,
            context.results,
        )
        context.state["probe_blocks"] = probe_blocks
        context.state["probe_targets"] = probe_targets

    def _hook_bst_cleanup_reiteration_suppression(
        self,
        context: FamilyPostPipelineContext,
    ) -> None:
        if not context.pipeline:
            return
        context.total_changes = self._suppress_reiteration_after_bst_cleanup(
            bst_cleanup_ran=bool(context.state.get("bst_cleanup_ran", False)),
            nb_changes=context.total_changes,
        )

    def _hook_may_only_probe_rerun(self, context: FamilyPostPipelineContext) -> None:
        if not context.pipeline:
            return
        self._rerun_may_only_probe_hook(
            probe_blocks=tuple(context.state.get("probe_blocks", ())),
            probe_targets=tuple(context.state.get("probe_targets", ())),
        )

    def _hook_reachable_mbl_keep(self, context: FamilyPostPipelineContext) -> None:
        if context.pipeline:
            self._run_reachable_mbl_keep_hook()

    def _run_post_apply_bst_cleanup_hook(
        self,
        snapshot: AnalysisSnapshot,
        pipeline: list[PlanFragment],
        results: list[StageResult],
        nb_changes: int,
        live_residual_dispatcher_preds_by_strategy: dict[str, tuple[int, ...]],
    ) -> tuple[int, bool]:
        """Run Hodur's post-apply dispatcher/BST cleanup hook."""
        owner = self.owner
        bst_cleanup_ran = False
        bst_cleanup_blockers = collect_post_apply_bst_cleanup_blockers(
            pipeline,
            results,
            live_residual_dispatcher_preds_by_strategy=(
                live_residual_dispatcher_preds_by_strategy
            ),
        )
        if bst_cleanup_blockers:
            unflat_logger.info(
                "Skipping post-apply BST cleanup because unresolved non-BST dispatcher predecessors remain: %s",
                bst_cleanup_blockers,
            )
        if not hasattr(owner, "_reconstruction_live_blocks"):
            owner._reconstruction_live_blocks: set[int] = set()
        for frag, res in zip(pipeline, results):
            if not res.success or res.edits_applied <= 0:
                continue
            for mod in frag.modifications:
                for attr in (
                    "from_serial", "new_target",
                    "goto_target", "block_serial", "source_block",
                    "src_block", "source_serial", "via_pred",
                    "conditional_target", "fallthrough_target",
                    "pred_serial", "succ_serial",
                ):
                    val = getattr(mod, attr, None)
                    if isinstance(val, int):
                        owner._reconstruction_live_blocks.add(val)
                ppt = getattr(mod, "per_pred_targets", None)
                if ppt is not None:
                    for pred, target in ppt:
                        owner._reconstruction_live_blocks.add(int(pred))
                        owner._reconstruction_live_blocks.add(int(target))

        if (
            not bst_cleanup_blockers
            and nb_changes > 0
            and snapshot.bst_result is not None
        ):
            bst_cleanup_edges = owner._post_apply_bst_cleanup(
                snapshot.bst_result.bst_node_blocks,
                snapshot.bst_dispatcher_serial,
                bst_result=snapshot.bst_result,
            )
            if bst_cleanup_edges > 0:
                nb_changes += bst_cleanup_edges
                bst_cleanup_ran = True
            owner._capture_intermediate_snapshot("post_bst_cleanup")
            return nb_changes, bst_cleanup_ran

        owner._capture_intermediate_snapshot("post_bst_cleanup_skipped")
        state_var = getattr(snapshot.state_machine, "state_var", None)
        if (
            state_var is not None
            and state_var.t == ida_hexrays.mop_S
            and snapshot.bst_result is not None
        ):
            owner._diagnostic_backward_scan(
                dispatcher_serial=snapshot.bst_dispatcher_serial,
                bst_node_blocks=snapshot.bst_result.bst_node_blocks,
                state_var_stkoff=state_var.s.off,
                bst_result=snapshot.bst_result,
                state_var_mop=state_var,
            )

        bst_serials = set()
        if snapshot.bst_result is not None:
            bst_serials = set(snapshot.bst_result.bst_node_blocks) | {
                snapshot.bst_dispatcher_serial
            }
            owner._prune_unreachable_bst_blocks(bst_serials)
        owner._capture_intermediate_snapshot("post_prune_unreachable")

        owner._reconstruction_live_blocks -= bst_serials
        owner._reconstruction_live_blocks.discard(snapshot.bst_dispatcher_serial)

        dead_cleanup_applied = owner._nop_unreachable_blocks_after_bst_cleanup(
            dispatcher_serial=snapshot.bst_dispatcher_serial,
            bst_serials=bst_serials,
            reconstruction_live=owner._reconstruction_live_blocks,
        )
        if dead_cleanup_applied > 0:
            nb_changes += dead_cleanup_applied
        owner._capture_intermediate_snapshot("post_dead_block_elim")
        self._capture_post_gut_and_wire_reachability(
            snapshot,
            results,
            bst_serials=bst_serials,
        )
        self._cache_post_apply_bst_cleanup_context(
            snapshot,
            bst_serials=bst_serials,
            dead_cleanup_applied=dead_cleanup_applied,
        )
        return nb_changes, bst_cleanup_ran

    def _capture_post_gut_and_wire_reachability(
        self,
        snapshot: AnalysisSnapshot,
        results: list[StageResult],
        *,
        bst_serials: set[int],
    ) -> None:
        """Capture diagnostic reachability after gut-and-wire cleanup."""
        owner = self.owner
        if not self._post_apply_hook_enabled("reachability_snapshot"):
            return
        try:
            from d810.hexrays.mba_serializer import mba_to_block_snapshots
            from d810.hexrays.observability import (
                request_capture_mba_snapshot,
            )
            from d810.core.observability_recon import observe_reachability

            diag_visited: set[int] = set()
            diag_queue: list[int] = [0]
            while diag_queue:
                serial = diag_queue.pop(0)
                if serial in diag_visited or serial < 0 or serial >= owner.mba.qty:
                    continue
                diag_visited.add(serial)
                block = owner.mba.get_mblock(serial)
                if block is not None:
                    for index in range(block.nsucc()):
                        diag_queue.append(block.succ(index))

            all_serials = set(range(owner.mba.qty))
            gutted_serials = all_serials - diag_visited - {owner.mba.qty - 1}
            claimed: set[int] = set()
            for result in results:
                claimed_sources = result.metadata.get("claimed_sources")
                if isinstance(claimed_sources, (set, frozenset)):
                    claimed |= set(claimed_sources)

            snap = request_capture_mba_snapshot(
                blocks=mba_to_block_snapshots(owner.mba),
                label="post_gut_and_wire",
                func_ea=owner.mba.entry_ea,
                maturity="MMAT_GLBOPT1",
                phase="post_gut_wire",
            )
            if snap is not None:
                observe_reachability(
                    snap,
                    all_serials=all_serials,
                    reachable=diag_visited,
                    bst_serials=bst_serials,
                    gutted=gutted_serials,
                    claimed_sources=claimed,
                )
        except Exception:
            unflat_logger.debug(
                "Diagnostic reachability snapshot failed (non-critical)",
                exc_info=True,
            )

    def _cache_post_apply_bst_cleanup_context(
        self,
        snapshot: AnalysisSnapshot,
        *,
        bst_serials: set[int],
        dead_cleanup_applied: int,
    ) -> None:
        """Cache dispatcher/BST residue for later Hex-Rays maturity hooks."""
        owner = self.owner
        if not self._post_apply_hook_enabled("dispatcher_residue_cache"):
            return
        if dead_cleanup_applied == 0:
            owner._last_bst_serials = bst_serials
            owner._last_dispatcher_serial = snapshot.bst_dispatcher_serial
            owner._last_func_ea = owner.mba.entry_ea
            owner._last_bst_block_eas = set()
            for serial in bst_serials:
                block = owner.mba.get_mblock(serial)
                if block is not None:
                    owner._last_bst_block_eas.add(block.start)
            owner._last_dispatcher_ea = (
                owner.mba.get_mblock(snapshot.bst_dispatcher_serial).start
                if snapshot.bst_dispatcher_serial >= 0
                and owner.mba.get_mblock(snapshot.bst_dispatcher_serial) is not None
                else 0
            )
        else:
            owner._last_bst_serials = None
            owner._last_dispatcher_serial = -1
            owner._last_bst_block_eas = set()
            owner._last_dispatcher_ea = 0

    def _record_family_pipeline_summary(
        self,
        results: list[StageResult],
        provenance: PipelineProvenance,
        nb_changes: int,
    ) -> None:
        """Record end-of-pass summary and advance the family pass counter."""
        owner = self.owner
        owner._capture_intermediate_snapshot("pre_pipeline_log")
        owner._log_pipeline_results(results, nb_changes)
        unflat_logger.info("Provenance: %s", provenance.phase_summary())
        if unflat_logger.debug_on:
            import json
            unflat_logger.debug(
                "Provenance detail: %s",
                json.dumps(provenance.to_dict(), indent=2),
            )

        unflat_logger.info(
            "HodurUnflattener: Pass %d made %d changes",
            owner._actual_pass_count,
            nb_changes,
        )
        if nb_changes == 0:
            unflat_logger.info(
                "HodurUnflattener: convergence reached at pass %d, maturity %s",
                owner._actual_pass_count,
                maturity_to_string(owner.cur_maturity),
            )
        owner._actual_pass_count += 1

    def _run_post_pipeline_audit_hooks(self, snapshot: AnalysisSnapshot) -> None:
        """Run profile-declared post-pipeline audit hooks."""
        owner = self.owner
        if (
            self._return_frontier_audit_enabled("return_frontier_post_pipeline")
            and snapshot.state_machine is not None
            and owner._audit_return_sites
        ):
            try:
                finalize_return_frontier_audit(
                    tuple(owner._audit_return_sites),
                    func_ea=owner.mba.entry_ea,
                    maturity=owner.cur_maturity,
                    log_dir=owner.log_dir,
                    artifact_dir=Path(f".tmp/recon/{owner.cur_maturity}"),
                    successors=owner._build_successor_map(),
                    exits=owner._find_exit_blocks(),
                    logger=unflat_logger,
                )
            except Exception:
                unflat_logger.debug("post_pipeline audit failed (non-critical)")

        if (
            owner._profile.enables_audit_hook("return_frontier_carrier_post_pipeline")
            and is_return_carrier_audit_enabled()
        ):
            try:
                corridors: tuple[tuple[int, ...], ...] = ()
                dag = getattr(snapshot, "dag", None)
                if dag is not None:
                    raw = getattr(dag, "side_effect_corridors", ()) or ()
                    try:
                        corridors = tuple(
                            tuple(int(block) for block in chain) for chain in raw
                        )
                    except (TypeError, ValueError):
                        corridors = ()
                function_priors = FunctionAnalysisPriors()
                if owner.flow_context is not None:
                    function_priors = owner.flow_context.function_analysis_priors(
                        owner.mba.entry_ea
                    )
                audit_return_frontier_carriers(
                    mba=owner.mba,
                    side_effect_corridors=corridors,
                    label="post_pipeline",
                    artifact_priors=(
                        function_priors.return_frontier_artifacts
                    ),
                )
            except Exception:
                unflat_logger.debug(
                    "return-frontier carrier audit failed (non-critical)",
                    exc_info=True,
                )

    def _run_inline_add_stkvar_canonicalization_hook(self) -> None:
        """Canonicalize inline add operands onto matching stack aliases."""
        try:
            from d810.hexrays.mutation.insn_snapshot_materializer import (
                canonicalize_inline_add_in_mba,
            )

            canonicalize_inline_add_in_mba(self.owner.mba)
        except Exception:
            unflat_logger.debug(
                "inline_add_to_stkvar canonicalisation failed (non-critical)",
                exc_info=True,
            )

    def _run_terminal_byte_mbl_keep_hook(self, snapshot: AnalysisSnapshot) -> None:
        """Run terminal-byte MBL_KEEP tagging when enabled."""
        if os.environ.get("D810_TERMINAL_BYTE_MBL_KEEP", "1") != "1":
            return
        try:
            tagged = self.owner._tag_terminal_byte_mbl_keep(snapshot)
            if tagged:
                self.owner._capture_intermediate_snapshot(
                    "post_mbl_keep_terminal_byte"
                )
        except Exception:
            unflat_logger.debug(
                "MBL_KEEP terminal-byte tag failed (non-critical)",
                exc_info=True,
            )

    def _run_tag_all_mbl_keep_hook(self) -> None:
        """Run the diagnostic blanket MBL_KEEP escape hatch."""
        if os.environ.get("D810_TAG_ALL_MBL_KEEP", "0") != "1":
            return
        try:
            qty = int(getattr(self.owner.mba, "qty", 0) or 0)
            tagged = 0
            for serial in range(qty):
                block = self.owner.mba.get_mblock(serial)
                if block is None:
                    continue
                try:
                    block.flags |= MBL_KEEP
                    tagged += 1
                except Exception:
                    continue
            unflat_logger.info(
                "MBL_KEEP_TAG_ALL applied tagged=%d/qty=%d", tagged, qty
            )
            self.owner._capture_intermediate_snapshot("post_mbl_keep_tag_all")
        except Exception:
            unflat_logger.debug(
                "MBL_KEEP blanket tag failed (non-critical)", exc_info=True,
            )

    def _run_tail_shaping_hook(self, snapshot: AnalysisSnapshot) -> None:
        """Run env-gated terminal tail shaping hooks."""
        owner = self.owner
        try:
            from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
                maybe_rewrite_impossible_return_artifact_edges,
                maybe_run_byte_anchor,
                maybe_run_terminal_tail_cascade_egress_lowering,
                maybe_run_tail_distinct,
                maybe_run_tail_duplicate_convergence,
                maybe_run_tail_state_cascade,
            )
            from d810.hexrays.mutation.byte_tail_runtime_evidence import (
                ByteTailRuntimeEvidence,
                StaticByteTailRuntimeEvidenceProvider,
            )

            unflat_logger.info(
                "TAIL_SHAPING_HOOK phase=after_post_bundle_stabilize"
            )
            fact_view = getattr(snapshot, "diagnostic_fact_view", None)
            if fact_view is None and owner.flow_context is not None:
                try:
                    fact_view = owner.flow_context.validated_fact_view(
                        owner.cur_maturity
                    )
                except Exception:
                    unflat_logger.debug(
                        "terminal_tail_cascade_egress fact view lookup failed",
                        exc_info=True,
                    )
                    fact_view = None
            runtime_fact_raw = os.environ.get(
                "D810_TERMINAL_TAIL_CASCADE_EGRESS_RUNTIME_FACTS", "0"
            )
            if str(runtime_fact_raw).lower() in {"1", "true", "yes", "on"}:
                try:
                    from d810.analyses.control_flow.runtime_evidence import (
                        ensure_terminal_byte_fact_view,
                    )

                    fact_view = ensure_terminal_byte_fact_view(
                        owner.mba,
                        func_ea=int(getattr(owner.mba, "entry_ea", 0) or 0),
                        maturity=int(
                            getattr(owner.mba, "maturity", owner.cur_maturity) or 0
                        ),
                        fact_view=fact_view,
                        phase="post_bundle_stabilize",
                    )
                except Exception:
                    unflat_logger.debug(
                        "terminal_tail_cascade_egress runtime fact collection failed",
                        exc_info=True,
                    )
            latest_dag = None
            try:
                from d810.analyses.control_flow.runtime_evidence import (
                    get_latest_reconstruction_dag,
                )

                latest_dag = get_latest_reconstruction_dag(
                    int(getattr(owner.mba, "entry_ea", 0) or 0)
                )
            except Exception:
                unflat_logger.debug(
                    "terminal_tail_cascade_egress DAG lookup failed",
                    exc_info=True,
                )
            function_priors = FunctionAnalysisPriors()
            if owner.flow_context is not None:
                function_priors = owner.flow_context.function_analysis_priors(
                    owner.mba.entry_ea
                )
            impossible_return_artifact_edges = tuple(
                function_priors
                .return_frontier_artifacts
                .impossible_return_artifact_edges
            )
            evidence_provider = StaticByteTailRuntimeEvidenceProvider(
                ByteTailRuntimeEvidence(
                    fact_view=fact_view,
                    dag=latest_dag,
                    terminal_tail_cascade_egress=(
                        function_priors.terminal_tail_cascade_egress
                    ),
                    impossible_return_artifact_edges=(
                        impossible_return_artifact_edges
                    ),
                )
            )
            maybe_run_terminal_tail_cascade_egress_lowering(
                owner.mba,
                fact_view=fact_view,
                dag=latest_dag,
                evidence_provider=evidence_provider,
            )
            maybe_rewrite_impossible_return_artifact_edges(
                owner.mba,
                evidence_provider=evidence_provider,
            )
            maybe_run_tail_distinct(
                owner.mba,
                fact_view=fact_view,
                evidence_provider=evidence_provider,
            )
            maybe_run_tail_duplicate_convergence(
                owner.mba,
                fact_view=fact_view,
                evidence_provider=evidence_provider,
            )
            maybe_run_tail_state_cascade(
                owner.mba,
                fact_view=fact_view,
                evidence_provider=evidence_provider,
            )
            maybe_run_byte_anchor(owner.mba)
        except Exception:
            unflat_logger.debug(
                "tail_distinct hook failed (non-critical)", exc_info=True,
            )

    def _run_may_only_probe_hook(
        self,
        pipeline: list[PlanFragment],
        results: list[StageResult],
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """Run the sticky post-apply may-only probe hook once."""
        owner = self.owner
        probe_blocks, probe_targets = owner._collect_post_apply_may_only_probe_blocks(
            pipeline, results
        )
        sticky_entry_ea = getattr(owner, "_sticky_may_only_probe_entry_ea", None)
        if sticky_entry_ea != owner.mba.entry_ea:
            owner._sticky_may_only_probe_entry_ea = owner.mba.entry_ea
            owner._sticky_may_only_probe_blocks = set()
            owner._sticky_may_only_probe_targets = set()
        owner._sticky_may_only_probe_blocks.update(probe_blocks)
        owner._sticky_may_only_probe_targets.update(probe_targets)
        probe_blocks = tuple(sorted(owner._sticky_may_only_probe_blocks))
        probe_targets = tuple(sorted(owner._sticky_may_only_probe_targets))
        owner._apply_post_apply_may_only_probe(
            block_serials=probe_blocks,
            target_blocks=probe_targets,
        )
        return probe_blocks, probe_targets

    def _suppress_reiteration_after_bst_cleanup(
        self,
        *,
        bst_cleanup_ran: bool,
        nb_changes: int,
    ) -> int:
        """Suppress Hodur re-entry after BST cleanup invalidates analysis."""
        if bst_cleanup_ran:
            unflat_logger.info(
                "BST cleanup modified CFG — suppressing Hodur re-iteration"
            )
            return 0
        return nb_changes

    def _rerun_may_only_probe_hook(
        self,
        *,
        probe_blocks: tuple[int, ...],
        probe_targets: tuple[int, ...],
    ) -> None:
        """Re-apply may-only probe after late bridge rescue blocks appear."""
        self.owner._apply_post_apply_may_only_probe(
            block_serials=probe_blocks,
            target_blocks=probe_targets,
        )

    def _run_reachable_mbl_keep_hook(self) -> None:
        """Run the optional reachable-block MBL_KEEP experiment."""
        owner = self.owner
        if not (owner.MBL_KEEP_ENABLED and owner.mba is not None and owner.mba.qty > 1):
            return
        keep_visited: set[int] = set()
        keep_queue: list[int] = [0]
        while keep_queue:
            serial = keep_queue.pop()
            if serial in keep_visited or serial < 0 or serial >= owner.mba.qty:
                continue
            keep_visited.add(serial)
            block = owner.mba.get_mblock(serial)
            if block is None:
                continue
            for index in range(block.nsucc()):
                keep_queue.append(block.succ(index))
        kept_serials: list[int] = []
        for serial in sorted(keep_visited):
            block = owner.mba.get_mblock(serial)
            if block is None:
                continue
            pre_flags = int(block.flags)
            block.flags |= ida_hexrays.MBL_KEEP
            post_flags = int(block.flags)
            if pre_flags != post_flags:
                kept_serials.append(serial)
                unflat_logger.info(
                    "MBL_KEEP: blk[%d] flags 0x%05x -> 0x%05x (set MBL_KEEP=0x%05x)",
                    serial, pre_flags, post_flags, ida_hexrays.MBL_KEEP,
                )
        unflat_logger.info(
            "MBL_KEEP: marked %d/%d reachable blocks (kept_serials=%s)",
            len(kept_serials), len(keep_visited), kept_serials[:30],
        )
