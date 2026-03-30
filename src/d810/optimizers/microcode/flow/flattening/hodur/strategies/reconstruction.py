"""Experimental DAG-driven reconstruction strategy.

This strategy is reconstruction-first rather than dispatcher-first. It walks
semantic DAG edges, finds the deepest proven state-write horizon on each edge's
concrete corridor, and then rebuilds the corridor with the least invasive
rewrite that still removes the dispatcher handoff:

- direct truncation when the horizon is private and its trailing glue is clean
- predecessor split when a shared/merged block is uniquely reached via one pred
- grouped duplication when several predecessors of one shared block need
  different semantic targets
"""
from __future__ import annotations

from collections import Counter
from dataclasses import replace

import ida_hexrays

from d810.core import logging
from d810.cfg.reconstruction_execution import (
    execute_primary_reconstruction_modifications,
    execute_shared_group_reconstruction,
)
from d810.cfg.reconstruction_postprocess_execution import (
    execute_reconstruction_postprocess,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    blk_label,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_fragments import (
    finalize_reconstruction_fragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_reporting import (
    log_reconstruction_postprocess_result,
    snapshot_reconstruction_dag,
    snapshot_reconstruction_post_apply,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
)
from d810.recon.flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.edge_metadata import make_edge_metadata
from d810.recon.flow.edge_metadata import edge_kind_name
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint
from d810.recon.flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
    collect_shared_suffix_blocks,
    resolve_state_var_stkoff,
)
from d810.recon.flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.return_corridor_discovery import (
    collect_common_return_corridor,
)
from d810.recon.flow.terminal_family_collection import (
    collect_terminal_family_report,
)
from d810.recon.flow.reconstruction_candidate_builder import (
    ReconstructionCandidate,
    build_reconstruction_candidate,
)
from d810.recon.flow.transition_builder import TransitionResult

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

__all__ = ["StateWriteReconstructionStrategy"]


def _record_accept_metadata(
    metadata: list[dict[str, int | str | None]],
    candidate,
) -> None:
    metadata.append(
        make_edge_metadata(
            candidate.edge,
            horizon_block=candidate.horizon_block,
            site=candidate.site,
            target_entry=candidate.target_entry,
            first_shared_block=candidate.first_shared_block,
            via_pred=candidate.via_pred,
            emission_mode=candidate.emission_mode,
        )
    )


class StateWriteReconstructionStrategy:
    """Reconstruct proven semantic corridors from state-write horizons."""

    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "state_write_reconstruction"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    @staticmethod
    def _classify_artifact_return_blocks(
        flow_graph,
        state_var_stkoff: int,
        state_constants: set[int],
    ) -> set[int]:
        return classify_artifact_return_blocks(
            flow_graph,
            state_var_stkoff=state_var_stkoff,
            state_constants=state_constants,
        )

    def is_applicable(self, snapshot) -> bool:
        sm = snapshot.state_machine
        flow_graph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        if sm is None or flow_graph is None or bst_result is None:
            return False
        if not sm.handlers:
            return False
        return resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        ) is not None

    @classmethod
    def _emit_shared_group(
        cls,
        shared_block: int,
        candidates: list[ReconstructionCandidate],
        *,
        flow_graph,
        dispatcher_serial: int,
        bst_node_blocks: set[int],
        mba,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        accepted_metadata: list[dict[str, int | str | None]],
        rejected_metadata: list[dict[str, int | str | None]],
    ) -> int:
        del cls, dispatcher_serial, bst_node_blocks, builder
        shared_result = execute_shared_group_reconstruction(
            shared_block=int(shared_block),
            candidates=candidates,
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )
        if not shared_result.accepted_candidates and not shared_result.rejected_candidates:
            return 0

        if shared_result.rejected_candidates:
            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=shared_result.rejection_reason,
                )
                for candidate in shared_result.rejected_candidates
            )
            return 0
        for candidate in shared_result.accepted_candidates:
            _record_accept_metadata(
                accepted_metadata,
                replace(candidate, emission_mode="duplicate_and_redirect"),
            )
        logger.info(
            "RECON DAG: duplicate-and-redirect %s preds=%s",
            blk_label(mba, shared_block),
            [
                (blk_label(mba, pred), blk_label(mba, target))
                for pred, target in shared_result.per_pred_targets
            ],
        )
        return len(shared_result.accepted_candidates)

    def plan(self, snapshot):
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        bst_result = snapshot.bst_result
        flow_graph = snapshot.flow_graph
        mba = snapshot.mba
        assert sm is not None
        assert bst_result is not None
        assert flow_graph is not None

        state_var_stkoff = resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        )
        if state_var_stkoff is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        transition_result = TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(sm.transitions),
        )
        _corrected_dag_out: list = []
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=sm.initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(
                sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
            ),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
            corrected_dag_out=_corrected_dag_out,
        )
        # dag: stale augmented DAG (baseline behavior).  Used for phase 1
        # corridor candidates so redirect targets are identical to baseline.
        # corrected_dag: augmented DAG with dispatcher-validated supplemental
        # anchors.  Used for late phases (bridge, feeder, island rescue,
        # terminal family) that benefit from correct supplemental targets.
        corrected_dag = _corrected_dag_out[0] if _corrected_dag_out else dag
        constant_result = run_snapshot_constant_fixpoint(
            flow_graph,
            state_var_stkoff,
        )

        snapshot_reconstruction_dag(
            logger,
            dag=dag,
            mba=mba,
            strategy_name=self.name,
        )

        # Phase 1 uses dag (stale augmented — identical to baseline) so
        # that corridor redirect targets are unchanged.  Late phases below
        # switch to corrected_dag.
        dispatcher_region = set(dag.bst_node_blocks)
        if dag.dispatcher_entry_serial >= 0:
            dispatcher_region.add(int(dag.dispatcher_entry_serial))
        shared_suffix_blocks = collect_shared_suffix_blocks(dag)
        dag_maps = build_dag_node_maps(dag)
        node_by_key = dag_maps.node_by_key
        dispatcher_serial = int(dag.dispatcher_entry_serial)

        raw_candidates: list[ReconstructionCandidate] = []
        rejected_metadata: list[dict[str, int | str | None]] = []
        edge_kind_counts = Counter(
            edge_kind_name(e) for e in dag.edges
        )
        logger.info(
            "RECON DAG: edge distribution: %s",
            ", ".join(f"{k}={v}" for k, v in edge_kind_counts.most_common()),
        )
        for edge in dag.edges:
            candidate, rejection = build_reconstruction_candidate(
                edge,
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                state_var_stkoff=state_var_stkoff,
                constant_result=constant_result,
                shared_suffix_blocks=shared_suffix_blocks,
                dispatcher_region=dispatcher_region,
            )
            if candidate is not None:
                raw_candidates.append(candidate)
            elif rejection is not None:
                rejected_metadata.append(rejection)

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        accepted_metadata: list[dict[str, int | str | None]] = []

        if not raw_candidates:
            logger.info(
                "RECON DAG: no proven corridors across %d semantic edges (rejections=%d)",
                len(dag.edges),
                len(rejected_metadata),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
            # Fall through to Bridge Builder and Feeder redirect sections
            # which can wire edges rejected by the strict corridor emitter.

        run = execute_primary_reconstruction_modifications(
            raw_candidates=raw_candidates,
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )
        for result in run.conditional_results:
            candidate = result.candidate
            _record_accept_metadata(accepted_metadata, candidate)
            logger.info(
                "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                blk_label(mba, candidate.horizon_block),
                candidate.site.state_value & 0xFFFFFFFF,
                blk_label(mba, candidate.target_entry),
                candidate.edge.source_anchor.branch_arm or 0,
                result.redirect_count,
                result.passthrough_count,
            )

        for result in run.direct_results:
            if result.accepted_candidate is not None:
                candidate = result.accepted_candidate
                _record_accept_metadata(accepted_metadata, candidate)
                logger.info(
                    "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
                    blk_label(mba, candidate.horizon_block),
                    candidate.site.state_value & 0xFFFFFFFF,
                    blk_label(mba, candidate.target_entry),
                    1,
                )
                continue

            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    rejection_reason=result.rejection_reason,
                )
                for candidate in result.rejected_candidates
            )

        for result in run.shared_group_results:
            if result.rejected_candidates:
                rejected_metadata.extend(
                    make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=result.shared_block,
                        via_pred=candidate.via_pred,
                        rejection_reason=result.rejection_reason,
                    )
                    for candidate in result.rejected_candidates
                )
                continue
            if not result.accepted_candidates:
                continue
            for candidate in result.accepted_candidates:
                _record_accept_metadata(
                    accepted_metadata,
                    replace(candidate, emission_mode="duplicate_and_redirect"),
                )
            logger.info(
                "RECON DAG: duplicate-and-redirect %s preds=%s",
                blk_label(mba, result.shared_block),
                [
                    (blk_label(mba, pred), blk_label(mba, target))
                    for pred, target in result.per_pred_targets
                ],
            )

        if not modifications:
            logger.info(
                "RECON DAG: all %d candidate corridors were rejected during emission",
                len(raw_candidates),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
            # Fall through to Bridge Builder and Feeder redirect sections
            # which can wire edges rejected by the strict corridor emitter.
        else:
            logger.info(
                "RECON DAG: accepted %d/%d candidate corridors (rejections=%d)",
                len(accepted_metadata),
                len(raw_candidates),
                len(rejected_metadata),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )

        postprocess = execute_reconstruction_postprocess(
            dag=dag,
            corrected_dag=corrected_dag,
            flow_graph=flow_graph,
            modifications=modifications,
            builder=builder,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            bst_result=bst_result,
            state_machine=sm,
            state_var_stkoff=state_var_stkoff,
            constant_result=constant_result,
            node_by_key=node_by_key,
            rejected_metadata=rejected_metadata,
            owned_blocks=owned_blocks,
            collect_entry_island_rescue_seeds=collect_entry_island_rescue_seeds,
            collect_late_entry_island_diagnostics=collect_late_entry_island_diagnostics,
            collect_late_entry_island_rescue_seeds=collect_late_entry_island_rescue_seeds,
            collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
            compute_reachable_blocks=compute_reachable_blocks,
            classify_artifact_return_blocks=classify_artifact_return_blocks,
            collect_common_return_corridor=collect_common_return_corridor,
            collect_terminal_family_report=collect_terminal_family_report,
        )
        log_reconstruction_postprocess_result(
            logger,
            result=postprocess,
            dag=dag,
            mba=mba,
        )
        projected_flow_graph = postprocess.projected_flow_graph
        residual_dispatcher_preds = postprocess.residual_dispatcher_preds
        allow_post_apply_bst_cleanup = postprocess.allow_post_apply_bst_cleanup
        post_apply_bst_cleanup_reason = postprocess.post_apply_bst_cleanup_reason

        # Final guard: if no modifications after all emission phases, return None.
        if not modifications:
            logger.info(
                "RECON DAG: no modifications produced across strict + bridge + feeder phases",
            )
            return None

        snapshot_reconstruction_post_apply(
            logger,
            dag=dag,
            modifications=modifications,
            mba=mba,
            strategy_name=self.name,
        )

        return finalize_reconstruction_fragment(
            logger,
            strategy_name=self.name,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            allow_post_apply_bst_cleanup=allow_post_apply_bst_cleanup,
            post_apply_bst_cleanup_reason=post_apply_bst_cleanup_reason,
            residual_dispatcher_preds=residual_dispatcher_preds,
        )
