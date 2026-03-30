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

import ida_hexrays

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_fragments import (
    finalize_reconstruction_fragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_postprocess import (
    run_reconstruction_postprocess as execute_reconstruction_postprocess,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_recovery import (
    emit_primary_reconstruction_modifications as execute_reconstruction_primary_recovery,
    emit_shared_group_modifications as execute_reconstruction_shared_group,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_rescues import (
    emit_entry_island_rescues as execute_reconstruction_entry_island_rescues,
    emit_late_island_rescues as execute_reconstruction_late_island_rescues,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_reporting import (
    snapshot_reconstruction_dag,
    snapshot_reconstruction_post_apply,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_terminal_families import (
    emit_terminal_family_splits as execute_reconstruction_terminal_family_splits,
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
from d810.recon.flow.edge_metadata import edge_kind_name
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint
from d810.recon.flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
    collect_shared_suffix_blocks,
    resolve_state_var_stkoff,
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
        return execute_reconstruction_shared_group(
            logger,
            shared_block,
            candidates,
            flow_graph=flow_graph,
            mba=mba,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
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

        execute_reconstruction_primary_recovery(
            logger,
            raw_candidates=raw_candidates,
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            mba=mba,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
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
            logger,
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
            shared_suffix_blocks=shared_suffix_blocks,
            rejected_metadata=rejected_metadata,
            owned_blocks=owned_blocks,
            mba=mba,
            emit_entry_island_rescues=lambda *args, **kwargs: execute_reconstruction_entry_island_rescues(
                logger, *args, **kwargs
            ),
            emit_late_island_rescues=lambda *args, **kwargs: execute_reconstruction_late_island_rescues(
                logger, *args, **kwargs
            ),
            emit_terminal_family_splits=lambda *args, **kwargs: execute_reconstruction_terminal_family_splits(
                logger, *args, **kwargs
            ),
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
