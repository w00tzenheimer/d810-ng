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

from d810.cfg.graph_modification import (
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
)
from d810.cfg.plan import is_block_creating_modification
from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_postprocess import (
    run_reconstruction_postprocess as execute_reconstruction_postprocess,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_recovery import (
    emit_primary_reconstruction_modifications as execute_reconstruction_primary_recovery,
    emit_shared_group_modifications as execute_reconstruction_shared_group,
    record_accept_metadata as record_reconstruction_accept_metadata,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_rescues import (
    emit_entry_island_rescues as execute_reconstruction_entry_island_rescues,
    emit_late_island_rescues as execute_reconstruction_late_island_rescues,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_terminal_families import (
    emit_terminal_family_splits as execute_reconstruction_terminal_family_splits,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    StateDagEdge,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.edge_metadata import edge_kind_name, make_edge_metadata
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
    def _resolve_state_var_stkoff(snapshot, state_machine) -> int | None:
        return resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(state_machine, "state_var", None),
        )

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
    def _make_edge_metadata(
        cls,
        edge: StateDagEdge,
        *,
        horizon_block: int | None = None,
        site: StateWriteSite | None = None,
        target_entry: int | None = None,
        first_shared_block: int | None = None,
        via_pred: int | None = None,
        emission_mode: str | None = None,
        rejection_reason: str | None = None,
    ) -> dict[str, int | str | None]:
        return make_edge_metadata(
            edge,
            horizon_block=horizon_block,
            site=site,
            target_entry=target_entry,
            first_shared_block=first_shared_block,
            via_pred=via_pred,
            emission_mode=emission_mode,
            rejection_reason=rejection_reason,
        )

    @classmethod
    def _emit_entry_island_rescues(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        dispatcher_region: set[int],
        mba,
    ) -> int:
        return execute_reconstruction_entry_island_rescues(
            logger,
            dag=dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            builder=builder,
            modifications=modifications,
            dispatcher_region=dispatcher_region,
            mba=mba,
        )

    @classmethod
    def _emit_late_island_rescues(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        dispatcher_region: set[int],
        dispatcher=None,
        mba,
    ) -> int:
        return execute_reconstruction_late_island_rescues(
            logger,
            dag=dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            builder=builder,
            modifications=modifications,
            dispatcher_region=dispatcher_region,
            dispatcher=dispatcher,
            mba=mba,
        )

    @classmethod
    def _emit_terminal_family_splits(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        dispatcher_region: set[int],
        state_var_stkoff: int | None,
        mba,
    ) -> int:
        return execute_reconstruction_terminal_family_splits(
            logger,
            dag=dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            builder=builder,
            modifications=modifications,
            dispatcher_region=dispatcher_region,
            state_var_stkoff=state_var_stkoff,
            mba=mba,
        )

    @classmethod
    def _record_accept(
        cls,
        metadata: list[dict[str, int | str | None]],
        candidate: ReconstructionCandidate,
    ) -> None:
        del cls
        record_reconstruction_accept_metadata(metadata, candidate)

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

        # --- Early DAG-only diagnostic snapshot (fires even if no modifications) ---
        try:
            from d810.core.diag import get_diag_db
            diag_db = get_diag_db(mba.entry_ea if mba is not None else 0)
            if diag_db is not None:
                from d810.core.diag.snapshot import (
                    DagEdge,
                    DagNode,
                    snapshot_dag,
                    snapshot_mba,
                )
                import json as _json

                _early_snap_id = snapshot_mba(
                    diag_db,
                    [],
                    label=f"{self.name}_state_write_reconstruction_dag",
                    func_ea=mba.entry_ea if mba is not None else 0,
                    maturity="MMAT_GLBOPT1",
                    phase="post_apply",
                )

                _early_dag_nodes = []
                for node in dag.nodes:
                    _early_dag_nodes.append(DagNode(
                        state=int(node.key.state_const) if node.key.state_const is not None else 0,
                        state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
                        entry_block=int(node.entry_anchor),
                        classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                        shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                    ))

                _early_dag_edges = []
                for eidx, edge in enumerate(dag.edges):
                    _early_dag_edges.append(DagEdge(
                        edge_id=eidx,
                        source_state=int(edge.source_key.state_const) if edge.source_key.state_const is not None else None,
                        target_state=int(edge.target_key.state_const) if edge.target_key is not None and edge.target_key.state_const is not None else None,
                        edge_kind=str(edge.kind.name) if hasattr(edge.kind, "name") else str(edge.kind),
                        source_block=int(edge.source_anchor.block_serial) if edge.source_anchor is not None else None,
                        source_arm=edge.source_anchor.branch_arm if edge.source_anchor is not None else None,
                        target_entry=int(edge.target_entry_anchor) if edge.target_entry_anchor is not None else None,
                        ordered_path=_json.dumps([int(s) for s in edge.ordered_path]) if edge.ordered_path else "[]",
                    ))

                snapshot_dag(diag_db, _early_snap_id, _early_dag_nodes, _early_dag_edges)
        except Exception:
            logger.warning(
                "Early diagnostic DAG snapshot failed (non-critical)",
                exc_info=True,
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
            emit_entry_island_rescues=self._emit_entry_island_rescues,
            emit_late_island_rescues=self._emit_late_island_rescues,
            emit_terminal_family_splits=self._emit_terminal_family_splits,
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

        # --- Diagnostic snapshot: DAG + modifications (gated behind D810_DIAG_SNAPSHOT=1) ---
        try:
            from d810.core.diag import get_diag_db
            diag_db = get_diag_db(mba.entry_ea if mba is not None else 0)
            if diag_db is not None:
                from d810.core.diag.snapshot import (
                    DagEdge,
                    DagNode,
                    Modification,
                    snapshot_dag,
                    snapshot_mba,
                    snapshot_modifications,
                )
                import json as _json

                # Create a snapshot anchor for this DAG
                snap_id = snapshot_mba(
                    diag_db,
                    [],  # No block data here — executor captures full MBA
                    label=f"{self.name}_state_write_reconstruction_post_apply",
                    func_ea=mba.entry_ea if mba is not None else 0,
                    maturity="MMAT_GLBOPT1",
                    phase="post_apply",
                )

                # Build DAG node snapshots
                dag_nodes = []
                for node in dag.nodes:
                    dag_nodes.append(DagNode(
                        state=int(node.key.state_const) if node.key.state_const is not None else 0,
                        state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
                        entry_block=int(node.entry_anchor),
                        classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                        shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                    ))

                # Build DAG edge snapshots
                dag_edges = []
                for eidx, edge in enumerate(dag.edges):
                    dag_edges.append(DagEdge(
                        edge_id=eidx,
                        source_state=int(edge.source_key.state_const) if edge.source_key.state_const is not None else None,
                        target_state=int(edge.target_key.state_const) if edge.target_key is not None and edge.target_key.state_const is not None else None,
                        edge_kind=str(edge.kind.name) if hasattr(edge.kind, "name") else str(edge.kind),
                        source_block=int(edge.source_anchor.block_serial) if edge.source_anchor is not None else None,
                        source_arm=edge.source_anchor.branch_arm if edge.source_anchor is not None else None,
                        target_entry=int(edge.target_entry_anchor) if edge.target_entry_anchor is not None else None,
                        ordered_path=_json.dumps([int(s) for s in edge.ordered_path]) if edge.ordered_path else "[]",
                    ))

                snapshot_dag(diag_db, snap_id, dag_nodes, dag_edges)

                # Build modification snapshots
                mod_snapshots = []
                for midx, mod in enumerate(modifications):
                    mod_type = type(mod).__name__
                    source_block = getattr(mod, "from_serial", None) or getattr(mod, "source_block", None) or getattr(mod, "src_block", None) or getattr(mod, "block_serial", None)
                    target_block = getattr(mod, "new_target", None) or getattr(mod, "goto_target", None) or getattr(mod, "conditional_target", None)
                    old_target = getattr(mod, "old_target", None)
                    mod_snapshots.append(Modification(
                        mod_index=midx,
                        mod_type=mod_type,
                        source_block=int(source_block) if source_block is not None else None,
                        target_block=int(target_block) if target_block is not None else None,
                        old_target=int(old_target) if old_target is not None else None,
                        status="emitted",
                    ))

                snapshot_modifications(diag_db, snap_id, mod_snapshots)
        except Exception:
            logger.warning(
                "Diagnostic DAG/modifications snapshot failed (non-critical)",
                exc_info=True,
            )

        # Split fragment when block-creating ops and PTS share a batch.
        # Block-creating ops (duplicate_and_redirect) shift serials, making
        # PTS suffix serials stale by the time PTS executes.  Splitting lets
        # PTS run against the settled graph after block creators are applied.
        _PTS_TYPES = (PrivateTerminalSuffix, PrivateTerminalSuffixGroup)
        pts_mods = [m for m in modifications if isinstance(m, _PTS_TYPES)]
        has_block_creators = any(is_block_creating_modification(m) for m in modifications)

        if pts_mods and has_block_creators:
            # Drop PTS from this batch — block-creating ops shift serials,
            # making suffix serials stale. PTS will be re-discovered on the
            # next optimizer invocation when the planner runs against the
            # settled post-creation flow graph with correct serials.
            non_pts_mods = [m for m in modifications if not isinstance(m, _PTS_TYPES)]
            logger.info(
                "RECON: deferring %d PTS mods to next invocation "
                "(block-creating ops would shift suffix serials)",
                len(pts_mods),
            )
            modifications = non_pts_mods

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset(owned_edges),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=len(owned_blocks),
                transitions_resolved=len(accepted_metadata),
                blocks_freed=len(owned_blocks),
                conflict_density=0.0,
            ),
            risk_score=0.25,
            metadata={
                "mode": "experimental_reconstruction",
                "reconstruction_sites": tuple(accepted_metadata),
                "reconstruction_rejections": tuple(rejected_metadata),
                "allow_post_apply_bst_cleanup": allow_post_apply_bst_cleanup,
                "post_apply_bst_cleanup_reason": post_apply_bst_cleanup_reason,
                "residual_dispatcher_preds": residual_dispatcher_preds,
                "safeguard_min_required": 1,
            },
            modifications=modifications,
        )
