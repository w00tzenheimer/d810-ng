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

from collections import Counter, defaultdict, deque
from dataclasses import replace

import ida_hexrays

from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.graph_modification import (
    NopInstructions,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
)
from d810.cfg.lowering_selector import (
    SharedFeederContext,
    SharedFeederLoweringKind,
    select_shared_feeder_lowering,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.reconstruction_lowering import (
    SharedGroupEmissionCandidate,
)
from d810.cfg.reconstruction_modification_planning import (
    plan_conditional_arm_reconstruction_modifications,
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
    plan_shared_group_reconstruction_modifications,
)
from d810.cfg.terminal_family_split import (
    plan_terminal_family_splits,
)
from d810.cfg.plan import compile_patch_plan, is_block_creating_modification
from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_rescues import (
    emit_entry_island_rescues as execute_reconstruction_entry_island_rescues,
    emit_late_island_rescues as execute_reconstruction_late_island_rescues,
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
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
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
from d810.recon.flow.terminal_family_collection import (
    collect_terminal_family_report,
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
        run = plan_terminal_family_splits(
            dag=dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
            state_var_stkoff=state_var_stkoff,
            builder=builder,
            modifications=modifications,
            collect_report=collect_terminal_family_report,
            compute_reachable_blocks=lambda flow_graph: compute_reachable_blocks(
                flow_graph,
                start_serial=getattr(flow_graph, "entry_serial", None),
            ),
        )

        for iteration in run.iterations:
            report = iteration.report
            for seed_report in report.seed_reports:
                probe = seed_report.probe
                seed = probe.seed
                logger.info(
                    "RECON RETURN: terminal-family seed src=%s%s origins=%s "
                    "source_reachable=%s source_nsucc=%s arm_target=%s arm_target_origin=%s "
                    "family_entry=%s family_entry_origin=%s projected_path=%s stop=%s "
                    "rejection=%s path=%s",
                    blk_label(mba, int(seed.source_block)),
                    f".arm{seed.branch_arm}" if seed.branch_arm is not None else "",
                    list(probe.seed_origins),
                    probe.source_reachable,
                    probe.source_nsucc,
                    blk_label(mba, probe.arm_target) if probe.arm_target is not None else "None",
                    "projected_only" if probe.arm_target_projected_only else "base",
                    blk_label(mba, probe.family_entry) if probe.family_entry is not None else "None",
                    "projected_only" if probe.family_entry_projected_only else "base",
                    [blk_label(mba, serial) for serial in probe.path_projected_only_blocks],
                    blk_label(mba, probe.stop_block) if probe.stop_block is not None else "None",
                    probe.rejection_reason,
                    probe.path,
                )
                if probe.rejection_reason == "source_unreachable":
                    diagnostic = seed_report.unreachable_diagnostic
                    if diagnostic is None:
                        logger.info(
                            "RECON RETURN: source_unreachable diagnostic %s: "
                            "not in projected flow graph",
                            blk_label(mba, int(seed.source_block)),
                        )
                    else:
                        logger.info(
                            "RECON RETURN: source_unreachable diagnostic %s "
                            "preds=[%s] nearest_reachable=%s island_blocks=%s",
                            blk_label(mba, diagnostic.source_block),
                            ", ".join(diagnostic.pred_info),
                            (
                                blk_label(mba, diagnostic.nearest_reachable)
                                if diagnostic.nearest_reachable is not None
                                else "None"
                            ),
                            [blk_label(mba, b) for b in diagnostic.island_blocks],
                        )
            for candidate_report in report.candidate_reports:
                candidate = candidate_report.candidate
                logger.info(
                    "RECON RETURN: terminal-family inspect src=%s%s family_entry=%s "
                    "shared_suffix_entry=%s writer=%s materializer=%s "
                    "materializer_chain=%s stop=%s signature=%s rejection=accepted "
                    "path=%s lineage=%s",
                    blk_label(mba, candidate.source_block),
                    (
                        f".arm{candidate.branch_arm}"
                        if candidate.branch_arm is not None
                        else ""
                    ),
                    blk_label(mba, candidate.family_entry),
                    (
                        blk_label(mba, candidate_report.shared_suffix_entry)
                        if candidate_report.shared_suffix_entry is not None
                        else "None"
                    ),
                    blk_label(mba, candidate.writer_block) if candidate.writer_block is not None else "None",
                    blk_label(mba, candidate.materializer_block) if candidate.materializer_block is not None else "None",
                    [blk_label(mba, serial) for serial in candidate.materializer_chain_blocks],
                    blk_label(mba, candidate.stop_block),
                    candidate.value_family_signature,
                    candidate.path,
                    [hex(ea) for ea in candidate.lineage_eas],
                )
            selected = iteration.selected
            if selected is None:
                continue

            suffix_serials = selected.suffix_serials
            selected_anchors = selected.selected_anchors
            selected_candidates = iteration.selected_candidates
            primary_signature = selected.primary_signature
            logger.info(
                "RECON RETURN: terminal-family split shared_entry=%s stop=%s anchors=%s keep_signature=%s",
                blk_label(mba, int(suffix_serials[0])),
                blk_label(mba, int(suffix_serials[-1])),
                [blk_label(mba, anchor) for anchor in selected_anchors],
                primary_signature,
            )
            for candidate in selected_candidates:
                logger.info(
                    "RECON RETURN: privatized family src=%s%s family_entry=%s "
                    "shared_suffix_entry=%s writer=%s materializer=%s "
                    "materializer_chain=%s stop=%s signature=%s lineage=%s",
                    blk_label(mba, candidate.source_block),
                    (
                        f".arm{candidate.branch_arm}"
                        if candidate.branch_arm is not None
                        else ""
                    ),
                    blk_label(mba, candidate.family_entry),
                    blk_label(mba, int(suffix_serials[0])),
                    blk_label(mba, candidate.writer_block) if candidate.writer_block is not None else "None",
                    blk_label(mba, candidate.materializer_block) if candidate.materializer_block is not None else "None",
                    [blk_label(mba, serial) for serial in candidate.materializer_chain_blocks],
                    blk_label(mba, candidate.stop_block),
                    candidate.value_family_signature,
                    [hex(ea) for ea in candidate.lineage_eas],
                )

        return run.emitted_count

    @classmethod
    def _record_accept(
        cls,
        metadata: list[dict[str, int | str | None]],
        candidate: ReconstructionCandidate,
    ) -> None:
        metadata.append(
            cls._make_edge_metadata(
                candidate.edge,
                horizon_block=candidate.horizon_block,
                site=candidate.site,
                target_entry=candidate.target_entry,
                first_shared_block=candidate.first_shared_block,
                via_pred=candidate.via_pred,
                emission_mode=candidate.emission_mode,
            )
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
        del dispatcher_serial, bst_node_blocks, builder

        ordered_input_candidates = tuple(
            SharedGroupEmissionCandidate(
                via_pred=int(candidate.via_pred),
                target_entry=int(candidate.target_entry),
            )
            for candidate in candidates
            if candidate.via_pred is not None
        )
        if not ordered_input_candidates:
            return 0

        shared_plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=int(shared_block),
            ordered_path=tuple(int(serial) for serial in candidates[0].edge.ordered_path),
            shared_candidates=ordered_input_candidates,
        )
        if not shared_plan.accepted:
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=shared_plan.rejection_reason,
                )
                for candidate in candidates
                if candidate.via_pred is not None
            )
            return 0

        by_pred = {
            int(candidate.via_pred): candidate
            for candidate in candidates
            if candidate.via_pred is not None
        }
        ordered_candidates = [
            by_pred[int(via_pred)] for via_pred in shared_plan.ordered_via_preds
        ]
        modifications.extend(shared_plan.modifications)
        owned_blocks.add(int(shared_block))
        for _, target_entry in shared_plan.per_pred_targets:
            owned_edges.add((int(shared_block), int(target_entry)))
        for candidate in ordered_candidates:
            cls._record_accept(
                accepted_metadata,
                replace(candidate, emission_mode="duplicate_and_redirect"),
            )
        logger.info(
            "RECON DAG: duplicate-and-redirect %s preds=%s",
            blk_label(mba, shared_block),
            [
                (blk_label(mba, pred), blk_label(mba, target))
                for pred, target in shared_plan.per_pred_targets
            ],
        )
        return len(ordered_candidates)

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

        direct_groups: defaultdict[int, list[ReconstructionCandidate]] = defaultdict(list)
        shared_groups: defaultdict[int, list[ReconstructionCandidate]] = defaultdict(list)
        conditional_arm_candidates: list[ReconstructionCandidate] = []
        for candidate in raw_candidates:
            if candidate.emission_mode == "conditional_arm":
                conditional_arm_candidates.append(candidate)
            elif candidate.emission_mode == "direct":
                direct_groups[int(candidate.horizon_block)].append(candidate)
            else:
                assert candidate.first_shared_block is not None
                shared_groups[int(candidate.first_shared_block)].append(candidate)

        for candidate in conditional_arm_candidates:
            source_node = node_by_key.get(candidate.edge.source_key)
            pt_entry: int | None = None
            if source_node is not None and candidate.edge.source_key.state_const is not None:
                pt_entry = source_node.entry_anchor

            cond_plan = plan_conditional_arm_reconstruction_modifications(
                flow_graph=flow_graph,
                horizon_block=int(candidate.horizon_block),
                target_entry=int(candidate.target_entry),
                branch_arm=int(candidate.edge.source_anchor.branch_arm or 0),
                dispatcher_serial=dispatcher_serial,
                current_entry=pt_entry,
            )
            if cond_plan.modifications:
                modifications.extend(cond_plan.modifications)
                owned_blocks.add(int(candidate.horizon_block))
                owned_edges.add((int(candidate.horizon_block), int(candidate.target_entry)))
                self._record_accept(accepted_metadata, candidate)

                pt_plan = plan_passthrough_reconstruction_modifications(
                    flow_graph=flow_graph,
                    ordered_path=tuple(int(serial) for serial in candidate.edge.ordered_path),
                    horizon_block=int(candidate.horizon_block),
                    dispatcher_serial=dispatcher_serial,
                    current_state_entry=pt_entry,
                )
                modifications.extend(pt_plan.modifications)

                logger.info(
                    "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                    blk_label(mba, candidate.horizon_block),
                    candidate.site.state_value & 0xFFFFFFFF,
                    blk_label(mba, candidate.target_entry),
                    candidate.edge.source_anchor.branch_arm or 0,
                    len(cond_plan.modifications),
                    len(pt_plan.modifications),
                )

        for horizon_block in sorted(direct_groups):
            group = direct_groups[horizon_block]
            targets = {candidate.target_entry for candidate in group}
            if len(targets) > 1:
                rejected_metadata.extend(
                    self._make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=candidate.first_shared_block,
                        rejection_reason="direct_conflict",
                    )
                    for candidate in group
                )
                continue
            direct_candidate = group[0]
            direct_plan = plan_direct_reconstruction_modifications(
                flow_graph=flow_graph,
                horizon_block=int(direct_candidate.horizon_block),
                target_entry=int(direct_candidate.target_entry),
                ordered_path=tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
            )
            if not direct_plan.accepted:
                rejected_metadata.append(
                    self._make_edge_metadata(
                        direct_candidate.edge,
                        horizon_block=direct_candidate.horizon_block,
                        site=direct_candidate.site,
                        target_entry=direct_candidate.target_entry,
                        first_shared_block=direct_candidate.first_shared_block,
                        rejection_reason="noop_or_missing_old_target",
                    )
                )
                continue
            modifications.extend(direct_plan.modifications)
            owned_blocks.add(int(direct_candidate.horizon_block))
            owned_edges.add((int(direct_candidate.horizon_block), int(direct_candidate.target_entry)))
            self._record_accept(accepted_metadata, direct_candidate)
            logger.info(
                "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
                blk_label(mba, direct_candidate.horizon_block),
                direct_candidate.site.state_value & 0xFFFFFFFF,
                blk_label(mba, direct_candidate.target_entry),
                1,
            )
            # Resolve passthrough blocks for CONDITIONAL_TRANSITION direct candidates
            if direct_candidate.edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
                source_node = node_by_key.get(direct_candidate.edge.source_key)
                pt_entry_d: int | None = None
                if (
                    source_node is not None
                    and direct_candidate.edge.source_key.state_const is not None
                ):
                    pt_entry_d = source_node.entry_anchor
                pt_plan_d = plan_passthrough_reconstruction_modifications(
                    flow_graph=flow_graph,
                    ordered_path=tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
                    horizon_block=int(direct_candidate.horizon_block),
                    dispatcher_serial=dispatcher_serial,
                    current_state_entry=pt_entry_d,
                )
                modifications.extend(pt_plan_d.modifications)

        for shared_block in sorted(shared_groups):
            group = shared_groups[shared_block]
            ordered_input_candidates = tuple(
                SharedGroupEmissionCandidate(
                    via_pred=int(candidate.via_pred),
                    target_entry=int(candidate.target_entry),
                )
                for candidate in group
                if candidate.via_pred is not None
            )
            shared_plan = plan_shared_group_reconstruction_modifications(
                flow_graph=flow_graph,
                shared_block=int(shared_block),
                ordered_path=tuple(int(serial) for serial in group[0].edge.ordered_path),
                shared_candidates=ordered_input_candidates,
            )
            if not shared_plan.accepted:
                rejected_metadata.extend(
                    self._make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=shared_block,
                        via_pred=candidate.via_pred,
                        rejection_reason=shared_plan.rejection_reason,
                    )
                    for candidate in group
                    if candidate.via_pred is not None
                )
                continue
            by_pred = {
                int(candidate.via_pred): candidate
                for candidate in group
                if candidate.via_pred is not None
            }
            ordered_candidates = [
                by_pred[int(via_pred)] for via_pred in shared_plan.ordered_via_preds
            ]
            modifications.extend(shared_plan.modifications)
            owned_blocks.add(int(shared_block))
            for _, target_entry in shared_plan.per_pred_targets:
                owned_edges.add((int(shared_block), int(target_entry)))
            for candidate in ordered_candidates:
                self._record_accept(
                    accepted_metadata,
                    replace(candidate, emission_mode="duplicate_and_redirect"),
                )
            logger.info(
                "RECON DAG: duplicate-and-redirect %s preds=%s",
                blk_label(mba, shared_block),
                [
                    (blk_label(mba, pred), blk_label(mba, target))
                    for pred, target in shared_plan.per_pred_targets
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

        projected_flow_graph = flow_graph
        # corrected_dag is available for late phases but not yet wired in.
        _ = corrected_dag  # suppress unused warning

        residual_dispatcher_preds: tuple[int, ...] = ()
        allow_post_apply_bst_cleanup = True
        post_apply_bst_cleanup_reason: str | None = None
        if dispatcher_serial >= 0:
            try:
                patch_plan = compile_patch_plan(modifications, flow_graph)
                projected_flow_graph = project_post_state(flow_graph, patch_plan)
            except Exception:
                projected_flow_graph = flow_graph

            entry_island_rescue_count = self._emit_entry_island_rescues(
                corrected_dag,
                base_flow_graph=flow_graph,
                projected_flow_graph=projected_flow_graph,
                builder=builder,
                modifications=modifications,
                dispatcher_region=dispatcher_region,
                mba=mba,
            )
            if entry_island_rescue_count:
                logger.info(
                    "RECON DAG: entry-island rescue emitted %d redirects",
                    entry_island_rescue_count,
                )
                try:
                    patch_plan = compile_patch_plan(modifications, flow_graph)
                    projected_flow_graph = project_post_state(flow_graph, patch_plan)
                except Exception:
                    projected_flow_graph = flow_graph

            residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
                projected_flow_graph,
                dispatcher_serial,
                bst_node_blocks=dispatcher_region,
                reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
            )
            if residual_dispatcher_preds:
                allow_post_apply_bst_cleanup = False
                post_apply_bst_cleanup_reason = "residual_dispatcher_predecessors"
                logger.info(
                    "RECON DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
                    [blk_label(mba, serial) for serial in residual_dispatcher_preds],
                )

            # ------------------------------------------------------------------
            # Pre-header redirect: wire function entry to first handler
            # ------------------------------------------------------------------
            dispatcher = getattr(bst_result, "dispatcher", None)
            _bst_set = set(dag.bst_node_blocks)
            _bst_set.add(dispatcher_serial)

            if (
                dispatcher is not None
                and dag.pre_header_serial is not None
                and dag.initial_state is not None
            ):
                resolved = dispatcher.lookup(dag.initial_state)
                if resolved is not None and int(resolved) not in _bst_set:
                    pre_blk = flow_graph.get_block(dag.pre_header_serial)
                    if pre_blk is not None and pre_blk.nsucc == 1:
                        old = int(pre_blk.succs[0])
                        if old == dispatcher_serial or old in _bst_set:
                            modifications.append(
                                builder.goto_redirect(
                                    source_block=dag.pre_header_serial,
                                    target_block=int(resolved),
                                    old_target=old,
                                )
                            )
                            logger.info(
                                "RECON BRIDGE: pre-header blk[%d] -> blk[%d]",
                                dag.pre_header_serial, int(resolved),
                            )

            # ------------------------------------------------------------------
            # Bridge Builder: force-wire unclaimed DAG edge targets
            # ------------------------------------------------------------------
            # The strict corridor emitter handled the clean edges.
            # Now wire every remaining semantic edge the DAG mapped.

            # Step 1: Gather all target entries and source blocks that were
            # successfully claimed by the strict corridor emitter.
            claimed_targets: set[int] = set()
            claimed_sources: set[int] = set()
            for mod in modifications:
                # Collect targets: RedirectGoto/RedirectBranch/EdgeRedirectViaPredSplit
                if hasattr(mod, "new_target"):
                    claimed_targets.add(int(mod.new_target))
                # ConvertToGoto
                if hasattr(mod, "goto_target"):
                    claimed_targets.add(int(mod.goto_target))
                # CreateConditionalRedirect
                if hasattr(mod, "conditional_target"):
                    claimed_targets.add(int(mod.conditional_target))
                if hasattr(mod, "fallthrough_target"):
                    claimed_targets.add(int(mod.fallthrough_target))
                # DuplicateAndRedirect: per_pred_targets is ((pred, target), ...)
                if hasattr(mod, "per_pred_targets"):
                    for _pred, _tgt in mod.per_pred_targets:
                        claimed_sources.add(int(_pred))
                        claimed_targets.add(int(_tgt))
                # Collect sources to avoid double-wiring the same exit block
                if hasattr(mod, "from_serial"):
                    claimed_sources.add(int(mod.from_serial))
                if hasattr(mod, "source_serial"):
                    claimed_sources.add(int(mod.source_serial))
                if hasattr(mod, "source_block"):
                    claimed_sources.add(int(mod.source_block))
                if hasattr(mod, "src_block"):
                    claimed_sources.add(int(mod.src_block))
                if hasattr(mod, "block_serial"):
                    claimed_sources.add(int(mod.block_serial))
            # Shared-group predecessor-edge peel preserves the shared source on
            # its old target without emitting a direct modification for that
            # source block. Carry strict-emitter ownership forward so bridge and
            # feeder passes treat those sources as already handled.
            claimed_sources.update(int(block_serial) for block_serial in owned_blocks)

            # Step 1b: Build suppressed source->target pairs from structural
            # rejections (e.g. backward_same_corridor_target) to prevent
            # Bridge/Feeder from wiring edges that _build_candidate
            # intentionally refused for safety reasons.
            _structural_rejection_reasons = frozenset({
                "backward_same_corridor_target",
            })
            suppressed_bridge_pairs: set[tuple[int, int]] = set()
            for rej in rejected_metadata:
                if rej.get("rejection_reason") in _structural_rejection_reasons:
                    _rej_src = rej.get("source_block")
                    _rej_tgt = rej.get("target_entry_anchor")
                    if _rej_src is not None and _rej_tgt is not None:
                        suppressed_bridge_pairs.add((int(_rej_src), int(_rej_tgt)))

            # Step 2: Scan DAG edges for unclaimed targets
            bridge_mods: list = []

            for edge in dag.edges:
                if edge.target_entry_anchor is None:
                    continue
                target_entry = int(edge.target_entry_anchor)
                if target_entry in _bst_set:
                    continue  # Target is in dispatcher/BST region
                if target_entry in claimed_targets:
                    continue  # Already wired by strict emitter

                # This target is unclaimed — find the exit block to wire from.
                # Walk ordered_path to find the last non-BST block.
                # Fall back to source_anchor.block_serial for empty paths.
                exit_block: int | None = None
                if edge.ordered_path:
                    for serial in reversed(edge.ordered_path):
                        if serial not in _bst_set:
                            exit_block = serial
                            break
                else:
                    # Empty ordered_path: use source_anchor directly
                    src = int(edge.source_anchor.block_serial)
                    if src not in _bst_set:
                        exit_block = src

                if exit_block is None:
                    continue

                # Skip structurally suppressed edges (e.g. backward corridor)
                if (exit_block, target_entry) in suppressed_bridge_pairs:
                    continue

                # Skip if this exit block is already the source of a modification
                if exit_block in claimed_sources:
                    continue

                block = flow_graph.get_block(exit_block)
                if block is None:
                    continue

                # Check if exit_block already points to the target
                already_wired = any(
                    int(block.succs[i]) == target_entry
                    for i in range(block.nsucc)
                )
                if already_wired:
                    claimed_targets.add(target_entry)
                    continue

                if block.nsucc == 1:
                    # 1-way block: redirect goto to target handler entry
                    old_target = int(block.succs[0])
                    if old_target == dispatcher_serial or old_target in _bst_set:
                        # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                        # if edge.last_write_site is not None:
                        #     _ws_blk, _ws_ea = edge.last_write_site
                        #     bridge_mods.append(
                        #         NopInstructions(
                        #             block_serial=int(_ws_blk),
                        #             insn_eas=(int(_ws_ea),),
                        #         )
                        #     )
                        # else:
                        #     logger.debug(
                        #         "RECON BRIDGE: no last_write_site for "
                        #         "blk[%d] -> blk[%d], skipping NOP",
                        #         exit_block, target_entry,
                        #     )
                        _bridge_tag = (
                            "empty-path direct wire"
                            if not edge.ordered_path
                            else "1-way"
                        )
                        bridge_mods.append(
                            builder.goto_redirect(
                                source_block=exit_block,
                                target_block=target_entry,
                                old_target=old_target,
                            )
                        )
                        claimed_targets.add(target_entry)
                        claimed_sources.add(exit_block)
                        logger.info(
                            "RECON BRIDGE: wire blk[%d] -> blk[%d] (%s)",
                            exit_block, target_entry, _bridge_tag,
                        )
                elif block.nsucc == 2:
                    # 2-way block: find which arm points to BST/dispatcher
                    for arm in range(2):
                        arm_target = int(block.succs[arm])
                        if arm_target == dispatcher_serial or arm_target in _bst_set:
                            if arm == 1:  # RedirectBranch only handles arm=1
                                # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                                # if edge.last_write_site is not None:
                                #     _ws_blk, _ws_ea = edge.last_write_site
                                #     bridge_mods.append(
                                #         NopInstructions(
                                #             block_serial=int(_ws_blk),
                                #             insn_eas=(int(_ws_ea),),
                                #         )
                                #     )
                                # else:
                                #     logger.debug(
                                #         "RECON BRIDGE: no last_write_site for "
                                #         "blk[%d].arm%d -> blk[%d], skipping NOP",
                                #         exit_block, arm, target_entry,
                                #     )
                                _bridge_tag_2 = (
                                    "empty-path direct wire"
                                    if not edge.ordered_path
                                    else "2-way"
                                )
                                bridge_mods.append(
                                    builder.edge_redirect(
                                        source_block=exit_block,
                                        target_block=target_entry,
                                        old_target=arm_target,
                                    )
                                )
                                claimed_targets.add(target_entry)
                                claimed_sources.add(exit_block)
                                logger.info(
                                    "RECON BRIDGE: wire blk[%d].arm%d -> blk[%d] (%s)",
                                    exit_block, arm, target_entry, _bridge_tag_2,
                                )
                            break

            if bridge_mods:
                modifications.extend(bridge_mods)
                logger.info(
                    "RECON BRIDGE: %d bridge edges for unclaimed handler entries",
                    len(bridge_mods),
                )

            # ------------------------------------------------------------------
            # Feeder Redirect: redirect remaining dispatcher feeders
            # ------------------------------------------------------------------
            # After the Bridge Builder wires exit blocks TO unclaimed handler
            # entries, some blocks still feed the dispatcher via goto.  Scan
            # ALL DAG edges whose source anchor still points at the dispatcher
            # or BST region and redirect them to the resolved target entry.

            feeder_mods: list = []

            for edge in dag.edges:
                if edge.target_entry_anchor is None:
                    continue
                # UNKNOWN edges with valid target_entry_anchor are DFS-proven
                # transitions whose snapshot state writes were unresolvable.
                # They are safe to wire via the feeder redirect.
                if edge.kind not in (
                    SemanticEdgeKind.TRANSITION,
                    SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    SemanticEdgeKind.UNKNOWN,
                ):
                    continue
                target_entry = int(edge.target_entry_anchor)
                if target_entry in _bst_set:
                    continue

                src_serial = int(edge.source_anchor.block_serial)
                if src_serial in claimed_sources:
                    continue  # Already handled by strict emitter or bridge

                # Skip structurally suppressed edges (e.g. backward corridor)
                if (src_serial, target_entry) in suppressed_bridge_pairs:
                    continue

                src_block = flow_graph.get_block(src_serial)
                if src_block is None:
                    continue

                # Check if any successor is the dispatcher or a BST block
                has_dispatcher_succ = False
                for arm in range(src_block.nsucc):
                    if (
                        int(src_block.succs[arm]) == dispatcher_serial
                        or int(src_block.succs[arm]) in _bst_set
                    ):
                        has_dispatcher_succ = True
                        break

                if not has_dispatcher_succ:
                    continue

                if src_block.nsucc == 1:
                    old_target = int(src_block.succs[0])
                    if old_target == dispatcher_serial or old_target in _bst_set:
                        # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                        # if edge.last_write_site is not None:
                        #     _ws_blk, _ws_ea = edge.last_write_site
                        #     feeder_mods.append(
                        #         NopInstructions(
                        #             block_serial=int(_ws_blk),
                        #             insn_eas=(int(_ws_ea),),
                        #         )
                        #     )
                        # else:
                        #     logger.debug(
                        #         "RECON FEEDER: no last_write_site for "
                        #         "blk[%d] -> blk[%d], skipping NOP",
                        #         src_serial, target_entry,
                        #     )
                        _feeder_tag = (
                            "UNKNOWN 1-way"
                            if edge.kind == SemanticEdgeKind.UNKNOWN
                            else "1-way"
                        )
                        proj_src = projected_flow_graph.get_block(src_serial)
                        src_npred = len(proj_src.preds) if proj_src is not None else 0
                        pred_succs: tuple[int, ...] = ()
                        feeder_context = SharedFeederContext(
                            source_serial=src_serial,
                            source_pred_count=src_npred,
                            ordered_path=tuple(
                                int(node) for node in (edge.ordered_path or ())
                            ),
                            via_pred_succs=(),
                            target_entry=target_entry,
                            dispatcher_serial=dispatcher_serial,
                            bst_node_blocks=frozenset(_bst_set),
                            target_reaches_pred=False,
                        )
                        edge_pred = feeder_context.via_pred
                        if edge_pred is not None:
                            pred_block = projected_flow_graph.get_block(edge_pred)
                            if pred_block is not None:
                                pred_succs = tuple(
                                    int(succ) for succ in getattr(pred_block, "succs", ())
                                )
                        target_reaches_pred = (
                            target_reaches_source_ignoring_blocks(
                                projected_flow_graph,
                                target_entry=target_entry,
                                source_block=edge_pred,
                                ignored_blocks=_bst_set | {dispatcher_serial, src_serial},
                            )
                            if edge_pred is not None
                            else False
                        )
                        lowering = select_shared_feeder_lowering(
                            SharedFeederContext(
                                source_serial=feeder_context.source_serial,
                                source_pred_count=feeder_context.source_pred_count,
                                ordered_path=feeder_context.ordered_path,
                                via_pred_succs=pred_succs,
                                target_entry=feeder_context.target_entry,
                                dispatcher_serial=feeder_context.dispatcher_serial,
                                bst_node_blocks=feeder_context.bst_node_blocks,
                                target_reaches_pred=target_reaches_pred,
                            )
                        )
                        if not lowering.accepted:
                            logger.info(
                                "RECON BRIDGE: feeder blk[%d] -> blk[%d] rejected (%s)",
                                src_serial,
                                target_entry,
                                lowering.reason,
                            )
                            continue
                        if lowering.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE:
                            feeder_mods.append(
                                builder.duplicate_and_redirect(
                                    source_block=src_serial,
                                    per_pred_targets=[
                                        (lowering.via_pred, target_entry),
                                    ],
                                )
                            )
                            _feeder_tag += " pred-scoped"
                            claimed_sources.add(src_serial)
                        elif (
                            lowering.kind == SharedFeederLoweringKind.PRED_EDGE_PEEL
                            and lowering.via_pred is not None
                        ):
                            feeder_mods.append(
                                builder.edge_redirect(
                                    source_block=lowering.via_pred,
                                    target_block=target_entry,
                                    old_target=src_serial,
                                )
                            )
                            _feeder_tag += " pred-edge"
                            claimed_sources.add(lowering.via_pred)
                        else:
                            feeder_mods.append(
                                builder.goto_redirect(
                                    source_block=src_serial,
                                    target_block=target_entry,
                                    old_target=old_target,
                                )
                            )
                            claimed_sources.add(src_serial)
                        claimed_targets.add(target_entry)
                        logger.info(
                            "RECON BRIDGE: feeder blk[%d] -> blk[%d] (%s npred=%d via_pred=%s)",
                            src_serial,
                            target_entry,
                            _feeder_tag,
                            src_npred,
                            lowering.via_pred,
                        )
                elif src_block.nsucc == 2:
                    for arm in range(2):
                        arm_target = int(src_block.succs[arm])
                        if arm_target == dispatcher_serial or arm_target in _bst_set:
                            if arm == 1:  # RedirectBranch only handles arm=1
                                # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                                # if edge.last_write_site is not None:
                                #     _ws_blk, _ws_ea = edge.last_write_site
                                #     feeder_mods.append(
                                #         NopInstructions(
                                #             block_serial=int(_ws_blk),
                                #             insn_eas=(int(_ws_ea),),
                                #         )
                                #     )
                                # else:
                                #     logger.debug(
                                #         "RECON FEEDER: no last_write_site for "
                                #         "blk[%d].arm%d -> blk[%d], skipping NOP",
                                #         src_serial, arm, target_entry,
                                #     )
                                _feeder_tag_2 = (
                                    "UNKNOWN 2-way"
                                    if edge.kind == SemanticEdgeKind.UNKNOWN
                                    else "2-way"
                                )
                                feeder_mods.append(
                                    builder.edge_redirect(
                                        source_block=src_serial,
                                        target_block=target_entry,
                                        old_target=arm_target,
                                    )
                                )
                                claimed_sources.add(src_serial)
                                claimed_targets.add(target_entry)
                                logger.info(
                                    "RECON BRIDGE: feeder blk[%d].arm%d -> blk[%d] (%s)",
                                    src_serial, arm, target_entry, _feeder_tag_2,
                                )
                            break

            # Fallback: resolve feeder target via snapshot constant fixpoint
            # For blocks writing a known state constant to stkoff whose DAG
            # edge source_anchor did not match above.
            if (
                constant_result is not None
                and state_var_stkoff is not None
                and hasattr(constant_result, "out_stk_maps")
                and dispatcher is not None
            ):
                # Collect residual feeder candidates: all blocks that still
                # point to the dispatcher/BST but weren't claimed.
                for blk_serial in flow_graph.blocks:
                    if blk_serial in claimed_sources:
                        continue
                    blk = flow_graph.get_block(blk_serial)
                    if blk is None or blk.nsucc != 1:
                        continue
                    old = int(blk.succs[0])
                    if old != dispatcher_serial and old not in _bst_set:
                        continue
                    out_map = constant_result.out_stk_maps.get(blk_serial, {})
                    state_val = out_map.get(state_var_stkoff)
                    if state_val is None:
                        continue
                    resolved = dispatcher.lookup(state_val)
                    if resolved is None or int(resolved) in _bst_set:
                        continue
                    # Fixpoint feeder has no DAG edge, so no last_write_site.
                    # State-write NOP would require block instruction scan
                    # (IDA runtime only) — skip for now.
                    logger.debug(
                        "RECON FEEDER: fixpoint blk[%d] has no "
                        "last_write_site, skipping NOP",
                        blk_serial,
                    )
                    feeder_mods.append(
                        builder.goto_redirect(
                            source_block=blk_serial,
                            target_block=int(resolved),
                            old_target=old,
                        )
                    )
                    claimed_sources.add(blk_serial)
                    logger.info(
                        "RECON BRIDGE: fixpoint feeder blk[%d] -> blk[%d] (state=0x%x)",
                        blk_serial, int(resolved), state_val,
                    )

            if feeder_mods:
                modifications.extend(feeder_mods)
                logger.info(
                    "RECON BRIDGE: %d feeder redirects for residual dispatcher feeders",
                    len(feeder_mods),
                )

            # ------------------------------------------------------------------
            # Artifact return block classification: identify m_xdu / m_mov
            # blocks that copy the dead state variable into the return slot.
            # ------------------------------------------------------------------
            artifact_return_blocks: set[int] = set()
            if state_var_stkoff is not None:
                _state_consts = sm.state_constants if sm is not None else set()
                logger.info(
                    "RECON RETURN: classifying artifacts: "
                    "state_var_stkoff=%s, flow_graph blocks=%d, "
                    "state_constants count=%d",
                    state_var_stkoff, len(flow_graph.blocks),
                    len(_state_consts),
                )
                artifact_return_blocks = classify_artifact_return_blocks(
                    flow_graph,
                    state_var_stkoff=state_var_stkoff,
                    state_constants=_state_consts,
                )
                if artifact_return_blocks:
                    logger.info(
                        "RECON RETURN: artifact return blocks: %s",
                        sorted(artifact_return_blocks),
                    )
                else:
                    logger.info(
                        "RECON RETURN: NO artifact blocks found "
                        "(classifier returned empty set)",
                    )

            # ------------------------------------------------------------------
            # Return Path Wiring: path-local return lowering for
            # CONDITIONAL_RETURN edges using DAG shared-suffix info
            # ------------------------------------------------------------------
            # Instead of a generic hop-walk that follows flow_graph
            # successors (which may traverse m_xdu artifact blocks), use
            # the DAG's ordered_path and shared_suffix_blocks to identify
            # the correct return anchor and shared suffix entry.
            #
            # For each CONDITIONAL_RETURN edge:
            #   1. Look up the source node's shared_suffix_blocks
            #   2. Find the first shared suffix block in the ordered_path
            #   3. The "return anchor" is the block just before the suffix
            #   4. Wire the anchor's arm to the shared suffix entry

            return_mods: list = []
            return_skipped: list[tuple[int, str]] = []

            # Precompute the common return corridor: blocks that appear
            # in ALL CONDITIONAL_RETURN edge paths.  This identifies
            # blk[217]/blk[218] as the universal return corridor.
            _ret_paths: list[set[int]] = []
            for _e in dag.edges:
                if _e.kind == SemanticEdgeKind.CONDITIONAL_RETURN and _e.ordered_path:
                    _ret_paths.append({int(s) for s in _e.ordered_path})
            common_return_corridor: set[int] = set()
            if _ret_paths:
                common_return_corridor = _ret_paths[0]
                for _p in _ret_paths[1:]:
                    common_return_corridor &= _p
            # Extend the corridor backward: walk 1-way predecessors of
            # the earliest common corridor block to find the full return
            # corridor chain (e.g., blk[217] → blk[218] → blk[219]).
            # The paths may omit early corridor blocks due to pass-1
            # block serial drift.
            if common_return_corridor:
                earliest = min(common_return_corridor)
                _walk_serial = earliest
                for _ in range(5):  # max 5 backward hops
                    _walk_blk = flow_graph.get_block(_walk_serial)
                    if _walk_blk is None:
                        break
                    # Find 1-way predecessors of this block
                    preds = list(flow_graph.predecessors(_walk_serial))
                    logger.info(
                        "RECON RETURN: corridor backward walk blk[%d] "
                        "preds=%s shared_suffix_blocks=%s",
                        _walk_serial, preds, sorted(shared_suffix_blocks),
                    )
                    extended = False
                    # Pick the highest-serial 1-way predecessor that
                    # is not BST, not dispatcher, not already in corridor.
                    # The return corridor entry (blk[217]) typically has
                    # the highest serial among 1-way predecessors.
                    best_pred: int | None = None
                    for pred_serial in sorted(preds, reverse=True):
                        pred_blk = flow_graph.get_block(pred_serial)
                        if (
                            pred_blk is not None
                            and pred_blk.nsucc == 1
                            and pred_serial not in _bst_set
                            and pred_serial != dispatcher_serial
                            and pred_serial not in common_return_corridor
                        ):
                            best_pred = pred_serial
                            break
                    if best_pred is not None:
                        common_return_corridor.add(best_pred)
                        _walk_serial = best_pred
                        extended = True
                    if not extended:
                        break
            if common_return_corridor:
                logger.info(
                    "RECON RETURN: common return corridor blocks: %s",
                    sorted(common_return_corridor),
                )

            for edge in dag.edges:
                if edge.kind != SemanticEdgeKind.CONDITIONAL_RETURN:
                    continue

                src_serial = int(edge.source_anchor.block_serial)
                src_arm = edge.source_anchor.branch_arm

                if not edge.ordered_path:
                    return_skipped.append((src_serial, "empty_ordered_path"))
                    continue

                ordered = tuple(int(s) for s in edge.ordered_path)

                if len(ordered) < 2:
                    return_skipped.append((src_serial, "path_too_short"))
                    continue

                # Look up the source node to get shared_suffix_blocks
                source_node = node_by_key.get(edge.source_key)
                node_shared_suffix: set[int] = set()
                if source_node is not None:
                    node_shared_suffix = {
                        int(b) for b in source_node.shared_suffix_blocks
                    }

                # Determine the shared suffix entry block.
                # Use ONLY the node-local shared_suffix_blocks that are
                # on the return corridor (predecessors of the last block
                # in the ordered_path).  The suffix entry is the block
                # in the suffix set that is a predecessor of the terminal,
                # NOT the dispatcher or unrelated shared blocks.
                suffix_entry_serial: int | None = None
                anchor_serial: int | None = None
                if len(ordered) >= 2:
                    terminal = ordered[-1]
                    # Use the common return corridor directly (not per-node
                    # suffix).  The corridor entry is the lowest-serial
                    # block in the corridor that is not the terminal.
                    corridor_candidates = sorted(
                        b for b in common_return_corridor
                        if b != terminal
                    )
                    if not corridor_candidates:
                        # Fall back to node-local suffix
                        corridor_candidates = sorted(
                            b for b in node_shared_suffix
                            if b != terminal
                            and b not in _bst_set
                            and b != dispatcher_serial
                        )
                    if corridor_candidates:
                        suffix_entry_serial = corridor_candidates[0]

                    # The anchor is the source block itself (it's the
                    # block whose arm we need to rewire to the corridor).
                    # For edges like src=blk[206], the anchor IS blk[206]
                    # — its fallthrough should reach the suffix entry.
                    anchor_serial = src_serial

                if suffix_entry_serial is None:
                    # No shared suffix info — fall back to simple last-hop
                    # redirect.
                    # Use the last non-BST block pair in the ordered_path.
                    fallback_emitted = False
                    for hop_idx in range(len(ordered) - 1):
                        from_serial = ordered[hop_idx]
                        expected_next = ordered[hop_idx + 1]
                        if from_serial in _bst_set or from_serial in claimed_sources:
                            continue
                        from_block = flow_graph.get_block(from_serial)
                        if from_block is None:
                            continue
                        if from_block.nsucc == 1:
                            old_target = int(from_block.succs[0])
                            if old_target == expected_next:
                                continue
                            return_mods.append(
                                builder.goto_redirect(
                                    source_block=from_serial,
                                    target_block=expected_next,
                                    old_target=old_target,
                                )
                            )
                            claimed_sources.add(from_serial)
                            logger.info(
                                "RECON RETURN: fallback wire blk[%d] -> blk[%d] (1-way)",
                                from_serial, expected_next,
                            )
                            fallback_emitted = True
                            break
                        elif from_block.nsucc == 2:
                            check_arms = (
                                [src_arm]
                                if from_serial == src_serial and src_arm is not None
                                else [0, 1]
                            )
                            for arm in check_arms:
                                if arm >= from_block.nsucc:
                                    continue
                                arm_target = int(from_block.succs[arm])
                                if arm_target == expected_next:
                                    fallback_emitted = True
                                    break
                                return_mods.append(
                                    builder.edge_redirect(
                                        source_block=from_serial,
                                        target_block=expected_next,
                                        old_target=arm_target,
                                    )
                                )
                                claimed_sources.add(from_serial)
                                logger.info(
                                    "RECON RETURN: fallback wire blk[%d].arm%d -> blk[%d] (2-way)",
                                    from_serial, arm, expected_next,
                                )
                                fallback_emitted = True
                                break
                            if fallback_emitted:
                                break
                    if not fallback_emitted:
                        return_skipped.append(
                            (src_serial, "no_suffix_fallback_exhausted"),
                        )
                    continue

                # Shared suffix entry determined from node's shared_suffix_blocks.
                # anchor_serial determined as last non-suffix block in path.

                logger.info(
                    "RECON RETURN: path-local edge src=blk[%d] path=%s "
                    "suffix_entry=blk[%d] anchor=blk[%d]",
                    src_serial, ordered, suffix_entry_serial, anchor_serial,
                )

                # Skip BST anchors and already-claimed anchors
                if anchor_serial in _bst_set:
                    return_skipped.append(
                        (anchor_serial, "anchor_in_bst"),
                    )
                    continue
                if anchor_serial in claimed_sources:
                    return_skipped.append(
                        (anchor_serial, "anchor_claimed"),
                    )
                    continue

                anchor_block = flow_graph.get_block(anchor_serial)
                if anchor_block is None:
                    return_skipped.append(
                        (anchor_serial, "anchor_block_not_found"),
                    )
                    continue

                # Check if the anchor already points to the suffix entry
                if anchor_block.nsucc == 1:
                    old_target = int(anchor_block.succs[0])
                    if old_target == suffix_entry_serial:
                        # Already correct — nothing to do
                        logger.info(
                            "RECON RETURN: blk[%d] already points to "
                            "suffix entry blk[%d]",
                            anchor_serial, suffix_entry_serial,
                        )
                        continue
                    # Wire anchor to suffix entry, bypassing artifact
                    return_mods.append(
                        builder.goto_redirect(
                            source_block=anchor_serial,
                            target_block=suffix_entry_serial,
                            old_target=old_target,
                        )
                    )
                    claimed_sources.add(anchor_serial)
                    logger.info(
                        "RECON RETURN: wire blk[%d] -> blk[%d] "
                        "(bypass artifact blk[%d], 1-way)",
                        anchor_serial, suffix_entry_serial, old_target,
                    )

                elif anchor_block.nsucc == 2:
                    # For 2-way anchor, use the specific arm from
                    # source_anchor when anchor is the source block,
                    # otherwise check both arms.
                    if anchor_serial == src_serial and src_arm is not None:
                        check_arms = [src_arm]
                    else:
                        check_arms = [0, 1]

                    wired = False
                    for arm in check_arms:
                        if arm >= anchor_block.nsucc:
                            continue
                        arm_target = int(anchor_block.succs[arm])
                        if arm_target == suffix_entry_serial:
                            # Arm already correct
                            wired = True
                            break
                        if arm == 0:
                            # Fallthrough arm: classify as artifact or
                            # real return-value setter using the pre-
                            # computed artifact_return_blocks set.
                            artifact_blk = flow_graph.get_block(arm_target)
                            if (
                                artifact_blk is not None
                                and artifact_blk.nsucc == 1
                                and arm_target in artifact_return_blocks
                                and arm_target not in claimed_sources
                            ):
                                artifact_old = int(artifact_blk.succs[0])
                                return_mods.append(
                                    builder.goto_redirect(
                                        source_block=arm_target,
                                        target_block=suffix_entry_serial,
                                        old_target=artifact_old,
                                    )
                                )
                                claimed_sources.add(arm_target)
                                logger.info(
                                    "RECON RETURN: redirect artifact blk[%d] -> blk[%d]",
                                    arm_target, suffix_entry_serial,
                                )
                                wired = True
                                break
                            else:
                                # Real return-value setter — leave alone
                                logger.info(
                                    "RECON RETURN: skip arm0 blk[%d] (real return writer)",
                                    arm_target,
                                )
                                wired = True
                                break
                        else:
                            # Taken arm — use edge_redirect normally
                            return_mods.append(
                                builder.edge_redirect(
                                    source_block=anchor_serial,
                                    target_block=suffix_entry_serial,
                                    old_target=arm_target,
                                )
                            )
                        claimed_sources.add(anchor_serial)
                        logger.info(
                            "RECON RETURN: wire blk[%d].arm%d -> blk[%d] "
                            "(bypass artifact blk[%d], 2-way)",
                            anchor_serial, arm, suffix_entry_serial,
                            arm_target,
                        )
                        wired = True
                        break
                    if not wired:
                        return_skipped.append(
                            (anchor_serial, "no_eligible_arm"),
                        )
                else:
                    return_skipped.append(
                        (anchor_serial,
                         f"unexpected_nsucc_{anchor_block.nsucc}"),
                    )

            if return_mods:
                modifications.extend(return_mods)
            logger.info(
                "RECON RETURN: %d return path edges wired, %d skipped",
                len(return_mods), len(return_skipped),
            )
            for blk_ser, reason in return_skipped:
                logger.info(
                    "RECON RETURN: skip blk[%d] reason=%s",
                    blk_ser, reason,
                )

            # DISABLED: Force-Wire unnecessary when relay collapsing is off.
            # With immediate-target wiring, handlers that were previously
            # orphaned by relay collapsing now have their natural predecessors
            # preserved.  Force-Wire was solving the symptom (orphaned handlers)
            # rather than the root cause (relay collapsing skipping intermediates).
            force_wire_mods: list = []

            # ------------------------------------------------------------------
            # Re-project to update residual preds and BST cleanup gate
            # ------------------------------------------------------------------
            all_extra_mods = bridge_mods + return_mods + feeder_mods + force_wire_mods
            projected_flow_graph = flow_graph
            if all_extra_mods:
                try:
                    patch_plan = compile_patch_plan(modifications, flow_graph)
                    projected_flow_graph = project_post_state(
                        flow_graph, patch_plan,
                    )
                except Exception:
                    projected_flow_graph = flow_graph

                late_entry_island_rescue_count = self._emit_entry_island_rescues(
                    dag,
                    base_flow_graph=flow_graph,
                    projected_flow_graph=projected_flow_graph,
                    builder=builder,
                    modifications=modifications,
                    dispatcher_region=dispatcher_region,
                    mba=mba,
                )
                if late_entry_island_rescue_count:
                    logger.info(
                        "RECON DAG: post-bridge entry-island rescue emitted %d redirects",
                        late_entry_island_rescue_count,
                    )
                    try:
                        patch_plan = compile_patch_plan(modifications, flow_graph)
                        projected_flow_graph = project_post_state(
                            flow_graph, patch_plan,
                        )
                    except Exception:
                        projected_flow_graph = flow_graph

                residual_dispatcher_preds = (
                    collect_residual_dispatcher_predecessors(
                        projected_flow_graph,
                        dispatcher_serial,
                        bst_node_blocks=dispatcher_region,
                        reachable_from_serial=getattr(
                            projected_flow_graph, "entry_serial", None,
                        ),
                    )
                )
                if not residual_dispatcher_preds:
                    allow_post_apply_bst_cleanup = True
                    post_apply_bst_cleanup_reason = None
                    logger.info(
                        "RECON BRIDGE: cleared all residual dispatcher feeders — BST cleanup enabled",
                    )
                else:
                    logger.info(
                        "RECON BRIDGE: residual still has %d feeders: %s",
                        len(residual_dispatcher_preds),
                        [blk_label(mba, s) for s in residual_dispatcher_preds],
                    )

                # Late island rescue: reconnect handler bodies that are
                # unreachable because they sit behind dead BST nodes.
                late_island_rescue_count = self._emit_late_island_rescues(
                    dag,
                    base_flow_graph=flow_graph,
                    projected_flow_graph=projected_flow_graph,
                    builder=builder,
                    modifications=modifications,
                    dispatcher_region=dispatcher_region,
                    dispatcher=getattr(bst_result, "dispatcher", None),
                    mba=mba,
                )
                if late_island_rescue_count:
                    logger.info(
                        "RECON DAG: late island rescue emitted %d redirects",
                        late_island_rescue_count,
                    )
                    try:
                        patch_plan = compile_patch_plan(modifications, flow_graph)
                        projected_flow_graph = project_post_state(
                            flow_graph, patch_plan,
                        )
                    except Exception:
                        projected_flow_graph = flow_graph

            terminal_family_split_count = self._emit_terminal_family_splits(
                dag,
                base_flow_graph=flow_graph,
                projected_flow_graph=projected_flow_graph,
                builder=builder,
                modifications=modifications,
                dispatcher_region=dispatcher_region,
                state_var_stkoff=state_var_stkoff,
                mba=mba,
            )
            if terminal_family_split_count:
                logger.info(
                    "RECON RETURN: late terminal-family split emitted %d privatizations",
                    terminal_family_split_count,
                )
                try:
                    patch_plan = compile_patch_plan(modifications, flow_graph)
                    projected_flow_graph = project_post_state(
                        flow_graph, patch_plan,
                    )
                except Exception:
                    projected_flow_graph = flow_graph

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
