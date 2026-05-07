from __future__ import annotations

from dataclasses import dataclass

from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label


@dataclass(frozen=True, slots=True)
class SnapshotReconstructionResult:
    """Result of :func:`snapshot_reconstruction_dag`.

    ``persisted`` is ``True`` only when the snapshot landed in the
    diagnostic DB without raising.  Consumers (e.g. the selected-
    alternate edge override helper) need both ``diag_db`` and
    ``snap_id`` to read the just-written ``dag_edges`` rows; on any
    failure both are ``None`` so callers can no-op cleanly.
    """

    diag_db: object | None
    snap_id: int | None
    persisted: bool


def snapshot_reconstruction_dag(
    logger,
    *,
    dag,
    mba,
    strategy_name: str,
) -> SnapshotReconstructionResult:
    try:
        from d810.core.diag import get_diag_db
        diag_db = get_diag_db(mba.entry_ea if mba is not None else 0)
        if diag_db is not None:
            from d810.core.diag.snapshot import (
                DagEdge,
                DagNode,
                dag_node_diagnostic_state,
                snapshot_dag,
                snapshot_dag_local_facts,
                snapshot_mba,
            )
            import json as _json

            snap_id = snapshot_mba(
                diag_db,
                [],
                label=f"{strategy_name}_state_write_reconstruction_dag",
                func_ea=mba.entry_ea if mba is not None else 0,
                maturity="MMAT_GLBOPT1",
                phase="post_apply",
            )

            dag_nodes = []
            for node in dag.nodes:
                diagnostic_state = dag_node_diagnostic_state(node)
                dag_nodes.append(DagNode(
                    state=diagnostic_state,
                    state_hex=f"0x{diagnostic_state & 0xFFFFFFFFFFFFFFFF:016x}",
                    entry_block=int(node.entry_anchor),
                    classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                    shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                ))

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
            snapshot_dag_local_facts(diag_db, snap_id, dag)
            return SnapshotReconstructionResult(
                diag_db=diag_db,
                snap_id=int(snap_id),
                persisted=True,
            )
    except Exception:
        logger.warning(
            "Early diagnostic DAG snapshot failed (non-critical)",
            exc_info=True,
        )
    return SnapshotReconstructionResult(
        diag_db=None,
        snap_id=None,
        persisted=False,
    )


def snapshot_reconstruction_post_apply(
    logger,
    *,
    dag,
    modifications: list,
    mba,
    strategy_name: str,
) -> None:
    try:
        from d810.core.diag import get_diag_db
        diag_db = get_diag_db(mba.entry_ea if mba is not None else 0)
        if diag_db is not None:
            from d810.core.diag.snapshot import (
                DagEdge,
                DagNode,
                Modification,
                dag_node_diagnostic_state,
                snapshot_dag,
                snapshot_dag_local_facts,
                snapshot_mba,
                snapshot_modifications,
            )
            import json as _json

            snap_id = snapshot_mba(
                diag_db,
                [],
                label=f"{strategy_name}_state_write_reconstruction_post_apply",
                func_ea=mba.entry_ea if mba is not None else 0,
                maturity="MMAT_GLBOPT1",
                phase="post_apply",
            )

            dag_nodes = []
            for node in dag.nodes:
                diagnostic_state = dag_node_diagnostic_state(node)
                dag_nodes.append(DagNode(
                    state=diagnostic_state,
                    state_hex=f"0x{diagnostic_state & 0xFFFFFFFFFFFFFFFF:016x}",
                    entry_block=int(node.entry_anchor),
                    classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                    shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                ))

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
            snapshot_dag_local_facts(diag_db, snap_id, dag)

            mod_snapshots = []
            for midx, mod in enumerate(modifications):
                mod_type = type(mod).__name__
                # Mod-type-specific extraction: each GraphModification dataclass
                # carries different field names for "where the edge starts /
                # ends / used to end."  The previous getattr chain only matched
                # RedirectGoto/RedirectBranch/EdgeRedirectViaPredSplit, leaving
                # InsertBlock/DuplicateAndRedirect/CreateConditionalRedirect/
                # DuplicateBlock with all three columns NULL — making the
                # modifications table useless for tracing corridor topology
                # mutations driven by HCC's bulk-splice operations.
                source_block: int | None = None
                target_block: int | None = None
                old_target: int | None = None
                # 1) source-of-edit candidates by field name
                for src_attr in (
                    "from_serial",
                    "src_block",          # EdgeRedirectViaPredSplit
                    "source_block",       # RedirectGoto, RedirectBranch,
                                          # ConvertToGoto, RemoveEdge,
                                          # CreateConditionalRedirect,
                                          # DuplicateBlock
                    "source_serial",      # DuplicateAndRedirect, ReorderBlocks
                    "pred_serial",        # InsertBlock
                    "block_serial",       # NopInstructions, ZeroStateWrite,
                                          # PromoteOperandToScalar
                    "anchor_serial",      # PrivateTerminalSuffix
                ):
                    val = getattr(mod, src_attr, None)
                    if val is not None:
                        source_block = int(val)
                        break
                # 2) target-of-edit candidates by field name
                for tgt_attr in (
                    "new_target",         # RedirectGoto, RedirectBranch,
                                          # EdgeRedirectViaPredSplit
                    "goto_target",        # ConvertToGoto
                    "conditional_target", # CreateConditionalRedirect,
                                          # DuplicateAndRedirect (per-pred)
                    "succ_serial",        # InsertBlock
                    "target_block",       # DuplicateBlock
                    "to_serial",          # RemoveEdge
                    "shared_entry_serial",  # PrivateTerminalSuffix
                ):
                    val = getattr(mod, tgt_attr, None)
                    if val is not None:
                        target_block = int(val)
                        break
                # 3) old-target candidates: explicit field, then fall through
                #    to InsertBlock's old_target_serial alias.
                for old_attr in (
                    "old_target",         # EdgeRedirectViaPredSplit,
                                          # RedirectBranch
                    "old_target_serial",  # InsertBlock
                ):
                    val = getattr(mod, old_attr, None)
                    if val is not None:
                        old_target = int(val)
                        break
                mod_snapshots.append(Modification(
                    mod_index=midx,
                    mod_type=mod_type,
                    source_block=source_block,
                    target_block=target_block,
                    old_target=old_target,
                    status="emitted",
                ))

            snapshot_modifications(diag_db, snap_id, mod_snapshots)
    except Exception:
        logger.warning(
            "Diagnostic DAG/modifications snapshot failed (non-critical)",
            exc_info=True,
        )


def log_terminal_family_split_run(logger, *, run, mba) -> int:
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

    return int(run.emitted_count)


def log_entry_island_rescue_run(logger, *, run, mba, prefix: str) -> int:
    for iteration in run.iterations:
        selection = iteration.selection
        if (
            not selection.accepted
            or selection.option is None
            or selection.score is None
        ):
            continue
        logger.info(
            "RECON DAG: %s %s -> %s%s (delta=%+d)",
            prefix,
            blk_label(mba, selection.option.source_block),
            blk_label(mba, selection.option.lifted_entry),
            (
                f" via_pred={blk_label(mba, selection.option.via_pred)}"
                if selection.option.via_pred is not None
                else ""
            ),
            selection.score[0] if selection.score is not None else 0,
        )

    return int(run.emitted_count)


def log_late_island_rescue_run(logger, *, run, diagnostics, mba) -> int:
    for iteration in run.iterations:
        for seed in iteration.raw_seeds:
            if getattr(seed, "source_block", None) is None:
                logger.info(
                    "RECON DAG: late island rescue: no reachable "
                    "frontier for BST passthrough blk[%d] -> "
                    "blk[%d] (edge src=%s)",
                    seed.passthrough_block,
                    seed.lifted_entry,
                    blk_label(mba, seed.edge_source_block),
                )
        selection = iteration.selection
        if (
            not selection.accepted
            or selection.option is None
            or selection.score is None
        ):
            continue
        logger.info(
            "RECON DAG: late island rescue %s -> %s%s "
            "via BST passthrough (delta=%+d)",
            blk_label(mba, selection.option.source_block),
            blk_label(mba, selection.option.lifted_entry),
            (
                f" via_pred={blk_label(mba, selection.option.via_pred)}"
                if selection.option.via_pred is not None
                else ""
            ),
            selection.score[0] if selection.score is not None else 0,
        )

    for diagnostic in diagnostics:
        logger.info(
            "RECON DAG: late island rescue diagnostic: "
            "unreachable blk[%d] bst_preds=%s dispatcher_rows=[%s]",
            diagnostic.block_serial,
            list(diagnostic.bst_preds),
            (
                ", ".join(diagnostic.dispatcher_rows)
                if diagnostic.dispatcher_rows
                else "none"
            ),
        )

    return int(run.emitted_count)


def log_reconstruction_artifact_returns(
    logger,
    *,
    state_var_stkoff: int,
    flow_graph_block_count: int,
    state_constants_count: int,
    artifact_return_blocks: set[int],
) -> None:
    logger.info(
        "RECON RETURN: classifying artifacts: "
        "state_var_stkoff=%s, flow_graph blocks=%d, "
        "state_constants count=%d",
        state_var_stkoff,
        flow_graph_block_count,
        state_constants_count,
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


def log_reconstruction_common_return_corridor(logger, *, common_return_corridor: set[int]) -> None:
    if common_return_corridor:
        logger.info(
            "RECON RETURN: common return corridor blocks: %s",
            sorted(common_return_corridor),
        )


def log_reconstruction_preheader_bridge(logger, *, dag, preheader_bridge) -> None:
    if preheader_bridge.modification is not None and preheader_bridge.resolved_target is not None:
        logger.info(
            "RECON BRIDGE: pre-header blk[%d] -> blk[%d]",
            dag.pre_header_serial,
            preheader_bridge.resolved_target,
        )


def log_reconstruction_bridge_plan(logger, *, bridge_plan) -> int:
    for entry in bridge_plan.log_entries:
        if entry.branch_arm is None:
            logger.info(
                "RECON BRIDGE: wire blk[%d] -> blk[%d] (%s)",
                entry.source_block,
                entry.target_block,
                entry.tag,
            )
        else:
            logger.info(
                "RECON BRIDGE: wire blk[%d].arm%d -> blk[%d] (%s)",
                entry.source_block,
                entry.branch_arm,
                entry.target_block,
                entry.tag,
            )

    emitted = len(bridge_plan.modifications)
    if emitted:
        logger.info(
            "RECON BRIDGE: %d bridge edges for unclaimed handler entries",
            emitted,
        )
    return emitted


def log_reconstruction_feeder_plan(logger, *, feeder_plan, fixpoint_feeder_plan) -> int:
    for entry in feeder_plan.log_entries:
        if entry.branch_arm is None:
            logger.info(
                "RECON BRIDGE: feeder blk[%d] -> blk[%d] (%s npred=%d via_pred=%s)",
                entry.source_block,
                entry.target_block,
                entry.tag,
                entry.source_pred_count,
                entry.via_pred,
            )
        else:
            logger.info(
                "RECON BRIDGE: feeder blk[%d].arm%d -> blk[%d] (%s)",
                entry.source_block,
                entry.branch_arm,
                entry.target_block,
                entry.tag,
            )

    for entry in fixpoint_feeder_plan.log_entries:
        logger.debug(
            "RECON FEEDER: fixpoint blk[%d] has no "
            "last_write_site, skipping NOP",
            entry.source_block,
        )
        logger.info(
            "RECON BRIDGE: fixpoint feeder blk[%d] -> blk[%d] (state=0x%x)",
            entry.source_block,
            entry.target_block,
            entry.state_value,
        )

    emitted = len(feeder_plan.modifications) + len(fixpoint_feeder_plan.modifications)
    if emitted:
        logger.info(
            "RECON BRIDGE: %d feeder redirects for residual dispatcher feeders",
            emitted,
        )
    return emitted


def log_reconstruction_return_plan(logger, *, return_plan) -> int:
    for entry in return_plan.log_entries:
        if entry.tag == "fallback_1way":
            logger.info(
                "RECON RETURN: fallback wire blk[%d] -> blk[%d] (1-way)",
                entry.source_block,
                entry.target_block,
            )
        elif entry.tag == "fallback_2way":
            logger.info(
                "RECON RETURN: fallback wire blk[%d].arm%d -> blk[%d] (2-way)",
                entry.source_block,
                entry.branch_arm,
                entry.target_block,
            )
        elif entry.tag == "wire_1way":
            logger.info(
                "RECON RETURN: wire blk[%d] -> blk[%d] "
                "(bypass artifact blk[%d], 1-way)",
                entry.source_block,
                entry.target_block,
                entry.bypass_block,
            )
        elif entry.tag == "redirect_artifact":
            logger.info(
                "RECON RETURN: redirect artifact blk[%d] -> blk[%d]",
                entry.source_block,
                entry.target_block,
            )
        elif entry.tag == "wire_2way":
            logger.info(
                "RECON RETURN: wire blk[%d].arm%d -> blk[%d] "
                "(bypass artifact blk[%d], 2-way)",
                entry.source_block,
                entry.branch_arm,
                entry.target_block,
                entry.bypass_block,
            )

    logger.info(
        "RECON RETURN: %d return path edges wired, %d skipped",
        len(return_plan.modifications),
        len(return_plan.skipped_entries),
    )
    for entry in return_plan.skipped_entries:
        logger.info(
            "RECON RETURN: skip blk[%d] reason=%s",
            entry.source_block,
            entry.reason,
        )
    return len(return_plan.modifications)


def log_reconstruction_postprocess_result(logger, *, result, dag, mba) -> None:
    if result.entry_island_rescue_run is not None:
        entry_island_rescue_count = log_entry_island_rescue_run(
            logger,
            run=result.entry_island_rescue_run,
            mba=mba,
            prefix="entry-island rescue",
        )
        if entry_island_rescue_count:
            logger.info(
                "RECON DAG: entry-island rescue emitted %d redirects",
                entry_island_rescue_count,
            )

    if result.initial_residual_dispatcher_preds:
        logger.info(
            "RECON DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
            [blk_label(mba, serial) for serial in result.initial_residual_dispatcher_preds],
        )

    if result.state_var_stkoff is not None:
        log_reconstruction_artifact_returns(
            logger,
            state_var_stkoff=result.state_var_stkoff,
            flow_graph_block_count=result.flow_graph_block_count,
            state_constants_count=result.state_constants_count,
            artifact_return_blocks=set(result.artifact_return_blocks),
        )

    log_reconstruction_common_return_corridor(
        logger,
        common_return_corridor=set(result.common_return_corridor),
    )

    postprocess_plan = result.postprocess_plan
    if postprocess_plan is not None:
        preheader_bridge = postprocess_plan.preheader_bridge
        if (
            preheader_bridge.modification is not None
            and preheader_bridge.resolved_target is not None
        ):
            log_reconstruction_preheader_bridge(
                logger,
                dag=dag,
                preheader_bridge=preheader_bridge,
            )
        log_reconstruction_bridge_plan(
            logger,
            bridge_plan=postprocess_plan.bridge_plan,
        )
        log_reconstruction_feeder_plan(
            logger,
            feeder_plan=postprocess_plan.feeder_plan,
            fixpoint_feeder_plan=postprocess_plan.fixpoint_feeder_plan,
        )
        log_reconstruction_return_plan(
            logger,
            return_plan=postprocess_plan.return_plan,
        )

    if result.late_entry_island_rescue_run is not None:
        late_entry_island_rescue_count = log_entry_island_rescue_run(
            logger,
            run=result.late_entry_island_rescue_run,
            mba=mba,
            prefix="post-bridge entry-island rescue",
        )
        if late_entry_island_rescue_count:
            logger.info(
                "RECON DAG: post-bridge entry-island rescue emitted %d redirects",
                late_entry_island_rescue_count,
            )
        if not result.residual_dispatcher_preds:
            logger.info(
                "RECON BRIDGE: cleared all residual dispatcher feeders — BST cleanup enabled",
            )
        else:
            logger.info(
                "RECON BRIDGE: residual still has %d feeders: %s",
                len(result.residual_dispatcher_preds),
                [blk_label(mba, s) for s in result.residual_dispatcher_preds],
            )

    if result.late_island_rescue_result is not None:
        late_island_rescue_count = log_late_island_rescue_run(
            logger,
            run=result.late_island_rescue_result.run,
            diagnostics=result.late_island_rescue_result.diagnostics,
            mba=mba,
        )
        if late_island_rescue_count:
            logger.info(
                "RECON DAG: late island rescue emitted %d redirects",
                late_island_rescue_count,
            )

    if result.terminal_family_split_run is not None:
        terminal_family_split_count = log_terminal_family_split_run(
            logger,
            run=result.terminal_family_split_run,
            mba=mba,
        )
        if terminal_family_split_count:
            logger.info(
                "RECON RETURN: late terminal-family split emitted %d privatizations",
                terminal_family_split_count,
            )


__all__ = [
    "log_entry_island_rescue_run",
    "log_late_island_rescue_run",
    "log_reconstruction_artifact_returns",
    "log_reconstruction_bridge_plan",
    "log_reconstruction_common_return_corridor",
    "log_reconstruction_feeder_plan",
    "log_reconstruction_postprocess_result",
    "log_reconstruction_preheader_bridge",
    "log_reconstruction_return_plan",
    "log_terminal_family_split_run",
    "snapshot_reconstruction_dag",
    "snapshot_reconstruction_post_apply",
]
