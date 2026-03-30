from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label


def snapshot_reconstruction_dag(logger, *, dag, mba, strategy_name: str) -> None:
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
                dag_nodes.append(DagNode(
                    state=int(node.key.state_const) if node.key.state_const is not None else 0,
                    state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
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
    except Exception:
        logger.warning(
            "Early diagnostic DAG snapshot failed (non-critical)",
            exc_info=True,
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
                snapshot_dag,
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
                dag_nodes.append(DagNode(
                    state=int(node.key.state_const) if node.key.state_const is not None else 0,
                    state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
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

            mod_snapshots = []
            for midx, mod in enumerate(modifications):
                mod_type = type(mod).__name__
                source_block = (
                    getattr(mod, "from_serial", None)
                    or getattr(mod, "source_block", None)
                    or getattr(mod, "src_block", None)
                    or getattr(mod, "block_serial", None)
                )
                target_block = (
                    getattr(mod, "new_target", None)
                    or getattr(mod, "goto_target", None)
                    or getattr(mod, "conditional_target", None)
                )
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


__all__ = [
    "log_entry_island_rescue_run",
    "log_late_island_rescue_run",
    "log_terminal_family_split_run",
    "snapshot_reconstruction_dag",
    "snapshot_reconstruction_post_apply",
]
