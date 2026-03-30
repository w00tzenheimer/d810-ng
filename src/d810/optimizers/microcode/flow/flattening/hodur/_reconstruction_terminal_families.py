from __future__ import annotations

from d810.cfg.terminal_family_split import (
    plan_terminal_family_splits,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.graph_reachability import compute_reachable_blocks
from d810.recon.flow.terminal_family_collection import (
    collect_terminal_family_report,
)


def emit_terminal_family_splits(
    logger,
    dag,
    *,
    base_flow_graph,
    projected_flow_graph,
    builder,
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


__all__ = ["emit_terminal_family_splits"]
