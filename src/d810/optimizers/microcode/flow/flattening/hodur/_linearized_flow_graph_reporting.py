from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label


def log_residual_dispatcher_handoff_outcomes(
    logger,
    *,
    mba: object | None,
    outcomes: tuple[object, ...],
) -> None:
    for outcome in outcomes:
        source_block = int(outcome.source_block)
        source_plan = outcome.source_plan
        if not source_plan.accepted:
            if source_plan.rejection_reason == "shared_suffix_conditional_tail":
                logger.info(
                    "LFG DAG: residual handoff %s -> %s suppressed because %s is a shared-suffix tail of an earlier conditional corridor",
                    blk_label(mba, source_block),
                    blk_label(mba, int(source_plan.target_entry)),
                    blk_label(mba, source_block),
                )
            elif source_plan.rejection_reason == "prior_branch_cut":
                logger.info(
                    "LFG DAG: residual handoff %s -> %s suppressed because an earlier conditional corridor already owns state 0x%X",
                    blk_label(mba, source_block),
                    blk_label(mba, int(source_plan.target_entry)),
                    int(source_plan.state_value),
                )
            elif source_plan.rejection_reason == "cycle_risk":
                logger.info(
                    "LFG DAG: residual handoff %s -> %s still forms a non-dispatcher cycle, skipping",
                    blk_label(mba, source_block),
                    blk_label(mba, int(source_plan.target_entry)),
                )
            elif source_plan.rejection_reason == "live_oneway_noop":
                logger.info(
                    "LFG DAG: residual handoff %s already targets %s, skipping live no-op",
                    blk_label(mba, source_block),
                    blk_label(mba, int(source_plan.target_entry)),
                )
            continue

        kind_name = (
            source_plan.kind.name
            if hasattr(source_plan.kind, "name")
            else str(source_plan.kind)
        )
        if kind_name == "PRED_SPLIT":
            for selection in source_plan.pred_splits:
                logger.info(
                    "LFG DAG: residual dispatcher pred-split %s via %s -> %s (state 0x%X)",
                    blk_label(mba, source_block),
                    blk_label(mba, int(selection.via_pred)),
                    blk_label(mba, int(selection.target_entry)),
                    int(selection.state_value),
                )
        elif kind_name == "GOTO":
            logger.info(
                "LFG DAG: residual dispatcher handoff %s -> %s (state 0x%X)",
                blk_label(mba, source_block),
                blk_label(mba, int(source_plan.target_entry)),
                int(source_plan.state_value),
            )
        elif kind_name == "PREFIX_PEEL":
            logger.info(
                "LFG DAG: residual prefix handoff %s -> %s (bypassing %s via %s)",
                blk_label(mba, int(source_plan.via_pred)),
                blk_label(mba, int(source_plan.prefix_target)),
                blk_label(mba, source_block),
                source_plan.edge_kind_name,
            )


def log_resolved_state_machine_dot_report(
    logger,
    *,
    report: object,
) -> None:
    logger.info(
        "LFG resolved graph: %d nodes, %d edges, %d resolved, "
        "%d unresolved, %d exits, %d conditional",
        report.node_count,
        report.edge_count,
        report.resolved_count,
        report.unresolved_count,
        report.exit_count,
        report.conditional_count,
    )
    logger.info("LFG_RESOLVED_GRAPH_DOT_START")
    for line in report.dot_lines:
        logger.info(line)
    logger.info("LFG_RESOLVED_GRAPH_DOT_END")


__all__ = [
    "log_residual_dispatcher_handoff_outcomes",
    "log_resolved_state_machine_dot_report",
]
