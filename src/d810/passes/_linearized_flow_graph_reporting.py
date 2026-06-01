from __future__ import annotations

from d810.backends.hexrays.evidence._helpers import blk_label


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


def log_path_tail_redirect_outcome(
    logger,
    *,
    mba: object | None,
    edge: object,
    result: object,
) -> bool:
    if not result.accepted:
        source_block = result.source_block
        target_entry = result.target_entry
        if (
            result.rejection_reason == "foreign_exact_entry_owner"
            and result.foreign_exact_owner_label is not None
            and source_block is not None
            and target_entry is not None
        ):
            logger.info(
                "LFG DAG: skipping %s -> %s because %s is the exact entry for %s, not source corridor %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                blk_label(mba, source_block),
                result.foreign_exact_owner_label,
                result.source_state_const
                if result.source_state_const is not None
                else edge.source_key.handler_serial,
            )
        elif (
            result.rejection_reason == "backward_same_corridor"
            and source_block is not None
            and target_entry is not None
        ):
            logger.info(
                "LFG DAG: skipping %s -> %s because target is earlier in the same corridor",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )
        elif (
            result.rejection_reason == "target_reaches_source"
            and source_block is not None
            and target_entry is not None
        ):
            logger.info(
                "LFG DAG: skipping %s -> %s because target already reaches source",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )
        elif (
            result.rejection_reason == "shared_handoff_conflict"
            and result.shared_handoff is not None
            and source_block is not None
            and target_entry is not None
        ):
            logger.info(
                "LFG DAG: skipping %s -> %s because %s already proves concrete shared handoff %s for state 0x%X",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                blk_label(mba, source_block),
                blk_label(mba, result.shared_handoff[1]),
                result.shared_handoff[0],
            )
        return False

    assert result.kind is not None
    assert result.source_block is not None
    assert result.target_entry is not None
    source_block = result.source_block
    target_entry = result.target_entry
    via_pred = result.via_pred
    if result.kind == "shared_goto":
        logger.info(
            "LFG DAG: shared tail redirect %s -> %s via %s",
            blk_label(mba, source_block),
            blk_label(mba, target_entry),
            edge.kind.name.lower(),
        )
    elif result.kind == "direct_goto":
        logger.info(
            "LFG DAG: path-tail redirect %s -> %s via %s",
            blk_label(mba, source_block),
            blk_label(mba, target_entry),
            edge.kind.name.lower(),
        )
    elif result.kind == "pred_split":
        assert via_pred is not None
        logger.info(
            "LFG DAG: path-tail pred-split %s via %s -> %s",
            blk_label(mba, source_block),
            blk_label(mba, via_pred),
            blk_label(mba, target_entry),
        )
    elif result.kind == "duplicate":
        assert via_pred is not None
        logger.info(
            "LFG DAG: path-tail duplicate %s via %s -> %s",
            blk_label(mba, source_block),
            blk_label(mba, via_pred),
            blk_label(mba, target_entry),
        )
    return True


def log_dag_redirect_fallback_outcome(
    logger,
    *,
    mba: object | None,
    edge: object,
    result: object,
) -> bool:
    assert result.source_block is not None
    assert result.target_entry is not None
    source_block = result.source_block
    target_entry = result.target_entry
    if result.allowed_semantic_handoff_backreach:
        logger.info(
            "LFG DAG: allowing semantic handoff %s -> %s despite existing backreach",
            blk_label(mba, source_block),
            blk_label(mba, target_entry),
        )
    if not result.accepted:
        if result.rejection_reason == "backward_same_corridor":
            logger.info(
                "LFG DAG: skipping %s -> %s because target is earlier in the same corridor",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )
        elif result.rejection_reason == "target_reaches_source":
            logger.info(
                "LFG DAG: skipping %s -> %s because target already reaches source",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )
        elif result.rejection_reason == "live_oneway_noop":
            logger.info(
                "LFG DAG: skipping %s -> %s because live CFG already has that 1-way handoff",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )
        elif result.rejection_reason == "branch_conflict":
            assert result.old_target is not None
            assert result.existing_target is not None
            logger.info(
                "LFG DAG: conflict on 2-way %s old=%s: already -> %s, skipping -> %s",
                blk_label(mba, source_block),
                blk_label(mba, result.old_target),
                blk_label(mba, result.existing_target),
                blk_label(mba, target_entry),
            )
        elif result.rejection_reason == "oneway_conflict":
            assert result.existing_target is not None
            logger.info(
                "LFG DAG: conflict on 1-way %s: already -> %s, skipping -> %s",
                blk_label(mba, source_block),
                blk_label(mba, result.existing_target),
                blk_label(mba, target_entry),
            )
        return False
    logger.info(
        "LFG DAG: resolved %s -> %s via %s (%s)",
        blk_label(mba, source_block),
        blk_label(mba, target_entry),
        edge.kind.name.lower(),
        edge.source_anchor.kind.name.lower(),
    )
    return True


__all__ = [
    "log_dag_redirect_fallback_outcome",
    "log_path_tail_redirect_outcome",
    "log_residual_dispatcher_handoff_outcomes",
    "log_resolved_state_machine_dot_report",
]
