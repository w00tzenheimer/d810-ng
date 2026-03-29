from __future__ import annotations


def allow_same_maturity_rerun(
    *,
    snapshot: object,
    consume_retry: bool,
    logger: object,
    collect_residual_dispatcher_predecessors: object,
    collect_dispatcher_predecessors: object,
    has_live_exact_residual_handoff: object,
    last_successful_residual_dispatcher_pred_counts: dict[tuple[int, int], int],
    same_count_exact_rerun_used: set[tuple[int, int]],
) -> bool:
    mba = snapshot.mba
    flow_graph = snapshot.flow_graph
    bst_result = snapshot.bst_result
    if mba is None or flow_graph is None or bst_result is None:
        return False
    func_ea = mba.entry_ea
    maturity = mba.maturity
    key = (func_ea, maturity)
    bst_node_blocks = set(getattr(bst_result, "bst_node_blocks", ()) or ())
    residual_preds = collect_residual_dispatcher_predecessors(
        flow_graph,
        snapshot.bst_dispatcher_serial,
        bst_node_blocks=bst_node_blocks,
        reachable_from_serial=getattr(flow_graph, "entry_serial", None),
    )
    raw_residual_preds = collect_dispatcher_predecessors(
        flow_graph,
        snapshot.bst_dispatcher_serial,
        bst_node_blocks=bst_node_blocks,
    )
    effective_residual_preds = raw_residual_preds or residual_preds
    if not effective_residual_preds:
        logger.info(
            "LFG: already applied for func 0x%X at maturity %d",
            func_ea,
            maturity,
        )
        return False
    previous_residual_count = last_successful_residual_dispatcher_pred_counts.get(key)
    if (
        previous_residual_count is not None
        and len(effective_residual_preds) >= previous_residual_count
    ):
        if (
            key not in same_count_exact_rerun_used
            and has_live_exact_residual_handoff(
                snapshot,
                effective_residual_preds,
            )
        ):
            if consume_retry:
                same_count_exact_rerun_used.add(key)
            logger.info(
                "LFG: allowing one same-count rerun for func 0x%X at maturity %d because live residual exact handoffs remain: %s",
                func_ea,
                maturity,
                effective_residual_preds,
            )
            return True
        if (
            key not in same_count_exact_rerun_used
            and len(effective_residual_preds) == previous_residual_count
            and effective_residual_preds
        ):
            if consume_retry:
                same_count_exact_rerun_used.add(key)
            logger.info(
                "LFG: allowing one exploratory same-count rerun for func 0x%X at maturity %d because residual dispatcher preds remain: %s",
                func_ea,
                maturity,
                effective_residual_preds,
            )
            return True
        logger.info(
            "LFG: suppressing same-maturity rerun for func 0x%X at maturity %d "
            "because residual dispatcher preds did not improve (%d -> %d)",
            func_ea,
            maturity,
            previous_residual_count,
            len(effective_residual_preds),
        )
        return False
    same_count_exact_rerun_used.discard(key)
    logger.info(
        "LFG: allowing same-maturity rerun for func 0x%X with residual dispatcher preds %s",
        func_ea,
        effective_residual_preds,
    )
    return True


__all__ = ["allow_same_maturity_rerun"]
