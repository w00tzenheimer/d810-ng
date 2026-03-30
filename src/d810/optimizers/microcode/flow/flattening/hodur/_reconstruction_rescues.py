from __future__ import annotations

from d810.cfg.entry_island_rescue_planning import (
    plan_entry_island_rescues,
)
from d810.cfg.mod_claims import collect_mod_claims
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.recon.flow.graph_reachability import compute_reachable_blocks


def emit_entry_island_rescues(
    logger,
    dag,
    *,
    base_flow_graph,
    projected_flow_graph,
    builder,
    modifications: list,
    dispatcher_region: set[int],
    mba,
) -> int:
    def _collect_seeds(
        _dag,
        *,
        projected_flow_graph,
        reachable_blocks: set[int],
        dispatcher_region: set[int],
    ):
        _claimed_sources, claimed_targets = collect_mod_claims(modifications)
        return collect_entry_island_rescue_seeds(
            _dag,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
            claimed_targets=claimed_targets,
        )

    run = plan_entry_island_rescues(
        dag=dag,
        base_flow_graph=base_flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        modifications=modifications,
        dispatcher_region=dispatcher_region,
        collect_seeds=_collect_seeds,
        compute_reachable_blocks=lambda flow_graph: compute_reachable_blocks(
            flow_graph,
            start_serial=getattr(flow_graph, "entry_serial", None),
        ),
    )

    for iteration in run.iterations:
        selection = iteration.selection
        if (
            not selection.accepted
            or selection.option is None
            or selection.score is None
        ):
            continue
        logger.info(
            "RECON DAG: entry-island rescue %s -> %s%s (delta=%+d)",
            blk_label(mba, selection.option.source_block),
            blk_label(mba, selection.option.lifted_entry),
            (
                f" via_pred={blk_label(mba, selection.option.via_pred)}"
                if selection.option.via_pred is not None
                else ""
            ),
            selection.score[0] if selection.score is not None else 0,
        )

    return run.emitted_count


def emit_late_island_rescues(
    logger,
    dag,
    *,
    base_flow_graph,
    projected_flow_graph,
    builder,
    modifications: list,
    dispatcher_region: set[int],
    dispatcher=None,
    mba=None,
) -> int:
    def _collect_seeds(
        _dag,
        *,
        projected_flow_graph,
        reachable_blocks: set[int],
        dispatcher_region: set[int],
    ):
        return collect_late_entry_island_rescue_seeds(
            _dag,
            projected_flow_graph=projected_flow_graph,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
        )

    run = plan_entry_island_rescues(
        dag=dag,
        base_flow_graph=base_flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        modifications=modifications,
        dispatcher_region=dispatcher_region,
        collect_seeds=_collect_seeds,
        compute_reachable_blocks=lambda flow_graph: compute_reachable_blocks(
            flow_graph,
            start_serial=getattr(flow_graph, "entry_serial", None),
        ),
    )

    for iteration in run.iterations:
        for seed in iteration.raw_seeds:
            if seed.source_block is None:
                logger.info(
                    "RECON DAG: late island rescue: no reachable "
                    "frontier for BST passthrough blk[%d] -> "
                    "blk[%d] (edge src=%s)",
                    seed.passthrough_block,
                    seed.lifted_entry,
                    blk_label(mba, seed.edge_source_block),
                )
        if (
            not iteration.selection.accepted
            or iteration.selection.option is None
            or iteration.selection.score is None
        ):
            continue
        selection = iteration.selection
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

    if run.emitted_count == 0 and dispatcher is not None:
        reachable_blocks = compute_reachable_blocks(
            run.projected_flow_graph,
            start_serial=getattr(run.projected_flow_graph, "entry_serial", None),
        ) or set()
        for diagnostic in collect_late_entry_island_diagnostics(
            run.projected_flow_graph,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
            dispatcher=dispatcher,
        ):
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

    return run.emitted_count


__all__ = [
    "emit_entry_island_rescues",
    "emit_late_island_rescues",
]
