from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.plan import compile_patch_plan
from d810.cfg.reconstruction_postprocess_planning import (
    plan_reconstruction_postprocess_modifications,
)
from d810.cfg.terminal_family_split import plan_terminal_family_splits
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.reconstruction_discovery import classify_artifact_return_blocks
from d810.recon.flow.return_corridor_discovery import collect_common_return_corridor
from d810.recon.flow.terminal_family_collection import collect_terminal_family_report


@dataclass(frozen=True)
class ReconstructionPostprocessResult:
    projected_flow_graph: object
    residual_dispatcher_preds: tuple[int, ...]
    allow_post_apply_bst_cleanup: bool
    post_apply_bst_cleanup_reason: str | None


def run_reconstruction_postprocess(
    logger,
    *,
    dag,
    corrected_dag,
    flow_graph,
    modifications: list,
    builder,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    bst_result,
    state_machine,
    state_var_stkoff: int | None,
    constant_result,
    node_by_key,
    shared_suffix_blocks: set[int],
    rejected_metadata: list[dict[str, int | str | None]],
    owned_blocks: set[int],
    mba,
    log_terminal_family_split_run,
    emit_entry_island_rescues,
    emit_late_island_rescues,
) -> ReconstructionPostprocessResult:
    projected_flow_graph = flow_graph
    residual_dispatcher_preds: tuple[int, ...] = ()
    allow_post_apply_bst_cleanup = True
    post_apply_bst_cleanup_reason: str | None = None

    if dispatcher_serial < 0:
        return ReconstructionPostprocessResult(
            projected_flow_graph=projected_flow_graph,
            residual_dispatcher_preds=residual_dispatcher_preds,
            allow_post_apply_bst_cleanup=allow_post_apply_bst_cleanup,
            post_apply_bst_cleanup_reason=post_apply_bst_cleanup_reason,
        )

    try:
        patch_plan = compile_patch_plan(modifications, flow_graph)
        projected_flow_graph = project_post_state(flow_graph, patch_plan)
    except Exception:
        projected_flow_graph = flow_graph

    entry_island_rescue_count = emit_entry_island_rescues(
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

    dispatcher = getattr(bst_result, "dispatcher", None)
    _bst_set = set(dag.bst_node_blocks)
    _bst_set.add(dispatcher_serial)

    artifact_return_blocks: set[int] = set()
    if state_var_stkoff is not None:
        _state_consts = state_machine.state_constants if state_machine is not None else set()
        logger.info(
            "RECON RETURN: classifying artifacts: "
            "state_var_stkoff=%s, flow_graph blocks=%d, "
            "state_constants count=%d",
            state_var_stkoff,
            len(flow_graph.blocks),
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

    common_return_corridor = collect_common_return_corridor(
        dag,
        flow_graph,
        bst_node_blocks=_bst_set,
        dispatcher_serial=dispatcher_serial,
    )
    if common_return_corridor:
        logger.info(
            "RECON RETURN: common return corridor blocks: %s",
            sorted(common_return_corridor),
        )

    postprocess_plan = plan_reconstruction_postprocess_modifications(
        dag=dag,
        flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=_bst_set,
        dispatcher=dispatcher,
        modifications=modifications,
        owned_blocks=owned_blocks,
        rejected_metadata=rejected_metadata,
        constant_result=constant_result,
        state_var_stkoff=state_var_stkoff,
        artifact_return_blocks=artifact_return_blocks,
        common_return_corridor=common_return_corridor,
        node_by_key=node_by_key,
    )

    preheader_bridge = postprocess_plan.preheader_bridge
    if preheader_bridge.modification is not None and preheader_bridge.resolved_target is not None:
        modifications.append(preheader_bridge.modification)
        logger.info(
            "RECON BRIDGE: pre-header blk[%d] -> blk[%d]",
            dag.pre_header_serial,
            preheader_bridge.resolved_target,
        )

    bridge_plan = postprocess_plan.bridge_plan
    bridge_mods: list = list(bridge_plan.modifications)
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

    if bridge_mods:
        modifications.extend(bridge_mods)
        logger.info(
            "RECON BRIDGE: %d bridge edges for unclaimed handler entries",
            len(bridge_mods),
        )

    feeder_plan = postprocess_plan.feeder_plan
    feeder_mods: list = list(feeder_plan.modifications)
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

    fixpoint_feeder_plan = postprocess_plan.fixpoint_feeder_plan
    feeder_mods.extend(fixpoint_feeder_plan.modifications)
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

    if feeder_mods:
        modifications.extend(feeder_mods)
        logger.info(
            "RECON BRIDGE: %d feeder redirects for residual dispatcher feeders",
            len(feeder_mods),
        )

    return_plan = postprocess_plan.return_plan
    return_mods: list = list(return_plan.modifications)
    if return_mods:
        modifications.extend(return_mods)
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
        len(return_mods),
        len(return_plan.skipped_entries),
    )
    for entry in return_plan.skipped_entries:
        logger.info(
            "RECON RETURN: skip blk[%d] reason=%s",
            entry.source_block,
            entry.reason,
        )

    force_wire_mods: list = []

    all_extra_mods = bridge_mods + return_mods + feeder_mods + force_wire_mods
    projected_flow_graph = flow_graph
    if all_extra_mods:
        try:
            patch_plan = compile_patch_plan(modifications, flow_graph)
            projected_flow_graph = project_post_state(flow_graph, patch_plan)
        except Exception:
            projected_flow_graph = flow_graph

        late_entry_island_rescue_count = emit_entry_island_rescues(
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
                projected_flow_graph = project_post_state(flow_graph, patch_plan)
            except Exception:
                projected_flow_graph = flow_graph

        residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
            projected_flow_graph,
            dispatcher_serial,
            bst_node_blocks=dispatcher_region,
            reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
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

        late_island_rescue_count = emit_late_island_rescues(
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
                projected_flow_graph = project_post_state(flow_graph, patch_plan)
            except Exception:
                projected_flow_graph = flow_graph

    terminal_family_split_run = plan_terminal_family_splits(
        dag=dag,
        base_flow_graph=flow_graph,
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
    terminal_family_split_count = log_terminal_family_split_run(
        logger,
        run=terminal_family_split_run,
        mba=mba,
    )
    if terminal_family_split_count:
        logger.info(
            "RECON RETURN: late terminal-family split emitted %d privatizations",
            terminal_family_split_count,
        )
        try:
            patch_plan = compile_patch_plan(modifications, flow_graph)
            projected_flow_graph = project_post_state(flow_graph, patch_plan)
        except Exception:
            projected_flow_graph = flow_graph

    return ReconstructionPostprocessResult(
        projected_flow_graph=projected_flow_graph,
        residual_dispatcher_preds=residual_dispatcher_preds,
        allow_post_apply_bst_cleanup=allow_post_apply_bst_cleanup,
        post_apply_bst_cleanup_reason=post_apply_bst_cleanup_reason,
    )


__all__ = [
    "ReconstructionPostprocessResult",
    "run_reconstruction_postprocess",
]
