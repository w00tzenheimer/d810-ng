from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.plan import compile_patch_plan
from d810.cfg.reconstruction_bridge_planning import (
    collect_reconstruction_claims,
    collect_suppressed_bridge_pairs,
    plan_reconstruction_bridge_modifications,
    plan_reconstruction_feeder_modifications,
    plan_reconstruction_preheader_bridge,
)
from d810.cfg.terminal_family_split import plan_terminal_family_splits
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.linearized_state_dag import SemanticEdgeKind
from d810.recon.flow.reconstruction_discovery import classify_artifact_return_blocks
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

    preheader_bridge = plan_reconstruction_preheader_bridge(
        dag=dag,
        flow_graph=flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=_bst_set,
        dispatcher=dispatcher,
    )
    if preheader_bridge.modification is not None and preheader_bridge.resolved_target is not None:
        modifications.append(preheader_bridge.modification)
        logger.info(
            "RECON BRIDGE: pre-header blk[%d] -> blk[%d]",
            dag.pre_header_serial,
            preheader_bridge.resolved_target,
        )

    claimed_sources, claimed_targets = collect_reconstruction_claims(
        modifications,
        owned_blocks=owned_blocks,
    )
    suppressed_bridge_pairs = collect_suppressed_bridge_pairs(rejected_metadata)

    bridge_plan = plan_reconstruction_bridge_modifications(
        dag=dag,
        flow_graph=flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=_bst_set,
        claimed_sources=claimed_sources,
        claimed_targets=claimed_targets,
        suppressed_bridge_pairs=suppressed_bridge_pairs,
    )
    bridge_mods: list = list(bridge_plan.modifications)
    claimed_sources = set(bridge_plan.claimed_sources)
    claimed_targets = set(bridge_plan.claimed_targets)
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

    feeder_plan = plan_reconstruction_feeder_modifications(
        dag=dag,
        flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=_bst_set,
        claimed_sources=claimed_sources,
        claimed_targets=claimed_targets,
        suppressed_bridge_pairs=suppressed_bridge_pairs,
    )
    feeder_mods: list = list(feeder_plan.modifications)
    claimed_sources = set(feeder_plan.claimed_sources)
    claimed_targets = set(feeder_plan.claimed_targets)
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

    if (
        constant_result is not None
        and state_var_stkoff is not None
        and hasattr(constant_result, "out_stk_maps")
        and dispatcher is not None
    ):
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
                blk_serial,
                int(resolved),
                state_val,
            )

    if feeder_mods:
        modifications.extend(feeder_mods)
        logger.info(
            "RECON BRIDGE: %d feeder redirects for residual dispatcher feeders",
            len(feeder_mods),
        )

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

    return_mods: list = []
    return_skipped: list[tuple[int, str]] = []
    _ret_paths: list[set[int]] = []
    for _e in dag.edges:
        if _e.kind == SemanticEdgeKind.CONDITIONAL_RETURN and _e.ordered_path:
            _ret_paths.append({int(s) for s in _e.ordered_path})
    common_return_corridor: set[int] = set()
    if _ret_paths:
        common_return_corridor = _ret_paths[0]
        for _p in _ret_paths[1:]:
            common_return_corridor &= _p
    if common_return_corridor:
        earliest = min(common_return_corridor)
        _walk_serial = earliest
        for _ in range(5):
            _walk_blk = flow_graph.get_block(_walk_serial)
            if _walk_blk is None:
                break
            preds = list(flow_graph.predecessors(_walk_serial))
            logger.info(
                "RECON RETURN: corridor backward walk blk[%d] "
                "preds=%s shared_suffix_blocks=%s",
                _walk_serial,
                preds,
                sorted(shared_suffix_blocks),
            )
            extended = False
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

        source_node = node_by_key.get(edge.source_key)
        node_shared_suffix: set[int] = set()
        if source_node is not None:
            node_shared_suffix = {int(b) for b in source_node.shared_suffix_blocks}

        suffix_entry_serial: int | None = None
        anchor_serial: int | None = None
        if len(ordered) >= 2:
            terminal = ordered[-1]
            corridor_candidates = sorted(
                b for b in common_return_corridor if b != terminal
            )
            if not corridor_candidates:
                corridor_candidates = sorted(
                    b
                    for b in node_shared_suffix
                    if b != terminal and b not in _bst_set and b != dispatcher_serial
                )
            if corridor_candidates:
                suffix_entry_serial = corridor_candidates[0]
            anchor_serial = src_serial

        if suffix_entry_serial is None:
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
                        from_serial,
                        expected_next,
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
                            from_serial,
                            arm,
                            expected_next,
                        )
                        fallback_emitted = True
                        break
                    if fallback_emitted:
                        break
            if not fallback_emitted:
                return_skipped.append((src_serial, "no_suffix_fallback_exhausted"))
            continue

        logger.info(
            "RECON RETURN: path-local edge src=blk[%d] path=%s "
            "suffix_entry=blk[%d] anchor=blk[%d]",
            src_serial,
            ordered,
            suffix_entry_serial,
            anchor_serial,
        )

        if anchor_serial in _bst_set:
            return_skipped.append((anchor_serial, "anchor_in_bst"))
            continue
        if anchor_serial in claimed_sources:
            return_skipped.append((anchor_serial, "anchor_claimed"))
            continue

        anchor_block = flow_graph.get_block(anchor_serial)
        if anchor_block is None:
            return_skipped.append((anchor_serial, "anchor_block_not_found"))
            continue

        if anchor_block.nsucc == 1:
            old_target = int(anchor_block.succs[0])
            if old_target == suffix_entry_serial:
                logger.info(
                    "RECON RETURN: blk[%d] already points to "
                    "suffix entry blk[%d]",
                    anchor_serial,
                    suffix_entry_serial,
                )
                continue
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
                anchor_serial,
                suffix_entry_serial,
                old_target,
            )
        elif anchor_block.nsucc == 2:
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
                    wired = True
                    break
                if arm == 0:
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
                            arm_target,
                            suffix_entry_serial,
                        )
                        wired = True
                        break
                    logger.info(
                        "RECON RETURN: skip arm0 blk[%d] (real return writer)",
                        arm_target,
                    )
                    wired = True
                    break
                else:
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
                    anchor_serial,
                    arm,
                    suffix_entry_serial,
                    arm_target,
                )
                wired = True
                break
            if not wired:
                return_skipped.append((anchor_serial, "no_eligible_arm"))
        else:
            return_skipped.append(
                (anchor_serial, f"unexpected_nsucc_{anchor_block.nsucc}")
            )

    if return_mods:
        modifications.extend(return_mods)
    logger.info(
        "RECON RETURN: %d return path edges wired, %d skipped",
        len(return_mods),
        len(return_skipped),
    )
    for blk_ser, reason in return_skipped:
        logger.info("RECON RETURN: skip blk[%d] reason=%s", blk_ser, reason)

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
