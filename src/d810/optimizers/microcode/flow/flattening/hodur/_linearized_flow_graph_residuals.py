from __future__ import annotations

from d810.cfg.dispatcher_backedge_disconnect_execution import (
    execute_dispatcher_backedge_disconnects,
)
from d810.cfg.projected_alias_normalization_planning import (
    apply_projected_alias_normalization_actions,
    collect_projected_alias_normalization_actions,
)
from d810.cfg.residual_branch_anchor_execution import (
    ResidualBranchAnchorExecutionContext,
    ResidualBranchAnchorMutableState,
    execute_residual_branch_anchor_handoff,
)
from d810.cfg.residual_dispatcher_handoff_execution import (
    ResidualDispatcherHandoffMutableState,
    build_residual_dispatcher_handoff_execution_context,
    execute_residual_dispatcher_handoffs,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_reporting import (
    log_residual_dispatcher_handoff_outcomes,
    log_resolved_state_machine_dot_report,
)
from d810.recon.flow.resolved_graph_reporting import (
    build_resolved_state_machine_dot_report,
)


def emit_residual_branch_anchor_handoff(
    logger,
    *,
    edge,
    source_block: int,
    via_pred: int,
    prefix_target: int,
    projected_flow_graph,
    bst_node_blocks: set[int],
    dispatcher_serial: int,
    builder,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_2way: dict[tuple[int, int], int],
    ignored_blocks: set[int],
    residual_ignored_blocks: set[int],
    mba,
) -> bool:
    result = execute_residual_branch_anchor_handoff(
        ResidualBranchAnchorExecutionContext(
            edge=edge,
            source_block=int(source_block),
            via_pred=int(via_pred),
            prefix_target=int(prefix_target),
            projected_flow_graph=projected_flow_graph,
            bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
            dispatcher_serial=int(dispatcher_serial),
            block_succ_map=builder.block_succ_map,
            ignored_blocks=frozenset(int(block) for block in ignored_blocks),
            residual_ignored_blocks=frozenset(
                int(block) for block in residual_ignored_blocks
            ),
        ),
        state=ResidualBranchAnchorMutableState(
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_2way=claimed_2way,
        ),
    )
    if not result.accepted:
        return False
    if result.already_claimed:
        return True
    assert result.branch_source is not None
    assert result.prefix_target is not None
    assert result.via_pred is not None
    assert result.edge_kind_name is not None
    logger.info(
        "LFG DAG: residual branch handoff %s -> %s (bypassing %s -> %s via %s)",
        blk_label(mba, int(result.branch_source)),
        blk_label(mba, int(result.prefix_target)),
        blk_label(mba, int(result.via_pred)),
        blk_label(mba, source_block),
        result.edge_kind_name,
    )
    return True


def emit_residual_dispatcher_handoffs(
    logger,
    *,
    dag,
    state_machine,
    projected_flow_graph,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    builder,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int],
    claimed_2way: dict[tuple[int, int], int],
    state_var_stkoff: int | None,
    dispatcher_lookup,
    dispatcher=None,
    mba=None,
    redirected_blocks: set[int] | None = None,
    collect_residual_dispatcher_predecessors=None,
    build_projected_mba=None,
    collect_residual_source_handoff_facts=None,
    iter_residual_prefix_handoffs=None,
    can_rewrite_shared_suffix_family_fallback=None,
    has_prior_branch_cut_for_state=None,
    is_shared_suffix_conditional_tail=None,
    pred_split_target_reaches_via_pred=None,
    resolve_synthesized_handoff_target=None,
    resolve_projected_path_tail_target=None,
    resolve_immediate_handoff_target=None,
) -> int:
    result = execute_residual_dispatcher_handoffs(
        build_residual_dispatcher_handoff_execution_context(
            dag=dag,
            state_machine=state_machine,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=int(dispatcher_serial),
            bst_node_blocks=bst_node_blocks,
            block_succ_map=builder.block_succ_map,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
            build_projected_mba=build_projected_mba,
            collect_residual_source_handoff_facts=collect_residual_source_handoff_facts,
            iter_residual_prefix_handoffs=iter_residual_prefix_handoffs,
            can_rewrite_shared_suffix_family_fallback=can_rewrite_shared_suffix_family_fallback,
            has_prior_branch_cut_for_state=has_prior_branch_cut_for_state,
            is_shared_suffix_conditional_tail=is_shared_suffix_conditional_tail,
            pred_split_target_reaches_via_pred=pred_split_target_reaches_via_pred,
            resolve_synthesized_handoff_target=resolve_synthesized_handoff_target,
            resolve_projected_path_tail_target=resolve_projected_path_tail_target,
            resolve_immediate_handoff_target=resolve_immediate_handoff_target,
        ),
        state=ResidualDispatcherHandoffMutableState(
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            redirected_blocks=redirected_blocks,
        ),
    )

    log_residual_dispatcher_handoff_outcomes(
        logger,
        mba=mba,
        outcomes=result.outcomes,
    )

    return int(result.redirected_count)


def normalize_projected_alias_handoffs(
    logger,
    *,
    dag,
    projected_flow_graph,
    dispatcher_serial: int,
    redirected_blocks: set[int],
    bst_node_blocks: set[int],
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int],
    mba,
    resolve_projected_path_tail_target,
) -> int:
    actions = collect_projected_alias_normalization_actions(
        dag=dag,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=int(dispatcher_serial),
        redirected_blocks={int(block) for block in redirected_blocks},
        bst_node_blocks={int(block) for block in bst_node_blocks},
        modifications=modifications,
        emitted=emitted,
        resolve_projected_path_tail_target=resolve_projected_path_tail_target,
    )

    apply_projected_alias_normalization_actions(
        actions,
        modifications=modifications,
        emitted=emitted,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        claimed_1way=claimed_1way,
    )

    for action in actions:
        logger.info(
            "LFG DAG: normalized projected residual handoff %s -> %s (was %s)",
            blk_label(mba, int(action.source_block)),
            blk_label(mba, int(action.target_entry)),
            blk_label(mba, int(action.current_target)),
        )

    return len(actions)


def emit_resolved_graph_dot(
    logger,
    *,
    sm,
    bst_result,
    handler_state_map: dict[int, int],
) -> None:
    if not logger.info_on:
        return

    report = build_resolved_state_machine_dot_report(
        sm,
        bst_result,
        handler_state_map,
    )

    log_resolved_state_machine_dot_report(
        logger,
        report=report,
    )


def disconnect_bst_comparison_nodes(
    logger,
    *,
    bst_node_blocks: set[int],
    dispatcher_serial: int,
    builder,
    modifications: list,
    emitted: set[tuple[int, int]],
    mba=None,
) -> int:
    result = execute_dispatcher_backedge_disconnects(
        block_nsucc_map=builder.block_nsucc_map,
        block_succ_map=builder.block_succ_map,
        dispatcher_serial=int(dispatcher_serial),
        bst_node_blocks={int(block) for block in bst_node_blocks},
        emitted=emitted,
        convert_to_goto=builder.convert_to_goto,
        modifications=modifications,
    )
    for plan in result.plans:
        logger.info(
            "BST_DISCONNECT: %s (%s) 2-way -> 1-way goto "
            "%s (removed dispatcher back-edge to %s)",
            blk_label(mba, int(plan.source_block))
            if mba
            else f"blk[{int(plan.source_block)}]",
            "BST" if plan.is_bst else "handler",
            blk_label(mba, int(plan.keep_target))
            if mba
            else f"blk[{int(plan.keep_target)}]",
            blk_label(mba, dispatcher_serial) if mba else f"blk[{dispatcher_serial}]",
        )
    return result.count


__all__ = [
    "disconnect_bst_comparison_nodes",
    "emit_residual_branch_anchor_handoff",
    "emit_residual_dispatcher_handoffs",
    "emit_resolved_graph_dot",
    "normalize_projected_alias_handoffs",
]
