from __future__ import annotations

from d810.cfg.dag_redirect_execution import (
    DagRedirectExecutionContext,
    DagRedirectMutableState,
    execute_dag_redirect_fallback,
)
from d810.cfg.path_tail_redirect_execution import (
    PathTailRedirectExecutionContext,
    PathTailRedirectMutableState,
    execute_path_tail_redirect,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_reporting import (
    log_dag_redirect_fallback_outcome,
    log_path_tail_redirect_outcome,
)


def emit_path_tail_redirect(
    logger,
    *,
    edge: object,
    target_entry: int | None,
    dag: object,
    builder: object,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int] | None,
    claimed_exits: dict[int, int],
    claimed_path_edges: dict[tuple[int, int], int],
    blocked_sources: set[int],
    terminal_protected_blocks: set[int],
    report_exit_handlers: set[int],
    report_exit_owned_blocks: set[int],
    bst_node_blocks: set[int],
    dispatcher_region: set[int],
    flow_graph: object,
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object | None,
    resolve_effective_target_entry: object,
    resolve_immediate_handoff_target: object,
    find_foreign_exact_entry_owner: object,
    is_semantic_handoff_redirect: object,
) -> bool:
    result = execute_path_tail_redirect(
        PathTailRedirectExecutionContext(
            edge=edge,
            dag=dag,
            target_entry=target_entry,
            flow_graph=flow_graph,
            block_succ_map=builder.block_succ_map,
            report_exit_handlers=frozenset(report_exit_handlers),
            report_exit_owned_blocks=frozenset(report_exit_owned_blocks),
            terminal_protected_blocks=frozenset(terminal_protected_blocks),
            bst_node_blocks=frozenset(bst_node_blocks),
            dispatcher_region=frozenset(dispatcher_region),
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            resolve_effective_target_entry=resolve_effective_target_entry,
            resolve_immediate_handoff_target=resolve_immediate_handoff_target,
            find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
            is_semantic_handoff_redirect=is_semantic_handoff_redirect,
        ),
        state=PathTailRedirectMutableState(
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_exits=claimed_exits,
            claimed_path_edges=claimed_path_edges,
            blocked_sources=blocked_sources,
        ),
    )
    return log_path_tail_redirect_outcome(
        logger,
        mba=mba,
        edge=edge,
        result=result,
    )


def emit_dag_redirect(
    logger,
    *,
    edge: object,
    dag: object,
    builder: object,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int],
    claimed_2way: dict[tuple[int, int], int],
    claimed_exits: dict[int, int],
    claimed_path_edges: dict[tuple[int, int], int],
    blocked_sources: set[int],
    terminal_source_keys: set[object],
    terminal_source_handlers: set[int],
    terminal_source_owned_blocks: set[int],
    terminal_protected_blocks: set[int],
    report_exit_handlers: set[int],
    report_exit_owned_blocks: set[int],
    bst_node_blocks: set[int],
    dispatcher_region: set[int],
    flow_graph: object,
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object | None,
    build_dag_node_maps: object,
    resolve_effective_target_entry: object,
    emit_path_tail_redirect: object,
    is_semantic_handoff_redirect: object,
) -> bool:
    target_node = (
        build_dag_node_maps(dag).node_by_key.get(edge.target_key)
        if edge.target_key is not None
        else None
    )
    target_entry = resolve_effective_target_entry(
        dag,
        edge,
        bst_node_blocks=bst_node_blocks,
        state_var_stkoff=state_var_stkoff,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        mba=mba,
    )
    if (
        target_node is not None
        and target_entry is not None
        and edge.target_entry_anchor is not None
        and target_entry != edge.target_entry_anchor
    ):
        logger.info(
            "LFG DAG: retargeted stale BST entry %s -> semantic entry %s for %s",
            blk_label(mba, edge.target_entry_anchor),
            blk_label(mba, target_entry),
            target_node.state_label,
        )
    if target_entry is None:
        if edge.target_entry_anchor is not None:
            logger.info(
                "LFG DAG: skipping %s -> %s because target remains inside BST region",
                blk_label(mba, edge.source_anchor.block_serial),
                blk_label(mba, edge.target_entry_anchor),
            )
        return False

    if emit_path_tail_redirect(
        edge=edge,
        target_entry=target_entry,
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        emitted=emitted,
        claimed_1way=claimed_1way,
        claimed_exits=claimed_exits,
        claimed_path_edges=claimed_path_edges,
        blocked_sources=blocked_sources,
        terminal_source_keys=terminal_source_keys,
        terminal_source_handlers=terminal_source_handlers,
        terminal_source_owned_blocks=terminal_source_owned_blocks,
        terminal_protected_blocks=terminal_protected_blocks,
        report_exit_handlers=report_exit_handlers,
        report_exit_owned_blocks=report_exit_owned_blocks,
        bst_node_blocks=bst_node_blocks,
        dispatcher_region=dispatcher_region,
        flow_graph=flow_graph,
        state_var_stkoff=state_var_stkoff,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        mba=mba,
    ):
        return True

    if edge.target_entry_anchor is not None and target_entry != edge.target_entry_anchor:
        logger.info(
            "LFG DAG: skipping stale raw target %s in favor of semantic entry %s",
            blk_label(mba, edge.target_entry_anchor),
            blk_label(mba, target_entry),
        )

    result = execute_dag_redirect_fallback(
        DagRedirectExecutionContext(
            edge=edge,
            dag=dag,
            target_entry=int(target_entry),
            flow_graph=flow_graph,
            block_succ_map=builder.block_succ_map,
            block_nsucc_map=builder.block_nsucc_map,
            report_exit_handlers=frozenset(report_exit_handlers),
            report_exit_owned_blocks=frozenset(report_exit_owned_blocks),
            terminal_source_owned_blocks=frozenset(terminal_source_owned_blocks),
            terminal_protected_blocks=frozenset(terminal_protected_blocks),
            blocked_sources=frozenset(blocked_sources),
            bst_node_blocks=frozenset(bst_node_blocks),
            dispatcher_region=frozenset(dispatcher_region),
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            is_semantic_handoff_redirect=is_semantic_handoff_redirect,
        ),
        state=DagRedirectMutableState(
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
        ),
    )
    return log_dag_redirect_fallback_outcome(
        logger,
        mba=mba,
        edge=edge,
        result=result,
    )


__all__ = [
    "emit_dag_redirect",
    "emit_path_tail_redirect",
]
