from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Mapping

from d810.cfg.dag_redirect_modification_planning import (
    DagRedirectFallbackContext,
    apply_dag_redirect_emission_plan,
    plan_dag_redirect_fallback,
)
from d810.cfg.path_tail_redirect_execution import emit_path_tail_redirect
from d810.cfg.lowering_selector import (
    is_backward_same_corridor_target,
    is_live_oneway_noop,
    resolve_redirect_old_target,
    target_reaches_source_ignoring_blocks,
)


@dataclass(frozen=True, slots=True)
class DagRedirectExecutionContext:
    edge: object
    dag: object
    target_entry: int
    flow_graph: object
    block_succ_map: Mapping[int, tuple[int, ...]]
    block_nsucc_map: Mapping[int, int]
    report_exit_handlers: frozenset[int]
    report_exit_owned_blocks: frozenset[int]
    terminal_source_owned_blocks: frozenset[int]
    terminal_protected_blocks: frozenset[int]
    blocked_sources: frozenset[int]
    bst_node_blocks: frozenset[int]
    dispatcher_region: frozenset[int]
    state_var_stkoff: int | None
    dispatcher_lookup: object | None
    dispatcher: object | None
    mba: object | None
    is_semantic_handoff_redirect: Callable[..., bool]


@dataclass(slots=True)
class DagRedirectMutableState:
    modifications: list
    owned_blocks: set[int]
    owned_edges: set[tuple[int, int]]
    owned_transitions: set[tuple[int, int]]
    emitted: set[tuple[int, int]]
    claimed_1way: dict[int, int]
    claimed_2way: dict[tuple[int, int], int]


@dataclass(frozen=True, slots=True)
class DagRedirectExecutionResult:
    accepted: bool
    rejection_reason: str = ""
    source_block: int | None = None
    target_entry: int | None = None
    old_target: int | None = None
    existing_target: int | None = None
    allowed_semantic_handoff_backreach: bool = False


def execute_dag_redirect_fallback(
    context: DagRedirectExecutionContext,
    *,
    state: DagRedirectMutableState,
) -> DagRedirectExecutionResult:
    source_block = int(context.edge.source_anchor.block_serial)
    target_entry = int(context.target_entry)

    allow_semantic_handoff = context.is_semantic_handoff_redirect(
        context.dag,
        context.edge,
        source_block=source_block,
        target_entry=target_entry,
        state_var_stkoff=context.state_var_stkoff,
        dispatcher_lookup=context.dispatcher_lookup,
        dispatcher=context.dispatcher,
        mba=context.mba,
    )
    target_reaches_source = target_reaches_source_ignoring_blocks(
        context.flow_graph,
        target_entry=target_entry,
        source_block=source_block,
        ignored_blocks=set(context.dispatcher_region) | set(context.bst_node_blocks),
    )

    emit_key = (source_block, target_entry)
    nsucc = int(context.block_nsucc_map.get(source_block, 1))
    old_target = resolve_redirect_old_target(
        source_block,
        source_succs=tuple(context.block_succ_map.get(source_block, ())),
        ordered_path=tuple(int(node) for node in context.edge.ordered_path),
        target_entry_anchor=(
            int(context.edge.target_entry_anchor)
            if context.edge.target_entry_anchor is not None
            else None
        ),
        source_branch_arm=(
            int(context.edge.source_anchor.branch_arm)
            if context.edge.source_anchor.branch_arm is not None
            else None
        ),
        source_is_conditional_branch=(
            context.edge.source_anchor.kind.name == "CONDITIONAL_BRANCH"
        ),
        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
        dispatcher_region=set(int(block) for block in context.dispatcher_region),
    )
    branch_key = (
        (source_block, int(old_target))
        if nsucc == 2 and old_target is not None
        else None
    )
    decision = plan_dag_redirect_fallback(
        DagRedirectFallbackContext(
            source_block=source_block,
            target_entry=target_entry,
            source_handler_is_report_exit=(
                context.edge.source_key.handler_serial in context.report_exit_handlers
            ),
            ordered_path_head_is_report_exit=(
                bool(context.edge.ordered_path)
                and context.edge.ordered_path[0] in context.report_exit_handlers
            ),
            source_equals_target=(source_block == target_entry),
            backward_same_corridor=is_backward_same_corridor_target(
                ordered_path=tuple(int(node) for node in context.edge.ordered_path),
                source_block=source_block,
                target_entry=target_entry,
            ),
            allow_semantic_handoff=bool(allow_semantic_handoff),
            target_reaches_source=bool(target_reaches_source),
            source_blocked=(source_block in context.blocked_sources),
            source_terminal_protected=(source_block in context.terminal_protected_blocks),
            source_in_report_exit_owned=(source_block in context.report_exit_owned_blocks),
            source_in_terminal_source_owned_transition=(
                context.edge.kind.name == "TRANSITION"
                and source_block in context.terminal_source_owned_blocks
            ),
            ordered_path_ends_at_source=(
                not context.edge.ordered_path or source_block == context.edge.ordered_path[-1]
            ),
            emitted_already=(emit_key in state.emitted),
            nsucc=nsucc,
            old_target=(int(old_target) if old_target is not None else None),
            source_succs=tuple(
                int(succ) for succ in context.block_succ_map.get(source_block, ())
            ),
            edge_is_transition=(context.edge.kind.name == "TRANSITION"),
            live_oneway_noop=is_live_oneway_noop(
                source_succs=tuple(context.block_succ_map.get(source_block, ())),
                target_entry=target_entry,
            ),
            claimed_1way_target=state.claimed_1way.get(source_block),
            claimed_2way_target=(
                state.claimed_2way.get(branch_key)
                if branch_key is not None
                else None
            ),
        )
    )
    if not decision.accepted or decision.emission_plan is None:
        return DagRedirectExecutionResult(
            accepted=False,
            rejection_reason=decision.rejection_reason,
            source_block=source_block,
            target_entry=target_entry,
            old_target=(int(old_target) if old_target is not None else None),
            existing_target=(
                int(decision.emission_plan.existing_target)
                if decision.emission_plan is not None
                and decision.emission_plan.existing_target is not None
                else None
            ),
            allowed_semantic_handoff_backreach=(
                bool(allow_semantic_handoff) and bool(target_reaches_source)
            ),
        )

    apply_dag_redirect_emission_plan(
        decision.emission_plan,
        modifications=state.modifications,
        claimed_1way=state.claimed_1way,
        claimed_2way=state.claimed_2way,
        emitted=state.emitted,
        owned_blocks=state.owned_blocks,
        owned_edges=state.owned_edges,
        owned_transitions=state.owned_transitions,
        owned_transition=(
            (context.edge.source_key.state_const, context.edge.target_state & 0xFFFFFFFF)
            if context.edge.source_key.state_const is not None
            and context.edge.target_state is not None
            else None
        ),
    )
    return DagRedirectExecutionResult(
        accepted=True,
        source_block=source_block,
        target_entry=target_entry,
        old_target=(int(old_target) if old_target is not None else None),
        allowed_semantic_handoff_backreach=(
            bool(allow_semantic_handoff) and bool(target_reaches_source)
        ),
    )


def emit_dag_redirect(
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
    resolve_effective_target_entry,
    resolve_immediate_handoff_target,
    find_foreign_exact_entry_owner,
    is_semantic_handoff_redirect,
) -> tuple[bool, DagRedirectExecutionResult | None]:
    target_entry = resolve_effective_target_entry(
        dag,
        edge,
        bst_node_blocks=bst_node_blocks,
        state_var_stkoff=state_var_stkoff,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        mba=mba,
    )
    if target_entry is None:
        return False, None

    path_result = emit_path_tail_redirect(
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
        report_exit_handlers=report_exit_handlers,
        report_exit_owned_blocks=report_exit_owned_blocks,
        terminal_protected_blocks=terminal_protected_blocks,
        bst_node_blocks=bst_node_blocks,
        dispatcher_region=dispatcher_region,
        flow_graph=flow_graph,
        state_var_stkoff=state_var_stkoff,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        mba=mba,
        resolve_effective_target_entry=resolve_effective_target_entry,
        resolve_immediate_handoff_target=resolve_immediate_handoff_target,
        find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
        is_semantic_handoff_redirect=is_semantic_handoff_redirect,
    )
    if path_result.accepted:
        return True, None

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
    return bool(result.accepted), result


__all__ = [
    "emit_dag_redirect",
    "DagRedirectExecutionContext",
    "DagRedirectExecutionResult",
    "DagRedirectMutableState",
    "execute_dag_redirect_fallback",
]
