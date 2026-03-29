from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Mapping

from d810.cfg.lowering_selector import (
    is_backward_same_corridor_target,
    resolve_redirect_old_target,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.path_tail_modification_planning import (
    PathTailEmissionKind,
    PathTailRedirectContext,
    apply_path_tail_emission_plan,
    plan_path_tail_redirect,
)


@dataclass(frozen=True, slots=True)
class PathTailRedirectExecutionContext:
    edge: object
    dag: object
    target_entry: int | None
    flow_graph: object
    block_succ_map: Mapping[int, tuple[int, ...]]
    report_exit_handlers: frozenset[int]
    report_exit_owned_blocks: frozenset[int]
    terminal_protected_blocks: frozenset[int]
    bst_node_blocks: frozenset[int]
    dispatcher_region: frozenset[int]
    state_var_stkoff: int | None
    dispatcher_lookup: object | None
    dispatcher: object | None
    mba: object | None
    resolve_effective_target_entry: Callable[..., int | None]
    resolve_immediate_handoff_target: Callable[..., tuple[int, int] | None]
    find_foreign_exact_entry_owner: Callable[..., object | None]
    is_semantic_handoff_redirect: Callable[..., bool]


@dataclass(slots=True)
class PathTailRedirectMutableState:
    modifications: list
    owned_blocks: set[int]
    owned_edges: set[tuple[int, int]]
    owned_transitions: set[tuple[int, int]]
    emitted: set[tuple[int, int]]
    claimed_1way: dict[int, int] | None
    claimed_exits: dict[int, int]
    claimed_path_edges: dict[tuple[int, int], int]
    blocked_sources: set[int]


@dataclass(frozen=True, slots=True)
class PathTailRedirectExecutionResult:
    accepted: bool
    kind: str | None = None
    rejection_reason: str = ""
    source_block: int | None = None
    target_entry: int | None = None
    via_pred: int | None = None
    foreign_exact_owner_label: str | None = None
    source_state_const: int | None = None
    shared_handoff: tuple[int, int] | None = None


def execute_path_tail_redirect(
    context: PathTailRedirectExecutionContext,
    *,
    state: PathTailRedirectMutableState,
) -> PathTailRedirectExecutionResult:
    target_entry = context.target_entry
    if target_entry is None:
        target_entry = context.resolve_effective_target_entry(
            context.dag,
            context.edge,
            bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
            state_var_stkoff=context.state_var_stkoff,
            dispatcher_lookup=context.dispatcher_lookup,
            dispatcher=context.dispatcher,
            mba=context.mba,
        )
    if target_entry is None:
        return PathTailRedirectExecutionResult(
            accepted=False,
            rejection_reason="missing_target_entry",
        )

    claimed_1way = state.claimed_1way
    if claimed_1way is None:
        claimed_1way = {}
    if not context.edge.ordered_path or context.edge.target_entry_anchor is None:
        return PathTailRedirectExecutionResult(
            accepted=False,
            rejection_reason="missing_ordered_path_or_anchor",
        )

    source_block = int(context.edge.ordered_path[-1])
    foreign_exact_owner = context.find_foreign_exact_entry_owner(
        context.dag,
        source_key=context.edge.source_key,
        source_block=source_block,
    )
    backward_same_corridor = is_backward_same_corridor_target(
        ordered_path=tuple(int(node) for node in context.edge.ordered_path),
        source_block=source_block,
        target_entry=int(target_entry),
    )
    allow_semantic_handoff = context.is_semantic_handoff_redirect(
        context.dag,
        context.edge,
        source_block=source_block,
        target_entry=int(target_entry),
        state_var_stkoff=context.state_var_stkoff,
        dispatcher_lookup=context.dispatcher_lookup,
        dispatcher=context.dispatcher,
        mba=context.mba,
    )
    target_reaches_source = target_reaches_source_ignoring_blocks(
        context.flow_graph,
        target_entry=int(target_entry),
        source_block=source_block,
        ignored_blocks=set(context.dispatcher_region) | set(context.bst_node_blocks),
    )

    source_snapshot = context.flow_graph.get_block(source_block)
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

    emit_key = (source_block, int(target_entry))
    npreds = len(tuple(source_snapshot.preds)) if source_snapshot is not None else 0
    shared_handoff = None
    if npreds > 1:
        shared_handoff = context.resolve_immediate_handoff_target(
            context.dag,
            context.mba,
            source_block,
            state_var_stkoff=context.state_var_stkoff,
            bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
            dispatcher_lookup=context.dispatcher_lookup,
            dispatcher=context.dispatcher,
        )
    via_pred = context.edge.ordered_path[-2] if len(context.edge.ordered_path) >= 2 else None
    other_preds = tuple(
        pred for pred in tuple(getattr(source_snapshot, "preds", ()))
        if pred != via_pred
    )
    decision = plan_path_tail_redirect(
        PathTailRedirectContext(
            source_block=source_block,
            target_entry=int(target_entry),
            source_handler_is_report_exit=(
                context.edge.source_key.handler_serial in context.report_exit_handlers
            ),
            ordered_path_head_is_report_exit=(
                bool(context.edge.ordered_path)
                and context.edge.ordered_path[0] in context.report_exit_handlers
            ),
            source_in_report_exit_owned=(source_block in context.report_exit_owned_blocks),
            source_blocked=(source_block in state.blocked_sources),
            source_terminal_protected=(source_block in context.terminal_protected_blocks),
            foreign_exact_owner_label=(
                foreign_exact_owner.state_label
                if foreign_exact_owner is not None
                else None
            ),
            backward_same_corridor=bool(backward_same_corridor),
            allow_semantic_handoff=bool(allow_semantic_handoff),
            target_reaches_source=bool(target_reaches_source),
            source_nsucc=(
                int(source_snapshot.nsucc)
                if source_snapshot is not None
                else None
            ),
            source_npred=(int(npreds) if source_snapshot is not None else None),
            source_succs=tuple(int(succ) for succ in getattr(source_snapshot, "succs", ())),
            source_preds=tuple(int(pred) for pred in getattr(source_snapshot, "preds", ())),
            old_target=(int(old_target) if old_target is not None else None),
            emitted_already=(emit_key in state.emitted),
            shared_handoff_target=(
                int(shared_handoff[1]) if shared_handoff is not None else None
            ),
            via_pred=(int(via_pred) if via_pred is not None else None),
            via_pred_succs=tuple(
                int(succ) for succ in context.block_succ_map.get(via_pred, ())
            ),
            existing_exit_target=state.claimed_exits.get(source_block),
            existing_1way_target=claimed_1way.get(source_block),
            existing_path_edge_target=(
                state.claimed_path_edges.get((source_block, via_pred))
                if via_pred is not None
                else None
            ),
            via_pred_blocked=(via_pred in state.blocked_sources if via_pred is not None else False),
            via_pred_terminal_protected=(
                via_pred in context.terminal_protected_blocks if via_pred is not None else False
            ),
            source_is_conditional_branch=(
                context.edge.source_anchor.kind.name == "CONDITIONAL_BRANCH"
            ),
            source_anchor_block=int(context.edge.source_anchor.block_serial),
            source_branch_arm=(
                int(context.edge.source_anchor.branch_arm)
                if context.edge.source_anchor.branch_arm is not None
                else None
            ),
            other_preds=tuple(int(pred) for pred in other_preds),
        )
    )
    if not decision.accepted or decision.emission_plan is None:
        return PathTailRedirectExecutionResult(
            accepted=False,
            rejection_reason=decision.rejection_reason,
            source_block=source_block,
            target_entry=int(target_entry),
            via_pred=(int(via_pred) if via_pred is not None else None),
            foreign_exact_owner_label=(
                foreign_exact_owner.state_label
                if foreign_exact_owner is not None
                else None
            ),
            source_state_const=(
                int(context.edge.source_key.state_const)
                if context.edge.source_key.state_const is not None
                else None
            ),
            shared_handoff=(
                (int(shared_handoff[0]), int(shared_handoff[1]))
                if shared_handoff is not None
                else None
            ),
        )

    apply_path_tail_emission_plan(
        decision.emission_plan,
        modifications=state.modifications,
        owned_blocks=state.owned_blocks,
        owned_edges=state.owned_edges,
        owned_transitions=state.owned_transitions,
        emitted=state.emitted,
        claimed_1way=claimed_1way,
        claimed_exits=state.claimed_exits,
        claimed_path_edges=state.claimed_path_edges,
        blocked_sources=state.blocked_sources,
        owned_transition=(
            (context.edge.source_key.state_const, context.edge.target_state & 0xFFFFFFFF)
            if context.edge.source_key.state_const is not None
            and context.edge.target_state is not None
            else None
        ),
    )
    state.claimed_1way = claimed_1way
    return PathTailRedirectExecutionResult(
        accepted=True,
        kind=decision.emission_plan.kind,
        source_block=source_block,
        target_entry=int(target_entry),
        via_pred=(int(via_pred) if via_pred is not None else None),
    )


__all__ = [
    "PathTailRedirectExecutionContext",
    "PathTailRedirectExecutionResult",
    "PathTailRedirectMutableState",
    "execute_path_tail_redirect",
    "PathTailEmissionKind",
]
