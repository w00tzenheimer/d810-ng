from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Mapping

from d810.cfg.lowering_selector import (
    is_live_oneway_noop,
    is_valid_pred_split_pair,
    resolve_redirect_old_target,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.residual_dispatcher_attempt_building import (
    ResidualGotoAttemptBuildContext,
    ResidualPredSplitAttemptBuildContext,
    ResidualPrefixAttemptBuildContext,
    build_residual_goto_attempt,
    build_residual_pred_split_attempt,
    build_residual_prefix_attempt,
)
from d810.cfg.residual_dispatcher_source_planning import (
    ResidualDispatcherSourceContext,
    ResidualDispatcherSourcePlan,
    apply_residual_dispatcher_source_plan,
    plan_residual_dispatcher_source,
)
from d810.cfg.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
)

@dataclass(frozen=True, slots=True)
class ResidualDispatcherHandoffExecutionContext:
    dag: object
    state_machine: object | None
    projected_flow_graph: object
    dispatcher_serial: int
    bst_node_blocks: frozenset[int]
    residual_preds: tuple[int, ...]
    block_succ_map: Mapping[int, tuple[int, ...]]
    state_var_stkoff: int | None
    dispatcher_lookup: object | None
    dispatcher: object | None
    analysis_mba: object | None
    live_mba: object | None
    collect_residual_source_handoff_facts: Callable[..., object]
    iter_residual_prefix_handoffs: Callable[..., tuple]
    can_rewrite_shared_suffix_family_fallback: Callable[..., bool]
    has_prior_branch_cut_for_state: Callable[..., bool]
    is_shared_suffix_conditional_tail: Callable[..., bool]
    pred_split_target_reaches_via_pred: Callable[..., bool]
    resolve_synthesized_handoff_target: Callable[..., tuple[int, int] | None]
    resolve_projected_path_tail_target: Callable[..., tuple[int, int] | None]
    resolve_immediate_handoff_target: Callable[..., tuple[int, int] | None]


@dataclass(slots=True)
class ResidualDispatcherHandoffMutableState:
    modifications: list
    owned_blocks: set[int]
    owned_edges: set[tuple[int, int]]
    owned_transitions: set[tuple[int, int]]
    emitted: set[tuple[int, int]]
    claimed_1way: dict[int, int]
    claimed_2way: dict[tuple[int, int], int]
    redirected_blocks: set[int] | None = None


@dataclass(frozen=True, slots=True)
class ResidualDispatcherSourceOutcome:
    source_block: int
    source_plan: ResidualDispatcherSourcePlan


@dataclass(frozen=True, slots=True)
class ResidualDispatcherHandoffExecutionResult:
    redirected_count: int
    outcomes: tuple[ResidualDispatcherSourceOutcome, ...]


def build_residual_dispatcher_handoff_execution_context(
    *,
    dag: object,
    state_machine: object | None,
    projected_flow_graph: object,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    block_succ_map: Mapping[int, tuple[int, ...]],
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object | None,
    collect_residual_dispatcher_predecessors: Callable[..., tuple[int, ...]],
    build_projected_mba: Callable[[object], object | None],
    collect_residual_source_handoff_facts: Callable[..., object],
    iter_residual_prefix_handoffs: Callable[..., tuple],
    can_rewrite_shared_suffix_family_fallback: Callable[..., bool],
    has_prior_branch_cut_for_state: Callable[..., bool],
    is_shared_suffix_conditional_tail: Callable[..., bool],
    pred_split_target_reaches_via_pred: Callable[..., bool],
    resolve_synthesized_handoff_target: Callable[..., tuple[int, int] | None],
    resolve_projected_path_tail_target: Callable[..., tuple[int, int] | None],
    resolve_immediate_handoff_target: Callable[..., tuple[int, int] | None],
) -> ResidualDispatcherHandoffExecutionContext:
    residual_preds = collect_residual_dispatcher_predecessors(
        projected_flow_graph,
        int(dispatcher_serial),
        bst_node_blocks=set(int(block) for block in bst_node_blocks),
        reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
    )
    residual_mba_view = build_projected_mba(projected_flow_graph)
    analysis_mba = residual_mba_view if residual_mba_view is not None else mba
    return ResidualDispatcherHandoffExecutionContext(
        dag=dag,
        state_machine=state_machine,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=int(dispatcher_serial),
        bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
        residual_preds=tuple(int(pred) for pred in residual_preds),
        block_succ_map={
            int(block): tuple(int(succ) for succ in succs)
            for block, succs in block_succ_map.items()
        },
        state_var_stkoff=state_var_stkoff,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        analysis_mba=analysis_mba,
        live_mba=(mba if mba is not None else None),
        collect_residual_source_handoff_facts=collect_residual_source_handoff_facts,
        iter_residual_prefix_handoffs=iter_residual_prefix_handoffs,
        can_rewrite_shared_suffix_family_fallback=can_rewrite_shared_suffix_family_fallback,
        has_prior_branch_cut_for_state=has_prior_branch_cut_for_state,
        is_shared_suffix_conditional_tail=is_shared_suffix_conditional_tail,
        pred_split_target_reaches_via_pred=pred_split_target_reaches_via_pred,
        resolve_synthesized_handoff_target=resolve_synthesized_handoff_target,
        resolve_projected_path_tail_target=resolve_projected_path_tail_target,
        resolve_immediate_handoff_target=resolve_immediate_handoff_target,
    )


def execute_residual_dispatcher_handoffs(
    context: ResidualDispatcherHandoffExecutionContext,
    *,
    state: ResidualDispatcherHandoffMutableState,
) -> ResidualDispatcherHandoffExecutionResult:
    redirected = 0
    outcomes: list[ResidualDispatcherSourceOutcome] = []

    ignored_blocks = set(int(block) for block in context.bst_node_blocks)
    ignored_blocks.add(int(context.dispatcher_serial))
    residual_ignored_blocks = ignored_blocks | set(int(pred) for pred in context.residual_preds)
    pred_split_emitted: set[tuple[int, int, int]] = set()
    prefix_emitted: set[tuple[int, int, int]] = set()

    for source_block in context.residual_preds:
        block = context.projected_flow_graph.get_block(int(source_block))
        if block is None:
            continue
        succs = tuple(getattr(block, "succs", ()))
        if succs != (int(context.dispatcher_serial),):
            continue
        if int(source_block) in state.claimed_1way:
            continue

        current_preds = tuple(int(pred) for pred in getattr(block, "preds", ()))
        handoff_facts = context.collect_residual_source_handoff_facts(
            context.dag,
            state_machine=context.state_machine,
            projected_flow_graph=context.projected_flow_graph,
            source_block=int(source_block),
            current_preds=current_preds,
            state_var_stkoff=context.state_var_stkoff,
            bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
            dispatcher_lookup=context.dispatcher_lookup,
            dispatcher=context.dispatcher,
            analysis_mba=context.analysis_mba,
            live_mba=context.live_mba,
        )

        prefix_before_attempts: list[ResidualPrefixAttempt] = []
        for edge, via_pred, prefix_target in context.iter_residual_prefix_handoffs(
            context.dag,
            source_block=int(source_block),
            bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
            dispatcher=context.dispatcher,
        ):
            source_anchor = edge.source_anchor
            branch_source = source_anchor.block_serial
            branch_block = context.projected_flow_graph.get_block(branch_source)
            if branch_block is None:
                continue
            branch_succs = tuple(
                int(succ) for succ in tuple(getattr(branch_block, "succs", ()))
            )
            old_target = resolve_redirect_old_target(
                int(branch_source),
                source_succs=tuple(context.block_succ_map.get(int(branch_source), ())),
                ordered_path=tuple(int(node) for node in edge.ordered_path),
                target_entry_anchor=(
                    int(edge.target_entry_anchor)
                    if edge.target_entry_anchor is not None
                    else None
                ),
                source_branch_arm=(
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                source_is_conditional_branch=(
                    edge.source_anchor.kind.name == "CONDITIONAL_BRANCH"
                ),
                bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                dispatcher_region=ignored_blocks,
            )
            prefix_before_attempts.append(
                build_residual_prefix_attempt(
                    ResidualPrefixAttemptBuildContext(
                        via_pred=int(via_pred),
                        prefix_target=int(prefix_target),
                        claimed_branch_target=state.claimed_2way.get(
                            (int(branch_source), int(old_target))
                        ),
                        owned_transition=(
                            (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                            if edge.source_key.state_const is not None
                            and edge.target_state is not None
                            else None
                        ),
                        edge_kind_name=edge.kind.name.lower(),
                        is_conditional_branch_source=(
                            source_anchor.kind.name == "CONDITIONAL_BRANCH"
                        ),
                        branch_source=int(branch_source),
                        source_block=int(source_block),
                        branch_succs=branch_succs,
                        old_target=int(old_target),
                        ordered_path=tuple(int(node) for node in edge.ordered_path),
                        dispatcher_serial=int(context.dispatcher_serial),
                        bst_node_blocks=frozenset(int(block) for block in context.bst_node_blocks),
                        target_reaches_branch=target_reaches_source_ignoring_blocks(
                            context.projected_flow_graph,
                            target_entry=int(prefix_target),
                            source_block=int(branch_source),
                            ignored_blocks=(residual_ignored_blocks | {int(source_block), int(via_pred)}),
                        ),
                    )
                )
            )

        pred_split_attempts: list[ResidualPredSplitAttempt] = []
        goto_attempt: ResidualGotoAttempt | None = None
        prefix_after_attempts: list[ResidualPrefixAttempt] = []

        if handoff_facts.handoff is None:
            for via_pred in current_preds:
                pred_handoff = None
                if handoff_facts.source_has_state_write:
                    pred_handoff = context.resolve_synthesized_handoff_target(
                        context.dag,
                        context.analysis_mba,
                        int(source_block),
                        state_var_stkoff=context.state_var_stkoff,
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        dispatcher=context.dispatcher,
                        via_pred=int(via_pred),
                    )
                    if (
                        pred_handoff is None
                        and context.live_mba is not None
                        and context.analysis_mba is not context.live_mba
                    ):
                        pred_handoff = context.resolve_synthesized_handoff_target(
                            context.dag,
                            context.live_mba,
                            int(source_block),
                            state_var_stkoff=context.state_var_stkoff,
                            bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                            dispatcher=context.dispatcher,
                            via_pred=int(via_pred),
                        )
                if pred_handoff is None:
                    pred_handoff = context.resolve_projected_path_tail_target(
                        context.dag,
                        source_block=int(source_block),
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        dispatcher=context.dispatcher,
                        predecessor_hints=(int(via_pred),),
                        require_predecessor_match=True,
                    )
                if pred_handoff is None:
                    pred_handoff = context.resolve_synthesized_handoff_target(
                        context.dag,
                        context.analysis_mba,
                        int(source_block),
                        state_var_stkoff=context.state_var_stkoff,
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        dispatcher=context.dispatcher,
                        via_pred=int(via_pred),
                    )
                if (
                    pred_handoff is None
                    and context.live_mba is not None
                    and context.analysis_mba is not context.live_mba
                ):
                    pred_handoff = context.resolve_synthesized_handoff_target(
                        context.dag,
                        context.live_mba,
                        int(source_block),
                        state_var_stkoff=context.state_var_stkoff,
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        dispatcher=context.dispatcher,
                        via_pred=int(via_pred),
                    )
                if pred_handoff is None:
                    pred_handoff = context.resolve_immediate_handoff_target(
                        context.dag,
                        context.analysis_mba,
                        int(via_pred),
                        state_var_stkoff=context.state_var_stkoff,
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        dispatcher_lookup=(
                            getattr(context.dispatcher, "lookup", None)
                            if context.dispatcher is not None
                            else context.dispatcher_lookup
                        ),
                        dispatcher=context.dispatcher,
                    )
                if pred_handoff is None:
                    continue
                state_value, target_entry = pred_handoff
                emit_key = (int(source_block), int(via_pred), int(target_entry))
                pred_split_attempts.append(
                    build_residual_pred_split_attempt(
                        ResidualPredSplitAttemptBuildContext(
                            via_pred=int(via_pred),
                            target_entry=int(target_entry),
                            state_value=int(state_value),
                            source_block=int(source_block),
                            dispatcher_serial=int(context.dispatcher_serial),
                            bst_node_blocks=frozenset(int(block) for block in context.bst_node_blocks),
                            valid_pair=is_valid_pred_split_pair(
                                int(source_block),
                                via_pred=int(via_pred),
                                source_succs=tuple(context.block_succ_map.get(int(source_block), ())),
                                via_pred_succs=tuple(context.block_succ_map.get(int(via_pred), ())),
                            ),
                            target_reaches_via_pred=context.pred_split_target_reaches_via_pred(
                                context.projected_flow_graph,
                                target_entry=int(target_entry),
                                via_pred=int(via_pred),
                                source_block=int(source_block),
                                ignored_blocks=residual_ignored_blocks,
                            ),
                            already_emitted=emit_key in pred_split_emitted,
                        )
                    )
                )
        else:
            state_value, target_entry = handoff_facts.handoff
            goto_attempt = build_residual_goto_attempt(
                ResidualGotoAttemptBuildContext(
                    target_entry=int(target_entry),
                    state_value=int(state_value),
                    source_block=int(source_block),
                    dispatcher_serial=int(context.dispatcher_serial),
                    bst_node_blocks=frozenset(int(block) for block in context.bst_node_blocks),
                    allow_family_fallback_tail=context.can_rewrite_shared_suffix_family_fallback(
                        context.dag,
                        source_block=int(source_block),
                        target_entry=int(target_entry),
                        current_preds=current_preds,
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        flow_graph=context.projected_flow_graph,
                    ),
                    is_shared_suffix_conditional_tail=context.is_shared_suffix_conditional_tail(
                        context.dag,
                        source_block=int(source_block),
                    ),
                    has_prior_branch_cut=context.has_prior_branch_cut_for_state(
                        context.dag,
                        source_block=int(source_block),
                        state_value=int(state_value),
                        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                        dispatcher=context.dispatcher,
                    ),
                    target_reaches_source=target_reaches_source_ignoring_blocks(
                        context.projected_flow_graph,
                        target_entry=int(target_entry),
                        source_block=int(source_block),
                        ignored_blocks=residual_ignored_blocks,
                    ),
                    already_emitted=(int(source_block), int(target_entry)) in state.emitted,
                    live_oneway_noop=is_live_oneway_noop(
                        source_succs=tuple(context.block_succ_map.get(int(source_block), ())),
                        target_entry=int(target_entry),
                    ),
                )
            )

            for edge, via_pred, prefix_target in context.iter_residual_prefix_handoffs(
                context.dag,
                source_block=int(source_block),
                bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                dispatcher=context.dispatcher,
            ):
                pred_block = context.projected_flow_graph.get_block(int(via_pred))
                if pred_block is None:
                    continue
                pred_succs = tuple(getattr(pred_block, "succs", ()))
                prefix_key = (int(via_pred), int(source_block), int(prefix_target))
                source_anchor = edge.source_anchor
                branch_source = source_anchor.block_serial
                branch_block = context.projected_flow_graph.get_block(branch_source)
                branch_succs = (
                    tuple(int(succ) for succ in tuple(getattr(branch_block, "succs", ())))
                    if branch_block is not None
                    else ()
                )
                old_target = resolve_redirect_old_target(
                    int(branch_source),
                    source_succs=tuple(context.block_succ_map.get(int(branch_source), ())),
                    ordered_path=tuple(int(node) for node in edge.ordered_path),
                    target_entry_anchor=(
                        int(edge.target_entry_anchor)
                        if edge.target_entry_anchor is not None
                        else None
                    ),
                    source_branch_arm=(
                        int(edge.source_anchor.branch_arm)
                        if edge.source_anchor.branch_arm is not None
                        else None
                    ),
                    source_is_conditional_branch=(
                        edge.source_anchor.kind.name == "CONDITIONAL_BRANCH"
                    ),
                    bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
                    dispatcher_region=ignored_blocks,
                )
                prefix_after_attempts.append(
                    build_residual_prefix_attempt(
                        ResidualPrefixAttemptBuildContext(
                            via_pred=int(via_pred),
                            prefix_target=int(prefix_target),
                            claimed_branch_target=state.claimed_2way.get(
                                (int(branch_source), int(old_target))
                            ),
                            owned_transition=(
                                (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                                if edge.source_key.state_const is not None
                                and edge.target_state is not None
                                else None
                            ),
                            edge_kind_name=edge.kind.name.lower(),
                            is_conditional_branch_source=(
                                source_anchor.kind.name == "CONDITIONAL_BRANCH"
                            ),
                            branch_source=(
                                int(branch_source) if branch_block is not None else None
                            ),
                            source_block=int(source_block),
                            branch_succs=branch_succs,
                            old_target=int(old_target),
                            ordered_path=tuple(int(node) for node in edge.ordered_path),
                            dispatcher_serial=int(context.dispatcher_serial),
                            bst_node_blocks=frozenset(int(block) for block in context.bst_node_blocks),
                            target_reaches_branch=(
                                target_reaches_source_ignoring_blocks(
                                    context.projected_flow_graph,
                                    target_entry=int(prefix_target),
                                    source_block=int(branch_source),
                                    ignored_blocks=(
                                        residual_ignored_blocks | {int(source_block), int(via_pred)}
                                    ),
                                )
                                if branch_block is not None
                                else False
                            ),
                            via_pred_succs=tuple(int(succ) for succ in pred_succs),
                            target_reaches_pred=target_reaches_source_ignoring_blocks(
                                context.projected_flow_graph,
                                target_entry=int(prefix_target),
                                source_block=int(via_pred),
                                ignored_blocks=residual_ignored_blocks | {int(source_block)},
                            ),
                            already_emitted=prefix_key in prefix_emitted,
                            existing_target=state.claimed_1way.get(int(via_pred)),
                            via_pred_succ_count=len(pred_succs),
                        )
                    )
                )

        source_plan = plan_residual_dispatcher_source(
            ResidualDispatcherSourceContext(
                source_block=int(source_block),
                dispatcher_serial=int(context.dispatcher_serial),
                prefix_before_attempts=tuple(prefix_before_attempts),
                pred_split_attempts=tuple(pred_split_attempts),
                goto_attempt=goto_attempt,
                prefix_after_attempts=tuple(prefix_after_attempts),
            )
        )
        outcomes.append(
            ResidualDispatcherSourceOutcome(
                source_block=int(source_block),
                source_plan=source_plan,
            )
        )
        if not source_plan.accepted:
            continue

        apply_residual_dispatcher_source_plan(
            source_plan,
            modifications=state.modifications,
            claimed_1way=state.claimed_1way,
            claimed_2way=state.claimed_2way,
            emitted=state.emitted,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            owned_transitions=state.owned_transitions,
            pred_split_emitted=pred_split_emitted,
            prefix_emitted=prefix_emitted,
            redirected_blocks=state.redirected_blocks,
        )
        redirected += int(source_plan.redirected_count)

    return ResidualDispatcherHandoffExecutionResult(
        redirected_count=int(redirected),
        outcomes=tuple(outcomes),
    )


__all__ = [
    "build_residual_dispatcher_handoff_execution_context",
    "ResidualDispatcherHandoffExecutionContext",
    "ResidualDispatcherHandoffExecutionResult",
    "ResidualDispatcherHandoffMutableState",
    "ResidualDispatcherSourceOutcome",
    "execute_residual_dispatcher_handoffs",
]
