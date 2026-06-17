from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.core.typing import Callable, Mapping

from d810.transforms.reconstruction_redirect_log import log_redirect_attempt
from d810.transforms.lowering_selector import (
    is_live_oneway_noop,
    is_valid_pred_split_pair,
    resolve_redirect_old_target,
    target_reaches_source_ignoring_blocks,
)
from d810.transforms.residual_dispatcher_attempt_building import (
    ResidualGotoAttemptBuildContext,
    ResidualPredSplitAttemptBuildContext,
    ResidualPrefixAttemptBuildContext,
    build_residual_goto_attempt,
    build_residual_pred_split_attempt,
    build_residual_prefix_attempt,
)
from d810.transforms.residual_dispatcher_source_planning import (
    ResidualDispatcherSourceContext,
    ResidualDispatcherSourcePlan,
    apply_residual_dispatcher_source_plan,
    plan_residual_dispatcher_source,
)
from d810.transforms.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
)
logger = logging.getLogger("D810.cfg.residual_dispatcher_handoff_execution", logging.DEBUG)

@dataclass(frozen=True, slots=True)
class ResidualDispatcherHandoffExecutionContext:
    dag: object
    state_machine: object | None
    projected_flow_graph: object
    dispatcher_serial: int
    condition_chain_blocks: frozenset[int]
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
    resolve_effective_target_entry: Callable[..., object] | None


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
    condition_chain_blocks: set[int],
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
    resolve_effective_target_entry: Callable[..., object] | None = None,
) -> ResidualDispatcherHandoffExecutionContext:
    residual_preds = collect_residual_dispatcher_predecessors(
        projected_flow_graph,
        int(dispatcher_serial),
        condition_chain_blocks=set(int(block) for block in condition_chain_blocks),
        reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
    )
    residual_mba_view = build_projected_mba(projected_flow_graph)
    analysis_mba = residual_mba_view if residual_mba_view is not None else mba
    return ResidualDispatcherHandoffExecutionContext(
        dag=dag,
        state_machine=state_machine,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=int(dispatcher_serial),
        condition_chain_blocks=frozenset(int(block) for block in condition_chain_blocks),
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
        resolve_effective_target_entry=resolve_effective_target_entry,
    )


def _iter_matching_handoff_edges(
    dag: object,
    *,
    source_block: int,
    state_value: int,
):
    raw_state_value = int(state_value) & 0xFFFFFFFF
    terminal_matches: list[object] = []
    source_matches: list[object] = []
    for edge in getattr(dag, "edges", ()) or ():
        target_state = getattr(edge, "target_state", None)
        if target_state is None or (int(target_state) & 0xFFFFFFFF) != raw_state_value:
            continue
        ordered_path = tuple(
            int(block_serial) for block_serial in (getattr(edge, "ordered_path", ()) or ())
        )
        if ordered_path and int(ordered_path[-1]) == int(source_block):
            terminal_matches.append(edge)
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        if source_anchor is not None and int(getattr(source_anchor, "block_serial", -1)) == int(source_block):
            source_matches.append(edge)
    return tuple(terminal_matches) + tuple(source_matches)


def _normalize_residual_handoff(
    context: ResidualDispatcherHandoffExecutionContext,
    *,
    source_block: int,
    handoff: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if (
        handoff is None
        or context.resolve_effective_target_entry is None
        or context.analysis_mba is None
    ):
        return handoff

    state_value, target_entry = handoff
    for edge in _iter_matching_handoff_edges(
        context.dag,
        source_block=int(source_block),
        state_value=int(state_value),
    ):
        resolution = context.resolve_effective_target_entry(
            context.dag,
            edge,
            condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
            state_var_stkoff=context.state_var_stkoff,
            dispatcher_lookup=context.dispatcher_lookup,
            dispatcher=context.dispatcher,
            mba=context.analysis_mba,
        )
        resolved_target_entry = getattr(resolution, "target_entry", None)
        if resolved_target_entry is None:
            continue
        normalized_target = int(resolved_target_entry)
        if normalized_target == int(source_block):
            continue
        if normalized_target != int(target_entry):
            logger.info(
                "normalized residual handoff %d: state=0x%08X target %d -> %d",
                int(source_block),
                int(state_value) & 0xFFFFFFFF,
                int(target_entry),
                normalized_target,
            )
        return (int(state_value), normalized_target)
    return handoff


def _is_shared_suffix_block(dag: object, source_block: int) -> bool:
    return any(
        int(source_block) in getattr(node, "shared_suffix_blocks", ())
        for node in getattr(dag, "nodes", ()) or ()
    )


def _is_exact_owner_entry(dag: object, block_serial: int) -> bool:
    for node in getattr(dag, "nodes", ()) or ():
        kind = getattr(getattr(node, "kind", None), "name", None)
        if kind != "EXACT":
            continue
        if int(getattr(node, "entry_anchor", -1)) == int(block_serial):
            return True
    return False


def _prefer_shared_suffix_family_source(
    context: ResidualDispatcherHandoffExecutionContext,
    *,
    source_block: int,
    current_preds: tuple[int, ...],
    handoff: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if handoff is None or len(current_preds) != 1:
        return handoff
    if not _is_shared_suffix_block(context.dag, int(source_block)):
        return handoff
    via_pred = int(current_preds[0])
    if not _is_exact_owner_entry(context.dag, via_pred):
        return handoff
    state_value, target_entry = handoff
    if int(target_entry) == via_pred:
        return handoff
    if not context.can_rewrite_shared_suffix_family_fallback(
        context.dag,
        source_block=int(source_block),
        target_entry=int(target_entry),
        current_preds=current_preds,
        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
        flow_graph=context.projected_flow_graph,
    ):
        return handoff
    logger.info(
        "residual shared-suffix family source %d: target %d -> exact family pred %d",
        int(source_block),
        int(target_entry),
        via_pred,
    )
    return (int(state_value), via_pred)


def execute_residual_dispatcher_handoffs(
    context: ResidualDispatcherHandoffExecutionContext,
    *,
    state: ResidualDispatcherHandoffMutableState,
) -> ResidualDispatcherHandoffExecutionResult:
    redirected = 0
    outcomes: list[ResidualDispatcherSourceOutcome] = []

    ignored_blocks = set(int(block) for block in context.condition_chain_blocks)
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
            condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
            dispatcher_lookup=context.dispatcher_lookup,
            dispatcher=context.dispatcher,
            analysis_mba=context.analysis_mba,
            live_mba=context.live_mba,
        )
        logger.info(
            "residual handoff facts %d: preds=%s state_write=%s assignment=%s projected_snapshot=%s "
            "immediate=%s synthesized=%s live_immediate=%s live_synthesized=%s successor=%s "
            "live_successor=%s projected_path=%s chosen=%s",
            int(source_block),
            tuple(int(pred) for pred in current_preds),
            bool(handoff_facts.source_has_state_write),
            handoff_facts.assignment_map_handoff,
            handoff_facts.projected_snapshot_handoff,
            handoff_facts.immediate_handoff,
            handoff_facts.synthesized_handoff,
            handoff_facts.live_immediate_handoff,
            handoff_facts.live_synthesized_handoff,
            handoff_facts.successor_handoff,
            handoff_facts.live_successor_handoff,
            handoff_facts.projected_path_handoff,
            handoff_facts.handoff,
        )
        effective_handoff = _normalize_residual_handoff(
            context,
            source_block=int(source_block),
            handoff=handoff_facts.handoff,
        )
        effective_handoff = _prefer_shared_suffix_family_source(
            context,
            source_block=int(source_block),
            current_preds=current_preds,
            handoff=effective_handoff,
        )

        prefix_before_attempts: list[ResidualPrefixAttempt] = []
        for edge, via_pred, prefix_target in context.iter_residual_prefix_handoffs(
            context.dag,
            source_block=int(source_block),
            condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                        condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
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

        if effective_handoff is None:
            for via_pred in current_preds:
                pred_handoff = None
                if handoff_facts.source_has_state_write:
                    pred_handoff = context.resolve_synthesized_handoff_target(
                        context.dag,
                        context.analysis_mba,
                        int(source_block),
                        state_var_stkoff=context.state_var_stkoff,
                        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                            condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
                            dispatcher=context.dispatcher,
                            via_pred=int(via_pred),
                        )
                if pred_handoff is None:
                    pred_handoff = context.resolve_projected_path_tail_target(
                        context.dag,
                        source_block=int(source_block),
                        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
                        dispatcher=context.dispatcher,
                        via_pred=int(via_pred),
                    )
                if pred_handoff is None:
                    pred_handoff = context.resolve_immediate_handoff_target(
                        context.dag,
                        context.analysis_mba,
                        int(via_pred),
                        state_var_stkoff=context.state_var_stkoff,
                        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                            condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
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
            state_value, target_entry = effective_handoff
            source_is_shared_suffix_tail = (
                context.is_shared_suffix_conditional_tail(
                    context.dag,
                    source_block=int(source_block),
                )
                or _is_shared_suffix_block(context.dag, int(source_block))
            )
            allow_family_fallback_tail = context.can_rewrite_shared_suffix_family_fallback(
                context.dag,
                source_block=int(source_block),
                target_entry=int(target_entry),
                current_preds=current_preds,
                condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
                flow_graph=context.projected_flow_graph,
            )
            if (
                source_is_shared_suffix_tail
                and len(current_preds) == 1
                and int(target_entry) != int(current_preds[0])
            ):
                allow_family_fallback_tail = False
            goto_attempt = build_residual_goto_attempt(
                ResidualGotoAttemptBuildContext(
                    target_entry=int(target_entry),
                    state_value=int(state_value),
                    source_block=int(source_block),
                    dispatcher_serial=int(context.dispatcher_serial),
                    condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
                    allow_family_fallback_tail=allow_family_fallback_tail,
                    is_shared_suffix_conditional_tail=source_is_shared_suffix_tail,
                    has_prior_branch_cut=context.has_prior_branch_cut_for_state(
                        context.dag,
                        source_block=int(source_block),
                        state_value=int(state_value),
                        condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                    condition_chain_blocks=set(int(block) for block in context.condition_chain_blocks),
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
                            condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
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
        logger.info(
            "residual handoff plan %d: accepted=%s kind=%s redirected=%d reason=%s pred_splits=%d goto=%s prefix_before=%d prefix_after=%d",
            int(source_block),
            bool(source_plan.accepted),
            source_plan.kind,
            int(source_plan.redirected_count),
            source_plan.rejection_reason,
            len(pred_split_attempts),
            None
            if goto_attempt is None
            else (int(goto_attempt.state_value), int(goto_attempt.target_entry)),
            len(prefix_before_attempts),
            len(prefix_after_attempts),
        )
        if not source_plan.accepted:
            logger.info(
                "residual handoff plan rejected %d: reason=%s pred_splits=%d goto=%s prefix_before=%d prefix_after=%d",
                int(source_block),
                source_plan.rejection_reason,
                len(pred_split_attempts),
                None
                if goto_attempt is None
                else (int(goto_attempt.state_value), int(goto_attempt.target_entry)),
                len(prefix_before_attempts),
                len(prefix_after_attempts),
            )
        if not source_plan.accepted:
            continue

        plan_target_entry = getattr(source_plan, "target_entry", None)
        plan_prefix_target = getattr(source_plan, "prefix_target", None)
        redirect_new_target = (
            int(plan_target_entry)
            if plan_target_entry is not None
            else (int(plan_prefix_target) if plan_prefix_target is not None else None)
        )
        redirect_old_target = getattr(source_plan, "old_target", None)
        if redirect_old_target is None:
            redirect_old_target = int(context.dispatcher_serial)
        if redirect_new_target is not None:
            log_redirect_attempt(
                phase="residual_handoff",
                src=int(source_block),
                old_target=int(redirect_old_target),
                new_target=int(redirect_new_target),
                dag=context.dag,
                state_const=getattr(source_plan, "state_value", None),
            )

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


def emit_residual_dispatcher_handoffs(
    *,
    dag: object,
    state_machine: object | None,
    projected_flow_graph: object,
    dispatcher_serial: int,
    condition_chain_blocks: set[int],
    builder: object,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int],
    claimed_2way: dict[tuple[int, int], int],
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None = None,
    mba: object | None = None,
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
    resolve_effective_target_entry=None,
) -> ResidualDispatcherHandoffExecutionResult:
    return execute_residual_dispatcher_handoffs(
        build_residual_dispatcher_handoff_execution_context(
            dag=dag,
            state_machine=state_machine,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=int(dispatcher_serial),
            condition_chain_blocks=condition_chain_blocks,
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
            resolve_effective_target_entry=resolve_effective_target_entry,
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


__all__ = [
    "build_residual_dispatcher_handoff_execution_context",
    "emit_residual_dispatcher_handoffs",
    "ResidualDispatcherHandoffExecutionContext",
    "ResidualDispatcherHandoffExecutionResult",
    "ResidualDispatcherHandoffMutableState",
    "ResidualDispatcherSourceOutcome",
    "execute_residual_dispatcher_handoffs",
]
