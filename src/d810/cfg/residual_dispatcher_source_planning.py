from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.cfg.residual_handoff_modification_planning import (
    plan_residual_goto_emission,
    plan_residual_pred_split_emissions,
    plan_residual_prefix_peel_emission,
)
from d810.cfg.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualHandoffMode,
    ResidualHandoffPlanningContext,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
    ResidualPredSplitSelection,
    SelectionDecision,
    plan_residual_handoff,
)


class ResidualDispatcherSourcePlanKind:
    PREFIX_BRANCH_ANCHOR = ResidualHandoffMode.BRANCH_ANCHOR
    PREFIX_PEEL = ResidualHandoffMode.PREFIX_PEEL
    PRED_SPLIT = ResidualHandoffMode.PRED_SPLIT
    GOTO = ResidualHandoffMode.GOTO
    REJECTED = ResidualHandoffMode.REJECTED


@dataclass(frozen=True, slots=True)
class ResidualDispatcherSourceContext:
    source_block: int
    dispatcher_serial: int
    prefix_before_attempts: tuple[ResidualPrefixAttempt, ...] = ()
    pred_split_attempts: tuple[ResidualPredSplitAttempt, ...] = ()
    goto_attempt: ResidualGotoAttempt | None = None
    prefix_after_attempts: tuple[ResidualPrefixAttempt, ...] = ()


@dataclass(frozen=True, slots=True)
class ResidualDispatcherSourcePlan:
    accepted: bool
    kind: str
    redirected_count: int = 0
    modifications: tuple[GraphModification, ...] = ()
    pred_splits: tuple[ResidualPredSplitSelection, ...] = ()
    emitted_edges: tuple[tuple[int, int], ...] = ()
    owned_blocks: tuple[int, ...] = ()
    owned_edges: tuple[tuple[int, int], ...] = ()
    owned_transitions: tuple[tuple[int, int], ...] = ()
    claimed_1way_updates: tuple[tuple[int, int], ...] = ()
    claimed_2way_updates: tuple[tuple[tuple[int, int], int], ...] = ()
    pred_split_keys: tuple[tuple[int, int, int], ...] = ()
    prefix_keys: tuple[tuple[int, int, int], ...] = ()
    redirect_blocks: tuple[int, ...] = ()
    via_pred: int | None = None
    target_entry: int | None = None
    state_value: int | None = None
    branch_source: int | None = None
    old_target: int | None = None
    prefix_target: int | None = None
    edge_kind_name: str = ""
    already_claimed: bool = False
    rejection_reason: str = ""


def _branch_anchor_modification(attempt: ResidualPrefixAttempt) -> GraphModification | None:
    branch_context = attempt.branch_context
    if branch_context is None:
        return None
    if len(tuple(int(succ) for succ in branch_context.branch_succs)) == 2:
        return RedirectBranch(
            from_serial=int(branch_context.branch_source),
            old_target=int(branch_context.old_target),
            new_target=int(branch_context.prefix_target),
        )
    return RedirectGoto(
        from_serial=int(branch_context.branch_source),
        old_target=int(branch_context.old_target),
        new_target=int(branch_context.prefix_target),
    )


def _match_prefix_attempt(
    attempts: tuple[ResidualPrefixAttempt, ...],
    decision: SelectionDecision,
) -> ResidualPrefixAttempt | None:
    for attempt in attempts:
        if int(attempt.via_pred) != int(decision.via_pred):
            continue
        if int(attempt.prefix_target) != int(decision.prefix_target):
            continue
        if decision.kind == ResidualHandoffMode.BRANCH_ANCHOR and attempt.branch_context is not None:
            return attempt
        if decision.kind == ResidualHandoffMode.PREFIX_PEEL and attempt.peel_context is not None:
            return attempt
    return None


def _plan_prefix_result(
    *,
    source_block: int,
    attempts: tuple[ResidualPrefixAttempt, ...],
    decision: SelectionDecision,
) -> ResidualDispatcherSourcePlan:
    attempt = _match_prefix_attempt(attempts, decision)
    if attempt is None:
        return ResidualDispatcherSourcePlan(
            accepted=False,
            kind=ResidualDispatcherSourcePlanKind.REJECTED,
            rejection_reason="missing_prefix_attempt",
        )

    if decision.kind == ResidualHandoffMode.BRANCH_ANCHOR:
        if decision.already_claimed:
            return ResidualDispatcherSourcePlan(
                accepted=True,
                kind=ResidualDispatcherSourcePlanKind.PREFIX_BRANCH_ANCHOR,
                redirected_count=1,
                via_pred=int(decision.via_pred),
                branch_source=int(decision.branch_source),
                old_target=int(decision.old_target),
                prefix_target=int(decision.prefix_target),
                edge_kind_name=decision.edge_kind_name,
                already_claimed=True,
            )
        modification = _branch_anchor_modification(attempt)
        if modification is None:
            return ResidualDispatcherSourcePlan(
                accepted=False,
                kind=ResidualDispatcherSourcePlanKind.REJECTED,
                rejection_reason="missing_branch_context",
            )
        branch_source = int(decision.branch_source)
        prefix_target = int(decision.prefix_target)
        return ResidualDispatcherSourcePlan(
            accepted=True,
            kind=ResidualDispatcherSourcePlanKind.PREFIX_BRANCH_ANCHOR,
            redirected_count=1,
            modifications=(modification,),
            emitted_edges=((branch_source, prefix_target),),
            owned_blocks=(branch_source,),
            owned_edges=((branch_source, prefix_target),),
            owned_transitions=(
                (attempt.owned_transition,) if attempt.owned_transition is not None else ()
            ),
            claimed_2way_updates=(
                (((branch_source, int(decision.old_target)), prefix_target),)
            ),
            via_pred=int(decision.via_pred),
            branch_source=branch_source,
            old_target=int(decision.old_target),
            prefix_target=prefix_target,
            edge_kind_name=decision.edge_kind_name,
        )

    peel_context = attempt.peel_context
    if peel_context is None:
        return ResidualDispatcherSourcePlan(
            accepted=False,
            kind=ResidualDispatcherSourcePlanKind.REJECTED,
            rejection_reason="missing_peel_context",
        )
    via_pred = int(decision.via_pred)
    prefix_target = int(decision.prefix_target)
    modification = plan_residual_prefix_peel_emission(
        via_pred=via_pred,
        prefix_target=prefix_target,
        old_target=int(source_block),
        via_pred_succs=tuple(int(succ) for succ in peel_context.peel_context.via_pred_succs),
    )
    return ResidualDispatcherSourcePlan(
        accepted=True,
        kind=ResidualDispatcherSourcePlanKind.PREFIX_PEEL,
        redirected_count=1,
        modifications=(modification,),
        emitted_edges=((via_pred, prefix_target),),
        owned_blocks=(via_pred,),
        owned_edges=((via_pred, prefix_target),),
        owned_transitions=(
            (attempt.owned_transition,) if attempt.owned_transition is not None else ()
        ),
        claimed_1way_updates=(
            ((via_pred, int(decision.claim_oneway_target)),)
            if decision.claim_oneway_target is not None
            else ()
        ),
        prefix_keys=((via_pred, int(source_block), prefix_target),),
        via_pred=via_pred,
        prefix_target=prefix_target,
        edge_kind_name=decision.edge_kind_name,
    )


def _plan_prefix_attempts(
    *,
    source_block: int,
    attempts: tuple[ResidualPrefixAttempt, ...],
) -> ResidualDispatcherSourcePlan:
    if not attempts:
        return ResidualDispatcherSourcePlan(
            accepted=False,
            kind=ResidualDispatcherSourcePlanKind.REJECTED,
            rejection_reason="no_prefix_candidate",
        )
    decision = plan_residual_handoff(
        ResidualHandoffPlanningContext(
            mode=ResidualHandoffMode.PREFIX,
            prefix_attempts=attempts,
        )
    )
    if not decision.accepted:
        return ResidualDispatcherSourcePlan(
            accepted=False,
            kind=ResidualDispatcherSourcePlanKind.REJECTED,
            rejection_reason=decision.rejection_reason,
        )
    return _plan_prefix_result(
        source_block=source_block,
        attempts=attempts,
        decision=decision,
    )


def _plan_pred_split_attempts(
    *,
    source_block: int,
    dispatcher_serial: int,
    attempts: tuple[ResidualPredSplitAttempt, ...],
) -> ResidualDispatcherSourcePlan:
    decision = plan_residual_handoff(
        ResidualHandoffPlanningContext(
            mode=ResidualHandoffMode.PRED_SPLIT,
            pred_split_attempts=attempts,
        )
    )
    if not decision.accepted:
        return ResidualDispatcherSourcePlan(
            accepted=False,
            kind=ResidualDispatcherSourcePlanKind.REJECTED,
            rejection_reason=decision.rejection_reason,
        )
    modifications = plan_residual_pred_split_emissions(
        source_block=int(source_block),
        dispatcher_serial=int(dispatcher_serial),
        pred_splits=tuple(
            (int(selection.via_pred), int(selection.target_entry))
            for selection in decision.pred_splits
        ),
    )
    return ResidualDispatcherSourcePlan(
        accepted=True,
        kind=ResidualDispatcherSourcePlanKind.PRED_SPLIT,
        redirected_count=len(decision.pred_splits),
        modifications=tuple(modifications),
        pred_splits=tuple(decision.pred_splits),
        emitted_edges=tuple(
            (int(source_block), int(selection.target_entry))
            for selection in decision.pred_splits
        ),
        owned_blocks=(int(source_block),),
        owned_edges=tuple(
            (int(source_block), int(selection.target_entry))
            for selection in decision.pred_splits
        ),
        pred_split_keys=tuple(
            (int(source_block), int(selection.via_pred), int(selection.target_entry))
            for selection in decision.pred_splits
        ),
    )


def _plan_goto_attempt(
    *,
    source_block: int,
    dispatcher_serial: int,
    attempt: ResidualGotoAttempt,
) -> ResidualDispatcherSourcePlan:
    decision = plan_residual_handoff(
        ResidualHandoffPlanningContext(
            mode=ResidualHandoffMode.GOTO,
            goto_attempt=attempt,
        )
    )
    if not decision.accepted:
        return ResidualDispatcherSourcePlan(
            accepted=False,
            kind=ResidualDispatcherSourcePlanKind.REJECTED,
            target_entry=int(attempt.target_entry),
            state_value=int(attempt.state_value),
            rejection_reason=decision.rejection_reason,
        )
    target_entry = int(decision.target_entry)
    return ResidualDispatcherSourcePlan(
        accepted=True,
        kind=ResidualDispatcherSourcePlanKind.GOTO,
        redirected_count=1,
        modifications=(
            plan_residual_goto_emission(
                source_block=int(source_block),
                dispatcher_serial=int(dispatcher_serial),
                target_entry=target_entry,
            ),
        ),
        emitted_edges=((int(source_block), target_entry),),
        owned_blocks=(int(source_block),),
        owned_edges=((int(source_block), target_entry),),
        claimed_1way_updates=((int(source_block), target_entry),),
        redirect_blocks=(int(source_block),),
        target_entry=target_entry,
        state_value=int(decision.state_value),
    )


def plan_residual_dispatcher_source(
    context: ResidualDispatcherSourceContext,
) -> ResidualDispatcherSourcePlan:
    """Plan one residual dispatcher source rewrite without touching live CFG state."""

    prefix_before = _plan_prefix_attempts(
        source_block=int(context.source_block),
        attempts=tuple(context.prefix_before_attempts),
    )
    if prefix_before.accepted:
        return prefix_before

    if context.goto_attempt is None:
        return _plan_pred_split_attempts(
            source_block=int(context.source_block),
            dispatcher_serial=int(context.dispatcher_serial),
            attempts=tuple(context.pred_split_attempts),
        )

    goto_plan = _plan_goto_attempt(
        source_block=int(context.source_block),
        dispatcher_serial=int(context.dispatcher_serial),
        attempt=context.goto_attempt,
    )
    if goto_plan.accepted:
        return goto_plan

    if goto_plan.rejection_reason in {
        "shared_suffix_conditional_tail",
        "prior_branch_cut",
        "cycle_risk",
        "live_oneway_noop",
        "invalid_target",
        "handoff_already_emitted",
    }:
        return goto_plan

    prefix_after = _plan_prefix_attempts(
        source_block=int(context.source_block),
        attempts=tuple(context.prefix_after_attempts),
    )
    if prefix_after.accepted:
        return prefix_after
    if prefix_after.rejection_reason:
        return prefix_after
    return goto_plan


def apply_residual_dispatcher_source_plan(
    source_plan: ResidualDispatcherSourcePlan,
    *,
    modifications: list[GraphModification],
    claimed_1way: dict[int, int],
    claimed_2way: dict[tuple[int, int], int],
    emitted: set[tuple[int, int]],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    pred_split_emitted: set[tuple[int, int, int]],
    prefix_emitted: set[tuple[int, int, int]],
    redirected_blocks: set[int] | None = None,
) -> None:
    modifications.extend(source_plan.modifications)
    for claim_source, claim_target in source_plan.claimed_1way_updates:
        claimed_1way[int(claim_source)] = int(claim_target)
    for claim_key, claim_target in source_plan.claimed_2way_updates:
        claimed_2way[(int(claim_key[0]), int(claim_key[1]))] = int(claim_target)
    for emitted_edge in source_plan.emitted_edges:
        emitted.add((int(emitted_edge[0]), int(emitted_edge[1])))
    for owned_block in source_plan.owned_blocks:
        owned_blocks.add(int(owned_block))
    for owned_edge in source_plan.owned_edges:
        owned_edges.add((int(owned_edge[0]), int(owned_edge[1])))
    for owned_transition in source_plan.owned_transitions:
        owned_transitions.add((int(owned_transition[0]), int(owned_transition[1])))
    for pred_split_key in source_plan.pred_split_keys:
        pred_split_emitted.add(
            (int(pred_split_key[0]), int(pred_split_key[1]), int(pred_split_key[2]))
        )
    for prefix_key in source_plan.prefix_keys:
        prefix_emitted.add(
            (int(prefix_key[0]), int(prefix_key[1]), int(prefix_key[2]))
        )
    if redirected_blocks is not None:
        for redirected_block in source_plan.redirect_blocks:
            redirected_blocks.add(int(redirected_block))


__all__ = [
    "apply_residual_dispatcher_source_plan",
    "ResidualDispatcherSourceContext",
    "ResidualDispatcherSourcePlan",
    "ResidualDispatcherSourcePlanKind",
    "plan_residual_dispatcher_source",
]
