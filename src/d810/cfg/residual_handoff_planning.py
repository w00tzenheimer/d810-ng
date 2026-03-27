from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.lowering_selector import (
    ResidualBranchAnchorContext,
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
    ResidualPrefixPeelContext,
    plan_residual_branch_anchor_handoff,
    plan_residual_goto_handoff,
    plan_residual_pred_split,
    plan_residual_prefix_peel,
)


class ResidualHandoffMode:
    """Labels for residual dispatcher handoff selection."""

    PRED_SPLIT = "pred_split"
    GOTO = "goto"
    PREFIX = "prefix"
    BRANCH_ANCHOR = "branch_anchor"
    PREFIX_PEEL = "prefix_peel"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class ResidualPredSplitAttempt:
    """One candidate predecessor-owned residual handoff."""

    via_pred: int
    target_entry: int
    state_value: int
    context: ResidualPredSplitContext


@dataclass(frozen=True, slots=True)
class ResidualPredSplitSelection:
    """Accepted predecessor-owned residual handoff."""

    via_pred: int
    target_entry: int
    state_value: int


@dataclass(frozen=True, slots=True)
class ResidualGotoAttempt:
    """One direct residual goto handoff candidate."""

    target_entry: int
    state_value: int
    context: ResidualGotoHandoffContext


@dataclass(frozen=True, slots=True)
class ResidualPrefixAttempt:
    """One prefix fallback route candidate."""

    via_pred: int
    prefix_target: int
    claimed_branch_target: int | None = None
    owned_transition: tuple[int, int] | None = None
    edge_kind_name: str = ""
    branch_context: ResidualBranchAnchorContext | None = None
    peel_context: ResidualPrefixPeelContext | None = None


@dataclass(frozen=True, slots=True)
class ResidualHandoffPlanningContext:
    """Structured request for residual dispatcher handoff planning."""

    mode: str
    pred_split_attempts: tuple[ResidualPredSplitAttempt, ...] = ()
    goto_attempt: ResidualGotoAttempt | None = None
    prefix_attempts: tuple[ResidualPrefixAttempt, ...] = ()


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    """Structured result for residual dispatcher handoff selection."""

    accepted: bool
    kind: str
    pred_splits: tuple[ResidualPredSplitSelection, ...] = ()
    via_pred: int | None = None
    target_entry: int | None = None
    state_value: int | None = None
    branch_source: int | None = None
    old_target: int | None = None
    prefix_target: int | None = None
    claim_oneway_target: int | None = None
    owned_transition: tuple[int, int] | None = None
    edge_kind_name: str = ""
    already_claimed: bool = False
    rejection_reason: str = ""


def plan_residual_handoff(
    context: ResidualHandoffPlanningContext,
) -> SelectionDecision:
    """Select residual dispatcher handoffs using cfg-owned planning rules."""

    if context.mode == ResidualHandoffMode.PRED_SPLIT:
        accepted: list[ResidualPredSplitSelection] = []
        for attempt in context.pred_split_attempts:
            plan = plan_residual_pred_split(attempt.context)
            if not plan.accepted:
                continue
            accepted.append(
                ResidualPredSplitSelection(
                    via_pred=int(attempt.via_pred),
                    target_entry=int(attempt.target_entry),
                    state_value=int(attempt.state_value),
                )
            )
        if not accepted:
            return SelectionDecision(
                accepted=False,
                kind=ResidualHandoffMode.REJECTED,
                rejection_reason="no_pred_split_candidate",
            )
        return SelectionDecision(
            accepted=True,
            kind=ResidualHandoffMode.PRED_SPLIT,
            pred_splits=tuple(accepted),
        )

    if context.mode == ResidualHandoffMode.GOTO and context.goto_attempt is not None:
        goto_plan = plan_residual_goto_handoff(context.goto_attempt.context)
        if not goto_plan.accepted:
            return SelectionDecision(
                accepted=False,
                kind=ResidualHandoffMode.REJECTED,
                target_entry=int(context.goto_attempt.target_entry),
                state_value=int(context.goto_attempt.state_value),
                rejection_reason=goto_plan.rejection_reason,
            )
        return SelectionDecision(
            accepted=True,
            kind=ResidualHandoffMode.GOTO,
            target_entry=int(context.goto_attempt.target_entry),
            state_value=int(context.goto_attempt.state_value),
        )

    if context.mode == ResidualHandoffMode.PREFIX:
        for attempt in context.prefix_attempts:
            if attempt.branch_context is not None:
                branch_plan = plan_residual_branch_anchor_handoff(attempt.branch_context)
                if branch_plan.accepted:
                    if attempt.claimed_branch_target is not None:
                        if int(attempt.claimed_branch_target) != int(attempt.prefix_target):
                            continue
                        return SelectionDecision(
                            accepted=True,
                            kind=ResidualHandoffMode.BRANCH_ANCHOR,
                            via_pred=int(attempt.via_pred),
                            branch_source=int(branch_plan.branch_source),
                            old_target=int(branch_plan.old_target),
                            prefix_target=int(attempt.prefix_target),
                            owned_transition=attempt.owned_transition,
                            edge_kind_name=attempt.edge_kind_name,
                            already_claimed=True,
                        )
                    return SelectionDecision(
                        accepted=True,
                        kind=ResidualHandoffMode.BRANCH_ANCHOR,
                        via_pred=int(attempt.via_pred),
                        branch_source=int(branch_plan.branch_source),
                        old_target=int(branch_plan.old_target),
                        prefix_target=int(attempt.prefix_target),
                        owned_transition=attempt.owned_transition,
                        edge_kind_name=attempt.edge_kind_name,
                    )
            if attempt.peel_context is None:
                continue
            peel_plan = plan_residual_prefix_peel(attempt.peel_context)
            if peel_plan.accepted:
                return SelectionDecision(
                    accepted=True,
                    kind=ResidualHandoffMode.PREFIX_PEEL,
                    via_pred=int(attempt.via_pred),
                    prefix_target=int(attempt.prefix_target),
                    claim_oneway_target=(
                        int(peel_plan.claim_oneway_target)
                        if peel_plan.claim_oneway_target is not None
                        else None
                    ),
                    owned_transition=attempt.owned_transition,
                    edge_kind_name=attempt.edge_kind_name,
                )
            if peel_plan.stop_iteration:
                return SelectionDecision(
                    accepted=False,
                    kind=ResidualHandoffMode.REJECTED,
                    rejection_reason=peel_plan.rejection_reason,
                )
        return SelectionDecision(
            accepted=False,
            kind=ResidualHandoffMode.REJECTED,
            rejection_reason="no_prefix_candidate",
        )

    return SelectionDecision(
        accepted=False,
        kind=ResidualHandoffMode.REJECTED,
        rejection_reason="unsupported_handoff_mode",
    )


__all__ = [
    "ResidualGotoAttempt",
    "ResidualHandoffMode",
    "ResidualHandoffPlanningContext",
    "ResidualPrefixAttempt",
    "ResidualPredSplitAttempt",
    "ResidualPredSplitSelection",
    "SelectionDecision",
    "plan_residual_handoff",
]
