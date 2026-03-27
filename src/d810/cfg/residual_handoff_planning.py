from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.lowering_selector import (
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
    plan_residual_goto_handoff,
    plan_residual_pred_split,
)


class ResidualHandoffMode:
    """Labels for residual dispatcher handoff selection."""

    PRED_SPLIT = "pred_split"
    GOTO = "goto"
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
class ResidualHandoffPlanningContext:
    """Structured request for residual dispatcher handoff planning."""

    mode: str
    pred_split_attempts: tuple[ResidualPredSplitAttempt, ...] = ()
    goto_attempt: ResidualGotoAttempt | None = None


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    """Structured result for residual dispatcher handoff selection."""

    accepted: bool
    kind: str
    pred_splits: tuple[ResidualPredSplitSelection, ...] = ()
    target_entry: int | None = None
    state_value: int | None = None
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

    return SelectionDecision(
        accepted=False,
        kind=ResidualHandoffMode.REJECTED,
        rejection_reason="unsupported_handoff_mode",
    )


__all__ = [
    "ResidualGotoAttempt",
    "ResidualHandoffMode",
    "ResidualHandoffPlanningContext",
    "ResidualPredSplitAttempt",
    "ResidualPredSplitSelection",
    "SelectionDecision",
    "plan_residual_handoff",
]
