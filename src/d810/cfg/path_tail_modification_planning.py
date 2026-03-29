from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import (
    DuplicateAndRedirect,
    EdgeRedirectViaPredSplit,
    GraphModification,
    RedirectGoto,
)
from d810.cfg.lowering_selector import can_duplicate_path_tail, is_valid_pred_split_pair


class PathTailEmissionKind:
    SHARED_GOTO = "shared_goto"
    DIRECT_GOTO = "direct_goto"
    PRED_SPLIT = "pred_split"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class PathTailEmissionPlan:
    accepted: bool
    kind: str = ""
    modification: GraphModification | None = None
    block_source: int | None = None
    target_entry: int | None = None
    via_pred: int | None = None
    blocked_pred: int | None = None
    path_edge_key: tuple[int, int] | None = None
    rejection_reason: str = ""


def plan_path_tail_emission(
    *,
    source_block: int,
    target_entry: int,
    old_target: int,
    npreds: int,
    shared_handoff_target: int | None,
    existing_exit_target: int | None,
    existing_1way_target: int | None,
    via_pred: int | None,
    existing_path_edge_target: int | None,
    via_pred_blocked: bool,
    via_pred_terminal_protected: bool,
    source_succs: tuple[int, ...],
    via_pred_succs: tuple[int, ...],
    source_is_conditional_branch: bool,
    source_anchor_block: int,
    source_branch_arm: int | None,
    other_preds: tuple[int, ...],
) -> PathTailEmissionPlan:
    if npreds > 1 and shared_handoff_target is not None and shared_handoff_target != int(target_entry):
        return PathTailEmissionPlan(
            accepted=False,
            rejection_reason="shared_handoff_conflict",
        )

    if npreds > 1 and shared_handoff_target == int(target_entry):
        if existing_exit_target is not None or existing_1way_target is not None:
            return PathTailEmissionPlan(
                accepted=False,
                rejection_reason="existing_claim",
            )
        return PathTailEmissionPlan(
            accepted=True,
            kind=PathTailEmissionKind.SHARED_GOTO,
            modification=RedirectGoto(
                from_serial=int(source_block),
                old_target=int(old_target),
                new_target=int(target_entry),
            ),
            block_source=int(source_block),
            target_entry=int(target_entry),
        )

    if npreds <= 1:
        if existing_exit_target is not None or existing_1way_target is not None:
            return PathTailEmissionPlan(
                accepted=False,
                rejection_reason="existing_claim",
            )
        return PathTailEmissionPlan(
            accepted=True,
            kind=PathTailEmissionKind.DIRECT_GOTO,
            modification=RedirectGoto(
                from_serial=int(source_block),
                old_target=int(old_target),
                new_target=int(target_entry),
            ),
            block_source=int(source_block),
            target_entry=int(target_entry),
        )

    if via_pred is not None and is_valid_pred_split_pair(
        int(source_block),
        via_pred=int(via_pred),
        source_succs=tuple(int(succ) for succ in source_succs),
        via_pred_succs=tuple(int(succ) for succ in via_pred_succs),
    ):
        if via_pred_blocked or via_pred_terminal_protected:
            return PathTailEmissionPlan(
                accepted=False,
                rejection_reason="blocked_via_pred",
            )
        if existing_path_edge_target is not None:
            return PathTailEmissionPlan(
                accepted=False,
                rejection_reason="existing_path_claim",
            )
        return PathTailEmissionPlan(
            accepted=True,
            kind=PathTailEmissionKind.PRED_SPLIT,
            modification=EdgeRedirectViaPredSplit(
                src_block=int(source_block),
                old_target=int(old_target),
                new_target=int(target_entry),
                via_pred=int(via_pred),
                rule_priority=550,
            ),
            block_source=int(source_block),
            target_entry=int(target_entry),
            via_pred=int(via_pred),
            blocked_pred=int(via_pred),
            path_edge_key=(int(source_block), int(via_pred)),
        )

    if via_pred is not None and can_duplicate_path_tail(
        int(source_block),
        via_pred=int(via_pred),
        source_succs=tuple(int(succ) for succ in source_succs),
        via_pred_succs=tuple(int(succ) for succ in via_pred_succs),
        source_is_conditional_branch=bool(source_is_conditional_branch),
        source_anchor_block=int(source_anchor_block),
        source_branch_arm=(
            int(source_branch_arm) if source_branch_arm is not None else None
        ),
    ):
        if via_pred_blocked:
            return PathTailEmissionPlan(
                accepted=False,
                rejection_reason="blocked_via_pred",
            )
        if other_preds:
            return PathTailEmissionPlan(
                accepted=True,
                kind=PathTailEmissionKind.DUPLICATE,
                modification=DuplicateAndRedirect(
                    source_serial=int(source_block),
                    per_pred_targets=(
                        (int(other_preds[0]), int(old_target)),
                        (int(via_pred), int(target_entry)),
                    ),
                ),
                block_source=int(source_block),
                target_entry=int(target_entry),
                via_pred=int(via_pred),
                blocked_pred=int(via_pred),
            )

    return PathTailEmissionPlan(
        accepted=False,
        rejection_reason="no_path_tail_shape",
    )


__all__ = [
    "PathTailEmissionKind",
    "PathTailEmissionPlan",
    "plan_path_tail_emission",
]
