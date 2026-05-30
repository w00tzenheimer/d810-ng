from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import (
    EdgeRedirectViaPredSplit,
    GraphModification,
    RedirectGoto,
)
from d810.transforms.loop_bound_writer_guard import (
    LoopBoundWriterDiagnostic,
    detect_loop_bound_writer_redirect,
)
from d810.transforms.lowering_selector import can_duplicate_path_tail, is_valid_pred_split_pair


# ``LoopBoundWriterDiagnostic`` and ``detect_loop_bound_writer_redirect`` are
# re-exported above from :mod:`d810.transforms.loop_bound_writer_guard` so the
# shared-group reconstruction emitter can use the same predicate without
# importing planner internals.  See that module for the four-condition
# detector.



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
    extra_owned_blocks: tuple[int, ...] = ()
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class PathTailRedirectContext:
    source_block: int
    target_entry: int
    source_handler_is_report_exit: bool
    ordered_path_head_is_report_exit: bool
    source_in_report_exit_owned: bool
    source_blocked: bool
    source_terminal_protected: bool
    foreign_exact_owner_label: str | None
    backward_same_corridor: bool
    allow_semantic_handoff: bool
    target_reaches_source: bool
    source_nsucc: int | None
    source_npred: int | None
    source_succs: tuple[int, ...]
    source_preds: tuple[int, ...]
    old_target: int | None
    emitted_already: bool
    shared_handoff_target: int | None
    via_pred: int | None
    via_pred_succs: tuple[int, ...]
    existing_exit_target: int | None
    existing_1way_target: int | None
    existing_path_edge_target: int | None
    via_pred_blocked: bool
    via_pred_terminal_protected: bool
    source_is_conditional_branch: bool
    source_anchor_block: int
    source_branch_arm: int | None
    other_preds: tuple[int, ...]
    loop_bound_writer_diag: LoopBoundWriterDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class PathTailRedirectDecision:
    accepted: bool
    emission_plan: PathTailEmissionPlan | None = None
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
            extra_owned_blocks=(int(via_pred),),
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
                accepted=False,
                rejection_reason="path_tail_clone_safety_gap",
            )

    return PathTailEmissionPlan(
        accepted=False,
        rejection_reason="no_path_tail_shape",
    )


def plan_path_tail_redirect(
    context: PathTailRedirectContext,
) -> PathTailRedirectDecision:
    if context.loop_bound_writer_diag is not None:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="loop_bound_writer_guard",
        )
    if context.source_handler_is_report_exit:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="report_exit_source_handler",
        )
    if context.ordered_path_head_is_report_exit:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="report_exit_path_head",
        )
    if int(context.source_block) == int(context.target_entry):
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="source_equals_target",
        )
    if context.foreign_exact_owner_label is not None:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="foreign_exact_entry_owner",
        )
    if context.backward_same_corridor:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="backward_same_corridor",
        )
    if context.target_reaches_source and not context.allow_semantic_handoff:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="target_reaches_source",
        )
    if context.source_in_report_exit_owned:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="source_in_report_exit_owned",
        )
    if context.source_blocked:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="blocked_source",
        )
    if context.source_terminal_protected:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="terminal_protected_source",
        )
    if context.source_nsucc != 1:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="non_oneway_source",
        )
    if context.old_target is None or int(context.old_target) == int(context.target_entry):
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="noop_or_missing_old_target",
        )
    if context.emitted_already:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason="already_emitted",
        )

    emission_plan = plan_path_tail_emission(
        source_block=int(context.source_block),
        target_entry=int(context.target_entry),
        old_target=int(context.old_target),
        npreds=int(context.source_npred or 0),
        shared_handoff_target=(
            int(context.shared_handoff_target)
            if context.shared_handoff_target is not None
            else None
        ),
        existing_exit_target=(
            int(context.existing_exit_target)
            if context.existing_exit_target is not None
            else None
        ),
        existing_1way_target=(
            int(context.existing_1way_target)
            if context.existing_1way_target is not None
            else None
        ),
        via_pred=(int(context.via_pred) if context.via_pred is not None else None),
        existing_path_edge_target=(
            int(context.existing_path_edge_target)
            if context.existing_path_edge_target is not None
            else None
        ),
        via_pred_blocked=bool(context.via_pred_blocked),
        via_pred_terminal_protected=bool(context.via_pred_terminal_protected),
        source_succs=tuple(int(succ) for succ in context.source_succs),
        via_pred_succs=tuple(int(succ) for succ in context.via_pred_succs),
        source_is_conditional_branch=bool(context.source_is_conditional_branch),
        source_anchor_block=int(context.source_anchor_block),
        source_branch_arm=(
            int(context.source_branch_arm)
            if context.source_branch_arm is not None
            else None
        ),
        other_preds=tuple(int(pred) for pred in context.other_preds),
    )
    if not emission_plan.accepted:
        return PathTailRedirectDecision(
            accepted=False,
            rejection_reason=emission_plan.rejection_reason,
        )
    return PathTailRedirectDecision(
        accepted=True,
        emission_plan=emission_plan,
    )


def apply_path_tail_emission_plan(
    emission_plan: PathTailEmissionPlan,
    *,
    modifications: list[GraphModification],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int],
    claimed_exits: dict[int, int],
    claimed_path_edges: dict[tuple[int, int], int],
    blocked_sources: set[int],
    owned_transition: tuple[int, int] | None = None,
) -> None:
    if emission_plan.modification is None:
        raise ValueError("path-tail emission plan has no modification")
    if emission_plan.block_source is None or emission_plan.target_entry is None:
        raise ValueError("path-tail emission plan is missing block source or target entry")

    source_block = int(emission_plan.block_source)
    target_entry = int(emission_plan.target_entry)
    modifications.append(emission_plan.modification)
    emitted.add((source_block, target_entry))
    owned_blocks.add(source_block)
    owned_edges.add((source_block, target_entry))

    for owned_block in emission_plan.extra_owned_blocks:
        owned_blocks.add(int(owned_block))

    if owned_transition is not None:
        owned_transitions.add((int(owned_transition[0]), int(owned_transition[1])))

    if emission_plan.kind in (
        PathTailEmissionKind.SHARED_GOTO,
        PathTailEmissionKind.DIRECT_GOTO,
    ):
        claimed_exits[source_block] = target_entry
        claimed_1way[source_block] = target_entry
    elif emission_plan.kind == PathTailEmissionKind.PRED_SPLIT:
        if emission_plan.path_edge_key is None:
            raise ValueError("pred-split path-tail emission plan missing path edge key")
        claimed_path_edges[
            (int(emission_plan.path_edge_key[0]), int(emission_plan.path_edge_key[1]))
        ] = target_entry

    if emission_plan.blocked_pred is not None:
        blocked_sources.add(int(emission_plan.blocked_pred))


__all__ = [
    "apply_path_tail_emission_plan",
    "detect_loop_bound_writer_redirect",
    "LoopBoundWriterDiagnostic",
    "PathTailEmissionKind",
    "PathTailEmissionPlan",
    "PathTailRedirectContext",
    "PathTailRedirectDecision",
    "plan_path_tail_emission",
    "plan_path_tail_redirect",
]
