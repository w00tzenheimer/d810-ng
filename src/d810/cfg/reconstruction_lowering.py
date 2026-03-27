from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.lowering_selector import (
    SharedGroupCandidate,
    SharedGroupContext,
    plan_shared_group_duplication,
)


@dataclass(frozen=True, slots=True)
class SharedGroupEmissionCandidate:
    via_pred: int
    target_entry: int


@dataclass(frozen=True, slots=True)
class SharedGroupEmissionPlan:
    accepted: bool
    ordered_candidates: tuple[SharedGroupEmissionCandidate, ...] = ()
    per_pred_targets: tuple[tuple[int, int], ...] = ()
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class RedirectSpec:
    source_block: int
    target_block: int
    old_target: int


@dataclass(frozen=True, slots=True)
class DirectEmissionPlan:
    accepted: bool
    old_target: int | None = None
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class ConditionalArmEmissionPlan:
    accepted: bool
    redirects: tuple[RedirectSpec, ...] = ()
    rejection_reason: str = ""


def plan_shared_group_emission(
    *,
    shared_block: int,
    shared_preds: tuple[int, ...],
    old_target: int | None,
    candidates: tuple[SharedGroupEmissionCandidate, ...],
) -> SharedGroupEmissionPlan:
    by_pred: dict[int, SharedGroupEmissionCandidate] = {}
    for candidate in candidates:
        existing = by_pred.get(int(candidate.via_pred))
        if existing is None:
            by_pred[int(candidate.via_pred)] = candidate
            continue
        if int(existing.target_entry) == int(candidate.target_entry):
            continue
        return SharedGroupEmissionPlan(
            accepted=False,
            rejection_reason="shared_block_conflict",
        )

    if not by_pred:
        return SharedGroupEmissionPlan(
            accepted=False,
            rejection_reason="no_candidates",
        )

    ordered_candidates = tuple(by_pred[pred] for pred in sorted(by_pred))
    if old_target is None:
        return SharedGroupEmissionPlan(
            accepted=False,
            ordered_candidates=ordered_candidates,
            rejection_reason="missing_old_target",
        )

    if all(int(candidate.target_entry) == int(old_target) for candidate in ordered_candidates):
        return SharedGroupEmissionPlan(
            accepted=False,
            ordered_candidates=ordered_candidates,
            rejection_reason="noop_or_missing_old_target",
        )

    shared_group_plan = plan_shared_group_duplication(
        SharedGroupContext(
            shared_block=int(shared_block),
            old_target=int(old_target),
            shared_preds=tuple(int(pred) for pred in shared_preds),
            candidates=tuple(
                SharedGroupCandidate(
                    via_pred=int(candidate.via_pred),
                    target_entry=int(candidate.target_entry),
                )
                for candidate in ordered_candidates
            ),
        )
    )
    if not shared_group_plan.accepted:
        return SharedGroupEmissionPlan(
            accepted=False,
            ordered_candidates=ordered_candidates,
            rejection_reason=shared_group_plan.rejection_reason,
        )

    return SharedGroupEmissionPlan(
        accepted=True,
        ordered_candidates=ordered_candidates,
        per_pred_targets=tuple(shared_group_plan.per_pred_targets),
    )


def plan_direct_emission(
    *,
    old_target: int | None,
    target_entry: int,
) -> DirectEmissionPlan:
    if old_target is None or int(old_target) == int(target_entry):
        return DirectEmissionPlan(
            accepted=False,
            old_target=old_target,
            rejection_reason="noop_or_missing_old_target",
        )
    return DirectEmissionPlan(
        accepted=True,
        old_target=int(old_target),
    )


def plan_conditional_arm_emission(
    *,
    horizon_block: int,
    block_succs: tuple[int, ...],
    branch_arm: int,
    target_entry: int,
    dispatcher_serial: int,
    current_entry: int | None,
) -> ConditionalArmEmissionPlan:
    if branch_arm < 0 or branch_arm >= len(block_succs):
        return ConditionalArmEmissionPlan(
            accepted=False,
            rejection_reason="branch_arm_out_of_range",
        )

    transition_arm_target = int(block_succs[branch_arm])
    other_arm = 1 - branch_arm
    if other_arm < 0 or other_arm >= len(block_succs):
        return ConditionalArmEmissionPlan(
            accepted=False,
            rejection_reason="unsupported_branch_shape",
        )
    other_arm_target = int(block_succs[other_arm])
    redirects: list[RedirectSpec] = []

    both_arms_to_dispatcher = (
        transition_arm_target == dispatcher_serial
        and other_arm_target == dispatcher_serial
    )
    if both_arms_to_dispatcher:
        if branch_arm == 1:
            redirects.append(
                RedirectSpec(
                    source_block=int(horizon_block),
                    target_block=int(target_entry),
                    old_target=int(dispatcher_serial),
                )
            )
        elif current_entry is not None:
            redirects.append(
                RedirectSpec(
                    source_block=int(horizon_block),
                    target_block=int(current_entry),
                    old_target=int(dispatcher_serial),
                )
            )
        return ConditionalArmEmissionPlan(
            accepted=True,
            redirects=tuple(redirects),
        )

    if transition_arm_target == dispatcher_serial:
        redirects.append(
            RedirectSpec(
                source_block=int(horizon_block),
                target_block=int(target_entry),
                old_target=int(dispatcher_serial),
            )
        )
    if (
        other_arm_target == dispatcher_serial
        and current_entry is not None
        and other_arm == 1
    ):
        redirects.append(
            RedirectSpec(
                source_block=int(horizon_block),
                target_block=int(current_entry),
                old_target=int(dispatcher_serial),
            )
        )
    return ConditionalArmEmissionPlan(
        accepted=True,
        redirects=tuple(redirects),
    )


__all__ = [
    "ConditionalArmEmissionPlan",
    "DirectEmissionPlan",
    "RedirectSpec",
    "SharedGroupEmissionCandidate",
    "SharedGroupEmissionPlan",
    "plan_conditional_arm_emission",
    "plan_direct_emission",
    "plan_shared_group_emission",
]
