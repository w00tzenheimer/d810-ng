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


__all__ = [
    "SharedGroupEmissionCandidate",
    "SharedGroupEmissionPlan",
    "plan_shared_group_emission",
]
