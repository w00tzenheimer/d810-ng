from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import GraphModification, RedirectBranch, RedirectGoto


@dataclass(frozen=True, slots=True)
class DagRedirectEmissionPlan:
    accepted: bool
    modification: GraphModification | None = None
    claim_1way_target: int | None = None
    claim_2way_key: tuple[int, int] | None = None
    claim_2way_target: int | None = None
    rejection_reason: str = ""
    existing_target: int | None = None


def plan_dag_redirect_fallback_emission(
    *,
    source_block: int,
    target_entry: int,
    nsucc: int,
    old_target: int | None,
    edge_is_transition: bool,
    live_oneway_noop: bool,
    claimed_1way_target: int | None,
    claimed_2way_target: int | None,
) -> DagRedirectEmissionPlan:
    if nsucc == 2 and edge_is_transition:
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="transition_two_way_source",
        )

    if nsucc == 2:
        if old_target is None or int(old_target) == int(target_entry):
            return DagRedirectEmissionPlan(
                accepted=False,
                rejection_reason="invalid_old_target",
            )
        if claimed_2way_target is not None:
            if int(claimed_2way_target) == int(target_entry):
                return DagRedirectEmissionPlan(
                    accepted=False,
                    rejection_reason="existing_branch_target",
                    existing_target=int(claimed_2way_target),
                )
            return DagRedirectEmissionPlan(
                accepted=False,
                rejection_reason="branch_conflict",
                existing_target=int(claimed_2way_target),
            )
        return DagRedirectEmissionPlan(
            accepted=True,
            modification=RedirectBranch(
                from_serial=int(source_block),
                old_target=int(old_target),
                new_target=int(target_entry),
            ),
            claim_2way_key=(int(source_block), int(old_target)),
            claim_2way_target=int(target_entry),
        )

    if live_oneway_noop:
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="live_oneway_noop",
        )
    if claimed_1way_target is not None and int(claimed_1way_target) != int(target_entry):
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="oneway_conflict",
            existing_target=int(claimed_1way_target),
        )
    return DagRedirectEmissionPlan(
        accepted=True,
        modification=RedirectGoto(
            from_serial=int(source_block),
            old_target=(int(old_target) if old_target is not None else 0),
            new_target=int(target_entry),
        ),
        claim_1way_target=int(target_entry),
    )


__all__ = [
    "DagRedirectEmissionPlan",
    "plan_dag_redirect_fallback_emission",
]
