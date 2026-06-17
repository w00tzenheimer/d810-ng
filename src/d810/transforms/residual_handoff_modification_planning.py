from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import (
    EdgeRedirectViaPredSplit,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.residual_handoff_planning import (
    ResidualBranchAnchorContext,
    ResidualHandoffMode,
    ResidualHandoffPlanningContext,
    ResidualPrefixAttempt,
    plan_residual_handoff,
)


@dataclass(frozen=True, slots=True)
class ResidualBranchAnchorEmissionPlan:
    accepted: bool
    already_claimed: bool = False
    modification: GraphModification | None = None
    branch_source: int | None = None
    prefix_target: int | None = None
    old_target: int | None = None
    via_pred: int | None = None
    owned_transition: tuple[int, int] | None = None
    edge_kind_name: str = ""


@dataclass(frozen=True, slots=True)
class ProjectedAliasNormalizationPlan:
    accepted: bool
    modification: GraphModification | None = None
    replace_index: int | None = None
    replaced_target: int | None = None
    source_block: int | None = None
    target_entry: int | None = None
    rejection_reason: str = ""


def plan_residual_branch_anchor_emission(
    *,
    is_conditional_branch_source: bool,
    branch_source: int,
    source_block: int,
    via_pred: int,
    prefix_target: int,
    branch_succs: tuple[int, ...],
    old_target: int,
    ordered_path: tuple[int, ...],
    dispatcher_serial: int,
    condition_chain_blocks: frozenset[int],
    target_reaches_branch: bool,
    claimed_branch_target: int | None,
    owned_transition: tuple[int, int] | None,
    edge_kind_name: str,
) -> ResidualBranchAnchorEmissionPlan:
    decision = plan_residual_handoff(
        ResidualHandoffPlanningContext(
            mode=ResidualHandoffMode.PREFIX,
            prefix_attempts=(
                ResidualPrefixAttempt(
                    via_pred=int(via_pred),
                    prefix_target=int(prefix_target),
                    claimed_branch_target=(
                        int(claimed_branch_target)
                        if claimed_branch_target is not None
                        else None
                    ),
                    owned_transition=owned_transition,
                    edge_kind_name=str(edge_kind_name),
                    branch_context=ResidualBranchAnchorContext(
                        is_conditional_branch_source=bool(is_conditional_branch_source),
                        branch_source=int(branch_source),
                        source_block=int(source_block),
                        via_pred=int(via_pred),
                        prefix_target=int(prefix_target),
                        branch_succs=tuple(int(succ) for succ in branch_succs),
                        old_target=int(old_target),
                        ordered_path=tuple(int(node) for node in ordered_path),
                        dispatcher_serial=int(dispatcher_serial),
                        condition_chain_blocks=frozenset(int(block) for block in condition_chain_blocks),
                        target_reaches_branch=bool(target_reaches_branch),
                    ),
                ),
            ),
        )
    )
    if not decision.accepted or decision.kind != ResidualHandoffMode.BRANCH_ANCHOR:
        return ResidualBranchAnchorEmissionPlan(accepted=False)
    if decision.already_claimed:
        return ResidualBranchAnchorEmissionPlan(
            accepted=True,
            already_claimed=True,
            branch_source=int(decision.branch_source),
            prefix_target=int(decision.prefix_target),
            old_target=int(decision.old_target),
            via_pred=int(decision.via_pred),
            owned_transition=decision.owned_transition,
            edge_kind_name=decision.edge_kind_name,
        )
    modification: GraphModification
    if len(tuple(int(succ) for succ in branch_succs)) == 2:
        modification = RedirectBranch(
            from_serial=int(decision.branch_source),
            old_target=int(decision.old_target),
            new_target=int(decision.prefix_target),
        )
    else:
        modification = RedirectGoto(
            from_serial=int(decision.branch_source),
            old_target=int(decision.old_target),
            new_target=int(decision.prefix_target),
        )
    return ResidualBranchAnchorEmissionPlan(
        accepted=True,
        modification=modification,
        branch_source=int(decision.branch_source),
        prefix_target=int(decision.prefix_target),
        old_target=int(decision.old_target),
        via_pred=int(decision.via_pred),
        owned_transition=decision.owned_transition,
        edge_kind_name=decision.edge_kind_name,
    )


def plan_projected_alias_handoff_normalization(
    *,
    source_block: int,
    current_target: int,
    target_entry: int,
    existing_redirect_index: int | None,
    existing_redirect_old_target: int | None,
    existing_redirect_target: int | None,
    already_emitted: bool,
) -> ProjectedAliasNormalizationPlan:
    if existing_redirect_target is not None:
        if int(existing_redirect_target) == int(target_entry):
            return ProjectedAliasNormalizationPlan(
                accepted=False,
                rejection_reason="existing_redirect_matches_target",
            )
        if existing_redirect_index is None or existing_redirect_old_target is None:
            return ProjectedAliasNormalizationPlan(
                accepted=False,
                rejection_reason="incomplete_existing_redirect",
            )
        return ProjectedAliasNormalizationPlan(
            accepted=True,
            modification=RedirectGoto(
                from_serial=int(source_block),
                old_target=int(existing_redirect_old_target),
                new_target=int(target_entry),
            ),
            replace_index=int(existing_redirect_index),
            replaced_target=int(existing_redirect_target),
            source_block=int(source_block),
            target_entry=int(target_entry),
        )
    if already_emitted:
        return ProjectedAliasNormalizationPlan(
            accepted=False,
            rejection_reason="already_emitted",
        )
    return ProjectedAliasNormalizationPlan(
        accepted=True,
        modification=RedirectGoto(
            from_serial=int(source_block),
            old_target=int(current_target),
            new_target=int(target_entry),
        ),
        source_block=int(source_block),
        target_entry=int(target_entry),
    )


def plan_residual_pred_split_emissions(
    *,
    source_block: int,
    dispatcher_serial: int,
    pred_splits: tuple[tuple[int, int], ...],
) -> tuple[GraphModification, ...]:
    return tuple(
        EdgeRedirectViaPredSplit(
            src_block=int(source_block),
            old_target=int(dispatcher_serial),
            new_target=int(target_entry),
            via_pred=int(via_pred),
            rule_priority=550,
        )
        for via_pred, target_entry in pred_splits
    )


def plan_residual_goto_emission(
    *,
    source_block: int,
    dispatcher_serial: int,
    target_entry: int,
) -> GraphModification:
    return RedirectGoto(
        from_serial=int(source_block),
        old_target=int(dispatcher_serial),
        new_target=int(target_entry),
    )


def plan_residual_prefix_peel_emission(
    *,
    via_pred: int,
    prefix_target: int,
    old_target: int,
    via_pred_succs: tuple[int, ...],
) -> GraphModification:
    if len(tuple(int(succ) for succ in via_pred_succs)) == 2:
        return RedirectBranch(
            from_serial=int(via_pred),
            old_target=int(old_target),
            new_target=int(prefix_target),
        )
    return RedirectGoto(
        from_serial=int(via_pred),
        old_target=int(old_target),
        new_target=int(prefix_target),
    )


def apply_residual_branch_anchor_emission_plan(
    plan: ResidualBranchAnchorEmissionPlan,
    *,
    modifications: list[GraphModification],
    claimed_2way: dict[tuple[int, int], int],
    emitted: set[tuple[int, int]],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
) -> None:
    if plan.modification is None:
        raise ValueError("residual branch-anchor emission plan has no modification")
    if (
        plan.branch_source is None
        or plan.prefix_target is None
        or plan.old_target is None
    ):
        raise ValueError(
            "residual branch-anchor emission plan is missing source, old target, or prefix target"
        )

    branch_source = int(plan.branch_source)
    prefix_target = int(plan.prefix_target)
    old_target = int(plan.old_target)
    modifications.append(plan.modification)
    claimed_2way[(branch_source, old_target)] = prefix_target
    emitted.add((branch_source, prefix_target))
    owned_blocks.add(branch_source)
    owned_edges.add((branch_source, prefix_target))
    if plan.owned_transition is not None:
        owned_transitions.add(
            (int(plan.owned_transition[0]), int(plan.owned_transition[1]))
        )


__all__ = [
    "apply_residual_branch_anchor_emission_plan",
    "ProjectedAliasNormalizationPlan",
    "plan_residual_goto_emission",
    "plan_residual_pred_split_emissions",
    "plan_residual_prefix_peel_emission",
    "plan_projected_alias_handoff_normalization",
    "ResidualBranchAnchorEmissionPlan",
    "plan_residual_branch_anchor_emission",
]
