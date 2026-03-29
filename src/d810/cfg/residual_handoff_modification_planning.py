from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.cfg.residual_handoff_planning import (
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
    bst_node_blocks: frozenset[int],
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
                        bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
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


__all__ = [
    "ResidualBranchAnchorEmissionPlan",
    "plan_residual_branch_anchor_emission",
]
