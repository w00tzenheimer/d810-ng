from __future__ import annotations

from dataclasses import dataclass

# The mode-enum + planning request/result dataclasses are portable (no transforms
# deps) and live in the analyses layer so the read-only reconstruction candidate
# builder can reference them without an upward import (dissolution, llr-lyly).
from d810.analyses.control_flow.reconstruction_planning_context import (
    ReconstructionEmissionMode,
    ReconstructionPlanningContext,
    ReconstructionPlanningDecision,
)
from d810.transforms.reconstruction_emission_planning import plan_reconstruction_emission
from d810.transforms.reconstruction_lowering import (
    ConditionalArmEmissionPlan,
    DirectEmissionPlan,
    RedirectSpec,
    SharedGroupEmissionCandidate,
    SharedGroupEmissionPlan,
    plan_conditional_arm_emission,
    plan_direct_emission,
    plan_passthrough_redirects,
    plan_shared_group_emission,
)


class ReconstructionLoweringKind:
    """Labels for reconstruction lowering requests."""

    DIRECT = "direct"
    CONDITIONAL_ARM = "conditional_arm"
    SHARED_GROUP = "shared_group"
    PASSTHROUGH = "passthrough"


@dataclass(frozen=True, slots=True)
class ReconstructionLoweringContext:
    """Structured request for one reconstruction lowering plan."""

    kind: str
    target_entry: int | None = None
    old_target: int | None = None
    horizon_block: int | None = None
    block_succs: tuple[int, ...] = ()
    branch_arm: int | None = None
    dispatcher_serial: int | None = None
    current_entry: int | None = None
    shared_block: int | None = None
    shared_preds: tuple[int, ...] = ()
    shared_candidates: tuple[SharedGroupEmissionCandidate, ...] = ()
    ordered_path: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class ReconstructionLoweringDecision:
    """Planner result for one reconstruction lowering request."""

    accepted: bool
    kind: str
    redirects: tuple[RedirectSpec, ...] = ()
    per_pred_targets: tuple[tuple[int, int], ...] = ()
    ordered_candidates: tuple[SharedGroupEmissionCandidate, ...] = ()
    rejection_reason: str = ""


def plan_reconstruction_candidate(
    flow_graph,
    context: ReconstructionPlanningContext,
) -> ReconstructionPlanningDecision:
    """Select the lowering shape for one reconstructed semantic corridor."""

    emission_decision = plan_reconstruction_emission(
        flow_graph,
        tuple(int(serial) for serial in context.ordered_path),
        horizon_block=int(context.horizon_block),
        source_anchor_block=int(context.source_anchor_block),
        source_branch_arm=(
            int(context.source_branch_arm)
            if context.source_branch_arm is not None
            else None
        ),
        is_conditional_transition=bool(context.is_conditional_transition),
        shared_suffix_blocks=set(int(block) for block in context.shared_suffix_blocks),
        dispatcher_region=set(int(block) for block in context.dispatcher_region),
        has_unsafe_trailing_insns=bool(context.has_unsafe_trailing_insns),
    )
    if not emission_decision.accepted:
        return ReconstructionPlanningDecision(
            accepted=False,
            target_entry=int(context.target_entry),
            emission_mode=emission_decision.emission_mode,
            first_shared_block=emission_decision.first_shared_block,
            via_pred=emission_decision.via_pred,
            rejection_reason=emission_decision.rejection_reason or "",
        )
    return ReconstructionPlanningDecision(
        accepted=True,
        target_entry=int(context.target_entry),
        emission_mode=emission_decision.emission_mode,
        first_shared_block=emission_decision.first_shared_block,
        via_pred=emission_decision.via_pred,
    )


def _lower_from_direct_plan(
    plan: DirectEmissionPlan,
    *,
    context: ReconstructionLoweringContext,
) -> ReconstructionLoweringDecision:
    if (
        not plan.accepted
        or plan.old_target is None
        or context.horizon_block is None
        or context.target_entry is None
    ):
        return ReconstructionLoweringDecision(
            accepted=False,
            kind=ReconstructionLoweringKind.DIRECT,
            rejection_reason=plan.rejection_reason,
        )
    return ReconstructionLoweringDecision(
        accepted=True,
        kind=ReconstructionLoweringKind.DIRECT,
        redirects=(
            RedirectSpec(
                source_block=int(context.horizon_block),
                target_block=int(context.target_entry),
                old_target=int(plan.old_target),
            ),
        ),
    )


def _lower_from_conditional_plan(
    plan: ConditionalArmEmissionPlan,
) -> ReconstructionLoweringDecision:
    if not plan.accepted:
        return ReconstructionLoweringDecision(
            accepted=False,
            kind=ReconstructionLoweringKind.CONDITIONAL_ARM,
            rejection_reason=plan.rejection_reason,
        )
    return ReconstructionLoweringDecision(
        accepted=True,
        kind=ReconstructionLoweringKind.CONDITIONAL_ARM,
        redirects=tuple(plan.redirects),
    )


def _lower_from_shared_group_plan(
    plan: SharedGroupEmissionPlan,
) -> ReconstructionLoweringDecision:
    if not plan.accepted:
        return ReconstructionLoweringDecision(
            accepted=False,
            kind=ReconstructionLoweringKind.SHARED_GROUP,
            ordered_candidates=tuple(plan.ordered_candidates),
            rejection_reason=plan.rejection_reason,
        )
    return ReconstructionLoweringDecision(
        accepted=True,
        kind=ReconstructionLoweringKind.SHARED_GROUP,
        ordered_candidates=tuple(plan.ordered_candidates),
        per_pred_targets=tuple(plan.per_pred_targets),
    )


def plan_reconstruction_lowering(
    *,
    flow_graph,
    context: ReconstructionLoweringContext,
) -> ReconstructionLoweringDecision:
    """Plan one lowering request using the extracted cfg contract."""

    if context.kind == ReconstructionLoweringKind.DIRECT:
        direct_plan = plan_direct_emission(
            old_target=(
                int(context.old_target)
                if context.old_target is not None
                else None
            ),
            target_entry=int(context.target_entry),
        )
        return _lower_from_direct_plan(direct_plan, context=context)

    if context.kind == ReconstructionLoweringKind.CONDITIONAL_ARM:
        conditional_plan = plan_conditional_arm_emission(
            horizon_block=int(context.horizon_block),
            block_succs=tuple(int(succ) for succ in context.block_succs),
            branch_arm=int(context.branch_arm),
            target_entry=int(context.target_entry),
            dispatcher_serial=int(context.dispatcher_serial),
            current_entry=(
                int(context.current_entry)
                if context.current_entry is not None
                else None
            ),
        )
        return _lower_from_conditional_plan(conditional_plan)

    if context.kind == ReconstructionLoweringKind.SHARED_GROUP:
        shared_group_plan = plan_shared_group_emission(
            shared_block=int(context.shared_block),
            shared_preds=tuple(int(pred) for pred in context.shared_preds),
            old_target=(
                int(context.old_target)
                if context.old_target is not None
                else None
            ),
            candidates=tuple(context.shared_candidates),
        )
        return _lower_from_shared_group_plan(shared_group_plan)

    if context.kind == ReconstructionLoweringKind.PASSTHROUGH:
        redirects = plan_passthrough_redirects(
            flow_graph=flow_graph,
            ordered_path=tuple(int(serial) for serial in context.ordered_path),
            horizon_block=int(context.horizon_block),
            dispatcher_serial=int(context.dispatcher_serial),
            current_state_entry=(
                int(context.current_entry)
                if context.current_entry is not None
                else None
            ),
        )
        return ReconstructionLoweringDecision(
            accepted=True,
            kind=ReconstructionLoweringKind.PASSTHROUGH,
            redirects=tuple(redirects),
        )

    return ReconstructionLoweringDecision(
        accepted=False,
        kind=str(context.kind),
        rejection_reason="unsupported_lowering_kind",
    )


__all__ = [
    "ReconstructionEmissionMode",
    "ReconstructionLoweringContext",
    "ReconstructionLoweringDecision",
    "ReconstructionLoweringKind",
    "ReconstructionPlanningContext",
    "ReconstructionPlanningDecision",
    "plan_reconstruction_candidate",
    "plan_reconstruction_lowering",
]
