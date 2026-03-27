from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.reconstruction_emission import plan_reconstruction_emission


class ReconstructionEmissionMode:
    """Labels for reconstruction emission decisions."""

    DIRECT = "direct"
    CONDITIONAL_ARM = "conditional_arm"
    PRED_SPLIT = "pred_split"


@dataclass(frozen=True, slots=True)
class ReconstructionPlanningContext:
    """Structured request from Hodur into CFG reconstruction planning."""

    ordered_path: tuple[int, ...]
    horizon_block: int
    target_entry: int
    source_anchor_block: int
    source_branch_arm: int | None
    is_conditional_transition: bool
    shared_suffix_blocks: frozenset[int]
    dispatcher_region: frozenset[int]
    has_unsafe_trailing_insns: bool


@dataclass(frozen=True, slots=True)
class ReconstructionPlanningDecision:
    """Planner result for a reconstructed semantic corridor candidate."""

    accepted: bool
    target_entry: int | None = None
    emission_mode: str | None = None
    first_shared_block: int | None = None
    via_pred: int | None = None
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


__all__ = [
    "ReconstructionEmissionMode",
    "ReconstructionPlanningContext",
    "ReconstructionPlanningDecision",
    "plan_reconstruction_candidate",
]
