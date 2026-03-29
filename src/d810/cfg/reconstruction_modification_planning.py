from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateAndRedirect,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_planning import (
    ReconstructionLoweringContext,
    ReconstructionLoweringKind,
    plan_reconstruction_lowering,
)
from d810.cfg.shared_corridor import resolve_old_target


@dataclass(frozen=True, slots=True)
class ReconstructionModificationPlan:
    accepted: bool
    modifications: tuple[GraphModification, ...] = ()
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class SharedGroupModificationPlan:
    accepted: bool
    modifications: tuple[GraphModification, ...] = ()
    ordered_via_preds: tuple[int, ...] = ()
    per_pred_targets: tuple[tuple[int, int], ...] = ()
    rejection_reason: str = ""


def _goto_redirect_for_block(
    flow_graph,
    *,
    source_block: int,
    target_block: int,
    old_target: int,
) -> GraphModification:
    block = flow_graph.get_block(int(source_block))
    if block is not None and int(getattr(block, "nsucc", len(getattr(block, "succs", ())))) == 2:
        return ConvertToGoto(block_serial=int(source_block), goto_target=int(target_block))
    return RedirectGoto(
        from_serial=int(source_block),
        old_target=int(old_target),
        new_target=int(target_block),
    )


def _edge_redirect_for_block(
    flow_graph,
    *,
    source_block: int,
    target_block: int,
    old_target: int,
) -> GraphModification:
    block = flow_graph.get_block(int(source_block))
    if block is not None and int(getattr(block, "nsucc", len(getattr(block, "succs", ())))) == 2:
        return RedirectBranch(
            from_serial=int(source_block),
            old_target=int(old_target),
            new_target=int(target_block),
        )
    return RedirectGoto(
        from_serial=int(source_block),
        old_target=int(old_target),
        new_target=int(target_block),
    )


def plan_direct_reconstruction_modifications(
    *,
    flow_graph,
    horizon_block: int,
    target_entry: int,
    ordered_path: tuple[int, ...],
) -> ReconstructionModificationPlan:
    old_target = resolve_old_target(
        flow_graph,
        int(horizon_block),
        tuple(int(serial) for serial in ordered_path),
    )
    lowering_decision = plan_reconstruction_lowering(
        flow_graph=flow_graph,
        context=ReconstructionLoweringContext(
            kind=ReconstructionLoweringKind.DIRECT,
            target_entry=int(target_entry),
            old_target=(int(old_target) if old_target is not None else None),
            horizon_block=int(horizon_block),
        ),
    )
    if not lowering_decision.accepted:
        return ReconstructionModificationPlan(
            accepted=False,
            rejection_reason=lowering_decision.rejection_reason,
        )
    redirect = lowering_decision.redirects[0]
    return ReconstructionModificationPlan(
        accepted=True,
        modifications=(
            _goto_redirect_for_block(
                flow_graph,
                source_block=int(redirect.source_block),
                target_block=int(redirect.target_block),
                old_target=int(redirect.old_target),
            ),
        ),
    )


def plan_conditional_arm_reconstruction_modifications(
    *,
    flow_graph,
    horizon_block: int,
    target_entry: int,
    branch_arm: int,
    dispatcher_serial: int,
    current_entry: int | None,
) -> ReconstructionModificationPlan:
    block = flow_graph.get_block(int(horizon_block))
    if block is None:
        return ReconstructionModificationPlan(accepted=False, rejection_reason="missing_horizon_block")

    lowering_decision = plan_reconstruction_lowering(
        flow_graph=flow_graph,
        context=ReconstructionLoweringContext(
            kind=ReconstructionLoweringKind.CONDITIONAL_ARM,
            target_entry=int(target_entry),
            horizon_block=int(horizon_block),
            block_succs=tuple(int(succ) for succ in block.succs),
            branch_arm=int(branch_arm),
            dispatcher_serial=int(dispatcher_serial),
            current_entry=(int(current_entry) if current_entry is not None else None),
        ),
    )
    if not lowering_decision.accepted:
        return ReconstructionModificationPlan(
            accepted=False,
            rejection_reason=lowering_decision.rejection_reason,
        )
    return ReconstructionModificationPlan(
        accepted=True,
        modifications=tuple(
            _edge_redirect_for_block(
                flow_graph,
                source_block=int(redirect.source_block),
                target_block=int(redirect.target_block),
                old_target=int(redirect.old_target),
            )
            for redirect in lowering_decision.redirects
        ),
    )


def plan_passthrough_reconstruction_modifications(
    *,
    flow_graph,
    ordered_path: tuple[int, ...],
    horizon_block: int,
    dispatcher_serial: int,
    current_state_entry: int | None,
) -> ReconstructionModificationPlan:
    lowering_decision = plan_reconstruction_lowering(
        flow_graph=flow_graph,
        context=ReconstructionLoweringContext(
            kind=ReconstructionLoweringKind.PASSTHROUGH,
            ordered_path=tuple(int(serial) for serial in ordered_path),
            horizon_block=int(horizon_block),
            dispatcher_serial=int(dispatcher_serial),
            current_entry=(
                int(current_state_entry) if current_state_entry is not None else None
            ),
        ),
    )
    return ReconstructionModificationPlan(
        accepted=True,
        modifications=tuple(
            _edge_redirect_for_block(
                flow_graph,
                source_block=int(redirect.source_block),
                target_block=int(redirect.target_block),
                old_target=int(redirect.old_target),
            )
            for redirect in lowering_decision.redirects
        ),
    )


def plan_shared_group_reconstruction_modifications(
    *,
    flow_graph,
    shared_block: int,
    ordered_path: tuple[int, ...],
    shared_candidates: tuple[SharedGroupEmissionCandidate, ...],
) -> SharedGroupModificationPlan:
    shared_snapshot = flow_graph.get_block(int(shared_block))
    if shared_snapshot is None:
        return SharedGroupModificationPlan(
            accepted=False,
            rejection_reason="missing_shared_block",
        )

    old_target = resolve_old_target(
        flow_graph,
        int(shared_block),
        tuple(int(serial) for serial in ordered_path),
    )
    lowering_decision = plan_reconstruction_lowering(
        flow_graph=flow_graph,
        context=ReconstructionLoweringContext(
            kind=ReconstructionLoweringKind.SHARED_GROUP,
            shared_block=int(shared_block),
            shared_preds=tuple(int(pred) for pred in shared_snapshot.preds),
            old_target=(int(old_target) if old_target is not None else None),
            shared_candidates=tuple(shared_candidates),
        ),
    )
    if not lowering_decision.accepted:
        return SharedGroupModificationPlan(
            accepted=False,
            ordered_via_preds=tuple(
                int(candidate.via_pred) for candidate in lowering_decision.ordered_candidates
            ),
            rejection_reason=lowering_decision.rejection_reason,
        )
    return SharedGroupModificationPlan(
        accepted=True,
        modifications=(
            DuplicateAndRedirect(
                source_serial=int(shared_block),
                per_pred_targets=tuple(
                    (int(pred), int(target))
                    for pred, target in lowering_decision.per_pred_targets
                ),
            ),
        ),
        ordered_via_preds=tuple(
            int(candidate.via_pred) for candidate in lowering_decision.ordered_candidates
        ),
        per_pred_targets=tuple(
            (int(pred), int(target))
            for pred, target in lowering_decision.per_pred_targets
        ),
    )


__all__ = [
    "ReconstructionModificationPlan",
    "SharedGroupModificationPlan",
    "plan_conditional_arm_reconstruction_modifications",
    "plan_direct_reconstruction_modifications",
    "plan_passthrough_reconstruction_modifications",
    "plan_shared_group_reconstruction_modifications",
]
