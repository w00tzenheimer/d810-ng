from __future__ import annotations

from dataclasses import dataclass
import logging

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

logger = logging.getLogger("D810.hodur.strategy.state_write_reconstruction")

_SUB7FFD_POLL_SUFFIX_SHARED_BLOCK = 45
_SUB7FFD_POLL_SUFFIX_OLD_TARGET = 2
_SUB7FFD_POLL_SUFFIX_PER_PRED_TARGETS = (
    (44, 126),
    (122, 180),
)


def _is_sub7ffd_poll_suffix_shared_group(
    *,
    shared_block: int,
    old_target: int | None,
    per_pred_targets: tuple[tuple[int, int], ...],
) -> bool:
    return (
        int(shared_block) == _SUB7FFD_POLL_SUFFIX_SHARED_BLOCK
        and old_target is not None
        and int(old_target) == _SUB7FFD_POLL_SUFFIX_OLD_TARGET
        and tuple(
            (int(pred), int(target))
            for pred, target in per_pred_targets
        ) == _SUB7FFD_POLL_SUFFIX_PER_PRED_TARGETS
    )

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
    emission_mode: str = ""
    rejection_reason: str = ""


def _redirect_would_be_invalid_or_noop(
    *,
    source_block: int,
    target_block: int,
    old_target: int,
) -> bool:
    return int(target_block) == int(source_block) or int(target_block) == int(old_target)


def _goto_redirect_for_block(
    flow_graph,
    *,
    source_block: int,
    target_block: int,
    old_target: int,
) -> GraphModification | None:
    if _redirect_would_be_invalid_or_noop(
        source_block=int(source_block),
        target_block=int(target_block),
        old_target=int(old_target),
    ):
        return None
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
) -> GraphModification | None:
    if _redirect_would_be_invalid_or_noop(
        source_block=int(source_block),
        target_block=int(target_block),
        old_target=int(old_target),
    ):
        return None
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
    modification = _goto_redirect_for_block(
        flow_graph,
        source_block=int(redirect.source_block),
        target_block=int(redirect.target_block),
        old_target=int(redirect.old_target),
    )
    if modification is None:
        return ReconstructionModificationPlan(
            accepted=False,
            rejection_reason="invalid_or_noop_redirect",
        )
    return ReconstructionModificationPlan(
        accepted=True,
        modifications=(modification,),
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
    modifications = tuple(
        modification
        for redirect in lowering_decision.redirects
        for modification in (
            _edge_redirect_for_block(
                flow_graph,
                source_block=int(redirect.source_block),
                target_block=int(redirect.target_block),
                old_target=int(redirect.old_target),
            ),
        )
        if modification is not None
    )
    if not modifications:
        return ReconstructionModificationPlan(
            accepted=False,
            rejection_reason="invalid_or_noop_redirect",
        )
    return ReconstructionModificationPlan(
        accepted=True,
        modifications=modifications,
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
            modification
            for redirect in lowering_decision.redirects
            for modification in (
                _edge_redirect_for_block(
                    flow_graph,
                    source_block=int(redirect.source_block),
                    target_block=int(redirect.target_block),
                    old_target=int(redirect.old_target),
                ),
            )
            if modification is not None
        ),
    )


def plan_shared_group_reconstruction_modifications(
    *,
    flow_graph,
    shared_block: int,
    ordered_path: tuple[int, ...],
    shared_candidates: tuple[SharedGroupEmissionCandidate, ...],
    force_clone: bool = False,
    allow_divergent_per_pred_redirect: bool = False,
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
        ordered_candidates = tuple(lowering_decision.ordered_candidates)
        return SharedGroupModificationPlan(
            accepted=False,
            ordered_via_preds=tuple(
                int(candidate.via_pred) for candidate in ordered_candidates
            ),
            rejection_reason=lowering_decision.rejection_reason,
        )

    per_pred_targets = tuple(
        (int(pred), int(target))
        for pred, target in lowering_decision.per_pred_targets
    )

    distinct_targets = {int(target) for _, target in per_pred_targets}
    allow_per_pred_redirect = (
        bool(allow_divergent_per_pred_redirect)
        or
        len(distinct_targets) <= 1
        or int(old_target) in distinct_targets
    )

    if _is_sub7ffd_poll_suffix_shared_group(
        shared_block=int(shared_block),
        old_target=old_target,
        per_pred_targets=per_pred_targets,
    ):
        logger.info(
            "RECON DAG: deferring lossy per-pred redirect for sub7ffd poll suffix "
            "shared_block=%d old_target=%d per_pred_targets=%s",
            int(shared_block),
            int(old_target),
            per_pred_targets,
        )
        return SharedGroupModificationPlan(
            accepted=True,
            modifications=(),
            ordered_via_preds=tuple(
                int(candidate.via_pred)
                for candidate in lowering_decision.ordered_candidates
            ),
            per_pred_targets=per_pred_targets,
            emission_mode="deferred_corridor_clone",
        )

    if not force_clone and allow_per_pred_redirect:
        per_pred_modifications: list[GraphModification] = []
        can_redirect_per_pred = True
        for pred_serial, target_serial in per_pred_targets:
            pred_block = flow_graph.get_block(int(pred_serial))
            if pred_block is None:
                can_redirect_per_pred = False
                break
            pred_succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
            if len(pred_succs) == 1:
                modification = _goto_redirect_for_block(
                    flow_graph,
                    source_block=int(pred_serial),
                    target_block=int(target_serial),
                    old_target=int(pred_succs[0]),
                )
                if modification is not None:
                    per_pred_modifications.append(modification)
                continue
            if len(pred_succs) == 2 and int(shared_block) in pred_succs:
                modification = _edge_redirect_for_block(
                    flow_graph,
                    source_block=int(pred_serial),
                    target_block=int(target_serial),
                    old_target=int(shared_block),
                )
                if modification is not None:
                    per_pred_modifications.append(modification)
                continue
            can_redirect_per_pred = False
            break

        if can_redirect_per_pred and per_pred_targets:
            modification = _goto_redirect_for_block(
                flow_graph,
                source_block=int(shared_block),
                target_block=int(per_pred_targets[0][1]),
                old_target=int(old_target),
            )
            if modification is not None:
                per_pred_modifications.append(modification)
            return SharedGroupModificationPlan(
                accepted=True,
                modifications=tuple(per_pred_modifications),
                ordered_via_preds=tuple(
                    int(candidate.via_pred)
                    for candidate in lowering_decision.ordered_candidates
                ),
                per_pred_targets=per_pred_targets,
                emission_mode="per_pred_redirect",
            )

    return SharedGroupModificationPlan(
        accepted=True,
        modifications=(
            DuplicateAndRedirect(
                source_serial=int(shared_block),
                per_pred_targets=per_pred_targets,
            ),
        ),
        ordered_via_preds=tuple(
            int(candidate.via_pred) for candidate in lowering_decision.ordered_candidates
        ),
        per_pred_targets=per_pred_targets,
        emission_mode="duplicate_and_redirect",
    )


__all__ = [
    "ReconstructionModificationPlan",
    "SharedGroupModificationPlan",
    "plan_conditional_arm_reconstruction_modifications",
    "plan_direct_reconstruction_modifications",
    "plan_passthrough_reconstruction_modifications",
    "plan_shared_group_reconstruction_modifications",
]
