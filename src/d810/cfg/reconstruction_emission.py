from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.cfg.shared_corridor import (
    first_boundary_index,
    first_shared_block_index,
    is_shared_block,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ReconstructionEmissionDecision:
    accepted: bool
    emission_mode: str | None = None
    first_shared_block: int | None = None
    via_pred: int | None = None
    rejection_reason: str | None = None


def _can_emit_direct(
    flow_graph,
    ordered_path: tuple[int, ...],
    *,
    horizon_index: int,
    source_anchor_block: int,
    is_conditional_transition: bool,
    shared_suffix_blocks: set[int],
    dispatcher_region: set[int],
) -> bool:
    horizon_block = int(ordered_path[horizon_index])
    block = flow_graph.get_block(horizon_block)
    if block is None or block.nsucc != 1 or block.npred > 1:
        return False
    if is_shared_block(
        flow_graph,
        horizon_block,
        shared_suffix_blocks=shared_suffix_blocks,
    ):
        return False
    if is_conditional_transition and horizon_block == int(source_anchor_block):
        return False

    boundary_index = first_boundary_index(
        flow_graph,
        ordered_path,
        start_index=horizon_index + 1,
        shared_suffix_blocks=shared_suffix_blocks,
        dispatcher_region=dispatcher_region,
    )
    end_index = len(ordered_path) if boundary_index is None else boundary_index
    for index in range(horizon_index + 1, end_index):
        block_serial = int(ordered_path[index])
        curr = flow_graph.get_block(block_serial)
        if curr is None or curr.nsucc != 1 or curr.npred != 1:
            return False
        if is_shared_block(
            flow_graph,
            block_serial,
            shared_suffix_blocks=shared_suffix_blocks,
        ):
            return False
    return True


def _can_emit_conditional_arm(
    flow_graph,
    ordered_path: tuple[int, ...],
    *,
    horizon_index: int,
    source_anchor_block: int,
    source_branch_arm: int | None,
    is_conditional_transition: bool,
) -> bool:
    if not is_conditional_transition:
        return False

    horizon_block = int(ordered_path[horizon_index])
    if horizon_block != int(source_anchor_block):
        return False

    block = flow_graph.get_block(horizon_block)
    if block is None or block.nsucc != 2:
        return False

    return source_branch_arm is not None


def plan_reconstruction_emission(
    flow_graph,
    ordered_path: tuple[int, ...],
    *,
    horizon_block: int,
    source_anchor_block: int,
    source_branch_arm: int | None,
    is_conditional_transition: bool,
    shared_suffix_blocks: set[int],
    dispatcher_region: set[int],
    has_unsafe_trailing_insns: bool,
) -> ReconstructionEmissionDecision:
    try:
        horizon_index = ordered_path.index(int(horizon_block))
    except ValueError:
        return ReconstructionEmissionDecision(
            accepted=False,
            rejection_reason="horizon_not_on_path",
        )

    first_shared_index = first_shared_block_index(
        flow_graph,
        ordered_path,
        start_index=horizon_index,
        shared_suffix_blocks=shared_suffix_blocks,
        dispatcher_region=dispatcher_region,
    )
    first_shared_block = (
        int(ordered_path[first_shared_index])
        if first_shared_index is not None
        else None
    )

    if _can_emit_direct(
        flow_graph,
        ordered_path,
        horizon_index=horizon_index,
        source_anchor_block=source_anchor_block,
        is_conditional_transition=is_conditional_transition,
        shared_suffix_blocks=shared_suffix_blocks,
        dispatcher_region=dispatcher_region,
    ):
        return ReconstructionEmissionDecision(
            accepted=True,
            emission_mode="direct",
            first_shared_block=first_shared_block,
        )

    if _can_emit_conditional_arm(
        flow_graph,
        ordered_path,
        horizon_index=horizon_index,
        source_anchor_block=source_anchor_block,
        source_branch_arm=source_branch_arm,
        is_conditional_transition=is_conditional_transition,
    ):
        return ReconstructionEmissionDecision(
            accepted=True,
            emission_mode="conditional_arm",
        )

    if first_shared_index is None:
        return ReconstructionEmissionDecision(
            accepted=False,
            rejection_reason=(
                "blocked_side_effects"
                if has_unsafe_trailing_insns
                else "no_shared_rewrite_site"
            ),
        )

    via_pred = int(ordered_path[first_shared_index - 1]) if first_shared_index > 0 else None
    shared_block = int(ordered_path[first_shared_index])
    shared_snapshot = flow_graph.get_block(shared_block)
    if (
        via_pred is None
        or shared_snapshot is None
        or via_pred not in tuple(shared_snapshot.preds)
    ):
        logger.info(
            "RECON DAG planner: missing_via_pred horizon=%d shared_block=%d via_pred=%s "
            "shared_preds=%s horizon_index=%d first_shared_index=%s ordered_path=%s",
            int(horizon_block),
            int(shared_block),
            (int(via_pred) if via_pred is not None else None),
            tuple(int(pred) for pred in getattr(shared_snapshot, "preds", ()))
            if shared_snapshot is not None
            else (),
            int(horizon_index),
            (int(first_shared_index) if first_shared_index is not None else None),
            tuple(int(serial) for serial in ordered_path),
        )
        return ReconstructionEmissionDecision(
            accepted=False,
            first_shared_block=shared_block,
            via_pred=via_pred,
            rejection_reason="missing_via_pred",
        )

    return ReconstructionEmissionDecision(
        accepted=True,
        emission_mode="pred_split",
        first_shared_block=shared_block,
        via_pred=int(via_pred),
    )


__all__ = [
    "ReconstructionEmissionDecision",
    "plan_reconstruction_emission",
]
