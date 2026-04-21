from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.cfg.reconstruction_planning import (
    ReconstructionEmissionMode,
    ReconstructionPlanningContext,
    plan_reconstruction_candidate,
)
from d810.cfg.shared_corridor import is_backward_same_corridor_target
from d810.recon.flow.edge_metadata import make_edge_metadata
from d810.recon.flow.linearized_state_dag import (
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
)
from d810.recon.flow.reconstruction_discovery import (
    discover_reconstruction_candidate_seed,
)
from d810.recon.flow.state_machine_analysis import (
    SnapshotConstantFixpointResult,
    StateWriteSite,
)

logger = logging.getLogger("D810.hodur.strategy.state_write_reconstruction")
_SUB7FFD_PROBE_TARGET_STATE = 0x24E2E77A
_SUB7FFD_PROBE_SOURCE_BLOCK = 93
_SUB7FFD_PROBE_SHARED_BLOCK = 95
_SUB7FFD_PROBE_RETRY_TARGET = 212
_SUB7FFD_PROBE_RETRY_PATH = (93, 95, 92, 34)
_SUB7FFD_POLL_TARGET_STATE = 0x00C0C59F
_SUB7FFD_CORRIDOR_TARGET_STATES = frozenset({0x0B2FECE0, 0x385BBE2D})


def _should_probe_sub7ffd_edge(edge: StateDagEdge) -> bool:
    return (
        edge.target_state is not None
        and int(edge.target_state) == _SUB7FFD_PROBE_TARGET_STATE
        and int(edge.source_anchor.block_serial) == _SUB7FFD_PROBE_SOURCE_BLOCK
    )


def _should_probe_sub7ffd_poll_edge(edge: StateDagEdge) -> bool:
    return (
        edge.target_state is not None
        and int(edge.target_state) & 0xFFFFFFFF == _SUB7FFD_POLL_TARGET_STATE
    )


def _should_probe_sub7ffd_corridor_edge(edge: StateDagEdge) -> bool:
    return (
        edge.target_state is not None
        and (int(edge.target_state) & 0xFFFFFFFF) in _SUB7FFD_CORRIDOR_TARGET_STATES
    )


def _should_hoist_sub7ffd_retry_edge(
    edge: StateDagEdge,
    *,
    ordered_path: tuple[int, ...],
    horizon_block: int,
    target_entry: int,
    first_shared_block: int | None,
    via_pred: int | None,
) -> bool:
    return (
        _should_probe_sub7ffd_edge(edge)
        and tuple(int(serial) for serial in ordered_path) == _SUB7FFD_PROBE_RETRY_PATH
        and int(horizon_block) == _SUB7FFD_PROBE_SHARED_BLOCK
        and int(target_entry) == _SUB7FFD_PROBE_RETRY_TARGET
        and int(edge.source_anchor.block_serial) == _SUB7FFD_PROBE_SOURCE_BLOCK
        and int(edge.source_anchor.branch_arm or 0) == 1
        and first_shared_block is not None
        and int(first_shared_block) == _SUB7FFD_PROBE_SHARED_BLOCK
        and via_pred is not None
        and int(via_pred) == _SUB7FFD_PROBE_SOURCE_BLOCK
    )


@dataclass(frozen=True, slots=True)
class ReconstructionCandidate:
    """One proven semantic corridor that can be rebuilt without the dispatcher."""

    edge: StateDagEdge
    horizon_block: int
    site: StateWriteSite
    target_entry: int
    first_shared_block: int | None
    via_pred: int | None
    emission_mode: str
    conditional_group_policy: str = "auto"


def build_reconstruction_candidate(
    edge: StateDagEdge,
    *,
    flow_graph,
    node_by_key: dict[StateDagNodeKey, StateDagNode],
    state_var_stkoff: int,
    constant_result: SnapshotConstantFixpointResult,
    shared_suffix_blocks: set[int],
    dispatcher_region: set[int],
) -> tuple[ReconstructionCandidate | None, dict[str, int | str | None] | None]:
    if edge.kind not in (
        SemanticEdgeKind.TRANSITION,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
    ):
        return None, make_edge_metadata(
            edge,
            rejection_reason="unsupported_edge_kind",
        )

    if edge.target_state is None:
        return None, make_edge_metadata(
            edge,
            rejection_reason="missing_target_state",
        )

    ordered_path = tuple(int(serial) for serial in edge.ordered_path)
    seed, seed_rejection = discover_reconstruction_candidate_seed(
        edge,
        flow_graph=flow_graph,
        node_by_key=node_by_key,
        state_var_stkoff=state_var_stkoff,
        constant_result=constant_result,
        dispatcher_region=dispatcher_region,
    )
    if seed is None:
        if _should_probe_sub7ffd_corridor_edge(edge):
            logger.info(
                "RECON DAG: corridor-target candidate seed reject src=%d arm=%s target_state=0x%08X reason=%s path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(edge.target_state) & 0xFFFFFFFF,
                seed_rejection,
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_poll_edge(edge):
            logger.info(
                "RECON DAG: poll-target candidate seed reject src=%d arm=%s target_state=0x%08X reason=%s path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(edge.target_state) & 0xFFFFFFFF,
                seed_rejection,
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_edge(edge):
            logger.info(
                "RECON DAG: sub7ffd target24 seed reject src=%d arm=%s target_state=0x%08X reason=%s path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(edge.target_state) & 0xFFFFFFFF,
                seed_rejection,
                tuple(int(serial) for serial in ordered_path),
            )
        return None, make_edge_metadata(
            edge,
            rejection_reason=seed_rejection,
        )

    horizon_block = seed.horizon_block
    site = seed.site
    target_entry = seed.target_entry

    if is_backward_same_corridor_target(
        ordered_path,
        rewrite_block=horizon_block,
        target_entry=target_entry,
    ):
        if _should_probe_sub7ffd_corridor_edge(edge):
            logger.info(
                "RECON DAG: corridor-target candidate reject src=%d arm=%s horizon=%d target_entry=%d reason=backward_same_corridor_target path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_poll_edge(edge):
            logger.info(
                "RECON DAG: poll-target candidate reject src=%d arm=%s horizon=%d target_entry=%d reason=backward_same_corridor_target path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        return None, make_edge_metadata(
            edge,
            horizon_block=horizon_block,
            site=site,
            target_entry=target_entry,
            rejection_reason="backward_same_corridor_target",
        )

    try:
        ordered_path.index(int(horizon_block))
    except ValueError:
        if _should_probe_sub7ffd_corridor_edge(edge):
            logger.info(
                "RECON DAG: corridor-target candidate reject src=%d arm=%s horizon=%d target_entry=%d reason=horizon_not_on_path path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_poll_edge(edge):
            logger.info(
                "RECON DAG: poll-target candidate reject src=%d arm=%s horizon=%d target_entry=%d reason=horizon_not_on_path path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        return None, make_edge_metadata(
            edge,
            horizon_block=horizon_block,
            site=site,
            target_entry=target_entry,
            rejection_reason="horizon_not_on_path",
        )

    planning_decision = plan_reconstruction_candidate(
        flow_graph,
        ReconstructionPlanningContext(
            ordered_path=ordered_path,
            horizon_block=int(horizon_block),
            target_entry=int(target_entry),
            source_anchor_block=int(edge.source_anchor.block_serial),
            source_branch_arm=(
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            is_conditional_transition=(
                edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
            ),
            shared_suffix_blocks=frozenset(int(block) for block in shared_suffix_blocks),
            dispatcher_region=frozenset(int(block) for block in dispatcher_region),
            has_unsafe_trailing_insns=bool(site.unsafe_trailing_insn_eas),
        ),
    )

    if not planning_decision.accepted:
        if _should_probe_sub7ffd_corridor_edge(edge):
            logger.info(
                "RECON DAG: corridor-target candidate plan reject src=%d arm=%s horizon=%d target_entry=%d first_shared=%s via_pred=%s reason=%s path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                (
                    int(planning_decision.first_shared_block)
                    if planning_decision.first_shared_block is not None
                    else None
                ),
                (
                    int(planning_decision.via_pred)
                    if planning_decision.via_pred is not None
                    else None
                ),
                planning_decision.rejection_reason,
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_poll_edge(edge):
            logger.info(
                "RECON DAG: poll-target candidate plan reject src=%d arm=%s horizon=%d target_entry=%d first_shared=%s via_pred=%s reason=%s path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                (
                    int(planning_decision.first_shared_block)
                    if planning_decision.first_shared_block is not None
                    else None
                ),
                (
                    int(planning_decision.via_pred)
                    if planning_decision.via_pred is not None
                    else None
                ),
                planning_decision.rejection_reason,
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_edge(edge):
            logger.info(
                "RECON DAG: sub7ffd target24 plan reject src=%d arm=%s horizon=%d target_entry=%d first_shared=%s via_pred=%s reason=%s path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                (
                    int(planning_decision.first_shared_block)
                    if planning_decision.first_shared_block is not None
                    else None
                ),
                (
                    int(planning_decision.via_pred)
                    if planning_decision.via_pred is not None
                    else None
                ),
                planning_decision.rejection_reason,
                tuple(int(serial) for serial in ordered_path),
            )
        return None, make_edge_metadata(
            edge,
            horizon_block=horizon_block,
            site=site,
            target_entry=target_entry,
            first_shared_block=planning_decision.first_shared_block,
            via_pred=planning_decision.via_pred,
            rejection_reason=planning_decision.rejection_reason,
        )

    if planning_decision.emission_mode == ReconstructionEmissionMode.DIRECT:
        if _should_probe_sub7ffd_corridor_edge(edge):
            logger.info(
                "RECON DAG: corridor-target candidate accept mode=direct src=%d arm=%s horizon=%d target_entry=%d path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_poll_edge(edge):
            logger.info(
                "RECON DAG: poll-target candidate accept mode=direct src=%d arm=%s horizon=%d target_entry=%d path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_edge(edge):
            logger.info(
                "RECON DAG: sub7ffd target24 accept mode=direct src=%d arm=%s horizon=%d target_entry=%d path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        return (
            ReconstructionCandidate(
                edge=edge,
                horizon_block=int(horizon_block),
                site=site,
                target_entry=int(target_entry),
                first_shared_block=planning_decision.first_shared_block,
                via_pred=None,
                emission_mode="direct",
            ),
            None,
        )

    if planning_decision.emission_mode == ReconstructionEmissionMode.CONDITIONAL_ARM:
        if _should_probe_sub7ffd_corridor_edge(edge):
            logger.info(
                "RECON DAG: corridor-target candidate accept mode=conditional_arm src=%d arm=%s horizon=%d target_entry=%d path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_poll_edge(edge):
            logger.info(
                "RECON DAG: poll-target candidate accept mode=conditional_arm src=%d arm=%s horizon=%d target_entry=%d path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        if _should_probe_sub7ffd_edge(edge):
            logger.info(
                "RECON DAG: sub7ffd target24 accept mode=conditional_arm src=%d arm=%s horizon=%d target_entry=%d path=%s",
                int(edge.source_anchor.block_serial),
                (
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                int(horizon_block),
                int(target_entry),
                tuple(int(serial) for serial in ordered_path),
            )
        return (
            ReconstructionCandidate(
                edge=edge,
                horizon_block=int(horizon_block),
                site=site,
                target_entry=int(target_entry),
                first_shared_block=None,
                via_pred=None,
                emission_mode="conditional_arm",
            ),
            None,
        )

    if _should_probe_sub7ffd_corridor_edge(edge):
        logger.info(
            "RECON DAG: corridor-target candidate accept mode=pred_split src=%d arm=%s horizon=%d target_entry=%d first_shared=%s via_pred=%s path=%s",
            int(edge.source_anchor.block_serial),
            (
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            int(horizon_block),
            int(target_entry),
            (
                int(planning_decision.first_shared_block)
                if planning_decision.first_shared_block is not None
                else None
            ),
            (
                int(planning_decision.via_pred)
                if planning_decision.via_pred is not None
                else None
            ),
            tuple(int(serial) for serial in ordered_path),
        )
    if _should_probe_sub7ffd_poll_edge(edge):
        logger.info(
            "RECON DAG: poll-target candidate accept mode=pred_split src=%d arm=%s horizon=%d target_entry=%d first_shared=%s via_pred=%s path=%s",
            int(edge.source_anchor.block_serial),
            (
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            int(horizon_block),
            int(target_entry),
            (
                int(planning_decision.first_shared_block)
                if planning_decision.first_shared_block is not None
                else None
            ),
            (
                int(planning_decision.via_pred)
                if planning_decision.via_pred is not None
                else None
            ),
            tuple(int(serial) for serial in ordered_path),
        )
    if _should_probe_sub7ffd_edge(edge):
        logger.info(
            "RECON DAG: sub7ffd target24 accept mode=pred_split src=%d arm=%s horizon=%d target_entry=%d first_shared=%s via_pred=%s path=%s",
            int(edge.source_anchor.block_serial),
            (
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            int(horizon_block),
            int(target_entry),
            (
                int(planning_decision.first_shared_block)
                if planning_decision.first_shared_block is not None
                else None
            ),
            (
                int(planning_decision.via_pred)
                if planning_decision.via_pred is not None
                else None
            ),
            tuple(int(serial) for serial in ordered_path),
        )
    if _should_hoist_sub7ffd_retry_edge(
        edge,
        ordered_path=ordered_path,
        horizon_block=int(horizon_block),
        target_entry=int(target_entry),
        first_shared_block=planning_decision.first_shared_block,
        via_pred=planning_decision.via_pred,
    ):
        logger.info(
            "RECON DAG: sub7ffd target24 hoist src=%d arm=%s from_horizon=%d shared=%d target=%d path=%s",
            int(edge.source_anchor.block_serial),
            (
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            int(horizon_block),
            int(planning_decision.first_shared_block or -1),
            int(target_entry),
            tuple(int(serial) for serial in ordered_path),
        )
        return (
            ReconstructionCandidate(
                edge=edge,
                horizon_block=int(edge.source_anchor.block_serial),
                site=site,
                target_entry=int(target_entry),
                first_shared_block=None,
                via_pred=None,
                emission_mode="conditional_arm",
            ),
            None,
        )
    return (
        ReconstructionCandidate(
            edge=edge,
            horizon_block=int(horizon_block),
            site=site,
            target_entry=int(target_entry),
            first_shared_block=planning_decision.first_shared_block,
            via_pred=int(planning_decision.via_pred),
            emission_mode="pred_split",
        ),
        None,
    )


__all__ = [
    "ReconstructionCandidate",
    "build_reconstruction_candidate",
]
