from __future__ import annotations

from dataclasses import dataclass

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
