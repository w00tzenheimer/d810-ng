from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.reconstruction_bridge_planning import (
    ReconstructionBridgePlanResult,
    ReconstructionFeederPlanResult,
    ReconstructionFixpointFeederPlanResult,
    ReconstructionPreheaderBridgeResult,
    collect_reconstruction_claims,
    collect_suppressed_bridge_pairs,
    plan_fixpoint_feeder_modifications,
    plan_reconstruction_bridge_modifications,
    plan_reconstruction_feeder_modifications,
    plan_reconstruction_preheader_bridge,
)
from d810.cfg.reconstruction_return_planning import (
    ReconstructionReturnPlanResult,
    plan_reconstruction_return_modifications,
)


@dataclass(frozen=True, slots=True)
class ReconstructionPostprocessPlanningResult:
    preheader_bridge: ReconstructionPreheaderBridgeResult
    bridge_plan: ReconstructionBridgePlanResult
    feeder_plan: ReconstructionFeederPlanResult
    fixpoint_feeder_plan: ReconstructionFixpointFeederPlanResult
    return_plan: ReconstructionReturnPlanResult
    claimed_sources: frozenset[int]
    claimed_targets: frozenset[int]


def plan_reconstruction_postprocess_modifications(
    *,
    dag,
    flow_graph,
    projected_flow_graph,
    builder,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    dispatcher,
    modifications: list,
    owned_blocks: set[int],
    rejected_metadata: list[dict[str, int | str | None]],
    constant_result,
    state_var_stkoff: int | None,
    artifact_return_blocks: set[int],
    common_return_corridor: set[int],
    node_by_key,
) -> ReconstructionPostprocessPlanningResult:
    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in bst_node_blocks)

    preheader_bridge = plan_reconstruction_preheader_bridge(
        dag=dag,
        flow_graph=flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        dispatcher=dispatcher,
    )

    planned_modifications = list(modifications)
    if preheader_bridge.modification is not None:
        planned_modifications.append(preheader_bridge.modification)

    claimed_sources, claimed_targets = collect_reconstruction_claims(
        planned_modifications,
        owned_blocks=owned_blocks,
    )
    suppressed_bridge_pairs = collect_suppressed_bridge_pairs(rejected_metadata)

    bridge_plan = plan_reconstruction_bridge_modifications(
        dag=dag,
        flow_graph=flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        claimed_sources=claimed_sources,
        claimed_targets=claimed_targets,
        suppressed_bridge_pairs=suppressed_bridge_pairs,
    )
    claimed_sources = set(bridge_plan.claimed_sources)
    claimed_targets = set(bridge_plan.claimed_targets)

    feeder_plan = plan_reconstruction_feeder_modifications(
        dag=dag,
        flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        claimed_sources=claimed_sources,
        claimed_targets=claimed_targets,
        suppressed_bridge_pairs=suppressed_bridge_pairs,
    )
    claimed_sources = set(feeder_plan.claimed_sources)
    claimed_targets = set(feeder_plan.claimed_targets)

    fixpoint_feeder_plan = plan_fixpoint_feeder_modifications(
        flow_graph=flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        claimed_sources=claimed_sources,
        constant_result=constant_result,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
    )
    claimed_sources = set(fixpoint_feeder_plan.claimed_sources)

    return_plan = plan_reconstruction_return_modifications(
        dag=dag,
        flow_graph=flow_graph,
        builder=builder,
        claimed_sources=claimed_sources,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        common_return_corridor=common_return_corridor,
        artifact_return_blocks=artifact_return_blocks,
        node_by_key=node_by_key,
    )
    claimed_sources = set(return_plan.claimed_sources)

    return ReconstructionPostprocessPlanningResult(
        preheader_bridge=preheader_bridge,
        bridge_plan=bridge_plan,
        feeder_plan=feeder_plan,
        fixpoint_feeder_plan=fixpoint_feeder_plan,
        return_plan=return_plan,
        claimed_sources=frozenset(int(serial) for serial in claimed_sources),
        claimed_targets=frozenset(int(serial) for serial in claimed_targets),
    )


__all__ = [
    "ReconstructionPostprocessPlanningResult",
    "plan_reconstruction_postprocess_modifications",
]
