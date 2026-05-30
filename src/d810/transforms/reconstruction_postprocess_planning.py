from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.reconstruction_bridge_planning import (
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
from d810.transforms.reconstruction_return_planning import (
    ReconstructionReturnPlanResult,
    plan_reconstruction_return_modifications,
)
from d810.transforms.mod_claims import collect_mod_claims


@dataclass(frozen=True, slots=True)
class ReconstructionPostprocessPlanningResult:
    preheader_bridge: ReconstructionPreheaderBridgeResult
    bridge_plan: ReconstructionBridgePlanResult
    feeder_plan: ReconstructionFeederPlanResult
    fixpoint_feeder_plan: ReconstructionFixpointFeederPlanResult
    return_plan: ReconstructionReturnPlanResult
    claimed_sources: frozenset[int]
    claimed_targets: frozenset[int]


def _fixpoint_claimed_sources(
    *,
    flow_graph,
    projected_flow_graph,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    dispatcher,
    constant_result,
    state_var_stkoff: int | None,
    claimed_sources: set[int],
    planned_modifications: list,
) -> set[int]:
    """Return the source claims that should block fixpoint feeder rewrites.

    ``owned_blocks`` and typed-clone source claims are intentionally
    conservative for most planning phases, but they are too coarse for the
    final fixpoint-feeder pass.  Earlier reconstruction can legitimately claim
    a shared block while redirecting all old local predecessors away from it,
    leaving the original block as a reachable residual state writer for a newly
    bridged predecessor.  If the projected source still exits to the dispatcher
    and its concrete state resolves to a non-BST target, allow the fixpoint pass
    to rewrite that outgoing edge.
    """

    fixpoint_claimed = set(int(source) for source in claimed_sources)
    if (
        dispatcher is None
        or constant_result is None
        or state_var_stkoff is None
        or not hasattr(constant_result, "out_stk_maps")
    ):
        return fixpoint_claimed

    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in bst_node_blocks)

    for source in tuple(sorted(fixpoint_claimed)):
        projected_block = (
            projected_flow_graph.get_block(source)
            if projected_flow_graph is not None
            else None
        )
        if projected_block is None or getattr(projected_block, "nsucc", 0) != 1:
            continue
        projected_target = int(projected_block.succs[0])
        if projected_target != int(dispatcher_serial) and projected_target not in bst_set:
            continue

        out_map = constant_result.out_stk_maps.get(source, {})
        state_val = out_map.get(state_var_stkoff)
        if state_val is None:
            continue
        resolved = dispatcher.lookup(state_val)
        if resolved is None or int(resolved) in bst_set or int(resolved) == source:
            continue

        fixpoint_claimed.discard(source)

    for mod in planned_modifications:
        source_serial = getattr(mod, "source_serial", None)
        per_pred_targets = getattr(mod, "per_pred_targets", None)
        if source_serial is None or not per_pred_targets:
            continue

        source = int(source_serial)
        block = flow_graph.get_block(source)
        if block is None or block.nsucc != 1:
            continue
        old_target = int(block.succs[0])
        if old_target != int(dispatcher_serial) and old_target not in bst_set:
            continue

        out_map = constant_result.out_stk_maps.get(source, {})
        state_val = out_map.get(state_var_stkoff)
        if state_val is None:
            continue
        resolved = dispatcher.lookup(state_val)
        if resolved is None or int(resolved) in bst_set:
            continue

        duplicate_targets = {
            int(target_serial) for _pred_serial, target_serial in per_pred_targets
        }
        if duplicate_targets != {int(resolved)}:
            continue

        fixpoint_claimed.discard(source)

    return fixpoint_claimed


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
    fixpoint_redirect_veto=None,
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
        redirect_veto=fixpoint_redirect_veto,
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

    post_feeder_modifications = (
        list(planned_modifications)
        + list(bridge_plan.modifications)
        + list(feeder_plan.modifications)
    )
    mod_claimed_sources, _mod_claimed_targets = collect_mod_claims(
        post_feeder_modifications
    )
    fixpoint_blocking_sources = _fixpoint_claimed_sources(
        flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        dispatcher=dispatcher,
        constant_result=constant_result,
        state_var_stkoff=state_var_stkoff,
        claimed_sources=set(mod_claimed_sources) | set(claimed_sources),
        planned_modifications=post_feeder_modifications,
    )

    fixpoint_feeder_plan = plan_fixpoint_feeder_modifications(
        flow_graph=flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        claimed_sources=fixpoint_blocking_sources,
        constant_result=constant_result,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
        redirect_veto=fixpoint_redirect_veto,
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
