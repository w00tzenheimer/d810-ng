from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.plan import compile_patch_plan
from d810.cfg.reconstruction_postprocess_planning import (
    plan_reconstruction_postprocess_modifications,
)
from d810.cfg.reconstruction_rescue_execution import (
    execute_reconstruction_entry_island_rescues,
    execute_reconstruction_late_island_rescues,
)
from d810.cfg.terminal_family_split import plan_terminal_family_splits


@dataclass(frozen=True, slots=True)
class ReconstructionPostprocessExecutionResult:
    projected_flow_graph: object
    residual_dispatcher_preds: tuple[int, ...]
    initial_residual_dispatcher_preds: tuple[int, ...]
    allow_post_apply_bst_cleanup: bool
    post_apply_bst_cleanup_reason: str | None
    entry_island_rescue_run: object | None = None
    late_entry_island_rescue_run: object | None = None
    late_island_rescue_result: object | None = None
    terminal_family_split_run: object | None = None
    postprocess_plan: object | None = None
    artifact_return_blocks: frozenset[int] = frozenset()
    common_return_corridor: frozenset[int] = frozenset()
    state_var_stkoff: int | None = None
    state_constants_count: int = 0
    flow_graph_block_count: int = 0


def _project_flow_graph(base_flow_graph, modifications: list):
    try:
        patch_plan = compile_patch_plan(modifications, base_flow_graph)
        return project_post_state(base_flow_graph, patch_plan)
    except Exception:
        return base_flow_graph


def execute_reconstruction_postprocess(
    *,
    dag,
    corrected_dag,
    flow_graph,
    modifications: list,
    builder,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    bst_result,
    state_machine,
    state_var_stkoff: int | None,
    constant_result,
    node_by_key,
    rejected_metadata: list[dict[str, int | str | None]],
    owned_blocks: set[int],
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
    classify_artifact_return_blocks,
    collect_common_return_corridor,
    collect_terminal_family_report,
) -> ReconstructionPostprocessExecutionResult:
    projected_flow_graph = flow_graph
    residual_dispatcher_preds: tuple[int, ...] = ()
    initial_residual_dispatcher_preds: tuple[int, ...] = ()
    allow_post_apply_bst_cleanup = True
    post_apply_bst_cleanup_reason: str | None = None
    entry_island_rescue_run = None
    late_entry_island_rescue_run = None
    late_island_rescue_result = None
    terminal_family_split_run = None
    postprocess_plan = None
    artifact_return_blocks: set[int] = set()
    common_return_corridor: set[int] = set()
    state_constants_count = len(
        state_machine.state_constants if state_machine is not None else set()
    )
    flow_graph_block_count = len(getattr(flow_graph, "blocks", {}) or {})

    if dispatcher_serial < 0:
        return ReconstructionPostprocessExecutionResult(
            projected_flow_graph=projected_flow_graph,
            residual_dispatcher_preds=residual_dispatcher_preds,
            initial_residual_dispatcher_preds=initial_residual_dispatcher_preds,
            allow_post_apply_bst_cleanup=allow_post_apply_bst_cleanup,
            post_apply_bst_cleanup_reason=post_apply_bst_cleanup_reason,
            state_var_stkoff=state_var_stkoff,
            state_constants_count=state_constants_count,
            flow_graph_block_count=flow_graph_block_count,
        )

    projected_flow_graph = _project_flow_graph(flow_graph, modifications)

    entry_island_rescue_run = execute_reconstruction_entry_island_rescues(
        dag=corrected_dag,
        base_flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        modifications=modifications,
        dispatcher_region=dispatcher_region,
        collect_seeds=lambda dag, **kwargs: collect_entry_island_rescue_seeds(
            dag,
            reachable_blocks=kwargs["reachable_blocks"],
            dispatcher_region=kwargs["dispatcher_region"],
            claimed_targets=collect_mod_claims(modifications)[1],
        ),
        compute_reachable_blocks=lambda fg: compute_reachable_blocks(
            fg,
            start_serial=getattr(fg, "entry_serial", None),
        ),
    )
    if entry_island_rescue_run.emitted_count:
        projected_flow_graph = _project_flow_graph(flow_graph, modifications)

    initial_residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
        projected_flow_graph,
        dispatcher_serial,
        bst_node_blocks=dispatcher_region,
        reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
    )
    residual_dispatcher_preds = initial_residual_dispatcher_preds
    if residual_dispatcher_preds:
        allow_post_apply_bst_cleanup = False
        post_apply_bst_cleanup_reason = "residual_dispatcher_predecessors"

    dispatcher = getattr(bst_result, "dispatcher", None)
    bst_set = set(dag.bst_node_blocks)
    bst_set.add(dispatcher_serial)

    if state_var_stkoff is not None:
        state_constants = state_machine.state_constants if state_machine is not None else set()
        artifact_return_blocks = classify_artifact_return_blocks(
            flow_graph,
            state_var_stkoff=state_var_stkoff,
            state_constants=state_constants,
        )

    common_return_corridor = collect_common_return_corridor(
        dag,
        flow_graph,
        bst_node_blocks=bst_set,
        dispatcher_serial=dispatcher_serial,
    )

    postprocess_plan = plan_reconstruction_postprocess_modifications(
        dag=dag,
        flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_set,
        dispatcher=dispatcher,
        modifications=modifications,
        owned_blocks=owned_blocks,
        rejected_metadata=rejected_metadata,
        constant_result=constant_result,
        state_var_stkoff=state_var_stkoff,
        artifact_return_blocks=artifact_return_blocks,
        common_return_corridor=common_return_corridor,
        node_by_key=node_by_key,
    )

    preheader_bridge = postprocess_plan.preheader_bridge
    if preheader_bridge.modification is not None:
        modifications.append(preheader_bridge.modification)

    bridge_mods = list(postprocess_plan.bridge_plan.modifications)
    if bridge_mods:
        modifications.extend(bridge_mods)

    feeder_mods = list(postprocess_plan.feeder_plan.modifications)
    feeder_mods.extend(postprocess_plan.fixpoint_feeder_plan.modifications)
    if feeder_mods:
        modifications.extend(feeder_mods)

    return_mods = list(postprocess_plan.return_plan.modifications)
    if return_mods:
        modifications.extend(return_mods)

    all_extra_mods = bridge_mods + return_mods + feeder_mods
    projected_flow_graph = flow_graph
    if all_extra_mods:
        projected_flow_graph = _project_flow_graph(flow_graph, modifications)

        late_entry_island_rescue_run = execute_reconstruction_entry_island_rescues(
            dag=dag,
            base_flow_graph=flow_graph,
            projected_flow_graph=projected_flow_graph,
            builder=builder,
            modifications=modifications,
            dispatcher_region=dispatcher_region,
            collect_seeds=lambda dag, **kwargs: collect_entry_island_rescue_seeds(
                dag,
                reachable_blocks=kwargs["reachable_blocks"],
                dispatcher_region=kwargs["dispatcher_region"],
                claimed_targets=collect_mod_claims(modifications)[1],
            ),
            compute_reachable_blocks=lambda fg: compute_reachable_blocks(
                fg,
                start_serial=getattr(fg, "entry_serial", None),
            ),
        )
        if late_entry_island_rescue_run.emitted_count:
            projected_flow_graph = _project_flow_graph(flow_graph, modifications)

        residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
            projected_flow_graph,
            dispatcher_serial,
            bst_node_blocks=dispatcher_region,
            reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
        )
        if not residual_dispatcher_preds:
            allow_post_apply_bst_cleanup = True
            post_apply_bst_cleanup_reason = None

        late_island_rescue_result = execute_reconstruction_late_island_rescues(
            dag=dag,
            base_flow_graph=flow_graph,
            projected_flow_graph=projected_flow_graph,
            builder=builder,
            modifications=modifications,
            dispatcher_region=dispatcher_region,
            dispatcher=getattr(bst_result, "dispatcher", None),
            collect_seeds=lambda dag, **kwargs: collect_late_entry_island_rescue_seeds(
                dag,
                projected_flow_graph=kwargs["projected_flow_graph"],
                reachable_blocks=kwargs["reachable_blocks"],
                dispatcher_region=kwargs["dispatcher_region"],
            ),
            collect_diagnostics=collect_late_entry_island_diagnostics,
            compute_reachable_blocks=lambda fg: compute_reachable_blocks(
                fg,
                start_serial=getattr(fg, "entry_serial", None),
            ),
        )
        if late_island_rescue_result.run.emitted_count:
            projected_flow_graph = _project_flow_graph(flow_graph, modifications)

    terminal_family_split_run = plan_terminal_family_splits(
        dag=dag,
        base_flow_graph=flow_graph,
        projected_flow_graph=projected_flow_graph,
        dispatcher_region=dispatcher_region,
        state_var_stkoff=state_var_stkoff,
        builder=builder,
        modifications=modifications,
        collect_report=collect_terminal_family_report,
        compute_reachable_blocks=lambda fg: compute_reachable_blocks(
            fg,
            start_serial=getattr(fg, "entry_serial", None),
        ),
    )
    if terminal_family_split_run.emitted_count:
        projected_flow_graph = _project_flow_graph(flow_graph, modifications)

    return ReconstructionPostprocessExecutionResult(
        projected_flow_graph=projected_flow_graph,
        residual_dispatcher_preds=tuple(int(serial) for serial in residual_dispatcher_preds),
        initial_residual_dispatcher_preds=tuple(
            int(serial) for serial in initial_residual_dispatcher_preds
        ),
        allow_post_apply_bst_cleanup=allow_post_apply_bst_cleanup,
        post_apply_bst_cleanup_reason=post_apply_bst_cleanup_reason,
        entry_island_rescue_run=entry_island_rescue_run,
        late_entry_island_rescue_run=late_entry_island_rescue_run,
        late_island_rescue_result=late_island_rescue_result,
        terminal_family_split_run=terminal_family_split_run,
        postprocess_plan=postprocess_plan,
        artifact_return_blocks=frozenset(int(serial) for serial in artifact_return_blocks),
        common_return_corridor=frozenset(int(serial) for serial in common_return_corridor),
        state_var_stkoff=state_var_stkoff,
        state_constants_count=state_constants_count,
        flow_graph_block_count=flow_graph_block_count,
    )


__all__ = [
    "ReconstructionPostprocessExecutionResult",
    "execute_reconstruction_postprocess",
]
