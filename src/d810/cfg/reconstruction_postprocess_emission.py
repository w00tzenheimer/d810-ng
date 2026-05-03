from __future__ import annotations

import os
from dataclasses import dataclass

from d810.core import logging
from d810.core.typing import TYPE_CHECKING, Callable
from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.plan import compile_patch_plan
from d810.cfg.reconstruction_postprocess_planning import (
    plan_reconstruction_postprocess_modifications,
)
from d810.cfg.reconstruction_rescue_emission import (
    execute_reconstruction_entry_island_rescues,
    execute_reconstruction_late_island_rescues,
)
from d810.cfg.residual_alias_emission import emit_residual_alias_modifications
from d810.cfg.terminal_family_split import plan_terminal_family_splits

if TYPE_CHECKING:
    from d810.recon.flow.residual_alias_discovery import (
        ResidualAliasDiscoveryResult,
    )

# Callback signature for the recon-layer residual-alias discovery producer.
# Injected by the optimizers/hodur caller to avoid a cfg -> recon runtime
# import (which the layered-architecture import-linter contract forbids).
DiscoverResidualAliasOverridesFn = Callable[..., "ResidualAliasDiscoveryResult"]

logger = logging.getLogger(
    "D810.cfg.reconstruction_postprocess_execution",
    logging.DEBUG,
)

_PHASE_PROBE_WATCH_BLOCKS = (
    8, 11, 20, 32, 35, 45, 64, 69, 81, 83, 95, 100, 104, 156, 184, 187, 192, 195, 200, 203,
)


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


def _log_postprocess_phase_probe(
    *,
    phase: str,
    projected_flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    residual_dispatcher_preds: tuple[int, ...] | list[int] | set[int] = (),
    compute_reachable_blocks=None,
) -> None:
    if projected_flow_graph is None:
        return
    reachable_set: set[int] = set()
    if callable(compute_reachable_blocks):
        try:
            reachable_blocks = compute_reachable_blocks(
                projected_flow_graph,
                start_serial=getattr(projected_flow_graph, "entry_serial", None),
            )
            reachable_set = {int(serial) for serial in (reachable_blocks or ())}
        except Exception:
            logger.debug(
                "RECON POST PHASE PROBE[%s]: reachable-block computation failed",
                phase,
                exc_info=True,
            )
    watched_snapshots: list[str] = []
    get_block = getattr(projected_flow_graph, "get_block", None)
    block_map = getattr(projected_flow_graph, "blocks", {}) or {}
    for serial in _PHASE_PROBE_WATCH_BLOCKS:
        block = None
        if callable(get_block):
            block = get_block(int(serial))
        elif block_map:
            block = block_map.get(int(serial))
        if block is None:
            watched_snapshots.append(
                f"{int(serial)}:missing:reachable={int(serial) in reachable_set}"
            )
            continue
        preds = tuple(int(pred) for pred in getattr(block, "preds", ()) or ())
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
        watched_snapshots.append(
            f"{int(serial)}:reachable={int(serial) in reachable_set}:preds={preds}:succs={succs}"
        )
    logger.info(
        "RECON POST PHASE PROBE[%s]: mods=%d owned_blocks=%d owned_edges=%d residual_preds=%s watched=%s",
        phase,
        len(modifications),
        len(owned_blocks),
        len(owned_edges),
        tuple(sorted(int(serial) for serial in residual_dispatcher_preds)),
        watched_snapshots,
    )


def _build_node_by_key(dag) -> dict:
    node_by_key: dict = {}
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        try:
            hash(key)
        except Exception:
            continue
        node_by_key[key] = node
    return node_by_key


def _collect_shared_suffix_blocks(dag) -> set[int]:
    shared_blocks: set[int] = set()
    for node in getattr(dag, "nodes", ()) or ():
        shared_blocks.update(
            int(serial)
            for serial in (getattr(node, "shared_suffix_blocks", ()) or ())
        )
    return shared_blocks


def emit_residual_alias_overrides(
    *,
    dag,
    flow_graph,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    state_var_stkoff: int | None,
    constant_result,
    resolve_effective_target_entry,
    build_reconstruction_candidate,
    analysis_mba,
    dispatcher_lookup,
    dispatcher,
    residual_dispatcher_preds: tuple[int, ...],
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    discover_overrides_fn: DiscoverResidualAliasOverridesFn | None = None,
) -> int:
    """Residual raw-alias reconstruction solver (public entry point).

    Thin facade: delegates DAG-walk classification to the injected
    ``discover_overrides_fn`` (wired to
    :func:`d810.recon.flow.residual_alias_discovery.discover_residual_alias_overrides`
    by the optimizers caller) and modification emission to
    :func:`d810.cfg.residual_alias_emission.emit_residual_alias_modifications`.
    Callback injection avoids a cfg -> recon runtime import, keeping the
    layered-architecture import-linter contract green.

    Returns ``0`` when ``discover_overrides_fn`` is None (no recon wiring
    supplied), matching the historical early-exit when
    ``build_reconstruction_candidate`` is None.
    """
    if (
        state_var_stkoff is None
        or build_reconstruction_candidate is None
        or discover_overrides_fn is None
    ):
        return 0

    node_by_key = _build_node_by_key(dag)
    shared_suffix_blocks = _collect_shared_suffix_blocks(dag)
    bst_node_blocks = set(int(serial) for serial in getattr(dag, "bst_node_blocks", ()) or ())
    bst_node_blocks.add(int(dispatcher_serial))

    discovery = discover_overrides_fn(
        dag=dag,
        flow_graph=flow_graph,
        dispatcher_region=dispatcher_region,
        dispatcher_serial=dispatcher_serial,
        state_var_stkoff=state_var_stkoff,
        constant_result=constant_result,
        resolve_effective_target_entry=resolve_effective_target_entry,
        build_reconstruction_candidate=build_reconstruction_candidate,
        analysis_mba=analysis_mba,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        residual_dispatcher_preds=residual_dispatcher_preds,
        node_by_key=node_by_key,
        shared_suffix_blocks=shared_suffix_blocks,
        bst_node_blocks=bst_node_blocks,
    )
    return emit_residual_alias_modifications(
        discovery=discovery,
        flow_graph=flow_graph,
        node_by_key=node_by_key,
        dispatcher_serial=dispatcher_serial,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )


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
    owned_edges: set[tuple[int, int]],
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
    classify_artifact_return_blocks,
    collect_common_return_corridor,
    collect_terminal_family_report,
    resolve_effective_target_entry=None,
    build_reconstruction_candidate=None,
    build_projected_mba=None,
    discover_residual_alias_overrides_fn: DiscoverResidualAliasOverridesFn | None = None,
    fixpoint_redirect_veto=None,
) -> ReconstructionPostprocessExecutionResult:
    initial_modification_count = len(modifications)
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
    _log_postprocess_phase_probe(
        phase="post_initial_projection",
        projected_flow_graph=projected_flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        compute_reachable_blocks=compute_reachable_blocks,
    )

    # D810_RECON_SKIP_ISLAND_RESCUE=1 → skip early + late entry-island rescue
    # (technique 5 of the 5-item port list). Diagnostic knob for the
    # reconstruction-contribution harness.
    _skip_island_rescue = (
        os.getenv("D810_RECON_SKIP_ISLAND_RESCUE", "").strip() == "1"
    )
    if _skip_island_rescue:
        from d810.cfg.entry_island_rescue_planning import EntryIslandRescueRun
        entry_island_rescue_run = EntryIslandRescueRun(
            projected_flow_graph=projected_flow_graph,
            emitted_count=0,
            iterations=(),
        )
    else:
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
    _log_postprocess_phase_probe(
        phase="post_entry_island_rescue",
        projected_flow_graph=projected_flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        compute_reachable_blocks=compute_reachable_blocks,
    )

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
    # D810_RECON_SKIP_RESIDUAL_ALIAS=1 → skip the early + late residual raw-alias
    # reconstruction overrides (technique 1 of the 5-item port list).
    _skip_residual_alias = (
        os.getenv("D810_RECON_SKIP_RESIDUAL_ALIAS", "").strip() == "1"
    )
    early_residual_raw_alias_redirect_count = 0 if _skip_residual_alias else emit_residual_alias_overrides(
        dag=corrected_dag,
        flow_graph=projected_flow_graph,
        dispatcher_region=dispatcher_region,
        dispatcher_serial=dispatcher_serial,
        state_var_stkoff=state_var_stkoff,
        constant_result=constant_result,
        resolve_effective_target_entry=resolve_effective_target_entry,
        build_reconstruction_candidate=build_reconstruction_candidate,
        analysis_mba=(
            build_projected_mba(projected_flow_graph)
            if callable(build_projected_mba)
            else None
        ),
        dispatcher_lookup=(getattr(dispatcher, "lookup", None) if dispatcher is not None else None),
        dispatcher=dispatcher,
        residual_dispatcher_preds=residual_dispatcher_preds,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        discover_overrides_fn=discover_residual_alias_overrides_fn,
    )
    if early_residual_raw_alias_redirect_count:
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
    _log_postprocess_phase_probe(
        phase="post_early_residual_alias",
        projected_flow_graph=projected_flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        residual_dispatcher_preds=residual_dispatcher_preds,
        compute_reachable_blocks=compute_reachable_blocks,
    )

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
        fixpoint_redirect_veto=fixpoint_redirect_veto,
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
    if all_extra_mods:
        projected_flow_graph = _project_flow_graph(flow_graph, modifications)
        _log_postprocess_phase_probe(
            phase="post_bridge_feeder_return",
            projected_flow_graph=projected_flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            residual_dispatcher_preds=residual_dispatcher_preds,
            compute_reachable_blocks=compute_reachable_blocks,
        )

        if _skip_island_rescue:
            from d810.cfg.entry_island_rescue_planning import EntryIslandRescueRun
            late_entry_island_rescue_run = EntryIslandRescueRun(
                projected_flow_graph=projected_flow_graph,
                emitted_count=0,
                iterations=(),
            )
        else:
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
        _log_postprocess_phase_probe(
            phase="post_late_entry_island_rescue",
            projected_flow_graph=projected_flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            residual_dispatcher_preds=residual_dispatcher_preds,
            compute_reachable_blocks=compute_reachable_blocks,
        )

        if not residual_dispatcher_preds:
            allow_post_apply_bst_cleanup = True
            post_apply_bst_cleanup_reason = None

        if _skip_island_rescue:
            from d810.cfg.entry_island_rescue_planning import EntryIslandRescueRun
            from d810.cfg.reconstruction_rescue_emission import (
                LateReconstructionRescueRun,
            )
            late_island_rescue_result = LateReconstructionRescueRun(
                run=EntryIslandRescueRun(
                    projected_flow_graph=projected_flow_graph,
                    emitted_count=0,
                    iterations=(),
                ),
                diagnostics=(),
            )
        else:
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
        _log_postprocess_phase_probe(
            phase="post_late_island_rescue",
            projected_flow_graph=projected_flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            residual_dispatcher_preds=residual_dispatcher_preds,
            compute_reachable_blocks=compute_reachable_blocks,
        )

    residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
        projected_flow_graph,
        dispatcher_serial,
        bst_node_blocks=dispatcher_region,
        reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
    )
    if not residual_dispatcher_preds:
        allow_post_apply_bst_cleanup = True
        post_apply_bst_cleanup_reason = None
    residual_raw_alias_redirect_count = 0
    if not early_residual_raw_alias_redirect_count and not _skip_residual_alias:
        residual_raw_alias_redirect_count = emit_residual_alias_overrides(
            dag=corrected_dag,
            flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            constant_result=constant_result,
            resolve_effective_target_entry=resolve_effective_target_entry,
            build_reconstruction_candidate=build_reconstruction_candidate,
            analysis_mba=(
                build_projected_mba(projected_flow_graph)
                if callable(build_projected_mba)
                else None
            ),
            dispatcher_lookup=(
                getattr(dispatcher, "lookup", None) if dispatcher is not None else None
            ),
            dispatcher=dispatcher,
            residual_dispatcher_preds=residual_dispatcher_preds,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            discover_overrides_fn=discover_residual_alias_overrides_fn,
        )
    if residual_raw_alias_redirect_count:
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
    _log_postprocess_phase_probe(
        phase="post_late_residual_alias",
        projected_flow_graph=projected_flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        residual_dispatcher_preds=residual_dispatcher_preds,
        compute_reachable_blocks=compute_reachable_blocks,
    )

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
    _log_postprocess_phase_probe(
        phase="post_terminal_family_split",
        projected_flow_graph=projected_flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        residual_dispatcher_preds=residual_dispatcher_preds,
        compute_reachable_blocks=compute_reachable_blocks,
    )

    if (
        len(modifications) > initial_modification_count
        and post_apply_bst_cleanup_reason is None
    ):
        allow_post_apply_bst_cleanup = False
        post_apply_bst_cleanup_reason = "residual_dispatcher_redirects"

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
