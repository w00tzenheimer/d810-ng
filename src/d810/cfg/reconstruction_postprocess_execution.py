from __future__ import annotations

from dataclasses import dataclass, replace

from d810.core import logging
from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.plan import compile_patch_plan
from d810.cfg.reconstruction_execution import (
    execute_primary_reconstruction_modifications,
)
from d810.cfg.reconstruction_postprocess_planning import (
    plan_reconstruction_postprocess_modifications,
)
from d810.cfg.reconstruction_rescue_execution import (
    execute_reconstruction_entry_island_rescues,
    execute_reconstruction_late_island_rescues,
)
from d810.cfg.terminal_family_split import plan_terminal_family_splits

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


def _is_raw_state_label(label: str, state_value: int) -> bool:
    if label.endswith("_fallback"):
        return False
    try:
        return int(label, 16) == (state_value & 0xFFFFFFFF)
    except Exception:
        return False


def _iter_residual_raw_alias_edges(
    dag,
    *,
    residual_dispatcher_preds: tuple[int, ...],
):
    residual_set = {int(serial) for serial in residual_dispatcher_preds}
    seen: set[tuple[int, int, tuple[int, ...], int | None]] = set()
    for edge in getattr(dag, "edges", ()) or ():
        target_state = getattr(edge, "target_state", None)
        target_label = str(getattr(edge, "target_label", "") or "")
        if target_state is None or not _is_raw_state_label(target_label, int(target_state)):
            continue
        ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
        source_block = None
        if ordered_path and int(ordered_path[-1]) in residual_set:
            source_block = int(ordered_path[-1])
        else:
            source_anchor = getattr(edge, "source_anchor", None)
            anchor_block = getattr(source_anchor, "block_serial", None)
            if anchor_block is not None and int(anchor_block) in residual_set:
                source_block = int(anchor_block)
            elif not residual_set:
                # After region lowering, dispatcher predecessors may already be gone
                # even though a raw alias still survives on a post-source exit tail.
                # In that case, only admit tails that extend past the source anchor;
                # this keeps the late phase narrow while still catching shapes like
                # blk[15].fallthrough -> blk[16] -> 0x4C77464F.
                if ordered_path and anchor_block is not None and int(ordered_path[-1]) != int(anchor_block):
                    source_block = int(ordered_path[-1])
        if source_block is None:
            continue
        key = (
            int(source_block),
            int(target_state) & 0xFFFFFFFF,
            ordered_path,
            int(getattr(edge, "target_entry_anchor", -1))
            if getattr(edge, "target_entry_anchor", None) is not None
            else None,
        )
        if key in seen:
            continue
        seen.add(key)
        yield int(source_block), edge


def _resolve_target_label_for_entry(
    dag,
    *,
    target_entry: int,
    fallback_label: str,
) -> str:
    for node in getattr(dag, "nodes", ()) or ():
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is None or int(entry_anchor) != int(target_entry):
            continue
        label = str(getattr(node, "state_label", "") or "")
        if label:
            return label
    return fallback_label


def _emit_residual_raw_alias_reconstruction_overrides(
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
) -> int:
    if state_var_stkoff is None or build_reconstruction_candidate is None:
        return 0

    node_by_key = _build_node_by_key(dag)
    shared_suffix_blocks = _collect_shared_suffix_blocks(dag)
    bst_node_blocks = set(int(serial) for serial in getattr(dag, "bst_node_blocks", ()) or ())
    bst_node_blocks.add(int(dispatcher_serial))

    raw_candidates: list[object] = []
    seen_candidates: set[tuple[str, int, int, int | None, int | None, tuple[int, ...]]] = set()

    for source_block, edge in _iter_residual_raw_alias_edges(
        dag,
        residual_dispatcher_preds=residual_dispatcher_preds,
    ):
        target_entry = getattr(edge, "target_entry_anchor", None)
        if (
            resolve_effective_target_entry is not None
            and analysis_mba is not None
        ):
            resolution = resolve_effective_target_entry(
                dag,
                edge,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=int(state_var_stkoff),
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=analysis_mba,
            )
            resolved_target_entry = getattr(resolution, "target_entry", None)
            if resolved_target_entry is not None:
                target_entry = resolved_target_entry
        if target_entry is None:
            continue
        normalized_target = int(target_entry)
        original_target_entry = getattr(edge, "target_entry_anchor", None)
        if (
            normalized_target == int(source_block)
            or normalized_target in bst_node_blocks
        ):
            continue
        if (
            original_target_entry is not None
            and int(original_target_entry) == normalized_target
            and not _is_raw_state_label(
                str(getattr(edge, "target_label", "") or ""),
                int(getattr(edge, "target_state", 0)) & 0xFFFFFFFF,
            )
        ):
            continue

        normalized_edge = replace(
            edge,
            target_entry_anchor=normalized_target,
            target_label=_resolve_target_label_for_entry(
                dag,
                target_entry=normalized_target,
                fallback_label=str(getattr(edge, "target_label", "") or ""),
            ),
        )
        candidate, _rejection = build_reconstruction_candidate(
            normalized_edge,
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            state_var_stkoff=int(state_var_stkoff),
            constant_result=constant_result,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        )
        if candidate is None:
            continue
        candidate_key = (
            str(getattr(candidate, "emission_mode", "")),
            int(getattr(candidate, "horizon_block", -1)),
            int(getattr(candidate, "target_entry", -1)),
            (
                int(getattr(candidate, "first_shared_block"))
                if getattr(candidate, "first_shared_block", None) is not None
                else None
            ),
            (
                int(getattr(candidate, "via_pred"))
                if getattr(candidate, "via_pred", None) is not None
                else None
            ),
            tuple(int(serial) for serial in getattr(candidate.edge, "ordered_path", ()) or ()),
        )
        if candidate_key in seen_candidates:
            continue
        seen_candidates.add(candidate_key)
        raw_candidates.append(candidate)

    if not raw_candidates:
        return 0

    pre_modification_count = len(modifications)
    execute_primary_reconstruction_modifications(
        raw_candidates=raw_candidates,
        flow_graph=flow_graph,
        node_by_key=node_by_key,
        dispatcher_serial=int(dispatcher_serial),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )
    return len(modifications) - pre_modification_count


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
    early_residual_raw_alias_redirect_count = _emit_residual_raw_alias_reconstruction_overrides(
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
    if not early_residual_raw_alias_redirect_count:
        residual_raw_alias_redirect_count = _emit_residual_raw_alias_reconstruction_overrides(
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
