"""LinearizedFlowGraphStrategy -- DAG-driven branch stitching.

Builds a live :class:`LinearizedStateDag` from the current CFG and uses that
state-level semantic graph as the planning surface for redirect emission.

The current implementation prefers DAG-selected path tails and branch anchors,
and now also allows direct rewrites of shared 1-way dispatcher tails when the
tail block itself proves the same state->handler mapping. This lets LFG absorb
the late orphan-goto cases that previously required backward_pred_resolution.
"""
from __future__ import annotations

from dataclasses import replace
import os

import ida_hexrays

from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.transforms.lowering import LoweringMode
from d810.transforms.edit_simulator import project_post_state
from d810.transforms.edit_simulator import (
    graph_modifications_to_simulated_edits,
    simulate_edits,
)
from d810.transforms.plan import compile_patch_plan
from d810.transforms.dag_redirect_emission import (
    emit_dag_redirect,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.dispatcher_backedge_disconnect_emission import (
    disconnect_bst_comparison_nodes,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
    to_redirect_intent,
)
from d810.transforms.zero_state_write_emission import (
    ZsvSiteRequest,
    ZsvSource,
    collect_zero_state_writes,
)
from d810.transforms.linearized_flow_graph_fragment_planning import (
    LinearizedDagStructuredRegion,
    LinearizedFlowGraphPlanSetup,
    LinearizedFlowGraphStructuredRegionResult,
    flow_graph_block_serials,
    prepare_linearized_flow_graph_plan_setup,
    build_linearized_flow_graph_planning_callbacks,
    build_linearized_flow_graph_planning_context,
    execute_linearized_flow_graph_planning,
)
from d810.transforms.semantic_region_lowering import (
    build_region_contract_fallback_lowering,
    build_region_preferred_direct_lowering,
    build_region_preferred_conditional_lowering,
    collect_admissible_region_lowering_sites,
    override_exit_sites_with_child_region_entries,
)
from d810.transforms.path_tail_redirect_emission import (
    emit_path_tail_redirect,
)
from d810.transforms.projected_alias_normalization_planning import (
    normalize_projected_alias_handoffs,
)
from d810.transforms.residual_branch_anchor_emission import (
    emit_residual_branch_anchor_handoff,
)
from d810.transforms.residual_dispatcher_handoff_emission import (
    emit_residual_dispatcher_handoffs,
)
from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.core.typing import TYPE_CHECKING, AbstractSet

from d810.transforms.modification_builder import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    blk_label,
)
from d810.capabilities.constant_fixpoint import ConstantFixpointBackend
from d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend import (
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND,
)
from d810.optimizers.microcode.flow.flattening.hodur.live_microcode_properties import (
    DEFAULT_HODUR_LIVE_MICROCODE_PROPERTIES,
    HodurLiveMicrocodePropertiesBackend,
)
from d810.optimizers.microcode.flow.flattening.hodur.lfg_handoff_resolution_backend import (
    AssignmentMapHandoffTargetRequest,
    DEFAULT_HODUR_LFG_HANDOFF_RESOLUTION_BACKEND,
    EffectiveTargetEntryRequest,
    ImmediateHandoffTargetRequest,
    LinearizedFlowGraphHandoffResolutionBackend,
    ProjectedPathTailTargetRequest,
    ProjectedSnapshotHandoffTargetRequest,
    SynthesizedHandoffTargetRequest,
)
from d810.transforms.projected_topology_backend import (
    HodurProjectedTopologyBackend,
    ProjectedTopologyBackend,
)
from d810.optimizers.microcode.flow.flattening.residual_handoff_resolution import (
    has_live_exact_residual_handoff_with_valranges,
    is_semantic_handoff_redirect,
    resolve_singleton_state_write_value,
)
from d810.analyses.control_flow.graph_reachability import (
    collect_dispatcher_predecessors,
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.analyses.control_flow.dag_redirect_discovery import (
    find_foreign_exact_entry_owner,
    select_plannable_dag_edges,
)
from d810.analyses.control_flow.linearized_dag_round_discovery import (
    build_linearized_dag_round_summary,
)
from d810.analyses.control_flow.round_discovery_context_probe import (
    compare_round_context_to_rebuild,
    probe_enabled as _round_ctx_probe_enabled,
)


def _round_ctx_probe_wrap(snapshot, inner):
    """Wrap ``build_linearized_dag_round_summary`` with an env-gated equivalence
    probe against ``snapshot.discovery`` — fires only on the FIRST round summary
    build of the pass.

    ``snapshot.discovery`` is the pass-entry frozen DAG/indexes/structured-
    regions view. ``round_summary`` is the round-local rebuild against the
    PROJECTED flow_graph (original + cumulative modifications from earlier
    rounds). They are only expected to match on round 1 (pass-entry inputs).
    Round 2+ divergence is the intended pass-vs-round scope boundary, not a
    bug.

    When ``D810_RECON_ROUND_CTX_PROBE=1`` AND ``snapshot.discovery`` is present,
    emit ONE INFO line on round 1 only:
        ``ROUND CTX DAG EQUIV: match=yes``
        ``ROUND CTX DAG EQUIV: match=no mismatches=[...]``
    Subsequent round calls are silently delegated. B1 step 1 wiring — no
    behavior change.
    """
    # Closure-local flag so each wrapped callback instance fires the probe
    # at most once per pass.
    state = {"probed": False}

    def _wrapped(*args, **kwargs):
        round_summary = inner(*args, **kwargs)
        if state["probed"]:
            return round_summary
        ctx = getattr(snapshot, "discovery", None)
        if ctx is not None and _round_ctx_probe_enabled():
            try:
                compare_round_context_to_rebuild(
                    ctx,
                    rebuild_dag=round_summary.dag,
                    rebuild_corrected_dag=ctx.corrected_dag,
                    rebuild_indexes=ctx.indexes,
                )
            except Exception:
                logger.debug(
                    "ROUND CTX DAG EQUIV probe failed", exc_info=True
                )
        state["probed"] = True
        return round_summary

    return _wrapped


from functools import partial as _partial

from d810.transforms.reconstruction_planning import plan_reconstruction_candidate
from d810.analyses.control_flow.reconstruction_candidate_builder import (
    ReconstructionCandidate,
    build_reconstruction_candidate as _build_reconstruction_candidate,
)

# Wire the real (transforms-bound) planner into the read-only candidate builder
# at this live caller (dissolution, llr-lyly).
build_reconstruction_candidate = _partial(
    _build_reconstruction_candidate,
    plan_reconstruction_candidate=plan_reconstruction_candidate,
)
from d810.analyses.control_flow.reconstruction_discovery import (
    collect_shared_suffix_blocks,
)
from d810.analyses.control_flow.residual_alias_discovery import (
    discover_residual_alias_overrides,
)
from d810.analyses.control_flow.residual_handoff_discovery import (
    collect_residual_source_handoff_facts,
    iter_residual_prefix_handoffs,
    resolve_contextual_dag_entry_for_state,
    resolve_cover_fallback_entry_for_state,
    resolve_dag_entry_for_state,
    resolve_normalized_alias_entry_for_state,
    resolve_redirect_safe_entry_from_node,
    resolve_redirect_safe_target_entry,
)
from d810.analyses.control_flow.exit_transition_discovery import (
    resolve_state_var_stkoff as discover_state_var_stkoff,
)
from d810.analyses.control_flow.shared_suffix_discovery import (
    can_rewrite_shared_suffix_family_fallback,
    has_prior_branch_cut_for_state,
    is_shared_suffix_conditional_tail,
    pred_split_target_reaches_via_pred,
)
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    LinearizationDecision,
    PlannerContextContribution,
)
from d810.evaluator.hexrays_microcode.use_def_dominance import (
    HexRaysUseDefSafetyBackend,
    UseDefSafetyBackend,
)
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_reporting import (
    log_dag_redirect_fallback_outcome,
    log_path_tail_redirect_outcome,
    log_residual_dispatcher_handoff_outcomes,
)
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    StateDagEdge,
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.recon_dag_index import build_dag_node_maps
from d810.analyses.control_flow.state_machine_analysis import (
    build_mba_view_from_flow_graph,
    find_last_state_write_site_snapshot,
    find_last_state_write_site_on_path_snapshot,
)
from d810.transforms.reconstruction_emission import (
    execute_primary_reconstruction_modifications,
)
from d810.transforms.reconstruction_postprocess_emission import (
    execute_reconstruction_postprocess,
)
from d810.analyses.control_flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report_from_graph,
)
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.analyses.control_flow.conditional_arm_canonicalization import (
    canonicalize_same_target_conditional_candidates,
)
from d810.analyses.control_flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.analyses.control_flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
)
from d810.analyses.control_flow.return_corridor_discovery import (
    collect_common_return_corridor,
)
from d810.analyses.control_flow.terminal_family_collection import (
    collect_terminal_family_report,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
        DispatcherStateMachine,
    )
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.linearized_flow_graph", logging.DEBUG)


class _StrategyProjectedTopologyBackend(HodurProjectedTopologyBackend):
    """Strategy-local seam for tests that patch historical topology helpers."""

    def build_projected_mba(self, flow_graph: object) -> object:
        return build_mba_view_from_flow_graph(flow_graph)

    def project_flow_graph(
        self,
        base_flow_graph: object,
        modifications: object,
    ) -> object:
        return project_post_state(
            base_flow_graph,
            compile_patch_plan(modifications, base_flow_graph),
        )

    def build_live_dag(
        self,
        current_flow_graph: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        mba: object | None,
        prefer_local_corridors: bool = True,
        corrected_dag_out: list[object] | None = None,
    ) -> object:
        return build_live_linearized_state_dag_from_graph(
            current_flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=pre_header_serial,
            initial_state=initial_state,
            handler_range_map=handler_range_map or {},
            bst_node_blocks=tuple(sorted(int(block) for block in bst_node_blocks)),
            diagnostics=tuple(diagnostics or ()),
            dispatcher=dispatcher,
            mba=mba,
            prefer_local_corridors=prefer_local_corridors,
            corrected_dag_out=corrected_dag_out,
        )


_USE_DEF_SAFETY_BACKEND: UseDefSafetyBackend = HexRaysUseDefSafetyBackend()
_LIVE_MICROCODE_PROPERTIES: HodurLiveMicrocodePropertiesBackend = (
    DEFAULT_HODUR_LIVE_MICROCODE_PROPERTIES
)
_PROJECTED_TOPOLOGY_BACKEND: ProjectedTopologyBackend = (
    _StrategyProjectedTopologyBackend()
)
_CONSTANT_FIXPOINT_BACKEND: ConstantFixpointBackend = (
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND
)
_HANDOFF_RESOLUTION_BACKEND: LinearizedFlowGraphHandoffResolutionBackend = (
    DEFAULT_HODUR_LFG_HANDOFF_RESOLUTION_BACKEND
)


def _lfg_bounded_postprocess_enabled() -> bool:
    return os.environ.get("D810_LFG_BOUNDED_POSTPROCESS", "1").strip() != "0"


def _lfg_use_def_veto_enabled() -> bool:
    return os.environ.get("D810_HCC_USE_DEF_VETO", "1").strip() != "0"


def _filter_lfg_use_def_vetoes(
    modifications: tuple[object, ...],
    *,
    enabled: bool,
    mba: object | None,
    flow_graph: FlowGraph,
    state_var_stkoff: int,
    backend: UseDefSafetyBackend = _USE_DEF_SAFETY_BACKEND,
) -> tuple[object, ...]:
    if not enabled or mba is None:
        return modifications

    use_def_filtered_modifications = []
    vetoed_use_def_count = 0
    for modification in modifications:
        if not isinstance(modification, RedirectGoto):
            use_def_filtered_modifications.append(modification)
            continue
        try:
            violations = backend.redirect_use_def_violations(
                to_redirect_intent(modification),
                mba,
                flow_graph,
            )
        except Exception:
            logger.debug(
                "LFG DAG: bounded postprocess use-def veto check raised for %r",
                modification,
                exc_info=True,
            )
            use_def_filtered_modifications.append(modification)
            continue
        if not violations:
            use_def_filtered_modifications.append(modification)
            continue
        real_violations = tuple(
            violation
            for violation in violations
            if int(violation.var_stkoff) != int(state_var_stkoff)
        )
        if not real_violations:
            use_def_filtered_modifications.append(modification)
            logger.info(
                "LFG DAG: bounded postprocess use-def warning ignored"
                " for %r because only state-variable dispatcher uses"
                " would be severed",
                modification,
            )
            continue
        details = "; ".join(
            f"var_stk[{violation.var_stkoff:#x}]@blk[{violation.use_block}]"
            for violation in real_violations[:8]
        )
        if len(real_violations) > 8:
            details = f"{details}; ..."
        logger.warning(
            "LFG DAG: bounded postprocess use-def vetoed %r orphaned_uses=%d details=%s",
            modification,
            len(real_violations),
            details,
        )
        vetoed_use_def_count += 1
    if vetoed_use_def_count:
        logger.info(
            "LFG DAG: bounded postprocess use-def veto filtered %d redirect(s)",
            vetoed_use_def_count,
        )
        return tuple(use_def_filtered_modifications)
    return modifications


def _accepted_region_site_signature(site: object) -> tuple[int, int, int, int, tuple[int, ...]]:
    return (
        int(getattr(site, "source_state", 0)) & 0xFFFFFFFF,
        int(getattr(site, "target_state", 0)) & 0xFFFFFFFF,
        int(getattr(site, "source_entry_anchor", -1)),
        int(getattr(site, "target_entry_anchor", -1)),
        tuple(int(block) for block in (getattr(site, "ordered_path", ()) or ())),
    )


def _match_accepted_region_sites(
    *,
    lowering_sites: tuple[object, ...] | list[object],
    accepted_candidates: tuple[object, ...] | list[object],
) -> tuple[object, ...]:
    """Recover semantic lowering sites for accepted reconstruction candidates.

    Reconstruction can preserve the semantic edge while rebuilding candidate
    objects, so object identity is not stable enough to drive successor-state
    propagation for the recursive region worklist. Match by semantic signature
    first and only fall back to edge identity when the site is truly unique.
    """

    if not lowering_sites or not accepted_candidates:
        return ()

    sites_by_signature: dict[tuple[int, int, int, int, tuple[int, ...]], list[object]] = {}
    sites_by_edge_id: dict[int, list[object]] = {}
    for site in lowering_sites:
        signature = _accepted_region_site_signature(site)
        sites_by_signature.setdefault(signature, []).append(site)
        sites_by_edge_id.setdefault(id(getattr(site, "edge", None)), []).append(site)

    matched: list[object] = []
    consumed_site_ids: set[int] = set()
    for candidate in accepted_candidates:
        edge = getattr(candidate, "edge", None)
        source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        target_state = getattr(edge, "target_state", None)
        if source_state is None or target_state is None:
            continue
        candidate_signature = (
            int(source_state) & 0xFFFFFFFF,
            int(target_state) & 0xFFFFFFFF,
            int(getattr(getattr(edge, "source_key", None), "handler_serial", -1)),
            int(getattr(candidate, "target_entry", -1)),
            tuple(int(block) for block in (getattr(edge, "ordered_path", ()) or ())),
        )
        signature_matches = [
            site
            for site in sites_by_signature.get(candidate_signature, ())
            if id(site) not in consumed_site_ids
        ]
        if signature_matches:
            site = signature_matches[0]
            matched.append(site)
            consumed_site_ids.add(id(site))
            continue
        edge_matches = [
            site
            for site in sites_by_edge_id.get(id(edge), ())
            if id(site) not in consumed_site_ids
        ]
        if edge_matches:
            site = edge_matches[0]
            matched.append(site)
            consumed_site_ids.add(id(site))
    return tuple(matched)


def _collect_consumed_structured_region_state_edges(
    *,
    accepted_sites: tuple[object, ...] | list[object],
    accepted_candidates: tuple[object, ...] | list[object],
) -> frozenset[tuple[int, int]]:
    consumed: set[tuple[int, int]] = set()

    for site in accepted_sites:
        edge = getattr(site, "edge", None)
        source_state = getattr(site, "source_state", None)
        if source_state is None:
            source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        if source_state is None:
            continue
        normalized_source = int(source_state) & 0xFFFFFFFF
        for target_state in (
            getattr(site, "target_state", None),
            getattr(site, "successor_state_value", None),
            getattr(edge, "target_state", None),
            getattr(edge, "observed_target_state", None),
        ):
            if target_state is None:
                continue
            normalized_target = int(target_state) & 0xFFFFFFFF
            if normalized_target == normalized_source:
                continue
            consumed.add((normalized_source, normalized_target))

    for candidate in accepted_candidates:
        edge = getattr(candidate, "edge", None)
        source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        if source_state is None:
            continue
        normalized_source = int(source_state) & 0xFFFFFFFF
        for target_state in (
            getattr(edge, "target_state", None),
            getattr(edge, "observed_target_state", None),
        ):
            if target_state is None:
                continue
            normalized_target = int(target_state) & 0xFFFFFFFF
            if normalized_target == normalized_source:
                continue
            consumed.add((normalized_source, normalized_target))

    return frozenset(consumed)


def _collect_accepted_reconstruction_candidates(run) -> list[object]:
    accepted_candidates = [
        result.candidate for result in getattr(run, "conditional_results", ())
    ]
    accepted_candidates.extend(
        result.accepted_candidate
        for result in getattr(run, "direct_results", ())
        if getattr(result, "accepted_candidate", None) is not None
    )
    for result in getattr(run, "shared_group_results", ()):
        accepted_candidates.extend(getattr(result, "accepted_candidates", ()))
    return accepted_candidates


def _collect_unmatched_region_sites(
    *,
    lowering_sites: tuple[object, ...] | list[object],
    accepted_sites: tuple[object, ...] | list[object],
) -> tuple[object, ...]:
    accepted_site_ids = {id(site) for site in accepted_sites}
    return tuple(
        site
        for site in lowering_sites
        if id(site) not in accepted_site_ids
    )


def _build_narrow_branch_local_region_fallback_candidates(
    *,
    unresolved_sites: tuple[object, ...] | list[object],
    flow_graph: object,
) -> tuple[ReconstructionCandidate, ...]:
    candidates: list[ReconstructionCandidate] = []
    seen_signatures: set[tuple[int, int, int, int, int, tuple[int, ...]]] = set()

    for site in unresolved_sites:
        site_kind = str(getattr(site, "site_kind", ""))
        if site_kind not in {"exit", "exit_alias_candidate", "terminal_self_anchor"}:
            continue

        edge = getattr(site, "edge", None)
        source_anchor = getattr(edge, "source_anchor", None)
        branch_arm = getattr(source_anchor, "branch_arm", None)
        if branch_arm not in (0, 1):
            continue

        target_entry = getattr(site, "target_entry_anchor", None)
        if target_entry is None or int(target_entry) < 0:
            continue

        ordered_path = tuple(
            int(serial) for serial in (getattr(site, "ordered_path", ()) or ())
        )
        if len(ordered_path) < 2:
            continue

        source_anchor_block = int(getattr(site, "source_anchor_block", -1))
        if source_anchor_block >= 0 and source_anchor_block in ordered_path:
            horizon_block = int(source_anchor_block)
        else:
            horizon_block = int(getattr(site, "source_entry_anchor", -1))
        if horizon_block is None or int(horizon_block) < 0:
            continue

        horizon_snapshot = flow_graph.get_block(int(horizon_block))
        if horizon_snapshot is None:
            continue
        horizon_succs = tuple(int(succ) for succ in getattr(horizon_snapshot, "succs", ()) or ())
        if int(getattr(horizon_snapshot, "nsucc", len(horizon_succs))) != 2:
            continue
        if int(horizon_block) not in ordered_path:
            continue

        source_state = getattr(site, "source_state", None)
        successor_state = getattr(site, "successor_state_value", None)
        if source_state is None:
            source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        if successor_state is None:
            successor_state = getattr(edge, "target_state", None)
        if source_state is None or successor_state is None:
            continue

        signature = (
            int(source_state) & 0xFFFFFFFF,
            int(successor_state) & 0xFFFFFFFF,
            int(target_entry),
            int(horizon_block),
            int(branch_arm),
            ordered_path,
        )
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)

        site_state_value = getattr(getattr(edge, "site", None), "state_value", None)
        if site_state_value is None:
            site_state_value = getattr(
                edge,
                "observed_target_state",
                getattr(edge, "target_state", None),
            )
        synthetic_site = getattr(edge, "site", None) or type(
            "_SyntheticStateWriteSite",
            (),
            {
                "block_serial": int(ordered_path[-1]),
                "state_value": (
                    int(site_state_value) & 0xFFFFFFFF
                    if site_state_value is not None
                    else int(successor_state) & 0xFFFFFFFF
                ),
                "insn_ea": 0,
                "unsafe_trailing_insn_eas": (),
            },
        )()
        candidates.append(
            ReconstructionCandidate(
                edge=edge,
                horizon_block=int(horizon_block),
                site=synthetic_site,
                target_entry=int(target_entry),
                first_shared_block=None,
                via_pred=None,
                emission_mode="conditional_arm",
                conditional_group_policy="rewrite_horizon",
            )
        )
    return tuple(candidates)


def _normalize_duplicate_target_redirect_branches(
    modifications: tuple[object, ...] | list[object],
    *,
    flow_graph: object,
) -> tuple[tuple[object, ...], int]:
    """Collapse branch redirects that would duplicate the sibling successor.

    Reconstruction postprocess can emit a `RedirectBranch(old -> new)` on a 2-way
    block where `new` is already the block's other successor. Leaving that as a
    branch redirect produces two edges from the same source to the same target
    and fails projected CFG contract checks. Normalize those cases into
    `ConvertToGoto`.
    """

    normalized: list[object] = []
    collapsed_count = 0
    for modification in modifications:
        if isinstance(modification, RedirectBranch):
            block = flow_graph.get_block(int(modification.from_serial))
            succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
            other_succs = {
                int(succ)
                for succ in succs
                if int(succ) != int(modification.old_target)
            }
            if (
                block is not None
                and int(getattr(block, "nsucc", len(succs))) == 2
                and int(modification.new_target) in other_succs
            ):
                normalized.append(
                    ConvertToGoto(
                        block_serial=int(modification.from_serial),
                        goto_target=int(modification.new_target),
                    )
                )
                collapsed_count += 1
                continue
        normalized.append(modification)
    return tuple(normalized), collapsed_count


def _sanitize_progressive_topology_modifications(
    modifications: tuple[object, ...] | list[object],
    *,
    flow_graph: FlowGraph,
) -> tuple[tuple[object, ...], int, int]:
    """Drop stale/no-op topology edits against progressively updated successors.

    The planner can legitimately emit redirects whose ``old_target`` was valid
    when selected but is no longer present after earlier rewrites in the same
    stage. The backend simulator already fail-closes those edits; sanitize them
    here so they do not reach backend apply at all.

    This helper intentionally focuses on topology-changing edits and keeps
    non-topological edits untouched.
    """

    current_adj = {
        int(serial): [int(succ) for succ in getattr(block, "succs", ()) or ()]
        for serial, block in flow_graph.blocks.items()
    }
    sanitized: list[object] = []
    normalized_count = 0
    dropped_count = 0

    for modification in modifications:
        candidate = modification
        if isinstance(candidate, RedirectBranch):
            succs = list(current_adj.get(int(candidate.from_serial), ()))
            other_succs = {
                int(succ)
                for succ in succs
                if int(succ) != int(candidate.old_target)
            }
            if int(candidate.new_target) in other_succs:
                candidate = ConvertToGoto(
                    block_serial=int(candidate.from_serial),
                    goto_target=int(candidate.new_target),
                )
                normalized_count += 1

        simulated = graph_modifications_to_simulated_edits([candidate])
        if not simulated:
            sanitized.append(candidate)
            continue

        simulated_result = simulate_edits(current_adj, simulated)
        if simulated_result.adj == current_adj:
            dropped_count += 1
            continue

        sanitized.append(candidate)
        current_adj = simulated_result.adj

    return tuple(sanitized), normalized_count, dropped_count

__all__ = [
    "LinearizedFlowGraphStrategy",
    "SemanticStructuredRegionStrategy",
]


def _collect_structured_region_zero_state_write_modifications(
    *,
    accepted_candidates: tuple[object, ...] | list[object],
    flow_graph: FlowGraph,
    state_var_stkoff: int,
    constant_result: object,
    existing_modifications: tuple[object, ...] | list[object],
) -> tuple[ZeroStateWrite, ...]:
    """Resolve structured-region path-walk sites and emit ZSW.

    Thin adapter over the unified :func:`collect_zero_state_writes`
    emitter (Phase 4 of uee-jrgq, ticket uee-rjo8). Performs the
    LFG-local recon-side path resolution
    (:func:`find_last_state_write_site_on_path_snapshot`) to project
    accepted candidates into :class:`ZsvSiteRequest` records, then
    delegates emission to the single-emitter module.

    The shared dedup invariant (every ``(block, insn_ea)`` is keyed
    identically across all 3 collector inputs) is preserved: any
    ZSW already in ``existing_modifications`` seeds the unified
    ``seen`` set.
    """
    in_stk_maps = getattr(constant_result, "in_stk_maps", None)
    in_reg_maps = getattr(constant_result, "in_reg_maps", None)

    requests: list[ZsvSiteRequest] = []
    for candidate in accepted_candidates:
        edge = getattr(candidate, "edge", None)
        if edge is None:
            continue
        target_states = frozenset(
            int(state_value) & 0xFFFFFFFF
            for state_value in (
                getattr(edge, "target_state", None),
                getattr(edge, "observed_target_state", None),
            )
            if state_value is not None
        )
        if not target_states:
            continue
        ordered_path = tuple(
            int(serial) for serial in getattr(edge, "ordered_path", ()) if serial is not None
        )
        if not ordered_path:
            continue
        resolved = find_last_state_write_site_on_path_snapshot(
            flow_graph,
            ordered_path,
            int(state_var_stkoff),
            in_stk_maps=in_stk_maps,
            in_reg_maps=in_reg_maps,
        )
        if resolved is None:
            continue
        block_serial, site = resolved
        site_state = getattr(site, "state_value", None)
        insn_ea = getattr(site, "insn_ea", None)
        if site_state is None or insn_ea is None or int(insn_ea) == 0:
            continue
        requests.append(
            ZsvSiteRequest(
                block_serial=int(block_serial),
                insn_ea=int(insn_ea),
                site_state=int(site_state),
                target_states=target_states,
                provenance="lfg_structured_region",
            )
        )

    return collect_zero_state_writes(
        source=ZsvSource.from_resolved_sites(requests),
        existing_modifications=existing_modifications,
    )


def _collect_trivial_redirect_tail_zero_state_write_modifications(
    *,
    modifications: tuple[object, ...] | list[object],
    flow_graph: FlowGraph,
    dispatcher_serial: int,
    state_var_stkoff: int,
) -> tuple[ZeroStateWrite, ...]:
    """Resolve dispatcher-redirect tail sites and emit ZSW.

    Thin adapter over the unified :func:`collect_zero_state_writes`
    emitter (Phase 4 of uee-jrgq, ticket uee-rjo8). Walks the
    accumulated modifications for ``RedirectGoto`` mods whose
    ``old_target`` is the dispatcher and resolves the source block's
    last state write via :func:`find_last_state_write_site_snapshot`,
    then delegates emission to the single-emitter module.

    The original block-only collector did not have a target-state
    handle (it only knew the source block and dispatcher), so the
    request leaves ``target_states`` empty — the unified emitter then
    skips the site_state↔target_states match check, mirroring the
    legacy behaviour.
    """
    requests: list[ZsvSiteRequest] = []
    for mod in modifications:
        if not isinstance(mod, RedirectGoto):
            continue
        if int(mod.old_target) != int(dispatcher_serial):
            continue
        source_block = int(mod.from_serial)
        source_snapshot = flow_graph.get_block(source_block)
        if source_snapshot is None:
            continue
        succs = tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))
        if succs != (int(dispatcher_serial),):
            continue
        site = find_last_state_write_site_snapshot(
            flow_graph,
            source_block,
            int(state_var_stkoff),
        )
        if site is None:
            continue
        insn_ea = getattr(site, "insn_ea", None)
        if insn_ea is None or int(insn_ea) == 0:
            continue
        if tuple(getattr(site, "unsafe_trailing_insn_eas", ())):
            continue
        if len(tuple(getattr(site, "trailing_insn_eas", ()))) > 1:
            continue
        site_state = getattr(site, "state_value", None)
        requests.append(
            ZsvSiteRequest(
                block_serial=source_block,
                insn_ea=int(insn_ea),
                site_state=None if site_state is None else int(site_state),
                target_states=frozenset(),
                provenance="lfg_trivial_redirect_tail",
            )
        )

    return collect_zero_state_writes(
        source=ZsvSource.from_resolved_sites(requests),
        existing_modifications=modifications,
    )


def _filter_unsafe_preferred_region_lowering(
    *,
    preferred: object | None,
    site: object,
    flow_graph: FlowGraph,
    state_var_stkoff: int,
    constant_result: object,
) -> object | None:
    debug_branch_site = (
        int(getattr(site, "source_state", 0)) & 0xFFFFFFFF == 0x6107F8EC
        and getattr(getattr(site, "edge", None), "source_anchor", None) is not None
        and getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None) in (0, 1)
    )
    if preferred is None:
        return None
    if str(getattr(preferred, "emission_mode", "")) != "conditional_arm":
        return preferred

    resolved_horizon = find_last_state_write_site_on_path_snapshot(
        flow_graph,
        tuple(int(serial) for serial in getattr(site, "ordered_path", ()) or ()),
        int(state_var_stkoff),
        in_stk_maps=getattr(constant_result, "in_stk_maps", None),
        in_reg_maps=getattr(constant_result, "in_reg_maps", None),
    )
    if resolved_horizon is None:
        return preferred
    write_block, write_site = resolved_horizon
    ordered_path = tuple(int(serial) for serial in getattr(site, "ordered_path", ()) or ())
    source_anchor_block = int(getattr(site, "source_anchor_block", -1))
    if (
        len(ordered_path) == 1
        and int(ordered_path[0]) == source_anchor_block
        and hasattr(flow_graph, "get_block")
    ):
        source_snapshot = flow_graph.get_block(source_anchor_block)
        if (
            source_snapshot is not None
            and int(getattr(source_snapshot, "nsucc", 0)) == 2
        ):
            return preferred
    if int(write_block) != source_anchor_block:
        if not hasattr(flow_graph, "get_block"):
            if debug_branch_site:
                logger.info(
                    "LFG DAG: branch site filter reject reason=no_get_block source_anchor=%d write_block=%d path=%s",
                    source_anchor_block,
                    int(write_block),
                    ordered_path,
                )
            return None
        if (
            len(ordered_path) == 1
            and int(ordered_path[0]) == source_anchor_block
        ):
            source_snapshot = flow_graph.get_block(source_anchor_block)
            if (
                source_snapshot is not None
                and int(getattr(source_snapshot, "nsucc", 0)) == 2
                and not tuple(getattr(write_site, "unsafe_trailing_insn_eas", ()))
            ):
                return preferred
            if debug_branch_site:
                logger.info(
                    "LFG DAG: branch site filter singleton-head source_anchor=%d write_block=%d nsucc=%s preds=%s succs=%s unsafe=%s",
                    source_anchor_block,
                    int(write_block),
                    None if source_snapshot is None else int(getattr(source_snapshot, "nsucc", 0)),
                    None if source_snapshot is None else tuple(int(pred) for pred in getattr(source_snapshot, "preds", ()) or ()),
                    None if source_snapshot is None else tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()) or ()),
                    tuple(getattr(write_site, "unsafe_trailing_insn_eas", ())),
                )
        try:
            source_index = ordered_path.index(source_anchor_block)
            write_index = ordered_path.index(int(write_block))
        except ValueError:
            if debug_branch_site:
                logger.info(
                    "LFG DAG: branch site filter reject reason=write_not_on_path source_anchor=%d write_block=%d path=%s unsafe=%s",
                    source_anchor_block,
                    int(write_block),
                    ordered_path,
                    tuple(getattr(write_site, "unsafe_trailing_insn_eas", ())),
                )
            return None
        if write_index <= source_index or write_index != len(ordered_path) - 1:
            if debug_branch_site:
                logger.info(
                    "LFG DAG: branch site filter reject reason=write_index source_anchor=%d write_block=%d source_index=%d write_index=%d path=%s",
                    source_anchor_block,
                    int(write_block),
                    int(source_index),
                    int(write_index),
                    ordered_path,
                )
            return None
        feeder_path = ordered_path[source_index + 1 : write_index + 1]
        if not feeder_path:
            if debug_branch_site:
                logger.info(
                    "LFG DAG: branch site filter reject reason=empty_feeder source_anchor=%d write_block=%d path=%s",
                    source_anchor_block,
                    int(write_block),
                    ordered_path,
                )
            return None
        for idx, block_serial in enumerate(feeder_path):
            block = flow_graph.get_block(block_serial)
            if block is None:
                if debug_branch_site:
                    logger.info(
                        "LFG DAG: branch site filter reject reason=missing_block block=%d feeder_path=%s",
                        int(block_serial),
                        feeder_path,
                    )
                return None
            succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
            preds = tuple(int(pred) for pred in getattr(block, "preds", ()) or ())
            if len(succs) != 1:
                if debug_branch_site:
                    logger.info(
                        "LFG DAG: branch site filter reject reason=feeder_nsucc block=%d succs=%s preds=%s feeder_path=%s",
                        int(block_serial),
                        succs,
                        preds,
                        feeder_path,
                    )
                return None
            if block_serial != int(write_block):
                expected_succ = int(feeder_path[idx + 1])
                if int(succs[0]) != expected_succ:
                    if debug_branch_site:
                        logger.info(
                            "LFG DAG: branch site filter reject reason=feeder_succ_mismatch block=%d succs=%s expected=%d feeder_path=%s",
                            int(block_serial),
                            succs,
                            int(expected_succ),
                            feeder_path,
                        )
                    return None
                if len(preds) != 1 or int(preds[0]) != int(ordered_path[source_index + idx]):
                    if debug_branch_site:
                        logger.info(
                            "LFG DAG: branch site filter reject reason=feeder_pred_mismatch block=%d preds=%s expected_pred=%d feeder_path=%s",
                            int(block_serial),
                            preds,
                            int(ordered_path[source_index + idx]),
                            feeder_path,
                        )
                    return None
    if tuple(getattr(write_site, "unsafe_trailing_insn_eas", ())):
        if debug_branch_site:
            logger.info(
                "LFG DAG: branch site filter reject reason=unsafe_trailing source_anchor=%d write_block=%d unsafe=%s",
                source_anchor_block,
                int(write_block),
                tuple(getattr(write_site, "unsafe_trailing_insn_eas", ())),
            )
        return None
    return preferred


def _should_defer_transient_internal_region_site(
    *,
    site: object,
    dag: object,
) -> bool:
    if str(getattr(site, "site_kind", "")) != "internal":
        return False
    source_anchor = getattr(getattr(site, "edge", None), "source_anchor", None)
    if getattr(source_anchor, "branch_arm", None) is not None:
        return False
    transient_states = {
        int(state) & 0xFFFFFFFF
        for state in getattr(dag, "transient_state_values", ()) or ()
    }
    if not transient_states:
        return False
    source_state = int(getattr(site, "source_state", -1)) & 0xFFFFFFFF
    target_state = int(getattr(site, "target_state", -1)) & 0xFFFFFFFF
    return source_state in transient_states and target_state in transient_states


def _prepare_linearized_flow_graph_plan_setup(
    *,
    snapshot: object,
    state_machine: object,
    bst_result: object,
    flow_graph: object,
    mba: object | None,
    same_maturity_rerun: bool,
) -> LinearizedFlowGraphPlanSetup:
    transition_result = TransitionResult(
        transitions=list(state_machine.transitions),
        handlers=dict(state_machine.handlers),
        assignment_map=dict(state_machine.assignment_map),
        initial_state=state_machine.initial_state,
        pre_header_serial=getattr(bst_result, "pre_header_serial", None),
        strategy_name="linearized_flow_graph",
        resolved_count=len(state_machine.transitions),
    )
    return prepare_linearized_flow_graph_plan_setup(
        snapshot=snapshot,
        state_machine=state_machine,
        bst_result=bst_result,
        flow_graph=flow_graph,
        same_maturity_rerun=same_maturity_rerun,
        build_builder=ModificationBuilder.from_snapshot,
        resolve_state_var_stkoff=LinearizedFlowGraphStrategy._resolve_state_var_stkoff,
        supports_projected_replanning=LinearizedFlowGraphStrategy._supports_projected_replanning,
        label_block=(lambda serial: blk_label(mba, serial) if serial is not None else "<none>"),
        transition_result=transition_result,
    )


def _log_linearized_flow_graph_plan_result(
    *,
    mba: object | None,
    result: object,
) -> None:
    if result.unresolved_bst_targets:
        logger.info(
            "LFG DAG: preserving BST cleanup because %d targets still resolve only inside BST region",
            result.unresolved_bst_targets,
        )
    if result.cleanup_gate_reason == "residual_dispatcher_predecessors":
        logger.info(
            "LFG DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
            [blk_label(mba, serial) for serial in result.residual_dispatcher_preds],
        )
    if result.cleanup_gate_reason == "residual_dispatcher_redirects":
        logger.info(
            "LFG DAG: preserving post-apply BST cleanup because residual dispatcher rewrites were emitted this round; defer cleanup until a later verified pass",
        )

    logger.info(
        "LFG DAG: emitted %d redirects (%d unconditional, %d conditional); "
        "%d terminal edges ignored, %d unknown edges ignored, %d skipped conflicts; "
        "%d BST disconnects",
        result.transition_count + result.conditional_count,
        result.transition_count,
        result.conditional_count,
        result.terminal_skipped,
        result.unknown_skipped,
        result.skipped_count,
        result.disconnect_count,
    )


def _build_linearized_flow_graph_planner_context_contribution(
    *,
    strategy_name: str,
    modifications,
    owned_blocks: frozenset[int],
    round_index: int,
) -> PlannerContextContribution:
    """Scan emitted mods + owned_blocks to produce a PlannerContextContribution.

    Symmetric to
    :func:`d810.optimizers.microcode.flow.flattening.hodur.reconstruction_fragment_builder._build_planner_context_contribution`:
    every :class:`RedirectGoto` becomes a :class:`LinearizationDecision` so
    later strategies (same pipeline, later rounds) can call
    ``view.is_linearized(src)`` and skip emitting a contradictory reverse
    redirect. Owned blocks populate ``claimed_sources`` so the same
    strategies can also call ``view.is_claimed(src)`` for broader scope.

    ``StateWriteNeutralization`` contributions are deliberately omitted in
    this first pass — building them would require threading the original
    state constant through the emission path (``ZeroStateWrite`` stores
    only the insn_ea, not the pre-zeroing value). Added incrementally.
    """
    linearizations = tuple(
        LinearizationDecision(
            src=int(mod.from_serial),
            tgt=int(mod.new_target),
            reason=strategy_name,
            strategy=strategy_name,
            round_index=round_index,
        )
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    )
    return PlannerContextContribution(
        linearizations=linearizations,
        neutralizations=(),
        claimed_sources=frozenset(int(blk) for blk in owned_blocks),
    )


def _build_linearized_flow_graph_plan_fragment(
    *,
    strategy_name: str,
    family: str,
    prerequisites: list[str],
    state_machine: object,
    bst_node_blocks: frozenset[int],
    result: object,
    round_index: int = 0,
) -> PlanFragment:
    ownership = OwnershipScope(
        blocks=result.owned_blocks,
        edges=result.owned_edges,
        transitions=result.owned_transitions,
    )
    benefit = BenefitMetrics(
        handlers_resolved=len(state_machine.handlers),
        transitions_resolved=result.transition_count + result.conditional_count,
        blocks_freed=len(bst_node_blocks),
        conflict_density=0.0,
    )
    planner_ctx = _build_linearized_flow_graph_planner_context_contribution(
        strategy_name=strategy_name,
        modifications=result.modifications,
        owned_blocks=result.owned_blocks,
        round_index=round_index,
    )
    return PlanFragment(
        strategy_name=strategy_name,
        family=family,
        modifications=list(result.modifications),
        ownership=ownership,
        prerequisites=prerequisites,
        expected_benefit=benefit,
        risk_score=0.1,
        metadata={
            "handlers_visited": len(state_machine.handlers),
            "resolved_count": result.transition_count + result.conditional_count,
            "dag_transition_count": result.transition_count,
            "dag_conditional_count": result.conditional_count,
            "dag_terminal_skipped": result.terminal_skipped,
            "dag_unknown_skipped": result.unknown_skipped,
            "skipped_count": result.skipped_count,
            "disconnect_count": result.disconnect_count,
            "allow_post_apply_bst_cleanup": result.cleanup_gate_reason is None,
            "post_apply_bst_cleanup_reason": result.cleanup_gate_reason,
            "residual_dispatcher_preds": result.residual_dispatcher_preds,
            "residual_dispatcher_redirect_count": result.residual_dispatcher_redirect_count,
            "residual_dispatcher_normalized_count": result.residual_dispatcher_normalized_count,
            "dead_island_cleanup_count": result.dead_island_cleanup_count,
            "unresolved_bst_targets": result.unresolved_bst_targets,
            "bst_convert_count": 0,
            "goto_nop_count": 0,
            "goto_skip_count": 0,
            "nop_state_values": {},
            "safeguard_min_required": 1,
            PLANNER_CTX_METADATA_KEY: planner_ctx,
        },
    )


class LinearizedFlowGraphStrategy:
    """Emit DAG-selected redirect edits for branch-anchored handler exits."""

    lowering_mode = LoweringMode.DIRECT_GRAPH
    _MAX_PROJECTED_PLANNING_ROUNDS = 4

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "linearized_flow_graph"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    # No prerequisites -- this is a standalone first-pass strategy.
    prerequisites: list[str] = []
    _applied: set[tuple[int, int]] = set()  # (func_ea, maturity) already processed
    _last_successful_residual_dispatcher_pred_counts: dict[tuple[int, int], int] = {}
    _same_count_exact_rerun_used: set[tuple[int, int]] = set()
    _projected_topology_backend: ProjectedTopologyBackend = (
        _PROJECTED_TOPOLOGY_BACKEND
    )
    _constant_fixpoint_backend: ConstantFixpointBackend = (
        _CONSTANT_FIXPOINT_BACKEND
    )
    _handoff_resolution_backend: LinearizedFlowGraphHandoffResolutionBackend = (
        _HANDOFF_RESOLUTION_BACKEND
    )

    @staticmethod
    def _resolve_state_var_stkoff(
        snapshot: AnalysisSnapshot,
        sm: DispatcherStateMachine,
    ) -> int | None:
        return discover_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        )

    @staticmethod
    def _supports_projected_replanning(flow_graph: object) -> bool:
        return isinstance(flow_graph, FlowGraph)

    _flow_graph_block_serials = staticmethod(flow_graph_block_serials)
    _resolve_singleton_state_write_value = staticmethod(resolve_singleton_state_write_value)

    @classmethod
    def _collect_dead_dispatcher_root_cleanup_modifications(
        cls,
        projected_flow_graph,
        *,
        dispatcher_serial: int,
        original_stop_serial: int | None,
        original_blocks: set[int],
    ) -> list[RedirectGoto]:
        del cls
        if not projected_flow_graph.blocks:
            return []
        if dispatcher_serial < 0 or original_stop_serial is None:
            return []
        stop_serial = int(original_stop_serial)
        entry_serial = getattr(projected_flow_graph, "entry_serial", None)
        reachable_blocks = compute_reachable_blocks(
            projected_flow_graph,
            start_serial=entry_serial,
        )
        filtered: list[RedirectGoto] = []
        for block_serial in sorted(projected_flow_graph.blocks.keys()):
            if block_serial not in original_blocks:
                continue
            if block_serial in {dispatcher_serial, stop_serial}:
                continue
            if reachable_blocks is not None and block_serial in reachable_blocks:
                continue
            block = projected_flow_graph.get_block(block_serial)
            if block is None:
                continue
            if tuple(getattr(block, "preds", ())) != ():
                continue
            if _LIVE_MICROCODE_PROPERTIES.is_two_way_block_type(
                getattr(block, "block_type", None)
            ):
                continue
            succs = tuple(getattr(block, "succs", ()))
            if len(succs) != 1:
                continue
            old_target = int(succs[0])
            if old_target == stop_serial:
                continue
            if old_target != dispatcher_serial:
                continue
            filtered.append(
                RedirectGoto(
                    from_serial=int(block_serial),
                    old_target=old_target,
                    new_target=stop_serial,
                )
            )
        filtered.sort(key=lambda mod: mod.from_serial)
        return filtered

    _collect_residual_dispatcher_predecessors = staticmethod(
        collect_residual_dispatcher_predecessors
    )
    _resolve_redirect_safe_entry_from_node = staticmethod(
        resolve_redirect_safe_entry_from_node
    )
    _resolve_redirect_safe_target_entry = staticmethod(
        resolve_redirect_safe_target_entry
    )
    _resolve_contextual_dag_entry_for_state = staticmethod(
        resolve_contextual_dag_entry_for_state
    )
    _resolve_normalized_alias_entry_for_state = staticmethod(
        resolve_normalized_alias_entry_for_state
    )
    _resolve_cover_fallback_entry_for_state = staticmethod(
        resolve_cover_fallback_entry_for_state
    )

    @classmethod
    def _resolve_projected_path_tail_target(
        cls,
        dag: object,
        *,
        source_block: int,
        bst_node_blocks: AbstractSet[int],
        dispatcher: object | None = None,
        predecessor_hints: tuple[int, ...] | None = None,
        require_predecessor_match: bool = False,
    ) -> tuple[int | None, int] | None:
        response = cls._handoff_resolution_backend.resolve_projected_path_tail_target(
            ProjectedPathTailTargetRequest(
                dag=dag,
                source_block=source_block,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
                predecessor_hints=predecessor_hints,
                require_predecessor_match=require_predecessor_match,
            )
        )
        return response.target

    @classmethod
    def _resolve_immediate_handoff_target(
        cls,
        dag: object,
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None,
        bst_node_blocks: AbstractSet[int],
        dispatcher_lookup: object | None,
        dispatcher: object | None = None,
    ) -> tuple[int, int] | None:
        response = cls._handoff_resolution_backend.resolve_immediate_handoff_target(
            ImmediateHandoffTargetRequest(
                dag=dag,
                mba=mba,
                block_serial=block_serial,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
            )
        )
        return response.target

    @classmethod
    def _resolve_projected_snapshot_handoff_target(
        cls,
        dag: object,
        flow_graph: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None,
        bst_node_blocks: AbstractSet[int],
        dispatcher: object | None,
    ) -> tuple[int, int] | None:
        response = (
            cls._handoff_resolution_backend.resolve_projected_snapshot_handoff_target(
                ProjectedSnapshotHandoffTargetRequest(
                    dag=dag,
                    flow_graph=flow_graph,
                    block_serial=block_serial,
                    state_var_stkoff=state_var_stkoff,
                    bst_node_blocks=bst_node_blocks,
                    dispatcher=dispatcher,
                )
            )
        )
        return response.target

    @classmethod
    def _resolve_assignment_map_handoff_target(
        cls,
        dag: object,
        state_machine: object | None,
        block_serial: int,
        *,
        bst_node_blocks: AbstractSet[int],
        dispatcher: object | None,
    ) -> tuple[int, int] | None:
        response = cls._handoff_resolution_backend.resolve_assignment_map_handoff_target(
            AssignmentMapHandoffTargetRequest(
                dag=dag,
                state_machine=state_machine,
                block_serial=block_serial,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
            )
        )
        return response.target

    @classmethod
    def _resolve_synthesized_handoff_target(
        cls,
        dag: object,
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None,
        bst_node_blocks: AbstractSet[int],
        dispatcher: object | None,
        via_pred: int | None = None,
    ) -> tuple[int, int] | None:
        response = cls._handoff_resolution_backend.resolve_synthesized_handoff_target(
            SynthesizedHandoffTargetRequest(
                dag=dag,
                mba=mba,
                block_serial=block_serial,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
                via_pred=via_pred,
            )
        )
        return response.target

    @classmethod
    def _resolve_effective_target_entry(
        cls,
        dag: object,
        edge: object,
        *,
        bst_node_blocks: AbstractSet[int],
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None,
        mba: object,
    ) -> int | None:
        response = cls._handoff_resolution_backend.resolve_effective_target_entry(
            EffectiveTargetEntryRequest(
                dag=dag,
                edge=edge,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=mba,
            )
        )
        return response.target_entry

    @classmethod
    def _emit_residual_branch_anchor_handoff(
        cls,
        *,
        edge: StateDagEdge,
        source_block: int,
        via_pred: int,
        prefix_target: int,
        projected_flow_graph: object,
        bst_node_blocks: set[int],
        dispatcher_serial: int,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_2way: dict[tuple[int, int], int],
        ignored_blocks: set[int],
        residual_ignored_blocks: set[int],
        mba: object | None,
    ) -> bool:
        result = emit_residual_branch_anchor_handoff(
            edge=edge,
            source_block=int(source_block),
            via_pred=int(via_pred),
            prefix_target=int(prefix_target),
            projected_flow_graph=projected_flow_graph,
            bst_node_blocks=bst_node_blocks,
            dispatcher_serial=int(dispatcher_serial),
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_2way=claimed_2way,
            ignored_blocks=ignored_blocks,
            residual_ignored_blocks=residual_ignored_blocks,
        )
        if not result.accepted:
            return False
        if result.already_claimed:
            return True
        assert result.branch_source is not None
        assert result.prefix_target is not None
        assert result.via_pred is not None
        assert result.edge_kind_name is not None
        logger.info(
            "LFG DAG: residual branch handoff %s -> %s (bypassing %s -> %s via %s)",
            blk_label(mba, int(result.branch_source)),
            blk_label(mba, int(result.prefix_target)),
            blk_label(mba, int(result.via_pred)),
            blk_label(mba, source_block),
            result.edge_kind_name,
        )
        return True

    @classmethod
    def _allow_same_maturity_rerun(
        cls,
        snapshot: AnalysisSnapshot,
        *,
        consume_retry: bool,
    ) -> bool:
        """Return whether a same-maturity rerun should proceed.

        This must stay side-effect free when ``consume_retry`` is False because
        the planner probes applicability before calling ``plan()``.  The retry
        token is only consumed from ``plan()`` so the second check does not
        spend the allowance before a fragment is actually built.
        """
        mba = snapshot.mba
        flow_graph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        if mba is None or flow_graph is None or bst_result is None:
            return False
        func_ea = mba.entry_ea
        maturity = mba.maturity
        key = (func_ea, maturity)
        bst_node_blocks = set(getattr(bst_result, "bst_node_blocks", ()) or ())
        residual_preds = cls._collect_residual_dispatcher_predecessors(
            flow_graph,
            snapshot.bst_dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
            reachable_from_serial=getattr(flow_graph, "entry_serial", None),
        )
        raw_residual_preds = collect_dispatcher_predecessors(
            flow_graph,
            snapshot.bst_dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
        )
        effective_residual_preds = raw_residual_preds or residual_preds
        if not effective_residual_preds:
            logger.info(
                "LFG: already applied for func 0x%X at maturity %s",
                func_ea,
                maturity_to_string(maturity),
            )
            return False
        previous_residual_count = cls._last_successful_residual_dispatcher_pred_counts.get(key)
        if (
            previous_residual_count is not None
            and len(effective_residual_preds) >= previous_residual_count
        ):
            if (
                key not in cls._same_count_exact_rerun_used
                and cls._has_live_exact_residual_handoff(
                    snapshot,
                    effective_residual_preds,
                )
            ):
                if consume_retry:
                    cls._same_count_exact_rerun_used.add(key)
                logger.info(
                    "LFG: allowing one same-count rerun for func 0x%X at maturity %s because live residual exact handoffs remain: %s",
                    func_ea,
                    maturity_to_string(maturity),
                    effective_residual_preds,
                )
                return True
            if (
                key not in cls._same_count_exact_rerun_used
                and len(effective_residual_preds) == previous_residual_count
                and effective_residual_preds
            ):
                if consume_retry:
                    cls._same_count_exact_rerun_used.add(key)
                logger.info(
                    "LFG: allowing one exploratory same-count rerun for func 0x%X at maturity %s because residual dispatcher preds remain: %s",
                    func_ea,
                    maturity_to_string(maturity),
                    effective_residual_preds,
                )
                return True
            logger.info(
                "LFG: suppressing same-maturity rerun for func 0x%X at maturity %s "
                "because residual dispatcher preds did not improve (%d -> %d)",
                func_ea,
                maturity_to_string(maturity),
                previous_residual_count,
                len(effective_residual_preds),
            )
            return False
        cls._same_count_exact_rerun_used.discard(key)
        logger.info(
            "LFG: allowing same-maturity rerun for func 0x%X with residual dispatcher preds %s",
            func_ea,
            effective_residual_preds,
        )
        return True

    # ------------------------------------------------------------------
    # Applicability
    # ------------------------------------------------------------------

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a state machine with handlers,
        a BST result with ``handler_state_map``, and a known ``initial_state``.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the transition graph can be traversed.
        """
        mba = snapshot.mba
        if mba is not None:
            func_ea = mba.entry_ea
            maturity = mba.maturity
            if (func_ea, maturity) in LinearizedFlowGraphStrategy._applied:
                if not self._allow_same_maturity_rerun(
                    snapshot,
                    consume_retry=False,
                ):
                    return False

        sm = snapshot.state_machine
        if sm is None or not sm.handlers:
            return False
        if sm.initial_state is None:
            return False

        bst = snapshot.bst_result
        if bst is None:
            return False
        handler_state_map = getattr(bst, "handler_state_map", None) or {}
        if not handler_state_map:
            return False
        return True

    @classmethod
    def _has_live_exact_residual_handoff(
        cls,
        snapshot: AnalysisSnapshot,
        residual_preds: tuple[int, ...],
    ) -> bool:
        mba = getattr(snapshot, "mba", None)
        bst_result = getattr(snapshot, "bst_result", None)
        state_machine = getattr(snapshot, "state_machine", None)
        if mba is None or bst_result is None or state_machine is None:
            return False
        state_var_stkoff = cls._resolve_state_var_stkoff(snapshot, state_machine)
        dispatcher = getattr(bst_result, "dispatcher", None)
        return has_live_exact_residual_handoff_with_valranges(
            mba,
            residual_preds,
            state_var_stkoff=state_var_stkoff,
            dispatcher=dispatcher,
        )

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a :class:`PlanFragment` by stitching the transition graph.

        Iterates EVERY resolved edge in the state machine transition graph
        and emits a redirect for each one.  Then NOPs all state variable
        writes in handler blocks so the BST dispatcher becomes dead code.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A :class:`PlanFragment` with redirect modifications, or ``None``
            when the strategy has nothing to contribute.
        """
        mba = snapshot.mba
        if mba is not None and (mba.entry_ea, mba.maturity) in self._applied:
            if not self._allow_same_maturity_rerun(snapshot, consume_retry=True):
                return None
        elif not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        assert sm is not None  # guaranteed by is_applicable
        bst_result = snapshot.bst_result
        assert bst_result is not None
        flow_graph = snapshot.flow_graph
        if flow_graph is None:
            logger.info("LFG: no flow_graph available, skipping")
            return None
        func_ea = getattr(mba, "entry_ea", None)
        maturity = getattr(mba, "maturity", None)
        same_maturity_rerun = (
            func_ea is not None
            and maturity is not None
            and (func_ea, maturity) in self._applied
        )

        dag_setup = _prepare_linearized_flow_graph_plan_setup(
            snapshot=snapshot,
            state_machine=sm,
            bst_result=bst_result,
            flow_graph=flow_graph,
            mba=mba,
            same_maturity_rerun=bool(same_maturity_rerun),
        )
        planning_callbacks = self._build_planning_callbacks(
            snapshot=snapshot,
            state_machine=sm,
            bst_result=bst_result,
            mba=mba,
            dag_setup=dag_setup,
        )
        dag_result = execute_linearized_flow_graph_planning(
            build_linearized_flow_graph_planning_context(
                flow_graph=flow_graph,
                mba=mba,
                state_machine=sm,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                setup=dag_setup,
                snapshot=snapshot,
            ),
            callbacks=planning_callbacks,
        )
        if not dag_result.accepted:
            logger.info("LFG: DAG produced no redirect modifications")
            return None

        if _lfg_bounded_postprocess_enabled():
            dag_result = self._apply_bounded_postprocess(
                snapshot=snapshot,
                state_machine=sm,
                bst_result=bst_result,
                flow_graph=flow_graph,
                mba=mba,
                dag_setup=dag_setup,
                dag_result=dag_result,
            )
        else:
            logger.info(
                "LFG DAG: bounded postprocess disabled"
                " (set D810_LFG_BOUNDED_POSTPROCESS=0 to disable)"
            )

        (
            sanitized_modifications,
            topology_normalized_count,
            topology_dropped_count,
        ) = _sanitize_progressive_topology_modifications(
            dag_result.modifications,
            flow_graph=flow_graph,
        )
        if (
            topology_normalized_count
            or topology_dropped_count
            or len(sanitized_modifications) != len(dag_result.modifications)
        ):
            logger.info(
                "LFG DAG: sanitized full modification bundle normalized=%d dropped=%d kept=%d/%d",
                topology_normalized_count,
                topology_dropped_count,
                len(sanitized_modifications),
                len(dag_result.modifications),
            )
            dag_result = replace(dag_result, modifications=sanitized_modifications)

        if dag_setup.state_var_stkoff is not None:
            trivial_cleanup_mods = _collect_trivial_redirect_tail_zero_state_write_modifications(
                modifications=dag_result.modifications,
                flow_graph=flow_graph,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                state_var_stkoff=int(dag_setup.state_var_stkoff),
            )
            if trivial_cleanup_mods:
                logger.info(
                    "LFG DAG: appended %d trivial redirect tail cleanup site(s)",
                    len(trivial_cleanup_mods),
                )
                dag_result = replace(
                    dag_result,
                    modifications=tuple((*dag_result.modifications, *trivial_cleanup_mods)),
                )

        _log_linearized_flow_graph_plan_result(
            mba=mba,
            result=dag_result,
        )
        return _build_linearized_flow_graph_plan_fragment(
            strategy_name=self.name,
            family=self.family,
            prerequisites=self.prerequisites,
            state_machine=sm,
            bst_node_blocks=dag_setup.bst_node_blocks,
            result=dag_result,
        )

    def _build_planning_callbacks(
        self,
        *,
        snapshot: AnalysisSnapshot,
        state_machine: DispatcherStateMachine,
        bst_result,
        mba,
        dag_setup: LinearizedFlowGraphPlanSetup,
    ):
        topology_backend = self._projected_topology_backend
        return build_linearized_flow_graph_planning_callbacks(
            snapshot=snapshot,
            state_machine=state_machine,
            bst_result=bst_result,
            mba=mba,
            setup=dag_setup,
            discover_round_summary=_round_ctx_probe_wrap(snapshot, build_linearized_dag_round_summary),
            build_projected_mba=topology_backend.build_projected_mba,
            project_flow_graph=topology_backend.project_flow_graph,
            resolve_redirect_safe_target_entry=self._resolve_redirect_safe_target_entry,
            resolve_initial_entry=resolve_dag_entry_for_state,
            emit_dag_redirect=self._emit_dag_redirect,
            collect_residual_dispatcher_predecessors=self._collect_residual_dispatcher_predecessors,
            resolve_effective_target_entry=self._resolve_effective_target_entry,
            emit_structured_region=lambda *,
                region,
                dag,
                semantic_reference_program,
                structured_regions,
                flow_graph,
                state: self._emit_structured_region_reconstruction(
                    region=region,
                    dag=dag,
                    semantic_reference_program=semantic_reference_program,
                    structured_regions=structured_regions,
                    flow_graph=flow_graph,
                    state=state,
                    state_var_stkoff=dag_setup.state_var_stkoff,
                    dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                    dispatcher=dag_setup.dispatcher,
                    snapshot=snapshot,
                ),
            emit_residual_dispatcher_handoffs=self._emit_residual_dispatcher_handoffs,
            disconnect_bst_comparison_nodes=self._disconnect_bst_comparison_nodes,
            build_live_dag=topology_backend.build_live_dag,
            build_transition_report=build_dispatcher_transition_report_from_graph,
            select_plannable_edges=select_plannable_dag_edges,
        )

    @classmethod
    def _emit_structured_region_reconstruction(
        cls,
        *,
        region: LinearizedDagStructuredRegion,
        dag: LinearizedStateDag,
        semantic_reference_program: object | None,
        structured_regions: tuple[LinearizedDagStructuredRegion, ...],
        flow_graph: object,
        state,
        state_var_stkoff: int | None,
        dispatcher_serial: int,
        dispatcher: object | None,
        snapshot: object | None = None,
    ) -> LinearizedFlowGraphStructuredRegionResult:
        if state_var_stkoff is None:
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=False,
                rejection_reason="missing_state_var_stkoff",
            )

        node_by_key = build_dag_node_maps(dag).node_by_key
        dispatcher_region = set(int(block) for block in dag.bst_node_blocks)
        if int(dispatcher_serial) >= 0:
            dispatcher_region.add(int(dispatcher_serial))
        # B1 step 2: constant_fixpoint is a pass-invariant (computed from
        # pass-entry flow_graph + state_var_stkoff; post-round CFG changes
        # don't alter state-constant propagation). Prefer the canonical
        # pass-entry value from snapshot.discovery when available, avoiding
        # one backend constant-fixpoint compute per region per round.
        ctx = getattr(snapshot, "discovery", None) if snapshot is not None else None
        constant_result = (
            ctx.constant_fixpoint
            if ctx is not None and ctx.constant_fixpoint is not None
            else cls._constant_fixpoint_backend.compute(
                flow_graph,
                int(state_var_stkoff),
            )
        )
        shared_suffix_blocks = collect_shared_suffix_blocks(dag)
        allowed_pairs = {
            (int(source), int(target))
            for source, target in region.internal_state_edges
        }

        lowering_sites = collect_admissible_region_lowering_sites(
            region=region,
            dag=dag,
            node_by_key=node_by_key,
            dispatcher_region=dispatcher_region,
            semantic_reference_program=semantic_reference_program,
            dispatcher=dispatcher,
        )
        lowering_sites = override_exit_sites_with_child_region_entries(
            lowering_sites,
            current_region_name=str(getattr(region, "region_name", "")),
            structured_regions=structured_regions,
            dag=dag,
            dispatcher_region=dispatcher_region,
            semantic_reference_program=semantic_reference_program,
            dispatcher=dispatcher,
        )
        if not lowering_sites:
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=False,
                rejection_reason="no_admissible_region_sites",
            )

        raw_candidates = []
        fallback_candidates: list[ReconstructionCandidate] = []
        for site in lowering_sites:
            edge = site.edge
            if _should_defer_transient_internal_region_site(site=site, dag=dag):
                logger.info(
                    "LFG DAG: structured region %s deferring transient internal site src=0x%08X target=0x%08X path=%s",
                    region.region_name,
                    int(site.source_state) & 0xFFFFFFFF,
                    int(site.target_state) & 0xFFFFFFFF,
                    tuple(int(serial) for serial in site.ordered_path),
                )
                continue
            if (
                int(site.source_state) == 0x11CD1DA3
                and int(site.target_state) == 0x4E69F350
            ):
                logger.info(
                    "LFG DAG: region site src=0x%08X target=0x%08X kind=%s source_entry=%d source_anchor=%d target_entry=%d path=%s semantic_label=%s",
                    int(site.source_state),
                    int(site.target_state),
                    site.site_kind,
                    int(site.source_entry_anchor),
                    int(site.source_anchor_block),
                    int(site.target_entry_anchor),
                    tuple(int(serial) for serial in site.ordered_path),
                    site.semantic_target_label,
                )
            preferred = build_region_preferred_conditional_lowering(
                site=site,
            )
            if (
                str(getattr(region, "region_name", "")) == "sub7ffd_10743c4c_branch_region"
                and int(getattr(site, "source_state", 0)) & 0xFFFFFFFF == 0x6107F8EC
            ):
                logger.info(
                    "LFG DAG: branch site prefilter src=0x%08X succ=%s source_entry=%d source_anchor=%d branch_arm=%s target_entry=%d path=%s preferred=%s",
                    int(site.source_state) & 0xFFFFFFFF,
                    None
                    if site.successor_state_value is None
                    else f"0x{int(site.successor_state_value) & 0xFFFFFFFF:08X}",
                    int(site.source_entry_anchor),
                    int(site.source_anchor_block),
                    getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None),
                    int(site.target_entry_anchor),
                    tuple(int(serial) for serial in (site.ordered_path or ())),
                    None
                    if preferred is None
                    else (
                        str(getattr(preferred, "emission_mode", "")),
                        int(getattr(preferred, "horizon_block", -1)),
                        int(getattr(preferred, "target_entry_anchor", -1)),
                    ),
                )
            preferred = _filter_unsafe_preferred_region_lowering(
                preferred=preferred,
                site=site,
                flow_graph=flow_graph,
                state_var_stkoff=int(state_var_stkoff),
                constant_result=constant_result,
            )
            if (
                str(getattr(region, "region_name", "")) == "sub7ffd_10743c4c_branch_region"
                and int(getattr(site, "source_state", 0)) & 0xFFFFFFFF == 0x6107F8EC
            ):
                logger.info(
                    "LFG DAG: branch site postfilter src=0x%08X succ=%s preferred=%s",
                    int(site.source_state) & 0xFFFFFFFF,
                    None
                    if site.successor_state_value is None
                    else f"0x{int(site.successor_state_value) & 0xFFFFFFFF:08X}",
                    None
                    if preferred is None
                    else (
                        str(getattr(preferred, "emission_mode", "")),
                        int(getattr(preferred, "horizon_block", -1)),
                        int(getattr(preferred, "target_entry_anchor", -1)),
                    ),
                )
            if preferred is None:
                preferred = build_region_preferred_direct_lowering(
                    site=site,
                )
            if (
                int(site.source_state) == 0x11CD1DA3
                and int(site.target_state) == 0x4E69F350
            ):
                logger.info(
                    "LFG DAG: region site preferred lowering=%s",
                    None
                    if preferred is None
                    else (
                        preferred.emission_mode,
                        int(preferred.horizon_block),
                        int(preferred.target_entry_anchor),
                    ),
                )
            if preferred is not None:
                raw_candidates.append(
                    ReconstructionCandidate(
                        edge=edge,
                        horizon_block=int(preferred.horizon_block),
                        site=getattr(edge, "site", None) or type(
                            "_SyntheticStateWriteSite",
                            (),
                            {
                                "block_serial": int(preferred.horizon_block),
                                "state_value": int(site.target_state),
                                "insn_ea": 0,
                                "unsafe_trailing_insn_eas": (),
                            },
                        )(),
                        target_entry=int(preferred.target_entry_anchor),
                        first_shared_block=None,
                        via_pred=None,
                        emission_mode=str(preferred.emission_mode),
                        conditional_group_policy=(
                            "rewrite_horizon"
                            if str(preferred.emission_mode) == "conditional_arm"
                            else "auto"
                        ),
                    )
                )
                continue
            candidate, rejection = build_reconstruction_candidate(
                edge,
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                state_var_stkoff=int(state_var_stkoff),
                constant_result=constant_result,
                shared_suffix_blocks=shared_suffix_blocks,
                dispatcher_region=dispatcher_region,
            )
            if candidate is not None:
                raw_candidates.append(candidate)
                continue

            fallback = build_region_contract_fallback_lowering(
                site=site,
                rejection_reason=(
                    str(rejection.get("rejection_reason"))
                    if isinstance(rejection, dict) and rejection.get("rejection_reason") is not None
                    else None
                ),
            )
            if fallback is None:
                continue

            fallback_candidates.append(
                ReconstructionCandidate(
                    edge=edge,
                    horizon_block=int(fallback.horizon_block),
                    site=getattr(candidate, "site", None) or getattr(edge, "site", None) or type(
                        "_SyntheticStateWriteSite",
                        (),
                        {
                            "block_serial": int(fallback.horizon_block),
                            "state_value": int(site.target_state),
                            "insn_ea": 0,
                            "unsafe_trailing_insn_eas": (),
                        },
                    )(),
                    target_entry=int(fallback.target_entry_anchor),
                    first_shared_block=None,
                    via_pred=None,
                    emission_mode=str(fallback.emission_mode),
                    conditional_group_policy=(
                        "rewrite_horizon"
                        if str(fallback.emission_mode) == "conditional_arm"
                        else "auto"
                    ),
                )
            )

        if not raw_candidates and not fallback_candidates:
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=False,
                rejection_reason="no_reconstruction_candidates",
            )

        raw_candidates.extend(fallback_candidates)
        for candidate in raw_candidates:
            logger.info(
                "LFG DAG: structured region %s candidate mode=%s src=0x%08X target=0x%08X horizon=%d target_entry=%d branch_arm=%s path=%s",
                region.region_name,
                str(getattr(candidate, "emission_mode", "")),
                (
                    int(candidate.edge.source_key.state_const) & 0xFFFFFFFF
                    if getattr(candidate.edge.source_key, "state_const", None) is not None
                    else -1
                ),
                (
                    int(candidate.edge.target_state) & 0xFFFFFFFF
                    if getattr(candidate.edge, "target_state", None) is not None
                    else -1
                ),
                int(candidate.horizon_block),
                int(candidate.target_entry),
                getattr(getattr(candidate.edge, "source_anchor", None), "branch_arm", None),
                tuple(int(serial) for serial in getattr(candidate.edge, "ordered_path", ()) or ()),
            )
        raw_candidates, collapsed_same_target_conditionals = (
            canonicalize_same_target_conditional_candidates(raw_candidates)
        )
        if collapsed_same_target_conditionals:
            logger.info(
                "LFG DAG: structured region %s collapsed %d same-target conditional candidate(s) into direct handoff(s)",
                region.region_name,
                int(collapsed_same_target_conditionals),
            )

        # TODO(loop-bound-writer-guard): mba is not currently in scope at
        # this LFG entry point.  execute_shared_group_reconstruction logs a
        # RECON_SHARED_GROUP_BOUND_WRITER_GUARD_SKIPPED line when mba is
        # None, so any bound-writer cascade routed through this path will
        # be visible in d810.log.  Plumb mba here once the surrounding LFG
        # snapshot/state object exposes it.
        run = execute_primary_reconstruction_modifications(
            raw_candidates=raw_candidates,
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            dispatcher_serial=int(dispatcher_serial),
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
        )
        accepted_candidates = _collect_accepted_reconstruction_candidates(run)
        accepted_sites = _match_accepted_region_sites(
            lowering_sites=lowering_sites,
            accepted_candidates=accepted_candidates,
        )
        narrow_branch_local_fallback_candidates = (
            _build_narrow_branch_local_region_fallback_candidates(
                unresolved_sites=_collect_unmatched_region_sites(
                    lowering_sites=lowering_sites,
                    accepted_sites=accepted_sites,
                ),
                flow_graph=flow_graph,
            )
        )
        narrow_fallback_accepted_count = 0
        if narrow_branch_local_fallback_candidates:
            logger.info(
                "LFG DAG: structured region %s narrow branch-local fallback retrying %d unresolved conditional site(s)",
                region.region_name,
                len(narrow_branch_local_fallback_candidates),
            )
            # TODO(loop-bound-writer-guard): same plumbing gap as the
            # primary call above; relies on the explicit skip-log inside
            # execute_shared_group_reconstruction for visibility.
            fallback_run = execute_primary_reconstruction_modifications(
                raw_candidates=list(narrow_branch_local_fallback_candidates),
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                dispatcher_serial=int(dispatcher_serial),
                modifications=state.modifications,
                owned_blocks=state.owned_blocks,
                owned_edges=state.owned_edges,
            )
            fallback_accepted_candidates = _collect_accepted_reconstruction_candidates(
                fallback_run
            )
            if fallback_accepted_candidates:
                narrow_fallback_accepted_count = len(fallback_accepted_candidates)
                accepted_candidates.extend(fallback_accepted_candidates)
                accepted_sites = _match_accepted_region_sites(
                    lowering_sites=lowering_sites,
                    accepted_candidates=accepted_candidates,
                )
                logger.info(
                    "LFG DAG: structured region %s narrow branch-local fallback accepted %d candidate(s)",
                    region.region_name,
                    narrow_fallback_accepted_count,
                )

        if not accepted_candidates:
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=False,
                rejection_reason="structured_region_no_applied_modifications",
            )

        zero_mods = _collect_structured_region_zero_state_write_modifications(
            accepted_candidates=accepted_candidates,
            flow_graph=flow_graph,
            state_var_stkoff=int(state_var_stkoff),
            constant_result=constant_result,
            existing_modifications=tuple(state.modifications),
        )
        state.modifications.extend(zero_mods)

        direct_count = sum(
            1 for result in run.direct_results if result.accepted_candidate is not None
        )
        conditional_count = len(run.conditional_results)
        shared_count = sum(
            len(result.accepted_candidates) for result in run.shared_group_results
        )
        exit_count = sum(
            1 for site in lowering_sites if site.site_kind == "exit"
        )
        fallback_count = len(fallback_candidates)
        region_state_values = {
            int(state_value) & 0xFFFFFFFF
            for state_value in getattr(region, "state_values", ())
        }
        expected_successors_by_source: dict[int, set[int]] = {}
        for site in lowering_sites:
            successor_state = site.successor_state_value
            if successor_state is None:
                successor_state = getattr(site.edge, "target_state", None)
            if successor_state is None:
                continue
            source_state = int(site.source_state) & 0xFFFFFFFF
            expected_successors_by_source.setdefault(source_state, set()).add(
                int(successor_state) & 0xFFFFFFFF
            )
        accepted_successors_by_source: dict[int, set[int]] = {}
        for site in accepted_sites:
            source_state = getattr(site, "source_state", None)
            successor_state = (
                site.successor_state_value
                if getattr(site, "successor_state_value", None) is not None
                else getattr(getattr(site, "edge", None), "target_state", None)
            )
            if source_state is None or successor_state is None:
                continue
            accepted_successors_by_source.setdefault(
                int(source_state) & 0xFFFFFFFF,
                set(),
            ).add(int(successor_state) & 0xFFFFFFFF)
        unresolved_state_values = frozenset(
            source_state
            for source_state, expected_successors in expected_successors_by_source.items()
            if not expected_successors.issubset(
                accepted_successors_by_source.get(source_state, set())
            )
        )
        successor_state_values = frozenset(
            int(successor_state) & 0xFFFFFFFF
            for site in accepted_sites
            for successor_state in (
                (
                    site.successor_state_value
                    if site.successor_state_value is not None
                    else getattr(site.edge, "target_state", None)
                ),
            )
            if successor_state is not None
            and (int(successor_state) & 0xFFFFFFFF) not in region_state_values
        )
        logger.info(
            "LFG DAG: structured region %s accepted successor states=%s matched_sites=%d",
            region.region_name,
            tuple(f"0x{state_value:08X}" for state_value in sorted(successor_state_values)),
            len(accepted_sites),
        )
        logger.info(
            "LFG DAG: structured region %s accepted %d candidates (direct=%d conditional=%d shared=%d exit_sites=%d fallback_sites=%d cleanup_sites=%d unresolved_sources=%s)",
            region.region_name,
            len(accepted_candidates),
            direct_count,
            conditional_count + narrow_fallback_accepted_count,
            shared_count,
            exit_count,
            fallback_count,
            len(zero_mods),
            tuple(f"0x{state_value:08X}" for state_value in sorted(unresolved_state_values)),
        )
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            consumed_state_edges=_collect_consumed_structured_region_state_edges(
                accepted_sites=accepted_sites,
                accepted_candidates=accepted_candidates,
            ),
            successor_state_values=successor_state_values,
            unresolved_state_values=unresolved_state_values,
            transition_count=int(direct_count + shared_count),
            conditional_count=int(conditional_count),
        )


@algorithm_metadata(
    algorithm_id="hodur.semantic_structured_region",
    family="structured_region_semantic_lowering",
    summary="Region-first lowering that compiles trusted structured semantic regions before any raw DAG edge redirects.",
    use_cases=(
        "Try semantic-region realization against the linearized state program without bulk exact-row lowering.",
        "Keep dispatcher bypass grounded in region ownership instead of feeder-row redirects.",
    ),
    examples=(
        "Lower sub_7FFD structured regions using reconstruction candidates derived only from admissible semantic entries.",
    ),
    tags=("hodur", "semantic-region", "structured-lowering", "region-first"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/linearized_flow_graph.py",
        "src/d810/cfg/semantic_region_lowering.py",
    ),
)
class SemanticStructuredRegionStrategy(LinearizedFlowGraphStrategy):
    """Region-first variant of LFG that disables raw plannable-edge lowering."""

    lowering_mode = LoweringMode.STRUCTURED_REGION

    @property
    def name(self) -> str:
        return "semantic_structured_region"

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        mba = getattr(snapshot, "mba", None)
        if not _LIVE_MICROCODE_PROPERTIES.has_maturity(mba, "global_opt_1"):
            return False
        return super().is_applicable(snapshot)

    def _build_planning_callbacks(
        self,
        *,
        snapshot: AnalysisSnapshot,
        state_machine: DispatcherStateMachine,
        bst_result,
        mba,
        dag_setup: LinearizedFlowGraphPlanSetup,
    ):
        topology_backend = self._projected_topology_backend
        return build_linearized_flow_graph_planning_callbacks(
            snapshot=snapshot,
            state_machine=state_machine,
            bst_result=bst_result,
            mba=mba,
            setup=dag_setup,
            discover_round_summary=_round_ctx_probe_wrap(snapshot, build_linearized_dag_round_summary),
            build_projected_mba=topology_backend.build_projected_mba,
            project_flow_graph=topology_backend.project_flow_graph,
            resolve_redirect_safe_target_entry=self._resolve_redirect_safe_target_entry,
            resolve_initial_entry=resolve_dag_entry_for_state,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=self._collect_residual_dispatcher_predecessors,
            resolve_effective_target_entry=self._resolve_effective_target_entry,
            emit_structured_region=lambda *,
                region,
                dag,
                semantic_reference_program,
                structured_regions,
                flow_graph,
                state: self._emit_structured_region_reconstruction(
                    region=region,
                    dag=dag,
                    semantic_reference_program=semantic_reference_program,
                    structured_regions=structured_regions,
                    flow_graph=flow_graph,
                    state=state,
                    state_var_stkoff=dag_setup.state_var_stkoff,
                    dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                    dispatcher=dag_setup.dispatcher,
                    snapshot=snapshot,
                ),
            emit_residual_dispatcher_handoffs=self._emit_residual_dispatcher_handoffs,
            disconnect_bst_comparison_nodes=self._disconnect_bst_comparison_nodes,
            build_live_dag=topology_backend.build_live_dag,
            build_transition_report=build_dispatcher_transition_report_from_graph,
            select_plannable_edges=select_plannable_dag_edges,
            include_synthetic_exact_regions=False,
        )

    def _apply_bounded_postprocess(
        self,
        *,
        snapshot: AnalysisSnapshot,
        state_machine: DispatcherStateMachine,
        bst_result,
        flow_graph: object,
        mba: object | None,
        dag_setup: LinearizedFlowGraphPlanSetup,
        dag_result,
    ):
        state_var_stkoff = dag_setup.state_var_stkoff
        if state_var_stkoff is None:
            return dag_result

        modifications = list(dag_result.modifications)
        original_modification_count = len(modifications)
        if not modifications:
            return dag_result

        try:
            projected_flow_graph = (
                self._projected_topology_backend.project_flow_graph(
                    flow_graph,
                    modifications,
                )
            )
        except Exception as exc:
            logger.info(
                "LFG DAG: bounded postprocess skipped (projection_failed=%s)",
                exc,
            )
            return dag_result

        try:
            projected_mba = self._projected_topology_backend.build_projected_mba(
                projected_flow_graph
            )
        except Exception as exc:
            logger.info(
                "LFG DAG: bounded postprocess skipped (projected_mba_failed=%s)",
                exc,
            )
            return dag_result

        corrected_dag_out: list = []
        dag = self._projected_topology_backend.build_live_dag(
            projected_flow_graph,
            dag_setup.transition_result,
            dispatcher_entry_serial=int(snapshot.bst_dispatcher_serial),
            state_var_stkoff=int(state_var_stkoff),
            pre_header_serial=dag_setup.pre_header_serial,
            initial_state=getattr(state_machine, "initial_state", None),
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(
                sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
            ),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=projected_mba,
            prefer_local_corridors=True,
            corrected_dag_out=corrected_dag_out,
        )
        corrected_dag = corrected_dag_out[0] if corrected_dag_out else dag

        constant_result = self._constant_fixpoint_backend.compute(
            flow_graph,
            int(state_var_stkoff),
        )
        node_by_key = build_dag_node_maps(dag).node_by_key
        rejected_metadata: list[dict[str, int | str | None]] = []
        owned_blocks = set(int(serial) for serial in dag_result.owned_blocks)
        owned_edges = {
            (int(src), int(dst))
            for src, dst in (getattr(dag_result, "owned_edges", ()) or ())
        }
        postprocess = execute_reconstruction_postprocess(
            dag=dag,
            corrected_dag=corrected_dag,
            flow_graph=flow_graph,
            modifications=modifications,
            builder=dag_setup.builder,
            dispatcher_region=set(int(serial) for serial in dag_setup.dispatcher_region),
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
            bst_result=bst_result,
            state_machine=state_machine,
            state_var_stkoff=int(state_var_stkoff),
            constant_result=constant_result,
            node_by_key=node_by_key,
            rejected_metadata=rejected_metadata,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            collect_entry_island_rescue_seeds=collect_entry_island_rescue_seeds,
            collect_late_entry_island_diagnostics=collect_late_entry_island_diagnostics,
            collect_late_entry_island_rescue_seeds=collect_late_entry_island_rescue_seeds,
            collect_residual_dispatcher_predecessors=self._collect_residual_dispatcher_predecessors,
            compute_reachable_blocks=compute_reachable_blocks,
            classify_artifact_return_blocks=classify_artifact_return_blocks,
            collect_common_return_corridor=collect_common_return_corridor,
            collect_terminal_family_report=collect_terminal_family_report,
            build_reconstruction_candidate=build_reconstruction_candidate,
            resolve_effective_target_entry=self._resolve_effective_target_entry,
            build_projected_mba=(
                self._projected_topology_backend.build_projected_mba
            ),
            discover_residual_alias_overrides_fn=discover_residual_alias_overrides,
        )

        if len(modifications) == original_modification_count:
            return replace(
                dag_result,
                cleanup_gate_reason=postprocess.post_apply_bst_cleanup_reason,
                residual_dispatcher_preds=tuple(
                    int(serial) for serial in postprocess.residual_dispatcher_preds
                ),
            )

        appended_modifications = tuple(modifications[original_modification_count:])
        normalized_appended_modifications, collapsed_branch_count = (
            _normalize_duplicate_target_redirect_branches(
                appended_modifications,
                flow_graph=projected_flow_graph,
            )
        )
        if collapsed_branch_count:
            appended_modifications = normalized_appended_modifications
            logger.info(
                "LFG DAG: bounded postprocess normalized %d duplicate-target branch redirect(s) into goto(s)",
                collapsed_branch_count,
            )

        filtered_appended_modifications = tuple(
            modification
            for modification in appended_modifications
            if not isinstance(
                modification,
                (
                    ConvertToGoto,
                    PrivateTerminalSuffix,
                    PrivateTerminalSuffixGroup,
                ),
            )
        )
        if len(filtered_appended_modifications) != len(appended_modifications):
            logger.info(
                "LFG DAG: bounded postprocess filtered %d high-risk late modification(s) for region-first execution",
                len(appended_modifications) - len(filtered_appended_modifications),
            )
            appended_modifications = filtered_appended_modifications

        appended_modifications = _filter_lfg_use_def_vetoes(
            appended_modifications,
            enabled=_lfg_use_def_veto_enabled(),
            mba=mba,
            flow_graph=flow_graph,
            state_var_stkoff=state_var_stkoff,
        )

        modifications = [
            *modifications[:original_modification_count],
            *appended_modifications,
        ]

        for index, modification in enumerate(appended_modifications, start=1):
            logger.info(
                "LFG DAG: bounded postprocess mod[%d/%d] %r",
                index,
                len(appended_modifications),
                modification,
            )
        logger.info(
            "LFG DAG: bounded postprocess appended %d modification(s), residual_dispatcher_preds=%s cleanup_gate=%s",
            len(appended_modifications),
            tuple(int(serial) for serial in postprocess.residual_dispatcher_preds),
            postprocess.post_apply_bst_cleanup_reason,
        )
        return replace(
            dag_result,
            modifications=tuple(modifications),
            owned_blocks=frozenset(int(serial) for serial in owned_blocks),
            owned_edges=frozenset((int(src), int(dst)) for src, dst in owned_edges),
            cleanup_gate_reason=postprocess.post_apply_bst_cleanup_reason,
            residual_dispatcher_preds=tuple(
                int(serial) for serial in postprocess.residual_dispatcher_preds
            ),
        )

    @classmethod
    def _emit_residual_dispatcher_handoffs(
        cls,
        *,
        dag: LinearizedStateDag,
        state_machine: DispatcherStateMachine | None,
        projected_flow_graph: object,
        dispatcher_serial: int,
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
        claimed_2way: dict[tuple[int, int], int],
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None = None,
        mba: object | None = None,
        redirected_blocks: set[int] | None = None,
        rejected_sources: set[int] | None = None,
    ) -> int:
        result = emit_residual_dispatcher_handoffs(
            dag=dag,
            state_machine=state_machine,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=int(dispatcher_serial),
            bst_node_blocks=bst_node_blocks,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            redirected_blocks=redirected_blocks,
            collect_residual_dispatcher_predecessors=cls._collect_residual_dispatcher_predecessors,
            build_projected_mba=(
                cls._projected_topology_backend.build_projected_mba
            ),
            collect_residual_source_handoff_facts=collect_residual_source_handoff_facts,
            iter_residual_prefix_handoffs=iter_residual_prefix_handoffs,
            can_rewrite_shared_suffix_family_fallback=can_rewrite_shared_suffix_family_fallback,
            has_prior_branch_cut_for_state=has_prior_branch_cut_for_state,
            is_shared_suffix_conditional_tail=is_shared_suffix_conditional_tail,
            pred_split_target_reaches_via_pred=pred_split_target_reaches_via_pred,
            resolve_synthesized_handoff_target=cls._resolve_synthesized_handoff_target,
            resolve_projected_path_tail_target=cls._resolve_projected_path_tail_target,
            resolve_immediate_handoff_target=cls._resolve_immediate_handoff_target,
            resolve_effective_target_entry=cls._resolve_effective_target_entry,
        )
        log_residual_dispatcher_handoff_outcomes(
            logger,
            mba=mba,
            outcomes=result.outcomes,
        )
        if rejected_sources is not None:
            for outcome in result.outcomes:
                if not outcome.source_plan.accepted:
                    rejected_sources.add(int(outcome.source_block))
        return int(result.redirected_count)

    @classmethod
    def _normalize_projected_alias_handoffs(
        cls,
        *,
        dag: LinearizedStateDag,
        projected_flow_graph: object,
        dispatcher_serial: int,
        redirected_blocks: set[int],
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
        mba: object,
    ) -> int:
        return normalize_projected_alias_handoffs(
            dag=dag,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=int(dispatcher_serial),
            redirected_blocks=redirected_blocks,
            bst_node_blocks=bst_node_blocks,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            emitted=emitted,
            claimed_1way=claimed_1way,
            resolve_projected_path_tail_target=cls._resolve_projected_path_tail_target,
            log_action=lambda action: logger.info(
                "LFG DAG: normalized projected residual handoff %s -> %s (was %s)",
                blk_label(mba, int(action.source_block)),
                blk_label(mba, int(action.target_entry)),
                blk_label(mba, int(action.current_target)),
            ),
        )

    @classmethod
    def _emit_path_tail_redirect(
        cls,
        *,
        edge: StateDagEdge,
        target_entry: int | None = None,
        dag: LinearizedStateDag,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int] | None = None,
        claimed_exits: dict[int, int],
        claimed_path_edges: dict[tuple[int, int], int],
        blocked_sources: set[int],
        terminal_source_keys: set[object],
        terminal_source_handlers: set[int],
        terminal_source_owned_blocks: set[int],
        terminal_protected_blocks: set[int],
        report_exit_handlers: set[int],
        report_exit_owned_blocks: set[int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        flow_graph: object,
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None = None,
        mba: object | None = None,
    ) -> bool:
        result = emit_path_tail_redirect(
            edge=edge,
            target_entry=target_entry,
            dag=dag,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_exits=claimed_exits,
            claimed_path_edges=claimed_path_edges,
            blocked_sources=blocked_sources,
            report_exit_handlers=report_exit_handlers,
            report_exit_owned_blocks=report_exit_owned_blocks,
            terminal_protected_blocks=terminal_protected_blocks,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
            flow_graph=flow_graph,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            resolve_effective_target_entry=cls._resolve_effective_target_entry,
            resolve_immediate_handoff_target=cls._resolve_immediate_handoff_target,
            find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
            is_semantic_handoff_redirect=is_semantic_handoff_redirect,
        )
        return log_path_tail_redirect_outcome(
            logger,
            mba=mba,
            edge=edge,
            result=result,
        )

    @classmethod
    def _emit_dag_redirect(
        cls,
        *,
        edge: StateDagEdge,
        dag: LinearizedStateDag,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
        claimed_2way: dict[tuple[int, int], int],
        claimed_exits: dict[int, int],
        claimed_path_edges: dict[tuple[int, int], int],
        blocked_sources: set[int],
        terminal_source_keys: set[object],
        terminal_source_handlers: set[int],
        terminal_source_owned_blocks: set[int],
        terminal_protected_blocks: set[int],
        report_exit_handlers: set[int],
        report_exit_owned_blocks: set[int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        flow_graph: object,
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        mba: object,
        dispatcher: object | None = None,
    ) -> bool:
        accepted, result = emit_dag_redirect(
            edge=edge,
            dag=dag,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            claimed_exits=claimed_exits,
            claimed_path_edges=claimed_path_edges,
            blocked_sources=blocked_sources,
            terminal_source_keys=terminal_source_keys,
            terminal_source_handlers=terminal_source_handlers,
            terminal_source_owned_blocks=terminal_source_owned_blocks,
            terminal_protected_blocks=terminal_protected_blocks,
            report_exit_handlers=report_exit_handlers,
            report_exit_owned_blocks=report_exit_owned_blocks,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
            flow_graph=flow_graph,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            resolve_effective_target_entry=cls._resolve_effective_target_entry,
            resolve_immediate_handoff_target=cls._resolve_immediate_handoff_target,
            find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
            is_semantic_handoff_redirect=is_semantic_handoff_redirect,
        )
        if result is None:
            return accepted
        return log_dag_redirect_fallback_outcome(
            logger,
            mba=mba,
            edge=edge,
            result=result,
        )

    # ------------------------------------------------------------------
    # Resolved state machine DOT graph
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # EXIT state resolution via handler_state_map
    # ------------------------------------------------------------------

    @staticmethod
    def _disconnect_bst_comparison_nodes(
        bst_node_blocks: set[int],
        dispatcher_serial: int,
        builder: ModificationBuilder,
        modifications: list,
        emitted: set[tuple[int, int]],
        *,
        mba: object | None = None,
    ) -> int:
        """Convert 2-way blocks with dispatcher back-edges to 1-way.

        After linearization, handler exits have been redirected to their
        target handler entries and state variable writes have been NOP'd.
        However, some 2-way blocks (BST comparison nodes or handler
        conditionals) may still have the dispatcher as one successor.
        These back-edges create ``while`` loops in the decompiled output.

        Emits :class:`ConvertToGoto` keeping the non-dispatcher successor.

        Args:
            bst_node_blocks: Set of BST comparison block serials.
            dispatcher_serial: Serial of the dispatcher entry block.
            builder: Modification builder for emitting graph edits.
            modifications: List to append new modifications to.
            emitted: Set of ``(from, to)`` pairs for dedup.

        Returns:
            Number of blocks disconnected from the dispatcher.
        """
        return disconnect_bst_comparison_nodes(
            set(int(block) for block in bst_node_blocks),
            int(dispatcher_serial),
            builder,
            modifications,
            emitted,
            log_plan=lambda plan: logger.info(
                "BST_DISCONNECT: %s (%s) 2-way -> 1-way goto "
                "%s (removed dispatcher back-edge to %s)",
                blk_label(mba, int(plan.source_block))
                if mba
                else f"blk[{int(plan.source_block)}]",
                "BST" if plan.is_bst else "handler",
                blk_label(mba, int(plan.keep_target))
                if mba
                else f"blk[{int(plan.keep_target)}]",
                blk_label(mba, dispatcher_serial) if mba else f"blk[{dispatcher_serial}]",
            ),
        )


# NOTE: The legacy LinearizedFlowGraphStrategy still owns the callback wiring
# for these helper seams, while the region-first subclass is no longer part of
# the default Hodur strategy list. Keep the base class method surface intact
# until this file is split cleanly or the legacy strategy is deleted outright.
for _lfg_helper_name in (
    "_apply_bounded_postprocess",
    "_emit_residual_dispatcher_handoffs",
    "_normalize_projected_alias_handoffs",
    "_emit_path_tail_redirect",
    "_emit_dag_redirect",
    "_disconnect_bst_comparison_nodes",
):
    setattr(
        LinearizedFlowGraphStrategy,
        _lfg_helper_name,
        SemanticStructuredRegionStrategy.__dict__[_lfg_helper_name],
    )
del _lfg_helper_name
