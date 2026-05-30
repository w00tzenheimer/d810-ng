"""Experimental DAG-driven reconstruction strategy.

This strategy is reconstruction-first rather than dispatcher-first. It walks
semantic DAG edges, finds the deepest proven state-write horizon on each edge's
concrete corridor, and then rebuilds the corridor with the least invasive
rewrite that still removes the dispatcher handoff:

- direct truncation when the horizon is private and its trailing glue is clean
- predecessor split when a shared/merged block is uniquely reached via one pred
- grouped duplication when several predecessors of one shared block need
  different semantic targets
"""
from __future__ import annotations

from d810.cfg.state_edge_pair import state_edge_pair

from collections import Counter, defaultdict
from dataclasses import replace
import os

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.reconstruction_emission import (
    apply_shared_group_reachability_fallback,
    execute_primary_reconstruction_modifications,
    execute_shared_group_reconstruction,
)
from d810.cfg.reconstruction_postprocess_emission import (
    execute_reconstruction_postprocess,
)
from d810.cfg.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
)
from d810.cfg.reconstruction_recording import RoundAcceptLedger
from d810.hexrays.mutation.ir_translator import (
    classify_live_insn_kind,
    classify_live_operand_kind,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    blk_label,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_reporting import (
    log_reconstruction_postprocess_result,
    snapshot_reconstruction_dag,
    snapshot_reconstruction_post_apply,
)
from d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend import (
    ConstantFixpointBackend,
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND,
)
from d810.cfg.graph_modification import (
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
)
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.modification_builder import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.reconstruction_fragment_builder import (
    finalize_reconstruction_fragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.projected_topology_backend import (
    HodurProjectedTopologyBackend,
    ProjectedTopologyBackend,
)
from d810.analyses.control_flow.linearized_dag_round_discovery import (
    discover_structured_dag_regions,
)
from d810.analyses.control_flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    build_live_linearized_state_dag_from_graph,
    build_linearized_state_program,
)
from d810.analyses.control_flow.recon_dag_index import build_dag_node_maps
from d810.analyses.control_flow.edge_metadata import make_edge_metadata
from d810.analyses.control_flow.edge_metadata import edge_kind_name
from d810.analyses.control_flow.full_coverage_chain_probe import log_chain_coverage
from d810.analyses.control_flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
    collect_boundary_protected_shared_blocks,
    collect_shared_suffix_blocks,
    resolve_state_var_stkoff,
)
from d810.analyses.control_flow.reconstruction_discovery_indexes import (
    build_reconstruction_discovery_indexes,
)
from d810.analyses.control_flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.analyses.control_flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.analyses.control_flow.return_corridor_discovery import (
    collect_common_return_corridor,
)
from d810.analyses.control_flow.terminal_family_collection import (
    collect_terminal_family_report,
)
from functools import partial as _partial

from d810.cfg.reconstruction_planning import plan_reconstruction_candidate
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
from d810.analyses.control_flow.residual_alias_discovery import (
    discover_residual_alias_overrides,
)
from d810.analyses.control_flow.transition_builder import (
    TransitionResult,
    build_transition_result_from_state_machine,
)
from d810.analyses.control_flow.conditional_arm_canonicalization import (
    canonicalize_same_target_conditional_candidates,
)
from d810.analyses.control_flow.shared_group_bucketing import (
    group_candidates_by_shared_block,
)
from d810.analyses.control_flow.narrow_branch_local_discovery import (
    discover_narrow_branch_local_reconstruction_candidates,
)
from d810.analyses.control_flow.frontier_override_discovery import (
    discover_frontier_overrides,
)
from d810.cfg.frontier_override_emission import emit_frontier_overrides
from d810.analyses.control_flow.missing_via_pred_discovery import (
    discover_missing_via_pred_direct_overrides,
)
from d810.cfg.reconstruction_missing_via_pred_emission import (
    emit_missing_via_pred_direct_overrides,
)
from d810.analyses.control_flow.force_edge_override_discovery import (
    discover_force_edge_overrides,
)
from d810.cfg.reconstruction_force_edge_override_emission import (
    execute_force_edge_override,
)
from d810.analyses.control_flow.structured_region_fidelity_report import (
    build_structured_region_fidelity_report,
    collect_sub7ffd_may_only_probe_blocks,
)
from d810.transforms.reconstruction_diagnostics import (
    log_reconstruction_candidate_probe,
    log_reconstruction_phase_probe,
)

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)


class _StrategyProjectedTopologyBackend(HodurProjectedTopologyBackend):
    """Strategy-local seam for tests that monkeypatch the historical builder."""

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


_PROJECTED_TOPOLOGY_BACKEND: ProjectedTopologyBackend = (
    _StrategyProjectedTopologyBackend()
)
_CONSTANT_FIXPOINT_BACKEND: ConstantFixpointBackend = (
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND
)

__all__ = ["StateWriteReconstructionStrategy"]

_SUB7FFD_INITIAL_REGION_NAME = "sub7ffd_initial_semantic_region"
_SUB7FFD_INITIAL_FORCE_EDGE = (0x139F2922, 0x63F502FA)
_SUB7FFD_DOWNSTREAM_REGION_NAME = "sub7ffd_downstream_chain_region"
_SUB7FFD_DOWNSTREAM_FORCE_EDGE = (0x32FCD904, 0x2E6C61F3)
_SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE = (0x2E6C61F3, 0x652D7A98)
_SUB7FFD_RETRY_CHAIN_REGION_NAME = "sub7ffd_retry_chain_region"
_SUB7FFD_RETRY_CHAIN_FORCE_EDGES = (
    (0x37B42A40, 0x63D54755),
    (0x63D54755, 0x57BE6FD0),
    (0x57BE6FD0, 0x03E42B03),
    (0x03E42B03, 0x610BB4D9),
)
_SUB7FFD_6D207773_CORRIDOR_REGION_NAME = "sub7ffd_6d207773_corridor_region"
_SUB7FFD_6D207773_CORRIDOR_FORCE_EDGE = (0x0B2FECE0, 0x2A5E29F6)
_SUB7FFD_7C2C0220_CORRIDOR_REGION_NAME = "sub7ffd_7c2c0220_corridor_region"
_SUB7FFD_7C2C0220_CORRIDOR_FORCE_EDGE = (0x385BBE2D, 0x10743C4C)
_SUB7FFD_FUNC_EA = 0x180012B60
_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE = 34
_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET = 26
_SUB7FFD_FORCED_REGION_EDGES: dict[str, tuple[tuple[int, int], ...]] = {
    _SUB7FFD_INITIAL_REGION_NAME: (_SUB7FFD_INITIAL_FORCE_EDGE,),
    _SUB7FFD_DOWNSTREAM_REGION_NAME: (
        _SUB7FFD_DOWNSTREAM_FORCE_EDGE,
        _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE,
    ),
    _SUB7FFD_RETRY_CHAIN_REGION_NAME: _SUB7FFD_RETRY_CHAIN_FORCE_EDGES,
}
_ENABLE_STRUCTURED_REGION_OVERLAY = False


def _parse_relaxed_lateclone_shared_blocks() -> frozenset[int]:
    raw_value = os.getenv("D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS", "").strip()
    if not raw_value:
        return frozenset()
    relaxed: set[int] = set()
    for token in raw_value.replace(",", " ").split():
        try:
            relaxed.add(int(token, 0))
        except ValueError:
            logger.info(
                "RECON DAG: ignoring invalid late-clone relaxation token=%r",
                token,
            )
    return frozenset(relaxed)


def _parse_force_keep_per_pred_shared_blocks() -> frozenset[int]:
    raw_value = os.getenv("D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS", "").strip()
    if not raw_value:
        return frozenset()
    keep: set[int] = set()
    for token in raw_value.replace(",", " ").split():
        try:
            keep.add(int(token, 0))
        except ValueError:
            logger.info(
                "RECON DAG: ignoring invalid force-keep per-pred token=%r",
                token,
            )
    return frozenset(keep)


def _parse_force_clone_primary_shared_blocks() -> frozenset[int]:
    raw_value = os.getenv("D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS", "").strip()
    if not raw_value:
        return frozenset()
    forced: set[int] = set()
    for token in raw_value.replace(",", " ").split():
        try:
            forced.add(int(token, 0))
        except ValueError:
            logger.info(
                "RECON DAG: ignoring invalid primary force-clone token=%r",
                token,
            )
    return frozenset(forced)




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


def _should_defer_force_edge_materialization(
    *,
    region_name: str,
    force_edge: tuple[int, int],
    override_candidates: list[object],
) -> bool:
    # Later same-maturity reruns can still carry trusted region ownership even
    # when the live graph no longer exposes a safe direct override candidate.
    # For sub_7FFD's downstream head edge, forcing the cached direct redirect
    # too early suppresses the bridge/post-bridge rescue sequence that currently
    # yields the less-bad CFG shape, so keep this edge deferred.
    return (
        region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
        and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
        and not override_candidates
    )


def _record_accept_metadata(
    metadata: list[dict[str, int | str | None]],
    candidate,
) -> None:
    metadata.append(
        make_edge_metadata(
            candidate.edge,
            horizon_block=candidate.horizon_block,
            site=candidate.site,
            target_entry=candidate.target_entry,
            first_shared_block=candidate.first_shared_block,
            via_pred=candidate.via_pred,
            emission_mode=candidate.emission_mode,
        )
    )


def _collect_rejected_reconstruction_candidates(run) -> list[object]:
    rejected: list[object] = []
    for result in getattr(run, "direct_results", ()):
        rejected.extend(getattr(result, "rejected_candidates", ()))
    for result in getattr(run, "shared_group_results", ()):
        rejected.extend(getattr(result, "rejected_candidates", ()))
    return rejected


def _build_execution_probe_metadata(
    run,
) -> tuple[list[dict[str, int | str | None]], list[dict[str, int | str | None]]]:
    accepted_metadata: list[dict[str, int | str | None]] = []
    rejected_metadata: list[dict[str, int | str | None]] = []
    for result in getattr(run, "conditional_results", ()):
        _record_accept_metadata(accepted_metadata, result.candidate)
    for result in getattr(run, "direct_results", ()):
        accepted_candidate = getattr(result, "accepted_candidate", None)
        if accepted_candidate is not None:
            _record_accept_metadata(accepted_metadata, accepted_candidate)
        for candidate in getattr(result, "rejected_candidates", ()):
            rejected_metadata.append(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=result.rejection_reason,
                )
            )
    for result in getattr(run, "shared_group_results", ()):
        for candidate in getattr(result, "accepted_candidates", ()):
            _record_accept_metadata(accepted_metadata, candidate)
        for candidate in getattr(result, "rejected_candidates", ()):
            rejected_metadata.append(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=result.rejection_reason,
                )
            )
    return accepted_metadata, rejected_metadata


@algorithm_metadata(
    algorithm_id="hodur.state_write_reconstruction",
    family="structured_semantic_region_lowering",
    summary="Reconstructs semantic corridors from state-write horizons and shared-group lowering.",
    use_cases=(
        "Promote proven state-write corridors into direct CFG rewrites when simple exact-node lowering is insufficient.",
        "Own shared groups, pred-split sites, and structured-region corridors using state-write provenance.",
    ),
    examples=(
        "Rebuild a retry-chain corridor from horizon-discovered state writes and shared-group emission.",
        "Choose between duplicate-and-redirect, per-pred redirect, and source-arm redirect for a reconstructed site.",
    ),
    tags=("reconstruction", "state-write", "structured-region", "shared-group"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/reconstruction.py",
        "src/d810/cfg/linearized_flow_graph_fragment_planning.py",
    ),
)
class StateWriteReconstructionStrategy:
    """Reconstruct proven semantic corridors from state-write horizons."""

    prerequisites: list[str] = []

    def __init__(self):
        self._cached_structured_regions_by_round: dict[
            tuple[int, int], tuple[object, ...]
        ] = {}
        self._cached_force_edge_direct_overrides_by_round: dict[
            tuple[int, int, tuple[int, int]], tuple[int, int, tuple[int, ...]]
        ] = {}
        self._projected_topology_backend: ProjectedTopologyBackend = (
            _PROJECTED_TOPOLOGY_BACKEND
        )
        self._constant_fixpoint_backend: ConstantFixpointBackend = (
            _CONSTANT_FIXPOINT_BACKEND
        )

    @property
    def name(self) -> str:
        return "state_write_reconstruction"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    @staticmethod
    def _classify_artifact_return_blocks(
        flow_graph,
        state_var_stkoff: int,
        state_constants: set[int],
    ) -> set[int]:
        return classify_artifact_return_blocks(
            flow_graph,
            state_var_stkoff=state_var_stkoff,
            state_constants=state_constants,
        )

    def is_applicable(self, snapshot) -> bool:
        sm = snapshot.state_machine
        flow_graph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        if sm is None or flow_graph is None or bst_result is None:
            return False
        if not sm.handlers:
            return False
        return resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        ) is not None

    @classmethod
    def _emit_shared_group(
        cls,
        shared_block: int,
        candidates: list[ReconstructionCandidate],
        *,
        flow_graph,
        dispatcher_serial: int,
        bst_node_blocks: set[int],
        mba,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        accepted_metadata: list[dict[str, int | str | None]],
        rejected_metadata: list[dict[str, int | str | None]],
    ) -> int:
        del cls, dispatcher_serial, bst_node_blocks, builder
        shared_result = execute_shared_group_reconstruction(
            shared_block=int(shared_block),
            candidates=candidates,
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            mba=mba,
            insn_kind_classifier=classify_live_insn_kind,
            operand_kind_classifier=classify_live_operand_kind,
        )
        if not shared_result.accepted_candidates and not shared_result.rejected_candidates:
            return 0

        if shared_result.rejected_candidates:
            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=shared_result.rejection_reason,
                )
                for candidate in shared_result.rejected_candidates
            )
            return 0
        for candidate in shared_result.accepted_candidates:
            _record_accept_metadata(
                accepted_metadata,
                replace(candidate, emission_mode=shared_result.emission_mode),
            )
        if shared_result.emission_mode == "per_pred_redirect":
            logger.info(
                "RECON DAG: per-pred-redirect %s preds=%s (clone avoided)",
                blk_label(mba, shared_block),
                [
                    (blk_label(mba, pred), blk_label(mba, target))
                    for pred, target in shared_result.per_pred_targets
                ],
            )
        elif shared_result.emission_mode == "single_pred_redirect":
            logger.info(
                "RECON DAG: single-pred-redirect %s preds=%s",
                blk_label(mba, shared_block),
                [
                    (blk_label(mba, pred), blk_label(mba, target))
                    for pred, target in shared_result.per_pred_targets
                ],
            )
        elif shared_result.emission_mode == "source_arm_redirect":
            logger.info(
                "RECON DAG: source-arm-redirect %s preds=%s",
                blk_label(mba, shared_block),
                [
                    (blk_label(mba, pred), blk_label(mba, target))
                    for pred, target in shared_result.per_pred_targets
                ],
            )
        else:
            logger.info(
                "RECON DAG: duplicate-and-redirect %s preds=%s",
                blk_label(mba, shared_block),
                [
                    (blk_label(mba, pred), blk_label(mba, target))
                    for pred, target in shared_result.per_pred_targets
                ],
            )
        return len(shared_result.accepted_candidates)

    def plan(self, snapshot):
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        bst_result = snapshot.bst_result
        flow_graph = snapshot.flow_graph
        mba = snapshot.mba
        assert sm is not None
        assert bst_result is not None
        assert flow_graph is not None

        state_var_stkoff = resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        )
        if state_var_stkoff is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        transition_result = build_transition_result_from_state_machine(
            sm,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
        )
        _corrected_dag_out: list = []
        dag = self._projected_topology_backend.build_live_dag(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=sm.initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(
                sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
            ),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
            corrected_dag_out=_corrected_dag_out,
        )
        # dag: stale augmented DAG (baseline behavior).  Used for phase 1
        # corridor candidates so redirect targets are identical to baseline.
        # corrected_dag: augmented DAG with dispatcher-validated supplemental
        # anchors.  Used for late phases (bridge, feeder, island rescue,
        # terminal family) that benefit from correct supplemental targets.
        corrected_dag = _corrected_dag_out[0] if _corrected_dag_out else dag

        # D810_DIAG_FULL_COVERAGE_CHAIN=1 → log SCC-based full-coverage
        # chain diagnostic. Observational only; validates that a Tarjan-SCC
        # traversal would cover every DAG state (Option A from
        # .claude/notes/investigations/2026-04-23-sub_7ffd_lowering.md).
        log_chain_coverage(corrected_dag, context_label="SRW corrected_dag")

        constant_result = self._constant_fixpoint_backend.compute(
            flow_graph,
            state_var_stkoff,
        )
        structured_regions = ()
        if _ENABLE_STRUCTURED_REGION_OVERLAY:
            semantic_reference_program = build_linearized_state_program(
                dag,
                order_strategy=RenderOrderStrategy.SEMANTIC,
                program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
                label_render_mode=LabelRenderMode.STATE_FAMILY,
                boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
                comment_mode=ProgramCommentMode.MINIMAL,
            )
            structured_regions = discover_structured_dag_regions(
                dag,
                semantic_reference_program=semantic_reference_program,
            )
        cache_key = (
            int(getattr(mba, "entry_ea", 0) or 0),
            int(getattr(mba, "maturity", 0) or 0),
        )
        if structured_regions:
            self._cached_structured_regions_by_round[cache_key] = tuple(structured_regions)
        else:
            cached_structured_regions = self._cached_structured_regions_by_round.get(
                cache_key, ()
            )
            if cached_structured_regions:
                logger.info(
                    "RECON DAG: cached structured regions available for func=0x%X maturity=%s but deferred because the live pass could not rediscover them: names=%s",
                    cache_key[0],
                    maturity_to_string(cache_key[1]),
                    [str(region.region_name) for region in cached_structured_regions],
                )
        # Snapshot for diagnostics, then apply selected-alternate overrides
        # from the in-memory fact view so SQLite availability cannot affect
        # behavior.
        _snapshot_result = snapshot_reconstruction_dag(
            logger,
            dag=dag,
            mba=mba,
            strategy_name=self.name,
        )
        from d810.analyses.control_flow.selected_alternate_edge_override import (
            apply_selected_alternate_edge_overrides,
            derive_selected_alternate_edge_override_map,
        )
        fact_view = getattr(snapshot, "diagnostic_fact_view", None)
        override_map = derive_selected_alternate_edge_override_map(
            dag,
            fact_view,
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
        )
        dag = apply_selected_alternate_edge_overrides(
            dag,
            fact_view,
            override_map=override_map,
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
        )
        corrected_dag = apply_selected_alternate_edge_overrides(
            corrected_dag,
            fact_view,
            override_map=override_map,
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
        )

        indexes = build_reconstruction_discovery_indexes(
            dag=dag,
            corrected_dag=corrected_dag,
            structured_regions=structured_regions,
        )
        structured_region_edge_pairs = indexes.structured_region_edge_pairs
        structured_region_source_blocks = indexes.structured_region_source_blocks
        dispatcher_region = indexes.dispatcher_region
        shared_suffix_blocks = indexes.shared_suffix_blocks
        corrected_boundary_shared_blocks = indexes.corrected_boundary_shared_blocks
        dag_maps = indexes.dag_maps
        node_by_key = indexes.node_by_key
        dispatcher_serial = indexes.dispatcher_serial
        for region in structured_regions:
            logger.info(
                "RECON DAG: structured region discovered %s entry=0x%08X states=%d internal_edges=%d exits=%d",
                region.region_name,
                int(region.entry_state) & 0xFFFFFFFF,
                len(region.state_values),
                len(region.internal_state_edges),
                len(region.exit_state_values),
            )

        # Phase 1 uses dag (stale augmented — identical to baseline) so
        # that corridor redirect targets are unchanged.  Late phases below
        # switch to corrected_dag.

        raw_candidates: list[ReconstructionCandidate] = []
        rejected_metadata: list[dict[str, int | str | None]] = []
        structured_region_candidate_counts: Counter[str] = Counter()
        structured_region_candidate_pairs: dict[str, list[tuple[int, int]]] = defaultdict(list)
        structured_region_candidates_by_pair: dict[tuple[int, int], list[ReconstructionCandidate]] = defaultdict(list)
        structured_region_edges_by_pair: dict[tuple[int, int], list[object]] = defaultdict(list)
        corrected_region_edges_by_pair: dict[tuple[int, int], list[object]] = defaultdict(list)
        edge_kind_counts = Counter(
            edge_kind_name(e) for e in dag.edges
        )
        logger.info(
            "RECON DAG: edge distribution: %s",
            ", ".join(f"{k}={v}" for k, v in edge_kind_counts.most_common()),
        )
        for edge in dag.edges:
            pair = state_edge_pair(edge)
            if pair is not None:
                structured_region_edges_by_pair[pair].append(edge)
            candidate, rejection = build_reconstruction_candidate(
                edge,
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                state_var_stkoff=state_var_stkoff,
                constant_result=constant_result,
                shared_suffix_blocks=shared_suffix_blocks,
                dispatcher_region=dispatcher_region,
            )
            if candidate is not None:
                raw_candidates.append(candidate)
                if pair is not None:
                    structured_region_candidates_by_pair[pair].append(candidate)
                    for region_name, source_state, target_state in structured_region_edge_pairs:
                        if pair == (source_state, target_state):
                            structured_region_candidate_counts[region_name] += 1
                            structured_region_candidate_pairs[region_name].append(pair)
            elif rejection is not None:
                rejected_metadata.append(rejection)
        for edge in corrected_dag.edges:
            pair = state_edge_pair(edge)
            if pair is not None:
                corrected_region_edges_by_pair[pair].append(edge)

        for force_edge in (
            _SUB7FFD_INITIAL_FORCE_EDGE,
            _SUB7FFD_DOWNSTREAM_FORCE_EDGE,
            _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE,
        ):
            dag_targets = sorted(
                {
                    int(getattr(edge, "target_entry_anchor"))
                    for edge in structured_region_edges_by_pair.get(force_edge, ())
                    if getattr(edge, "target_entry_anchor", None) is not None
                }
            )
            corrected_targets = sorted(
                {
                    int(getattr(edge, "target_entry_anchor"))
                    for edge in corrected_region_edges_by_pair.get(force_edge, ())
                    if getattr(edge, "target_entry_anchor", None) is not None
                }
            )
            if dag_targets or corrected_targets:
                logger.info(
                    "RECON DAG: force-edge targets %s dag=%s corrected=%s",
                    "0x%08X->0x%08X" % force_edge,
                    [blk_label(mba, target) for target in dag_targets],
                    [blk_label(mba, target) for target in corrected_targets],
                )

        for region in structured_regions:
            missing_pairs = [
                (int(source), int(target))
                for source, target in region.internal_state_edges
                if (int(source), int(target))
                not in set(structured_region_candidate_pairs.get(region.region_name, ()))
            ]
            for source_state, target_state in missing_pairs:
                source_blocks = structured_region_source_blocks.get(
                    (source_state, target_state), set()
                )
                matching_rejections = [
                    rejection
                    for rejection in rejected_metadata
                    if int(rejection.get("target_state") or -1) == int(target_state)
                    and (
                        not source_blocks
                        or int(rejection.get("source_block") or -1) in source_blocks
                    )
                ]
                if not matching_rejections:
                    logger.info(
                        "RECON DAG: structured region %s missing candidate for 0x%08X->0x%08X without matching rejection metadata",
                        region.region_name,
                        source_state,
                        target_state,
                    )
                    continue
                reason_counts = Counter(
                    str(rejection.get("rejection_reason") or "unknown")
                    for rejection in matching_rejections
                )
                logger.info(
                    "RECON DAG: structured region %s missing candidate for 0x%08X->0x%08X source_blocks=%s rejection_reasons=%s",
                    region.region_name,
                    source_state,
                    target_state,
                    sorted(source_blocks),
                    ", ".join(
                        f"{reason}={count}"
                        for reason, count in reason_counts.most_common()
                    ),
                )

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        ledger = RoundAcceptLedger()
        accepted_metadata = ledger.accepted_metadata
        structured_region_accepted_counts = ledger.structured_region_accepted_counts
        structured_region_accepted_pairs = ledger.structured_region_accepted_pairs
        shared_group_candidates_by_block = group_candidates_by_shared_block(raw_candidates)
        if 95 in shared_group_candidates_by_block:
            logger.info(
                "RECON DAG: shared-group bucket blk[95] candidates=%s",
                [
                    {
                        "target": int(candidate.target_entry),
                        "via_pred": int(candidate.via_pred) if candidate.via_pred is not None else None,
                        "src": int(candidate.edge.source_anchor.block_serial),
                        "arm": (
                            int(candidate.edge.source_anchor.branch_arm)
                            if candidate.edge.source_anchor.branch_arm is not None
                            else None
                        ),
                        "path": tuple(int(serial) for serial in candidate.edge.ordered_path),
                    }
                    for candidate in shared_group_candidates_by_block[95]
                ],
            )

        if not raw_candidates:
            logger.info(
                "RECON DAG: no proven corridors across %d semantic edges (rejections=%d)",
                len(dag.edges),
                len(rejected_metadata),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
            # Fall through to Bridge Builder and Feeder redirect sections
            # which can wire edges rejected by the strict corridor emitter.

        raw_candidates, collapsed_same_target_conditionals = (
            canonicalize_same_target_conditional_candidates(raw_candidates)
        )
        if collapsed_same_target_conditionals:
            logger.info(
                "RECON DAG: collapsed %d same-target conditional candidate(s) into direct handoffs",
                int(collapsed_same_target_conditionals),
            )
        force_clone_primary_shared_blocks = _parse_force_clone_primary_shared_blocks()
        if force_clone_primary_shared_blocks:
            logger.info(
                "RECON DAG: primary shared-group force-clone blocks=%s",
                sorted(int(block) for block in force_clone_primary_shared_blocks),
            )
        log_reconstruction_candidate_probe(
            phase="pre_primary_execution",
            raw_candidates=tuple(raw_candidates),
        )

        run = execute_primary_reconstruction_modifications(
            raw_candidates=list(raw_candidates),
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            force_clone_shared_blocks=force_clone_primary_shared_blocks,
            mba=mba,
            insn_kind_classifier=classify_live_insn_kind,
            operand_kind_classifier=classify_live_operand_kind,
        )
        primary_probe_accepted_candidates = _collect_accepted_reconstruction_candidates(run)
        primary_probe_rejected_candidates = _collect_rejected_reconstruction_candidates(run)
        log_reconstruction_candidate_probe(
            phase="post_primary_execution",
            raw_candidates=tuple(raw_candidates),
            accepted_candidates=tuple(primary_probe_accepted_candidates),
            rejected_candidates=tuple(primary_probe_rejected_candidates),
        )
        (
            primary_probe_accepted_metadata,
            primary_probe_rejected_metadata,
        ) = _build_execution_probe_metadata(run)
        log_reconstruction_phase_probe(
            phase="post_primary_execution",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=primary_probe_accepted_metadata,
            rejected_metadata=primary_probe_rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(run.shared_group_results),
        )
        for result in run.shared_group_results:
            if int(result.shared_block) == 95:
                logger.info(
                    "RECON DAG: shared-group result blk[95] accepted=%s emission_mode=%s rejected=%s accepted_targets=%s",
                    bool(result.accepted_candidates),
                    result.emission_mode,
                    [
                        int(candidate.target_entry)
                        for candidate in result.rejected_candidates
                    ],
                    [
                        int(candidate.target_entry)
                        for candidate in result.accepted_candidates
                    ],
                )
        for result in run.conditional_results:
            candidate = result.candidate
            ledger.record_accept(
                candidate,
                structured_region_edge_pairs=structured_region_edge_pairs,
                edge_metadata_fn=make_edge_metadata,
                state_edge_pair_fn=state_edge_pair,
            )
            logger.info(
                "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                blk_label(mba, candidate.horizon_block),
                candidate.site.state_value & 0xFFFFFFFF,
                blk_label(mba, candidate.target_entry),
                candidate.edge.source_anchor.branch_arm or 0,
                result.redirect_count,
                result.passthrough_count,
            )

        for result in run.direct_results:
            if result.accepted_candidate is not None:
                candidate = result.accepted_candidate
                ledger.record_accept(
                    candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
                logger.info(
                    "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
                    blk_label(mba, candidate.horizon_block),
                    candidate.site.state_value & 0xFFFFFFFF,
                    blk_label(mba, candidate.target_entry),
                    1,
                )
                continue

            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    rejection_reason=result.rejection_reason,
                )
                for candidate in result.rejected_candidates
            )

        shared_group_results = list(run.shared_group_results)
        unresolved_branch_local_edges = tuple(
            edge
            for region_name, source_state, target_state in structured_region_edge_pairs
            if (source_state, target_state)
            not in structured_region_accepted_pairs.get(region_name, set())
            for edge in structured_region_edges_by_pair.get((source_state, target_state), ())
        )
        narrow_branch_local_candidates = discover_narrow_branch_local_reconstruction_candidates(
            unresolved_edges=unresolved_branch_local_edges,
            flow_graph=flow_graph,
        )
        if narrow_branch_local_candidates:
            narrow_branch_local_candidates, collapsed_branch_local_conditionals = (
                canonicalize_same_target_conditional_candidates(
                    list(narrow_branch_local_candidates)
                )
            )
            if collapsed_branch_local_conditionals:
                logger.info(
                    "RECON DAG: narrow branch-local fallback collapsed %d same-target conditional candidate(s)",
                    int(collapsed_branch_local_conditionals),
                )
            logger.info(
                "RECON DAG: narrow branch-local fallback retrying %d unresolved conditional edge(s)",
                len(narrow_branch_local_candidates),
            )
            fallback_run = execute_primary_reconstruction_modifications(
                raw_candidates=list(narrow_branch_local_candidates),
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                dispatcher_serial=dispatcher_serial,
                modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            mba=mba,
            insn_kind_classifier=classify_live_insn_kind,
            operand_kind_classifier=classify_live_operand_kind,
        )
            fallback_accepted_candidates = _collect_accepted_reconstruction_candidates(
                fallback_run
            )
            for result in fallback_run.conditional_results:
                candidate = result.candidate
                ledger.record_accept(
                    candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
                logger.info(
                    "RECON DAG: narrow branch-local conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                    blk_label(mba, candidate.horizon_block),
                    candidate.site.state_value & 0xFFFFFFFF,
                    blk_label(mba, candidate.target_entry),
                    candidate.edge.source_anchor.branch_arm or 0,
                    result.redirect_count,
                    result.passthrough_count,
                )
            for result in fallback_run.direct_results:
                if result.accepted_candidate is None:
                    continue
                candidate = result.accepted_candidate
                ledger.record_accept(
                    candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
            for result in fallback_run.shared_group_results:
                shared_group_results.append(result)
                for candidate in result.accepted_candidates:
                    ledger.record_accept(
                        candidate,
                        structured_region_edge_pairs=structured_region_edge_pairs,
                        edge_metadata_fn=make_edge_metadata,
                        state_edge_pair_fn=state_edge_pair,
                    )
            if fallback_accepted_candidates:
                logger.info(
                    "RECON DAG: narrow branch-local fallback accepted %d candidate(s)",
                    len(fallback_accepted_candidates),
                )
        for region in structured_regions:
            force_edges = _SUB7FFD_FORCED_REGION_EDGES.get(str(region.region_name), ())
            if not force_edges:
                continue
            for force_edge in force_edges:
                force_edge_plan = discover_force_edge_overrides(
                    region_name=str(region.region_name),
                    force_edge=force_edge,
                    structured_region_accepted_pairs=structured_region_accepted_pairs,
                    structured_region_candidates_by_pair=structured_region_candidates_by_pair,
                    corrected_region_edges_by_pair=corrected_region_edges_by_pair,
                )
                execute_force_edge_override(
                    force_edge_plan,
                    mba=mba,
                    flow_graph=flow_graph,
                    builder=builder,
                    dispatcher_serial=dispatcher_serial,
                    node_by_key=node_by_key,
                    cache_key=cache_key,
                    modifications=modifications,
                    owned_blocks=owned_blocks,
                    owned_edges=owned_edges,
                    shared_group_results=shared_group_results,
                    ledger=ledger,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    structured_region_edges_by_pair=structured_region_edges_by_pair,
                    corrected_region_edges_by_pair=corrected_region_edges_by_pair,
                    shared_group_candidates_by_block=shared_group_candidates_by_block,
                    rejected_metadata=rejected_metadata,
                    cache_read=self._cached_force_edge_direct_overrides_by_round.get,
                    cache_write=self._cached_force_edge_direct_overrides_by_round.__setitem__,
                    blk_label=blk_label,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                    discover_missing_via_pred_fn=discover_missing_via_pred_direct_overrides,
                )

        frontier_override_plans = discover_frontier_overrides(
            dag=dag,
            flow_graph=flow_graph,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            structured_regions=structured_regions,
            structured_region_candidate_pairs=structured_region_candidate_pairs,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
        )
        _frontier_claimed_sources, _frontier_claimed_targets = collect_mod_claims(
            modifications
        )
        _frontier_claimed_sources.update(
            int(block_serial) for block_serial in owned_blocks
        )
        structured_frontier_overrides = emit_frontier_overrides(
            frontier_override_plans,
            builder=builder,
            modifications=modifications,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            claimed_sources=_frontier_claimed_sources,
            claimed_targets=_frontier_claimed_targets,
        )
        log_reconstruction_phase_probe(
            phase="pre_postprocess",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(shared_group_results),
        )

        postprocess = execute_reconstruction_postprocess(
            dag=dag,
            corrected_dag=corrected_dag,
            flow_graph=flow_graph,
            modifications=modifications,
            builder=builder,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            bst_result=bst_result,
            state_machine=sm,
            state_var_stkoff=state_var_stkoff,
            constant_result=constant_result,
            node_by_key=node_by_key,
            rejected_metadata=rejected_metadata,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            collect_entry_island_rescue_seeds=collect_entry_island_rescue_seeds,
            collect_late_entry_island_diagnostics=collect_late_entry_island_diagnostics,
            collect_late_entry_island_rescue_seeds=collect_late_entry_island_rescue_seeds,
            collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
            compute_reachable_blocks=compute_reachable_blocks,
            classify_artifact_return_blocks=classify_artifact_return_blocks,
            collect_common_return_corridor=collect_common_return_corridor,
            collect_terminal_family_report=collect_terminal_family_report,
            build_reconstruction_candidate=build_reconstruction_candidate,
            discover_residual_alias_overrides_fn=discover_residual_alias_overrides,
        )
        log_reconstruction_postprocess_result(
            logger,
            result=postprocess,
            dag=dag,
            mba=mba,
        )
        structured_region_fidelity = {}
        projected_flow_graph = postprocess.projected_flow_graph
        residual_dispatcher_preds = postprocess.residual_dispatcher_preds
        allow_post_apply_bst_cleanup = postprocess.allow_post_apply_bst_cleanup
        post_apply_bst_cleanup_reason = postprocess.post_apply_bst_cleanup_reason
        relaxed_lateclone_shared_blocks = _parse_relaxed_lateclone_shared_blocks()
        force_keep_per_pred_shared_blocks = _parse_force_keep_per_pred_shared_blocks()
        if relaxed_lateclone_shared_blocks:
            logger.info(
                "RECON DAG: relaxing late semantic-clone blocks=%s",
                tuple(sorted(int(block) for block in relaxed_lateclone_shared_blocks)),
            )
        if force_keep_per_pred_shared_blocks:
            logger.info(
                "RECON DAG: force-keeping late per-pred shared groups=%s",
                tuple(sorted(int(block) for block in force_keep_per_pred_shared_blocks)),
            )

        def _shared_block_still_needs_late_clone(block_serial: int) -> bool:
            projected_block = (
                projected_flow_graph.get_block(int(block_serial))
                if projected_flow_graph is not None
                else None
            )
            if projected_block is None:
                return True
            succs = tuple(int(succ) for succ in getattr(projected_block, "succs", ()) or ())
            if len(succs) != 1:
                return True
            return int(succs[0]) in dispatcher_region

        fixpoint_resolved_shared_blocks = frozenset(
            int(entry.source_block)
            for entry in (
                postprocess.postprocess_plan.fixpoint_feeder_plan.log_entries
                if postprocess.postprocess_plan is not None
                else ()
            )
            if not _shared_block_still_needs_late_clone(int(entry.source_block))
        )
        if fixpoint_resolved_shared_blocks:
            logger.info(
                "RECON DAG: force-keeping fixpoint-resolved shared groups=%s",
                tuple(sorted(fixpoint_resolved_shared_blocks)),
            )

        log_reconstruction_phase_probe(
            phase="pre_late_shared_fallback",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(shared_group_results),
        )
        final_shared_group_results = apply_shared_group_reachability_fallback(
            shared_group_results=tuple(shared_group_results),
            shared_groups=shared_group_candidates_by_block,
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            handler_entries=tuple(int(node.entry_anchor) for node in dag.nodes),
            compute_reachable_blocks=compute_reachable_blocks,
            mba=mba,
            insn_kind_classifier=classify_live_insn_kind,
            operand_kind_classifier=classify_live_operand_kind,
            force_clone_shared_blocks=frozenset(
                int(result.shared_block)
                for result in shared_group_results
                if result.emission_mode == "per_pred_redirect"
                and int(result.shared_block) in corrected_boundary_shared_blocks
                and int(result.shared_block) not in relaxed_lateclone_shared_blocks
                and int(result.shared_block) not in force_keep_per_pred_shared_blocks
                and _shared_block_still_needs_late_clone(int(result.shared_block))
            ),
            force_keep_per_pred_shared_blocks=frozenset(
                set(force_keep_per_pred_shared_blocks)
                | set(fixpoint_resolved_shared_blocks)
            ),
        )
        log_reconstruction_phase_probe(
            phase="post_late_shared_fallback",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(final_shared_group_results),
        )

        for result in final_shared_group_results:
            if result.rejected_candidates:
                rejected_metadata.extend(
                    make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=result.shared_block,
                        via_pred=candidate.via_pred,
                        rejection_reason=result.rejection_reason,
                    )
                    for candidate in result.rejected_candidates
                )
                continue
            if not result.accepted_candidates:
                continue
            for candidate in result.accepted_candidates:
                ledger.record_accept(
                    replace(candidate, emission_mode=result.emission_mode),
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
            if result.emission_mode == "per_pred_redirect":
                logger.info(
                    "RECON DAG: per-pred-redirect %s preds=%s (clone avoided)",
                    blk_label(mba, result.shared_block),
                    [
                        (blk_label(mba, pred), blk_label(mba, target))
                        for pred, target in result.per_pred_targets
                    ],
                )
            elif result.emission_mode == "single_pred_redirect":
                logger.info(
                    "RECON DAG: single-pred-redirect %s preds=%s",
                    blk_label(mba, result.shared_block),
                    [
                        (blk_label(mba, pred), blk_label(mba, target))
                        for pred, target in result.per_pred_targets
                    ],
                )
            else:
                logger.info(
                    "RECON DAG: duplicate-and-redirect %s preds=%s",
                    blk_label(mba, result.shared_block),
                    [
                        (blk_label(mba, pred), blk_label(mba, target))
                        for pred, target in result.per_pred_targets
                    ],
                )

        if structured_regions and postprocess.postprocess_plan is not None:
            structured_region_fidelity = build_structured_region_fidelity_report(
                logger=logger,
                mba=mba,
                structured_region_accepted_counts=structured_region_accepted_counts,
                structured_regions=structured_regions,
                structured_region_candidate_pairs=structured_region_candidate_pairs,
                structured_region_accepted_pairs=structured_region_accepted_pairs,
                dispatcher_region=dispatcher_region,
                dispatcher_serial=dispatcher_serial,
                dag=dag,
                postprocess_plan=postprocess.postprocess_plan,
            )
            if structured_frontier_overrides:
                structured_region_fidelity["structured_frontier_overrides"] = tuple(
                    structured_frontier_overrides
                )
            may_only_probe_blocks, may_only_probe_targets = (
                collect_sub7ffd_may_only_probe_blocks(
                    structured_region_fidelity=structured_region_fidelity,
                    structured_frontier_overrides=structured_frontier_overrides,
                    postprocess_plan=postprocess.postprocess_plan,
                )
            )
            if may_only_probe_blocks:
                structured_region_fidelity["post_apply_may_only_probe_blocks"] = (
                    may_only_probe_blocks
                )
                logger.info(
                    "RECON DAG: queued may-only liveness probe blocks=%s",
                    may_only_probe_blocks,
                )
            if may_only_probe_targets:
                structured_region_fidelity["post_apply_may_only_probe_targets"] = (
                    may_only_probe_targets
                )
                logger.info(
                    "RECON DAG: queued may-only liveness probe targets=%s",
                    may_only_probe_targets,
                )

        if not modifications:
            logger.info(
                "RECON DAG: all %d candidate corridors were rejected during emission",
                len(raw_candidates),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
            # Fall through to Bridge Builder and Feeder redirect sections
            # which can wire edges rejected by the strict corridor emitter.
        else:
            logger.info(
                "RECON DAG: accepted %d/%d candidate corridors (rejections=%d)",
                len(accepted_metadata),
                len(raw_candidates),
                len(rejected_metadata),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
        if structured_regions:
            for region in structured_regions:
                logger.info(
                    "RECON DAG: structured region %s raw_candidates=%d accepted=%d candidate_pairs=%s accepted_pairs=%s",
                    region.region_name,
                    structured_region_candidate_counts.get(region.region_name, 0),
                    structured_region_accepted_counts.get(region.region_name, 0),
                    [
                        "0x%08X->0x%08X" % pair
                        for pair in structured_region_candidate_pairs.get(region.region_name, ())
                    ],
                    [
                        "0x%08X->0x%08X" % pair
                        for pair in sorted(structured_region_accepted_pairs.get(region.region_name, ()))
                    ],
                )

        # Final guard: if no modifications after all emission phases, return None.
        if not modifications:
            logger.info(
                "RECON DAG: no modifications produced across strict + bridge + feeder phases",
            )
            return None

        fragment = finalize_reconstruction_fragment(
            strategy_name=self.name,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            allow_post_apply_bst_cleanup=allow_post_apply_bst_cleanup,
            post_apply_bst_cleanup_reason=post_apply_bst_cleanup_reason,
            residual_dispatcher_preds=residual_dispatcher_preds,
            structured_region_fidelity=structured_region_fidelity,
            # Honor prior-fragment linearizations: if SSR (running first)
            # already committed to a target for this src, don't emit a
            # contradictory redirect. Drops ~7 Mode 1 overrides per run on
            # sub_7FFD3338C040 (logged via PLANNER_CTX_CONFLICT).
            cumulative_planner_view=snapshot.cumulative_planner_view,
        )

        # Snapshot AFTER finalize so the diag DB reflects the post-filter
        # state of ``modifications``. Previously this ran before finalize,
        # causing dropped Mode 1 conflicts to still appear in the
        # ``state_write_reconstruction_post_apply`` DB snapshot while being
        # absent from the actual applied fragment — a misleading signal.
        snapshot_reconstruction_post_apply(
            logger,
            dag=dag,
            modifications=fragment.modifications,
            mba=mba,
            strategy_name=self.name,
        )

        return fragment
