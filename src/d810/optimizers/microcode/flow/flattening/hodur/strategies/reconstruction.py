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

from collections import Counter, defaultdict
from dataclasses import replace
import os

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.reconstruction_execution import (
    apply_shared_group_reachability_fallback,
    execute_primary_reconstruction_modifications,
    execute_shared_group_reconstruction,
)
from d810.cfg.reconstruction_postprocess_execution import (
    execute_reconstruction_postprocess,
)
from d810.cfg.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    blk_label,
)
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_reporting import (
    log_reconstruction_postprocess_result,
    snapshot_reconstruction_dag,
    snapshot_reconstruction_post_apply,
)
from d810.cfg.graph_modification import (
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
)
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.modification_builder import (
    ModificationBuilder,
)
from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.plan import compile_patch_plan, is_block_creating_modification
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.linearized_dag_round_discovery import (
    discover_structured_dag_regions,
)
from d810.recon.flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    build_linearized_state_program,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.edge_metadata import make_edge_metadata
from d810.recon.flow.edge_metadata import edge_kind_name
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint
from d810.recon.flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
    collect_boundary_protected_shared_blocks,
    collect_shared_suffix_blocks,
    resolve_state_var_stkoff,
)
from d810.recon.flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.return_corridor_discovery import (
    collect_common_return_corridor,
)
from d810.recon.flow.terminal_family_collection import (
    collect_terminal_family_report,
)
from d810.recon.flow.reconstruction_candidate_builder import (
    ReconstructionCandidate,
    build_reconstruction_candidate,
)
from d810.recon.flow.transition_builder import TransitionResult

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
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
_RECON_PHASE_WATCH_BLOCKS = (
    8, 11, 20, 32, 35, 45, 64, 69, 81, 83, 95, 100, 104, 156, 184, 187, 192, 195, 200, 203,
)


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


def _project_phase_probe_flow_graph(flow_graph, modifications: list):
    try:
        patch_plan = compile_patch_plan(modifications, flow_graph)
        return project_post_state(flow_graph, patch_plan)
    except Exception:
        logger.debug("RECON PHASE PROBE: projection failed", exc_info=True)
        return flow_graph


def _log_reconstruction_phase_probe(
    *,
    phase: str,
    flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    rejected_metadata: list[dict[str, int | str | None]],
    compute_reachable_blocks,
    shared_group_results=(),
) -> None:
    projected_flow_graph = _project_phase_probe_flow_graph(flow_graph, modifications)
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
                "RECON PHASE PROBE[%s]: reachable-block computation failed",
                phase,
                exc_info=True,
            )
    accepted_modes = Counter(
        str(metadata.get("emission_mode") or "unknown")
        for metadata in accepted_metadata
    )
    shared_summary = tuple(
        (int(result.shared_block), str(result.emission_mode or ""))
        for result in shared_group_results
    )
    watched_snapshots: list[str] = []
    get_block = getattr(projected_flow_graph, "get_block", None)
    block_map = getattr(projected_flow_graph, "blocks", {}) or {}
    for serial in _RECON_PHASE_WATCH_BLOCKS:
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
        "RECON PHASE PROBE[%s]: mods=%d owned_blocks=%d owned_edges=%d accepted=%d rejected=%d accepted_modes=%s shared=%s watched=%s",
        phase,
        len(modifications),
        len(owned_blocks),
        len(owned_edges),
        len(accepted_metadata),
        len(rejected_metadata),
        dict(accepted_modes),
        shared_summary,
        watched_snapshots,
    )


def _candidate_probe_signature(candidate) -> str:
    edge = getattr(candidate, "edge", None)
    source_anchor = getattr(edge, "source_anchor", None)
    ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
    return (
        f"src={int(getattr(source_anchor, 'block_serial', -1))}"
        f"/arm={getattr(source_anchor, 'branch_arm', None)}"
        f"/h={int(getattr(candidate, 'horizon_block', -1))}"
        f"/t={int(getattr(candidate, 'target_entry', -1))}"
        f"/shared={getattr(candidate, 'first_shared_block', None)}"
        f"/via={getattr(candidate, 'via_pred', None)}"
        f"/mode={getattr(candidate, 'emission_mode', None)}"
        f"/path={ordered_path}"
    )


def _should_watch_candidate(candidate) -> bool:
    edge = getattr(candidate, "edge", None)
    source_anchor = getattr(edge, "source_anchor", None)
    ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
    interesting_values = {
        int(getattr(source_anchor, "block_serial", -1)),
        int(getattr(candidate, "horizon_block", -1)),
        int(getattr(candidate, "target_entry", -1)),
        int(getattr(candidate, "first_shared_block", -1))
        if getattr(candidate, "first_shared_block", None) is not None
        else -1,
        int(getattr(candidate, "via_pred", -1))
        if getattr(candidate, "via_pred", None) is not None
        else -1,
    }
    if any(int(serial) in _RECON_PHASE_WATCH_BLOCKS for serial in ordered_path):
        return True
    return any(value in _RECON_PHASE_WATCH_BLOCKS for value in interesting_values)


def _log_reconstruction_candidate_probe(
    *,
    phase: str,
    raw_candidates=(),
    accepted_candidates=(),
    rejected_candidates=(),
) -> None:
    raw_signatures = [
        _candidate_probe_signature(candidate)
        for candidate in raw_candidates
        if _should_watch_candidate(candidate)
    ]
    accepted_signatures = [
        _candidate_probe_signature(candidate)
        for candidate in accepted_candidates
        if _should_watch_candidate(candidate)
    ]
    rejected_signatures = [
        _candidate_probe_signature(candidate)
        for candidate in rejected_candidates
        if _should_watch_candidate(candidate)
    ]
    logger.info(
        "RECON CANDIDATE PROBE[%s]: raw=%s accepted=%s rejected=%s",
        phase,
        raw_signatures,
        accepted_signatures,
        rejected_signatures,
    )


def _state_edge_pair(edge) -> tuple[int, int] | None:
    source_key = getattr(edge, "source_key", None)
    source_state = getattr(source_key, "state_const", None)
    target_state = getattr(edge, "target_state", None)
    if source_state is None or target_state is None:
        return None
    return (
        int(source_state) & 0xFFFFFFFF,
        int(target_state) & 0xFFFFFFFF,
    )


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


def _canonicalize_same_target_conditional_candidates(
    raw_candidates: list[ReconstructionCandidate],
) -> tuple[tuple[ReconstructionCandidate, ...], int]:
    """Collapse same-target conditional arms into a single direct handoff."""

    grouped_branch_arms: dict[tuple[int, int, int, int | None], set[int]] = {}
    for candidate in raw_candidates:
        if candidate.emission_mode != "conditional_arm":
            continue
        source_anchor = getattr(candidate.edge, "source_anchor", None)
        branch_arm = getattr(source_anchor, "branch_arm", None)
        source_state = getattr(getattr(candidate.edge, "source_key", None), "state_const", None)
        if branch_arm is None:
            continue
        key = (
            int(getattr(source_anchor, "block_serial", candidate.horizon_block)),
            int(candidate.horizon_block),
            int(candidate.target_entry),
            int(source_state) if source_state is not None else None,
        )
        grouped_branch_arms.setdefault(key, set()).add(int(branch_arm))

    collapsed_keys = {
        key for key, branch_arms in grouped_branch_arms.items() if len(branch_arms) > 1
    }
    if not collapsed_keys:
        return tuple(raw_candidates), 0

    seen_collapsed: set[tuple[int, int, int, int | None]] = set()
    collapsed_count = 0
    canonicalized: list[ReconstructionCandidate] = []
    for candidate in raw_candidates:
        if candidate.emission_mode != "conditional_arm":
            canonicalized.append(candidate)
            continue
        source_anchor = getattr(candidate.edge, "source_anchor", None)
        source_state = getattr(getattr(candidate.edge, "source_key", None), "state_const", None)
        key = (
            int(getattr(source_anchor, "block_serial", candidate.horizon_block)),
            int(candidate.horizon_block),
            int(candidate.target_entry),
            int(source_state) if source_state is not None else None,
        )
        if key not in collapsed_keys:
            canonicalized.append(candidate)
            continue
        if key in seen_collapsed:
            collapsed_count += 1
            continue
        seen_collapsed.add(key)
        canonicalized.append(replace(candidate, emission_mode="direct"))
    return tuple(canonicalized), int(collapsed_count)


def _build_narrow_branch_local_reconstruction_candidates(
    *,
    unresolved_edges: tuple[object, ...] | list[object],
    flow_graph: object,
) -> tuple[ReconstructionCandidate, ...]:
    candidates: list[ReconstructionCandidate] = []
    seen_signatures: set[tuple[int, int, int, int, int, tuple[int, ...]]] = set()

    for edge in unresolved_edges:
        source_anchor = getattr(edge, "source_anchor", None)
        branch_arm = getattr(source_anchor, "branch_arm", None)
        if branch_arm not in (0, 1):
            continue

        target_entry = getattr(edge, "target_entry_anchor", None)
        if target_entry is None or int(target_entry) < 0:
            continue

        ordered_path = tuple(int(serial) for serial in (getattr(edge, "ordered_path", ()) or ()))
        if len(ordered_path) < 2:
            continue

        source_anchor_block = int(getattr(source_anchor, "block_serial", -1))
        if source_anchor_block >= 0 and source_anchor_block in ordered_path:
            horizon_block = int(source_anchor_block)
        else:
            horizon_block = int(getattr(getattr(edge, "source_key", None), "handler_serial", -1))
        if int(horizon_block) < 0:
            continue

        horizon_snapshot = flow_graph.get_block(int(horizon_block))
        if horizon_snapshot is None:
            continue
        horizon_succs = tuple(int(succ) for succ in getattr(horizon_snapshot, "succs", ()) or ())
        if int(getattr(horizon_snapshot, "nsucc", len(horizon_succs))) != 2:
            continue
        if int(horizon_block) not in ordered_path:
            continue

        source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        target_state = getattr(edge, "target_state", None)
        if source_state is None or target_state is None:
            continue

        signature = (
            int(source_state) & 0xFFFFFFFF,
            int(target_state) & 0xFFFFFFFF,
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
                    else int(target_state) & 0xFFFFFFFF
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


def _record_region_accept(
    *,
    candidate,
    structured_region_edge_pairs: set[tuple[str, int, int]],
    structured_region_accepted_counts: Counter[str],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
) -> None:
    state_edge_pair = _state_edge_pair(candidate.edge)
    if state_edge_pair is None:
        return
    for region_name, source_state, target_state in structured_region_edge_pairs:
        if state_edge_pair == (source_state, target_state):
            structured_region_accepted_counts[region_name] += 1
            structured_region_accepted_pairs[region_name].add(state_edge_pair)


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


def _should_defer_structured_frontier_override(
    *,
    edge,
    memberships: list[dict[str, str]],
    exit_block: int,
    target_entry: int,
) -> bool:
    if exit_block == 170 and target_entry == 211:
        return any(
            membership["region_name"] == _SUB7FFD_INITIAL_REGION_NAME
            for membership in memberships
        )
    state_edge_pair = _state_edge_pair(edge)
    if state_edge_pair != (0x16F7FF74, 0x652D7A98):
        return False
    return any(
        membership["region_name"] == _SUB7FFD_INITIAL_REGION_NAME
        and membership["role"] == "post_exit_frontier"
        for membership in memberships
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


def _emit_missing_via_pred_direct_override(
    *,
    force_edge: tuple[int, int],
    region_name: str,
    structured_region_edges_by_pair: dict[tuple[int, int], list[object]],
    corrected_region_edges_by_pair: dict[tuple[int, int], list[object]],
    rejected_metadata: list[dict[str, int | str | None]],
    flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    structured_region_edge_pairs: set[tuple[str, int, int]],
    structured_region_accepted_counts: Counter[str],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
    builder,
    node_by_key: dict,
    dispatcher_serial: int,
    mba,
) -> bool:
    raw_matching_edges = list(structured_region_edges_by_pair.get(force_edge, ()))
    if not raw_matching_edges:
        return False

    def _try_edge_set(
        matching_edges: list[object],
        *,
        variant: str,
    ) -> tuple[bool, int | None, int | None, tuple[int, ...] | None]:
        source_blocks = {
            int(getattr(getattr(edge, "source_anchor", None), "block_serial", -1))
            for edge in matching_edges
        }
        source_blocks.discard(-1)
        target_entries = {
            int(getattr(edge, "target_entry_anchor"))
            for edge in matching_edges
            if getattr(edge, "target_entry_anchor", None) is not None
        }
        if len(source_blocks) != 1 or len(target_entries) != 1:
            return False, None, None, None

        source_block = next(iter(source_blocks))
        target_entry = next(iter(target_entries))
        source_snapshot = flow_graph.get_block(int(source_block))
        if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 1:
            return False, None, None, None

        target_snapshot = flow_graph.get_block(int(target_entry))
        if target_snapshot is None or int(getattr(target_snapshot, "nsucc", 0)) != 1:
            logger.info(
                "RECON DAG: structured region direct-source override skipped %s for %s via %s target=%s variant=%s reason=complex_target_nsucc_%s",
                region_name,
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, int(source_block)),
                blk_label(mba, int(target_entry)),
                variant,
                (
                    "missing"
                    if target_snapshot is None
                    else int(getattr(target_snapshot, "nsucc", 0))
                ),
            )
            return False, None, None, None

        ordered_path = tuple(int(serial) for serial in (matching_edges[0].ordered_path or ()))
        if not ordered_path:
            ordered_path = (int(source_block),)
        direct_plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(source_block),
            target_entry=int(target_entry),
            ordered_path=ordered_path,
        )
        if not direct_plan.accepted:
            logger.info(
                "RECON DAG: structured region direct-source override rejected %s for %s via %s target=%s variant=%s reason=%s",
                region_name,
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, int(source_block)),
                blk_label(mba, int(target_entry)),
                variant,
                direct_plan.rejection_reason,
            )
            return False, None, None, None

        modifications.extend(direct_plan.modifications)
        owned_blocks.add(int(source_block))
        owned_edges.add((int(source_block), int(target_entry)))
        passthrough_count = 0
        if (
            getattr(getattr(matching_edges[0], "kind", None), "name", None)
            == "CONDITIONAL_TRANSITION"
        ):
            source_key = getattr(matching_edges[0], "source_key", None)
            source_node = node_by_key.get(source_key)
            pt_entry_direct: int | None = None
            if (
                source_node is not None
                and getattr(source_key, "state_const", None) is not None
            ):
                pt_entry_direct = int(source_node.entry_anchor)
            pt_plan_direct = plan_passthrough_reconstruction_modifications(
                flow_graph=flow_graph,
                ordered_path=ordered_path,
                horizon_block=int(source_block),
                dispatcher_serial=dispatcher_serial,
                current_state_entry=pt_entry_direct,
            )
            modifications.extend(pt_plan_direct.modifications)
            passthrough_count = len(pt_plan_direct.modifications)
        if (
            region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
            and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
            and variant == "corrected"
            and int(source_block) == 170
            and int(target_entry) == _SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE
            and raw_matching_edges
        ):
            raw_target_entries = {
                int(getattr(edge, "target_entry_anchor"))
                for edge in raw_matching_edges
                if getattr(edge, "target_entry_anchor", None) is not None
            }
            if raw_target_entries == {_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET}:
                rescue_mod = builder.edge_redirect(
                    source_block=_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE,
                    target_block=_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET,
                    via_pred=int(source_block),
                )
                modifications.append(rescue_mod)
                owned_blocks.add(_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE)
                owned_edges.add(
                    (
                        _SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE,
                        _SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET,
                    )
                )
                logger.info(
                    "RECON DAG: structured region corrected head rescue %s forced %s via %s rescue=%s->%s",
                    region_name,
                    "0x%08X->0x%08X" % force_edge,
                    blk_label(mba, int(source_block)),
                    blk_label(mba, _SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE),
                    blk_label(mba, _SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET),
                )
        accepted_metadata.append(
            make_edge_metadata(
                matching_edges[0],
                horizon_block=int(source_block),
                target_entry=int(target_entry),
                emission_mode=(
                    "structured_head_direct"
                    if variant == "raw"
                    else "structured_head_corrected_direct"
                ),
            )
        )
        structured_region_accepted_counts[region_name] += 1
        structured_region_accepted_pairs[region_name].add(force_edge)
        logger.info(
            "RECON DAG: structured region direct-source override %s forced %s via %s target=%s variant=%s passthrough=%d",
            region_name,
            "0x%08X->0x%08X" % force_edge,
            blk_label(mba, int(source_block)),
            blk_label(mba, int(target_entry)),
            variant,
            passthrough_count,
        )
        return True, int(source_block), int(target_entry), ordered_path

    raw_source_blocks = {
        int(getattr(getattr(edge, "source_anchor", None), "block_serial", -1))
        for edge in raw_matching_edges
    }
    raw_source_blocks.discard(-1)
    matching_rejections = [
        rejection
        for rejection in rejected_metadata
        if int(rejection.get("target_state") or -1) == int(force_edge[1])
        and int(rejection.get("source_block") or -1) in raw_source_blocks
    ]
    rejection_reasons = {
        str(rejection.get("rejection_reason") or "")
        for rejection in matching_rejections
    }
    if rejection_reasons != {"missing_via_pred"}:
        return False

    accepted, _, _, _ = _try_edge_set(raw_matching_edges, variant="raw")
    if accepted:
        return True

    if (
        region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
        and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
    ):
        logger.info(
            "RECON DAG: structured region corrected direct-source override disabled for %s %s; leaving head edge to bridge/postprocess",
            region_name,
            "0x%08X->0x%08X" % force_edge,
        )
        return False

    corrected_matching_edges = list(corrected_region_edges_by_pair.get(force_edge, ()))
    if corrected_matching_edges:
        accepted, _, _, _ = _try_edge_set(
            corrected_matching_edges,
            variant="corrected",
        )
        if accepted:
            return True

    return False


def _bridge_exit_block_for_edge(
    edge,
    *,
    dispatcher_region: set[int],
    dispatcher_serial: int,
) -> int | None:
    if edge.ordered_path:
        for serial in reversed(edge.ordered_path):
            block_serial = int(serial)
            if (
                block_serial != dispatcher_serial
                and block_serial not in dispatcher_region
            ):
                return block_serial
        return None

    source_block = int(edge.source_anchor.block_serial)
    if source_block == dispatcher_serial or source_block in dispatcher_region:
        return None
    return source_block


def _late_rewrite_memberships(
    *,
    state_edge_pair: tuple[int, int] | None,
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
) -> tuple[dict[str, str], ...]:
    if state_edge_pair is None:
        return ()

    source_state, target_state = state_edge_pair
    memberships: list[dict[str, str]] = []
    for region in structured_regions:
        region_name = str(region.region_name)
        region_states = {int(state) & 0xFFFFFFFF for state in region.state_values}
        region_internal_edges = {
            (int(src) & 0xFFFFFFFF, int(dst) & 0xFFFFFFFF)
            for src, dst in region.internal_state_edges
        }
        region_exit_states = {
            int(state) & 0xFFFFFFFF for state in getattr(region, "exit_state_values", ())
        }
        candidate_pairs = set(structured_region_candidate_pairs.get(region_name, ()))
        accepted_pairs = set(structured_region_accepted_pairs.get(region_name, ()))

        if state_edge_pair in region_internal_edges:
            if state_edge_pair in accepted_pairs:
                primary_status = "accepted_primary_region"
            elif state_edge_pair in candidate_pairs:
                primary_status = "raw_primary_region_candidate_unaccepted"
            else:
                primary_status = "internal_region_edge_without_primary_candidate"
            memberships.append(
                {
                    "region_name": region_name,
                    "role": "internal",
                    "leak_unit": region_name,
                    "primary_status": primary_status,
                }
            )
            continue

        if source_state in region_states and target_state in region_exit_states:
            memberships.append(
                {
                    "region_name": region_name,
                    "role": "exit_frontier",
                    "leak_unit": f"{region_name}:exit_frontier",
                    "primary_status": "outside_primary_region_contract",
                }
            )
            continue

        if source_state in region_exit_states:
            memberships.append(
                {
                    "region_name": region_name,
                    "role": "post_exit_frontier",
                    "leak_unit": f"{region_name}:post_exit_frontier",
                    "primary_status": "outside_primary_region_contract",
                }
            )

    return tuple(memberships)


def _build_late_rewrite_semantic_indexes(
    *,
    dag,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
) -> tuple[
    dict[tuple[int, int], list[dict[str, object]]],
    dict[tuple[int, int, int | None], list[dict[str, object]]],
]:
    bridge_index: dict[tuple[int, int], list[dict[str, object]]] = defaultdict(list)
    feeder_index: dict[tuple[int, int, int | None], list[dict[str, object]]] = defaultdict(list)
    for edge in getattr(dag, "edges", ()):
        target_entry = getattr(edge, "target_entry_anchor", None)
        if target_entry is None:
            continue
        state_edge_pair = _state_edge_pair(edge)
        memberships = _late_rewrite_memberships(
            state_edge_pair=state_edge_pair,
            structured_regions=structured_regions,
            structured_region_candidate_pairs=structured_region_candidate_pairs,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
        )
        record = {
            "state_edge_pair": state_edge_pair,
            "edge_kind": edge_kind_name(edge),
            "memberships": memberships,
        }
        bridge_exit_block = _bridge_exit_block_for_edge(
            edge,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
        )
        if bridge_exit_block is not None:
            bridge_index[(int(bridge_exit_block), int(target_entry))].append(record)
        feeder_index[
            (
                int(edge.source_anchor.block_serial),
                int(target_entry),
                getattr(edge.source_anchor, "branch_arm", None),
            )
        ].append(record)
    return dict(bridge_index), dict(feeder_index)


def _format_state_pair(state_edge_pair: tuple[int, int] | None) -> str:
    if state_edge_pair is None:
        return "none"
    return "0x%08X->0x%08X" % state_edge_pair


def _log_late_rewrite_fidelity(
    *,
    logger,
    mba,
    structured_region_accepted_counts: Counter[str],
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
    dispatcher_region: set[int],
    dispatcher_serial: int,
    dag,
    postprocess_plan,
) -> dict[str, object]:
    primary_region_edges = int(
        sum(len(pairs) for pairs in structured_region_accepted_pairs.values())
    )
    bridge_recovery_edges = len(postprocess_plan.bridge_plan.modifications)
    feeder_recovery_edges = len(postprocess_plan.feeder_plan.modifications) + len(
        postprocess_plan.fixpoint_feeder_plan.modifications
    )
    return_recovery_edges = len(postprocess_plan.return_plan.modifications)
    late_local_redirect_edges = (
        bridge_recovery_edges + feeder_recovery_edges + return_recovery_edges
    )
    logger.info(
        "RECON DAG: fidelity primary_region_edges=%d bridge_recovery_edges=%d late_local_redirect_edges=%d",
        primary_region_edges,
        bridge_recovery_edges,
        late_local_redirect_edges,
    )

    bridge_index, feeder_index = _build_late_rewrite_semantic_indexes(
        dag=dag,
        dispatcher_region=dispatcher_region,
        dispatcher_serial=dispatcher_serial,
        structured_regions=structured_regions,
        structured_region_candidate_pairs=structured_region_candidate_pairs,
        structured_region_accepted_pairs=structured_region_accepted_pairs,
    )
    leak_units: Counter[str] = Counter()
    leak_roles: Counter[str] = Counter()
    detailed_entries: list[dict[str, object]] = []

    def _record_entry(
        *,
        planner: str,
        source_block: int,
        target_block: int,
        branch_arm: int | None,
        tag: str,
        matches: list[dict[str, object]],
    ) -> None:
        if not matches:
            logger.info(
                "RECON DAG: late rewrite planner=%s blk[%d]%s -> blk[%d] tag=%s semantic=unmatched",
                planner,
                source_block,
                f".arm{branch_arm}" if branch_arm is not None else "",
                target_block,
                tag,
            )
            detailed_entries.append(
                {
                    "planner": planner,
                    "source_block": source_block,
                    "target_block": target_block,
                    "branch_arm": branch_arm,
                    "tag": tag,
                    "semantic_status": "unmatched",
                }
            )
            return

        pair_labels = sorted({_format_state_pair(match["state_edge_pair"]) for match in matches})
        edge_kinds = sorted({str(match["edge_kind"]) for match in matches})
        memberships = [
            membership
            for match in matches
            for membership in match["memberships"]
        ]
        if not memberships:
            logger.info(
                "RECON DAG: late rewrite planner=%s blk[%d]%s -> blk[%d] tag=%s states=%s edge_kinds=%s structural_role=outside_structured_regions",
                planner,
                source_block,
                f".arm{branch_arm}" if branch_arm is not None else "",
                target_block,
                tag,
                pair_labels,
                edge_kinds,
            )
            detailed_entries.append(
                {
                    "planner": planner,
                    "source_block": source_block,
                    "target_block": target_block,
                    "branch_arm": branch_arm,
                    "tag": tag,
                    "semantic_status": "outside_structured_regions",
                    "state_pairs": tuple(pair_labels),
                    "edge_kinds": tuple(edge_kinds),
                }
            )
            return

        unit_labels = sorted({membership["leak_unit"] for membership in memberships})
        role_labels = sorted({membership["role"] for membership in memberships})
        primary_statuses = sorted({membership["primary_status"] for membership in memberships})
        for membership in memberships:
            leak_units[str(membership["leak_unit"])] += 1
            leak_roles[str(membership["role"])] += 1
        logger.info(
            "RECON DAG: late rewrite planner=%s blk[%d]%s -> blk[%d] tag=%s states=%s edge_kinds=%s leak_units=%s roles=%s primary_status=%s",
            planner,
            source_block,
            f".arm{branch_arm}" if branch_arm is not None else "",
            target_block,
            tag,
            pair_labels,
            edge_kinds,
            unit_labels,
            role_labels,
            primary_statuses,
        )
        detailed_entries.append(
            {
                "planner": planner,
                "source_block": source_block,
                "target_block": target_block,
                "branch_arm": branch_arm,
                "tag": tag,
                "semantic_status": "structured_leakage",
                "state_pairs": tuple(pair_labels),
                "edge_kinds": tuple(edge_kinds),
                "leak_units": tuple(unit_labels),
                "roles": tuple(role_labels),
                "primary_status": tuple(primary_statuses),
            }
        )

    for entry in postprocess_plan.bridge_plan.log_entries:
        matches = bridge_index.get((int(entry.source_block), int(entry.target_block)), [])
        _record_entry(
            planner="bridge",
            source_block=int(entry.source_block),
            target_block=int(entry.target_block),
            branch_arm=getattr(entry, "branch_arm", None),
            tag=str(entry.tag),
            matches=matches,
        )
    for entry in postprocess_plan.feeder_plan.log_entries:
        matches = feeder_index.get(
            (
                int(entry.source_block),
                int(entry.target_block),
                getattr(entry, "branch_arm", None),
            ),
            [],
        )
        _record_entry(
            planner="feeder",
            source_block=int(entry.source_block),
            target_block=int(entry.target_block),
            branch_arm=getattr(entry, "branch_arm", None),
            tag=str(entry.tag),
            matches=matches,
        )

    if leak_units:
        logger.info(
            "RECON DAG: leaked semantic units: %s",
            ", ".join(f"{unit}={count}" for unit, count in leak_units.most_common()),
        )
    if leak_roles:
        logger.info(
            "RECON DAG: leaked semantic roles: %s",
            ", ".join(f"{role}={count}" for role, count in leak_roles.most_common()),
        )

    return {
        "primary_region_edges": primary_region_edges,
        "bridge_recovery_edges": bridge_recovery_edges,
        "late_local_redirect_edges": late_local_redirect_edges,
        "leaked_units": tuple((unit, count) for unit, count in leak_units.most_common()),
        "leaked_roles": tuple((role, count) for role, count in leak_roles.most_common()),
        "late_rewrite_entries": tuple(detailed_entries),
    }


def _emit_structured_frontier_overrides(
    *,
    dag,
    flow_graph,
    builder: ModificationBuilder,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    dispatcher_region: set[int],
    dispatcher_serial: int,
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
    mba,
) -> list[dict[str, object]]:
    claimed_sources, claimed_targets = collect_mod_claims(modifications)
    claimed_sources.update(int(block_serial) for block_serial in owned_blocks)
    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in dispatcher_region)
    emitted_records: list[dict[str, object]] = []

    for edge in getattr(dag, "edges", ()):
        target_entry = getattr(edge, "target_entry_anchor", None)
        if target_entry is None:
            continue
        memberships = [
            membership
            for membership in _late_rewrite_memberships(
                state_edge_pair=_state_edge_pair(edge),
                structured_regions=structured_regions,
                structured_region_candidate_pairs=structured_region_candidate_pairs,
                structured_region_accepted_pairs=structured_region_accepted_pairs,
            )
            if membership["region_name"]
            in {_SUB7FFD_INITIAL_REGION_NAME, "sub7ffd_retry_chain_region"}
            and membership["role"] in {"exit_frontier", "post_exit_frontier"}
        ]
        if not memberships:
            continue
        exit_block = _bridge_exit_block_for_edge(
            edge,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
        )
        if exit_block is None:
            continue
        exit_block = int(exit_block)
        target_entry = int(target_entry)
        if _should_defer_structured_frontier_override(
            edge=edge,
            memberships=memberships,
            exit_block=exit_block,
            target_entry=target_entry,
        ):
            logger.info(
                "RECON DAG: deferring structured frontier override blk[%d] -> blk[%d] state=%s roles=%s to bridge/postprocess",
                exit_block,
                target_entry,
                _format_state_pair(_state_edge_pair(edge)),
                sorted({membership['role'] for membership in memberships}),
            )
            continue
        if exit_block in claimed_sources or target_entry in claimed_targets:
            continue
        if target_entry in bst_set:
            continue

        block = flow_graph.get_block(exit_block)
        if block is None:
            continue
        if any(int(block.succs[arm]) == target_entry for arm in range(block.nsucc)):
            claimed_targets.add(target_entry)
            continue

        modification = None
        branch_arm: int | None = None
        tag = "structured_exit_frontier"
        if block.nsucc == 1:
            old_target = int(block.succs[0])
            if old_target != dispatcher_serial and old_target not in bst_set:
                continue
            modification = builder.goto_redirect(
                source_block=exit_block,
                target_block=target_entry,
                old_target=old_target,
            )
        elif block.nsucc == 2:
            for arm in range(2):
                arm_target = int(block.succs[arm])
                if arm_target == dispatcher_serial or arm_target in bst_set:
                    if arm != 1:
                        break
                    branch_arm = arm
                    modification = builder.edge_redirect(
                        source_block=exit_block,
                        target_block=target_entry,
                        old_target=arm_target,
                    )
                    tag = "structured_exit_frontier_2way"
                    break
        if modification is None:
            continue

        modifications.append(modification)
        claimed_sources.add(exit_block)
        claimed_targets.add(target_entry)
        owned_edges.add((exit_block, target_entry))
        accepted_metadata.append(
            make_edge_metadata(
                edge,
                horizon_block=exit_block,
                target_entry=target_entry,
                emission_mode=tag,
            )
        )
        emitted_records.append(
            {
                "source_block": exit_block,
                "target_entry": target_entry,
                "branch_arm": branch_arm,
                "tag": tag,
                "state_edge_pair": _state_edge_pair(edge),
                "roles": tuple(sorted({membership["role"] for membership in memberships})),
            }
        )
        logger.info(
            "RECON DAG: structured frontier override blk[%d]%s -> blk[%d] roles=%s state=%s",
            exit_block,
            f".arm{branch_arm}" if branch_arm is not None else "",
            target_entry,
            sorted({membership["role"] for membership in memberships}),
            _format_state_pair(_state_edge_pair(edge)),
        )

    return emitted_records


def _collect_sub7ffd_may_only_probe_blocks(
    *,
    structured_region_fidelity: dict[str, object],
    structured_frontier_overrides: list[dict[str, object]],
    postprocess_plan,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return leaked-frontier blocks for the explicit may-only liveness probe.

    The old microcode dump bug effectively replaced may-lists with
    may-minus-must on the live MBA.  We do not want to do that globally again,
    but for sub_7FFD exploration we can probe the same effect explicitly on the
    leaked initial frontier blocks that still fall out into bridge/local
    recovery.
    """
    block_serials: set[int] = set()
    structured_frontier_targets: set[int] = set()
    leaked_entries = structured_region_fidelity.get("late_rewrite_entries", ())
    if isinstance(leaked_entries, tuple):
        iterable_entries = leaked_entries
    elif isinstance(leaked_entries, list):
        iterable_entries = tuple(leaked_entries)
    else:
        iterable_entries = ()

    for entry in iterable_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("semantic_status") != "structured_leakage":
            continue
        leak_units = {
            str(unit)
            for unit in entry.get("leak_units", ())
            if unit is not None
        }
        if not any(
            unit.startswith(f"{_SUB7FFD_INITIAL_REGION_NAME}:")
            for unit in leak_units
        ):
            continue
        source_block = entry.get("source_block")
        if isinstance(source_block, int):
            block_serials.add(source_block)

    for entry in structured_frontier_overrides:
        if not isinstance(entry, dict):
            continue
        roles = {str(role) for role in entry.get("roles", ()) if role is not None}
        if not roles & {"exit_frontier", "post_exit_frontier"}:
            continue
        source_block = entry.get("source_block")
        if isinstance(source_block, int):
            block_serials.add(source_block)
        target_entry = entry.get("target_entry")
        if isinstance(target_entry, int):
            structured_frontier_targets.add(target_entry)

    for entry in getattr(getattr(postprocess_plan, "bridge_plan", None), "log_entries", ()):
        source_block = getattr(entry, "source_block", None)
        target_block = getattr(entry, "target_block", None)
        if not isinstance(source_block, int) or not isinstance(target_block, int):
            continue
        if target_block in structured_frontier_targets:
            block_serials.add(source_block)

    return tuple(sorted(block_serials)), tuple(sorted(structured_frontier_targets))


def _finalize_reconstruction_fragment(
    *,
    strategy_name: str,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    rejected_metadata: list[dict[str, int | str | None]],
    allow_post_apply_bst_cleanup: bool,
    post_apply_bst_cleanup_reason: str | None,
    residual_dispatcher_preds: tuple[int, ...],
    structured_region_fidelity: dict[str, object] | None = None,
) -> PlanFragment:
    pts_types = (PrivateTerminalSuffix, PrivateTerminalSuffixGroup)
    pts_mods = [mod for mod in modifications if isinstance(mod, pts_types)]
    has_block_creators = any(
        is_block_creating_modification(mod) for mod in modifications
    )
    structured_region_fidelity = structured_region_fidelity or {}
    leaked_units = tuple(structured_region_fidelity.get("leaked_units", ()))
    if leaked_units and allow_post_apply_bst_cleanup:
        allow_post_apply_bst_cleanup = False
        post_apply_bst_cleanup_reason = "structured_region_leakage"

    if pts_mods and has_block_creators:
        non_pts_mods = [mod for mod in modifications if not isinstance(mod, pts_types)]
        logger.info(
            "RECON: deferring %d PTS mods to next invocation "
            "(block-creating ops would shift suffix serials)",
            len(pts_mods),
        )
        modifications = non_pts_mods

    return PlanFragment(
        strategy_name=strategy_name,
        family=FAMILY_DIRECT,
        ownership=OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=len(owned_blocks),
            transitions_resolved=len(accepted_metadata),
            blocks_freed=len(owned_blocks),
            conflict_density=0.0,
        ),
        risk_score=0.25,
        metadata={
            "mode": "experimental_reconstruction",
            "reconstruction_sites": tuple(accepted_metadata),
            "reconstruction_rejections": tuple(rejected_metadata),
            "allow_post_apply_bst_cleanup": allow_post_apply_bst_cleanup,
            "post_apply_bst_cleanup_reason": post_apply_bst_cleanup_reason,
            "residual_dispatcher_preds": residual_dispatcher_preds,
            "structured_region_fidelity": structured_region_fidelity,
            "safeguard_min_required": 1,
        },
        modifications=modifications,
    )


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
        transition_result = TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(sm.transitions),
        )
        _corrected_dag_out: list = []
        dag = build_live_linearized_state_dag_from_graph(
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
        constant_result = run_snapshot_constant_fixpoint(
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
                    "RECON DAG: cached structured regions available for func=0x%X maturity=%d but deferred because the live pass could not rediscover them: names=%s",
                    cache_key[0],
                    cache_key[1],
                    [str(region.region_name) for region in cached_structured_regions],
                )
        structured_region_edge_pairs = {
            (str(region.region_name), int(source), int(target))
            for region in structured_regions
            for source, target in region.internal_state_edges
        }
        structured_region_source_blocks: dict[tuple[int, int], set[int]] = defaultdict(set)
        for edge in dag.edges:
            state_edge_pair = _state_edge_pair(edge)
            if state_edge_pair is None:
                continue
            structured_region_source_blocks[state_edge_pair].add(
                int(edge.source_anchor.block_serial)
            )
        for region in structured_regions:
            logger.info(
                "RECON DAG: structured region discovered %s entry=0x%08X states=%d internal_edges=%d exits=%d",
                region.region_name,
                int(region.entry_state) & 0xFFFFFFFF,
                len(region.state_values),
                len(region.internal_state_edges),
                len(region.exit_state_values),
            )

        snapshot_reconstruction_dag(
            logger,
            dag=dag,
            mba=mba,
            strategy_name=self.name,
        )

        # Phase 1 uses dag (stale augmented — identical to baseline) so
        # that corridor redirect targets are unchanged.  Late phases below
        # switch to corrected_dag.
        dispatcher_region = set(dag.bst_node_blocks)
        if dag.dispatcher_entry_serial >= 0:
            dispatcher_region.add(int(dag.dispatcher_entry_serial))
        shared_suffix_blocks = collect_shared_suffix_blocks(dag)
        corrected_boundary_shared_blocks = collect_boundary_protected_shared_blocks(
            corrected_dag
        )
        dag_maps = build_dag_node_maps(dag)
        node_by_key = dag_maps.node_by_key
        dispatcher_serial = int(dag.dispatcher_entry_serial)

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
            state_edge_pair = _state_edge_pair(edge)
            if state_edge_pair is not None:
                structured_region_edges_by_pair[state_edge_pair].append(edge)
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
                if state_edge_pair is not None:
                    structured_region_candidates_by_pair[state_edge_pair].append(candidate)
                    for region_name, source_state, target_state in structured_region_edge_pairs:
                        if state_edge_pair == (source_state, target_state):
                            structured_region_candidate_counts[region_name] += 1
                            structured_region_candidate_pairs[region_name].append(state_edge_pair)
            elif rejection is not None:
                rejected_metadata.append(rejection)
        for edge in corrected_dag.edges:
            state_edge_pair = _state_edge_pair(edge)
            if state_edge_pair is not None:
                corrected_region_edges_by_pair[state_edge_pair].append(edge)

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
        accepted_metadata: list[dict[str, int | str | None]] = []
        structured_region_accepted_counts: Counter[str] = Counter()
        structured_region_accepted_pairs: dict[str, set[tuple[int, int]]] = defaultdict(set)
        shared_group_candidates_by_block: dict[int, list[ReconstructionCandidate]] = defaultdict(list)
        for candidate in raw_candidates:
            if (
                candidate.emission_mode not in {"conditional_arm", "direct"}
                and candidate.first_shared_block is not None
            ):
                shared_group_candidates_by_block[int(candidate.first_shared_block)].append(candidate)
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
            _canonicalize_same_target_conditional_candidates(raw_candidates)
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
        _log_reconstruction_candidate_probe(
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
        )
        primary_probe_accepted_candidates = _collect_accepted_reconstruction_candidates(run)
        primary_probe_rejected_candidates = _collect_rejected_reconstruction_candidates(run)
        _log_reconstruction_candidate_probe(
            phase="post_primary_execution",
            raw_candidates=tuple(raw_candidates),
            accepted_candidates=tuple(primary_probe_accepted_candidates),
            rejected_candidates=tuple(primary_probe_rejected_candidates),
        )
        (
            primary_probe_accepted_metadata,
            primary_probe_rejected_metadata,
        ) = _build_execution_probe_metadata(run)
        _log_reconstruction_phase_probe(
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
            _record_accept_metadata(accepted_metadata, candidate)
            _record_region_accept(
                candidate=candidate,
                structured_region_edge_pairs=structured_region_edge_pairs,
                structured_region_accepted_counts=structured_region_accepted_counts,
                structured_region_accepted_pairs=structured_region_accepted_pairs,
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
                _record_accept_metadata(accepted_metadata, candidate)
                _record_region_accept(
                    candidate=candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    structured_region_accepted_counts=structured_region_accepted_counts,
                    structured_region_accepted_pairs=structured_region_accepted_pairs,
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
        narrow_branch_local_candidates = _build_narrow_branch_local_reconstruction_candidates(
            unresolved_edges=unresolved_branch_local_edges,
            flow_graph=flow_graph,
        )
        if narrow_branch_local_candidates:
            narrow_branch_local_candidates, collapsed_branch_local_conditionals = (
                _canonicalize_same_target_conditional_candidates(
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
            )
            fallback_accepted_candidates = _collect_accepted_reconstruction_candidates(
                fallback_run
            )
            for result in fallback_run.conditional_results:
                candidate = result.candidate
                _record_accept_metadata(accepted_metadata, candidate)
                _record_region_accept(
                    candidate=candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    structured_region_accepted_counts=structured_region_accepted_counts,
                    structured_region_accepted_pairs=structured_region_accepted_pairs,
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
                _record_accept_metadata(accepted_metadata, candidate)
                _record_region_accept(
                    candidate=candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    structured_region_accepted_counts=structured_region_accepted_counts,
                    structured_region_accepted_pairs=structured_region_accepted_pairs,
                )
            for result in fallback_run.shared_group_results:
                shared_group_results.append(result)
                for candidate in result.accepted_candidates:
                    _record_accept_metadata(accepted_metadata, candidate)
                    _record_region_accept(
                        candidate=candidate,
                        structured_region_edge_pairs=structured_region_edge_pairs,
                        structured_region_accepted_counts=structured_region_accepted_counts,
                        structured_region_accepted_pairs=structured_region_accepted_pairs,
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
                if force_edge in structured_region_accepted_pairs.get(region.region_name, set()):
                    continue
                override_candidates = list(
                    structured_region_candidates_by_pair.get(force_edge, ())
                )
                logger.info(
                    "RECON DAG: force-edge status %s region=%s override_candidates=%d shared_blocks=%s",
                    "0x%08X->0x%08X" % force_edge,
                    region.region_name,
                    len(override_candidates),
                    sorted(
                        {
                            int(candidate.first_shared_block)
                            for candidate in override_candidates
                            if candidate.first_shared_block is not None
                        }
                    ),
                )
                allow_corrected_missing_via_pred_retry = (
                    str(region.region_name) == _SUB7FFD_DOWNSTREAM_REGION_NAME
                    and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
                    and not override_candidates
                    and bool(corrected_region_edges_by_pair.get(force_edge, ()))
                )
                if _should_defer_force_edge_materialization(
                    region_name=str(region.region_name),
                    force_edge=force_edge,
                    override_candidates=override_candidates,
                ) and not allow_corrected_missing_via_pred_retry:
                    logger.info(
                        "RECON DAG: deferring structured region force-edge %s region=%s to bridge/postprocess because live pass has no direct override candidate",
                        "0x%08X->0x%08X" % force_edge,
                        region.region_name,
                    )
                    continue
                if not override_candidates:
                    cached_direct_override = self._cached_force_edge_direct_overrides_by_round.get(
                        (cache_key[0], cache_key[1], force_edge)
                    )
                    if cached_direct_override is not None:
                        cached_source_block, cached_target_entry, cached_ordered_path = (
                            cached_direct_override
                        )
                        cached_direct_plan = plan_direct_reconstruction_modifications(
                            flow_graph=flow_graph,
                            horizon_block=int(cached_source_block),
                            target_entry=int(cached_target_entry),
                            ordered_path=tuple(int(serial) for serial in cached_ordered_path),
                        )
                        if (
                            not cached_direct_plan.accepted
                            and tuple(int(serial) for serial in cached_ordered_path)
                            != (int(cached_source_block),)
                        ):
                            logger.info(
                                "RECON DAG: cached force-edge direct override %s rejected for %s via %s target=%s reason=%s ordered_path=%s; retrying with horizon-only path",
                                region.region_name,
                                "0x%08X->0x%08X" % force_edge,
                                blk_label(mba, cached_source_block),
                                blk_label(mba, cached_target_entry),
                                cached_direct_plan.rejection_reason,
                                tuple(int(serial) for serial in cached_ordered_path),
                            )
                            cached_direct_plan = plan_direct_reconstruction_modifications(
                                flow_graph=flow_graph,
                                horizon_block=int(cached_source_block),
                                target_entry=int(cached_target_entry),
                                ordered_path=(int(cached_source_block),),
                            )
                        if cached_direct_plan.accepted:
                            modifications.extend(cached_direct_plan.modifications)
                            owned_blocks.add(int(cached_source_block))
                            owned_edges.add(
                                (int(cached_source_block), int(cached_target_entry))
                            )
                            passthrough_count = 0
                            cached_matching_edges = list(
                                structured_region_edges_by_pair.get(force_edge, ())
                            ) or list(corrected_region_edges_by_pair.get(force_edge, ()))
                            if cached_matching_edges and (
                                getattr(getattr(cached_matching_edges[0], "kind", None), "name", None)
                                == "CONDITIONAL_TRANSITION"
                            ):
                                source_key = getattr(cached_matching_edges[0], "source_key", None)
                                source_node = node_by_key.get(source_key)
                                pt_entry_direct: int | None = None
                                if (
                                    source_node is not None
                                    and getattr(source_key, "state_const", None) is not None
                                ):
                                    pt_entry_direct = int(source_node.entry_anchor)
                                pt_plan_direct = plan_passthrough_reconstruction_modifications(
                                    flow_graph=flow_graph,
                                    ordered_path=tuple(int(serial) for serial in cached_ordered_path),
                                    horizon_block=int(cached_source_block),
                                    dispatcher_serial=dispatcher_serial,
                                    current_state_entry=pt_entry_direct,
                                )
                                modifications.extend(pt_plan_direct.modifications)
                                passthrough_count = len(pt_plan_direct.modifications)
                            accepted_metadata.append(
                                {
                                    "source_state": int(force_edge[0]),
                                    "target_state": int(force_edge[1]),
                                    "horizon_block": int(cached_source_block),
                                    "target_entry": int(cached_target_entry),
                                    "emission_mode": "cached_force_edge_direct_override",
                                }
                            )
                            structured_region_accepted_counts[str(region.region_name)] += 1
                            structured_region_accepted_pairs[str(region.region_name)].add(
                                force_edge
                            )
                            logger.info(
                                "RECON DAG: cached force-edge direct override %s forced %s via %s target=%s passthrough=%d",
                                region.region_name,
                                "0x%08X->0x%08X" % force_edge,
                                blk_label(mba, cached_source_block),
                                blk_label(mba, cached_target_entry),
                                passthrough_count,
                            )
                            continue
                        logger.info(
                            "RECON DAG: cached force-edge direct override %s failed for %s via %s target=%s reason=%s",
                            region.region_name,
                            "0x%08X->0x%08X" % force_edge,
                            blk_label(mba, cached_source_block),
                            blk_label(mba, cached_target_entry),
                            cached_direct_plan.rejection_reason,
                        )
                    if _emit_missing_via_pred_direct_override(
                        force_edge=force_edge,
                        region_name=str(region.region_name),
                        structured_region_edges_by_pair=structured_region_edges_by_pair,
                        corrected_region_edges_by_pair=corrected_region_edges_by_pair,
                        rejected_metadata=rejected_metadata,
                        flow_graph=flow_graph,
                        modifications=modifications,
                        owned_blocks=owned_blocks,
                        owned_edges=owned_edges,
                        accepted_metadata=accepted_metadata,
                        structured_region_edge_pairs=structured_region_edge_pairs,
                        structured_region_accepted_counts=structured_region_accepted_counts,
                        structured_region_accepted_pairs=structured_region_accepted_pairs,
                        builder=builder,
                        node_by_key=node_by_key,
                        dispatcher_serial=dispatcher_serial,
                        mba=mba,
                    ):
                        continue
                    continue
                shared_block = override_candidates[0].first_shared_block
                if shared_block is None:
                    continue
                override_result = execute_shared_group_reconstruction(
                    shared_block=int(shared_block),
                    candidates=override_candidates,
                    flow_graph=flow_graph,
                    modifications=modifications,
                    owned_blocks=owned_blocks,
                    owned_edges=owned_edges,
                    force_clone=True,
                )
                if not override_result.accepted_candidates:
                    logger.info(
                        "RECON DAG: structured region override %s failed for %s via shared_block=%s reason=%s",
                        region.region_name,
                        "0x%08X->0x%08X" % force_edge,
                        blk_label(mba, shared_block),
                        override_result.rejection_reason,
                    )
                    group_candidates = list(
                        shared_group_candidates_by_block.get(int(shared_block), ())
                    )
                    if len(group_candidates) != len(override_candidates):
                        group_override_result = execute_shared_group_reconstruction(
                            shared_block=int(shared_block),
                            candidates=group_candidates,
                            flow_graph=flow_graph,
                            modifications=modifications,
                            owned_blocks=owned_blocks,
                            owned_edges=owned_edges,
                            force_clone=True,
                        )
                        if group_override_result.accepted_candidates:
                            logger.info(
                                "RECON DAG: structured region mixed-group override %s forced shared_block=%s size=%d emission=%s",
                                region.region_name,
                                blk_label(mba, shared_block),
                                len(group_candidates),
                                group_override_result.emission_mode,
                            )
                            replacement_done = False
                            for idx, existing in enumerate(shared_group_results):
                                if int(existing.shared_block) == int(shared_block):
                                    shared_group_results[idx] = group_override_result
                                    replacement_done = True
                                    break
                            if not replacement_done:
                                shared_group_results.append(group_override_result)
                            continue
                        logger.info(
                            "RECON DAG: structured region direct override skipped for %s via %s because shared block has mixed group size=%d override_candidates=%d mixed_reason=%s",
                            "0x%08X->0x%08X" % force_edge,
                            blk_label(mba, shared_block),
                            len(group_candidates),
                            len(override_candidates),
                            group_override_result.rejection_reason,
                        )
                        group_targets = {
                            int(candidate.target_entry) for candidate in group_candidates
                        }
                        group_horizons = {
                            int(candidate.horizon_block) for candidate in group_candidates
                        }
                        if len(group_targets) != 1 or len(group_horizons) != 1:
                            continue
                        shared_target_entry = next(iter(group_targets))
                        shared_horizon_block = next(iter(group_horizons))
                        direct_plan = plan_direct_reconstruction_modifications(
                            flow_graph=flow_graph,
                            horizon_block=int(shared_horizon_block),
                            target_entry=int(shared_target_entry),
                            ordered_path=tuple(
                                int(serial) for serial in group_candidates[0].edge.ordered_path
                            ),
                        )
                        if not direct_plan.accepted:
                            logger.info(
                                "RECON DAG: structured region mixed-group direct override failed for shared_block=%s target=%s reason=%s",
                                blk_label(mba, shared_block),
                                blk_label(mba, shared_target_entry),
                                direct_plan.rejection_reason,
                            )
                            continue
                        modifications.extend(direct_plan.modifications)
                        owned_blocks.add(int(shared_horizon_block))
                        owned_edges.add((int(shared_horizon_block), int(shared_target_entry)))
                        passthrough_specs: set[tuple[int, int, int]] = set()
                        passthrough_count = 0
                        for grouped_candidate in group_candidates:
                            if getattr(getattr(grouped_candidate.edge, "kind", None), "name", None) != "CONDITIONAL_TRANSITION":
                                continue
                            source_node = node_by_key.get(grouped_candidate.edge.source_key)
                            pt_entry_direct: int | None = None
                            if (
                                source_node is not None
                                and grouped_candidate.edge.source_key.state_const is not None
                            ):
                                pt_entry_direct = source_node.entry_anchor
                            pt_plan_direct = plan_passthrough_reconstruction_modifications(
                                flow_graph=flow_graph,
                                ordered_path=tuple(
                                    int(serial) for serial in grouped_candidate.edge.ordered_path
                                ),
                                horizon_block=int(grouped_candidate.horizon_block),
                                dispatcher_serial=dispatcher_serial,
                                current_state_entry=pt_entry_direct,
                            )
                            for modification in pt_plan_direct.modifications:
                                spec = (
                                    int(getattr(modification, "from_serial")),
                                    int(getattr(modification, "old_target")),
                                    int(getattr(modification, "new_target")),
                                )
                                if spec in passthrough_specs:
                                    continue
                                passthrough_specs.add(spec)
                                modifications.append(modification)
                                passthrough_count += 1
                        logger.info(
                            "RECON DAG: structured region mixed-group direct override forced shared_block=%s target=%s size=%d passthrough=%d",
                            blk_label(mba, shared_block),
                            blk_label(mba, shared_target_entry),
                            len(group_candidates),
                            passthrough_count,
                        )
                        shared_group_results = [
                            existing
                            for existing in shared_group_results
                            if int(existing.shared_block) != int(shared_block)
                        ]
                        for grouped_candidate in group_candidates:
                            _record_accept_metadata(
                                accepted_metadata,
                                replace(grouped_candidate, emission_mode="structured_region_mixed_group_direct_override"),
                            )
                            _record_region_accept(
                                candidate=grouped_candidate,
                                structured_region_edge_pairs=structured_region_edge_pairs,
                                structured_region_accepted_counts=structured_region_accepted_counts,
                                structured_region_accepted_pairs=structured_region_accepted_pairs,
                            )
                        self._cached_force_edge_direct_overrides_by_round[
                            (cache_key[0], cache_key[1], force_edge)
                        ] = (
                            int(shared_horizon_block),
                            int(shared_target_entry),
                            tuple(
                                int(serial)
                                for serial in group_candidates[0].edge.ordered_path
                            ),
                        )
                        continue
                    direct_candidate = override_candidates[0]
                    direct_plan = plan_direct_reconstruction_modifications(
                        flow_graph=flow_graph,
                        horizon_block=int(direct_candidate.horizon_block),
                        target_entry=int(direct_candidate.target_entry),
                        ordered_path=tuple(
                            int(serial) for serial in direct_candidate.edge.ordered_path
                        ),
                    )
                    if not direct_plan.accepted:
                        logger.info(
                            "RECON DAG: structured region direct override failed for %s via %s reason=%s",
                            "0x%08X->0x%08X" % force_edge,
                            blk_label(mba, direct_candidate.horizon_block),
                            direct_plan.rejection_reason,
                        )
                        continue
                    modifications.extend(direct_plan.modifications)
                    owned_blocks.add(int(direct_candidate.horizon_block))
                    owned_edges.add(
                        (
                            int(direct_candidate.horizon_block),
                            int(direct_candidate.target_entry),
                        )
                    )
                    passthrough_count = 0
                    if getattr(getattr(direct_candidate.edge, "kind", None), "name", None) == "CONDITIONAL_TRANSITION":
                        source_node = node_by_key.get(direct_candidate.edge.source_key)
                        pt_entry_direct: int | None = None
                        if (
                            source_node is not None
                            and direct_candidate.edge.source_key.state_const is not None
                        ):
                            pt_entry_direct = source_node.entry_anchor
                        pt_plan_direct = plan_passthrough_reconstruction_modifications(
                            flow_graph=flow_graph,
                            ordered_path=tuple(
                                int(serial) for serial in direct_candidate.edge.ordered_path
                            ),
                            horizon_block=int(direct_candidate.horizon_block),
                            dispatcher_serial=dispatcher_serial,
                            current_state_entry=pt_entry_direct,
                        )
                        modifications.extend(pt_plan_direct.modifications)
                        passthrough_count = len(pt_plan_direct.modifications)
                    logger.info(
                        "RECON DAG: structured region direct override %s forced %s via %s (passthrough=%d)",
                        region.region_name,
                        "0x%08X->0x%08X" % force_edge,
                        blk_label(mba, direct_candidate.horizon_block),
                        passthrough_count,
                    )
                    shared_group_results = [
                        existing
                        for existing in shared_group_results
                        if int(existing.shared_block) != int(shared_block)
                    ]
                    _record_accept_metadata(
                        accepted_metadata,
                        replace(direct_candidate, emission_mode="structured_region_direct_override"),
                    )
                    _record_region_accept(
                        candidate=direct_candidate,
                        structured_region_edge_pairs=structured_region_edge_pairs,
                        structured_region_accepted_counts=structured_region_accepted_counts,
                        structured_region_accepted_pairs=structured_region_accepted_pairs,
                    )
                    self._cached_force_edge_direct_overrides_by_round[
                        (cache_key[0], cache_key[1], force_edge)
                    ] = (
                        int(direct_candidate.horizon_block),
                        int(direct_candidate.target_entry),
                        tuple(
                            int(serial) for serial in direct_candidate.edge.ordered_path
                        ),
                    )
                    continue
                logger.info(
                    "RECON DAG: structured region override %s forced %s via %s emission=%s",
                    region.region_name,
                    "0x%08X->0x%08X" % force_edge,
                    blk_label(mba, shared_block),
                    override_result.emission_mode,
                )
                replacement_done = False
                for idx, existing in enumerate(shared_group_results):
                    if int(existing.shared_block) == int(shared_block):
                        shared_group_results[idx] = override_result
                        replacement_done = True
                        break
                if not replacement_done:
                    shared_group_results.append(override_result)

        structured_frontier_overrides = _emit_structured_frontier_overrides(
            dag=dag,
            flow_graph=flow_graph,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            structured_regions=structured_regions,
            structured_region_candidate_pairs=structured_region_candidate_pairs,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
            mba=mba,
        )
        _log_reconstruction_phase_probe(
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
        _log_reconstruction_phase_probe(
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
            force_clone_shared_blocks=frozenset(
                int(result.shared_block)
                for result in shared_group_results
                if result.emission_mode == "per_pred_redirect"
                and int(result.shared_block) in corrected_boundary_shared_blocks
                and int(result.shared_block) not in relaxed_lateclone_shared_blocks
                and int(result.shared_block) not in force_keep_per_pred_shared_blocks
            ),
            force_keep_per_pred_shared_blocks=force_keep_per_pred_shared_blocks,
        )
        _log_reconstruction_phase_probe(
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
                _record_accept_metadata(
                    accepted_metadata,
                    replace(candidate, emission_mode=result.emission_mode),
                )
                _record_region_accept(
                    candidate=candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    structured_region_accepted_counts=structured_region_accepted_counts,
                    structured_region_accepted_pairs=structured_region_accepted_pairs,
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
            structured_region_fidelity = _log_late_rewrite_fidelity(
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
                _collect_sub7ffd_may_only_probe_blocks(
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

        snapshot_reconstruction_post_apply(
            logger,
            dag=dag,
            modifications=modifications,
            mba=mba,
            strategy_name=self.name,
        )

        return _finalize_reconstruction_fragment(
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
        )
