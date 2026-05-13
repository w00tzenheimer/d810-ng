"""Diagnostic helpers for reconstruction strategy phase / candidate probes.

Pure observability. ``log_reconstruction_phase_probe`` projects the current
modification list into a post-state flow graph and logs a summary of
accepted / rejected / reachable blocks for a watch-list of block serials.
``log_reconstruction_candidate_probe`` emits compact one-line records of
each watched candidate's provenance.

These are strictly observability; no CFG mutations, no claim updates, no
plan-fragment assembly. Safe to call at any point inside the strategy pass.
"""
from __future__ import annotations

from collections import Counter

from d810.core import logging
from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.plan import compile_patch_plan

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

# Sub_7FFD-focused block watch-list. Probes filter to these serials so the
# emitted logs stay compact. Does not affect pipeline behaviour.
RECON_PHASE_WATCH_BLOCKS: tuple[int, ...] = (
    8, 11, 20, 32, 35, 45, 64, 69, 81, 83, 95, 100, 104, 156, 184, 187, 192, 195, 200, 203,
)


__all__ = (
    "RECON_PHASE_WATCH_BLOCKS",
    "project_phase_probe_flow_graph",
    "log_reconstruction_phase_probe",
    "log_reconstruction_candidate_probe",
)


def project_phase_probe_flow_graph(flow_graph, modifications: list):
    try:
        patch_plan = compile_patch_plan(modifications, flow_graph)
        return project_post_state(flow_graph, patch_plan)
    except Exception:
        logger.debug("RECON PHASE PROBE: projection failed", exc_info=True)
        return flow_graph


def log_reconstruction_phase_probe(
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
    projected_flow_graph = project_phase_probe_flow_graph(flow_graph, modifications)
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
    for serial in RECON_PHASE_WATCH_BLOCKS:
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
    if any(int(serial) in RECON_PHASE_WATCH_BLOCKS for serial in ordered_path):
        return True
    return any(value in RECON_PHASE_WATCH_BLOCKS for value in interesting_values)


def log_reconstruction_candidate_probe(
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
