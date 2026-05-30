"""Narrow branch-local reconstruction-candidate discovery.

For edges whose source anchor is a 2-way horizon block and whose source-anchor
branch_arm is either 0 or 1, this producer synthesizes a per-arm
``ReconstructionCandidate`` so the downstream emitter can rewrite the specific
arm instead of the whole horizon. Used as a narrow fallback when broader
single-edge reconstruction rejects the edge but the per-arm shape is still safe.

Pure discovery: flow-graph only used for `get_block(...)` structural queries.
No IDA runtime calls.
"""
from __future__ import annotations

from d810.core.typing import Iterable

from d810.analyses.control_flow.reconstruction_candidate_builder import ReconstructionCandidate


def discover_narrow_branch_local_reconstruction_candidates(
    *,
    unresolved_edges: Iterable[object],
    flow_graph: object,
) -> tuple[ReconstructionCandidate, ...]:
    """Synthesize per-arm reconstruction candidates for unresolved 2-way horizons."""
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


__all__ = ("discover_narrow_branch_local_reconstruction_candidates",)
