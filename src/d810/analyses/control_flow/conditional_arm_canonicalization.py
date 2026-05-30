"""Conditional-arm canonicalization for reconstruction candidates.

When two conditional arms of the same branch resolve to the same target state,
the per-arm `conditional_arm` emission is semantically a single direct handoff.
This module collapses those duplicate arms into one `direct` candidate so the
downstream emitter does not schedule redundant per-arm rewrites.

Pure transform: accepts an iterable of `ReconstructionCandidate`, returns a
canonicalized tuple and a count of collapsed duplicates. No flow-graph access,
no IDA calls.
"""
from __future__ import annotations

from dataclasses import replace

from d810.analyses.control_flow.reconstruction_candidate_builder import ReconstructionCandidate


def canonicalize_same_target_conditional_candidates(
    raw_candidates: list[ReconstructionCandidate] | tuple[ReconstructionCandidate, ...],
) -> tuple[tuple[ReconstructionCandidate, ...], int]:
    """Collapse same-target conditional arms into a single direct handoff.

    Returns ``(canonicalized_candidates, collapsed_count)``. When both arms of
    a branch point at the same ``(source_anchor, horizon, target_entry,
    source_state)`` key, the first arm is promoted to ``emission_mode="direct"``
    and subsequent duplicate arms are dropped from the result.
    """
    candidates_seq = list(raw_candidates)
    grouped_branch_arms: dict[tuple[int, int, int, int | None], set[int]] = {}
    for candidate in candidates_seq:
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
        return tuple(candidates_seq), 0

    seen_collapsed: set[tuple[int, int, int, int | None]] = set()
    collapsed_count = 0
    canonicalized: list[ReconstructionCandidate] = []
    for candidate in candidates_seq:
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


__all__ = ("canonicalize_same_target_conditional_candidates",)
