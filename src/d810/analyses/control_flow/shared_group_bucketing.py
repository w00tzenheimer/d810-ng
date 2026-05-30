"""Shared-group bucketing for reconstruction candidates.

Groups reconstruction candidates by their ``first_shared_block`` so the
downstream shared-group reconstruction executor can process each shared-block
bucket independently. Candidates that are already committed as direct or
conditional-arm handoffs are excluded, since those are owned by the primary
single-edge emitter, not the shared-group path.

Pure transform: no flow-graph access, no IDA calls.
"""
from __future__ import annotations

from collections import defaultdict
from d810.core.typing import Iterable

from d810.analyses.control_flow.reconstruction_candidate_builder import ReconstructionCandidate


SharedGroupBucketMap = dict[int, list[ReconstructionCandidate]]


# Candidates committed as direct / conditional-arm handoffs are owned by the
# primary single-edge emitter and never enter the shared-group bucket.
_EXCLUDED_EMISSION_MODES = frozenset({"conditional_arm", "direct"})


def group_candidates_by_shared_block(
    raw_candidates: Iterable[ReconstructionCandidate],
) -> SharedGroupBucketMap:
    """Bucket reconstruction candidates by ``first_shared_block``.

    Returns a mapping ``{first_shared_block: [candidate, ...]}`` containing
    only candidates whose ``emission_mode`` is NOT ``conditional_arm``/``direct``
    and whose ``first_shared_block`` is set.
    """
    buckets: SharedGroupBucketMap = defaultdict(list)
    for candidate in raw_candidates:
        if candidate.emission_mode in _EXCLUDED_EMISSION_MODES:
            continue
        shared_block = candidate.first_shared_block
        if shared_block is None:
            continue
        buckets[int(shared_block)].append(candidate)
    return buckets


__all__ = ("SharedGroupBucketMap", "group_candidates_by_shared_block")
