"""Per-round accept-ledger for reconstruction metadata + region bookkeeping.

Consolidates the three accounting side-effects of a reconstruction accept:
 1. appending an edge-metadata dict to `accepted_metadata`
 2. bumping `structured_region_accepted_counts`
 3. adding to `structured_region_accepted_pairs`

Emitters/strategy call `ledger.record_accept(candidate, ...)` once per
successful candidate instead of threading three loose collections through
every function in the recording chain.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from d810.core.typing import Any, Callable

# Callable-injected to preserve the existing layer contract (cfg must not
# import d810.recon). Matches the `blk_label` / `edge_metadata_fn` pattern
# already used by `cfg/frontier_override_execution.py` and
# `cfg/reconstruction_missing_via_pred_execution.py`.
EdgeMetadataFn = Callable[..., dict[str, int | str | None]]
StateEdgePairFn = Callable[[Any], tuple[int, int] | None]


@dataclass
class RoundAcceptLedger:
    """Mutable accept-book for one reconstruction-round pass.

    The three fields are the same three collections that the current strategy
    threads through every emitter/helper. The ledger owns them so the strategy
    can pass a single handle instead of three kwargs.
    """
    accepted_metadata: list[dict[str, int | str | None]] = field(default_factory=list)
    structured_region_accepted_counts: Counter[str] = field(default_factory=Counter)
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]] = field(
        default_factory=lambda: defaultdict(set)
    )

    def record_accept(
        self,
        candidate,
        *,
        structured_region_edge_pairs: set[tuple[str, int, int]],
        edge_metadata_fn: EdgeMetadataFn,
        state_edge_pair_fn: StateEdgePairFn,
    ) -> None:
        """Record one accepted candidate. Mirrors the original
        `_record_accept_metadata` + `_record_region_accept` pair verbatim.
        """
        self.accepted_metadata.append(
            edge_metadata_fn(
                candidate.edge,
                horizon_block=candidate.horizon_block,
                site=candidate.site,
                target_entry=candidate.target_entry,
                first_shared_block=candidate.first_shared_block,
                via_pred=candidate.via_pred,
                emission_mode=candidate.emission_mode,
            )
        )
        state_edge_pair = state_edge_pair_fn(candidate.edge)
        if state_edge_pair is None:
            return
        for region_name, source_state, target_state in structured_region_edge_pairs:
            if state_edge_pair == (source_state, target_state):
                self.structured_region_accepted_counts[region_name] += 1
                self.structured_region_accepted_pairs[region_name].add(state_edge_pair)
