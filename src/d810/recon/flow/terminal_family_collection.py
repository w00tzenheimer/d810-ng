"""Terminal-family discovery collectors.

Pure discovery helpers for seeding and collecting terminal return families from
the current projected CFG and DAG facts.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.recon.flow.linearized_state_dag import LinearizedStateDag
from d810.recon.flow.terminal_family import (
    TerminalFamilyCandidate,
    TerminalFamilySeedProbe,
    build_terminal_family_candidates,
    candidate_shared_suffix_entries,
    seed_terminal_family_probes,
)


@dataclass(frozen=True, slots=True)
class TerminalFamilyCollection:
    """Collected terminal-family discovery facts for one graph snapshot."""

    seed_probes: tuple[TerminalFamilySeedProbe, ...]
    candidates: tuple[TerminalFamilyCandidate, ...]
    candidate_suffix_entries: dict[tuple[int, int | None, int, tuple[int, ...]], int]


def collect_terminal_family_candidates(
    dag: LinearizedStateDag,
    *,
    base_flow_graph,
    projected_flow_graph,
    dispatcher_region: set[int],
    reachable_blocks: set[int],
    state_var_stkoff: int | None,
) -> TerminalFamilyCollection:
    """Collect terminal-family probes and accepted candidates."""

    seed_probes = seed_terminal_family_probes(
        dag,
        base_flow_graph=base_flow_graph,
        projected_flow_graph=projected_flow_graph,
        dispatcher_region=dispatcher_region,
        reachable_blocks=reachable_blocks,
    )
    candidates = tuple(
        build_terminal_family_candidates(
            seed_probes,
            projected_flow_graph=projected_flow_graph,
            state_var_stkoff=state_var_stkoff,
        )
    )
    return TerminalFamilyCollection(
        seed_probes=tuple(seed_probes),
        candidates=tuple(candidates),
        candidate_suffix_entries=candidate_shared_suffix_entries(tuple(candidates)),
    )


__all__ = [
    "TerminalFamilyCollection",
    "collect_terminal_family_candidates",
]
