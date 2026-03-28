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


@dataclass(frozen=True, slots=True)
class TerminalSourceUnreachableDiagnostic:
    """Discovery facts for an unreachable terminal-family source corridor."""

    source_block: int
    pred_info: tuple[str, ...]
    nearest_reachable: int | None
    island_blocks: tuple[int, ...]


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


def collect_terminal_source_unreachable_diagnostic(
    projected_flow_graph,
    *,
    source_serial: int,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
) -> TerminalSourceUnreachableDiagnostic | None:
    source_snap = projected_flow_graph.get_block(source_serial)
    if source_snap is None:
        return None

    preds = sorted(int(p) for p in source_snap.preds)
    pred_info = []
    for pred in preds:
        if pred in reachable_blocks:
            status = "reachable"
        elif pred in dispatcher_region:
            status = "dispatcher"
        else:
            status = "unreachable"
        pred_info.append(f"blk[{pred}]={status}")

    visited: set[int] = set()
    queue: list[int] = [source_serial]
    frontier: int | None = None
    while queue and len(visited) < 64:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if current != source_serial and current in reachable_blocks:
            frontier = current
            break
        snap = projected_flow_graph.get_block(current)
        if snap is None:
            continue
        for pred in sorted(int(p) for p in snap.preds):
            if pred not in visited and pred not in dispatcher_region:
                queue.append(pred)

    return TerminalSourceUnreachableDiagnostic(
        source_block=int(source_serial),
        pred_info=tuple(pred_info),
        nearest_reachable=(int(frontier) if frontier is not None else None),
        island_blocks=tuple(sorted(visited - {source_serial})),
    )


__all__ = [
    "TerminalFamilyCollection",
    "TerminalSourceUnreachableDiagnostic",
    "collect_terminal_family_candidates",
    "collect_terminal_source_unreachable_diagnostic",
]
