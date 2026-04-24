"""Diagnostic probe for SCC-based full-coverage DAG linearization.

Given a :class:`LinearizedStateDag`, build a source→target adjacency, run
``DispatchRegionDetector.tarjan_scc``, and log what a full-coverage chain
traversal WOULD look like. This is read-only — no mods are emitted, no
behavior changes. It validates the approach of Option A from
``.claude/notes/investigations/2026-04-23-sub_7ffd_lowering.md`` before
committing to an emission rewrite:

- How many SCCs does the DAG have?
- How many single-state vs cyclic SCCs?
- Does the traversal cover every state (expected: yes, all 112 on sub_7FFD)?
- Does the chain match the reference ``_linearized.c`` state ordering?

Env-gated: ``D810_DIAG_FULL_COVERAGE_CHAIN=1``. No overhead when off.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from d810.core import logging
from d810.recon.flow.dispatch_region import DispatchRegionDetector


logger = logging.getLogger(
    "D810.recon.flow.full_coverage_chain_probe",
    logging.DEBUG,
)


__all__ = (
    "probe_enabled",
    "build_state_adjacency",
    "compute_full_coverage_chain",
    "log_chain_coverage",
    "FullCoverageChainSegment",
    "FullCoverageChainResult",
)


def probe_enabled() -> bool:
    return os.getenv("D810_DIAG_FULL_COVERAGE_CHAIN", "").strip() == "1"


@dataclass(frozen=True, slots=True)
class FullCoverageChainSegment:
    """One segment in the full-coverage chain: either a single state or an SCC cycle."""

    states: tuple[int, ...]  # state-constant values; len==1 for DAG leaves, >1 for SCC cycles
    is_cycle: bool
    has_back_edge: bool


@dataclass(frozen=True, slots=True)
class FullCoverageChainResult:
    segments: tuple[FullCoverageChainSegment, ...]
    total_states: int
    covered_states: int
    uncovered_states: tuple[int, ...]
    single_state_sccs: int
    cycle_sccs: int


def build_state_adjacency(dag) -> dict[int, tuple[int, ...]]:
    """Extract source-state → target-state adjacency from a LinearizedStateDag.

    Only includes edges whose source and target both have a resolvable
    state constant. Edges lacking state constants (e.g. UNKNOWN kind) are
    skipped — they're not part of the dispatcher state graph.
    """
    adj: dict[int, list[int]] = {}
    states_seen: set[int] = set()
    for edge in getattr(dag, "edges", ()) or ():
        src_key = getattr(edge, "source_key", None)
        src_state = getattr(src_key, "state_const", None) if src_key is not None else None
        tgt_state = getattr(edge, "target_state", None)
        if src_state is None or tgt_state is None:
            continue
        src = int(src_state) & 0xFFFFFFFF
        tgt = int(tgt_state) & 0xFFFFFFFF
        adj.setdefault(src, []).append(tgt)
        states_seen.add(src)
        states_seen.add(tgt)
    # Ensure every seen state is a key (even if it has no outgoing edges),
    # so Tarjan SCC processes it.
    for state in states_seen:
        adj.setdefault(state, [])
    return {k: tuple(v) for k, v in adj.items()}


def compute_full_coverage_chain(dag) -> FullCoverageChainResult:
    """Run Tarjan SCC on the state-transition adjacency and produce chain segments.

    SCC output from Tarjan is in reverse topological order — reverse it to
    emit parents before children. Within a cyclic SCC, the presence of a
    back-edge is detected (a cycle by definition has at least one back-edge).
    """
    adj = build_state_adjacency(dag)
    sccs = DispatchRegionDetector.tarjan_scc(adj)

    # sccs is in reverse topological order; iterate in reverse for forward
    # traversal (parents → children).
    chain: list[FullCoverageChainSegment] = []
    single_count = 0
    cycle_count = 0
    covered: set[int] = set()
    for scc in reversed(sccs):
        states = tuple(sorted(scc))
        is_cycle = len(states) > 1 or (
            len(states) == 1 and states[0] in adj.get(states[0], ())
        )
        if is_cycle:
            cycle_count += 1
        else:
            single_count += 1
        chain.append(
            FullCoverageChainSegment(
                states=states,
                is_cycle=is_cycle,
                has_back_edge=is_cycle,
            )
        )
        covered.update(states)

    all_states = set(adj.keys())
    uncovered = tuple(sorted(all_states - covered))

    return FullCoverageChainResult(
        segments=tuple(chain),
        total_states=len(all_states),
        covered_states=len(covered),
        uncovered_states=uncovered,
        single_state_sccs=single_count,
        cycle_sccs=cycle_count,
    )


def log_chain_coverage(dag, *, context_label: str = "") -> FullCoverageChainResult | None:
    """Env-gated diagnostic logger for the SCC-based full-coverage chain.

    Returns the chain result if the probe is enabled, otherwise ``None``.
    Does not emit any modifications; purely observational.
    """
    if not probe_enabled():
        return None

    result = compute_full_coverage_chain(dag)
    label = f" ({context_label})" if context_label else ""
    logger.info(
        "FULL COVERAGE CHAIN PROBE%s: total_states=%d covered=%d uncovered=%d "
        "single_sccs=%d cycle_sccs=%d segments=%d",
        label,
        result.total_states,
        result.covered_states,
        len(result.uncovered_states),
        result.single_state_sccs,
        result.cycle_sccs,
        len(result.segments),
    )
    if result.uncovered_states:
        logger.warning(
            "FULL COVERAGE CHAIN PROBE%s: %d uncovered states=%s",
            label,
            len(result.uncovered_states),
            [f"0x{s:08X}" for s in result.uncovered_states[:20]],
        )
    # Log the first 10 segments to show chain shape without flooding
    for idx, seg in enumerate(result.segments[:10]):
        state_labels = [f"0x{s:08X}" for s in seg.states]
        tag = "CYCLE" if seg.is_cycle else "SINGLE"
        logger.info(
            "FULL COVERAGE CHAIN PROBE%s[%d/%d] %s states=%s",
            label,
            idx,
            len(result.segments),
            tag,
            state_labels,
        )
    if len(result.segments) > 10:
        logger.info(
            "FULL COVERAGE CHAIN PROBE%s: ... (%d more segments)",
            label,
            len(result.segments) - 10,
        )
    return result
