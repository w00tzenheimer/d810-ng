"""Strongly-connected component analysis over the linearized state DAG.

Phase 1 of the loop-region unflattening plan: consolidate the existing
Tarjan SCC computation that already exists at three call sites, persist
SCCs on ``LinearizedStateDag``, and add diagnostic logging. No behavior
change — purely refactor + observability.

References
----------
- ``DispatchRegionDetector.tarjan_scc`` — pure-Python, doctested Tarjan
  implementation.
- ``compute_full_coverage_chain`` — existing cycle predicate.
- ``_semantic_render_order`` — existing adjacency builder over the
  state-transition graph.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from d810.core import logging
from d810.analyses.control_flow.dispatch_region import DispatchRegionDetector

logger = logging.getLogger("D810.recon.flow.scc_analysis", logging.INFO)


@dataclass(frozen=True, slots=True)
class StateSCC:
    """One strongly-connected component over the state-transition graph.

    Parameters
    ----------
    scc_id : int
        Stable index assigned in Tarjan output order (reverse topological).
    states : frozenset[int]
        Concrete state-constant values present in this component (32-bit
        masked). Empty if the component contains only synthetic / non-const
        nodes.
    nodes : frozenset[object]
        Opaque ``StateDagNodeKey`` instances. Typed as ``object`` to avoid
        an import cycle with ``linearized_state_dag``.
    has_self_loop : bool
        True iff size==1 and the single node has a self-edge.
    is_trivial : bool
        True iff size==1 with no self-edge (i.e. acyclic).
    """

    scc_id: int
    states: frozenset[int]
    nodes: frozenset[object]
    has_self_loop: bool
    is_trivial: bool

    @property
    def is_cyclic(self) -> bool:
        return not self.is_trivial


def compute_state_sccs(dag) -> tuple[StateSCC, ...]:
    """Compute SCCs over the DAG's state transition graph.

    Returned in reverse-topological order (Tarjan's standard output).
    """
    edges_by_source = defaultdict(list)
    for edge in dag.edges:
        if edge.target_key is not None:
            edges_by_source[edge.source_key].append(edge)

    nodes_by_key = {n.key: n for n in dag.nodes}
    key_to_idx = {key: idx for idx, key in enumerate(nodes_by_key)}
    idx_to_key = {idx: key for key, idx in key_to_idx.items()}

    adj: dict[int, tuple[int, ...]] = {}
    for key in nodes_by_key:
        succs = tuple(
            key_to_idx[edge.target_key]
            for edge in edges_by_source.get(key, ())
            if edge.target_key in key_to_idx
        )
        adj[key_to_idx[key]] = succs

    raw_sccs = DispatchRegionDetector.tarjan_scc(adj)

    out: list[StateSCC] = []
    for scc_id, idx_set in enumerate(raw_sccs):
        keys = frozenset(idx_to_key[i] for i in idx_set)
        states = frozenset(
            int(getattr(k, "state_const")) & 0xFFFFFFFF
            for k in keys
            if getattr(k, "state_const", None) is not None
        )
        size = len(idx_set)
        if size == 1:
            only = next(iter(idx_set))
            has_self_loop = only in adj.get(only, ())
        else:
            has_self_loop = False
        is_trivial = size == 1 and not has_self_loop
        out.append(
            StateSCC(
                scc_id=scc_id,
                states=states,
                nodes=keys,
                has_self_loop=has_self_loop,
                is_trivial=is_trivial,
            )
        )
    return tuple(out)


def log_sccs(sccs: tuple[StateSCC, ...]) -> None:
    """Emit one INFO line per cyclic SCC."""
    cyclic = [s for s in sccs if s.is_cyclic]
    if not cyclic:
        return
    logger.info("recon SCC: %d cyclic component(s)", len(cyclic))
    for s in cyclic:
        sample_states = ", ".join(f"0x{x:08X}" for x in sorted(s.states)[:8])
        more = "..." if len(s.states) > 8 else ""
        logger.info(
            "recon SCC: cycle id=%d size=%d states=[%s%s]%s",
            s.scc_id,
            len(s.states),
            sample_states,
            more,
            " self-loop" if s.has_self_loop else "",
        )


# ---------------------------------------------------------------------------
# Phase 2: Loop-region classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoopRegion:
    """A cyclic state-level region with its relationship to the dispatcher.

    Each :class:`LoopRegion` corresponds to one cyclic :class:`StateSCC` and
    augments it with structural information about how the cycle's handler
    blocks intersect the dispatcher region (condition-chain nodes plus dispatcher entry).

    Parameters
    ----------
    scc_id : int
        Matches ``StateSCC.scc_id``.
    kind : str
        One of ``"dispatcher_internal"`` (every handler block lies inside
        the dispatcher region), ``"handler_internal"`` (no handler block
        lies inside the dispatcher region), or ``"cross_cut"`` (mixed —
        the cycle straddles the dispatcher boundary).
    states : frozenset[int]
        Concrete state-constant values present in the cycle (mirrored from
        the underlying SCC).
    handler_serials : frozenset[int]
        Handler block serials participating in the cycle. May be empty if
        the cycle contains only synthetic / sentinel nodes.
    dispatcher_handlers : frozenset[int]
        Subset of ``handler_serials`` that lie inside the dispatcher region.
    nondispatcher_handlers : frozenset[int]
        Subset of ``handler_serials`` outside the dispatcher region.
    has_self_loop : bool
        Mirrored from the underlying SCC.
    size : int
        Number of nodes in the underlying SCC.
    """

    scc_id: int
    kind: str
    states: frozenset[int]
    handler_serials: frozenset[int]
    dispatcher_handlers: frozenset[int]
    nondispatcher_handlers: frozenset[int]
    has_self_loop: bool
    size: int


def classify_loop_regions(
    dag,
    *,
    dispatcher_region: set[int] | frozenset[int],
) -> tuple[LoopRegion, ...]:
    """Classify every cyclic SCC of ``dag`` as a :class:`LoopRegion`.

    Parameters
    ----------
    dag : LinearizedStateDag
        Must already have ``sccs`` populated (Phase 1 contract).
    dispatcher_region : set[int]
        Block serials considered "inside" the dispatcher. Typically
        ``set(report.condition_chain_blocks) | {report.dispatcher_entry_serial}``.
    """
    region = frozenset(dispatcher_region)
    sccs = getattr(dag, "sccs", ()) or ()
    regions: list[LoopRegion] = []

    for scc in sccs:
        if not scc.is_cyclic:
            continue
        handler_serials: set[int] = set()
        for key in scc.nodes:
            serial = getattr(key, "handler_serial", None)
            if serial is None:
                # Some StateDagNodeKey variants store the block serial under
                # a different attribute; fall back to ``block_serial``.
                serial = getattr(key, "block_serial", None)
            if serial is not None:
                try:
                    handler_serials.add(int(serial))
                except (TypeError, ValueError):
                    continue

        dispatcher_handlers = frozenset(s for s in handler_serials if s in region)
        nondispatcher_handlers = frozenset(
            s for s in handler_serials if s not in region
        )
        if not handler_serials:
            kind = "handler_internal"
        elif dispatcher_handlers and not nondispatcher_handlers:
            kind = "dispatcher_internal"
        elif nondispatcher_handlers and not dispatcher_handlers:
            kind = "handler_internal"
        else:
            kind = "cross_cut"

        regions.append(
            LoopRegion(
                scc_id=scc.scc_id,
                kind=kind,
                states=scc.states,
                handler_serials=frozenset(handler_serials),
                dispatcher_handlers=dispatcher_handlers,
                nondispatcher_handlers=nondispatcher_handlers,
                has_self_loop=scc.has_self_loop,
                size=len(scc.nodes),
            )
        )

    if regions:
        logger.info("loop region: %d classified", len(regions))
        for r in regions:
            sample_states = ", ".join(f"0x{x:08X}" for x in sorted(r.states)[:6])
            more = "..." if len(r.states) > 6 else ""
            sample_h = ", ".join(str(s) for s in sorted(r.handler_serials)[:6])
            more_h = "..." if len(r.handler_serials) > 6 else ""
            logger.info(
                "loop region: id=%d kind=%s size=%d states=[%s%s] handlers=[%s%s]"
                " disp=%d non-disp=%d%s",
                r.scc_id,
                r.kind,
                r.size,
                sample_states,
                more,
                sample_h,
                more_h,
                len(r.dispatcher_handlers),
                len(r.nondispatcher_handlers),
                " self-loop" if r.has_self_loop else "",
            )

    return tuple(regions)
