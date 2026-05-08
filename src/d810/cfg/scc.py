"""Strongly-connected component analysis over a live microcode CFG.

Microcode-level analog of ``recon.flow.scc_analysis.compute_state_sccs``.
``compute_state_sccs`` operates on the recon ``LinearizedStateDag``; this
module operates on the live ``mba_t`` block graph after D810 has applied
its modifications, where the residual SCCs are the structural artifact
that prevent IDA's structurer from rendering clean ``while``/``do-while``
loops.

The Tarjan implementation mirrors ``DispatchRegionDetector.tarjan_scc``
in the recon layer (the layered architecture forbids ``cfg`` from
importing ``recon``). Doctests on ``_tarjan_scc`` match the canonical
version exactly so any drift is caught. No IDA dependency at the
algorithm level: ``compute_live_cfg_sccs`` takes a plain successor map
and ``cfg_sccs_from_mba`` is a thin adapter that builds the map from a
live ``mba_t``.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import Mapping

logger = getLogger(__name__)


def _tarjan_scc(adj: dict[int, tuple[int, ...]]) -> list[frozenset[int]]:
    """Tarjan SCC over an integer adjacency map.

    Pure-Python, no dependencies. Mirrors
    ``d810.recon.flow.dispatch_region.DispatchRegionDetector.tarjan_scc``
    intentionally — the layered architecture forbids ``cfg`` from
    importing ``recon``. The doctests below match the canonical version
    bit-for-bit so any drift is caught immediately.

    Returns SCCs in reverse-topological order (Tarjan's standard output).

    >>> _tarjan_scc({0: (1,), 1: (0,)})
    [frozenset({0, 1})]
    >>> _tarjan_scc({0: (1,), 1: (2,), 2: ()})
    [frozenset({2}), frozenset({1}), frozenset({0})]
    """
    if not adj:
        return []

    nodes = set(adj.keys())
    for succs in adj.values():
        nodes.update(succs)

    index = 0
    stack: list[int] = []
    indices: dict[int, int] = {}
    lowlink: dict[int, int] = {}
    on_stack: set[int] = set()
    sccs: list[frozenset[int]] = []

    def strongconnect(v: int) -> None:
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in adj.get(v, ()):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            scc_nodes: set[int] = set()
            while stack:
                w = stack.pop()
                on_stack.discard(w)
                scc_nodes.add(w)
                if w == v:
                    break
            sccs.append(frozenset(scc_nodes))

    for n in nodes:
        if n not in indices:
            strongconnect(n)

    return sccs


@dataclass(frozen=True, slots=True)
class CfgSCC:
    """One strongly-connected component over the live microcode CFG.

    Parameters
    ----------
    scc_id : int
        Stable index assigned in Tarjan output order (reverse topological).
    blocks : frozenset[int]
        Block serials in this component.
    cyclic_edges : frozenset[tuple[int, int]]
        Edges ``(src, tgt)`` where both endpoints are in this SCC. These
        are the edges that close cycles; redirecting any one of them away
        from the SCC reduces the cycle.
    has_self_loop : bool
        True iff size==1 and the single block has a self-edge.
    is_trivial : bool
        True iff size==1 with no self-edge (i.e. acyclic singleton).
    """

    scc_id: int
    blocks: frozenset[int]
    cyclic_edges: frozenset[tuple[int, int]]
    has_self_loop: bool
    is_trivial: bool

    @property
    def is_cyclic(self) -> bool:
        return not self.is_trivial

    @property
    def size(self) -> int:
        return len(self.blocks)


def compute_live_cfg_sccs(
    block_succs: Mapping[int, tuple[int, ...]],
) -> tuple[CfgSCC, ...]:
    """Compute SCCs over a live microcode CFG given by a successor map.

    Returned in reverse-topological order (Tarjan's standard output:
    leaves first).

    Parameters
    ----------
    block_succs : Mapping[int, tuple[int, ...]]
        Map from block serial to its successors. Successors not present
        as keys are treated as having no outgoing edges (they remain in
        the graph as leaves).

    Returns
    -------
    tuple[CfgSCC, ...]
        SCCs in reverse-topological order.
    """
    adj: dict[int, tuple[int, ...]] = {}
    all_blocks: set[int] = set()
    for src, succs in block_succs.items():
        all_blocks.add(int(src))
        clean = tuple(int(s) for s in succs)
        adj[int(src)] = clean
        for s in clean:
            all_blocks.add(int(s))
    for serial in all_blocks:
        adj.setdefault(serial, ())

    raw_sccs = _tarjan_scc(adj)

    out: list[CfgSCC] = []
    for scc_id, idx_set in enumerate(raw_sccs):
        member = frozenset(int(b) for b in idx_set)
        cyclic_edges = frozenset(
            (src, tgt)
            for src in member
            for tgt in adj.get(src, ())
            if tgt in member
        )
        if len(member) == 1:
            only = next(iter(member))
            has_self_loop = only in adj.get(only, ())
        else:
            has_self_loop = False
        is_trivial = len(member) == 1 and not has_self_loop
        out.append(
            CfgSCC(
                scc_id=scc_id,
                blocks=member,
                cyclic_edges=cyclic_edges,
                has_self_loop=has_self_loop,
                is_trivial=is_trivial,
            )
        )
    return tuple(out)


def nontrivial_sccs(sccs: tuple[CfgSCC, ...]) -> tuple[CfgSCC, ...]:
    """Return only the cyclic SCCs (size>1 or size==1 with self-loop)."""
    return tuple(s for s in sccs if s.is_cyclic)


def block_succs_from_mba(mba) -> dict[int, tuple[int, ...]]:
    """Build a successor map from a live ``mba_t``.

    Pure adapter; kept separate so ``compute_live_cfg_sccs`` stays
    IDA-agnostic and unit-testable.
    """
    succs: dict[int, tuple[int, ...]] = {}
    qty = int(getattr(mba, "qty", 0))
    for i in range(qty):
        blk = mba.get_mblock(i)
        nsucc = int(blk.nsucc())
        succs[i] = tuple(int(blk.succ(j)) for j in range(nsucc))
    return succs


def cfg_sccs_from_mba(mba) -> tuple[CfgSCC, ...]:
    """Convenience: compute SCCs directly over a live ``mba_t``."""
    return compute_live_cfg_sccs(block_succs_from_mba(mba))


def log_sccs(sccs: tuple[CfgSCC, ...]) -> None:
    """Emit one INFO line per cyclic SCC."""
    cyclic = nontrivial_sccs(sccs)
    if not cyclic:
        return
    logger.info("live CFG SCC: %d cyclic component(s)", len(cyclic))
    for s in cyclic:
        sample = sorted(s.blocks)
        head = ", ".join(str(b) for b in sample[:8])
        more = "..." if len(sample) > 8 else ""
        logger.info(
            "live CFG SCC: id=%d size=%d back_edges=%d blocks=[%s%s]%s",
            s.scc_id,
            s.size,
            len(s.cyclic_edges),
            head,
            more,
            " self-loop" if s.has_self_loop else "",
        )


__all__ = [
    "CfgSCC",
    "block_succs_from_mba",
    "cfg_sccs_from_mba",
    "compute_live_cfg_sccs",
    "log_sccs",
    "nontrivial_sccs",
]
