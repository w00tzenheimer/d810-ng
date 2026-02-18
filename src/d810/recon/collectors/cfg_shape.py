"""CFGShapeCollector - microcode CFG topology metrics.

Operates on either a live ``mba_t`` (at IDA runtime) or a ``PortableCFG``
snapshot (for unit tests). Distinguishes the two by duck-typing: if the
target has a ``blocks`` attribute that maps serials to ``BlockSnapshot``,
it is treated as a ``PortableCFG``; otherwise it is treated as an ``mba_t``.

Maturities fired: MMAT_CALLS (3), MMAT_PREOPTIMIZED (5).
"""
from __future__ import annotations

import time
from types import MappingProxyType

from d810.recon.models import CandidateFlag, ReconResult

# IDA maturity constants - duplicated here so this file has no IDA dependency.
_MMAT_CALLS = 3
_MMAT_PREOPTIMIZED = 5

# Threshold above which a block's in-degree is flagged as a dispatcher candidate.
_HIGH_INDEGREE_THRESHOLD = 3


def _collect_from_portable_cfg(target) -> tuple[set[int], dict[int, tuple[int, ...]], dict[int, set[int]]]:
    """Extract nodes/succs/preds from a PortableCFG snapshot."""
    nodes: set[int] = set(target.blocks.keys())
    succs: dict[int, tuple[int, ...]] = {}
    preds: dict[int, set[int]] = {}
    for serial, blk in target.blocks.items():
        succs[serial] = blk.succs
        preds.setdefault(serial, set())
        for s in blk.succs:
            preds.setdefault(s, set()).add(serial)
    # Ensure all nodes have entries
    for n in nodes:
        preds.setdefault(n, set())
        succs.setdefault(n, ())
    return nodes, succs, preds


def _collect_from_mba(target) -> tuple[set[int], dict[int, tuple[int, ...]], dict[int, set[int]]]:
    """Extract nodes/succs/preds from a live mba_t."""
    nodes: set[int] = set()
    succs: dict[int, tuple[int, ...]] = {}
    preds: dict[int, set[int]] = {}
    qty = int(getattr(target, "qty", 0) or 0)
    for i in range(qty):
        blk = target.get_mblock(i)
        if blk is None:
            continue
        serial = int(getattr(blk, "serial", i))
        nodes.add(serial)
        out = tuple(int(s) for s in getattr(blk, "succset", ()))
        succs[serial] = out
        preds.setdefault(serial, set())
        for s in out:
            preds.setdefault(s, set()).add(serial)
    for n in nodes:
        preds.setdefault(n, set())
        succs.setdefault(n, ())
    return nodes, succs, preds


def _flattening_score(
    entry: int | None,
    nodes: set[int],
    succs: dict[int, tuple[int, ...]],
    preds: dict[int, set[int]],
) -> float:
    """Compute a flattening score: fraction of reachable blocks dominated
    by the strongest re-entry hub.  Borrowed from analysis_stats pattern.
    """
    if entry is None or entry not in nodes or len(nodes) <= 1:
        return 0.0

    # BFS reachability
    visited: set[int] = set()
    queue = [entry]
    while queue:
        cur = queue.pop()
        if cur in visited:
            continue
        visited.add(cur)
        for nxt in succs.get(cur, ()):
            if nxt not in visited:
                queue.append(nxt)
    reachable = visited
    if len(reachable) <= 1:
        return 0.0

    # Dataflow dominators (iterative)
    dom: dict[int, set[int]] = {}
    for node in reachable:
        dom[node] = {entry} if node == entry else set(reachable)

    changed = True
    while changed:
        changed = False
        for node in reachable:
            if node == entry:
                continue
            predset = [p for p in preds.get(node, set()) if p in reachable]
            if predset:
                inter = set(dom[predset[0]])
                for p in predset[1:]:
                    inter &= dom[p]
            else:
                inter = set()
            new_dom = {node} | inter
            if new_dom != dom[node]:
                dom[node] = new_dom
                changed = True

    best = 0.0
    denom = float(len(reachable))
    for block in reachable:
        dominated = {n for n in reachable if block in dom.get(n, set())}
        if not dominated:
            continue
        if not any(pred in dominated for pred in preds.get(block, set())):
            continue
        score = float(len(dominated)) / denom
        if score > best:
            best = score
    return float(best)


class CFGShapeCollector:
    """Collect CFG topology metrics from microcode at MMAT_CALLS and MMAT_PREOPTIMIZED.

    Metrics produced:
        - ``block_count``: total number of basic blocks
        - ``edge_count``: total number of CFG edges
        - ``max_in_degree``: maximum number of predecessors any block has
        - ``flattening_score``: ``float`` in ``[0.0, 1.0]`` - fraction of
          reachable blocks dominated by the strongest hub with back-edges

    Candidates flagged:
        - ``"high_indegree_block"`` when ``max_in_degree >= 3``

    Accepts both ``PortableCFG`` (unit tests) and live ``mba_t`` (IDA runtime).
    """

    name: str = "CFGShapeCollector"
    maturities: frozenset[int] = frozenset({_MMAT_CALLS, _MMAT_PREOPTIMIZED})
    level: str = "microcode"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        """Collect CFG shape metrics.

        :param target: ``PortableCFG`` or live ``mba_t``.
        :param func_ea: Function effective address.
        :param maturity: Current maturity level.
        :return: Frozen ``ReconResult`` with CFG shape metrics.
        """
        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            nodes, succs, preds = _collect_from_portable_cfg(target)
            entry = getattr(target, "entry_serial", None)
        else:
            nodes, succs, preds = _collect_from_mba(target)
            entry = 0 if 0 in nodes else (min(nodes) if nodes else None)

        block_count = len(nodes)
        edge_count = sum(len(s) for s in succs.values())
        max_in_degree = max((len(p) for p in preds.values()), default=0)
        score = _flattening_score(entry, nodes, succs, preds)

        metrics = MappingProxyType({
            "block_count": block_count,
            "edge_count": edge_count,
            "max_in_degree": max_in_degree,
            "flattening_score": score,
        })

        candidates: list[CandidateFlag] = []
        if max_in_degree >= _HIGH_INDEGREE_THRESHOLD:
            # Find block(s) with the highest in-degree
            hub_serial = max(nodes, key=lambda n: len(preds.get(n, set())))
            candidates.append(CandidateFlag(
                kind="high_indegree_block",
                block_serial=hub_serial,
                confidence=min(1.0, (max_in_degree - _HIGH_INDEGREE_THRESHOLD + 1) * 0.2),
                detail=f"block {hub_serial} has {max_in_degree} predecessors",
            ))

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=metrics,
            candidates=tuple(candidates),
        )
