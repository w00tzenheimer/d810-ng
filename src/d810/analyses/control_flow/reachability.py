"""Reachability — a portable CFG analysis primitive (LLVM-analysis / LiSA-CFG style).

Pure forward reachability over an adjacency map. Defined ONCE and reused by every consumer
(LLVM: one analysis, many users — like a cached ``DominatorTree``; LiSA: CFG-first primitives):

* the live ``HodurSnapshotPolicy.compute_reachability_info`` feeds it the
  ``MicrocodeEvidenceProvider`` adjacency and wraps the result in ``ReachabilityInfo``;
* the portable ``recover_dispatcher`` analysis pass feeds it ``FlowGraph.successors``.

The result is the reachable SET, so it is independent of traversal order — byte-identical to the
live DFS it was extracted from.
"""
from __future__ import annotations

from d810.core.typing import Iterable, Mapping


def reachable_from(
    adjacency: Mapping[int, Iterable[int]], block_count: int, entry: int = 0
) -> frozenset[int]:
    """Return the block serials reachable from ``entry`` within ``[0, block_count)``.

    Mirrors the exact semantics of the extracted live walk: a node is visited iff it is in range
    and reached through successor edges; out-of-range / negative targets are skipped.
    """
    visited: set[int] = set()
    stack = [entry]
    while stack:
        serial = stack.pop()
        if serial in visited or serial < 0 or serial >= block_count:
            continue
        visited.add(serial)
        stack.extend(adjacency.get(serial, ()))
    return frozenset(visited)
