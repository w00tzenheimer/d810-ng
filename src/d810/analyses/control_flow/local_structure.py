"""Portable per-block local-structure read-off for a state node's owned region.

The canonical intra-node structure is per-block: one :class:`StateLocalSegment`
(``blk[N]``) per owned block, kind-classified, plus one classified
:class:`StateLocalEdge` per intra-region CFG edge.  ``build_local_structure`` is
the portable producer -- a translation of the legacy ``_build_local_edges`` /
``_classify_local_edge_kind`` (linearized_state_dag.py) that reads the region
topology + the owner-set shared / terminal-exit sets and emits the CANONICAL
types instead of walking live ``HandlerPathResult`` paths.

The edge classification is the textbook LLVM CFG edge typing: a 2-successor
block's arms are FALLTHROUGH (arm 0) / TAKEN (arm 1); a >1-predecessor target is
a JOIN; the shared epilogue and terminal exits are tagged first.
"""
from __future__ import annotations

from d810.core.typing import Callable, FrozenSet, Iterable

from d810.analyses.control_flow.linearized_state_dag import (
    LocalEdgeKind,
    LocalSegmentKind,
    StateLocalEdge,
    StateLocalSegment,
    _segment_id,
)
from d810.analyses.data_flow.domain import NodeId

__all__ = ["build_local_structure"]

_Succ = Callable[[NodeId], Iterable[NodeId]]


def _segment_kind(
    block: int,
    *,
    successors_of: _Succ,
    predecessors_of: _Succ,
    shared_blocks: FrozenSet[int],
    terminal_exit_blocks: FrozenSet[int],
) -> LocalSegmentKind:
    if block in shared_blocks:
        return LocalSegmentKind.SHARED_SUFFIX
    if block in terminal_exit_blocks:
        return LocalSegmentKind.TERMINAL_SUFFIX
    if len(tuple(successors_of(block))) >= 2:
        return LocalSegmentKind.BRANCH
    if len(tuple(predecessors_of(block))) > 1:
        return LocalSegmentKind.JOIN
    return LocalSegmentKind.STRAIGHT_LINE


def _classify_local_edge(
    source_block: int,
    target_block: int,
    *,
    successors_of: _Succ,
    predecessors_of: _Succ,
    shared_blocks: FrozenSet[int],
    terminal_exit_blocks: FrozenSet[int],
) -> tuple[LocalEdgeKind, int | None]:
    # Mirrors _classify_local_edge_kind: terminal / shared tagged first, then the
    # 2-successor branch arms, then a multi-predecessor JOIN, else a GOTO.
    if target_block in terminal_exit_blocks:
        return LocalEdgeKind.TERMINAL, None
    if target_block in shared_blocks:
        return LocalEdgeKind.SHARED_SUFFIX, None
    succs = tuple(successors_of(source_block))
    if len(succs) == 2:
        if target_block == succs[0]:
            return LocalEdgeKind.FALLTHROUGH, 0
        if target_block == succs[1]:
            return LocalEdgeKind.TAKEN, 1
    if len(tuple(predecessors_of(target_block))) > 1:
        return LocalEdgeKind.JOIN, None
    return LocalEdgeKind.GOTO, None


def build_local_structure(
    owned_blocks: tuple[int, ...],
    *,
    successors_of: _Succ,
    predecessors_of: _Succ,
    shared_blocks: FrozenSet[int] = frozenset(),
    terminal_exit_blocks: FrozenSet[int] = frozenset(),
) -> tuple[tuple[StateLocalSegment, ...], tuple[StateLocalEdge, ...]]:
    """Return ``(local_segments, local_edges)`` for one node's owned region.

    One segment per owned block (``blk[N]``, kind-classified); one classified
    edge per CFG edge whose source AND target are both owned (intra-region).
    Deterministic (blocks/edges in sorted order) and deduplicated.
    """
    owned = {int(b) for b in owned_blocks}
    segments = tuple(
        StateLocalSegment(
            segment_id=_segment_id(block),
            kind=_segment_kind(
                block,
                successors_of=successors_of,
                predecessors_of=predecessors_of,
                shared_blocks=shared_blocks,
                terminal_exit_blocks=terminal_exit_blocks,
            ),
            blocks=(block,),
        )
        for block in sorted(owned)
    )

    seen: set[tuple[int, int, LocalEdgeKind, int | None]] = set()
    edges: list[StateLocalEdge] = []
    for source in sorted(owned):
        for target in successors_of(source):
            target = int(target)
            if target not in owned:
                continue
            kind, branch_arm = _classify_local_edge(
                source,
                target,
                successors_of=successors_of,
                predecessors_of=predecessors_of,
                shared_blocks=shared_blocks,
                terminal_exit_blocks=terminal_exit_blocks,
            )
            signature = (source, target, kind, branch_arm)
            if signature in seen:
                continue
            seen.add(signature)
            edges.append(
                StateLocalEdge(
                    source_segment_id=_segment_id(source),
                    target_segment_id=_segment_id(target),
                    kind=kind,
                    branch_arm=branch_arm,
                )
            )

    return segments, tuple(edges)
