"""Hex-Rays-agnostic CFG reachability helpers for flow reconnaissance."""

from __future__ import annotations


def compute_reachable_blocks(
    flow_graph: object,
    *,
    start_serial: int | None,
    limit: int = 4096,
) -> set[int] | None:
    """Return blocks reachable from ``start_serial`` within ``limit`` hops."""
    if start_serial is None:
        return None
    try:
        start_block = flow_graph.get_block(start_serial)
    except Exception:
        start_block = None
    if start_block is None:
        return None

    reachable: set[int] = set()
    worklist: list[int] = [int(start_serial)]
    while worklist and len(reachable) < limit:
        current = worklist.pop()
        if current in reachable:
            continue
        reachable.add(current)
        try:
            succs = tuple(flow_graph.successors(current))
        except Exception:
            block = flow_graph.get_block(current)
            succs = tuple(getattr(block, "succs", ())) if block is not None else ()
        for succ in succs:
            succ_serial = int(succ)
            if succ_serial not in reachable:
                worklist.append(succ_serial)
    return reachable


def target_reaches_source_ignoring_blocks(
    flow_graph: object,
    *,
    target_entry: int,
    source_block: int,
    ignored_blocks: set[int],
    limit: int = 256,
) -> bool:
    """Return whether ``target_entry`` can reach ``source_block``.

    ``ignored_blocks`` are treated as removed from the graph while exploring
    the reachable frontier.
    """
    if target_entry == source_block:
        return True

    worklist: list[int] = [int(target_entry)]
    seen: set[int] = set()
    while worklist and len(seen) < limit:
        current = worklist.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == source_block:
            return True
        try:
            succs = tuple(flow_graph.successors(current))
        except Exception:
            block = flow_graph.get_block(current)
            succs = tuple(getattr(block, "succs", ())) if block is not None else ()
        for succ in succs:
            succ_serial = int(succ)
            if succ_serial in ignored_blocks or succ_serial in seen:
                continue
            worklist.append(succ_serial)
    return False


def collect_dispatcher_predecessors(
    flow_graph: object,
    dispatcher_serial: int,
    *,
    bst_node_blocks: set[int],
) -> tuple[int, ...]:
    """Return non-BST predecessors of ``dispatcher_serial``."""
    if dispatcher_serial < 0:
        return ()
    try:
        dispatcher_block = flow_graph.get_block(dispatcher_serial)
    except Exception:
        dispatcher_block = None
    if dispatcher_block is None:
        return ()

    residual: list[int] = []
    for serial in sorted(tuple(getattr(dispatcher_block, "preds", ()))):
        if serial == dispatcher_serial or serial in bst_node_blocks:
            continue
        residual.append(int(serial))
    return tuple(residual)


def collect_residual_dispatcher_predecessors(
    flow_graph: object,
    dispatcher_serial: int,
    *,
    bst_node_blocks: set[int],
    reachable_from_serial: int | None = None,
) -> tuple[int, ...]:
    """Return dispatcher predecessors that remain reachable from entry."""
    residual = collect_dispatcher_predecessors(
        flow_graph,
        dispatcher_serial,
        bst_node_blocks=bst_node_blocks,
    )
    reachable_blocks = compute_reachable_blocks(
        flow_graph,
        start_serial=reachable_from_serial,
    )
    if reachable_blocks is None:
        return residual
    return tuple(serial for serial in residual if serial in reachable_blocks)


def edge_reachable_frontier(
    *,
    ordered_path: tuple[int, ...],
    source_block: int,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
) -> int | None:
    """Return the deepest reachable non-dispatcher block on a path."""
    for serial in reversed(tuple(int(block) for block in ordered_path)):
        if serial in dispatcher_region:
            continue
        if serial in reachable_blocks:
            return serial
    source_block = int(source_block)
    if source_block in dispatcher_region:
        return None
    if source_block in reachable_blocks:
        return source_block
    return None


def graph_reaches_block(
    flow_graph: object,
    *,
    source_block: int,
    target_block: int,
    limit: int = 512,
) -> bool:
    """Return whether ``source_block`` can reach ``target_block``."""
    reachable = compute_reachable_blocks(
        flow_graph,
        start_serial=source_block,
        limit=limit,
    )
    return bool(reachable is not None and target_block in reachable)


def pick_deepest_rescue_frontier(
    flow_graph: object,
    candidates: tuple[int, ...],
) -> int | None:
    """Pick the deepest non-dominated block from ``candidates``."""
    if not candidates:
        return None
    unique_candidates = tuple(sorted({int(serial) for serial in candidates}))
    if len(unique_candidates) == 1:
        return unique_candidates[0]

    deepest: list[int] = []
    for source_block in unique_candidates:
        if any(
            source_block != other
            and graph_reaches_block(
                flow_graph,
                source_block=source_block,
                target_block=other,
            )
            for other in unique_candidates
        ):
            continue
        deepest.append(source_block)

    if deepest:
        return deepest[-1]
    return unique_candidates[-1]


__all__ = [
    "collect_dispatcher_predecessors",
    "collect_residual_dispatcher_predecessors",
    "compute_reachable_blocks",
    "edge_reachable_frontier",
    "graph_reaches_block",
    "pick_deepest_rescue_frontier",
    "target_reaches_source_ignoring_blocks",
]
