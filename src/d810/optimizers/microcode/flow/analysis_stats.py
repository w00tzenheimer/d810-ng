from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import Iterable


@dataclass(frozen=True)
class FlowProfileStats:
    total_blocks: int
    dispatch_region_n: int
    dispatch_scc_n: int
    dispatch_blocks_n: int
    dispatch_block_ratio: float
    dispatch_glue_nodes_n: int
    dispatch_exit_nodes_n: int
    dispatch_relay_nodes_n: int
    dispatch_glue_ratio: float
    relay_depth_estimate: int
    flattening_score: float
    has_nested_dispatch: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "total_blocks": self.total_blocks,
            "dispatch_region_n": self.dispatch_region_n,
            "dispatch_scc_n": self.dispatch_scc_n,
            "dispatch_blocks_n": self.dispatch_blocks_n,
            "dispatch_block_ratio": self.dispatch_block_ratio,
            "dispatch_glue_nodes_n": self.dispatch_glue_nodes_n,
            "dispatch_exit_nodes_n": self.dispatch_exit_nodes_n,
            "dispatch_relay_nodes_n": self.dispatch_relay_nodes_n,
            "dispatch_glue_ratio": self.dispatch_glue_ratio,
            "relay_depth_estimate": self.relay_depth_estimate,
            "flattening_score": self.flattening_score,
            "has_nested_dispatch": self.has_nested_dispatch,
        }


def _block_successors(blk: Any) -> tuple[int, ...]:
    succset = getattr(blk, "succset", ())
    return tuple(int(s) for s in succset)


def _get_entry_serial(nodes: set[int]) -> int | None:
    if not nodes:
        return None
    if 0 in nodes:
        return 0
    return min(nodes)


def _collect_cfg_graph(mba: Any) -> tuple[set[int], dict[int, tuple[int, ...]], dict[int, set[int]]]:
    nodes: set[int] = set()
    succs: dict[int, tuple[int, ...]] = {}
    preds: dict[int, set[int]] = {}
    qty = int(getattr(mba, "qty", 0) or 0)

    for serial in range(qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        cur = int(getattr(blk, "serial", serial))
        nodes.add(cur)
        out = _block_successors(blk)
        succs[cur] = out
        preds.setdefault(cur, set())
        for dst in out:
            preds.setdefault(dst, set()).add(cur)

    for serial in nodes:
        preds.setdefault(serial, set())
        succs.setdefault(serial, tuple())
    return nodes, succs, preds


def _relay_depth_estimate(
    dispatch_region: set[int],
    succs: dict[int, tuple[int, ...]],
    *,
    max_depth: int = 16,
) -> int:
    best = 0
    for root in dispatch_region:
        cur = root
        depth = 0
        seen: set[int] = set()
        while cur in dispatch_region and cur not in seen and depth < max_depth:
            seen.add(cur)
            internal = [dst for dst in succs.get(cur, ()) if dst in dispatch_region]
            if len(internal) != 1:
                break
            cur = internal[0]
            depth += 1
        if depth > best:
            best = depth
    return int(best)


def _largest_dispatch_scc_size(
    dispatch_region: set[int],
    succs: dict[int, tuple[int, ...]],
) -> int:
    if not dispatch_region:
        return 0

    index = 0
    stack: list[int] = []
    indices: dict[int, int] = {}
    lowlink: dict[int, int] = {}
    on_stack: set[int] = set()
    best = 0

    def strongconnect(v: int) -> None:
        nonlocal index, best
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in succs.get(v, ()):
            if w not in dispatch_region:
                continue
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            size = 0
            while stack:
                w = stack.pop()
                on_stack.remove(w)
                size += 1
                if w == v:
                    break
            if size > best:
                best = size

    for node in dispatch_region:
        if node not in indices:
            strongconnect(node)
    return int(best)


def _reachable_nodes(entry: int, succs: dict[int, tuple[int, ...]]) -> set[int]:
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
    return visited


def _dominators(
    entry: int,
    succs: dict[int, tuple[int, ...]],
    preds: dict[int, set[int]],
) -> dict[int, set[int]]:
    reachable = _reachable_nodes(entry, succs)
    if entry not in reachable:
        return {}

    dom: dict[int, set[int]] = {}
    for node in reachable:
        if node == entry:
            dom[node] = {entry}
        else:
            dom[node] = set(reachable)

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
    return dom


def _flattening_score(
    entry: int | None,
    nodes: set[int],
    succs: dict[int, tuple[int, ...]],
    preds: dict[int, set[int]],
) -> float:
    if entry is None or entry not in nodes or len(nodes) <= 1:
        return 0.0
    dom = _dominators(entry, succs, preds)
    if not dom:
        return 0.0
    reachable = set(dom.keys())
    if len(reachable) <= 1:
        return 0.0

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


def compute_flow_profile_stats(mba: Any, analysis: Any) -> FlowProfileStats:
    nodes, succs, preds = _collect_cfg_graph(mba)
    entry = _get_entry_serial(nodes)
    total_blocks = len(nodes)

    dispatchers = getattr(analysis, "dispatchers", [])
    dispatch_region = {int(serial) for serial in dispatchers if int(serial) in nodes}
    dispatch_region_n = len(dispatch_region)
    dispatch_blocks_n = len(getattr(analysis, "blocks", {}))
    dispatch_block_ratio = (
        float(dispatch_region_n) / float(total_blocks) if total_blocks > 0 else 0.0
    )

    dispatch_exit_nodes_n = 0
    dispatch_relay_nodes_n = 0
    dispatch_glue_nodes_n = 0
    for serial in dispatch_region:
        out = succs.get(serial, tuple())
        internal = [dst for dst in out if dst in dispatch_region]
        outside = [dst for dst in out if dst not in dispatch_region]
        if outside:
            dispatch_exit_nodes_n += 1
        if len(internal) == 1:
            dispatch_relay_nodes_n += 1
        if not outside and len(internal) <= 1:
            dispatch_glue_nodes_n += 1

    dispatch_glue_ratio = (
        float(dispatch_glue_nodes_n) / float(dispatch_region_n)
        if dispatch_region_n > 0
        else 0.0
    )
    relay_depth = _relay_depth_estimate(dispatch_region, succs)
    dispatch_scc_n = _largest_dispatch_scc_size(dispatch_region, succs)
    flattening_score = _flattening_score(entry, nodes, succs, preds)
    has_nested_dispatch = bool(
        int(getattr(analysis, "nested_loop_depth", 0) or 0) >= 2
    )

    return FlowProfileStats(
        total_blocks=total_blocks,
        dispatch_region_n=dispatch_region_n,
        dispatch_scc_n=dispatch_scc_n,
        dispatch_blocks_n=dispatch_blocks_n,
        dispatch_block_ratio=dispatch_block_ratio,
        dispatch_glue_nodes_n=dispatch_glue_nodes_n,
        dispatch_exit_nodes_n=dispatch_exit_nodes_n,
        dispatch_relay_nodes_n=dispatch_relay_nodes_n,
        dispatch_glue_ratio=dispatch_glue_ratio,
        relay_depth_estimate=relay_depth,
        flattening_score=flattening_score,
        has_nested_dispatch=has_nested_dispatch,
    )


def summarize_dispatcher_detection(
    *,
    analysis: Any,
    blocks_analyzed: int,
    blocks_skipped: int,
    strategies: Iterable[Any],
) -> dict[str, object]:
    strategies_used: dict[str, int] = {}
    blocks = getattr(analysis, "blocks", {})
    for strategy in strategies:
        name = getattr(strategy, "name", "")
        if name == "NONE":
            continue
        count = sum(
            1
            for info in blocks.values()
            if strategy in getattr(info, "strategies", ())
        )
        if count > 0:
            strategies_used[name] = count

    skip_rate = (
        float(blocks_skipped) / float(blocks_analyzed)
        if blocks_analyzed > 0
        else 0.0
    )

    return {
        "blocks_analyzed": int(blocks_analyzed),
        "blocks_with_strategies": len(blocks),
        "blocks_skipped": int(blocks_skipped),
        "skip_rate": skip_rate,
        "dispatchers_found": len(getattr(analysis, "dispatchers", [])),
        "strategies_used": strategies_used,
        "dispatcher_type": getattr(getattr(analysis, "dispatcher_type", None), "name", "UNKNOWN"),
        "state_constants_count": len(getattr(analysis, "state_constants", set())),
    }
