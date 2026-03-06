"""Graph-only dominator tree computation for control-flow graphs."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import Mapping, Sequence

logger = getLogger(__name__)


@dataclass(frozen=True)
class DominatorTree:
    """Immutable dominator tree."""

    idom: Mapping[int, int | None]
    entry: int

    def dominates(self, a: int, b: int) -> bool:
        """Return True if node ``a`` dominates node ``b``."""
        if a == b:
            return True
        current: int | None = self.idom.get(b)
        while current is not None:
            if current == a:
                return True
            current = self.idom.get(current)
        return False

    def dominators_of(self, node: int) -> frozenset[int]:
        """Return all dominators of ``node`` (including itself)."""
        if node not in self.idom:
            return frozenset({node})
        result: list[int] = [node]
        current: int | None = self.idom.get(node)
        while current is not None:
            result.append(current)
            current = self.idom.get(current)
        return frozenset(result)


def _dfs_postorder(
    start: int,
    successors: Mapping[int, Sequence[int]],
) -> list[int]:
    visited: set[int] = set()
    postorder: list[int] = []
    stack: list[tuple[int, bool]] = [(start, False)]
    while stack:
        node, returning = stack.pop()
        if returning:
            postorder.append(node)
            continue
        if node in visited:
            continue
        visited.add(node)
        stack.append((node, True))
        for succ in successors.get(node, ()):
            if succ not in visited:
                stack.append((succ, False))
    return postorder


def compute_dom_tree(
    successors: Mapping[int, Sequence[int]],
    entry: int,
) -> DominatorTree:
    """Compute immediate dominators using the Cooper-Harvey-Kennedy algorithm."""
    all_nodes: set[int] = {entry}
    for node, succs in successors.items():
        all_nodes.add(node)
        all_nodes.update(int(s) for s in succs)

    norm_succs: dict[int, list[int]] = {node: [] for node in all_nodes}
    preds: dict[int, list[int]] = {node: [] for node in all_nodes}
    for node, succs in successors.items():
        norm_succs.setdefault(node, [])
        for succ in succs:
            succ_int = int(succ)
            norm_succs[node].append(succ_int)
            preds.setdefault(succ_int, []).append(int(node))

    postorder = _dfs_postorder(entry, norm_succs)
    if not postorder:
        return DominatorTree(idom={}, entry=entry)
    rpo: list[int] = list(reversed(postorder))
    rpo_number: dict[int, int] = {node: i for i, node in enumerate(rpo)}

    idom: dict[int, int] = {entry: entry}

    def intersect(b1: int, b2: int) -> int:
        finger1, finger2 = b1, b2
        while finger1 != finger2:
            while rpo_number[finger1] > rpo_number[finger2]:
                finger1 = idom[finger1]
            while rpo_number[finger2] > rpo_number[finger1]:
                finger2 = idom[finger2]
        return finger1

    changed = True
    while changed:
        changed = False
        for node in rpo:
            if node == entry:
                continue
            processed = [pred for pred in preds.get(node, []) if pred in idom]
            if not processed:
                continue
            new_idom = processed[0]
            for pred in processed[1:]:
                new_idom = intersect(pred, new_idom)
            if idom.get(node) != new_idom:
                idom[node] = new_idom
                changed = True

    public_idom: dict[int, int | None] = {}
    for node, dom in idom.items():
        public_idom[node] = None if node == entry else dom

    logger.debug(
        "compute_dom_tree: %d nodes, reachable=%d, entry=%d",
        len(all_nodes),
        len(public_idom),
        entry,
    )
    return DominatorTree(idom=public_idom, entry=entry)


def dominates(dom: list[set[int]] | DominatorTree, a: int, b: int) -> bool:
    """Check if block ``a`` dominates block ``b``."""
    if isinstance(dom, DominatorTree):
        return dom.dominates(a, b)
    if b < 0 or b >= len(dom):
        return False
    return a in dom[b]


__all__ = [
    "DominatorTree",
    "compute_dom_tree",
    "dominates",
]
