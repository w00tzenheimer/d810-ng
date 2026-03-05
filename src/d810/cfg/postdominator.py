"""Postdominator tree computation for control-flow graphs."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Sequence

logger = logging.getLogger(__name__)

# Sentinel used internally for the virtual exit node.
# Must not collide with real node ids (which are non-negative integers).
_VIRTUAL_EXIT = -1


@dataclass(frozen=True)
class PostdomTree:
    """Immutable postdominator tree.

    Attributes:
        idom: Mapping from node id to its immediate postdominator node id.
              None means the node is a root of the postdominator tree (an exit
              node has no postdominator above it in the real graph).
    """

    idom: Mapping[int, int | None]

    def postdominates(self, a: int, b: int) -> bool:
        """Return True if node ``a`` postdominates node ``b``.

        A node ``a`` postdominates ``b`` if every path from ``b`` to any
        exit passes through ``a``.  A node always postdominates itself.
        """
        if a == b:
            return True
        current: int | None = self.idom.get(b)
        while current is not None:
            if current == a:
                return True
            current = self.idom.get(current)
        return False

    def postdominators_of(self, node: int) -> frozenset[int]:
        """Return all postdominators of ``node`` (including itself)."""
        result: list[int] = [node]
        current: int | None = self.idom.get(node)
        while current is not None:
            result.append(current)
            current = self.idom.get(current)
        return frozenset(result)


# ---------------------------------------------------------------------------
# Cooper-Harvey-Kennedy (CHK) iterative dominator algorithm.
#
# Postdominators of the original CFG = dominators of the *reverse* CFG.
# We add a single virtual exit node that all declared exit nodes (and any
# no-successor node) point to, giving the reverse CFG a unique start node.
# ---------------------------------------------------------------------------


def _dfs_postorder(
    start: int,
    successors: dict[int, list[int]],
) -> list[int]:
    """Return nodes in DFS postorder from ``start`` using ``successors``."""
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
        for succ in successors.get(node, []):
            if succ not in visited:
                stack.append((succ, False))
    return postorder


def compute_postdom_tree(
    successors: Mapping[int, Sequence[int]],
    entry: int,
    exits: frozenset[int],
) -> PostdomTree:
    """Compute postdominator tree using the Cooper-Harvey-Kennedy algorithm.

    The postdominator tree of a CFG is computed by running the standard
    iterative dominator algorithm on the *reverse* CFG, with a virtual exit
    node that collects all exit nodes.

    Args:
        successors: node -> list of successor nodes in the original CFG.
        entry: entry node of the CFG (unused by the algorithm itself but
               kept for API clarity and future use).
        exits: set of exit/return nodes (nodes whose only successor in the
               extended CFG is the virtual exit).

    Returns:
        PostdomTree with immediate postdominator for each reachable node.
        Exit nodes map to None (no postdominator above them in real graph).
    """
    # Collect all real nodes.
    all_real: set[int] = set(successors.keys())
    for succs in successors.values():
        all_real.update(succs)

    # Build the REVERSE CFG:
    #   - Original edge u -> v  becomes  v -> u in the reverse graph.
    #   - All exit nodes get an edge to _VIRTUAL_EXIT (in the original sense),
    #     which in the reverse graph means _VIRTUAL_EXIT -> exit_node.
    #   - The virtual exit is the *start* of the reverse graph.
    #
    # We need two structures:
    #   rev_succs[v]  = successors of v in the reverse graph
    #                 = predecessors of v in the original graph
    #   rev_preds[v]  = predecessors of v in the reverse graph
    #                 = successors of v in the original graph
    #
    # The CHK loop queries rev_preds (to find predecessors in the graph we're
    # computing dominators on, i.e., the reverse CFG).
    # RPO DFS traversal uses rev_succs (to walk the reverse graph forward).

    rev_succs: dict[int, list[int]] = {_VIRTUAL_EXIT: list(exits)}
    rev_preds: dict[int, list[int]] = {_VIRTUAL_EXIT: []}

    for node in all_real:
        rev_succs.setdefault(node, [])
        rev_preds.setdefault(node, [])

    # exits -> _VIRTUAL_EXIT in original extended CFG
    # => _VIRTUAL_EXIT -> exit in reverse (already in rev_succs[_VIRTUAL_EXIT])
    # => exit is a predecessor of _VIRTUAL_EXIT ... wait, we want:
    #    rev_preds[_VIRTUAL_EXIT] = original successors of _VIRTUAL_EXIT = [] (virtual node)
    #    rev_preds[exit]          = original successors of exit node in extended = {_VIRTUAL_EXIT}
    for ex in exits:
        rev_preds[ex].append(_VIRTUAL_EXIT)

    for node, succs in successors.items():
        for succ in succs:
            # Original edge node -> succ
            # Reverse edge: succ -> node
            rev_succs.setdefault(succ, []).append(node)  # succ's rev successor = node
            rev_preds.setdefault(node, []).append(succ)  # node's rev predecessor = succ

        if not succs and node not in exits:
            # Implicit exit: treat as also connected to _VIRTUAL_EXIT.
            rev_succs[_VIRTUAL_EXIT].append(node)
            rev_preds.setdefault(node, []).append(_VIRTUAL_EXIT)

    # DFS postorder on reverse graph starting from _VIRTUAL_EXIT, then reverse = RPO.
    postorder = _dfs_postorder(_VIRTUAL_EXIT, rev_succs)
    rpo: list[int] = list(reversed(postorder))
    rpo_number: dict[int, int] = {node: i for i, node in enumerate(rpo)}

    # CHK iterative dominator computation on the reverse CFG.
    # idom[v] = immediate dominator of v in the reverse CFG
    #         = immediate postdominator of v in the original CFG.
    idom: dict[int, int] = {_VIRTUAL_EXIT: _VIRTUAL_EXIT}

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
            if node == _VIRTUAL_EXIT:
                continue
            # Predecessors of node in the reverse CFG (= original successors + virtual edges).
            processed = [p for p in rev_preds.get(node, []) if p in idom]
            if not processed:
                continue
            new_idom = processed[0]
            for pred in processed[1:]:
                new_idom = intersect(pred, new_idom)
            if idom.get(node) != new_idom:
                idom[node] = new_idom
                changed = True

    # Build public mapping: strip _VIRTUAL_EXIT sentinel.
    # Nodes whose idom is _VIRTUAL_EXIT have no real postdominator (exit nodes).
    public_idom: dict[int, int | None] = {}
    for node, dom in idom.items():
        if node == _VIRTUAL_EXIT:
            continue
        public_idom[node] = None if dom == _VIRTUAL_EXIT else dom

    logger.debug(
        "compute_postdom_tree: %d real nodes, %d exits, idom size=%d",
        len(all_real),
        len(exits),
        len(public_idom),
    )
    return PostdomTree(idom=public_idom)


def is_postdominated_by_any_exit(
    node: int,
    exits: frozenset[int],
    tree: PostdomTree,
) -> bool:
    """Check if ``node`` is postdominated by at least one exit node.

    Args:
        node: The node to test.
        exits: Set of exit nodes.
        tree: Precomputed PostdomTree.

    Returns:
        True if any exit node postdominates ``node``.
    """
    return any(tree.postdominates(ex, node) for ex in exits)
