"""Project a :class:`LinearizedStateDag` into a block-granularity CFG.

The goto-free structurer (:mod:`d810.analyses.control_flow.structurer`) consumes
a flow-graph of basic blocks (``.blocks`` / ``.entry_serial`` / ``.get_block`` +
``.successors`` / ``.predecessors``). Feeding it the raw lifted ``mba`` -- or even
the unflatten *projected* FlowGraph -- structures the **dispatcher**: those graphs keep
the BST comparison blocks (``if (var_64 <=u 0xNNNN)``) as nodes; the unflatten spine
only redirects edges, and the BST blocks die later via the full plan + IDA's DCE.

The recovered :class:`LinearizedStateDag` is the genuinely clean graph: handler
state nodes + typed semantic transitions, with no ``var_64`` BST nodes. This
adapter projects it back down to a **block** CFG so the structurer (and the
verified block-keyed reaching-defs/liveness in
:mod:`d810.backends.hexrays.evidence.stack_value_flow_live`) operate on real
handler block serials:

* **Nodes** = the union of every state node's ``owned_blocks`` plus every block
  named in a wired edge's ``ordered_path`` (handler bodies + the return
  corridor); no dispatcher / BST blocks are pulled in.
* **Edges** = primarily each semantic transition's ``ordered_path``: in the
  *flattened* base CFG, handler blocks do not directly succeed one another (they
  round-trip through the dispatcher), so the DAG's traced ``ordered_path`` is the
  authoritative intra+inter wiring. Consecutive path blocks are chained, and the
  path's last block (or ``source_anchor.block_serial`` when the path is empty)
  connects to the target handler's entry. ``base_successors`` restricted to a
  node's owned set is added as a supplement (covers owned body blocks not named
  in any path).
* **Self-loop transitions** (``source_state == target_state``) are dropped: they
  are the recovery's unresolved/​spin artifacts and would otherwise terminate the
  forward chain as a ``while (1)``.
* **Terminals** = ``EXIT_ROUTINE`` corridor tails and blocks left with no
  outgoing edge. The structurer emits a ``return`` for them; the carrier-delivery
  verdict decides the value.

Portable: no IDA import. ``base_successors`` is supplied by the caller (the live
wrapper passes the lifted FlowGraph's successor map; unit tests pass a literal).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Iterable, Mapping, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from d810.analyses.control_flow.linearized_state_dag import (
        LinearizedStateDag,
        StateDagEdge,
    )

__all__ = [
    "StateTransitionGraphBlock",
    "StateTransitionGraph",
    "build_state_transition_graph",
    "augment_state_transition_graph",
    "prune_infeasible_sibling_arms",
]


# Edge kinds (by name, to avoid importing the enum) that carry control forward to
# a target state node. Everything else (EXIT_ROUTINE / CONDITIONAL_RETURN /
# UNKNOWN) is a terminal arm -- no forward block edge is added.
_FORWARD_EDGE_KINDS = frozenset({"TRANSITION", "CONDITIONAL_TRANSITION"})


@dataclass(frozen=True, slots=True)
class StateTransitionGraphBlock:
    """One basic block in the projected handler CFG."""

    serial: int
    succs: tuple[int, ...]
    preds: tuple[int, ...]

    @property
    def nsucc(self) -> int:
        return len(self.succs)

    @property
    def npred(self) -> int:
        return len(self.preds)


@dataclass(frozen=True, slots=True)
class StateTransitionGraph:
    """A block-granularity CFG projected from a :class:`LinearizedStateDag`.

    Satisfies the structurer's flow-graph protocol: ``.blocks`` (serial-keyed
    dict), ``.entry_serial``, ``.get_block``, ``.successors``, ``.predecessors``.

    ``return_terminals`` are the blocks that tail an ``EXIT_ROUTINE`` corridor --
    the genuine function returns (as opposed to dead-end blocks at recovery
    gaps). The structurer emits a ``return`` there.
    """

    blocks: dict[int, StateTransitionGraphBlock]
    entry_serial: int
    return_terminals: frozenset[int] = frozenset()

    def get_block(self, serial: object) -> Optional[StateTransitionGraphBlock]:
        return self.blocks.get(int(serial))

    def successors(self, serial: object) -> tuple[int, ...]:
        block = self.blocks.get(int(serial))
        return block.succs if block is not None else ()

    def predecessors(self, serial: object) -> tuple[int, ...]:
        block = self.blocks.get(int(serial))
        return block.preds if block is not None else ()


def _resolve_target_entry(
    edge: "StateDagEdge",
    *,
    entry_by_key: Mapping[object, int],
    entry_by_state: Mapping[int, int],
) -> Optional[int]:
    """Resolve a semantic edge's target to a concrete handler entry block."""
    target_anchor = getattr(edge, "target_entry_anchor", None)
    if target_anchor is not None:
        return int(target_anchor)
    target_key = getattr(edge, "target_key", None)
    if target_key is not None and target_key in entry_by_key:
        return int(entry_by_key[target_key])
    target_state = getattr(edge, "target_state", None)
    if target_state is not None:
        masked = int(target_state) & 0xFFFFFFFF
        if masked in entry_by_state:
            return int(entry_by_state[masked])
    return None


def _edge_path(edge: object) -> tuple[int, ...]:
    return tuple(int(b) for b in getattr(edge, "ordered_path", ()) or ())


def _source_state(edge: object) -> Optional[int]:
    key = getattr(edge, "source_key", None)
    state = getattr(key, "state_const", None) if key is not None else None
    return int(state) & 0xFFFFFFFF if state is not None else None


def build_state_transition_graph(
    dag: "LinearizedStateDag",
    *,
    base_successors: Optional[Mapping[int, Iterable[int]]] = None,
    entry_serial: Optional[int] = None,
    materialize_blocks: Iterable[int] = (),
) -> StateTransitionGraph:
    """Project ``dag`` into a block CFG the structurer can structure.

    Args:
        dag: The recovered :class:`LinearizedStateDag` (handler nodes + edges).
        base_successors: Optional base CFG successor map (serial -> successors).
            Restricted to each handler's owned set and added as a supplement to
            the primary ``ordered_path`` wiring (covers owned body blocks not
            named in any path). In a flattened CFG this is usually near-empty.
        entry_serial: Override the function entry block. Defaults to the
            initial-state handler's entry anchor (falling back to the
            dispatcher entry serial, then the first node's entry anchor).
        materialize_blocks: Extra physical-CFG blocks to project as nodes even
            though they are not equality-leaf handlers -- dispatcher/BST-region
            blocks that write the state var and are resolved-edge endpoints (e.g.
            the ``!= 0x7D9C16EC`` BST else-leaf ``blk57``, reached by range-
            narrowing rather than an exact-equality leaf). The mba-aware caller
            decides this set via the state-var-write criterion; here they are
            simply added as nodes so :func:`augment_state_transition_graph` can attach
            their resolved edges (``35 -> 57 -> 186``). Without this, a resolved
            edge whose endpoint lives in the dispatcher region would be dropped,
            orphaning the block it re-dispatches to.

    Returns:
        A :class:`StateTransitionGraph` of handler blocks with dispatcher-free edges.
    """
    base_successors = base_successors or {}
    nodes = tuple(getattr(dag, "nodes", ()) or ())

    # 1. Index handler blocks + entry-resolution maps.
    owned_of: dict[int, frozenset[int]] = {}
    entry_by_key: dict[object, int] = {}
    entry_by_state: dict[int, int] = {}
    block_set: set[int] = set()
    for node in nodes:
        entry_anchor = int(getattr(node, "entry_anchor"))
        owned = frozenset(int(b) for b in getattr(node, "owned_blocks", ()) or ())
        owned = owned | {entry_anchor}
        owned_of[entry_anchor] = owned
        block_set.update(owned)
        key = getattr(node, "key", None)
        if key is not None:
            entry_by_key.setdefault(key, entry_anchor)
            state_const = getattr(key, "state_const", None)
            if state_const is not None:
                entry_by_state.setdefault(int(state_const) & 0xFFFFFFFF, entry_anchor)

    succ: dict[int, list[int]] = {}
    return_terminals: set[int] = set()

    def _add_edge(src: int, dst: int) -> None:
        if src == dst:
            # Block-level self-edge: a dispatcher-spin / unresolved artifact (the
            # state-level self-loop guard misses these when target_state is None
            # but the resolved target entry equals the source). Never a genuine
            # successor in the recovered handler CFG -> drop, else the structurer
            # emits a spurious do/while around a straight-line handler.
            block_set.add(src)
            return
        block_set.add(src)
        block_set.add(dst)
        bucket = succ.setdefault(src, [])
        if dst not in bucket:
            bucket.append(dst)

    # 2. Primary wiring: each semantic transition's ordered_path. Consecutive
    #    path blocks are chained; the path tail (or source anchor when empty)
    #    connects to the target handler entry. Self-loop transitions are dropped.
    for edge in getattr(dag, "edges", ()) or ():
        kind_name = getattr(getattr(edge, "kind", None), "name", "")
        path = _edge_path(edge)
        for a, b in zip(path, path[1:]):
            _add_edge(a, b)
        if kind_name == "EXIT_ROUTINE":
            # The corridor is wired by the path; the tail is the function return
            # (terminal). No edge to a target -> the structurer emits a return.
            anchor = getattr(edge, "source_anchor", None)
            anchor_block = getattr(anchor, "block_serial", None) if anchor else None
            tail = path[-1] if path else anchor_block
            if tail is not None:
                block_set.add(int(tail))
                return_terminals.add(int(tail))
            continue
        if kind_name not in _FORWARD_EDGE_KINDS:
            continue  # UNKNOWN / CONDITIONAL_RETURN: no forward block edge.
        src_state = _source_state(edge)
        tgt_state = getattr(edge, "target_state", None)
        if (
            src_state is not None
            and tgt_state is not None
            and src_state == (int(tgt_state) & 0xFFFFFFFF)
        ):
            continue  # degenerate self-loop (unresolved/spin) -> skip.
        target_entry = _resolve_target_entry(
            edge, entry_by_key=entry_by_key, entry_by_state=entry_by_state
        )
        if target_entry is None:
            continue
        anchor = getattr(edge, "source_anchor", None)
        anchor_block = getattr(anchor, "block_serial", None) if anchor else None
        exit_block = path[-1] if path else anchor_block
        if exit_block is None:
            continue
        _add_edge(int(exit_block), int(target_entry))

    # 3. Supplement: base successors restricted to a handler's owned set.
    for entry_anchor, owned in owned_of.items():
        for b in owned:
            for s in base_successors.get(b, ()) or ():
                if int(s) in owned:
                    _add_edge(b, int(s))

    # 3b. Materialise mba-decided routed state-write blocks (dispatcher-region
    #     blocks that write the state var; absent from the equality-leaf handler
    #     projection above). They enter as bare nodes here; their resolved edges
    #     attach in augment_state_transition_graph. No resolved edge is dropped merely
    #     because one endpoint lives behind a BST comparison.
    for b in materialize_blocks:
        block_set.add(int(b))

    # 4. Resolve the function entry.
    if entry_serial is None:
        entry_serial = _default_entry(dag, entry_by_state)
    entry_serial = int(entry_serial)
    if entry_serial not in block_set and block_set:
        entry_serial = min(block_set)

    # 5. Materialize blocks with predecessor lists.
    preds: dict[int, list[int]] = {b: [] for b in block_set}
    for src, dsts in succ.items():
        for dst in dsts:
            preds.setdefault(dst, []).append(src)

    blocks = {
        b: StateTransitionGraphBlock(
            serial=b,
            succs=tuple(succ.get(b, ())),
            preds=tuple(preds.get(b, ())),
        )
        for b in sorted(block_set)
    }
    # Only blocks that actually end up terminal (no successor) count as returns;
    # an EXIT_ROUTINE tail that also has a forward edge is a pass-through.
    real_terminals = frozenset(
        b for b in return_terminals if not blocks[b].succs
    )
    return StateTransitionGraph(
        blocks=blocks, entry_serial=entry_serial, return_terminals=real_terminals
    )


def augment_state_transition_graph(
    cfg: StateTransitionGraph,
    edges: Iterable[tuple[int, int]],
) -> tuple[StateTransitionGraph, tuple[tuple[int, int], ...]]:
    """Re-attach extra ``src -> dst`` block edges to an existing block CFG.

    The dag-level ``explore()`` injection
    (:func:`d810.backends.hexrays.evidence.microcode_dump._inject_explore_resolved_edges`)
    can only attach edges whose endpoints are :class:`LinearizedStateDag`
    *handler* nodes (the ~78-node ``node_by_handler`` view). Adapter-only blocks
    -- range-backed / producer blocks such as ``152`` / ``195`` pulled into the
    projected CFG by :func:`build_state_transition_graph` -- are not handler nodes, so
    their enumerated transitions (e.g. ``152 -> 48``) are dropped on injection
    even though both blocks exist here, in the projected 136-node CFG.

    This helper closes that gap: it adds each ``(src, dst)`` edge whose **both**
    endpoints already exist as blocks in ``cfg`` (an edge to an absent block has
    nowhere to attach) and whose ``src != dst`` (a block-level self-edge is a
    dispatcher-spin artifact the structurer would turn into a spurious
    ``do/while``). Predecessor lists and ``return_terminals`` are recomputed so
    a former terminal that gains a successor is no longer reported as a return.

    Pure / IDA-free (operates on the portable :class:`StateTransitionGraph`); the live
    structurer supplies the resolved edge pairs.

    Args:
        cfg: The projected block CFG to augment.
        edges: ``(src_serial, dst_serial)`` pairs to attach.

    Returns:
        ``(augmented_cfg, added_pairs)`` -- ``cfg`` unchanged (same object) and
        an empty tuple when nothing was attachable; otherwise a fresh
        :class:`StateTransitionGraph` and the edges actually added (for EA-carrying
        diagnostics: every serialized block number carries its EA at the call
        site).
    """
    succ: dict[int, list[int]] = {
        serial: list(block.succs) for serial, block in cfg.blocks.items()
    }
    added: list[tuple[int, int]] = []
    for src, dst in edges:
        src = int(src)
        dst = int(dst)
        if src == dst:
            continue
        if src not in cfg.blocks or dst not in cfg.blocks:
            continue
        bucket = succ[src]
        if dst in bucket:
            continue
        bucket.append(dst)
        added.append((src, dst))

    if not added:
        return cfg, ()

    preds: dict[int, list[int]] = {serial: [] for serial in cfg.blocks}
    for src, dsts in succ.items():
        for dst in dsts:
            preds[dst].append(src)

    blocks = {
        serial: StateTransitionGraphBlock(
            serial=serial,
            succs=tuple(succ[serial]),
            preds=tuple(preds[serial]),
        )
        for serial in cfg.blocks
    }
    return_terminals = frozenset(
        b for b in cfg.return_terminals if not blocks[b].succs
    )
    return (
        StateTransitionGraph(
            blocks=blocks,
            entry_serial=cfg.entry_serial,
            return_terminals=return_terminals,
        ),
        tuple(added),
    )


def prune_infeasible_sibling_arms(
    cfg: StateTransitionGraph,
    *,
    route_targets: Mapping[int, "Iterable[int]"],
    sibling_arms: Mapping[int, "Iterable[int]"],
) -> tuple[StateTransitionGraph, tuple[tuple[int, int], ...]]:
    """Drop ``src -> dst`` where *dst* is the infeasible BST sibling of *src*'s route.

    A block ``src`` that dispatches a concrete state routes, through the BST, to a
    single feasible target; the recovery can also wire it to that comparison's
    OTHER arm (e.g. ``blk35`` sets ``0x7FDCE054`` and routes past ``!= 0x7D9C16EC``
    to ``57``, yet is also wired to ``56``, the ``== 0x7D9C16EC`` sibling arm).
    Given the decision-DAG route oracle, drop exactly those infeasible sibling
    edges -- NARROW by construction: only a block in ``sibling_arms[T]`` (the
    proven other arm of a comparison reaching ``T``) for a routed target ``T`` of
    ``src``, and never a sibling that is itself one of ``src``'s routed targets
    (a genuine fan-out). Unrelated ordered-path successors are not siblings, so
    they are untouched (this is why the broad route-set prune over-pruned).

    *route_targets* maps ``src`` -> its resolved dispatch targets (``explore()``);
    *sibling_arms* maps a block -> the other arm(s) of comparisons reaching it
    (:meth:`DecisionDag.sibling_arms`). Pure / IDA-free.
    """
    succ: dict[int, list[int]] = {
        serial: list(block.succs) for serial, block in cfg.blocks.items()
    }
    pruned: list[tuple[int, int]] = []
    for raw_src, targets in route_targets.items():
        src = int(raw_src)
        if src not in succ:
            continue
        target_set = {int(t) for t in targets}
        infeasible: set[int] = set()
        for t in target_set:
            infeasible |= {int(s) for s in sibling_arms.get(t, ())}
        infeasible -= target_set  # a sibling that is ALSO a real target stays
        if not infeasible:
            continue
        kept: list[int] = []
        for dst in succ[src]:
            if dst in infeasible and dst != src:
                pruned.append((src, dst))
            else:
                kept.append(dst)
        succ[src] = kept

    if not pruned:
        return cfg, ()

    preds: dict[int, list[int]] = {serial: [] for serial in cfg.blocks}
    for src, dsts in succ.items():
        for dst in dsts:
            if dst in preds:
                preds[dst].append(src)
    blocks = {
        serial: StateTransitionGraphBlock(
            serial=serial,
            succs=tuple(succ[serial]),
            preds=tuple(preds[serial]),
        )
        for serial in cfg.blocks
    }
    return (
        StateTransitionGraph(
            blocks=blocks,
            entry_serial=cfg.entry_serial,
            return_terminals=cfg.return_terminals,
        ),
        tuple(pruned),
    )


def _default_entry(
    dag: "LinearizedStateDag", entry_by_state: Mapping[int, int]
) -> int:
    initial_state = getattr(dag, "initial_state", None)
    if initial_state is not None:
        masked = int(initial_state) & 0xFFFFFFFF
        if masked in entry_by_state:
            return int(entry_by_state[masked])
    dispatcher_entry = getattr(dag, "dispatcher_entry_serial", None)
    if dispatcher_entry is not None:
        return int(dispatcher_entry)
    nodes = tuple(getattr(dag, "nodes", ()) or ())
    if nodes:
        return int(getattr(nodes[0], "entry_anchor"))
    return 0
