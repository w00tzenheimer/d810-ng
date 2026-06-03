"""Project a :class:`LinearizedStateDag` into a block-granularity CFG.

The goto-free structurer (:mod:`d810.analyses.control_flow.structurer`) consumes
a flow-graph of basic blocks (``.blocks`` / ``.entry_serial`` / ``.get_block`` +
``.successors`` / ``.predecessors``). Feeding it the raw lifted ``mba`` -- or even
the §1a *projected* FlowGraph -- structures the **dispatcher**: those graphs keep
the BST comparison blocks (``if (var_64 <=u 0xNNNN)``) as nodes; the §1a spine
only redirects edges, and the BST blocks die later via the full plan + IDA's DCE.

The recovered :class:`LinearizedStateDag` is the genuinely clean graph: handler
state nodes + typed semantic transitions, with no ``var_64`` BST nodes. This
adapter projects it back down to a **block** CFG so the structurer (and the
verified block-keyed reaching-defs/liveness in
:mod:`d810.backends.hexrays.evidence.stack_value_flow_live`) operate on real
handler block serials:

* **Nodes** = the union of every state node's ``owned_blocks`` (handler bodies);
  no dispatcher / BST blocks are pulled in.
* **Intra-handler edges** = the base CFG's successors *restricted to the same
  state node's owned set* -- the genuine local control flow inside a handler.
  Edges that leave the owned set are dispatcher round-trips and are dropped.
* **Inter-handler edges** = the DAG's semantic transitions: a
  :class:`StateDagEdge`'s ``source_anchor.block_serial`` -> the target state
  node's entry block. This is the dispatcher *replacement*.
* **Terminals** = blocks with no outgoing edge after rewiring (``EXIT_ROUTINE`` /
  ``CONDITIONAL_RETURN`` arms, or owned blocks whose only base successors leave
  the handler without a recovered transition). The structurer emits a ``return``
  for them; the carrier-delivery verdict decides the value.

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

__all__ = ["StateDagCfgBlock", "StateDagCfg", "build_state_dag_cfg"]


# Edge kinds (by name, to avoid importing the enum) that carry control forward to
# a target state node. Everything else (EXIT_ROUTINE / CONDITIONAL_RETURN /
# UNKNOWN) is a terminal arm -- no forward block edge is added.
_FORWARD_EDGE_KINDS = frozenset({"TRANSITION", "CONDITIONAL_TRANSITION"})


@dataclass(frozen=True, slots=True)
class StateDagCfgBlock:
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
class StateDagCfg:
    """A block-granularity CFG projected from a :class:`LinearizedStateDag`.

    Satisfies the structurer's flow-graph protocol: ``.blocks`` (serial-keyed
    dict), ``.entry_serial``, ``.get_block``, ``.successors``, ``.predecessors``.
    """

    blocks: dict[int, StateDagCfgBlock]
    entry_serial: int

    def get_block(self, serial: object) -> Optional[StateDagCfgBlock]:
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


def build_state_dag_cfg(
    dag: "LinearizedStateDag",
    *,
    base_successors: Mapping[int, Iterable[int]],
    entry_serial: Optional[int] = None,
) -> StateDagCfg:
    """Project ``dag`` into a block CFG the structurer can structure.

    Args:
        dag: The recovered :class:`LinearizedStateDag` (handler nodes + edges).
        base_successors: The base CFG's successor map (serial -> successors),
            used for intra-handler control flow. Edges leaving a handler's
            owned set are dropped (they are dispatcher round-trips).
        entry_serial: Override the function entry block. Defaults to the
            initial-state handler's entry anchor (falling back to the
            dispatcher entry serial, then the first node's entry anchor).

    Returns:
        A :class:`StateDagCfg` of handler blocks with dispatcher-free edges.
    """
    nodes = tuple(getattr(dag, "nodes", ()) or ())

    # 1. Index handler blocks and per-block owning node. First writer wins on
    #    overlap (a shared suffix block is attributed to the first owner; its
    #    extra predecessors arrive as inter-handler edges).
    owned_of: dict[int, frozenset[int]] = {}
    owner_node: dict[int, object] = {}
    entry_by_key: dict[object, int] = {}
    entry_by_state: dict[int, int] = {}
    block_set: set[int] = set()
    for node in nodes:
        entry_anchor = int(getattr(node, "entry_anchor"))
        owned = frozenset(int(b) for b in getattr(node, "owned_blocks", ()) or ())
        owned = owned | {entry_anchor}
        owned_of[entry_anchor] = owned
        for b in owned:
            block_set.add(b)
            owner_node.setdefault(b, node)
        key = getattr(node, "key", None)
        if key is not None:
            entry_by_key.setdefault(key, entry_anchor)
            state_const = getattr(key, "state_const", None)
            if state_const is not None:
                entry_by_state.setdefault(int(state_const) & 0xFFFFFFFF, entry_anchor)

    succ: dict[int, list[int]] = {b: [] for b in block_set}

    def _add_edge(src: int, dst: int) -> None:
        if dst not in block_set:
            return
        bucket = succ.setdefault(src, [])
        if dst not in bucket:
            bucket.append(dst)

    # 2. Intra-handler edges: base successors restricted to the same owned set.
    for node in nodes:
        entry_anchor = int(getattr(node, "entry_anchor"))
        owned = owned_of.get(entry_anchor, frozenset())
        for b in owned:
            for s in base_successors.get(b, ()) or ():
                s = int(s)
                if s in owned:
                    _add_edge(b, s)

    # 3. Inter-handler edges: the DAG's semantic transitions (dispatcher
    #    replacement). Only forward kinds add a block edge; EXIT_ROUTINE /
    #    CONDITIONAL_RETURN / UNKNOWN arms stay terminal.
    for edge in getattr(dag, "edges", ()) or ():
        kind_name = getattr(getattr(edge, "kind", None), "name", "")
        if kind_name not in _FORWARD_EDGE_KINDS:
            continue
        anchor = getattr(edge, "source_anchor", None)
        src_block = getattr(anchor, "block_serial", None) if anchor is not None else None
        if src_block is None or int(src_block) not in block_set:
            continue
        target_entry = _resolve_target_entry(
            edge, entry_by_key=entry_by_key, entry_by_state=entry_by_state
        )
        if target_entry is None:
            continue
        _add_edge(int(src_block), int(target_entry))

    # 4. Resolve the function entry.
    if entry_serial is None:
        entry_serial = _default_entry(dag, entry_by_state)
    entry_serial = int(entry_serial)
    if entry_serial not in block_set and block_set:
        # Defensive: keep a valid entry even if the initial-state anchor was
        # not materialized as an owned block.
        entry_serial = min(block_set)

    # 5. Materialize blocks with predecessor lists.
    preds: dict[int, list[int]] = {b: [] for b in block_set}
    for src, dsts in succ.items():
        for dst in dsts:
            preds.setdefault(dst, []).append(src)

    blocks = {
        b: StateDagCfgBlock(
            serial=b,
            succs=tuple(succ.get(b, ())),
            preds=tuple(preds.get(b, ())),
        )
        for b in sorted(block_set)
    }
    return StateDagCfg(blocks=blocks, entry_serial=entry_serial)


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
