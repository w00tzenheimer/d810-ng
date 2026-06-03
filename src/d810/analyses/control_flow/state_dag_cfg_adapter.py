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


def _edge_path(edge: object) -> tuple[int, ...]:
    return tuple(int(b) for b in getattr(edge, "ordered_path", ()) or ())


def _source_state(edge: object) -> Optional[int]:
    key = getattr(edge, "source_key", None)
    state = getattr(key, "state_const", None) if key is not None else None
    return int(state) & 0xFFFFFFFF if state is not None else None


def build_state_dag_cfg(
    dag: "LinearizedStateDag",
    *,
    base_successors: Optional[Mapping[int, Iterable[int]]] = None,
    entry_serial: Optional[int] = None,
) -> StateDagCfg:
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

    Returns:
        A :class:`StateDagCfg` of handler blocks with dispatcher-free edges.
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

    def _add_edge(src: int, dst: int) -> None:
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
