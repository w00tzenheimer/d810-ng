"""DEFFAI preprocessing: condition-variable slicing + prune-block insertion.

DEFFAI preprocesses the CFF graph before the abstract interpretation (Baek & Lee,
IEEE TSE 52(3) 2026, §5 preprocessing):

* **Program slicing on the condition variables** -- keep only the blocks/insns
  that affect dispatcher routing (the state cell + the condvar defs).  This
  shrinks the product-graph the k-context fixpoint walks (cost control).  It is a
  *conservative* slice: when in doubt a block is kept, so slicing only shrinks
  work and never changes soundness.
* **Prune-block insertion** -- give each routed handler entry its own
  single-predecessor block on the dispatcher -> handler edge, so the k-context
  advances exactly once per case and per-case stores never alias.

Both produce a **new frozen** :class:`FlowGraph` (never mutating the input), with
an original<->new serial map stashed in ``metadata`` so the conversion layer can
translate recovered serials back.  ``MBL_KEEP`` / live-``mba`` clone hazards do
**not** apply here -- this operates purely on the portable snapshot; the only
clone risk lives in the emit/patch layer (out of P3 scope).

Portable-core: no IDA imports.
"""
from __future__ import annotations

from dataclasses import replace

from d810.core.typing import Iterable, Mapping

from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    OperandKind,
)
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.transfer import mop_cell

__all__ = [
    "PRUNE_BLOCK_META_KEY",
    "SLICE_META_KEY",
    "condvar_cells_of",
    "slice_on_condvars",
    "insert_prune_blocks",
]

#: ``metadata`` key carrying ``{new_serial: original_serial}`` for prune-inserted
#: blocks (original blocks map to themselves; only synthesized blocks appear).
PRUNE_BLOCK_META_KEY = "deffai_prune_origin"
#: ``metadata`` key recording the slice kept-block set (diagnostic).
SLICE_META_KEY = "deffai_slice_kept"


def condvar_cells_of(
    graph: FlowGraph, *, state_cell: LocationRef | None = None
) -> frozenset[LocationRef]:
    """The condition-variable cells: every cell compared in a 2-way branch tail.

    Reads each block's conditional tail and collects the non-constant operand's
    cell (the variable being tested).  The dispatcher state cell is included when
    given (it is the primary condvar).  These are the cells the k-context fixpoint
    refines on each arm.
    """
    cells: set[LocationRef] = set()
    if state_cell is not None:
        cells.add(state_cell)
    for blk in graph.blocks.values():
        tail = blk.tail
        if tail is None or not tail.is_conditional_jump:
            continue
        for operand in (getattr(tail, "l", None), getattr(tail, "r", None)):
            if operand is None or operand.kind is OperandKind.NUMBER:
                continue
            cell = mop_cell(operand)
            if cell is not None:
                cells.add(cell)
    return frozenset(cells)


def _block_defines_any(blk: BlockSnapshot, cells: frozenset[LocationRef]) -> bool:
    """``True`` iff any instruction in ``blk`` writes one of ``cells``."""
    for insn in blk.insn_snapshots:
        dest_cell = mop_cell(getattr(insn, "d", None))
        if dest_cell is not None and dest_cell in cells:
            return True
    return False


def _is_routing_block(blk: BlockSnapshot, condvars: frozenset[LocationRef]) -> bool:
    """``True`` iff ``blk`` is routing-relevant (kept by the slice).

    A block is kept when it: branches (any conditional / table tail -- it steers
    routing), defines a condvar/state cell, is a control-flow merge (multiple
    preds -- it is a join the context must see), or is a terminal / entry block.
    Conservative: any of these keeps the block; only pure pass-through
    straight-line blocks that touch no condvar are candidates for dropping.
    """
    tail = blk.tail
    if tail is not None and (
        tail.is_conditional_jump or tail.kind is InsnKind.TABLE_JUMP
    ):
        return True
    if blk.kind in (BlockKind.STOP, BlockKind.ZERO_WAY, BlockKind.N_WAY):
        return True
    if blk.npred != 1 or blk.nsucc != 1:
        return True  # merges, forks, terminals, entries
    return _block_defines_any(blk, condvars)


def slice_on_condvars(
    graph: FlowGraph,
    *,
    state_cell: LocationRef | None = None,
    condvar_cells: frozenset[LocationRef] | None = None,
) -> tuple[FlowGraph, frozenset[LocationRef]]:
    """Conservatively slice ``graph`` to routing-relevant blocks; return condvars.

    Returns ``(sliced_graph, condvar_cells)``.  The slice keeps every block that
    is routing-relevant (:func:`_is_routing_block`) **and** every block on a path
    between two kept blocks (so the result stays a connected, edge-consistent
    CFG).  A dropped straight-line block's single predecessor is reconnected to
    its single successor (edge contraction), preserving reachability.

    The slice never drops a condvar def, a branch, or a merge, so it cannot
    change which arms are feasible -- it only removes work (design §5: slicing is
    sound because it only shrinks the tracked set).

    **Idempotent**: re-slicing an already-sliced graph keeps every block (the
    pass-through blocks are gone), so the result is structurally stable.

    When the graph has no removable blocks (every block routing-relevant) the
    *same* block set is returned (a fresh :class:`FlowGraph`, condvars attached).
    """
    condvars = (
        condvar_cells
        if condvar_cells is not None
        else condvar_cells_of(graph, state_cell=state_cell)
    )
    kept = {
        serial
        for serial, blk in graph.blocks.items()
        if _is_routing_block(blk, condvars)
    }
    # Always keep the entry.
    kept.add(int(graph.entry_serial))

    # Contract dropped straight-line blocks: build a "skip" map serial -> the
    # nearest kept successor, following single-successor dropped chains.
    def _resolve_target(serial: int) -> int:
        seen: set[int] = set()
        cur = int(serial)
        while cur not in kept and cur not in seen:
            seen.add(cur)
            blk = graph.blocks.get(cur)
            if blk is None or blk.nsucc != 1:
                break
            cur = int(blk.succs[0])
        return cur

    # Rebuild kept blocks with successors rerouted around dropped chains.
    new_blocks: dict[int, BlockSnapshot] = {}
    for serial in kept:
        blk = graph.blocks.get(int(serial))
        if blk is None:
            continue
        new_succs = tuple(_resolve_target(s) for s in blk.succs)
        new_blocks[int(serial)] = replace(blk, succs=new_succs, preds=())

    # Recompute preds from the rerouted succ relation.
    _recompute_preds(new_blocks)

    metadata = dict(graph.metadata)
    metadata[SLICE_META_KEY] = tuple(sorted(kept))
    sliced = FlowGraph(
        blocks=new_blocks,
        entry_serial=int(graph.entry_serial),
        func_ea=int(graph.func_ea),
        metadata=metadata,
    )
    return sliced, condvars


def _recompute_preds(blocks: dict[int, BlockSnapshot]) -> None:
    """In-place: recompute every block's ``preds`` from the ``succs`` relation."""
    preds: dict[int, list[int]] = {s: [] for s in blocks}
    for serial, blk in blocks.items():
        for succ in blk.succs:
            if succ in preds:
                preds[int(succ)].append(int(serial))
    for serial in list(blocks):
        blocks[serial] = replace(blocks[serial], preds=tuple(sorted(preds[serial])))


def _next_free_serial(blocks: Mapping[int, BlockSnapshot]) -> int:
    """The smallest serial strictly greater than every existing serial."""
    return (max(blocks) + 1) if blocks else 0


def insert_prune_blocks(
    graph: FlowGraph,
    *,
    dispatcher_entry: int,
    handler_entries: Iterable[int],
) -> FlowGraph:
    """Insert a single-pred prune block on each dispatcher -> handler edge.

    For every ``handler`` in ``handler_entries`` that is a direct successor of
    ``dispatcher_entry`` **and** has more than one predecessor (so the edge does
    not already terminate in a clean single-pred block), synthesize an empty
    prune block ``P`` on the ``dispatcher_entry -> handler`` edge:

        dispatcher_entry -> P -> handler

    ``P`` is a fresh ONE_WAY block (no instructions, a synthetic goto) whose only
    predecessor is the dispatcher and only successor is the handler.  This gives
    the k-context a deterministic single point to advance per case and keeps
    per-case stores from aliasing at a shared multi-pred handler entry.

    Produces a new frozen :class:`FlowGraph`; the original->synthesized serial map
    is recorded under :data:`PRUNE_BLOCK_META_KEY`.

    **Idempotent**: a handler that already has a single predecessor (its prune
    block, or a naturally single-pred entry) is left untouched, so re-running is
    a no-op.
    """
    dispatcher_entry = int(dispatcher_entry)
    handlers = {int(h) for h in handler_entries}
    disp = graph.blocks.get(dispatcher_entry)
    if disp is None:
        return _rebuild_same(graph)

    direct_succs = set(disp.succs)
    targets = sorted(
        h
        for h in handlers
        if h in direct_succs and (blk := graph.blocks.get(h)) is not None
        and blk.npred > 1
    )
    if not targets:
        return _rebuild_same(graph)

    new_blocks: dict[int, BlockSnapshot] = {
        s: replace(b, preds=(), succs=b.succs) for s, b in graph.blocks.items()
    }
    next_serial = _next_free_serial(graph.blocks)
    prune_origin: dict[int, int] = {}

    # Rewire the dispatcher's successor list, inserting a prune block per target.
    disp_succs = list(new_blocks[dispatcher_entry].succs)
    for handler in targets:
        prune_serial = next_serial
        next_serial += 1
        prune_origin[prune_serial] = handler
        # Dispatcher now points at the prune block instead of the handler.
        disp_succs = [
            prune_serial if s == handler else s for s in disp_succs
        ]
        # The prune block: empty ONE_WAY -> handler.
        new_blocks[prune_serial] = BlockSnapshot(
            serial=prune_serial,
            block_type=disp.block_type,
            succs=(handler,),
            preds=(dispatcher_entry,),
            flags=0,
            start_ea=disp.start_ea,
            insn_snapshots=(),
            kind=BlockKind.ONE_WAY,
        )
    new_blocks[dispatcher_entry] = replace(
        new_blocks[dispatcher_entry], succs=tuple(disp_succs)
    )

    _recompute_preds(new_blocks)

    metadata = dict(graph.metadata)
    existing = dict(metadata.get(PRUNE_BLOCK_META_KEY, {}))
    existing.update(prune_origin)
    metadata[PRUNE_BLOCK_META_KEY] = existing
    return FlowGraph(
        blocks=new_blocks,
        entry_serial=int(graph.entry_serial),
        func_ea=int(graph.func_ea),
        metadata=metadata,
    )


def _rebuild_same(graph: FlowGraph) -> FlowGraph:
    """A fresh, structurally-identical :class:`FlowGraph` (no-op rewrite).

    Used when there is nothing to insert; returns a new object so callers always
    get a freshly-frozen graph regardless of whether a rewrite occurred.
    """
    return FlowGraph(
        blocks={s: replace(b) for s, b in graph.blocks.items()},
        entry_serial=int(graph.entry_serial),
        func_ea=int(graph.func_ea),
        metadata=dict(graph.metadata),
    )
