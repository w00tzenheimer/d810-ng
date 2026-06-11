"""Sound static-initializer folding for data-dependent global reads.

A flattening handler can compute its next dispatcher state from a *global*
variable that the loader zero-initialises (``.data`` / ``.bss``) and the
function later mutates -- e.g. Approov's ``approov_vm_dispatcher`` does
``qword |= 0xF6A20`` in the entry-state handler, where ``qword`` is a writable
``.data`` global statically equal to ``0``.  Reading that global as its static
initializer (``0``) resolves the next state to ``0xF6A20``; without it the
transition is data-dependent and the handler degenerates to ``while(1)``.

Folding a *writable* global to its initializer is only sound when **no store to
that global reaches the read on any path from function entry**.  That is a
classic reaching-definitions query (LLVM ``ReachingDefinitions`` / angr RDA):

  * the lattice location is the global address (``gaddr``),
  * a *def-site* is an instruction whose destination operand writes that gaddr,
  * a read folds to the initializer iff ``reaching_defs_of(state_at_read,
    gaddr)`` is empty -- the initializer is the only value that can be live.

This is strictly narrower than "fold every never-reaching-store global": it is
evaluated *per read site*.  The same global can fold at one read (the entry
handler, before any store) and be rejected at a later read (after a store
reaches it).  It is therefore sound where the blanket
``fold_writable_constants`` (memory: unsound in general, ``sub_7FFD``
indirect-write class) is not -- it never folds a read a store can reach.

Backend-neutral: consumes a :class:`d810.ir.flowgraph.FlowGraph` snapshot and a
``fetch_initializer(addr, size)`` callable (the only live-IDB touch).  No IDA
imports here.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import Callable, Mapping, Optional

from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.value_flow.reaching_defs import (
    BlockReachingFacts,
    ReachingDefsDomain,
    reaching_defs_of,
)
from d810.analyses.data_flow.worklist import run_fixpoint

logger = getLogger(__name__)

__all__ = [
    "FoldableGlobalReads",
    "compute_initializer_stable_global_reads",
]


# read_ea -> { gaddr -> initializer_value }.  Presence of ``(read_ea, gaddr)``
# certifies "no store to ``gaddr`` reaches the read at ``read_ea``"; the value
# is the static initializer the read may be folded to.
FoldableGlobalReads = Mapping[int, Mapping[int, int]]


def _operand_gaddr(mop: object) -> Optional[int]:
    """Return the global address an operand names, or ``None``."""
    if mop is None:
        return None
    g = getattr(mop, "gaddr", None)
    if g is None:
        g = getattr(mop, "g", None)
    try:
        return int(g) if g else None
    except (TypeError, ValueError):
        return None


def _iter_source_gaddrs(insn: object):
    """Yield ``(gaddr, size)`` for every *source* operand global read by *insn*.

    Sources are the ``l`` / ``r`` operands plus their nested sub-operands
    (``mop_d`` trees carried in ``sub_l`` / ``sub_r``).  The destination
    operand is excluded -- a store to a global is a def, not a read.
    """

    def _walk(mop: object):
        if mop is None:
            return
        g = _operand_gaddr(mop)
        if g is not None:
            size = 0
            try:
                size = int(getattr(mop, "size", 0) or 0)
            except (TypeError, ValueError):
                size = 0
            yield g, size
        # mop_d nested expression operands (e.g. ``(qword | 0xF6A20)``).
        yield from _walk(getattr(mop, "sub_l", None))
        yield from _walk(getattr(mop, "sub_r", None))

    for slot in ("l", "r"):
        yield from _walk(getattr(insn, slot, None))


def _store_gaddr(insn: object) -> Optional[int]:
    """Return the global address *insn* stores to via its destination, or ``None``.

    Conservatively, any instruction whose destination operand (or a nested dest
    sub-operand) names a global is treated as a store/def of that global.  Used
    only to *kill* a fold, so over-detecting stores keeps the analysis sound.
    """
    dest = getattr(insn, "d", None)
    if dest is None:
        return None
    g = _operand_gaddr(dest)
    if g is not None:
        return g
    # A nested address-bearing destination (rare) -- treat its global as a def.
    for slot in ("sub_l", "sub_r"):
        g = _operand_gaddr(getattr(dest, slot, None))
        if g is not None:
            return g
    return None


@dataclass(frozen=True, slots=True)
class _BlockGlobalFacts:
    """Per-block ordered global stores/reads, captured once for reuse."""

    # gaddr -> True (the block defines this global at least once).  Keys form
    # the kill/gen set for the block-level reaching-defs lattice.
    defs: frozenset
    # (insn_index, read_ea, gaddr, size) in program order.
    reads: tuple
    # (insn_index, gaddr) store sites in program order.
    stores: tuple


def _collect_block_facts(block: object) -> _BlockGlobalFacts:
    defs: set[int] = set()
    reads: list[tuple[int, int, int, int]] = []
    stores: list[tuple[int, int]] = []
    for idx, insn in enumerate(getattr(block, "insn_snapshots", ()) or ()):
        ea = int(getattr(insn, "ea", 0) or 0)
        for gaddr, size in _iter_source_gaddrs(insn):
            reads.append((idx, ea, gaddr, size))
        sg = _store_gaddr(insn)
        if sg is not None:
            stores.append((idx, sg))
            defs.add(sg)
    return _BlockGlobalFacts(
        defs=frozenset(defs), reads=tuple(reads), stores=tuple(stores)
    )


def _entry_reachable(
    serials, entry, succs_of, barrier_serials
):
    """Blocks reachable from ``entry`` once edges INTO any barrier are cut.

    The dispatcher entry is a *barrier*: a flattening loop routes every handler
    back through it by the (now folded-away) state value, so an edge ``handler ->
    dispatcher`` is a value-routing back-edge, NOT a straight-line data path.
    Cutting edges into the barrier leaves exactly the entry-to-here straight-line
    prefix (function entry -> initial handler -> direct goto-chains).  Reaching
    defs on this cut graph gives the SEMANTIC execution order: a store "reaches"
    a read iff it executes before it on a real straight path, not via an
    infeasible dispatcher self-loop.
    """
    reachable: set[int] = set()
    stack = [int(entry)]
    while stack:
        node = stack.pop()
        if node in reachable:
            continue
        reachable.add(node)
        for succ in succs_of(node):
            if int(succ) in barrier_serials:
                continue  # cut the edge INTO the dispatcher barrier
            stack.append(int(succ))
    return reachable


def compute_initializer_stable_global_reads(
    flow_graph: object,
    fetch_initializer: Callable[[int, int], Optional[int]],
    *,
    barrier_serials: object | None = None,
    entry_override: Optional[int] = None,
) -> FoldableGlobalReads:
    """Map each global read EA to the gaddrs foldable to their static initializer.

    A read of global ``G`` at instruction EA is *initializer-stable* iff no store
    to ``G`` reaches it on any path from the function entry (reaching-defs ==
    empty for ``G`` at that point).  The returned value is the static
    initializer ``fetch_initializer(G, size)`` -- the only value that can be live
    there -- so callers may soundly fold the read to it.

    ``barrier_serials`` (the dispatcher entry block) cuts edges *into* those
    blocks before the reaching-defs run: a flattening handler's edge back to the
    dispatcher is a value-routing back-edge whose feasibility depends on the
    state value, so on the raw CFG it would conservatively make the initial
    handler's read look "store-reachable" via its own infeasible self-loop.
    Cutting it yields the straight-line entry prefix (the real execution order the
    initial handler runs in).  A read in a block UNREACHABLE in the cut graph is
    NOT folded (its store-freeness was never proven from entry).  Omit the
    barrier (``None``) for an ordinary CFG with no dispatcher loop.

    Args:
        flow_graph: A :class:`d810.ir.flowgraph.FlowGraph` snapshot.
        fetch_initializer: ``(addr, size) -> int | None`` reading the static
            ``.data`` / ``.bss`` initializer (the loader-supplied value).  Only
            called for reads already proven store-free, so it never reads a
            value a store could have changed.
        barrier_serials: Block serials whose *incoming* edges are cut (the
            dispatcher entry).  ``None`` keeps the raw CFG.
        entry_override: Reaching-defs anchor block (the INITIAL handler the
            dispatcher routes the entry state to).  When set, reaching-defs and
            cut-graph reachability start here instead of ``flow_graph.entry_serial``
            -- the real first-executed handler in a dispatcher loop.  ``None``
            uses the function entry.

    Returns:
        ``{read_ea: {gaddr: initializer_value}}``.  Empty when nothing folds.
    """
    blocks = getattr(flow_graph, "blocks", None)
    if not blocks:
        return {}

    block_facts: dict[int, _BlockGlobalFacts] = {}
    any_global = False
    for serial, block in blocks.items():
        facts = _collect_block_facts(block)
        block_facts[int(serial)] = facts
        if facts.defs or facts.reads:
            any_global = True
    if not any_global:
        return {}

    barriers: set[int] = {int(b) for b in (barrier_serials or ())}

    def _succs(node):
        blk = blocks.get(node)
        succ = tuple(int(s) for s in getattr(blk, "succs", ())) if blk else ()
        return tuple(s for s in succ if s not in barriers)

    def _preds(node):
        blk = blocks.get(node)
        pred = tuple(int(p) for p in getattr(blk, "preds", ())) if blk else ()
        # Mirror the cut: a barrier has no outgoing edges in the cut graph, so it
        # is no predecessor of anything.
        return tuple(p for p in pred if p not in barriers)

    serials = [int(s) for s in blocks.keys()]
    if entry_override is not None and int(entry_override) in blocks:
        entry = int(entry_override)
    else:
        entry = int(getattr(flow_graph, "entry_serial", serials[0]))

    # With dispatcher-in edges cut, a block reached ONLY through the dispatcher is
    # disconnected -- its store-freeness is unproven, so it must not fold.
    reachable = (
        _entry_reachable(serials, entry, _succs, barriers)
        if (barriers or entry_override is not None)
        else set(serials)
    )

    # Reaching-defs lattice over global locations.  Def-site granularity is the
    # block serial (sufficient: we only ask "does ANY store reach?", not which);
    # intra-block ordering is handled by the per-instruction walk below.
    reaching_facts: dict[int, BlockReachingFacts] = {}
    for serial, facts in block_facts.items():
        if facts.defs:
            reaching_facts[serial] = BlockReachingFacts(
                gen={g: frozenset({serial}) for g in facts.defs}
            )
    domain = ReachingDefsDomain(reaching_facts)

    # Seed the worklist with EVERY block, not just the function entry.  The
    # generic forward solver only enqueues a node's successors when that node's
    # OUT *changes*; a real function entry that defines no global keeps OUT ==
    # bottom forever, so its successors (and thus a store on a back-edge) would
    # never be visited.  For reaching-defs the boundary is ``bottom`` (the empty
    # set) and confluence is union, so adding ``bottom`` to every node's IN is a
    # no-op -- seeding all nodes is sound and guarantees full propagation.
    result = run_fixpoint(
        domain,
        nodes=serials,
        entry_nodes=serials,
        entry_state=domain.bottom(),
        successors_of=_succs,
        predecessors_of=_preds,
        config=FixpointConfiguration(direction=Direction.FORWARD),
    )

    foldable: dict[int, dict[int, int]] = {}
    for serial, facts in block_facts.items():
        if not facts.reads:
            continue
        if serial not in reachable:
            continue  # unreachable in the cut graph -> store-freeness unproven
        in_state = result.in_states.get(serial, domain.bottom())
        # Walk the block in program order, tracking gaddrs stored EARLIER in this
        # same block (an intra-block reaching store the block-level IN cannot
        # see).  A read folds iff no store reaches it from either the block IN
        # state OR an earlier store in this block.
        stored_before: dict[int, int] = {}
        store_iter = iter(facts.stores)
        next_store = next(store_iter, None)
        for read_idx, read_ea, gaddr, size in facts.reads:
            # Advance the intra-block store cursor up to (not including) the read.
            while next_store is not None and next_store[0] < read_idx:
                stored_before[next_store[1]] = stored_before.get(next_store[1], 0) + 1
                next_store = next(store_iter, None)
            if stored_before.get(gaddr):
                continue  # an earlier store in this block reaches the read
            if reaching_defs_of(in_state, gaddr):
                continue  # a store on some predecessor path reaches the read
            init = fetch_initializer(gaddr, size if size in (1, 2, 4, 8) else 8)
            if init is None:
                continue
            foldable.setdefault(int(read_ea), {})[int(gaddr)] = int(init)

    if foldable and logger.debug_on:
        logger.debug(
            "global_init_fold: %d initializer-stable global read site(s): %s",
            len(foldable),
            {hex(ea): {hex(g): hex(v) for g, v in m.items()} for ea, m in foldable.items()},
        )
    return foldable
