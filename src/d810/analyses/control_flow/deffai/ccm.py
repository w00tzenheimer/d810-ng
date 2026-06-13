"""DEFFAI Context-to-CFG Map (CCM) -- Algorithm 1.

The CCM maps each reachable context to the **partial CFG** that context actually
executes -- the un-flattened, sequential handler body for that case-history
(Baek & Lee, IEEE TSE 52(3) 2026, Algorithm 1).

Algorithm 1 (reflected here):

    for each reachable context ctx in S#:
        blocks(ctx) = { bb : S#[ctx][bb] is reachable (store not bottom) }
                      minus the dispatcher region (the flattening scaffold)
        edges(ctx)  = original CFG edges restricted to blocks(ctx) that are
                      FEASIBLE under ctx -- a 2-way branch keeps only the arm(s)
                      whose predicate the per-context condvar store admits.

The dispatcher's broadcast fan-out is *removed*: the context already selects the
successor handler, so the partial CFG is the real, sequential body.

Portable-core: no IDA imports.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping

from d810.ir.flowgraph import FlowGraph
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.instruction_semantics import branch_predicate
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.analysis import AnalysisResult
from d810.analyses.control_flow.deffai.context import KContext
from d810.analyses.control_flow.deffai.transfer import (
    _arm_targets,
    _compare_const_and_cell,
)

__all__ = ["PartialCFG", "CCM", "build_ccm"]


@dataclass(frozen=True, slots=True)
class PartialCFG:
    """The per-context un-flattened partial CFG: block set + feasible edges."""

    blocks: frozenset[int]
    edges: frozenset[tuple[int, int]]

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)


@dataclass(frozen=True, slots=True)
class CCM:
    """Context-to-CFG Map: ``KContext -> PartialCFG``."""

    per_context: Mapping[KContext, PartialCFG]

    def get(self, ctx: KContext) -> PartialCFG:
        return self.per_context.get(ctx, PartialCFG(frozenset(), frozenset()))


def _arm_feasible(
    graph: FlowGraph,
    result: AnalysisResult,
    ctx: KContext,
    block: int,
    succ: int,
    state_cell: LocationRef,
) -> bool:
    """``True`` iff the edge ``block -> succ`` is feasible under ``ctx``.

    For a 2-way equality branch comparing the state/condvar cell to a const, the
    edge is feasible iff the per-context store admits the value the arm requires:
    the equal arm needs ``const`` in the cell's set; the not-equal arm needs the
    cell to hold something other than (only) ``const``.  Non-equality / non-
    routing edges are always feasible (conservative -- we never drop a real edge).
    """
    blk = graph.blocks.get(int(block))
    if blk is None:
        return False
    tail = blk.tail
    if tail is None or not tail.is_conditional_jump or len(blk.succs) != 2:
        return True
    pred = branch_predicate(tail)
    if pred not in (PredicateKind.EQ, PredicateKind.NE):
        return True
    const, cmp_cell = _compare_const_and_cell(tail)
    if const is None:
        return True
    if cmp_cell is None:
        cmp_cell = state_cell
    store = result.store_at(ctx, int(block))
    sv = store.get(cmp_cell)
    if sv.is_top:
        return True  # unknown -> keep both arms (sound over-approx)
    if sv.is_bottom:
        return False  # the block is unreachable here for this cell
    taken, fallthrough = _arm_targets(blk)
    eq_arm = taken if pred is PredicateKind.EQ else fallthrough
    if int(succ) == eq_arm:
        return const in sv.constants
    # not-equal arm: feasible unless the cell is exactly {const}
    return sv.constants != {const}


def build_ccm(
    result: AnalysisResult,
    graph: FlowGraph,
    *,
    state_cell: LocationRef,
    dispatcher_region: frozenset[int] = frozenset(),
) -> CCM:
    """DEFFAI Algorithm 1: build the per-context partial CFGs.

    For each reachable context, ``blocks(ctx)`` is every block whose per-context
    store is non-``bottom``, minus ``dispatcher_region`` (the flattening
    scaffold).  ``edges(ctx)`` restricts the original CFG edges to those blocks,
    keeping an edge only when it is feasible under ``ctx``
    (:func:`_arm_feasible`).

    ``dispatcher_region`` is the set of dispatcher block serials to exclude; when
    empty, no blocks are excluded (the caller supplies the anchor region in the
    wired engine -- out of P3-core scope, so it defaults empty here).
    """
    per_context: dict[KContext, PartialCFG] = {}
    for ctx in sorted(result.reachable_contexts, key=lambda c: c.cases):
        per_block = result.s_hash.get(ctx, {})
        ctx_blocks = {
            int(bb)
            for bb, store in per_block.items()
            if not store.is_bottom() and int(bb) not in dispatcher_region
        }
        edges: set[tuple[int, int]] = set()
        for bb in ctx_blocks:
            blk = graph.blocks.get(int(bb))
            if blk is None:
                continue
            for succ in blk.succs:
                if int(succ) not in ctx_blocks:
                    continue
                if _arm_feasible(graph, result, ctx, int(bb), int(succ), state_cell):
                    edges.add((int(bb), int(succ)))
        per_context[ctx] = PartialCFG(
            blocks=frozenset(ctx_blocks), edges=frozenset(edges)
        )
    return CCM(per_context=per_context)
