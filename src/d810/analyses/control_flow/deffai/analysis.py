"""DEFFAI k-switch context-sensitive fixpoint: ``S# : Ctxt -> BB -> M#``.

Realizes design **(A)** of the P3 plan (the Design-Verification-Gate-recommended
option): a **product graph** whose nodes are ``(block_serial, KContext)`` pairs,
driven by the proven worklist :func:`d810.analyses.data_flow.run_fixpoint`.  The
state ``StateT`` is :class:`PowersetStore`; the :class:`FlowDomain` delegates
``confluence`` / ``widen`` to the store and ``transfer`` to the set-valued block
fold.  Per-arm refinement and context advancement ride the ``edge_refine`` seam
and the product topology respectively:

* **Topology** -- ``(block, ctx)`` has successor ``(succ, ctx')`` for each
  successor ``succ`` of ``block``; ``ctx' = ctx.extend(case, k)`` when the edge is
  a dispatcher routing edge (``block`` is the dispatcher and ``succ`` is a routed
  handler whose case const is known), else ``ctx' = ctx``.
* **Transfer** -- ``transfer((block, ctx), in)`` folds the block set-valued
  (:func:`transfer_block_set`'s no-fork core) to one out-store.
* **edge_refine** -- ``edge_refine((block, ctx), (succ, ctx'), out)`` applies the
  per-arm ``assume`` (``meet_const`` / ``exclude``) for the specific arm leading
  to ``succ`` -- the LiSA per-edge narrowing that prunes infeasible arms.

This maximizes reuse (CORE doctrine: the convergence + widening guarantees come
from the proven solver) and is the textbook call-strings encoding (context as a
node-product).  The node set is bounded by ``|blocks| * |reachable contexts|`` and
the contexts are capped by ``policy.max_contexts``.

.. warning::
   **SOUNDNESS REVIEW PENDING (@verifier).**  The product-graph encoding's
   soundness obligation -- that the per-(block, context) fixpoint over
   ``run_fixpoint`` computes a sound over-approximation of the concrete CFF
   semantics, in particular that (a) splitting the join by k-context only refines
   (never merges two unrelated values into a wrong one) and (b) the ``edge_refine``
   arm ``assume`` composed with the context-routing topology drops no feasible
   transition -- is asserted by the plan (§7) but has **not** been formally
   discharged.  This is the P3 design-gate item flagged for ``@verifier`` before
   wiring.  The unit tests below check the operational properties (fork sets,
   convergence, top-density); they are necessary but not a soundness proof.

Portable-core: no IDA imports.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping, Optional

from d810.ir.flowgraph import FlowGraph
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.instruction_semantics import branch_predicate
from d810.analyses.data_flow import (
    FixpointConfiguration,
    FixpointResult,
    run_fixpoint,
)
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.context import ContextPolicy, KContext
from d810.analyses.control_flow.deffai.powerset_store import PowersetStore
from d810.analyses.control_flow.deffai.transfer import (
    BlockEvaluator,
    _arm_targets,
    _compare_const_and_cell,
    _fold_block_set,
    _refine_arm,
    scalar_block_evaluator,
)

__all__ = ["AnalysisResult", "ProductNode", "analyze_kswitch"]

#: A product-graph node: ``(block_serial, KContext)``.
ProductNode = tuple[int, KContext]


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """The context-sensitive fixpoint result ``S# : Ctxt -> BB -> M#``.

    ``s_hash[ctx][block]`` is the *in*-store at ``block`` under ``ctx``;
    ``out_hash[ctx][block]`` is the *out*-store (the value AFTER the block's
    set-valued fold -- this is where a handler's next-state write lives, so the
    CTG reads next-states from here, not the in-store).  ``reachable_contexts`` is
    every context that appears.  ``top_density`` is the fraction of (context,
    cell) entries that are ``top`` (the escalation signal -- high density =>
    unresolved condvars => raise k).  ``converged`` mirrors the underlying
    fixpoint's convergence.
    """

    s_hash: Mapping[KContext, Mapping[int, PowersetStore]]
    out_hash: Mapping[KContext, Mapping[int, PowersetStore]]
    reachable_contexts: frozenset[KContext]
    top_density: float
    converged: bool
    iterations: int

    def store_at(self, ctx: KContext, block: int) -> PowersetStore:
        """The *in*-store at ``(ctx, block)``, or ``bottom`` when unreached."""
        return self.s_hash.get(ctx, {}).get(int(block), PowersetStore.bottom())

    def out_store_at(self, ctx: KContext, block: int) -> PowersetStore:
        """The *out*-store at ``(ctx, block)``, or ``bottom`` when unreached.

        The post-fold store: a handler block's next-state write is here (the
        in-store still holds the dispatcher-routed value the block consumes).
        """
        return self.out_hash.get(ctx, {}).get(int(block), PowersetStore.bottom())


def _routing_case_const(
    dispatcher: "FlowGraph", block: int, succ: int, state_cell: LocationRef
) -> Optional[int]:
    """The case const routed on the dispatcher edge ``block -> succ``, or ``None``.

    A dispatcher block whose conditional tail compares the state cell to a
    constant routes its equal arm to one handler.  Returns that constant when the
    edge is the equal arm of such a compare, else ``None`` (the edge does not
    advance the context).
    """
    blk = dispatcher.blocks.get(int(block))
    if blk is None:
        return None
    tail = blk.tail
    if tail is None or not tail.is_conditional_jump:
        return None
    pred = branch_predicate(tail)
    if pred not in (PredicateKind.EQ, PredicateKind.NE):
        return None
    const, cmp_cell = _compare_const_and_cell(tail)
    if const is None:
        return None
    if cmp_cell is not None and cmp_cell != state_cell:
        return None
    taken, fallthrough = _arm_targets(blk)
    eq_arm = taken if pred is PredicateKind.EQ else fallthrough
    return const if eq_arm == int(succ) else None


def _build_product_topology(
    graph: FlowGraph,
    *,
    policy: ContextPolicy,
    state_cell: LocationRef,
    entry_ctx: KContext,
) -> tuple[
    list[ProductNode],
    dict[ProductNode, list[ProductNode]],
    dict[ProductNode, list[ProductNode]],
]:
    """Enumerate the reachable ``(block, ctx)`` product graph.

    Forward-explores from ``(entry, entry_ctx)``; a routing edge advances the
    context (``ctx.extend(case, k)``).  Bounded by ``policy.max_contexts`` distinct
    contexts -- exploration stops adding *new* contexts past the cap (existing
    contexts continue), so the product stays finite even for pathological graphs.

    Returns ``(nodes, succ_map, pred_map)``.
    """
    succ_map: dict[ProductNode, list[ProductNode]] = {}
    pred_map: dict[ProductNode, list[ProductNode]] = {}
    seen_contexts: set[KContext] = {entry_ctx}
    entry = (int(graph.entry_serial), entry_ctx)
    stack: list[ProductNode] = [entry]
    visited: set[ProductNode] = set()

    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        succ_map.setdefault(node, [])
        pred_map.setdefault(node, [])
        block, ctx = node
        blk = graph.blocks.get(int(block))
        if blk is None:
            continue
        for succ in blk.succs:
            case = _routing_case_const(graph, int(block), int(succ), state_cell)
            if case is not None:
                nctx = ctx.extend(case, policy.k)
            else:
                nctx = ctx
            if nctx not in seen_contexts:
                if len(seen_contexts) >= policy.max_contexts:
                    # Cost guard: do not mint new contexts past the cap; reuse
                    # the current context (a sound over-merge -- collapses to a
                    # coarser partition, never invents a value).
                    nctx = ctx
                else:
                    seen_contexts.add(nctx)
            child = (int(succ), nctx)
            succ_map[node].append(child)
            pred_map.setdefault(child, []).append(node)
            if child not in visited:
                stack.append(child)

    nodes = sorted(visited, key=lambda n: (n[0], n[1].cases))
    return nodes, succ_map, pred_map


class _ProductDomain:
    """:class:`FlowDomain` over :class:`PowersetStore` for the product graph.

    ``transfer`` folds the block set-valued (no fork -- the per-arm refinement is
    applied by ``edge_refine``).  ``confluence`` / ``widen`` delegate to the store
    lattice; the per-cell powerset is finite-height so ``widen == join`` suffices.
    """

    def __init__(
        self,
        graph: FlowGraph,
        *,
        state_cell: LocationRef,
        block_evaluator: BlockEvaluator,
        state_var_stkoff: int,
        max_product: int,
    ) -> None:
        self._graph = graph
        self._state_cell = state_cell
        self._eval = block_evaluator
        self._state_off = int(state_var_stkoff)
        self._max_product = int(max_product)

    def bottom(self) -> PowersetStore:
        return PowersetStore.bottom()

    def confluence(
        self, left: PowersetStore, right: PowersetStore
    ) -> PowersetStore:
        return left.join(right)

    def transfer(self, node: ProductNode, in_state: PowersetStore) -> PowersetStore:
        block, _ctx = node
        blk = self._graph.blocks.get(int(block))
        if blk is None or in_state.is_bottom():
            return in_state
        return _fold_block_set(
            blk,
            in_state,
            block_evaluator=self._eval,
            state_var_stkoff=self._state_off,
            state_cell=self._state_cell,
            max_product=self._max_product,
        )

    def equals(self, left: PowersetStore, right: PowersetStore) -> bool:
        return left == right

    def widen(
        self, previous: PowersetStore, current: PowersetStore
    ) -> PowersetStore:
        return previous.widen(current)

    # -- per-edge assume ----------------------------------------------------
    def edge_refine(
        self, src: ProductNode, dst: ProductNode, out_state: PowersetStore
    ) -> PowersetStore:
        """Refine ``src``'s out-store for the specific arm leading to ``dst``.

        For a 2-way equality branch, the equal arm refines the condvar cell with
        ``meet_const`` and the not-equal arm with ``exclude`` (the LiSA per-edge
        ``assume``).  Other edges pass the out-store through unchanged.
        """
        block, _ = src
        succ, _ = dst
        blk = self._graph.blocks.get(int(block))
        if blk is None or out_state.is_bottom():
            return out_state
        tail = blk.tail
        if (
            tail is None
            or not tail.is_conditional_jump
            or len(blk.succs) != 2
        ):
            return out_state
        pred = branch_predicate(tail)
        if pred not in (PredicateKind.EQ, PredicateKind.NE):
            return out_state
        const, cmp_cell = _compare_const_and_cell(tail)
        if const is None:
            return out_state
        if cmp_cell is None:
            cmp_cell = self._state_cell
        taken, fallthrough = _arm_targets(blk)
        eq_arm = taken if pred is PredicateKind.EQ else fallthrough
        is_equal_arm = int(succ) == eq_arm
        return _refine_arm(out_state, cmp_cell, const, equal=is_equal_arm)


def _compute_top_density(
    s_hash: Mapping[KContext, Mapping[int, PowersetStore]],
) -> float:
    """Fraction of (context, cell) entries that are ``top`` across all stores."""
    total = 0
    tops = 0
    for per_block in s_hash.values():
        for store in per_block.values():
            for _cell, value in store.cells:
                total += 1
                if value.is_top:
                    tops += 1
    return (tops / total) if total else 0.0


def analyze_kswitch(
    graph: FlowGraph,
    *,
    policy: ContextPolicy,
    state_cell: LocationRef,
    initial_state: Optional[int] = None,
    condvar_cells: frozenset[LocationRef] = frozenset(),
    block_evaluator: Optional[BlockEvaluator] = None,
    state_var_stkoff: Optional[int] = None,
    config: Optional[FixpointConfiguration] = None,
    max_product: int = 256,
    raise_on_nonconvergence: bool = False,
) -> AnalysisResult:
    """Run the k-switch context-sensitive fixpoint over ``graph``.

    Seeds ``(entry, ())`` with the state cell set to ``{initial_state}`` (a
    singleton) when given, else ``bottom``.  Builds the ``(block, ctx)`` product
    topology, drives :func:`run_fixpoint` with :class:`_ProductDomain` and the
    per-arm ``edge_refine``, then re-indexes the flat ``(block, ctx)`` in-states
    into ``S# : ctx -> block -> store``.

    ``block_evaluator`` defaults to the registry-backed scalar fold; pass a
    pure-Python evaluator for portable unit tests.  ``state_var_stkoff`` defaults
    to the state cell's stack offset.
    """
    if state_var_stkoff is None:
        state_var_stkoff = (
            int(state_cell.key) if state_cell.kind.name == "STACK" else 0
        )
    if block_evaluator is None:
        block_evaluator = scalar_block_evaluator(int(state_var_stkoff))
    if config is None:
        config = FixpointConfiguration()

    entry_ctx = KContext.empty()
    nodes, succ_map, pred_map = _build_product_topology(
        graph, policy=policy, state_cell=state_cell, entry_ctx=entry_ctx
    )

    entry_node: ProductNode = (int(graph.entry_serial), entry_ctx)
    if initial_state is not None:
        entry_store = PowersetStore.singleton(state_cell, int(initial_state))
    else:
        entry_store = PowersetStore.bottom()

    domain = _ProductDomain(
        graph,
        state_cell=state_cell,
        block_evaluator=block_evaluator,
        state_var_stkoff=int(state_var_stkoff),
        max_product=max_product,
    )

    result: FixpointResult = run_fixpoint(
        domain,
        nodes=nodes,
        entry_nodes=[entry_node],
        entry_state=entry_store,
        successors_of=lambda n: succ_map.get(n, ()),
        predecessors_of=lambda n: pred_map.get(n, ()),
        config=config,
        raise_on_nonconvergence=raise_on_nonconvergence,
        edge_refine=domain.edge_refine,
    )

    # Re-index the flat product in/out-states into S# : ctx -> block -> store.
    s_hash: dict[KContext, dict[int, PowersetStore]] = {}
    out_hash: dict[KContext, dict[int, PowersetStore]] = {}
    contexts: set[KContext] = set()
    for (block, ctx), store in result.in_states.items():
        if store.is_bottom():
            continue
        s_hash.setdefault(ctx, {})[int(block)] = store
        contexts.add(ctx)
    for (block, ctx), store in result.out_states.items():
        if store.is_bottom():
            continue
        out_hash.setdefault(ctx, {})[int(block)] = store

    return AnalysisResult(
        s_hash=s_hash,
        out_hash=out_hash,
        reachable_contexts=frozenset(contexts),
        top_density=_compute_top_density(s_hash),
        converged=result.converged,
        iterations=result.iterations,
    )
