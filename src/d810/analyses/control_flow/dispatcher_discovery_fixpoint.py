"""Dispatcher discovery as a value-set fixpoint.

``backends/hexrays/evidence/condition_chain_analysis.py::analyze_condition_chain_dispatcher`` discovers the dispatcher by a
procedural two-phase live walk: recurse the ``jz/jnz/jbe/ja`` comparison tree from the dispatcher
root collecting ``(const -> handler)`` leaves, then a second per-handler walk for the next-state
write.  It hard-codes the comparison topology, the comparison opcodes and the handler-chain shape.

This module does it the LiSA / abstract-interpretation way instead: a single forward value-set
fixpoint over the state variable, where **the dispatcher structure falls out of the abstract state**.
The condition chain is not a tree to walk -- it is a sequence of per-edge ``assume``s.  Each state comparison
``if s == K`` refines the value-set along its arms (``⊓ {K}`` on the equal arm, ``∖ {K}`` on the
not-equal arm).  After the fixpoint:

* a block whose entry value-set is the singleton ``{K}`` is ``handler(K)``'s entry (discovered, not
  supplied);
* a block whose entry value-set is a multi-constant set is range-routed (``RANGE_BACKED``);
* the dispatcher loop header is the block whose entry value-set is the broadest join (all states);
* the comparison blocks are the condition-chain nodes.

Only two pieces of structural evidence cross the boundary, both portable and minimal: the per-block
state-write view (``state_writes``: ``StateValue`` a block strong-updates to -- a constant, or ``⊤``
for an MBA-obfuscated write the :class:`ValRangeCapability` could not fold) and the per-block state
comparisons (:class:`StateArmComparison`).  Neither is a "shape": no recursion, no opcode matching, no
handler-chain assumption.  The result is portable-core (no IDA) and reuses the same
:func:`d810.analyses.data_flow.run_fixpoint` engine as every other dataflow analysis.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Callable, Iterable, Mapping

from d810.analyses.data_flow import FixpointConfiguration, FixpointResult, run_fixpoint
from d810.analyses.data_flow.domain import NodeId
from d810.analyses.control_flow.state_transition_domain import (
    StateTransitionDomain,
    StateValue,
)

__all__ = [
    "StateArmComparison",
    "DispatcherView",
    "assume_state",
    "read_dispatcher_from",
    "discover_dispatcher",
]

_Succ = Callable[[NodeId], Iterable[NodeId]]


@dataclass(frozen=True, slots=True)
class StateArmComparison:
    """A block that branches on ``state`` vs a constant.

    Resolved from the block's conditional-jump tail (predicate + the large-constant operand): the
    same recognition ``build_state_dispatcher_map_from_flow_graph`` already does, reduced to "which
    successor is taken when ``s == const`` (``eq_target``) vs ``s != const`` (``ne_target``)".  The
    EQ/NE opcode is already folded into the two targets, so the assume needs no opcode knowledge.
    """

    block: NodeId
    const: int
    eq_target: NodeId
    ne_target: NodeId


def assume_state(
    state: StateValue, comparison: StateArmComparison | None, to_node: NodeId
) -> StateValue:
    """The per-edge ``assume`` for a state comparison (the LiSA ``edge_refine``).

    Refines the value-set leaving ``comparison.block`` for the arm that reaches ``to_node``:
    ``⊓ {const}`` on the equal arm, ``∖ {const}`` on the not-equal arm.  A non-comparison block (or
    an edge to neither arm -- a shared/irregular successor) passes the value through unchanged.
    """
    if comparison is None:
        return state
    if int(to_node) == int(comparison.eq_target):
        return state.meet_const(comparison.const)
    if int(to_node) == int(comparison.ne_target):
        return state.exclude(comparison.const)
    return state


@dataclass(frozen=True, slots=True)
class DispatcherView:
    """The dispatcher structure read off a converged state-value fixpoint.

    Every field is a *view* over the fixpoint result, not a separately-walked structure:
    ``handler_state_map`` / ``handler_range_map`` / ``condition_chain_blocks`` /
    ``dispatcher_entry`` become projections of ``in_states``.
    """

    handler_entry_by_state: Mapping[int, NodeId]
    handler_range_map: Mapping[NodeId, tuple[int, int]]
    condition_chain_blocks: frozenset[NodeId]
    dispatcher_entry: NodeId | None
    result: FixpointResult = field(repr=False, default=None)


def read_dispatcher_from(
    result: FixpointResult,
    comparisons: Mapping[NodeId, StateArmComparison],
) -> DispatcherView:
    """Project the dispatcher structure out of a converged fixpoint.

    * ``handler_entry_by_state[K]`` = a non-comparison block whose entry value-set is exactly
      ``{K}`` (the assumes collapsed it to one constant -- it is reached only when ``s == K``).  When
      several blocks share the singleton, the one with the broadest *successor* fan-in toward the
      dispatcher wins is left to the caller; here we keep the lowest serial deterministically.
    * ``handler_range_map[b]`` = ``(min, max)`` for a block whose entry value-set is a concrete
      multi-constant set (range-routed -- ``RANGE_BACKED``).
    * ``condition_chain_blocks`` = the comparison blocks.
    * ``dispatcher_entry`` = the block whose entry value-set has the most constants (the loop header
      where every handler's next-state joins).  ``None`` if no block carries a multi-state set.
    """
    condition_chain_blocks = frozenset(int(b) for b in comparisons)
    in_states = result.in_states

    # Handler entry for K = the comparison's equal arm, kept only when the fixpoint proves it
    # FEASIBLE (its in-state is not ⊥). An infeasible arm means K never reaches here -- a dead
    # dispatcher edge the procedural condition-chain walk would still emit.
    # Deterministic on ties (lowest serial).
    handler_entry_by_state: dict[int, NodeId] = {}
    for comp in comparisons.values():
        eq_in = in_states.get(int(comp.eq_target))
        if eq_in is None or eq_in.is_bottom:
            continue
        prev = handler_entry_by_state.get(int(comp.const))
        if prev is None or int(comp.eq_target) < int(prev):
            handler_entry_by_state[int(comp.const)] = int(comp.eq_target)

    # The dispatcher head is the block carrying the broadest concrete value-set (every handler's
    # next-state joins there). A multi-state block that is NOT the head is range-routed (RANGE_BACKED).
    widest_block: NodeId | None = None
    widest_count = 1
    for block, in_state in in_states.items():
        if in_state.is_top or in_state.is_bottom:
            continue
        n = len(in_state.constants)
        if n > widest_count:
            widest_count, widest_block = n, int(block)

    handler_range_map: dict[NodeId, tuple[int, int]] = {}
    for block, in_state in in_states.items():
        block = int(block)
        # P3: a comparison block carries a multi-const set *because* it is mid-discrimination -- it is
        # a condition-chain node, not a range-routed handler. Only NON-comparison blocks reached for a genuine
        # multi-state range (a switch / interval handler with no final ``==`` check) are RANGE_BACKED.
        if (
            in_state.is_top
            or in_state.is_bottom
            or block == widest_block
            or block in condition_chain_blocks
        ):
            continue
        if len(in_state.constants) > 1:
            consts = sorted(in_state.constants)
            handler_range_map[block] = (consts[0], consts[-1])

    # P1: promote each genuine range-routed handler into ``handler_entry_by_state``
    # keyed by a representative state, so the exact-only ``recover_transition_result``
    # consumer sees it.  This mirrors ``_convert_condition_chain_to_result``'s IntervalDispatcher
    # backfill (transition_builder.py) but reads the routing off the fixpoint instead
    # of ``dispatcher._rows``, with two skips:
    #   * the default / catch-all arm -- a range block that is some comparison's
    #     ``ne_target`` is the "nothing matched" routing block, not a real handler
    #     (the fixpoint-native analogue of the ``_target_freq > 1`` skip);
    #   * a SHADOW block -- one whose entire value-set is already covered by exact
    #     handlers.  The representative must be a state NOT already mapped; a block
    #     with no such fresh state is a shared/merge block reachable on exact-handler
    #     paths, not a distinct handler, so promoting it would only clobber an exact
    #     entry without adding a handler.  (On real sub_7FFD both "range handlers"
    #     are shadows -- the value-set fixpoint is strictly more precise than the
    #     procedural condition-chain walk
    #     walk's count here, so the precise handler count stays at the 45 exact.)
    # Deterministic: lowest block serial wins on ties; lowest fresh state is the key.
    ne_targets = {int(comp.ne_target) for comp in comparisons.values()}
    promoted_blocks = set(handler_entry_by_state.values())
    for block in sorted(handler_range_map):
        if block in ne_targets or block in promoted_blocks:
            continue
        fresh = sorted(
            c for c in in_states[block].constants if c not in handler_entry_by_state
        )
        if not fresh:
            continue
        handler_entry_by_state[fresh[0]] = block
        promoted_blocks.add(block)

    return DispatcherView(
        handler_entry_by_state=handler_entry_by_state,
        handler_range_map=handler_range_map,
        condition_chain_blocks=condition_chain_blocks,
        dispatcher_entry=widest_block,
        result=result,
    )


def discover_dispatcher(
    *,
    nodes: Iterable[NodeId],
    entry_nodes: Iterable[NodeId],
    successors_of: _Succ,
    predecessors_of: _Succ,
    state_writes: Mapping[NodeId, StateValue],
    comparisons: Mapping[NodeId, StateArmComparison],
    entry_state: StateValue,
    config: FixpointConfiguration | None = None,
    require_resolved_head: bool = False,
) -> DispatcherView:
    """Discover the dispatcher by a forward value-set fixpoint with per-edge ``assume``.

    Replaces the procedural condition-chain + handler walk: propagate the state value-set from the
    function entry, strong-updating at state writes and refining at every comparison edge, then read
    the dispatcher structure off the result.  ``transition`` recovery is the existing
    :func:`state_transition_domain.recover_transition_result` fed this view's ``handler_entry_by_state``.

    ``entry_state`` MUST be the recovered initial state (``StateValue.of(initial_state)`` from the
    pre-header), NOT ``⊤``: seeding ``⊤`` poisons the loop header (``join(⊤, …) = ⊤``) so it never
    resolves to a concrete value-set and the head reads back as ``None``.  ``require_resolved_head``
    raises when that happens, surfacing an un-seeded / unreachable dispatcher rather than returning a
    silently headless view (P2).
    """
    domain = StateTransitionDomain(dict(state_writes))
    result = run_fixpoint(
        domain,
        nodes=list(nodes),
        entry_nodes=list(entry_nodes),
        entry_state=entry_state,
        successors_of=successors_of,
        predecessors_of=predecessors_of,
        config=FixpointConfiguration() if config is None else config,
        raise_on_nonconvergence=True,
        edge_refine=lambda p, n, s: assume_state(s, comparisons.get(int(p)), n),
    )
    view = read_dispatcher_from(result, comparisons)
    if require_resolved_head and view.dispatcher_entry is None:
        raise ValueError(
            "dispatcher head unresolved (⊤): seed entry_state with the recovered "
            "initial state, or the dispatcher loop is unreachable"
        )
    return view
