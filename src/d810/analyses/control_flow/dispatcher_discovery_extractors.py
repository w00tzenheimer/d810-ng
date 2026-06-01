"""FlowGraph -> (comparisons, state_writes) extractors for the LiSA dispatcher discovery.

The two pieces of evidence :func:`discover_dispatcher` consumes, read straight off the portable
``FlowGraph`` (no IDA): the per-block state comparisons (:class:`BstComparison`) and the per-block
state-write value (:class:`StateValue`).  Both are minimal -- a comparison is "this block branches on
``s`` vs a large constant", a state write is "this block stores ``K`` (or an unresolved value -> ``⊤``)
to the state slot".  Neither is a shape: no recursion, no handler-chain assumption.

The comparison recognition mirrors ``dispatcher_recovery.build_state_dispatcher_map_from_flow_graph``
(EQ -> jump target is the equal arm, NE -> fall-through is the equal arm).  The state-write value
resolution is the const-or-``⊤`` lattice element; a future cut routes the ``⊤`` writes through the
injected ``ValRangeCapability`` instead of giving up.
"""
from __future__ import annotations

from d810.core.typing import Mapping

from d810.ir.flowgraph import FlowGraph, OperandKind
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.control_flow.dispatcher_discovery_fixpoint import (
    BstComparison,
    DispatcherView,
    discover_dispatcher,
)

__all__ = [
    "extract_bst_comparisons",
    "extract_state_writes",
    "discover_dispatcher_from_flow_graph",
]

MIN_STATE_CONSTANT = 0x01000000
_EQUALITY = (PredicateKind.EQ, PredicateKind.NE)


def _split_const_state(left, right, min_const: int):
    for const_op, state_op in ((left, right), (right, left)):
        if (
            const_op is not None
            and const_op.kind is OperandKind.NUMBER
            and const_op.value is not None
            and int(const_op.value) > min_const
        ):
            return int(const_op.value), state_op
    return None, None


def _state_offset(operand) -> int | None:
    if operand is None:
        return None
    if operand.stkoff is not None:
        return int(operand.stkoff)
    if operand.stack_refs:
        return int(operand.stack_refs[0])
    return None


def extract_bst_comparisons(
    graph: FlowGraph,
    *,
    state_var_stkoff: int | None = None,
    min_state_constant: int = MIN_STATE_CONSTANT,
) -> dict[int, BstComparison]:
    """Every block whose tail branches on ``s == const`` -> a :class:`BstComparison`.

    When ``state_var_stkoff`` is given, only comparisons against that variable are kept (the
    dominant-state-var filter); otherwise every equality-vs-large-constant branch qualifies.
    """
    comparisons: dict[int, BstComparison] = {}
    for serial, blk in graph.blocks.items():
        tail = blk.tail
        if tail is None or not tail.is_conditional_jump:
            continue
        pred = tail.branch_predicate
        if pred not in _EQUALITY:
            continue
        const, state_op = _split_const_state(tail.l, tail.r, min_state_constant)
        if const is None:
            continue
        if (
            state_var_stkoff is not None
            and _state_offset(state_op) != int(state_var_stkoff)
        ):
            continue
        taken = tail.d.block_ref if tail.d is not None else None
        fallthrough = next((s for s in blk.succs if s != taken), None)
        if taken is None or fallthrough is None:
            continue
        # EQ (jz K): the taken arm is reached when s == K. NE (jnz K): the fall-through is.
        if pred is PredicateKind.EQ:
            eq_target, ne_target = int(taken), int(fallthrough)
        else:
            eq_target, ne_target = int(fallthrough), int(taken)
        comparisons[int(serial)] = BstComparison(
            block=int(serial), const=int(const), eq_target=eq_target, ne_target=ne_target
        )
    return comparisons


def extract_state_writes(
    graph: FlowGraph, *, state_var_stkoff: int
) -> dict[int, StateValue]:
    """Per-block strong-update value for the state variable (last write in the block wins).

    A constant store to the state slot yields ``StateValue.of(K)``; any other write to it (computed /
    register-sourced / MBA-obfuscated) yields ``⊤`` -- the value is unknown, made explicit rather
    than dropped.  Blocks with no write to the state slot are absent (the domain passes through).
    """
    target = int(state_var_stkoff)
    writes: dict[int, StateValue] = {}
    for serial, blk in graph.blocks.items():
        block_write: StateValue | None = None
        for insn in blk.insn_snapshots:
            dest = insn.d
            if dest is None or dest.stkoff is None or int(dest.stkoff) != target:
                continue
            src = insn.l
            if src is not None and src.kind is OperandKind.NUMBER and src.value is not None:
                block_write = StateValue.of(int(src.value))
            else:
                block_write = StateValue.top()
        if block_write is not None:
            writes[int(serial)] = block_write
    return writes


def discover_dispatcher_from_flow_graph(
    graph: FlowGraph,
    *,
    state_var_stkoff: int,
    initial_state: int | None,
    require_resolved_head: bool = False,
) -> DispatcherView:
    """Extract (comparisons, state_writes) off ``graph`` and run the discovery fixpoint.

    ``initial_state`` seeds the value-set at the function entry (the pre-header constant): without it
    the loop header stays ``⊤`` (P2).  When unknown, ``⊤`` is used and the head will read back as
    ``None`` -- set ``require_resolved_head`` to fail loud on that.
    """
    comparisons = extract_bst_comparisons(graph, state_var_stkoff=state_var_stkoff)
    state_writes = extract_state_writes(graph, state_var_stkoff=state_var_stkoff)
    blocks = graph.blocks
    return discover_dispatcher(
        nodes=list(blocks.keys()),
        entry_nodes=[int(graph.entry_serial)],
        successors_of=lambda s: blocks[int(s)].succs if int(s) in blocks else (),
        predecessors_of=lambda s: blocks[int(s)].preds if int(s) in blocks else (),
        state_writes=state_writes,
        comparisons=comparisons,
        entry_state=(
            StateValue.of(int(initial_state))
            if initial_state is not None
            else StateValue.top()
        ),
        require_resolved_head=require_resolved_head,
    )
