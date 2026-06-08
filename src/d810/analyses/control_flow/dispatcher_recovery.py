"""Recover the state-machine dispatcher from a portable FlowGraph (§1a pass #1).

LLVM-analysis / LiSA-CFG style: an analysis pass that reads only the portable ``FlowGraph`` and
produces an immutable result (``DispatcherRecovery``) — no microcode patching, no live ``mba``.

This is the portable hand-port of ``HodurStateMachineDetector`` (which reads live ``mop_t``): the
same equality-chain detection expressed over ``BlockSnapshot``/``MopSnapshot``. A state-check block
is a conditional jump comparing a state variable to a large constant; the constant routes to the
handler taken when ``state == const`` (``EQ`` -> jump target, ``NE`` -> fall-through). The dominant
compared variable (most comparisons) is the state variable, à la the live detector's cache-driven
selection. Output is a ``StateDispatcherMap`` (``state_const -> handler``) that every downstream §1a
pass consumes.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph, OperandKind
from d810.ir.semantics import PredicateKind
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.reachability import reachable_from
from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.switch_table_analysis import (
    analyze_switch_table_flow_graph,
)

# Matches the live HodurStateMachineDetector threshold (analysis.py MIN_STATE_CONSTANT).
MIN_STATE_CONSTANT = 0x01000000

# Equality-chain dispatchers route on EQ/NE; other predicates aren't state checks.
_EQUALITY_PREDICATES = (PredicateKind.EQ, PredicateKind.NE)


@dataclass(frozen=True, slots=True)
class DispatcherRecovery:
    """Portable result of dispatcher recovery over a FlowGraph."""

    reachable_block_serials: frozenset[int] = frozenset()
    dispatcher_block_serial: int | None = None
    bst_block_serials: tuple[int, ...] = ()
    state_var_stkoff: int | None = None
    dispatch_map: StateDispatcherMap | None = None


def _split_const_state(left, right, min_const: int):
    """Return ``(const_value, state_operand)`` from a compare's operands, or ``(None, None)``."""
    for const_op, state_op in ((left, right), (right, left)):
        if (
            const_op is not None
            and const_op.kind is OperandKind.NUMBER
            and const_op.value is not None
            and int(const_op.value) > min_const
        ):
            return int(const_op.value), state_op
    return None, None


def _state_var_offset(operand) -> int | None:
    """Portable identity for a state operand: its stack offset (direct or via an expr ref)."""
    if operand is None:
        return None
    if operand.stkoff is not None:
        return int(operand.stkoff)
    if operand.stack_refs:
        return int(operand.stack_refs[0])
    return None


def _state_var_identity(operand) -> tuple[str, int] | None:
    """Votable identity for a state operand: ``('stk', off)`` or ``('reg', reg)``.

    The equality leaves of a *register-resident* dispatcher compare a register
    (``jz eax, #state_const``) rather than a stack slot, so ``_state_var_offset``
    returns ``None`` and those votes are silently dropped -- which lets a lone
    decoy stack comparison win the vote. Identifying the operand by its register
    keeps those votes; the winner is resolved back to a stack slot afterwards.
    """
    if operand is None:
        return None
    off = _state_var_offset(operand)
    if off is not None:
        return ("stk", off)
    if getattr(operand, "reg", None) is not None:
        return ("reg", int(operand.reg))
    return None


def _resolve_state_identity_to_stkoff(identity, graph) -> int | None:
    """Resolve a voted state identity to a stack offset.

    Stack identities map directly. A register identity is resolved to the stack
    slot the register is loaded from (e.g. ``xdu [state_var], eax`` at the
    dispatcher head) -- the dominant stack source of that register across the
    function -- so downstream stkoff-based passes still see the real state var.
    """
    if identity is None:
        return None
    kind, key = identity
    if kind == "stk":
        return int(key)
    # Register: collect the stack slots it is loaded from, and (separately) the
    # slots that receive state-constant writes. A general-purpose register is
    # loaded from many scratch slots, so "most common load source" alone picks a
    # decoy; the state variable is the loaded slot that also receives the dispatch
    # transitions' next-state constant writes.
    src_counts: dict[int, int] = {}
    write_counts: dict[int, int] = {}
    for blk in graph.blocks.values():
        for insn in blk.insn_snapshots:
            dst = insn.d
            src = insn.l
            if (
                dst is not None
                and getattr(dst, "reg", None) == key
                and src is not None
                and getattr(src, "stkoff", None) is not None
            ):
                src_counts[int(src.stkoff)] = src_counts.get(int(src.stkoff), 0) + 1
            if (
                dst is not None
                and getattr(dst, "stkoff", None) is not None
                and src is not None
                and getattr(src, "value", None) is not None
                and int(src.value) >= MIN_STATE_CONSTANT
            ):
                write_counts[int(dst.stkoff)] = write_counts.get(int(dst.stkoff), 0) + 1
    if not src_counts:
        return None
    # Prefer the loaded slot with the most state-constant writes (the state var).
    state_slots = {off: write_counts.get(off, 0) for off in src_counts}
    best = max(state_slots, key=lambda k: state_slots[k])
    if state_slots[best] > 0:
        return best
    # Fall back: the most common load source.
    return max(src_counts, key=lambda k: src_counts[k])


def build_state_dispatcher_map_from_flow_graph(
    graph: FlowGraph, *, min_state_constant: int = MIN_STATE_CONSTANT
) -> StateDispatcherMap | None:
    """Detect an equality-chain dispatcher over a portable ``FlowGraph``.

    Hand-port of the live detector's equality-chain recognition. Returns ``None`` when no
    state-check chain is present.
    """
    raw: list[tuple[StateDispatcherRow, object]] = []
    dispatcher_blocks: set[int] = set()
    for serial, blk in graph.blocks.items():
        tail = blk.tail
        if tail is None or not tail.is_conditional_jump:
            continue
        pred = tail.branch_predicate
        if pred not in _EQUALITY_PREDICATES:
            continue
        const, state_op = _split_const_state(tail.l, tail.r, min_state_constant)
        if const is None:
            continue
        taken = tail.d.block_ref if tail.d is not None else None
        fallthrough = next((s for s in blk.succs if s != taken), None)
        handler = taken if pred is PredicateKind.EQ else fallthrough
        if handler is None:
            continue
        raw.append(
            (
                StateDispatcherRow(
                    state_const=const,
                    target_block=int(handler),
                    dispatcher_block=int(serial),
                    compare_block=int(serial),
                    branch_kind=pred.value,
                    source=DispatcherType.CONDITIONAL_CHAIN,
                ),
                state_op,
            )
        )
        dispatcher_blocks.add(int(serial))

    if not raw:
        return None

    # Pick the dominant state variable (most comparisons), keep only its rows — the live detector's
    # "operand with the most state comparisons" wisdom, which rejects decoy/early comparisons.
    # Votes are cast on a register/stack *identity* so register-resident compares
    # (``jz eax, #state_const`` — the MASM/non-spilled form) count instead of being
    # dropped and letting a lone decoy stack comparison win.
    votes: dict[tuple[str, int], int] = {}
    for _row, st_op in raw:
        identity = _state_var_identity(st_op)
        if identity is not None:
            votes[identity] = votes.get(identity, 0) + 1
    winner = max(votes, key=lambda k: votes[k]) if votes else None
    state_var_stkoff = _resolve_state_identity_to_stkoff(winner, graph)
    rows = tuple(
        row
        for row, st_op in raw
        if winner is None or _state_var_identity(st_op) == winner
    )
    chain_blocks = frozenset(row.dispatcher_block for row in rows)
    # Dispatcher entry = the loop head the handler tails converge on. The equality-chain comparators
    # each have near-zero in-degree (reached only from the previous comparator); the block the
    # handlers actually back-edge to is the comparators' common dominator -- the dispatcher loop
    # header -- which is itself NOT a state-comparison block. ``max(chain_blocks, ...)`` therefore
    # picked an arbitrary low in-degree mid-chain comparator. Walk the dominator tree from the
    # function entry and rank every dominator of the chain by in-degree so the true high-fan-in loop
    # head wins (the block ~all handler gotos return to).
    succ_map = {s: [int(x) for x in b.succs] for s, b in graph.blocks.items()}
    dom = compute_dom_tree(succ_map, graph.entry_serial)
    entry_candidates: set[int] = set(chain_blocks)
    for cb in chain_blocks:
        entry_candidates |= dom.dominators_of(cb)
    entry = max(entry_candidates, key=lambda s: len(graph.blocks[s].preds))
    return StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=int(entry),
        dispatcher_blocks=chain_blocks,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=None,
        source=DispatcherType.CONDITIONAL_CHAIN,
    )


def build_dispatch_map_any_kind(graph: FlowGraph) -> StateDispatcherMap | None:
    """Recover a ``StateDispatcherMap`` of ANY supported dispatcher kind.

    Equality-chain (``CONDITIONAL_CHAIN``) is preferred; on no match it falls back
    to the portable switch-table / masked detector (``switch(state & MASK)`` jtbl,
    e.g. abc_or_dispatch / OLLVM switch-fla). The switch detector already produces a
    ``StateDispatcherMap`` (``case_value -> handler``), so we reuse it instead of
    growing a parallel §1a detector (consolidation; playbook 2026-06-08 step 7,
    mirrors hodur ``snapshot_builder`` preferring ``switch_table_map``).

    This is the single front-end shared by ``HodurFamily.detect`` (the pipeline gate)
    and ``recover_dispatcher`` (pass #1) so the two never disagree on which dispatcher
    shapes are supported.
    """
    dmap = build_state_dispatcher_map_from_flow_graph(graph)
    if dmap is not None:
        return dmap
    switch_result = analyze_switch_table_flow_graph(graph)
    if switch_result is not None:
        return switch_result.state_dispatcher_map
    return None


def recover_dispatcher(
    graph: FlowGraph | None, facts: ValidatedFactView | None
) -> DispatcherRecovery:
    """Recover dispatcher structure + the exact state->handler map over a portable ``FlowGraph``."""
    if graph is None:
        return DispatcherRecovery()
    adjacency = {serial: graph.successors(serial) for serial in graph.blocks}
    reachable = reachable_from(adjacency, graph.block_count, graph.entry_serial)
    dmap = build_dispatch_map_any_kind(graph)
    if dmap is None:
        return DispatcherRecovery(reachable_block_serials=reachable)
    return DispatcherRecovery(
        reachable_block_serials=reachable,
        dispatcher_block_serial=dmap.dispatcher_entry_block,
        bst_block_serials=tuple(sorted(dmap.dispatcher_blocks)),
        state_var_stkoff=dmap.state_var_stkoff,
        dispatch_map=dmap,
    )
