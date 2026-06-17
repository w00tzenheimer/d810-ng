"""Recover the state-machine dispatcher from a portable FlowGraph (unflatten pass #1).

LLVM-analysis / LiSA-CFG style: an analysis pass that reads only the portable ``FlowGraph`` and
produces an immutable result (``DispatcherRecovery``) — no microcode patching, no live ``mba``.

This is the portable hand-port of ``HodurStateMachineDetector`` (which reads live ``mop_t``): the
same equality-chain detection expressed over ``BlockSnapshot``/``MopSnapshot``. A state-check block
is a conditional jump comparing a state variable to a large constant; the constant routes to the
handler taken when ``state == const`` (``EQ`` -> jump target, ``NE`` -> fall-through). The dominant
compared variable (most comparisons) is the state variable, à la the live detector's cache-driven
selection. Output is a ``StateDispatcherMap`` (``state_const -> handler``) that every downstream unflatten
pass consumes.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from d810.ir.flowgraph import FlowGraph, InsnKind, OperandKind
from d810.ir.semantics import PredicateKind
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.reachability import reachable_from
from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.dispatcher_resolver import (
    DispatcherResolver,
    resolve_dispatcher,
)
from d810.analyses.control_flow.switch_table_analysis import (
    analyze_switch_table_flow_graph,
)

# Matches the live HodurStateMachineDetector threshold (analysis.py MIN_STATE_CONSTANT).
MIN_STATE_CONSTANT = 0x01000000

# Equality-chain dispatchers route on EQ/NE; other predicates aren't state checks.
_EQUALITY_PREDICATES = (PredicateKind.EQ, PredicateKind.NE)


def min_state_constant_from_config(project_config) -> int:
    """Read ``min_state_constant`` from the unflatten rule's JSON config.

    ``project_config`` is the ``StateMachineCffUnflattener`` blk_rule ``config`` dict
    (e.g. ``{"min_state_constant": 16777216, ...}``) threaded by both detection
    (``HodurFamily.detect`` via ``select_family(context=...)``) and the recovery pass
    (``FunctionPipelineContext.project_config``). Both sites read the SAME value via this
    helper so detection and recovery never diverge on the threshold (a known bug class).
    Falls back to :data:`MIN_STATE_CONSTANT` when the field (or the config) is absent so
    every existing caller keeps the module default (hodur/sub_7FFD/tigress goldens).
    """
    if not isinstance(project_config, dict):
        return MIN_STATE_CONSTANT
    value = project_config.get("min_state_constant")
    if value is None:
        return MIN_STATE_CONSTANT
    try:
        return int(value)
    except (TypeError, ValueError):
        return MIN_STATE_CONSTANT


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
                    router_kind=RouterKind.CONDITION_CHAIN,
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
        router_kind=RouterKind.CONDITION_CHAIN,
    )


def _read_state_init_const(blk, state_var_stkoff: int) -> int | None:
    """Read the constant a block initializes the state variable to, portably.

    Mirrors the live ``_extract_state_from_block`` (bst_analysis) over portable
    ``InsnSnapshot``s: a state-var initialization is a ``mov #const -> stkoff``
    (``InsnKind.MOV``, dest is the state slot, source is a number) or the
    equivalent ``store #const -> &stkoff`` (``InsnKind.STORE``, the GLBOPT m_stx
    form where the value being stored is the *left* operand and the destination
    address resolves to the state slot's stkoff). Returns the constant or None.
    """
    if blk is None:
        return None
    for insn in blk.insn_snapshots:
        if insn.kind is InsnKind.MOV:
            dst, src = insn.d, insn.l
            if (
                dst is not None
                and getattr(dst, "stkoff", None) is not None
                and int(dst.stkoff) == int(state_var_stkoff)
                and src is not None
                and getattr(src, "value", None) is not None
            ):
                return int(src.value) & 0xFFFFFFFFFFFFFFFF
        elif insn.kind is InsnKind.STORE:
            # m_stx <value>, <addr>: value = left, destination address = right.
            val, addr = insn.l, insn.r
            addr_off = None
            if addr is not None:
                addr_off = getattr(addr, "stkoff", None)
                if addr_off is None and getattr(addr, "stack_refs", None):
                    addr_off = addr.stack_refs[0]
            if (
                addr_off is not None
                and int(addr_off) == int(state_var_stkoff)
                and val is not None
                and getattr(val, "value", None) is not None
            ):
                return int(val.value) & 0xFFFFFFFFFFFFFFFF
    return None


def recover_entry_dominated_initial_state(
    graph: FlowGraph, dmap: StateDispatcherMap
) -> int | None:
    """Recover the dispatcher's true initial state via entry-dominance (Approach B).

    The live ``_find_pre_header`` "fewest-npred" heuristic is backwards for
    equality chains: it can pick an ``m_goto`` back-edge predecessor over the
    real ``m_mov`` prologue, yielding a spurious mid-chain ``initial_state``.

    The entry-dominance test is exact: from the function entry, forward-traverse
    the CFG treating the dispatcher entry block as a CUT (never traverse *out*
    of it). A predecessor of the dispatcher entry is the true pre-header iff it
    is reachable from entry WITHOUT passing through the dispatcher. Back-edges
    are reachable only THROUGH the dispatcher, so they are excluded. When exactly
    one predecessor qualifies and it initializes the state variable to a
    constant, return that constant; otherwise return ``None`` (caller keeps the
    existing behaviour). Address-agnostic: the value is read from the recovered
    block, never hardcoded.
    """
    entry_block = dmap.dispatcher_entry_block
    state_var_stkoff = dmap.state_var_stkoff
    if entry_block is None or state_var_stkoff is None:
        return None
    dispatcher_blk = graph.blocks.get(int(entry_block))
    if dispatcher_blk is None:
        return None

    # Forward reachability from entry with the dispatcher entry as a cut: visit
    # it but never expand its successors, so anything reachable only via the
    # dispatcher loop (the back-edges) stays unreached.
    reachable: set[int] = set()
    stack = [int(graph.entry_serial)]
    while stack:
        serial = stack.pop()
        if serial in reachable or serial not in graph.blocks:
            continue
        reachable.add(serial)
        if serial == int(entry_block):
            continue  # CUT: do not traverse out of the dispatcher entry
        stack.extend(int(s) for s in graph.blocks[serial].succs)

    qualifying = [
        int(pred)
        for pred in dispatcher_blk.preds
        if int(pred) != int(entry_block) and int(pred) in reachable
    ]
    if len(qualifying) != 1:
        return None
    return _read_state_init_const(graph.blocks.get(qualifying[0]), int(state_var_stkoff))


@dataclass(frozen=True, slots=True)
class EqualityChainDispatcherResolver:
    """Equality-chain (``CONDITION_CHAIN``) resolver -- the preferred shape.

    ``specificity=10`` (> switch's 5) preserves the historical equality-first
    precedence of ``build_dispatch_map_any_kind`` under the ranked chain.
    """

    name: str = "equality_chain"
    router_kind: RouterKind = RouterKind.EQUALITY_CHAIN
    specificity: int = 10
    # Threaded from the unflatten rule config (min_state_constant_from_config) so a
    # project can admit sub-default state constants (approov ~0xF6A1F); defaults to
    # the module threshold so existing callers stay byte-identical.
    min_state_constant: int = MIN_STATE_CONSTANT

    def accepts(self, graph: FlowGraph) -> ResolverCandidate | None:
        dmap = build_state_dispatcher_map_from_flow_graph(
            graph, min_state_constant=self.min_state_constant
        )
        if dmap is None:
            return None
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=float(len(dmap.rows)),
            specificity=self.specificity,
            reasons=("equality-chain", "rows=%d" % len(dmap.rows)),
        )

    def resolve(
        self, graph: FlowGraph, candidate: ResolverCandidate
    ) -> DispatcherResolution | None:
        dmap = build_state_dispatcher_map_from_flow_graph(
            graph, min_state_constant=self.min_state_constant
        )
        if dmap is None:
            return None
        return DispatcherResolution(
            dispatcher_map=dmap,
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=candidate.confidence,
            ranking_reason=candidate.reasons,
        )


@dataclass(frozen=True, slots=True)
class SwitchTableDispatcherResolver:
    """Switch-table / masked (``switch(state & MASK)`` jtbl) resolver.

    Fallback shape (e.g. abc_or_dispatch / OLLVM switch-fla); ``specificity=5``
    keeps it below the equality-chain resolver in the ranking.
    """

    name: str = "switch_table"
    router_kind: RouterKind = RouterKind.SWITCH
    specificity: int = 5

    def accepts(self, graph: FlowGraph) -> ResolverCandidate | None:
        result = analyze_switch_table_flow_graph(graph)
        if result is None:
            return None
        dmap = result.state_dispatcher_map
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=float(len(dmap.rows)),
            specificity=self.specificity,
            reasons=("switch-table", "rows=%d" % len(dmap.rows)),
        )

    def resolve(
        self, graph: FlowGraph, candidate: ResolverCandidate
    ) -> DispatcherResolution | None:
        result = analyze_switch_table_flow_graph(graph)
        if result is None:
            return None
        return DispatcherResolution(
            dispatcher_map=result.state_dispatcher_map,
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=candidate.confidence,
            ranking_reason=candidate.reasons,
        )


# --- Process-scoped extra-resolver registry (llr-qb33) -----------------------
#
# The shared front-end ``build_dispatch_map_any_kind`` is called from THREE
# detection sites over a portable ``FlowGraph`` (``HodurFamily.detect``,
# ``ApproovFamily.detect`` / ``TigressFamily.detect``, and ``recover_dispatcher``),
# none of which can carry a live-IDA argument.  Some dispatcher shapes (e.g. the
# Tigress ``m_ijmp``-through-qword-table indirect dispatcher) can only be
# *resolved* with binary access (read the qword label table) -- that resolver is
# IDA-bound and lives in ``d810.backends.hexrays`` to keep this portable module
# IDA-free (``portable-core-no-ida``).
#
# A backend wires its resolver in via :func:`register_extra_dispatcher_resolver`
# (the entry holds the live ``mba`` and binds it into the resolver instance).  The
# registry stores ONLY opaque ``DispatcherResolver`` Protocol objects, so this
# module never imports IDA.  Registered resolvers are appended AFTER the default
# chain, so their ranked ``(specificity, confidence)`` competes with -- and only
# wins over -- the portable defaults when they out-rank them.
_EXTRA_DISPATCHER_RESOLVERS: list[DispatcherResolver] = []


def register_extra_dispatcher_resolver(resolver: DispatcherResolver) -> None:
    """Register a backend-supplied resolver consulted by the shared front-end.

    Idempotent by ``name``: re-registering a resolver of the same ``name``
    REPLACES the prior instance (so an entry can rebind a fresh live ``mba``
    each decompilation without leaking stale resolvers across runs).
    """
    name = getattr(resolver, "name", None)
    if name is not None:
        _EXTRA_DISPATCHER_RESOLVERS[:] = [
            r for r in _EXTRA_DISPATCHER_RESOLVERS if getattr(r, "name", None) != name
        ]
    _EXTRA_DISPATCHER_RESOLVERS.append(resolver)


def clear_extra_dispatcher_resolvers() -> None:
    """Drop all registered extra resolvers (per-run reset / test isolation)."""
    _EXTRA_DISPATCHER_RESOLVERS.clear()


def extra_dispatcher_resolvers() -> tuple[DispatcherResolver, ...]:
    """Return the currently registered backend resolvers (registration order)."""
    return tuple(_EXTRA_DISPATCHER_RESOLVERS)


def default_dispatcher_resolvers(
    *, min_state_constant: int = MIN_STATE_CONSTANT
) -> tuple[DispatcherResolver, ...]:
    """The portable resolver chain shared by every unflatten dispatch-map consumer.

    ``min_state_constant`` is threaded into the equality-chain resolver so a project
    config can admit sub-default state constants; defaults to :data:`MIN_STATE_CONSTANT`.
    """
    return (
        EqualityChainDispatcherResolver(min_state_constant=min_state_constant),
        SwitchTableDispatcherResolver(),
    )


def build_dispatch_map_any_kind(
    graph: FlowGraph, *, min_state_constant: int = MIN_STATE_CONSTANT
) -> StateDispatcherMap | None:
    """Recover a ``StateDispatcherMap`` of ANY supported dispatcher kind.

    Delegates to the ranked :func:`resolve_dispatcher` chain over
    :func:`default_dispatcher_resolvers`. Equality-chain (``CONDITION_CHAIN``,
    specificity 10) outranks the switch-table fallback (specificity 5), so the
    historical equality-first precedence is preserved. The two detectors are
    disjoint in practice (equality -> ``None`` on switch graphs and vice versa),
    so ranking is behavior-neutral by construction.

    This is the single front-end shared by ``HodurFamily.detect`` (the pipeline
    gate) and ``recover_dispatcher`` (pass #1) so the two never disagree on which
    dispatcher shapes are supported.

    Backend-registered resolvers (:func:`register_extra_dispatcher_resolver`,
    e.g. the IDA-bound indirect jump-table resolver) are appended AFTER the
    portable defaults, so a genuine indirect (``m_ijmp``) dispatcher is recognized
    here too while every portable consumer stays IDA-free (the registry holds
    opaque ``DispatcherResolver`` Protocol objects).
    """
    resolvers = (
        default_dispatcher_resolvers(min_state_constant=min_state_constant)
        + extra_dispatcher_resolvers()
    )
    resolution = resolve_dispatcher(graph, resolvers)
    return resolution.dispatcher_map if resolution is not None else None


def recover_dispatcher(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    min_state_constant: int = MIN_STATE_CONSTANT,
) -> DispatcherRecovery:
    """Recover dispatcher structure + the exact state->handler map over a portable ``FlowGraph``.

    ``min_state_constant`` is threaded into the equality-chain detection so a project config
    can recover sub-default state constants; defaults to :data:`MIN_STATE_CONSTANT`.
    """
    if graph is None:
        return DispatcherRecovery()
    adjacency = {serial: graph.successors(serial) for serial in graph.blocks}
    reachable = reachable_from(adjacency, graph.block_count, graph.entry_serial)
    dmap = build_dispatch_map_any_kind(graph, min_state_constant=min_state_constant)
    if dmap is None:
        return DispatcherRecovery(reachable_block_serials=reachable)
    # Equality-chain / switch dispatchers do not thread an ``initial_state`` (the
    # live BST evidence supplies a SPURIOUS mid-chain value via the backwards
    # ``_find_pre_header`` heuristic). Recover the true prologue state by
    # entry-dominance and thread it onto the map so the §1a entry bridge prefers
    # it over the spurious BST value. INDIRECT maps already carry their own
    # recovered ``initial_state`` and are left untouched (ticket llr-mra1).
    if dmap.router_kind is not RouterKind.INDIRECT_TABLE and dmap.initial_state is None:
        recovered_initial = recover_entry_dominated_initial_state(graph, dmap)
        if recovered_initial is not None:
            dmap = replace(dmap, initial_state=recovered_initial)
    return DispatcherRecovery(
        reachable_block_serials=reachable,
        dispatcher_block_serial=dmap.dispatcher_entry_block,
        bst_block_serials=tuple(sorted(dmap.dispatcher_blocks)),
        state_var_stkoff=dmap.state_var_stkoff,
        dispatch_map=dmap,
    )
