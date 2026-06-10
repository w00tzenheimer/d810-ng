"""Minimal per-handler state-transition recovery (epic d81-jfg2).

The legacy recovery builds a whole state-transition graph by symbolically
DFS-walking multi-block handler paths, classifying exits, detecting corridors,
and running SCC analysis (``evaluate_handler_paths`` + the supplemental DAG
builder).  That machinery drifts across shared blocks into the wrong
handler/exit (e.g. ``0x610BB4D9`` collapsed to the exit state) and produces
diagnostic projections that disagree with the actual output.

This module replaces it with the minimal model:

    transition(handler) = route( fold(handler's next-state write) )

For each handler the dispatcher routes to, we run a **strictly handler-local**
forward scan that:

  * starts at the handler entry with an empty const env,
  * folds the state-var write per block (``_transfer_snapshot_constant_block``
    — the sound local fold, carrying the handler's own constants so shared
    ``xor``/``sub`` suffixes fold to *this* handler's value automatically), and
  * **hard-stops** at the dispatcher entry, *any other handler's entry block*,
    or a STOP/terminal block.

The last folded state-var value on a path is that path's next-state; a 2-way
branch inside the region yields one arm per branch (a conditional transition).
Each next-state is routed through the interval-set dispatcher to its target
handler.  No global graph, no SCC, no exit-classification heuristics, no
drifting walk.

Portable: consumes a :class:`d810.ir.flowgraph.FlowGraph` snapshot and an
:class:`d810.analyses.control_flow.interval_map.IntervalDispatcher`; no live
IDA / Hex-Rays imports.  The MBA fold runs through the registered
``forward_eval_insn`` seam (same as the existing snapshot path eval).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.analyses.control_flow.state_machine_analysis import (
    _constant_dest_locator_snapshot,
    _eval_insn_view_snapshot,
    _is_stop_block,
    _transfer_snapshot_constant_block,
    run_snapshot_constant_fixpoint,
)

logger = getLogger(__name__)

# Default bound on the handler-local corridor scan.  Real OLLVM handler bodies
# (entry -> work -> const-load -> shared MBA suffix -> dispatcher) are short; a
# small bound keeps the scan O(handler) and prevents runaway on malformed CFGs.
_MAX_CORRIDOR_DEPTH = 24

__all__ = [
    "TransitionArm",
    "HandlerTransition",
    "recover_handler_transitions",
    "StateWriteTransition",
    "TransitionProof",
    "recover_state_write_transitions",
    "recover_state_write_transitions_via_fixpoint",
    "recover_state_write_transitions_via_multicell_fixpoint",
    "recover_state_write_transitions_via_partitioned_fixpoint",
    "diff_back_edge_transitions",
    "diff_back_edge_transitions_partitioned",
]

#: The oracle that resolves a back-edge next-state after the S4 C3 flip: the sound
#: region-partitioned multi-cell constant fixpoint (run_snapshot_constant_fixpoint).
_FIXPOINT_ORACLE = "region_partitioned_fixpoint"


@dataclass(frozen=True, slots=True)
class TransitionProof:
    """Typed provenance for a recovered back-edge transition (ticket d81-t9ok).

    Names the oracle that resolved the next-state and whether the result is trusted,
    so the fact/proof layer (epic llr-fqam) can rank edges by evidence instead of
    trusting every emitted edge equally / a provenance allowlist.  ``kind`` is the
    resolution shape (``global_fold`` / ``region_agreed`` / ``predecessor_partitioned``
    / ``unresolved``); ``trusted`` is ``False`` for an unresolved (routed-to-return)
    back-edge a consumer must not rewrite as a handler transition.
    """

    oracle_kind: str
    kind: str
    trusted: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class StateWriteTransition:
    """One dispatcher back-edge: a block that writes the next state then re-enters
    the dispatcher.

    The state-machine's *real* transition points are the dispatcher's
    predecessors — every block that writes the state variable and branches back
    into the comparison tree.  (For the OLLVM shape this module targets, the set
    of dispatcher predecessors is *exactly* the set of state-var-writing blocks.)
    Anchoring recovery on these back-edges — rather than on the dispatcher's
    routed *targets* (handler entries) — is robust to handlers that share
    suffixes or chain through one another's entry blocks: those interior fall
    -throughs are left as natural control flow and only the back-edge to the
    dispatcher is rewritten.
    """

    write_block: int             # redirect source (the back-edge, or a predecessor
                                 # of it when the back-edge is a per-predecessor split)
    next_state: int | None       # folded state-var value entering the dispatcher
    target_handler: int | None   # dispatcher route of next_state (None unresolved)
    is_return: bool              # routes to exit/STOP/default, or unresolved
    branch_arm: int | None       # succ index of the dispatcher edge (None => 1-way)
    via_block: int | None = None  # when set, redirect ``write_block -> via_block``
                                  # (bypass the shared back-edge) instead of
                                  # ``write_block -> dispatcher``
    proof: "TransitionProof | None" = None  # typed provenance (d81-t9ok); the
                                            # authoritative fixpoint emitter attaches
                                            # it, None = unattributed (legacy fold)


def _resolve_state_var_alias(
    flow_graph, dispatcher_entry_serial: int, state_var_stkoff: int
) -> int:
    """Follow a dispatcher-header copy ``state_var = src`` back to ``src``.

    OLLVM ``-fla`` keeps the dispatcher's *compared* state slot as a copy of the
    slot the handlers actually write the NEXT state to: the loop header does
    ``compared = next_write`` then routes on ``compared``.  At a handler
    back-edge the compared slot still holds the OLD (current) state, so folding
    it makes every handler resolve to its own incoming state -> ``route(own)`` is
    the handler itself -> self-loop, and the dispatcher collapses unchanged.  The
    slot the handlers freshly write is the copy SOURCE; fold *that* so back-edge
    next-states resolve.

    Detected structurally (no opcode interpretation -- the lifter leaves
    ``insn.kind`` UNKNOWN): a write into ``state_var_stkoff`` whose left operand
    is a *different* stack slot and whose right operand is empty is a pure copy
    (mov / widen), not arithmetic.  Returns the original offset when the header
    has no such incoming copy (clean hodur / sub_7FFD chains -> unchanged).
    """
    blk = flow_graph.get_block(int(dispatcher_entry_serial))
    if blk is None:
        return int(state_var_stkoff)
    soff = int(state_var_stkoff)
    source = soff
    for insn in getattr(blk, "insn_snapshots", ()):
        view = _eval_insn_view_snapshot(insn)
        if _constant_dest_locator_snapshot(getattr(view, "d", None)) != ("stk", soff):
            continue
        r = getattr(view, "r", None)
        if (
            _constant_dest_locator_snapshot(r) is not None
            or getattr(r, "value", None) is not None
        ):
            continue  # binary op (add/xor/...) -> not a pure copy
        lloc = _constant_dest_locator_snapshot(getattr(view, "l", None))
        if lloc is not None and lloc[0] == "stk" and lloc[1] != soff:
            source = int(lloc[1])  # last copy into state_var wins
    return source


def _resolve_back_edge_states(
    flow_graph,
    *,
    dispatcher,
    state_var_stkoff: int,
    dispatcher_entry: int,
    max_depth: int,
) -> dict[int, set[int]]:
    """Per-region forward const-fold -> the state each back-edge writes.

    Walks forward from every region entry (each dispatcher target + the function
    prologue), carrying exact stack/register constants block-by-block.  Carrying
    *region-local* constants — rather than meeting across all predecessors —
    resolves opaque ``state = reg_a ^ reg_b`` / ``sub`` writes whose register
    operands are constants set earlier in the same handler region.  Whenever the
    walk reaches a block that branches back into the dispatcher, the folded
    state value at that block is recorded for that back-edge.  A back-edge that
    folds to two distinct states across different region paths is a
    predecessor-partitioned (opaque-split) write and is reported as ambiguous.
    """

    disp = int(dispatcher_entry)
    soff = int(state_var_stkoff)
    region_entries: set[int] = {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None
    }
    entry = getattr(flow_graph, "entry_serial", None)
    if entry is not None:
        region_entries.add(int(entry))
    region_entries.discard(disp)

    # Region-entry seed: the dispatch key that routes to each region. A masked /
    # switch-table dispatcher (``switch(state & MASK)``) reaches handler ``H`` iff
    # ``state & MASK == key``, and the handler writes ``state = (state & ~MASK) | M``;
    # folding that write to ``M`` needs the incoming low bits, which ARE that key.
    # Seeding the state var with it lets the forward fold resolve the masked-OR/XOR
    # write that an empty seed cannot. Restricted to *point* rows (``hi == lo + 1``,
    # an exact single-state key) so range-row BST routers (the equality-chain
    # spine, e.g. sub_7FFD) are untouched; targets with conflicting keys (a handler
    # shared by several states, whose state-dependent write would need all of them)
    # are left unseeded.
    entry_seed: dict[int, int] = {}
    seed_conflict: set[int] = set()
    for row in getattr(dispatcher, "_rows", ()):
        target = getattr(row, "target", None)
        lo = getattr(row, "lo", None)
        hi = getattr(row, "hi", None)
        if target is None or lo is None or hi is None or int(hi) != int(lo) + 1:
            continue
        tgt = int(target)
        key = int(lo) & 0xFFFFFFFF
        if tgt in entry_seed and entry_seed[tgt] != key:
            seed_conflict.add(tgt)
        else:
            entry_seed[tgt] = key
    for tgt in seed_conflict:
        entry_seed.pop(tgt, None)

    # back-edge serial -> { immediate predecessor (None at a region head) -> states }.
    # Partitioning by the immediate predecessor recovers opaque ``state =
    # reg_a ^ reg_b`` writes whose register operands are set to *different*
    # constants on each incoming edge (the LiSA disjunctive / predecessor-
    # partitioned case): each edge folds to its own state instead of collapsing
    # to an ambiguous set.
    back_edge_states: dict[int, dict[int | None, set[int]]] = {}
    for start in sorted(region_entries):
        seed_stk = {soff: entry_seed[start]} if start in entry_seed else {}
        stack: list[tuple[int, dict, dict, frozenset[int], int, int | None]] = [
            (start, seed_stk, {}, frozenset({start}), 0, None)
        ]
        while stack:
            blk_serial, in_stk, in_reg, visited, depth, parent = stack.pop()
            block = flow_graph.get_block(blk_serial)
            if block is None:
                continue
            out_stk, out_reg = _transfer_snapshot_constant_block(
                block, dict(in_stk), dict(in_reg), soff
            )
            succs = tuple(int(s) for s in block.succs)
            if disp in succs:
                # This block branches back into the dispatcher -- it is a
                # back-edge (the region's transition point).  Record the folded
                # state keyed by the edge we arrived on, and STOP: do not walk
                # past it into the *next* region.
                value = out_stk.get(soff)
                if value is not None:
                    back_edge_states.setdefault(blk_serial, {}).setdefault(
                        parent, set()
                    ).add(int(value) & 0xFFFFFFFF)
                continue
            if depth >= max_depth:
                continue
            for succ in succs:
                if succ == disp or succ in visited:
                    continue
                if _is_stop_block(flow_graph.get_block(succ)):
                    continue
                stack.append(
                    (succ, out_stk, out_reg, visited | {succ}, depth + 1, blk_serial)
                )
    return back_edge_states


def recover_state_write_transitions(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int,
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> tuple[StateWriteTransition, ...]:
    """Recover one transition per dispatcher back-edge (state-write block).

    For every predecessor ``P`` of the dispatcher, the next state ``S`` it writes
    is resolved by a per-region forward fold (see
    :func:`_resolve_back_edge_states`).  The transition is ``P -> route(S)``.
    Back-edges that do not fold to a single state (unresolved, or a
    predecessor-partitioned opaque split that needs block de-sharing) are
    returned as ``is_return`` so the emitter routes them to the shared return.
    """

    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()

    # Follow a dispatcher-header copy (compared state var <- next-state slot) so
    # the fold reads the slot handlers freshly write (OLLVM -fla shadow); a clean
    # chain returns the same offset unchanged.
    effective_stkoff = _resolve_state_var_alias(flow_graph, disp, int(state_var_stkoff))
    back_edge_states = _resolve_back_edge_states(
        flow_graph,
        dispatcher=dispatcher,
        state_var_stkoff=effective_stkoff,
        dispatcher_entry=disp,
        max_depth=max_depth,
    )
    default = dispatcher.default_target

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        edge_states = back_edge_states.get(pred, {})
        all_states = {s for states in edge_states.values() for s in states}

        if len(all_states) == 1:
            # Unambiguous: every incoming edge folds to the same state -> redirect
            # the back-edge itself off the dispatcher.
            state = next(iter(all_states))
            target, is_ret = _classify(state)
            out.append(StateWriteTransition(pred, state, target, is_ret, arm))
            continue

        if all_states and all(
            ipred is not None and len(states) == 1
            for ipred, states in edge_states.items()
        ):
            # Predecessor-partitioned (opaque ``reg_a ^ reg_b`` split): each
            # incoming edge folds to its own state.  The back-edge block is pure
            # state-glue, so bypass it -- redirect every predecessor straight to
            # its own routed handler.
            for ipred, states in sorted(edge_states.items()):
                state = next(iter(states))
                target, is_ret = _classify(state)
                ip_block = flow_graph.get_block(int(ipred))
                ip_arm = (
                    [int(s) for s in ip_block.succs].index(pred)
                    if ip_block is not None and ip_block.nsucc > 1 and pred in [int(s) for s in ip_block.succs]
                    else None
                )
                out.append(
                    StateWriteTransition(
                        int(ipred), state, target, is_ret, ip_arm, via_block=pred
                    )
                )
            continue

        # Unresolved (no fold, or a predecessor maps to multiple states) -> route
        # the back-edge to the shared return.
        out.append(StateWriteTransition(pred, None, None, True, arm))

    return tuple(out)


def recover_state_write_transitions_via_fixpoint(
    flow_graph,
    dispatcher,
    *,
    dispatcher_entry_serial: int,
    out_states,
) -> tuple[StateWriteTransition, ...]:
    """Shadow of :func:`recover_state_write_transitions` sourced from the fixpoint.

    Step C1 of the S4 flip (ticket llr-1szn): instead of the ad-hoc per-region fold
    (:func:`_resolve_back_edge_states`), the next state each dispatcher back-edge writes
    is read from the sound ``StateValue`` fixpoint's converged ``out_states[pred]``.  The
    routing (``dispatcher.lookup``), return classification, and ``branch_arm`` are the
    SAME as the production emitter, so a back-edge whose fixpoint state is a singleton
    emits a **byte-identical** :class:`StateWriteTransition`.

    It is single-partition, so it cannot emit the Case-2 predecessor-partitioned opaque
    ``reg ^ reg`` split (the ``via_block`` form): those back-edges fold to ``⊤`` / a
    multi-set here and emit as an unresolved return.  :func:`diff_back_edge_transitions`
    surfaces exactly that residual -- the edges the concrete / correlated fold (step C2)
    must close before the authoritative flip.  Diagnostic only; mutates nothing.
    """
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    default = dispatcher.default_target

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        sv = out_states.get(pred)
        usable = (
            sv is not None
            and not getattr(sv, "is_top", False)
            and not getattr(sv, "is_bottom", False)
        )
        constants = set(getattr(sv, "constants", ())) if usable else set()
        if len(constants) == 1:
            state = next(iter(constants))
            target, is_ret = _classify(state)
            out.append(StateWriteTransition(pred, state, target, is_ret, arm))
        else:
            out.append(StateWriteTransition(pred, None, None, True, arm))
    return tuple(out)


def recover_state_write_transitions_via_multicell_fixpoint(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int,
) -> tuple[StateWriteTransition, ...]:
    """B1 shadow: source each back-edge's next state from the MULTI-CELL fixpoint.

    Step C2/B1 of the S4 flip (ticket llr-kz7n).  The single-cell
    :func:`recover_state_write_transitions_via_fixpoint` tracks only the state slot
    and so emits ``(None, None, True)`` for any back-edge whose write is an opaque
    ``state = reg_a ^ reg_b`` / ``sub`` fold — the register operands it needs are not
    in its store.  This variant runs the existing global stk+reg exact-constant
    fixpoint (:func:`run_snapshot_constant_fixpoint`, whose transfer is the SAME
    :func:`_transfer_snapshot_constant_block` the production fold uses) and reads the
    folded state-slot value out of each back-edge predecessor's converged ``out``
    store.  It is still **single-partition** (constants are MET across all incoming
    edges), so a back-edge whose register operands are set to *different* constants
    on different region paths still folds to ``⊥`` here and emits an unresolved
    return — that residual is the predecessor-partitioned (Case-2) case closed by the
    region-partitioned variant (B2).  Diagnostic only; mutates nothing.
    """
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    default = dispatcher.default_target

    # Same effective offset resolution + transfer as the production fold; only the
    # walk strategy (global fixpoint vs per-region) differs.
    effective_stkoff = _resolve_state_var_alias(flow_graph, disp, int(state_var_stkoff))
    fp = run_snapshot_constant_fixpoint(flow_graph, effective_stkoff)

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        value = fp.out_stk_maps.get(pred, {}).get(effective_stkoff)
        if value is not None:
            state = int(value) & 0xFFFFFFFF
            target, is_ret = _classify(state)
            out.append(StateWriteTransition(pred, state, target, is_ret, arm))
        else:
            out.append(StateWriteTransition(pred, None, None, True, arm))
    return tuple(out)


def recover_state_write_transitions_via_partitioned_fixpoint(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int,
    recover_terminal_tail: bool = False,
) -> tuple[StateWriteTransition, ...]:
    """B2 shadow: predecessor-partitioned multi-cell fold -> the Case-2 ``via_block`` split.

    Step C2/B2 of the S4 flip (ticket llr-kz7n).  The single-partition multi-cell
    fixpoint (:func:`recover_state_write_transitions_via_multicell_fixpoint`) MEETs
    constants across all incoming edges of a back-edge block, so an opaque
    ``state = reg_a ^ reg_b`` write whose register operands are set to *different*
    constants on different region paths folds to ``⊥`` there (the Case-2 residual).

    This variant reads the SAME global stk+reg fixpoint, but when a back-edge does
    not fold unambiguously it **partitions by immediate predecessor**: it applies the
    back-edge block's own transfer (:func:`_transfer_snapshot_constant_block`) to each
    immediate predecessor's converged OUT store *separately*, recovering the per-edge
    folded state.  When every incoming edge folds to its own single state, it emits
    the production ``via_block`` split — ``ipred -> route(state)`` bypassing the shared
    back-edge — mirroring :func:`recover_state_write_transitions`'s Case-2 branch and
    the per-region / immediate-predecessor keying of :func:`_resolve_back_edge_states`.
    Diagnostic only; mutates nothing.
    """
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    default = dispatcher.default_target
    effective_stkoff = _resolve_state_var_alias(flow_graph, disp, int(state_var_stkoff))
    fp = run_snapshot_constant_fixpoint(flow_graph, effective_stkoff)
    # Seeded per-region fold (additive fallback): the global meet collapses the
    # state var to bottom at the dispatcher join, so a masked-OR / state-reading
    # write (``state = (state & ~MASK) | M``, abc_or_dispatch) never folds via the
    # fixpoint. _resolve_back_edge_states seeds each region's entry with its
    # dispatch key, which makes that write fold to ``M``. Used ONLY for back-edges
    # the fixpoint leaves unresolved -- it never overrides a fixpoint result.
    seeded = _resolve_back_edge_states(
        flow_graph,
        dispatcher=dispatcher,
        state_var_stkoff=effective_stkoff,
        dispatcher_entry=disp,
        max_depth=_MAX_CORRIDOR_DEPTH,
    )

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    def _arm(block, succ_target: int) -> int | None:
        s = [int(x) for x in block.succs]
        return s.index(succ_target) if block.nsucc > 1 and succ_target in s else None

    if logger.debug_on:
        logger.debug(
            "partitioned_fixpoint: disp=%d preds=%s seeded_back_edges=%s",
            disp,
            sorted(int(p) for p in disp_block.preds),
            {k: sorted({s for v in m.values() for s in v}) for k, m in seeded.items()},
        )

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None

        value = fp.out_stk_maps.get(pred, {}).get(effective_stkoff)
        if value is not None:
            # Unambiguous global fold (the B1 case): redirect the back-edge itself.
            state = int(value) & 0xFFFFFFFF
            target, is_ret = _classify(state)
            out.append(
                StateWriteTransition(
                    pred, state, target, is_ret, arm,
                    proof=TransitionProof(_FIXPOINT_ORACLE, "global_fold", not is_ret),
                )
            )
            continue

        # Ambiguous: partition by immediate predecessor.  Apply the back-edge
        # block's transfer to each predecessor's OUT store separately and read the
        # per-edge folded state -- the same partitioning _resolve_back_edge_states
        # does by walking per region and keying on the immediate predecessor.
        edge_states: dict[int, int] = {}
        ambiguous = False
        for ip in sorted(int(p) for p in block.preds):
            ip_block = flow_graph.get_block(ip)
            if ip_block is None:
                ambiguous = True
                break
            out_stk, _ = _transfer_snapshot_constant_block(
                block,
                dict(fp.out_stk_maps.get(ip, {})),
                dict(fp.out_reg_maps.get(ip, {})),
                effective_stkoff,
            )
            ev = out_stk.get(effective_stkoff)
            if ev is None:
                ambiguous = True
                break
            edge_states[ip] = int(ev) & 0xFFFFFFFF

        distinct = set(edge_states.values())
        if not ambiguous and edge_states and len(distinct) > 1:
            # Predecessor-partitioned opaque split: emit one via_block redirect per
            # incoming edge, exactly like recover_state_write_transitions' Case-2.
            for ip, state in sorted(edge_states.items()):
                target, is_ret = _classify(state)
                ip_arm = _arm(flow_graph.get_block(int(ip)), pred)
                out.append(
                    StateWriteTransition(
                        int(ip), state, target, is_ret, ip_arm, via_block=pred,
                        proof=TransitionProof(
                            _FIXPOINT_ORACLE, "predecessor_partitioned", not is_ret
                        ),
                    )
                )
        elif not ambiguous and len(distinct) == 1:
            # Every edge agreed on one state -- a plain back-edge redirect.
            state = next(iter(distinct))
            target, is_ret = _classify(state)
            out.append(
                StateWriteTransition(
                    pred, state, target, is_ret, arm,
                    proof=TransitionProof(_FIXPOINT_ORACLE, "region_agreed", not is_ret),
                )
            )
        elif _emit_seeded_back_edge(
            out, seeded.get(pred, {}), pred, arm, flow_graph, _classify, _arm
        ):
            # The fixpoint could not fold this back-edge, but the seeded region
            # fold (masked-OR / state-reading write) resolved it.
            continue
        else:
            out.append(
                StateWriteTransition(
                    pred, None, None, True, arm,
                    proof=TransitionProof(_FIXPOINT_ORACLE, "unresolved", False),
                )
            )

    # Terminal-tail back-edges (Tigress decoy-exit shape): a state-write block
    # whose successor is a STOP/terminal (or otherwise never re-enters the
    # dispatcher) names its next state in the written const just as a normal
    # back-edge does, but it is NOT a dispatcher predecessor, so the loop above
    # never visits it and its valid transition is dropped (the legacy walk
    # misclassified it ``successor_kind="exit"``).  The transition is purely
    # ``block -> route(N)`` via the dispatch map -- walking successors is
    # unnecessary.  Recover it whenever the block's folded state routes to a real
    # handler; redirect its existing (terminal) successor edge onto that handler.
    #
    # INDIRECT-only (ticket llr-m9r4): this recovery is load-bearing for the
    # Tigress INDIRECT_JUMP decoy-exit shape (it kills a JUMPOUT) but ADDS
    # spurious terminal-tail transitions for equality-chain / switch profiles
    # (hodur, approov), which regressed their goldens.  Gated to the indirect
    # caller so non-indirect profiles get exactly their pre-change behavior.
    if recover_terminal_tail:
        out.extend(
            _recover_terminal_tail_transitions(
                flow_graph,
                fp,
                effective_stkoff,
                disp=disp,
                emitted=out,
                classify=_classify,
                arm_of=_arm,
            )
        )
    return tuple(out)


def _recover_terminal_tail_transitions(
    flow_graph,
    fp,
    effective_stkoff: int,
    *,
    disp: int,
    emitted: list,
    classify,
    arm_of,
) -> list[StateWriteTransition]:
    """Wire state-write blocks that route via the dispatch map but never re-enter
    the dispatcher (their successor is a STOP/terminal).

    Driven entirely by the dispatch map: a block whose converged out-state is a
    valid handler route (not return/default/STOP) is a legitimate transition
    ``block -> route(N)`` regardless of its ``successor_kind``.  Only blocks that
    (a) are not already emitted as a source/inner-predecessor, (b) are not
    dispatcher predecessors, and (c) cannot reach the dispatcher through their
    successor chain are considered -- so interior fall-throughs into a shared
    glue back-edge (handled by the predecessor-partitioned ``via_block`` split)
    are never double-wired.
    """
    already: set[int] = {int(t.write_block) for t in emitted}
    extra: list[StateWriteTransition] = []
    for serial in sorted(flow_graph.blocks):
        if serial == disp or int(serial) in already:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp in succs:
            continue  # a real dispatcher predecessor -- handled above
        value = fp.out_stk_maps.get(serial, {}).get(effective_stkoff)
        if value is None:
            continue
        state = int(value) & 0xFFFFFFFF
        target, is_ret = classify(state)
        if is_ret or target is None:
            continue  # not a real handler route -- leave as natural control flow
        if _reaches_dispatcher(flow_graph, serial, disp):
            continue  # interior write feeding a shared back-edge -- already wired
        # The block's successor is a terminal/non-dispatcher edge.  The emitter
        # redirects ``write_block -> dispatcher`` for a normal back-edge, but
        # this block points at its terminal successor, not the dispatcher.  Carry
        # that successor as ``via_block`` so the emitter re-points the existing
        # ``block -> successor`` edge onto the routed handler instead.
        if not succs:
            continue  # nothing to re-point (a true sink with no out-edge)
        old = succs[0]
        arm = arm_of(block, old)
        extra.append(
            StateWriteTransition(
                serial, state, target, False, arm, via_block=old,
                proof=TransitionProof(_FIXPOINT_ORACLE, "terminal_tail", True),
            )
        )
        already.add(int(serial))
    return extra


def _reaches_dispatcher(flow_graph, start: int, disp: int, *, bound: int = 64) -> bool:
    """``True`` if the dispatcher is forward-reachable from ``start`` (bounded)."""
    seen: set[int] = set()
    stack = [int(start)]
    steps = 0
    while stack and steps < bound:
        steps += 1
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        block = flow_graph.get_block(cur)
        if block is None:
            continue
        for s in block.succs:
            si = int(s)
            if si == disp:
                return True
            if si not in seen:
                stack.append(si)
    return False


def _emit_seeded_back_edge(
    out: list,
    edge_map: dict[int | None, set[int]],
    pred: int,
    arm: int | None,
    flow_graph,
    classify,
    arm_of,
) -> bool:
    """Append a seeded-fold transition for a back-edge, or return ``False``.

    ``edge_map`` is ``_resolve_back_edge_states[pred]`` (immediate-pred -> states).
    Mirrors the global/partitioned emit shape: a single agreed state -> a plain
    back-edge redirect; one distinct state per immediate predecessor -> the
    ``via_block`` split.  Returns ``True`` when a transition was appended.
    """
    all_states = {s for states in edge_map.values() for s in states}
    if len(all_states) == 1:
        state = next(iter(all_states))
        target, is_ret = classify(state)
        out.append(
            StateWriteTransition(
                pred, state, target, is_ret, arm,
                proof=TransitionProof(_FIXPOINT_ORACLE, "region_seeded", not is_ret),
            )
        )
        return True
    if all_states and all(
        ip is not None and len(states) == 1 for ip, states in edge_map.items()
    ):
        for ip, states in sorted(edge_map.items()):
            state = next(iter(states))
            target, is_ret = classify(state)
            ip_block = flow_graph.get_block(int(ip))
            ip_arm = arm_of(ip_block, pred) if ip_block is not None else None
            out.append(
                StateWriteTransition(
                    int(ip), state, target, is_ret, ip_arm, via_block=pred,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE, "region_seeded_partitioned", not is_ret
                    ),
                )
            )
        return True
    return False


def diff_back_edge_transitions(production, fixpoint) -> dict:
    """Per-back-edge agreement between the production fold and the fixpoint shadow.

    Keys on ``write_block``.  A production Case-2 split (``via_block`` set) keys on the
    inner predecessor the single-partition fixpoint never emits, so it is bucketed
    ``case2_opaque`` (the expected residual, not a regression).  Returns a summary +
    the mismatching rows (``write_block``, production ``(state, target, is_return)``,
    fixpoint ``(state, target, is_return)`` or ``None``).
    """
    fmap = {t.write_block: t for t in fixpoint}
    matched = 0
    case2_opaque = 0
    mismatch: list = []
    for t in production:
        if t.via_block is not None:
            case2_opaque += 1
            continue
        f = fmap.get(t.write_block)
        if (
            f is not None
            and f.next_state == t.next_state
            and f.target_handler == t.target_handler
            and f.is_return == t.is_return
        ):
            matched += 1
        else:
            mismatch.append(
                (
                    t.write_block,
                    (t.next_state, t.target_handler, t.is_return),
                    None
                    if f is None
                    else (f.next_state, f.target_handler, f.is_return),
                )
            )
    return {
        "prod_edges": len(production),
        "fixpoint_edges": len(fixpoint),
        "matched": matched,
        "case2_opaque": case2_opaque,
        "mismatch": mismatch,
    }


def diff_back_edge_transitions_partitioned(production, fixpoint) -> dict:
    """B2-aware per-back-edge agreement: also matches the Case-2 ``via_block`` splits.

    Unlike :func:`diff_back_edge_transitions` (which buckets every production
    ``via_block`` row as an unverified ``case2_opaque`` residual), this keys split
    rows on ``(write_block, via_block)`` so the predecessor-partitioned shadow
    (:func:`recover_state_write_transitions_via_partitioned_fixpoint`) is checked
    edge-for-edge against production.  A production split that the partitioned shadow
    reproduces (same ``next_state`` / ``target_handler`` / ``is_return``) counts as
    ``matched``; one it does not reproduce becomes ``case2_opaque`` (still residual);
    plain (non-split) rows behave exactly as in the single-partition diff.
    """

    def _key(t):
        return (t.write_block, t.via_block)

    fmap = {_key(t): t for t in fixpoint}
    matched = 0
    case2_opaque = 0
    mismatch: list = []
    for t in production:
        f = fmap.get(_key(t))
        agrees = (
            f is not None
            and f.next_state == t.next_state
            and f.target_handler == t.target_handler
            and f.is_return == t.is_return
        )
        if agrees:
            matched += 1
        elif t.via_block is not None:
            # Unreproduced predecessor-partitioned split -> still the Case-2 residual.
            case2_opaque += 1
        else:
            mismatch.append(
                (
                    t.write_block,
                    (t.next_state, t.target_handler, t.is_return),
                    None
                    if f is None
                    else (f.next_state, f.target_handler, f.is_return),
                )
            )
    return {
        "prod_edges": len(production),
        "fixpoint_edges": len(fixpoint),
        "matched": matched,
        "case2_opaque": case2_opaque,
        "mismatch": mismatch,
    }


@dataclass(frozen=True, slots=True)
class TransitionArm:
    """One outgoing edge of a handler.

    A handler with a single arm is an unconditional transition; multiple arms
    (distinct ``next_state``) are a conditional transition selected by
    ``branch_block``'s 2-way branch.
    """

    next_state: int | None       # folded next-state value (None => no write found)
    target_handler: int | None   # dispatcher route of next_state (None when unresolved)
    is_return: bool              # routes to exit/STOP, or no next-state at all
    branch_block: int | None     # the 2-way block that selected this arm (None => unconditional)
    write_block: int | None      # block whose state-var write produced next_state
    exit_block: int | None       # last block of the scanned path (the boundary)
    ordered_path: tuple[int, ...] = ()  # handler-local blocks visited (entry..exit)


@dataclass(frozen=True, slots=True)
class HandlerTransition:
    """All outgoing edges recovered for one handler block."""

    handler: int                 # handler entry block serial
    states: tuple[int, ...]      # representative states the dispatcher routes here
    arms: tuple[TransitionArm, ...]

    @property
    def is_conditional(self) -> bool:
        return len(self.arms) > 1


def _handler_entries(dispatcher) -> set[int]:
    """Distinct handler blocks the dispatcher routes to (excluding the default/exit)."""
    default = dispatcher.default_target
    return {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None and int(row.target) != (int(default) if default is not None else None)
    }


def _states_by_handler(dispatcher) -> dict[int, list[int]]:
    """Map handler block -> representative state values routed to it (one per row lo)."""
    out: dict[int, list[int]] = {}
    for row in getattr(dispatcher, "_rows", ()):
        if row.target is None:
            continue
        out.setdefault(int(row.target), []).append(int(row.lo))
    return out


def _scan_handler(
    flow_graph,
    entry: int,
    *,
    state_var_stkoff: int,
    dispatcher_entry_serial: int | None,
    handler_entries: set[int],
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> list[tuple[int | None, int | None, tuple[int, ...]]]:
    """Strictly handler-local forward scan from *entry*.

    Returns a list of ``(next_state, branch_block, ordered_path)`` — one entry
    per distinct terminal path.  ``next_state`` is the last folded state-var
    value on that path (``None`` if the handler writes no next-state).
    ``ordered_path`` is the blocks visited (entry..boundary), used downstream to
    pick the redirect source.  The scan stops at: the dispatcher entry, any
    *other* handler's entry block, or a STOP/terminal.
    """

    results: list[tuple[int | None, int | None, tuple[int, ...]]] = []
    # stack frames: (block, stk_map, reg_map, branch_block, visited, depth, path)
    stack: list[tuple[int, dict, dict, int | None, frozenset[int], int, tuple[int, ...]]] = [
        (int(entry), {}, {}, None, frozenset({int(entry)}), 0, (int(entry),))
    ]

    while stack:
        blk_serial, stk, reg, branch, visited, depth, path = stack.pop()
        block = flow_graph.get_block(blk_serial)
        if block is None:
            results.append((stk.get(state_var_stkoff), branch, path))
            continue

        # Fold this block's state-var write into the carried const env.
        nstk, nreg = _transfer_snapshot_constant_block(
            block, dict(stk), dict(reg), state_var_stkoff
        )
        running_state = nstk.get(state_var_stkoff)

        succs = tuple(int(s) for s in block.succs)

        def _is_boundary_succ(s: int) -> bool:
            if dispatcher_entry_serial is not None and s == int(dispatcher_entry_serial):
                return True
            if s in handler_entries and s != int(entry):
                return True
            succ_block = flow_graph.get_block(s)
            return _is_stop_block(succ_block)

        onward = [
            s
            for s in succs
            if s not in visited and not _is_boundary_succ(s)
        ]

        terminal = (
            not succs
            or _is_stop_block(block)
            or not onward
            or depth >= max_depth
        )
        if terminal:
            results.append((running_state, branch, path))
            continue

        # A 2-way block whose arms continue is a state-selecting branch.
        new_branch = branch if len(succs) < 2 else blk_serial
        for s in onward:
            stack.append(
                (s, nstk, nreg, new_branch, visited | {s}, depth + 1, path + (s,))
            )

    return results


def _classify_arm(
    next_state: int | None,
    branch_block: int | None,
    ordered_path: tuple[int, ...],
    *,
    dispatcher,
    flow_graph,
) -> TransitionArm:
    default = dispatcher.default_target
    exit_block = ordered_path[-1] if ordered_path else None
    target: int | None = None
    is_return = False
    if next_state is None:
        is_return = True
    else:
        routed = dispatcher.lookup(int(next_state) & 0xFFFFFFFF)
        if routed is None:
            is_return = True
        elif default is not None and int(routed) == int(default):
            target = int(routed)
            is_return = True
        elif _is_stop_block(flow_graph.get_block(int(routed))):
            target = int(routed)
            is_return = True
        else:
            target = int(routed)
    return TransitionArm(
        next_state=(int(next_state) & 0xFFFFFFFF) if next_state is not None else None,
        target_handler=target,
        is_return=is_return,
        branch_block=branch_block,
        write_block=exit_block,
        exit_block=exit_block,
        ordered_path=tuple(ordered_path),
    )


def recover_handler_transitions(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int | None = None,
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> tuple[HandlerTransition, ...]:
    """Recover each handler's outgoing transition(s) via the minimal model.

    Args:
        flow_graph: a :class:`d810.ir.flowgraph.FlowGraph` snapshot.
        dispatcher: an :class:`IntervalDispatcher` (state value -> handler block).
        state_var_stkoff: the dispatcher state variable's stack offset.
        dispatcher_entry_serial: the dispatcher block the handlers loop back to;
            used as a scan boundary.  Falls back to the dispatcher's most-routed
            block when not supplied is intentionally NOT done — callers should
            pass it.
        max_depth: corridor-scan bound.

    Returns:
        One :class:`HandlerTransition` per handler block, ordered by serial.
    """

    handler_entries = _handler_entries(dispatcher)
    states_by_handler = _states_by_handler(dispatcher)
    results: list[HandlerTransition] = []

    for handler in sorted(handler_entries):
        paths = _scan_handler(
            flow_graph,
            handler,
            state_var_stkoff=int(state_var_stkoff),
            dispatcher_entry_serial=dispatcher_entry_serial,
            handler_entries=handler_entries,
            max_depth=max_depth,
        )
        # Dedup arms by next_state: identical next-states on multiple paths are
        # the same edge (a degenerate branch), not a conditional.
        seen: dict[int | None, TransitionArm] = {}
        for next_state, branch_block, ordered_path in paths:
            key = (int(next_state) & 0xFFFFFFFF) if next_state is not None else None
            if key in seen:
                continue
            seen[key] = _classify_arm(
                next_state,
                branch_block,
                ordered_path,
                dispatcher=dispatcher,
                flow_graph=flow_graph,
            )
        arms = tuple(seen.values())
        # A multi-path handler whose arms all fold to the same state collapses to
        # one unconditional arm with no branch attribution.
        if len(arms) == 1:
            arms = (
                TransitionArm(
                    next_state=arms[0].next_state,
                    target_handler=arms[0].target_handler,
                    is_return=arms[0].is_return,
                    branch_block=None,
                    write_block=arms[0].write_block,
                    exit_block=arms[0].exit_block,
                    ordered_path=arms[0].ordered_path,
                ),
            )
        results.append(
            HandlerTransition(
                handler=int(handler),
                states=tuple(sorted(states_by_handler.get(int(handler), ()))),
                arms=arms,
            )
        )

    return tuple(results)
