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

from d810.analyses.control_flow.state_machine_analysis import (
    _constant_dest_locator_snapshot,
    _eval_insn_view_snapshot,
    _is_stop_block,
    _transfer_snapshot_constant_block,
)

# Default bound on the handler-local corridor scan.  Real OLLVM handler bodies
# (entry -> work -> const-load -> shared MBA suffix -> dispatcher) are short; a
# small bound keeps the scan O(handler) and prevents runaway on malformed CFGs.
_MAX_CORRIDOR_DEPTH = 24

__all__ = [
    "TransitionArm",
    "HandlerTransition",
    "recover_handler_transitions",
    "StateWriteTransition",
    "recover_state_write_transitions",
    "recover_state_write_transitions_via_fixpoint",
    "diff_back_edge_transitions",
]


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

    # back-edge serial -> { immediate predecessor (None at a region head) -> states }.
    # Partitioning by the immediate predecessor recovers opaque ``state =
    # reg_a ^ reg_b`` writes whose register operands are set to *different*
    # constants on each incoming edge (the LiSA disjunctive / predecessor-
    # partitioned case): each edge folds to its own state instead of collapsing
    # to an ambiguous set.
    back_edge_states: dict[int, dict[int | None, set[int]]] = {}
    for start in sorted(region_entries):
        stack: list[tuple[int, dict, dict, frozenset[int], int, int | None]] = [
            (start, {}, {}, frozenset({start}), 0, None)
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
