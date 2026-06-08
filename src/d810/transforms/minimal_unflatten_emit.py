"""Direct unflatten emission from the interval-set graph (epic d81-jfg2).

No ``StateDag`` materialization: the interval-set dispatcher (state -> handler)
plus :func:`recover_state_write_transitions` (dispatcher back-edge -> folded
next-state) *is* the state-transition graph.  This module walks that graph and
emits the CFG redirects that bypass the dispatcher.

The transition points are the dispatcher's **predecessors** — every block that
writes the state variable then re-enters the comparison tree.  For each such
back-edge ``P`` writing state ``S``, re-point ``P -> dispatcher`` onto
``route(S)`` (the routed handler), or onto the dispatcher's default
(shared-return) block when ``S`` routes to the exit/STOP/default.  The function
prologue's dispatcher edge is bridged to ``route(initial_state)``.

Anchoring on back-edges (not on the dispatcher's routed *targets*) is robust to
OLLVM handlers that share suffixes or chain through one another's entry blocks:
those interior fall-throughs are left as natural control flow and only the
dispatcher back-edge is rewritten.  Once every back-edge is re-pointed, the
dispatcher block becomes unreachable and IDA DCEs it (with the state-var writes,
whose only reader was the dispatcher comparison).  Explicit state-var DSE is
therefore not emitted here unless a later verification shows residual reads.

Portable transforms-layer: consumes a ``FlowGraph`` + ``IntervalDispatcher``;
emits ``GraphModification`` values compiled to a ``PatchPlan``.
"""
from __future__ import annotations

from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    recover_state_write_transitions_via_partitioned_fixpoint,
)
from d810.core import logging
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.plan import PatchPlan, compile_patch_plan

logger = logging.getLogger("D810.transforms.minimal_unflatten_emit")

__all__ = ["emit_minimal_unflatten", "build_state_write_redirects"]


def build_state_write_redirects(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    *,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
) -> list[object]:
    """Build the redirect modifications that linearize the interval-set graph.

    One redirect per dispatcher back-edge: ``P -> dispatcher`` becomes
    ``P -> route(state_written_by_P)`` (or ``-> default`` when the state routes
    to the exit).  Prologue back-edges are excluded here and handled by the
    entry bridge so the function entry is never sent to the shared-return block.
    """
    mods: list[object] = []
    seen: set[tuple[str, int, int, int]] = set()
    default_target = dispatcher.default_target
    disp = int(dispatcher_entry_serial) if dispatcher_entry_serial is not None else None

    def _add(src: int, old: int, new: int | None, *, two_way: bool) -> None:
        if new is None or int(old) == int(new):
            return
        key = ("B" if two_way else "G", int(src), int(old), int(new))
        if key in seen:
            return
        seen.add(key)
        if two_way:
            mods.append(RedirectBranch(from_serial=int(src), old_target=int(old), new_target=int(new)))
        else:
            mods.append(RedirectGoto(from_serial=int(src), old_target=int(old), new_target=int(new)))

    # Prologue dispatcher edges are bridged to route(initial_state); their own
    # state write (the initial state) would route there anyway, but routing them
    # via the bridge keeps the function-entry path explicit and avoids ever
    # redirecting the entry to the shared-return block.
    prologue_preds: set[int] = set()
    if disp is not None:
        prologue_preds = {
            int(p)
            for p in _dispatcher_entry_preds(
                flow_graph, disp, pre_header_hint=pre_header_serial
            )
        }

    if disp is not None:
        for transition in transitions:
            src = int(transition.write_block)
            if src in prologue_preds:
                continue  # handled by the entry bridge below
            # ``via_block`` set => bypass a shared (pure state-glue) back-edge:
            # redirect ``src -> via_block`` onto the routed handler.  Otherwise
            # sever ``src -> dispatcher``.
            old = int(transition.via_block) if transition.via_block is not None else disp
            new = default_target if transition.is_return else transition.target_handler
            src_block = flow_graph.get_block(src)
            if src_block is None:
                continue
            _add(src, old, new, two_way=(src_block.nsucc == 2))

    # Entry bridge: prologue blocks that fall into the dispatcher -> route(initial).
    if initial_state is not None and disp is not None:
        first = dispatcher.lookup(int(initial_state) & 0xFFFFFFFF)
        if first is not None:
            for entry_pred in sorted(prologue_preds):
                epblk = flow_graph.get_block(int(entry_pred))
                if epblk is None:
                    continue
                _add(int(entry_pred), disp, int(first), two_way=(epblk.nsucc == 2))

    return mods


def _recover_initial_state(
    flow_graph,
    transitions: tuple[StateWriteTransition, ...],
    dispatcher_entry_serial: int,
    pre_header_serial: int | None,
) -> int | None:
    """Derive the initial dispatcher state from the prologue's state-write fold.

    The prologue (function entry -> dispatcher, no back-edge) is a dispatcher
    predecessor, so :func:`recover_state_write_transitions` already folded its
    next-state. Identify the prologue structurally (reachable from the function
    entry without passing through the dispatcher) and return its resolved,
    non-return next-state -- the state the function is in on first dispatch.
    Matches both a direct write (``write_block``) and a bypassed pure-glue
    prologue (``via_block``). Returns None when the prologue state did not fold.
    """
    prologue_preds = {
        int(p)
        for p in _dispatcher_entry_preds(
            flow_graph, dispatcher_entry_serial, pre_header_hint=pre_header_serial
        )
    }
    if not prologue_preds:
        return None
    for t in transitions:
        if t.next_state is None or t.is_return:
            continue
        wb = int(t.write_block)
        vb = int(t.via_block) if t.via_block is not None else None
        if wb in prologue_preds or (vb is not None and vb in prologue_preds):
            return int(t.next_state)
    return None


def _dispatcher_entry_preds(
    flow_graph,
    dispatcher_entry_serial: int,
    *,
    pre_header_hint: int | None = None,
) -> list[int]:
    """Dispatcher predecessors reached from the function entry *without* passing
    through the dispatcher — i.e. the prologue entry paths, not handler
    back-edges.  Computed by forward reachability from ``flow_graph.entry_serial``
    with the dispatcher removed."""
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return [pre_header_hint] if pre_header_hint is not None else []
    disp_preds = {int(p) for p in disp_block.preds}
    if not disp_preds:
        return []

    entry = getattr(flow_graph, "entry_serial", None)
    if entry is None:
        return [pre_header_hint] if pre_header_hint is not None else []

    # BFS from the function entry, never entering the dispatcher.
    seen: set[int] = set()
    stack = [int(entry)]
    while stack:
        s = stack.pop()
        if s in seen or s == disp:
            continue
        seen.add(s)
        blk = flow_graph.get_block(s)
        if blk is None:
            continue
        for succ in blk.succs:
            si = int(succ)
            if si != disp and si not in seen:
                stack.append(si)

    entries = sorted(p for p in disp_preds if p in seen)
    if not entries and pre_header_hint is not None:
        entries = [int(pre_header_hint)]
    return entries


def emit_minimal_unflatten(
    flow_graph,
    dispatcher,
    *,
    state_var_stkoff: int,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None = None,
    initial_state: int | None = None,
) -> PatchPlan:
    """Recover back-edge transitions and emit the dispatcher-bypass ``PatchPlan``.

    The whole unflatten in one pass: ``recover_state_write_transitions`` over the
    dispatcher's predecessors, then :func:`build_state_write_redirects`, compiled
    to a ``PatchPlan``.  No ``StateDag``.
    """
    if dispatcher_entry_serial is None:
        return compile_patch_plan([], flow_graph)
    # S4 C3 flip (ticket llr-1szn): the back-edge next-states now come from the sound
    # region-partitioned multi-cell fixpoint (run_snapshot_constant_fixpoint, the SAME
    # _transfer_snapshot_constant_block transfer) instead of the ad-hoc per-region walk
    # in _resolve_back_edge_states. Proven byte-identical by the C1/B shadow-diff
    # (diff==0 on hodur 15/15 + sub_7FFD 78/78); the cff probe still diffs the two as a
    # standing equivalence guard.
    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        flow_graph,
        dispatcher,
        int(state_var_stkoff),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    # C3b (ticket llr-1szn / d81-t9ok): each transition carries a typed
    # ``TransitionProof`` naming the oracle and resolution shape. Observe-only --
    # the distribution surfaces how many edges resolved by global fold vs the
    # opaque-split / unresolved residual, feeding the fact/proof layer (llr-fqam)
    # without changing recovery (the diff compares states, never proof).
    if logger.info_on:
        kinds: dict[str, int] = {}
        for t in transitions:
            key = t.proof.kind if t.proof is not None else "unattributed"
            kinds[key] = kinds.get(key, 0) + 1
        logger.info(
            "s1a minimal unflatten: %d back-edge transitions, proof kinds=%s",
            len(transitions),
            dict(sorted(kinds.items())),
        )
    # Recover the initial state from the prologue's own state-write fold when the
    # caller could not supply it. The comparison-BST evidence collapses to a
    # single catch-all on a wide equality chain (OLLVM -fla), so
    # ``bst_evidence.initial_state`` is None -- but the prologue is a dispatcher
    # predecessor too, so its folded next-state (already in ``transitions``) IS
    # the initial state. Without it the entry bridge is skipped and removing the
    # dispatcher orphans every handler.
    if initial_state is None:
        initial_state = _recover_initial_state(
            flow_graph,
            transitions,
            int(dispatcher_entry_serial),
            pre_header_serial,
        )
    # Safety: the entry bridge is REQUIRED for correctness. Removing the
    # dispatcher orphans every handler unless the function-entry path is bridged
    # to ``route(initial_state)``. When a prologue exists but that bridge cannot
    # be established -- the initial state was not recovered, or it routes nowhere
    # -- bail and leave the function intact rather than gut it. This fires when
    # state-var detection picked a current-state SHADOW slot (OLLVM -fla writes
    # the next state to one stack slot and a copy of the current state to
    # another; choosing the shadow makes every handler self-loop and hides the
    # prologue's real initial-state write). Better a flattened function than a
    # destroyed one. See ticket for the state-var disambiguation fix.
    if dispatcher_entry_serial is not None:
        prologue_preds = _dispatcher_entry_preds(
            flow_graph, int(dispatcher_entry_serial), pre_header_hint=pre_header_serial
        )
        if prologue_preds:
            bridged = (
                initial_state is not None
                and dispatcher.lookup(int(initial_state) & 0xFFFFFFFF) is not None
            )
            if not bridged:
                if logger.info_on:
                    logger.info(
                        "s1a minimal unflatten: BAILED (no entry bridge: "
                        "initial_state=%s) -- leaving function intact",
                        initial_state,
                    )
                return compile_patch_plan([], flow_graph)
    mods = build_state_write_redirects(
        flow_graph,
        dispatcher,
        transitions,
        dispatcher_entry_serial=dispatcher_entry_serial,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
    )
    if logger.info_on:
        n_return = sum(1 for t in transitions if t.is_return)
        n_unresolved = sum(1 for t in transitions if t.next_state is None)
        reached, total, unreached = _reachability(
            flow_graph, dispatcher, mods, int(dispatcher_entry_serial)
        )
        logger.info(
            "s1a minimal unflatten: back_edges=%d return_edges=%d unresolved=%d "
            "redirects=%d reachable_handlers=%d/%d unreached=%s",
            len(transitions),
            n_return,
            n_unresolved,
            len(mods),
            reached,
            total,
            ",".join("blk%d" % b for b in unreached[:20]),
        )
    return compile_patch_plan(list(mods), flow_graph)


def _reachability(flow_graph, dispatcher, mods, dispatcher_entry_serial):
    """Faithful post-redirect reachability: apply the redirects to the CFG, then
    BFS from the function entry with the (now-bypassed) dispatcher removed.

    A dispatcher target (handler entry) that is NOT reached here will be DCE'd by
    IDA once the dispatcher is gone -- i.e. its real work is dropped. Returns
    ``(reached_handler_count, total_handler_count, sorted_unreached_handlers)``.
    """
    rewired: dict[int, list[int]] = {}
    for serial in flow_graph.blocks:
        blk = flow_graph.get_block(serial)
        rewired[int(serial)] = [int(s) for s in (blk.succs if blk is not None else ())]
    for m in mods:
        src = int(m.from_serial)
        old = int(m.old_target)
        new = int(m.new_target)
        succ = rewired.get(src)
        if succ and old in succ:
            succ[succ.index(old)] = new

    disp = int(dispatcher_entry_serial)
    entry = int(getattr(flow_graph, "entry_serial", 0) or 0)
    seen: set[int] = set()
    stack = [entry]
    while stack:
        b = stack.pop()
        if b in seen or b == disp:
            continue
        seen.add(b)
        for s in rewired.get(b, ()):
            if s not in seen and s != disp:
                stack.append(s)

    handlers = {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None
    }
    handlers.discard(disp)
    reached = sorted(h for h in handlers if h in seen)
    unreached = sorted(h for h in handlers if h not in seen)
    return len(reached), len(handlers), unreached
