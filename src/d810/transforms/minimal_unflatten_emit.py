"""Direct unflatten emission from the interval-set graph (epic d81-jfg2).

No ``StateDag`` materialization: the interval-set dispatcher (state -> handler)
plus :func:`recover_handler_transitions` (handler -> folded next-state(s)) *is*
the state-transition graph.  This module walks that graph and emits the CFG
redirects that bypass the dispatcher:

  * per handler arm: re-point the handler's exit off the dispatcher onto the
    routed target handler (own-exit) or, for a shared MBA suffix, the
    handler-owned predecessor (bypass the shared block);
  * terminal arms (next-state routes to the exit) -> the dispatcher's default
    (shared-return) block;
  * one entry bridge: pre-header -> route(initial_state).

Once every handler arm is re-pointed and the entry is bridged, the dispatcher
block becomes unreachable and IDA DCEs it (with the state-var writes, whose
only reader was the dispatcher comparison).  Explicit state-var DSE is therefore
not emitted here unless a later verification shows residual reads.

Portable transforms-layer: consumes a ``FlowGraph`` + ``IntervalDispatcher``;
emits ``GraphModification`` values compiled to a ``PatchPlan``.
"""
from __future__ import annotations

from d810.analyses.control_flow.minimal_state_recovery import (
    HandlerTransition,
    recover_handler_transitions,
)
from d810.core import logging
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.plan import PatchPlan, compile_patch_plan

logger = logging.getLogger("D810.transforms.minimal_unflatten_emit")

__all__ = ["emit_minimal_unflatten", "build_minimal_redirects"]


def _redirect_target_edge(
    flow_graph,
    arm,
    dispatcher_entry_serial: int | None,
) -> tuple[int, int] | None:
    """Return ``(source_block, old_target)`` for re-pointing *arm* off the dispatcher.

    Own-exit handler (``S -> dispatcher``): re-point ``S``.  Shared MBA suffix
    (``S`` multi-predecessor): re-point the handler-owned predecessor ``P`` of
    ``S`` (``P -> S``) so the shared block is bypassed and stays valid for the
    other handlers until they too bypass it.
    """
    path = arm.ordered_path
    if not path:
        return None
    s = int(path[-1])
    sblk = flow_graph.get_block(s)
    if sblk is None:
        return None
    succs = [int(x) for x in sblk.succs]
    # The boundary edge we are severing: the dispatcher re-entry if present.
    if dispatcher_entry_serial is not None and int(dispatcher_entry_serial) in succs:
        boundary = int(dispatcher_entry_serial)
    elif succs:
        boundary = succs[0]
    else:
        return None
    # Shared suffix: bypass it by re-pointing the owned predecessor on the path.
    if sblk.npred > 1 and len(path) >= 2:
        return (int(path[-2]), s)
    return (s, boundary)


def build_minimal_redirects(
    flow_graph,
    dispatcher,
    transitions: tuple[HandlerTransition, ...],
    *,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
) -> list[object]:
    """Build the redirect modifications that linearize the interval-set graph."""
    mods: list[object] = []
    seen: set[tuple[str, int, int, int]] = set()
    default_target = dispatcher.default_target

    def _add(src: int, old: int, new: int, *, two_way: bool) -> None:
        key = ("B" if two_way else "G", int(src), int(old), int(new))
        if key in seen or int(old) == int(new):
            return
        seen.add(key)
        if two_way:
            mods.append(RedirectBranch(from_serial=int(src), old_target=int(old), new_target=int(new)))
        else:
            mods.append(RedirectGoto(from_serial=int(src), old_target=int(old), new_target=int(new)))

    for transition in transitions:
        for arm in transition.arms:
            edge = _redirect_target_edge(flow_graph, arm, dispatcher_entry_serial)
            if edge is None:
                continue
            src, old = edge
            if arm.is_return:
                new = default_target
            else:
                new = arm.target_handler
            if new is None:
                continue
            src_block = flow_graph.get_block(int(src))
            if src_block is None:
                continue
            _add(src, old, int(new), two_way=(src_block.nsucc == 2))

    # Entry bridge: every block that reaches the dispatcher from the function
    # prologue (i.e. NOT a handler back-edge) sets the initial state and falls
    # into the dispatcher; re-point each straight at the first handler so the
    # dispatcher's comparison tree becomes unreachable (and IDA DCEs it). Handler
    # back-edges are already severed above; shared MBA suffixes are reached only
    # via handlers, so they are correctly excluded by the entry-reachability set.
    if initial_state is not None and dispatcher_entry_serial is not None:
        first = dispatcher.lookup(int(initial_state) & 0xFFFFFFFF)
        if first is not None:
            for entry_pred in _dispatcher_entry_preds(
                flow_graph,
                int(dispatcher_entry_serial),
                pre_header_hint=pre_header_serial,
            ):
                epblk = flow_graph.get_block(int(entry_pred))
                if epblk is None:
                    continue
                _add(
                    int(entry_pred),
                    int(dispatcher_entry_serial),
                    int(first),
                    two_way=(epblk.nsucc == 2),
                )

    return mods


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
    """Recover handler transitions and emit the dispatcher-bypass ``PatchPlan``.

    The whole unflatten in one pass: ``recover_handler_transitions`` over the
    interval-set dispatcher, then :func:`build_minimal_redirects`, compiled to a
    ``PatchPlan``.  No ``StateDag``.
    """
    transitions = recover_handler_transitions(
        flow_graph,
        dispatcher,
        int(state_var_stkoff),
        dispatcher_entry_serial=dispatcher_entry_serial,
    )
    mods = build_minimal_redirects(
        flow_graph,
        dispatcher,
        transitions,
        dispatcher_entry_serial=dispatcher_entry_serial,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
    )
    if logger.info_on:
        n_cond = sum(1 for t in transitions for a in t.arms if a.branch_block is not None)
        logger.info(
            "s1a minimal unflatten: handlers=%d arms=%d conditional_arms=%d redirects=%d",
            len(transitions),
            sum(len(t.arms) for t in transitions),
            n_cond,
            len(mods),
        )
    return compile_patch_plan(list(mods), flow_graph)
