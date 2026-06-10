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
    HandlerTransition,
    StateWriteTransition,
    recover_handler_transitions,
    recover_state_write_transitions_via_partitioned_fixpoint,
)
from d810.core import logging
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.plan import PatchPlan, compile_patch_plan

logger = logging.getLogger("D810.transforms.minimal_unflatten_emit")

__all__ = [
    "emit_minimal_unflatten",
    "build_state_write_redirects",
    "build_conditional_arm_redirects",
]


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


def _existing_redirect_keys(mods: list[object]) -> set[tuple[int, int]]:
    """``(from_serial, old_target)`` of every redirect already planned.

    Keyed on *source edge* (not target) so the conditional-arm pass never
    re-points an edge the back-edge model already resolved -- it only fills in
    edges the back-edge model left pointing at the dispatcher.
    """
    keys: set[tuple[int, int]] = set()
    for m in mods:
        if isinstance(m, (RedirectGoto, RedirectBranch)):
            keys.add((int(m.from_serial), int(m.old_target)))
    return keys


def _existing_redirect_sources(mods: list[object]) -> set[int]:
    """``from_serial`` of every redirect already planned by the back-edge model.

    A conditional handler whose two arms reach the dispatcher through *distinct*
    per-arm glue blocks (each its own dispatcher predecessor) is already fully
    resolved by the back-edge / predecessor-partitioned model: each glue block is
    redirected ``glue -> route(arm.next_state)``.  The branch-anchored fall-through
    redirect this pass would otherwise add for the shared-EXIT case is then both
    redundant and harmful -- it retargets the selecting branch's *fall-through*
    edge, which the 2-way ``BLOCK_TARGET_CHANGE`` backend cannot express (it
    retargets only the conditional jump arm), severing the fall-through arm to the
    shared return.  Recognising the per-arm glue block as an existing redirect
    source lets the pass defer to the back-edge model that already wired it.
    """
    return {
        int(m.from_serial)
        for m in mods
        if isinstance(m, (RedirectGoto, RedirectBranch))
    }


def _arm_branch_successor(arm) -> int | None:
    """The block ``branch_block`` flows to *on this arm's path*.

    For a conditional handler whose two arms share one back-edge write block, the
    selecting 2-way branch is upstream at ``arm.branch_block`` and the arms differ
    only in which successor of that branch they take.  ``ordered_path`` is the
    handler-local block sequence (entry..exit); the block immediately after
    ``branch_block`` in the path is the successor edge this arm owns.
    """
    branch = arm.branch_block
    path = arm.ordered_path
    if branch is None or not path:
        return None
    try:
        idx = path.index(int(branch))
    except ValueError:
        return None
    if idx + 1 >= len(path):
        return None
    return int(path[idx + 1])


def build_conditional_arm_redirects(
    flow_graph,
    dispatcher,
    handler_transitions: tuple[HandlerTransition, ...],
    *,
    dispatcher_entry_serial: int | None,
    existing: set[tuple[int, int]],
    existing_sources: set[int] | None = None,
    is_indirect: bool = False,
) -> list[object]:
    """Emit per-arm redirects for conditional handlers, anchored on the branch.

    The back-edge model (:func:`build_state_write_redirects`) anchors on the
    dispatcher's predecessors and resolves each as a single ``write_block ->
    route(state)`` edge.  When a handler 2-way-branches to two distinct
    next-states *through a single shared back-edge write block* (the OLLVM
    conditional-state shape: ``state = select(cond, A, B)`` lowered as
    ``branch_block`` selecting two arms that converge on one write block), the
    global fold of that shared block collapses to the handler's OWN incoming
    state -> ``route`` is the handler itself -> a self-loop / 2-cycle, dropping
    BOTH real arms.  The recovered graph then fragments and forward reachability
    collapses (the ``5/44`` symptom).

    :func:`recover_handler_transitions` carries the full multi-arm model
    (``HandlerTransition.arms``), each arm naming the selecting ``branch_block``,
    the path it takes, and its (correctly per-path-folded) ``next_state``.  For a
    conditional handler this pass redirects the SELECTING BRANCH's two successor
    edges -- ``branch_block -> arm_succ`` re-pointed onto ``route(arm.next_state)``
    -- bypassing the shared write block entirely.  Control flow now leaves the
    handler's branch straight to each correct next handler; the dead shared state
    write is DCE'd with the dispatcher.

    When a conditional handler's arms instead live on *distinct* write blocks
    (each its own dispatcher predecessor), the back-edge model already resolves
    both correctly; two vetoes keep this pass from touching them: the ``existing``
    veto (keyed on the source edge) skips an edge already redirected, and the
    ``existing_sources`` veto skips a shared-EXIT branch redirect whose per-arm
    glue block (``_arm_branch_successor``) is already a back-edge redirect source.
    The second veto is what keeps the pass from severing a fall-through arm whose
    glue block the predecessor-partitioned model already wired (Tigress
    ``local_state & 1``).  Strictly additive: only emits edges the back-edge model
    did not.

    INDIRECT-only (ticket llr-m9r4): the ``existing_sources`` shared-EXIT veto is
    gated behind ``is_indirect``.  It recovered the Tigress INDIRECT_JUMP switch
    but skipped a legitimate redirect on equality-chain / switch profiles (hodur),
    regressing their goldens.  When ``is_indirect`` is False this pass behaves
    exactly as before the gap2 change (only the ``existing`` source-edge veto
    applies inside ``_add``).
    """
    disp = int(dispatcher_entry_serial) if dispatcher_entry_serial is not None else None
    if disp is None:
        return []
    default_target = dispatcher.default_target
    sources = existing_sources if existing_sources is not None else set()
    mods: list[object] = []
    seen: set[tuple[str, int, int, int]] = set()

    def _add(src: int, old: int, new: int | None) -> None:
        if new is None or int(old) == int(new):
            return
        if (int(src), int(old)) in existing:
            return  # back-edge model owns this source edge
        src_block = flow_graph.get_block(int(src))
        if src_block is None:
            return
        two_way = src_block.nsucc == 2
        key = ("B" if two_way else "G", int(src), int(old), int(new))
        if key in seen:
            return
        seen.add(key)
        if two_way:
            mods.append(
                RedirectBranch(from_serial=int(src), old_target=int(old), new_target=int(new))
            )
        else:
            mods.append(
                RedirectGoto(from_serial=int(src), old_target=int(old), new_target=int(new))
            )

    for handler in handler_transitions:
        if not handler.is_conditional:
            continue
        write_blocks = {int(a.write_block) for a in handler.arms if a.write_block is not None}
        shared_write_block = len(write_blocks) == 1
        for arm in handler.arms:
            new = default_target if arm.is_return else arm.target_handler
            if shared_write_block and arm.branch_block is not None:
                # Both arms reach the dispatcher through one *shared exit* block
                # (``arm.write_block`` is the scan boundary, not the state-write
                # site).  When each arm flows through its OWN per-arm glue block
                # -- a distinct dispatcher predecessor the back-edge /
                # predecessor-partitioned model already split (``glue ->
                # route(next_state)``) -- the branch-anchored redirect is both
                # redundant and harmful: it retargets the selecting branch's
                # *fall-through* edge, which ``BLOCK_TARGET_CHANGE`` cannot express
                # (it retargets only the conditional jump arm), severing the
                # fall-through arm to the shared return and orphaning the real
                # next handler (the Tigress ``local_state & 1`` ODD-arm drop).
                # Defer to the back-edge model whenever it already wired this
                # arm's glue block.
                # INDIRECT-only (ticket llr-m9r4): the shared-EXIT ``existing_sources``
                # veto recovered the Tigress ``local_state & 1`` switch but skipped a
                # legitimate redirect for equality-chain / switch profiles (hodur),
                # regressing their goldens.  Gate the shared-EXIT skip to the indirect
                # caller; non-indirect profiles fall back to the original ``existing``
                # veto inside ``_add`` exactly as before the gap2 change.
                old = _arm_branch_successor(arm)
                if is_indirect and old is not None and int(old) in sources:
                    continue
                if old is not None:
                    _add(int(arm.branch_block), int(old), new)
                continue
            # Distinct write blocks per arm: each is its own dispatcher
            # predecessor; only fill in arms the back-edge model left unredirected.
            wb = arm.write_block
            if wb is None:
                continue
            wb_block = flow_graph.get_block(int(wb))
            if wb_block is None or disp not in tuple(int(s) for s in wb_block.succs):
                continue
            _add(int(wb), disp, new)
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
    is_indirect: bool = False,
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
        recover_terminal_tail=is_indirect,
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
    # Conditional/multi-arm transitions (ticket llr-aga1): the back-edge model
    # above emits one redirect per dispatcher predecessor and collapses a
    # 2-way-branching handler onto a single next-state, fragmenting the recovered
    # graph into disconnected cycles (the ``5/44`` reachability symptom). The
    # per-handler multi-arm model (recover_handler_transitions) recovers BOTH
    # arms; emit the missing arm redirects additively, vetoed on any source edge
    # the back-edge model already resolved so the unconditional case stays
    # byte-identical.
    handler_transitions = recover_handler_transitions(
        flow_graph,
        dispatcher,
        int(state_var_stkoff),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    arm_mods = build_conditional_arm_redirects(
        flow_graph,
        dispatcher,
        handler_transitions,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        existing=_existing_redirect_keys(mods),
        existing_sources=_existing_redirect_sources(mods),
        is_indirect=is_indirect,
    )
    if arm_mods:
        mods = list(mods) + arm_mods
    if logger.info_on:
        n_cond = sum(1 for h in handler_transitions if h.is_conditional)
        logger.info(
            "s1a minimal unflatten: conditional_handlers=%d arm_redirects_added=%d",
            n_cond,
            len(arm_mods),
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
