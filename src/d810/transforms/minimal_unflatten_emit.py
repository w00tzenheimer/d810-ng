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
    block_has_live_carrier_write,
    recover_handler_transitions,
    recover_state_write_transitions_via_partitioned_fixpoint,
)
from d810.analyses.control_flow.state_machine_analysis import _is_stop_block
from d810.core import logging
from d810.transforms.graph_modification import (
    LowerConditionalStateTransition,
    RedirectBranch,
    RedirectGoto,
    SyntheticCounterBoundCondition,
)
from d810.transforms.plan import PatchPlan, compile_patch_plan
from d810.transforms.use_def_redirect_filter import (
    count_use_def_severances,
    filter_use_def_severing_redirects,
    severance_bail_enabled,
)

logger = logging.getLogger("D810.transforms.minimal_unflatten_emit")

__all__ = [
    "emit_minimal_unflatten",
    "build_state_write_redirects",
    "build_conditional_arm_redirects",
    "build_folded_loop_guard_lowerings",
]


def _carrier_return_via_routes(
    flow_graph,
    transitions: tuple[StateWriteTransition, ...],
    *,
    disp: int,
    state_var_stkoff: int | None,
    default_target: int | None,
) -> dict[int, int]:
    """Map each carrier-bearing shared ``via_block`` -> its single exit route.

    A predecessor-partitioned ``via_block`` is normally pure state-glue and the
    emitter bypasses it; but a conditional handler whose arms converge on one
    shared block can carry a LIVE non-state assignment (the Approov ``v4 = a1``
    carrier).  That carrier is the function's RETURN value -- live only on the arm
    whose state routes to the exit -- so the return must flow THROUGH the carrier
    block.  This identifies, for each such block, the single exit route to which it
    should be redirected (keeping the return arm's edge into it intact while the
    loop-continue arms bypass).

    A via_block qualifies only when: it is the canonical shared-glue shape (single
    successor == dispatcher), it carries a live non-state write, AND exactly one
    distinct exit route is needed across its return arms.  When no return arm
    exists, or the return arms route to two different exits, the block is omitted
    and falls back to the plain bypass (byte-identical to the pre-change path).
    Returns ``{}`` when ``state_var_stkoff`` is unknown.
    """
    if state_var_stkoff is None:
        return {}
    # via_block -> set of distinct return routes its live-carrier arms need.  The
    # carrier is the function's RETURN value, so the arm that must keep it is the
    # one whose route reaches an ACTUAL function return (a STOP terminal) -- NOT the
    # one whose ``is_return`` flag is set merely because it routes to the
    # dispatcher's default/gap target (which loops back; the Approov 0xF6A1E handler
    # doubles as the gap target so is_return is True there but it does not return).
    # ``_routes_to_function_return`` is the precise discriminator.
    candidate: dict[int, set[int]] = {}
    blocked: set[int] = set()
    for transition in transitions:
        vb = transition.via_block
        if vb is None:
            continue
        vbi = int(vb)
        if vbi in blocked:
            continue
        route = transition.target_handler
        if route is None and transition.is_return:
            route = default_target
        if route is None:
            continue  # unresolved arm -- leave to the bypass
        if not _routes_to_function_return(flow_graph, int(route), disp=int(disp)):
            continue  # a continue / default-gap arm, not a real return -- skip
        vb_block = flow_graph.get_block(vbi)
        if vb_block is None:
            blocked.add(vbi)
            candidate.pop(vbi, None)
            continue
        if tuple(int(s) for s in vb_block.succs) != (int(disp),):
            blocked.add(vbi)
            candidate.pop(vbi, None)
            continue
        if not block_has_live_carrier_write(vb_block, int(state_var_stkoff)):
            blocked.add(vbi)
            candidate.pop(vbi, None)
            continue
        candidate.setdefault(vbi, set()).add(int(route))
    return {
        vbi: next(iter(routes))
        for vbi, routes in candidate.items()
        if vbi not in blocked and len(routes) == 1
    }


def _routes_to_function_return(flow_graph, start: int, *, disp: int, bound: int = 16) -> bool:
    """``True`` if ``start`` reaches a STOP/return terminal without re-entering the
    dispatcher (a bounded forward walk).

    Distinguishes a real exit handler (reaches a function return) from the
    dispatcher's default/gap target, which routes back through the dispatcher and
    so loops rather than returning.  Used to pick the carrier-return arm: the
    carrier is the return value, so it must flow through the block whose route
    actually terminates the function.
    """
    seen: set[int] = set()
    stack = [int(start)]
    steps = 0
    while stack and steps < bound:
        steps += 1
        cur = stack.pop()
        if cur in seen or cur == disp:
            continue
        seen.add(cur)
        block = flow_graph.get_block(cur)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if not succs or _is_stop_block(block):
            return True  # a terminal/return reached
        for s in succs:
            if s == disp:
                # this path loops back to the dispatcher -- not a return path, but
                # other successors may still terminate, so keep scanning them.
                continue
            if s not in seen:
                stack.append(s)
    return False


def _return_redirect_target(
    flow_graph, target_handler: int | None, *, default_target: int | None
) -> int | None:
    """Pick the redirect target for a ``is_return`` back-edge.

    A return transition is ``_classify``'d True in three cases (see
    :func:`recover_state_write_transitions`):

    * the routed target IS the dispatcher's ``default_target`` (catch-all),
    * the routed target is an actual STOP/return block, or
    * the state is unresolved (``target_handler is None``).

    The historical emit collapsed all three onto ``default_target`` — correct for
    the hodur / approov shape where the catch-all default IS the function's
    return/STOP block.  But an OLLVM ``-fla`` chain routes its EXIT state via an
    EXPLICIT map row to a STOP block (``0xBFF7ACB5 -> 126``) while ``default_target``
    is a SEPARATE catch-all that loops back to the dispatcher; collapsing onto that
    catch-all stranded the terminal output write inside a ``while(1)`` (no exit
    edge, ``returns=0``).  When the routed ``target_handler`` is itself a STOP block
    DISTINCT from ``default_target``, redirect the back-edge straight onto that STOP
    so the function actually returns (ticket llr-gpt3).

    Behaviour-neutral for the existing corpus: when ``target_handler`` is None /
    equals ``default_target`` / is not a STOP block, this returns ``default_target``
    exactly as before.
    """
    if (
        target_handler is not None
        and (default_target is None or int(target_handler) != int(default_target))
        and _is_stop_block(flow_graph.get_block(int(target_handler)))
    ):
        return int(target_handler)
    return default_target


def build_state_write_redirects(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    *,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
    state_var_stkoff: int | None = None,
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

    # A predecessor-partitioned ``via_block`` is normally pure state-glue: the
    # emitter bypasses it (``src -> via_block`` re-pointed onto the routed handler)
    # and lets the orphaned block DCE.  But a conditional handler whose two arms
    # write the next state in separate blocks then *converge* on one shared block
    # can carry a LIVE non-state write on that shared block (the Approov ``v4 = a1``
    # carrier).  That carrier is the function's RETURN value: it is live only on the
    # arm whose state routes to the exit (the loop-continue arm overwrites it on the
    # next handler), and bypassing the shared block drops it, so the recovered
    # function returns the wrong value.  Keep the carrier on the RETURN path by
    # redirecting the shared block ITSELF onto the exit route (control still flows
    # ``return_pred -> via_block(carrier) -> exit``), while the loop-continue
    # predecessors bypass normally (their carrier copy is dead).  ``return_via``
    # maps a carrier via_block -> the single exit route its return arm needs; an
    # ambiguous via_block (no return arm, or two distinct return routes) is left to
    # the plain bypass exactly as before.
    return_via = (
        _carrier_return_via_routes(
            flow_graph,
            transitions,
            disp=disp,
            state_var_stkoff=state_var_stkoff,
            default_target=default_target,
        )
        if disp is not None
        else {}
    )
    emitted_via_self: set[int] = set()

    if disp is not None:
        for transition in transitions:
            src = int(transition.write_block)
            if src in prologue_preds:
                continue  # handled by the entry bridge below
            vb = transition.via_block
            # ``via_block`` set => bypass a shared (pure state-glue) back-edge:
            # redirect ``src -> via_block`` onto the routed handler.  Otherwise
            # sever ``src -> dispatcher``.
            old = int(vb) if vb is not None else disp
            new = (
                _return_redirect_target(
                    flow_graph,
                    transition.target_handler,
                    default_target=default_target,
                )
                if transition.is_return
                else transition.target_handler
            )
            # Carrier RETURN arm: the shared block ``vb`` carries the function's
            # return value (a live non-state write) and THIS arm's route reaches the
            # actual return.  Keep ``src -> vb`` intact (so the carrier executes) and
            # redirect ``vb``'s own dispatcher edge onto the return route once; the
            # other (loop-continue) arms bypass ``vb`` normally below.  Identified by
            # route equality with ``return_via`` rather than ``is_return`` (the real
            # return arm's routed handler is a work block whose is_return is False).
            if (
                vb is not None
                and int(vb) in return_via
                and new is not None
                and int(new) == int(return_via[int(vb)])
            ):
                vbi = int(vb)
                if vbi not in emitted_via_self:
                    emitted_via_self.add(vbi)
                    vb_block = flow_graph.get_block(vbi)
                    if vb_block is not None:
                        _add(
                            vbi, disp, int(return_via[vbi]),
                            two_way=(vb_block.nsucc == 2),
                        )
                continue  # the return_pred -> via_block edge stays intact
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
    carrier_via_blocks: set[int] | None = None,
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

    Carrier veto (ticket llr-mra1): when an arm's successor feeds a shared
    *carrier* via_block -- a block holding the function's live return value that
    the back-edge model keeps on the return path (see
    :func:`_carrier_return_via_routes`) -- ``_succ_reaches_carrier`` defers this
    branch-anchored redirect so the carrier is not bypassed.  ``carrier_via_blocks``
    is empty for every non-carrier shape, leaving those byte-identical.
    """
    disp = int(dispatcher_entry_serial) if dispatcher_entry_serial is not None else None
    if disp is None:
        return []
    default_target = dispatcher.default_target
    sources = existing_sources if existing_sources is not None else set()
    carriers = {int(b) for b in (carrier_via_blocks or ())}
    mods: list[object] = []
    seen: set[tuple[str, int, int, int]] = set()

    def _succ_reaches_carrier(succ: int) -> bool:
        """``True`` if the arm successor is a 1-way feeder into a carrier via_block.

        The carrier-preserving back-edge model owns the ``feeder -> via_block``
        edges of a shared carrier block: it keeps the return arm's edge intact (so
        the carrier write -- the function's return value -- executes) and bypasses
        the loop-continue feeders.  The branch-anchored redirect here would instead
        re-point the SELECTING branch straight past the feeder AND the carrier
        block, dropping the carrier on the return path -- so defer to the back-edge
        model whenever this arm's successor feeds a carrier via_block.
        """
        if not carriers:
            return False
        s_block = flow_graph.get_block(int(succ))
        if s_block is None:
            return False
        s_succs = tuple(int(x) for x in s_block.succs)
        return s_block.nsucc == 1 and s_succs and int(s_succs[0]) in carriers

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
                # Carrier-preserving back-edge split owns this arm: its successor
                # feeds a shared via_block that carries a live non-state write the
                # split clones.  A branch-anchored redirect here would bypass that
                # carrier block -- defer to the split.
                if old is not None and _succ_reaches_carrier(int(old)):
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


def build_folded_loop_guard_lowerings(
    flow_graph,
    dispatcher,
    transitions,
    fact_view,
    *,
    dispatcher_entry_serial: int,
):
    """Lower folded counted-loop guards into explicit ``if (i < N)`` 2-way edges.

    Hex-Rays folds the constant-trip-count guard of a counted accumulation loop
    to a constant branch and DCEs the body arm before the unflatten recovery maturity,
    so the back-edge model recovers the guard handler as a SELF-LOOP (it writes
    its own loop-header state) and the loop renders as an empty ``while (1);``.
    The :class:`FoldedLoopGuardFact` (observed at the earlier LOCOPT maturity and
    carried forward) names the surviving counter slot, the numeric bound, and the
    body/exit state constants, so we re-materialize the explicit guard:

        guard:  if (counter < bound) -> route(body_state) else -> route(exit_state)

    Returns ``(lowerings, suppressed_sources)``: the typed lowering steps and the
    set of guard ``from_serial`` redirects the caller must drop (the spurious
    self-loop the back-edge model emitted for the same block).  Strictly
    fact-gated -- emits nothing when no folded guard is observed, so non-loop
    indirect functions are unaffected.
    """
    if fact_view is None:
        return [], set()
    guards = getattr(fact_view, "folded_loop_guards", None)
    if callable(guards):
        guard_facts = tuple(guards())
    else:
        # ``ctx.facts`` is the ``AnalysisManager`` view, which forwards
        # ``active_observations`` but not the typed accessor. Filter the
        # carried-forward observations for the folded-guard kind directly.
        observations = getattr(fact_view, "active_observations", ())
        guard_facts = tuple(
            obs
            for obs in observations
            if getattr(obs, "kind", None) == "FoldedLoopGuardFact"
        )
    if not guard_facts:
        return [], set()

    disp = int(dispatcher_entry_serial)
    # Map guard EA -> the live guard handler block (serial is maturity-local, EA
    # is the stable cross-maturity key).
    serial_by_ea: dict[int, int] = {}
    for serial in flow_graph.blocks:
        blk = flow_graph.get_block(serial)
        if blk is not None:
            serial_by_ea[int(getattr(blk, "start_ea", -1))] = int(serial)

    # Self-loop guards the back-edge model produced (write_block routes to
    # itself) -- the folded-guard symptom we replace.
    self_loop_guards = {
        int(t.write_block)
        for t in transitions
        if t.target_handler is not None
        and int(t.target_handler) == int(t.write_block)
        and not t.is_return
    }

    lowerings: list[object] = []
    suppressed: set[int] = set()
    for fact in guard_facts:
        payload = fact.payload or {}
        guard_ea = payload.get("guard_ea")
        if guard_ea is None:
            continue
        guard_serial = serial_by_ea.get(int(guard_ea))
        if guard_serial is None or guard_serial not in self_loop_guards:
            continue
        body_state = payload.get("body_state")
        exit_state = payload.get("exit_state")
        counter_stkoff = payload.get("counter_stkoff")
        counter_reg = payload.get("counter_reg")
        bound = payload.get("bound")
        if None in (body_state, exit_state, bound):
            continue
        if counter_stkoff is None and counter_reg is None:
            continue
        body_target = dispatcher.lookup(int(body_state) & 0xFFFFFFFF)
        exit_target = dispatcher.lookup(int(exit_state) & 0xFFFFFFFF)
        if body_target is None or exit_target is None:
            continue
        guard_block = flow_graph.get_block(guard_serial)
        if guard_block is None or guard_block.nsucc != 1:
            continue
        if int(guard_block.succs[0]) != disp:
            continue  # guard must still flow only to the dispatcher
        # The backend removes instructions from ``rewrite_from_ea`` onward, so it
        # must be the EA of an actual live instruction in the guard block -- NOT
        # the block's nominal ``start_ea`` (which preserves the original handler
        # EA and may precede the first surviving instruction after folding).
        insns = getattr(guard_block, "insn_snapshots", ()) or ()
        if not insns:
            continue
        rewrite_ea = int(getattr(insns[0], "ea", 0) or 0)
        if rewrite_ea == 0:
            continue
        condition = SyntheticCounterBoundCondition(
            counter_stkoff=(
                int(counter_stkoff) if counter_stkoff is not None else None
            ),
            counter_reg=int(counter_reg) if counter_reg is not None else None,
            counter_size=int(payload.get("counter_size", 4) or 4),
            bound=int(bound),
            signed=bool(payload.get("signed", True)),
        )
        lowerings.append(
            LowerConditionalStateTransition(
                source_serial=int(guard_serial),
                old_dispatcher_serial=disp,
                rewrite_from_ea=rewrite_ea,
                condition_operand=condition,
                false_target_serial=int(exit_target),
                true_target_serial=int(body_target),
                proof_id=fact.fact_id,
                reason="folded_loop_guard",
            )
        )
        suppressed.add(int(guard_serial))
        if logger.info_on:
            counter_desc = (
                f"reg=0x{int(counter_reg):x}"
                if counter_reg is not None
                else f"stkoff=0x{int(counter_stkoff):x}"
            )
            logger.info(
                "unflat folded-loop-guard: blk[%d]@0x%x if(counter@%s<0x%x) "
                "-> body=blk[%d](0x%x) else exit=blk[%d](0x%x)",
                guard_serial,
                int(guard_ea),
                counter_desc,
                int(bound),
                int(body_target),
                int(body_state) & 0xFFFFFFFF,
                int(exit_target),
                int(exit_state) & 0xFFFFFFFF,
            )
    return lowerings, suppressed


def emit_minimal_unflatten(
    flow_graph,
    dispatcher,
    *,
    state_var_stkoff: int,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None = None,
    initial_state: int | None = None,
    is_indirect: bool = False,
    fact_view=None,
    emu=None,
    live_block_for=None,
    use_def_safety=None,
    live_function=None,
) -> PatchPlan:
    """Recover back-edge transitions and emit the dispatcher-bypass ``PatchPlan``.

    The whole unflatten in one pass: ``recover_state_write_transitions`` over the
    dispatcher's predecessors, then :func:`build_state_write_redirects`, compiled
    to a ``PatchPlan``.  No ``StateDag``.

    ``emu`` / ``live_block_for`` (ticket llr-xauw) inject the optional reduced-product
    CONCRETE leg into the partitioned fixpoint: an ``EmulationCapability`` consulted
    only where the abstract fold left a back-edge next-state at ``⊥``, plus the
    serial->live-block resolver it steps.  Both ``None`` -> abstract-only (unchanged).

    ``use_def_safety`` / ``live_function`` (ticket llr-wlzb) inject the optional
    use-def severance veto: a redirect that would orphan a NON-state-variable use
    (the OLLVM handler-body accumulator carriers ``var_18 = var_378`` /
    ``var_84 = var_378`` whose downstream readers are the terminal store and the loop
    guard) is dropped, leaving that back-edge on the dispatcher so IDA's reaching-def
    analysis cannot backfill the live carrier from the prologue and DCE the body.
    Gated by ``D810_USE_DEF_VETO`` (default OFF -> byte-identical); the state variable
    itself is intentionally severed (that is the unflattening) and never vetoed.
    """
    if dispatcher_entry_serial is None:
        return compile_patch_plan([], flow_graph)
    # S4 C3 flip (ticket llr-1szn): the back-edge next-states now come from the sound
    # region-partitioned multi-cell fixpoint (run_snapshot_constant_fixpoint, the SAME
    # _transfer_snapshot_constant_block transfer) instead of the ad-hoc per-region walk
    # in _resolve_back_edge_states. Proven byte-identical by the C1/B shadow-diff
    # (diff==0 on hodur 15/15 + sub_7FFD 78/78); the cff probe still diffs the two as a
    # standing equivalence guard.  The reduced-product CONCRETE leg (llr-xauw) is
    # consulted ONLY at the residual ⊥ back-edges, so an abstract-resolved transition
    # is byte-identical with and without ``emu``.
    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        flow_graph,
        dispatcher,
        int(state_var_stkoff),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        recover_terminal_tail=is_indirect,
        initial_state=initial_state,
        emu=emu,
        live_block_for=live_block_for,
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
            "unflat minimal unflatten: %d back-edge transitions, proof kinds=%s",
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
                        "unflat minimal unflatten: BAILED (no entry bridge: "
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
        state_var_stkoff=int(state_var_stkoff),
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
        carrier_via_blocks=set(
            _carrier_return_via_routes(
                flow_graph,
                transitions,
                disp=int(dispatcher_entry_serial),
                state_var_stkoff=int(state_var_stkoff),
                default_target=dispatcher.default_target,
            )
        ),
    )
    if arm_mods:
        mods = list(mods) + arm_mods
    if logger.info_on:
        n_cond = sum(1 for h in handler_transitions if h.is_conditional)
        logger.info(
            "unflat minimal unflatten: conditional_handlers=%d arm_redirects_added=%d",
            n_cond,
            len(arm_mods),
        )
    # Folded counted-loop guards (ticket llr-pydd): a guard the back-edge model
    # recovered as a SELF-LOOP (write_block routes to itself) is the
    # constant-folded ``i < N`` accumulation guard whose body arm was DCE'd
    # before the recovery maturity.  Re-materialize it as an explicit 2-way edge
    # from the cross-maturity FoldedLoopGuardFact, and DROP the spurious
    # self-loop redirect the back-edge model emitted for the same source.
    # INDIRECT-only: the fact is observed for the Tigress shape; the gate keeps
    # equality-chain / switch goldens byte-identical.
    if is_indirect:
        guard_lowerings, suppressed = build_folded_loop_guard_lowerings(
            flow_graph,
            dispatcher,
            transitions,
            fact_view,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
        )
        if suppressed:
            mods = [
                m
                for m in mods
                if not (
                    isinstance(m, (RedirectGoto, RedirectBranch))
                    and int(m.from_serial) in suppressed
                )
            ]
        if guard_lowerings:
            mods = list(mods) + guard_lowerings
    # Use-def severance veto (ticket llr-wlzb): drop any redirect that would orphan a
    # NON-state-variable use. For the OLLVM shadow shape the accumulator reaches the
    # terminal/guard only through carrier copies (``var_18 = var_378`` /
    # ``var_84 = var_378``); bypassing those blocks lets IDA backfill the slot from the
    # prologue (0 / failed-flag) and DCE the whole ``var_378`` computation (207->17).
    # Vetoing such a redirect keeps that back-edge on the dispatcher (engine-style
    # residual) so the carrier stays on-path. Gated ``D810_USE_DEF_VETO`` (default OFF
    # -> byte-identical); the state variable's own severance is the unflattening and is
    # never vetoed.
    if use_def_safety is not None and live_function is not None:
        # Conservative bail (ticket llr-wlzb): on a shape where unflattening would
        # orphan a non-state carrier (the OLLVM pointer-indirected accumulator whose
        # setup/math handlers get severed), abandon the whole unflatten and leave the
        # dispatcher as a residual loop. The shared instruction rules still fold the
        # MBA/BCF noise, so the result is the engine-equivalent correct partial rather
        # than a gutted function. Gated D810_S1A_SEVERANCE_BAIL (default OFF).
        if severance_bail_enabled():
            severed = count_use_def_severances(
                mods,
                use_def_safety=use_def_safety,
                live_function=live_function,
                pre_cfg=flow_graph,
                state_var_stkoff=int(state_var_stkoff),
            )
            if severed:
                if logger.info_on:
                    logger.info(
                        "unflat minimal unflatten: conservative BAIL on %d carrier "
                        "severance(s) -> empty plan (leave SM residual, "
                        "engine-equivalent)",
                        severed,
                    )
                return compile_patch_plan([], flow_graph)
        mods = filter_use_def_severing_redirects(
            mods,
            use_def_safety=use_def_safety,
            live_function=live_function,
            pre_cfg=flow_graph,
            state_var_stkoff=int(state_var_stkoff),
        )
    if logger.info_on:
        n_return = sum(1 for t in transitions if t.is_return)
        n_unresolved = sum(1 for t in transitions if t.next_state is None)
        reached, total, unreached = _reachability(
            flow_graph, dispatcher, mods, int(dispatcher_entry_serial)
        )
        logger.info(
            "unflat minimal unflatten: back_edges=%d return_edges=%d unresolved=%d "
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
        # A folded-loop-guard lowering re-points the guard's sole dispatcher edge
        # onto a 2-way ``false``/``true`` split; model both targets as reachable.
        if isinstance(m, LowerConditionalStateTransition):
            succ = rewired.get(int(m.source_serial))
            if succ is not None:
                rewired[int(m.source_serial)] = [
                    int(m.false_target_serial),
                    int(m.true_target_serial),
                ]
            continue
        if not isinstance(m, (RedirectGoto, RedirectBranch)):
            continue
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
