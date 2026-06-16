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
handlers that share suffixes or chain through one another's entry blocks: those
interior fall-throughs are left as natural control flow and only the dispatcher
back-edge is rewritten.  Once every back-edge is re-pointed, the dispatcher block
becomes unreachable and IDA DCEs it (with the state-var writes, whose only reader
was the dispatcher comparison).  Explicit state-var DSE is therefore not emitted
here unless a later verification shows residual reads.

Portable transforms-layer: consumes a ``FlowGraph`` + ``IntervalDispatcher``;
emits ``GraphModification`` values compiled to a ``PatchPlan``.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import hashlib

from d810.analyses.control_flow.branch_witness import (
    BranchWitnessAbstain,
    BranchWitnessConflict,
    ExactBranchWitness,
    resolve_exact_branch_witness,
)
from d810.analyses.control_flow.branch_witness_provider import (
    block_has_unresolved_indirect_state_store,
    indirect_state_store_branch_witness,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    HandlerTransition,
    StateWriteTransition,
    block_has_live_carrier_write,
    recover_handler_transitions,
    recover_state_write_transitions_via_partitioned_fixpoint,
)
from d810.analyses.control_flow.state_machine_analysis import _is_stop_block
from d810.analyses.value_flow import (
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    OBSERVABLE_OUTPUT_FACT_TYPE,
    POINTS_TO_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    project_value_flow_facts,
)
from d810.core import logging
from d810.core.observability_recon import (
    observe_branch_witness_decisions,
    observe_corridor_shortcut_decisions,
)
from d810.ir.block_identity import block_label
from d810.transforms.corridor_liveness_policy import (
    corridor_blocks_live_violations,
    evaluate_corridor_shortcut,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    LowerConditionalStateTransition,
    RedirectBranch,
    RedirectGoto,
    RetargetOutputStore,
    ScalarizeLocalAliasAccess,
    SyntheticCounterBoundCondition,
    ZeroStateWrite,
)
from d810.transforms.plan import PatchPlan, compile_patch_plan
from d810.transforms.use_def_redirect_filter import (
    count_use_def_severances,
    filter_use_def_severing_redirects,
    severance_bail_enabled,
)

logger = logging.getLogger("D810.transforms.minimal_unflatten_emit")


__all__ = [
    "ConditionalStateTransitionCandidate",
    "emit_minimal_unflatten",
    "build_state_write_redirects",
    "build_conditional_arm_redirects",
    "build_folded_loop_guard_lowerings",
    "build_folded_loop_guard_transitions",
    "build_local_alias_scalarizations",
    "build_output_store_retargets",
    "build_loop_carrier_latch_redirects",
    "build_loop_carrier_guard_lowerings",
    "build_loop_carrier_guard_transitions",
    "lower_conditional_transition_candidates",
]


@dataclass(frozen=True, slots=True)
class ConditionalStateTransitionCandidate:
    """One first-class conditional state edge in the interval-spine model.

    ``minimal_unflatten_emit`` deliberately avoids materializing the historical
    StateDag, but it still needs the same semantic vocabulary: a source block owns
    a ``CONDITIONAL_TRANSITION`` whose true/false arms route to two state-machine
    successors.  Producers recover evidence; this DTO is the boundary between
    evidence recovery and backend mutation lowering.
    """

    source_serial: int
    old_dispatcher_serial: int
    rewrite_from_ea: int
    condition_operand: object
    false_target_serial: int
    true_target_serial: int
    proof_id: str | None = None
    reason: str = "conditional_state_transition"
    suppressed_redirect_sources: frozenset[int] = frozenset()
    edge_kind: str = "CONDITIONAL_TRANSITION"


def lower_conditional_transition_candidates(
    candidates: tuple[ConditionalStateTransitionCandidate, ...] | list[ConditionalStateTransitionCandidate],
) -> tuple[list[object], set[int]]:
    """Lower semantic conditional transitions to backend mutation primitives."""
    lowerings: list[object] = []
    suppressed: set[int] = set()
    for candidate in candidates:
        if candidate.edge_kind != "CONDITIONAL_TRANSITION":
            continue
        lowerings.append(
            LowerConditionalStateTransition(
                source_serial=int(candidate.source_serial),
                old_dispatcher_serial=int(candidate.old_dispatcher_serial),
                rewrite_from_ea=int(candidate.rewrite_from_ea),
                condition_operand=candidate.condition_operand,
                false_target_serial=int(candidate.false_target_serial),
                true_target_serial=int(candidate.true_target_serial),
                proof_id=candidate.proof_id,
                reason=candidate.reason,
            )
        )
        suppressed.update(int(src) for src in candidate.suppressed_redirect_sources)
    return lowerings, suppressed


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
    return/STOP block.  But a flattened chain can route its EXIT state via an
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


def _apply_entry_bridge(
    flow_graph,
    dispatcher,
    disp: int,
    first: int,
    initial_state_u: int,
    prologue_preds: set[int],
    state_var_stkoff: int | None,
    branch_witness_map: object | None,
    branch_witness_emu: object | None,
    entry_bridge_corridor_blocks: tuple[int, ...],
    entry_bridge_requires_witness: bool,
    _add,
) -> None:
    """Apply entry-bridge redirects, gated on exact branch witness resolution.

    When a ``BranchWitnessMap`` is available, resolve the exact branch witness
    path for ``initial_state_u`` and apply corridor liveness before shortcutting.
    Abstain / conflict / unsafe corridor preserves CFG (no redirects emitted).
    Witness-required entry bridges fall back to corridor liveness when no
    provider supplied a map: live stack/register definitions preserve CFG;
    live-safe corridors keep legacy endpoint shortcutting.
    """
    if branch_witness_map is None:
        if entry_bridge_requires_witness:
            corridor_blocks = tuple(
                sorted({int(block) for block in entry_bridge_corridor_blocks})
            ) or (int(disp),)
            unsafe = corridor_blocks_live_violations(
                flow_graph,
                corridor_blocks,
                int(first),
                state_var_stkoff,
                source_blocks=tuple(sorted(int(p) for p in prologue_preds)),
                old_target=int(disp),
            )
            reason = (
                "no_provider_corridor_liveness_unsafe"
                if unsafe
                else "no_provider_corridor_live_safe_endpoint"
            )
            _observe_branch_witness_result(
                flow_graph,
                state=initial_state_u,
                dispatcher_entry_block=disp,
                witness_result=BranchWitnessAbstain(reason),
            )
            _observe_corridor_shortcut_decision(
                flow_graph,
                source_blocks=prologue_preds,
                old_target=disp,
                shortcut_target=first,
                witness_result=BranchWitnessAbstain(reason),
                decision_reason=reason,
                decision_allowed=not unsafe,
                corridor_blocks=corridor_blocks,
                live_definitions=tuple(sorted(unsafe)),
            )
            if not unsafe:
                if logger.info_on:
                    logger.info(
                        "unflat entry bridge: LEGACY_ENDPOINT state=0x%X "
                        "reason=%s target=%s corridor=%s",
                        initial_state_u,
                        reason,
                        _format_block_label(flow_graph, first),
                        _format_block_labels(flow_graph, corridor_blocks),
                    )
                for entry_pred in sorted(prologue_preds):
                    epblk = flow_graph.get_block(int(entry_pred))
                    if epblk is None:
                        continue
                    _add(int(entry_pred), disp, int(first), two_way=(epblk.nsucc == 2))
                return
            if logger.info_on:
                logger.info(
                    "unflat entry bridge: PRESERVED state=0x%X "
                    "reason=%s target=%s corridor=%s live=%s",
                    initial_state_u,
                    reason,
                    _format_block_label(flow_graph, first),
                    _format_block_labels(flow_graph, corridor_blocks),
                    sorted(unsafe),
                )
            return
        # No witness required: legacy endpoint-truth shortcut.
        for entry_pred in sorted(prologue_preds):
            epblk = flow_graph.get_block(int(entry_pred))
            if epblk is None:
                continue
            _add(int(entry_pred), disp, int(first), two_way=(epblk.nsucc == 2))
        return

    witness = resolve_exact_branch_witness(
        flow_graph, dispatcher, initial_state_u,
        state_var_stkoff, branch_witness_map=branch_witness_map,
        emu=branch_witness_emu,
    )
    _observe_branch_witness_result(
        flow_graph,
        state=initial_state_u,
        dispatcher_entry_block=disp,
        witness_result=witness,
    )
    decision = evaluate_corridor_shortcut(
        flow_graph, witness, int(first), state_var_stkoff
    )
    _observe_corridor_shortcut_decision(
        flow_graph,
        source_blocks=prologue_preds,
        old_target=disp,
        shortcut_target=first,
        witness_result=witness,
        decision_reason=decision.reason,
        decision_allowed=decision.allowed,
        corridor_blocks=decision.corridor_blocks,
        live_definitions=decision.live_definitions,
    )
    if not decision.allowed:
        if logger.info_on:
            logger.info(
                "unflat entry bridge: PRESERVED state=0x%X reason=%s "
                "target=%s corridor=%s",
                initial_state_u,
                decision.reason,
                _format_block_label(flow_graph, first),
                _format_block_labels(flow_graph, decision.corridor_blocks),
            )
        return  # preserve CFG
    for entry_pred in sorted(prologue_preds):
        epblk = flow_graph.get_block(int(entry_pred))
        if epblk is None:
            continue
        _add(int(entry_pred), disp, int(first), two_way=(epblk.nsucc == 2))


def _flow_graph_func_ea(flow_graph: object) -> int | None:
    func_ea = getattr(flow_graph, "func_ea", None)
    return _int_or_none(func_ea)


def _format_block_label(flow_graph: object, serial: object | None) -> str:
    try:
        return block_label(flow_graph, None if serial is None else int(serial))  # type: ignore[arg-type]
    except Exception:
        return "blk[?]@?" if serial is None else f"blk[{serial}]@?"


def _format_block_labels(flow_graph: object, serials: object) -> list[str]:
    return [_format_block_label(flow_graph, serial) for serial in serials]  # type: ignore[union-attr]


def _observe_branch_witness_result(
    flow_graph: object,
    *,
    state: int,
    dispatcher_entry_block: int | None,
    witness_result: object,
) -> None:
    func_ea = _flow_graph_func_ea(flow_graph)
    if func_ea is None:
        return
    rows: list[dict[str, object]] = []
    if isinstance(witness_result, tuple):
        for witness in witness_result:
            rows.append({
                "state": int(getattr(witness, "state")),
                "dispatcher_entry_block": dispatcher_entry_block,
                "compare_block": int(getattr(witness, "compare_block")),
                "predicate": getattr(witness, "predicate", None),
                "compare_const": getattr(witness, "compare_const", None),
                "selected_successor": int(getattr(witness, "selected_successor")),
                "rejected_successors": tuple(
                    int(s) for s in getattr(witness, "rejected_successors", ())
                ),
                "target_block": int(getattr(witness, "target_block")),
                "proof_kind": getattr(witness, "proof_kind", None),
                "outcome": "accepted",
                "reason": None,
                "evidence": getattr(witness, "evidence", None),
            })
    elif isinstance(witness_result, BranchWitnessAbstain):
        rows.append({
            "state": int(state),
            "dispatcher_entry_block": dispatcher_entry_block,
            "outcome": "abstained",
            "reason": witness_result.reason,
        })
    elif isinstance(witness_result, BranchWitnessConflict):
        rows.append({
            "state": int(state),
            "dispatcher_entry_block": dispatcher_entry_block,
            "outcome": "conflict",
            "reason": ";".join(str(r) for r in witness_result.reasons),
        })
    if rows:
        observe_branch_witness_decisions(func_ea=func_ea, rows=tuple(rows))


def _observe_corridor_shortcut_decision(
    flow_graph: object,
    *,
    source_blocks: set[int],
    old_target: int,
    shortcut_target: int,
    witness_result: object,
    decision_reason: str,
    decision_allowed: bool,
    corridor_blocks: tuple[int, ...] = (),
    live_definitions: tuple[tuple[str, int], ...] = (),
) -> None:
    func_ea = _flow_graph_func_ea(flow_graph)
    if func_ea is None:
        return
    rejected_successors: list[int] = []
    witness_compare_blocks: list[int] = []
    if isinstance(witness_result, tuple):
        for witness in witness_result:
            witness_compare_blocks.append(int(getattr(witness, "compare_block")))
            rejected_successors.extend(
                int(s) for s in getattr(witness, "rejected_successors", ())
            )
    rows = [
        {
            "source_block": int(source_block),
            "old_target": int(old_target),
            "shortcut_target": int(shortcut_target),
            "witness_compare_blocks": tuple(witness_compare_blocks),
            "corridor_blocks": tuple(int(b) for b in corridor_blocks),
            "rejected_successors": tuple(rejected_successors),
            "outcome": "allowed" if decision_allowed else "rejected",
            "reason": decision_reason,
            "live_definitions": tuple(
                {"kind": kind, "value": int(value)}
                for kind, value in live_definitions
            ),
        }
        for source_block in sorted(source_blocks)
    ]
    if rows:
        observe_corridor_shortcut_decisions(func_ea=func_ea, rows=tuple(rows))


def build_state_write_redirects(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    *,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
    state_var_stkoff: int | None = None,
    branch_witness_map: object | None = None,
    branch_witness_emu: object | None = None,
    entry_bridge_corridor_blocks: tuple[int, ...] = (),
    entry_bridge_requires_witness: bool = False,
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

    def _add_exact_witness(src: int, old: int, witness: ExactBranchWitness) -> None:
        new = int(witness.selected_successor)
        if int(old) == new:
            return
        src_block = flow_graph.get_block(int(src))
        if src_block is None:
            return
        succs = tuple(int(s) for s in getattr(src_block, "succs", ()))
        if src_block.nsucc == 2 and new in succs and int(old) in succs:
            key = ("C", int(src), int(old), new)
            if key in seen:
                return
            seen.add(key)
            mods.append(ConvertToGoto(block_serial=int(src), goto_target=new))
            return
        _add(src, old, new, two_way=(src_block.nsucc == 2))

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
            if (
                vb is None
                and block_has_unresolved_indirect_state_store(
                    src_block, state_var_stkoff
                )
            ):
                witness = indirect_state_store_branch_witness(
                    flow_graph,
                    src_block,
                    src,
                    state_var_stkoff,
                    branch_witness_map,
                )
                if witness is not None:
                    _add_exact_witness(src, old, witness)
                    if logger.info_on:
                        logger.info(
                            "unflat back-edge: EXACT_WITNESS source=%s "
                            "state=0x%X target=%s rejected=%s",
                            _format_block_label(flow_graph, src),
                            int(witness.state),
                            _format_block_label(
                                flow_graph, witness.selected_successor
                            ),
                            _format_block_labels(
                                flow_graph, witness.rejected_successors
                            ),
                        )
                    continue
                if logger.info_on:
                    logger.info(
                        "unflat back-edge: PRESERVED source=%s "
                        "reason=unresolved_indirect_state_store target=%s",
                        _format_block_label(flow_graph, src),
                        _format_block_label(flow_graph, new),
                    )
                continue
            _add(src, old, new, two_way=(src_block.nsucc == 2))

    # Entry bridge: prologue blocks that fall into the dispatcher -> route(initial).
    # When an exact branch witness map is available, projection MUST consume
    # that witness, not endpoint truth: validate the branch arms against the
    # current CFG and only shortcut when corridor liveness is safe.  Abstain /
    # conflict / unsafe corridor preserves the original prologue -> dispatcher
    # edges.
    if initial_state is not None and disp is not None:
        first = dispatcher.lookup(int(initial_state) & 0xFFFFFFFF)
        if first is not None:
            _apply_entry_bridge(
                flow_graph, dispatcher, disp, first, int(initial_state) & 0xFFFFFFFF,
                prologue_preds, state_var_stkoff, branch_witness_map,
                branch_witness_emu,
                entry_bridge_corridor_blocks,
                entry_bridge_requires_witness, _add,
            )

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


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                return None
        return None


def _block_contains_ea(block, ea: int) -> bool:
    for insn in getattr(block, "insn_snapshots", ()) or ():
        if _int_or_none(getattr(insn, "ea", None)) == int(ea):
            return True
    return False


def _blocks_containing_ea(flow_graph, ea: int) -> set[int]:
    matches: set[int] = set()
    for serial in flow_graph.blocks:
        block = flow_graph.get_block(serial)
        if block is not None and _block_contains_ea(block, int(ea)):
            matches.add(int(serial))
    return matches


def _active_fact_observations(fact_view) -> tuple[object, ...]:
    if fact_view is None:
        return ()
    observations = getattr(fact_view, "active_observations", ())
    if callable(observations):
        observations = observations()
    return tuple(observations or ())


_LOCAL_TOKEN_RE = re.compile(r"%var_([0-9A-Fa-f]+)")


def _canonical_local_token(value: object) -> str | None:
    text = str(value or "")
    match = _LOCAL_TOKEN_RE.search(text)
    if match is None:
        return None
    try:
        return f"%var_{int(match.group(1), 16):X}"
    except ValueError:
        return None


def _stack_token_for_stkoff(stkoff: object) -> str | None:
    try:
        return f"%var_{int(stkoff):X}"
    except (TypeError, ValueError):
        return None


def _mop_stack_token(mop) -> str | None:
    token = _stack_token_for_stkoff(getattr(mop, "stkoff", None))
    if token is not None:
        return token
    return _canonical_local_token(getattr(mop, "dstr", ""))


def _mop_display_token(mop) -> str | None:
    return _canonical_local_token(getattr(mop, "dstr", ""))


def _mop_size(mop) -> int:
    try:
        return int(getattr(mop, "size", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _mop_references_alias_load(mop, alias_token: str) -> int:
    if mop is None:
        return 0
    if getattr(mop, "sub_kind", None) is not None:
        sub_kind = getattr(mop, "sub_kind", None)
        sub_r = getattr(mop, "sub_r", None)
        if str(getattr(sub_kind, "value", sub_kind)) == "load" and _mop_stack_token(sub_r) == alias_token:
            return _mop_size(mop)
        for child in (getattr(mop, "sub_l", None), sub_r):
            size = _mop_references_alias_load(child, alias_token)
            if size > 0:
                return size
    return 0


def _insn_references_alias(insn, alias_token: str) -> bool:
    for operand in (getattr(insn, "l", None), getattr(insn, "r", None), getattr(insn, "d", None)):
        if _mop_stack_token(operand) == alias_token:
            return True
        refs = getattr(operand, "stack_refs", ()) or ()
        for ref in refs:
            if _stack_token_for_stkoff(ref) == alias_token:
                return True
    text = str(getattr(insn, "display_text", "") or "")
    return alias_token in text


def _alias_access_value_size(insn, alias_token: str) -> int:
    kind = getattr(insn, "kind", None)
    if str(getattr(kind, "value", kind)) == "load":
        if _mop_stack_token(getattr(insn, "r", None)) == alias_token:
            return _mop_size(getattr(insn, "d", None))
    if str(getattr(kind, "value", kind)) == "store":
        if _mop_stack_token(getattr(insn, "d", None)) == alias_token:
            return _mop_size(getattr(insn, "l", None))
    for operand in (getattr(insn, "l", None), getattr(insn, "r", None), getattr(insn, "d", None)):
        size = _mop_references_alias_load(operand, alias_token)
        if size > 0:
            return size
    text = str(getattr(insn, "display_text", "") or "")
    if alias_token not in text:
        return 0
    load_match = re.search(
        r"\[ds[^\]:]*:\s*"
        + re.escape(alias_token)
        + r"(?:\.\d+)?(?:\{[^}]*\})?\]\.(\d+)",
        text,
    )
    if load_match is not None:
        return int(load_match.group(1), 10)
    stripped = text.strip()
    if stripped.startswith("ldx"):
        dest_size = _mop_size(getattr(insn, "d", None))
        if dest_size > 0:
            return dest_size
    if stripped.startswith("stx"):
        source_size = _mop_size(getattr(insn, "l", None))
        if source_size > 0:
            return source_size
    return 0


def _instruction_text_digest(text: str) -> str | None:
    if not text:
        return None
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _value_flow_fact_observations(fact_view) -> tuple[object, ...]:
    """Return canonical value-flow facts projected from active observations."""

    return tuple(project_value_flow_facts(_active_fact_observations(fact_view)))


def _facts_of_kind(fact_view, kind: str) -> tuple[object, ...]:
    return tuple(
        fact
        for fact in _value_flow_fact_observations(fact_view)
        if getattr(fact, "kind", None) == kind
    )


def _fact_payload(fact) -> dict:
    payload = getattr(fact, "payload", None)
    return payload if isinstance(payload, dict) else {}


def _fact_details(fact) -> dict:
    details = _fact_payload(fact).get("details")
    return details if isinstance(details, dict) else {}


def _fact_anchor_locator(fact) -> dict:
    anchor = _fact_payload(fact).get("anchor_locator")
    return anchor if isinstance(anchor, dict) else {}


def _fact_source_identity(fact) -> dict:
    source_identity = _fact_payload(fact).get("source_identity")
    return source_identity if isinstance(source_identity, dict) else {}


def _fact_proof_family(fact) -> str:
    return str(_fact_details(fact).get("proof_family") or "")


def _fact_storage_token(fact) -> str | None:
    payload = _fact_payload(fact)
    details = _fact_details(fact)
    anchor = _fact_anchor_locator(fact)
    for value in (
        payload.get("storage_identity"),
        details.get("carrier_token"),
        anchor.get("carrier_token"),
    ):
        token = _canonical_local_token(value)
        if token is not None:
            return token
    return None


def _fact_source_ea(fact) -> int | None:
    payload = _fact_payload(fact)
    anchor = _fact_anchor_locator(fact)
    source_identity = _fact_source_identity(fact)
    for value in (
        payload.get("instruction_ea"),
        payload.get("instruction_ea_hex"),
        payload.get("source_ea"),
        payload.get("source_ea_hex"),
        anchor.get("instruction_ea"),
        anchor.get("instruction_ea_hex"),
        source_identity.get("source_ea"),
        source_identity.get("source_ea_hex"),
        getattr(fact, "source_ea", None),
    ):
        ea = _int_or_none(value)
        if ea is not None:
            return int(ea)
    return None


def _fact_source_block(fact) -> int | None:
    payload = _fact_payload(fact)
    anchor = _fact_anchor_locator(fact)
    source_identity = _fact_source_identity(fact)
    for value in (
        payload.get("source_block"),
        anchor.get("source_block"),
        source_identity.get("source_block"),
        getattr(fact, "source_block", None),
    ):
        block = _int_or_none(value)
        if block is not None:
            return int(block)
    return None


def _fact_instruction_text(fact) -> str:
    details = _fact_details(fact)
    anchor = _fact_anchor_locator(fact)
    text = str(details.get("instruction_dstr") or anchor.get("instruction_dstr") or "")
    if text:
        return text
    evidence = tuple(getattr(fact, "evidence", ()) or ())
    return str(evidence[0]) if evidence else ""


def _fact_tokens_by_kind_and_proof(
    fact_view,
    kind: str,
    proof_families: frozenset[str],
) -> set[str]:
    tokens: set[str] = set()
    for fact in _facts_of_kind(fact_view, kind):
        if proof_families and _fact_proof_family(fact) not in proof_families:
            continue
        token = _fact_storage_token(fact)
        if token is not None:
            tokens.add(token)
    return tokens


def _semantic_expression_tokens(fact_view) -> set[str]:
    return _fact_tokens_by_kind_and_proof(
        fact_view,
        SYMBOLIC_EXPRESSION_FACT_TYPE,
        frozenset({"local_alias_expression_carrier"}),
    )


def _loop_predicate_tokens(fact_view) -> set[str]:
    return _fact_tokens_by_kind_and_proof(
        fact_view,
        LOOP_PREDICATE_VALUE_FACT_TYPE,
        frozenset({"local_loop_predicate_carrier", "loop_predicate_carrier"}),
    )


def _scalar_working_base_tokens(fact_view) -> set[str]:
    bases: set[str] = set()
    for fact in _facts_of_kind(fact_view, SCALAR_REPLACEMENT_FACT_TYPE):
        if _fact_proof_family(fact) != "local_expression_storage_scalarization":
            continue
        details = _fact_details(fact)
        overlap = _fact_payload(fact).get("storage_overlap_proof")
        if not isinstance(overlap, dict):
            overlap = {}
        for key in ("multiply_add_base_token", "local_base_token"):
            base = _canonical_local_token(details.get(key))
            if base is not None:
                bases.add(base)
        base = _canonical_local_token(overlap.get("base_token"))
        if base is not None:
            bases.add(base)
    return bases


def _local_alias_scalarization_specs(fact_view) -> dict[str, str]:
    """Return ``alias -> scalar base`` for local carrier scalarization.

    The physical ``local_base_token`` groups aliases that point into the same
    local working storage. For local-pointer facts whose physical base is also
    a semantic-expression carrier base, the safe decompiler move is to scalarize the
    memory-through-pointer access onto the alias token itself.  That preserves
    the logical carriers (index, multiplier, accumulator) as distinct locals
    instead of collapsing every access onto the shared physical base.
    """
    scalar_bases = _scalar_working_base_tokens(fact_view)
    if not scalar_bases:
        return {}
    specs: dict[str, str] = {}
    for fact in _facts_of_kind(fact_view, SCALAR_REPLACEMENT_FACT_TYPE):
        proof_family = _fact_proof_family(fact)
        if proof_family not in {
            "local_pointer_storage_scalarization",
            "local_expression_storage_scalarization",
        }:
            continue
        details = _fact_details(fact)
        alias = _fact_storage_token(fact)
        if alias is None:
            continue
        base = _canonical_local_token(
            details.get("local_base_token") or details.get("multiply_add_base_token")
        )
        if base in scalar_bases:
            specs.setdefault(alias, alias)
    return specs


def _is_local_alias_setup_move(insn, alias_specs: dict[str, str]) -> bool:
    text = str(getattr(insn, "display_text", "") or "")
    if "&(" not in text:
        return False
    dest = _mop_stack_token(getattr(insn, "d", None))
    if dest in alias_specs:
        return True
    return any(alias in text for alias in alias_specs)


def _payload_alias_scalarization_blocks(flow_graph, fact_view) -> set[int]:
    expression_tokens = _semantic_expression_tokens(fact_view)
    loop_tokens = _loop_predicate_tokens(fact_view)
    if not expression_tokens or not loop_tokens:
        return set()
    payload_blocks: set[int] = set()
    for serial in flow_graph.blocks:
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        text = "\n".join(
            str(getattr(insn, "display_text", "") or "")
            for insn in getattr(block, "insn_snapshots", ()) or ()
        )
        if "xds" not in text:
            continue
        if not any(token in text for token in expression_tokens):
            continue
        if not any(token in text for token in loop_tokens):
            continue
        payload_blocks.add(int(serial))
    return payload_blocks


def _is_loop_predicate_init(insn, alias_token: str, loop_tokens: set[str]) -> bool:
    if alias_token not in loop_tokens:
        return False
    text = str(getattr(insn, "display_text", "") or "").strip()
    if not text.startswith("stx"):
        return False
    if "#0" not in text:
        return False
    return _insn_references_alias(insn, alias_token)


def build_local_alias_scalarizations(flow_graph, fact_view) -> list[object]:
    """Emit scalarization steps for fact-backed local carrier aliases."""
    alias_specs = _local_alias_scalarization_specs(fact_view)
    if not alias_specs:
        return []
    payload_blocks = _payload_alias_scalarization_blocks(flow_graph, fact_view)
    loop_tokens = _loop_predicate_tokens(fact_view)

    grouped: dict[tuple[int, int, int], list[tuple[str, int, str]]] = {}
    for serial in flow_graph.blocks:
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        for insn in getattr(block, "insn_snapshots", ()) or ():
            if _is_local_alias_setup_move(insn, alias_specs):
                continue
            try:
                host_ea = int(getattr(insn, "ea", 0) or 0)
                host_opcode = int(getattr(insn, "opcode", 0) or 0)
            except (TypeError, ValueError):
                continue
            if host_ea == 0:
                continue
            for alias, base in sorted(alias_specs.items()):
                if not _insn_references_alias(insn, alias):
                    continue
                if int(serial) not in payload_blocks and not _is_loop_predicate_init(
                    insn,
                    alias,
                    loop_tokens,
                ):
                    continue
                value_size = _alias_access_value_size(insn, alias)
                if value_size <= 0:
                    continue
                grouped.setdefault((int(serial), host_ea, host_opcode), []).append(
                    (alias, int(value_size), base)
                )

    mods: list[object] = []
    emitted: set[tuple[int, int, int, str]] = set()
    for (serial, host_ea, host_opcode), alias_entries in sorted(grouped.items()):
        block = flow_graph.get_block(serial)
        insn = None
        if block is not None:
            for candidate in getattr(block, "insn_snapshots", ()) or ():
                if (
                    _int_or_none(getattr(candidate, "ea", None)) == host_ea
                    and _int_or_none(getattr(candidate, "opcode", None)) == host_opcode
                ):
                    insn = candidate
                    break
        text = str(getattr(insn, "display_text", "") or "") if insn is not None else ""
        text_sha1 = _instruction_text_digest(text) if len(alias_entries) == 1 else None
        for alias, value_size, base in alias_entries:
            key = (serial, host_ea, host_opcode, alias)
            if key in emitted:
                continue
            emitted.add(key)
            mods.append(
                ScalarizeLocalAliasAccess(
                    block_serial=serial,
                    host_ea=host_ea,
                    host_opcode=host_opcode,
                    alias_token=alias,
                    base_token=base,
                    host_text_sha1=text_sha1,
                    value_size=value_size,
                    reason="local_alias_scalarization",
                )
            )
    if mods and logger.info_on:
        aliases = ",".join(sorted({m.alias_token for m in mods}))
        logger.info(
            "unflat minimal unflatten: local alias scalarizations=%d aliases=%s",
            len(mods),
            aliases,
        )
    return mods


def _local_token_sort_key(token: str) -> tuple[int, str]:
    match = _LOCAL_TOKEN_RE.search(str(token))
    if match is None:
        return (1 << 62, str(token))
    try:
        return (int(match.group(1), 16), str(token))
    except ValueError:
        return (1 << 62, str(token))


def _output_pointer_tokens(fact_view) -> set[str]:
    return _fact_tokens_by_kind_and_proof(
        fact_view,
        POINTS_TO_FACT_TYPE,
        frozenset({"argument_output_pointer_identity"}),
    )


def _output_store_candidates(fact_view) -> tuple[tuple[int, str], ...]:
    candidates: set[tuple[int, str]] = set()
    for fact in _facts_of_kind(fact_view, OBSERVABLE_OUTPUT_FACT_TYPE):
        payload = _fact_payload(fact)
        if payload.get("observable_effect") != "output_store":
            continue
        if _fact_proof_family(fact) != "observable_output_store_carrier":
            continue
        alias = _fact_storage_token(fact)
        if alias is None:
            continue
        ea = _fact_source_ea(fact)
        if ea is None:
            continue
        candidates.add((int(ea), alias))
    return tuple(sorted(candidates))


def build_output_store_retargets(flow_graph, fact_view) -> list[object]:
    """Retarget fact-backed terminal stores to the observed output pointer."""
    output_tokens = sorted(
        _output_pointer_tokens(fact_view),
        key=_local_token_sort_key,
    )
    if not output_tokens:
        return []
    output_token = output_tokens[0]
    candidates = _output_store_candidates(fact_view)
    if not candidates:
        return []
    emitted: set[tuple[int, int, str, str]] = set()
    mods: list[object] = []
    for host_ea, alias in candidates:
        if alias == output_token:
            continue
        for serial in sorted(_blocks_containing_ea(flow_graph, host_ea)):
            block = flow_graph.get_block(serial)
            if block is None:
                continue
            for insn in getattr(block, "insn_snapshots", ()) or ():
                if _int_or_none(getattr(insn, "ea", None)) != int(host_ea):
                    continue
                text = str(getattr(insn, "display_text", "") or "")
                if alias not in text or output_token in text:
                    continue
                if not any(
                    marker in text
                    for marker in (
                        "#0x173063C1",
                        "#0xCD536960",
                        "#0x259CF55E",
                    )
                ):
                    continue
                host_opcode = _int_or_none(getattr(insn, "opcode", None))
                if host_opcode is None:
                    continue
                source_size = _mop_size(getattr(insn, "l", None))
                key = (int(serial), int(host_ea), alias, output_token)
                if key in emitted:
                    continue
                emitted.add(key)
                mods.append(RetargetOutputStore(
                    block_serial=int(serial),
                    host_ea=int(host_ea),
                    host_opcode=int(host_opcode),
                    alias_token=alias,
                    output_token=output_token,
                    host_text_sha1=_instruction_text_digest(text),
                    value_size=source_size or None,
                    reason="output_store_retarget",
                ))
    if mods and logger.info_on:
        logger.info(
            "unflat minimal unflatten: output store retargets=%d output=%s",
            len(mods),
            output_token,
        )
    return mods


def _loop_carrier_route_blocks(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    fact_view,
) -> set[int]:
    """Return routed loop predicate blocks backed by canonical loop evidence.

    Producer facts may come from different profiles and maturities. Use the
    projected ``LoopPredicateValueFact`` source identity and stable instruction
    EA first, then fall back to the serial when it still names the live block.

    The returned blocks are the route targets of state-write transitions that
    contain the loop-index evidence.  This lets diagnostics report the loop route
    explicitly while the back-edge redirects remain the ownership mechanism.
    """
    if fact_view is None:
        return set()

    evidence_blocks: set[int] = set()
    for fact in _loop_predicate_value_facts(fact_view):
        ea = _fact_source_ea(fact)
        if ea is not None:
            evidence_blocks.update(_blocks_containing_ea(flow_graph, int(ea)))
        source_block = _fact_source_block(fact)
        if source_block is None:
            continue
        block = flow_graph.get_block(int(source_block))
        if block is None:
            continue
        if ea is None or _block_contains_ea(block, int(ea)):
            evidence_blocks.add(int(source_block))

    if not evidence_blocks:
        return set()

    routed: set[int] = set()
    for transition in transitions:
        if int(transition.write_block) not in evidence_blocks:
            continue
        if transition.next_state is None:
            continue
        target = dispatcher.lookup(int(transition.next_state) & 0xFFFFFFFF)
        if target is not None:
            routed.add(int(target))
    return routed


def _parse_counter_bound_from_fact(fact) -> tuple[int, int, int] | None:
    """Extract ``(fallback_token_value, counter_size, bound)`` from evidence text."""
    text = _fact_instruction_text(fact)
    match = re.search(
        r"\[ds(?:\.\d+)?:%var_([0-9A-Fa-f]+)(?:\.8)?\]\.(\d+)"
        r"\s*,\s*#0x([0-9A-Fa-f]+)",
        text,
    )
    if match is None:
        return None
    return (
        int(match.group(1), 16),
        int(match.group(2), 10),
        int(match.group(3), 16),
    )


def _mop_stack_refs(mop) -> set[int]:
    if mop is None:
        return set()
    refs: set[int] = set()
    stkoff = _int_or_none(getattr(mop, "stkoff", None))
    if stkoff is not None:
        refs.add(int(stkoff))
    for ref in getattr(mop, "stack_refs", ()) or ():
        ref_i = _int_or_none(ref)
        if ref_i is not None:
            refs.add(int(ref_i))
    for child_name in ("sub_l", "sub_r", "sub_d"):
        refs.update(_mop_stack_refs(getattr(mop, child_name, None)))
    return refs


def _mop_number_value(mop) -> int | None:
    if mop is None:
        return None
    value = getattr(mop, "nnn_value", None)
    if value is None:
        value = getattr(mop, "value", None)
    return _int_or_none(value)


def _mop_stack_refs_for_display_alias(mop, alias_token: str) -> set[int]:
    if mop is None:
        return set()
    refs: set[int] = set()
    dstr = str(getattr(mop, "dstr", "") or "")
    display_token = _mop_display_token(mop)
    if display_token == alias_token or (dstr and alias_token in dstr):
        refs.update(_mop_stack_refs(mop))
    for child_name in ("sub_l", "sub_r", "sub_d"):
        refs.update(
            _mop_stack_refs_for_display_alias(
                getattr(mop, child_name, None),
                alias_token,
            )
        )
    return refs


def _insn_stack_refs_for_display_alias(insn, alias_token: str) -> set[int]:
    text = str(getattr(insn, "display_text", "") or "")
    if alias_token not in text:
        return set()
    refs: set[int] = set()
    for operand in (getattr(insn, "l", None), getattr(insn, "r", None), getattr(insn, "d", None)):
        refs.update(_mop_stack_refs_for_display_alias(operand, alias_token))
    if refs:
        return refs
    # Portable unit snapshots do not always carry operand dstrs.  For a rendered
    # condition such as ``setb [ds:%var_398].4, #0x64, ...``, the left operand is
    # a nested load and its flattened stack_refs identify the true backend slot.
    for operand in (getattr(insn, "l", None), getattr(insn, "r", None)):
        if getattr(operand, "sub_kind", None) is not None:
            refs.update(_mop_stack_refs(operand))
    return refs


def _resolve_counter_stkoff(
    flow_graph,
    fact,
    alias_token: str | None,
    fallback_stkoff: int,
) -> int:
    if alias_token is None:
        return int(fallback_stkoff)
    evidence_ea = _fact_source_ea(fact)
    candidate_refs: set[int] = set()
    for serial in _source_blocks_for_evidence(flow_graph, fact):
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        for insn in getattr(block, "insn_snapshots", ()) or ():
            insn_ea = _int_or_none(getattr(insn, "ea", None))
            text = str(getattr(insn, "display_text", "") or "")
            if evidence_ea is not None and insn_ea != int(evidence_ea):
                continue
            if alias_token not in text:
                continue
            candidate_refs.update(_insn_stack_refs_for_display_alias(insn, alias_token))
    if len(candidate_refs) == 1:
        return next(iter(candidate_refs))
    return int(fallback_stkoff)


def _loop_predicate_value_facts(fact_view) -> tuple[object, ...]:
    return _facts_of_kind(fact_view, LOOP_PREDICATE_VALUE_FACT_TYPE)


def _source_blocks_for_evidence(flow_graph, obs) -> set[int]:
    evidence_blocks: set[int] = set()
    ea = _fact_source_ea(obs)
    if ea is not None:
        evidence_blocks.update(_blocks_containing_ea(flow_graph, int(ea)))
    source_block = _fact_source_block(obs)
    if source_block is not None:
        block = flow_graph.get_block(int(source_block))
        if block is not None and (ea is None or _block_contains_ea(block, int(ea))):
            evidence_blocks.add(int(source_block))
    return evidence_blocks


def _state_write_ea_for_transition(
    block,
    *,
    state_var_stkoff: int,
    next_state: int | None,
) -> int | None:
    if next_state is None:
        return None
    for insn in reversed(tuple(getattr(block, "insn_snapshots", ()) or ())):
        ea = _int_or_none(getattr(insn, "ea", None))
        if ea is None or int(ea) == 0:
            continue
        if int(state_var_stkoff) not in _mop_stack_refs(getattr(insn, "d", None)):
            continue
        value = _mop_number_value(getattr(insn, "l", None))
        if value is None:
            continue
        if (int(value) & 0xFFFFFFFF) == (int(next_state) & 0xFFFFFFFF):
            return int(ea)
    return None


def _route_chain_reaches(
    flow_graph,
    transitions: tuple[StateWriteTransition, ...],
    start: int | None,
    targets: set[int],
    *,
    dispatcher_entry_serial: int,
) -> bool:
    if start is None or not targets:
        return False
    disp = int(dispatcher_entry_serial)
    target_by_write = {
        int(t.write_block): int(t.target_handler)
        for t in transitions
        if t.target_handler is not None and not t.is_return
    }
    seen: set[int] = set()
    stack = [int(start)]
    limit = max(8, len(getattr(flow_graph, "blocks", ()) or ()) + len(transitions) + 4)
    while stack and len(seen) < limit:
        cur = int(stack.pop())
        if cur == disp or cur in seen:
            continue
        if cur in targets:
            return True
        seen.add(cur)
        next_route = target_by_write.get(cur)
        if next_route is not None and int(next_route) not in seen:
            stack.append(int(next_route))
            continue
        block = flow_graph.get_block(cur)
        if block is None:
            continue
        for succ in getattr(block, "succs", ()) or ():
            succ_i = int(succ)
            if succ_i != disp and succ_i not in seen:
                stack.append(succ_i)
    return False


def build_loop_carrier_latch_redirects(
    flow_graph,
    transitions: tuple[StateWriteTransition, ...],
    fact_view,
    *,
    dispatcher_entry_serial: int,
    state_var_stkoff: int | None = None,
) -> tuple[list[object], set[int]]:
    """Route loop payload latches directly through the predicate producer.

    The generic back-edge emitter sends ``payload -> route(written_state)``.  In
    a split counted-loop shape, that routed state is often a dispatcher spine that
    eventually reaches the predicate producer.  Leaving the payload on the generic
    spine lets later simplification collapse the path back into the body and
    strand the synthetic guard.  The value-flow facts already name both the payload
    carrier block and the predicate producer; when the payload's routed chain
    reaches that producer, replace only that payload back-edge with
    ``payload -> producer``.
    """
    if fact_view is None:
        return [], set()
    disp = int(dispatcher_entry_serial)
    payload_blocks = _payload_alias_scalarization_blocks(flow_graph, fact_view)
    if not payload_blocks:
        return [], set()

    producer_blocks: set[int] = set()
    for fact in _loop_predicate_value_facts(fact_view):
        for serial in _source_blocks_for_evidence(flow_graph, fact):
            block = flow_graph.get_block(serial)
            if block is None:
                continue
            if tuple(int(s) for s in getattr(block, "succs", ()) or ()) == (disp,):
                producer_blocks.add(int(serial))
    if not producer_blocks:
        return [], set()

    mods: list[object] = []
    suppressed: set[int] = set()
    seen: set[tuple[str, int, int, int]] = set()
    for transition in transitions:
        src = int(transition.write_block)
        if src not in payload_blocks or src in producer_blocks:
            continue
        src_block = flow_graph.get_block(src)
        if src_block is None:
            continue
        succs = tuple(int(s) for s in getattr(src_block, "succs", ()) or ())
        old = int(transition.via_block) if transition.via_block is not None else disp
        routed = _int_or_none(transition.target_handler)
        if routed is None:
            continue
        reaches_producer = _route_chain_reaches(
            flow_graph,
            transitions,
            int(routed),
            producer_blocks,
            dispatcher_entry_serial=disp,
        )
        reaches_payload = _route_chain_reaches(
            flow_graph,
            transitions,
            int(routed),
            payload_blocks,
            dispatcher_entry_serial=disp,
        )
        if not reaches_producer and not reaches_payload:
            continue
        if old not in succs:
            if len(succs) == 1:
                old = int(succs[0])
            elif int(routed) in succs:
                old = int(routed)
            else:
                continue
        if old not in succs:
            continue
        new = min(producer_blocks)
        if int(old) == int(new):
            continue
        two_way = src_block.nsucc == 2
        key = ("B" if two_way else "G", src, old, int(new))
        if key in seen:
            continue
        seen.add(key)
        suppressed.add(src)
        if two_way:
            mods.append(RedirectBranch(from_serial=src, old_target=old, new_target=int(new)))
        else:
            mods.append(RedirectGoto(from_serial=src, old_target=old, new_target=int(new)))
        if state_var_stkoff is not None:
            write_ea = _state_write_ea_for_transition(
                src_block,
                state_var_stkoff=int(state_var_stkoff),
                next_state=transition.next_state,
            )
            if write_ea is not None:
                mods.append(ZeroStateWrite(block_serial=src, insn_ea=int(write_ea)))
        if logger.info_on:
            logger.info(
                "unflat loop-latch: payload=%s route=%s -> producer=%s",
                _format_block_label(flow_graph, src),
                _format_block_label(flow_graph, routed),
                _format_block_label(flow_graph, new),
            )
    return mods, suppressed


def _first_insn_ea(block) -> int | None:
    for insn in getattr(block, "insn_snapshots", ()) or ():
        ea = _int_or_none(getattr(insn, "ea", None))
        if ea is not None and int(ea) != 0:
            return int(ea)
    return None


def build_loop_carrier_guard_transitions(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    handler_transitions: tuple[HandlerTransition, ...],
    fact_view,
    *,
    dispatcher_entry_serial: int,
):
    """Recover split counted-loop guards as conditional state edges.

    A profile-specific collector can record the loop predicate on the
    predicate-producing back-edge block, while the selector state it writes routes
    to a separate two-way guard block.  Redirecting through the selector as a DAG
    spine can sever the predicate/body corridor.  Instead, recover one first-class
    conditional transition at the actual predicate producer:

        producer(counter < bound, state=selector) -> true: body, false: exit

    The source producer redirect and the selector's sibling branch redirects are
    suppressed because the synthesized conditional edge owns that whole loop edge.
    """
    if fact_view is None:
        return []
    disp = int(dispatcher_entry_serial)
    handlers = {int(h.handler): h for h in handler_transitions}
    candidates: list[ConditionalStateTransitionCandidate] = []
    emitted_sources: set[int] = set()

    for fact in _loop_predicate_value_facts(fact_view):
        parsed = _parse_counter_bound_from_fact(fact)
        if parsed is None:
            continue
        counter_stkoff, counter_size, bound = parsed
        counter_alias = _fact_storage_token(fact)
        counter_stkoff = _resolve_counter_stkoff(
            flow_graph,
            fact,
            counter_alias,
            int(counter_stkoff),
        )
        evidence_blocks = _source_blocks_for_evidence(flow_graph, fact)
        if not evidence_blocks:
            continue
        for transition in transitions:
            source = int(transition.write_block)
            if source in emitted_sources or source not in evidence_blocks:
                continue
            if transition.next_state is None:
                continue
            selector = dispatcher.lookup(int(transition.next_state) & 0xFFFFFFFF)
            if selector is None:
                continue
            selector = int(selector)
            selector_block = flow_graph.get_block(selector)
            source_block = flow_graph.get_block(source)
            if selector_block is None or source_block is None:
                continue
            if tuple(int(s) for s in source_block.succs) != (disp,):
                continue
            selector_succs = tuple(int(s) for s in selector_block.succs)
            if len(selector_succs) != 2:
                continue
            handler = handlers.get(selector)
            if handler is None or not handler.is_conditional:
                continue
            arm_targets: dict[int, int] = {}
            for arm in handler.arms:
                if arm.branch_block is None or int(arm.branch_block) != selector:
                    continue
                old = _arm_branch_successor(arm)
                if old is None:
                    continue
                new = dispatcher.default_target if arm.is_return else arm.target_handler
                if new is not None:
                    arm_targets[int(old)] = int(new)
            true_target = arm_targets.get(selector_succs[0])
            false_target = arm_targets.get(selector_succs[1])
            if true_target is None or false_target is None:
                continue
            rewrite_ea = _first_insn_ea(source_block)
            if rewrite_ea is None:
                continue
            candidates.append(
                ConditionalStateTransitionCandidate(
                    source_serial=source,
                    old_dispatcher_serial=disp,
                    rewrite_from_ea=int(rewrite_ea),
                    condition_operand=SyntheticCounterBoundCondition(
                        counter_stkoff=int(counter_stkoff),
                        counter_reg=None,
                        counter_size=int(counter_size),
                        bound=int(bound),
                        signed=False,
                    ),
                    false_target_serial=int(false_target),
                    true_target_serial=int(true_target),
                    proof_id=getattr(fact, "fact_id", None),
                    reason="loop_carrier_guard",
                    suppressed_redirect_sources=frozenset((source, selector)),
                )
            )
            emitted_sources.add(source)
            if logger.info_on:
                logger.info(
                    "unflat conditional-transition: reason=loop_carrier_guard "
                    "producer=%s selector=%s "
                    "if(counter@stkoff=0x%x<0x%x) -> body=%s else exit=%s",
                    _format_block_label(flow_graph, source),
                    _format_block_label(flow_graph, selector),
                    int(counter_stkoff),
                    int(bound),
                    _format_block_label(flow_graph, true_target),
                    _format_block_label(flow_graph, false_target),
                )
    return candidates


def build_loop_carrier_guard_lowerings(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    handler_transitions: tuple[HandlerTransition, ...],
    fact_view,
    *,
    dispatcher_entry_serial: int,
):
    """Compatibility wrapper: recover then lower loop-carrier transitions."""
    return lower_conditional_transition_candidates(
        build_loop_carrier_guard_transitions(
            flow_graph,
            dispatcher,
            transitions,
            handler_transitions,
            fact_view,
            dispatcher_entry_serial=dispatcher_entry_serial,
        )
    )


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
    next-states *through a single shared back-edge write block* (the flattened
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
                # Edge-specific shared-write split: the back-edge model already
                # rewired this arm successor into the arm's shared write block
                # (``old -> arm.write_block``).  A branch redirect from the
                # selector to ``old`` would be redundant, and can target the
                # fall-through edge that the backend cannot express as a branch
                # target change.  Keep the actual write-anchor route instead.
                if (
                    old is not None
                    and arm.write_block is not None
                    and (int(old), int(arm.write_block)) in existing
                ):
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


def build_folded_loop_guard_transitions(
    flow_graph,
    dispatcher,
    transitions,
    fact_view,
    *,
    dispatcher_entry_serial: int,
):
    """Recover folded counted-loop guards as conditional state edges.

    Hex-Rays folds the constant-trip-count guard of a counted accumulation loop
    to a constant branch and DCEs the body arm before the unflatten recovery maturity,
    so the back-edge model recovers the guard handler as a SELF-LOOP (it writes
    its own loop-header state) and the loop renders as an empty ``while (1);``.
    The :class:`FoldedLoopGuardFact` (observed at the earlier LOCOPT maturity and
    carried forward) names the surviving counter slot, the numeric bound, and the
    body/exit state constants, so we re-materialize the explicit guard:

        guard:  if (counter < bound) -> route(body_state) else -> route(exit_state)

    Returns semantic ``CONDITIONAL_TRANSITION`` candidates.  Each candidate carries
    the guard ``from_serial`` redirect the caller must drop (the spurious self-loop
    the back-edge model emitted for the same block).  Strictly
    fact-gated -- emits nothing when no folded guard is observed, so non-loop
    indirect functions are unaffected.
    """
    if fact_view is None:
        return []
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
        return []

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

    candidates: list[ConditionalStateTransitionCandidate] = []
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
        candidates.append(
            ConditionalStateTransitionCandidate(
                source_serial=int(guard_serial),
                old_dispatcher_serial=disp,
                rewrite_from_ea=rewrite_ea,
                condition_operand=condition,
                false_target_serial=int(exit_target),
                true_target_serial=int(body_target),
                proof_id=fact.fact_id,
                reason="folded_loop_guard",
                suppressed_redirect_sources=frozenset((int(guard_serial),)),
            )
        )
        if logger.info_on:
            counter_desc = (
                f"reg=0x{int(counter_reg):x}"
                if counter_reg is not None
                else f"stkoff=0x{int(counter_stkoff):x}"
            )
            logger.info(
                "unflat conditional-transition: reason=folded_loop_guard "
                "guard=%s if(counter@%s<0x%x) "
                "-> body=%s(state=0x%x) else exit=%s(state=0x%x)",
                _format_block_label(flow_graph, guard_serial),
                counter_desc,
                int(bound),
                _format_block_label(flow_graph, body_target),
                int(body_state) & 0xFFFFFFFF,
                _format_block_label(flow_graph, exit_target),
                int(exit_state) & 0xFFFFFFFF,
            )
    return candidates


def build_folded_loop_guard_lowerings(
    flow_graph,
    dispatcher,
    transitions,
    fact_view,
    *,
    dispatcher_entry_serial: int,
):
    """Compatibility wrapper: recover then lower folded guard transitions."""
    return lower_conditional_transition_candidates(
        build_folded_loop_guard_transitions(
            flow_graph,
            dispatcher,
            transitions,
            fact_view,
            dispatcher_entry_serial=dispatcher_entry_serial,
        )
    )


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
    branch_witness_map: object | None = None,
    branch_witness_emu: object | None = None,
    entry_bridge_corridor_blocks: tuple[int, ...] = (),
    entry_bridge_requires_witness: bool = False,
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
    (handler-body accumulator carriers such as ``var_18 = var_378`` /
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
        # Preserve the ORACLE and the KIND separately (ticket llr-a93i): a bare
        # ``kind`` histogram cannot tell an abstract ``global_fold`` from a future
        # concrete one, and the whole promotion turns on seeing the concrete leg's
        # ``emulation_concrete_leg`` buckets emerge.  Key ``oracle:kind`` so the
        # distribution names the evidence source AND the resolution site.
        kinds: dict[str, int] = {}
        for t in transitions:
            if t.proof is not None:
                key = f"{t.proof.oracle_kind}:{t.proof.kind}"
            else:
                key = "unattributed"
            kinds[key] = kinds.get(key, 0) + 1
        logger.info(
            "unflat minimal unflatten: %d back-edge transitions, proof kinds=%s",
            len(transitions),
            dict(sorted(kinds.items())),
        )
    # Recover the initial state from the prologue's own state-write fold when the
    # caller could not supply it. The comparison-BST evidence collapses to a
    # single catch-all on a wide equality chain, so
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
    # state-var detection picked a current-state SHADOW slot: some flatteners write
    # the next state to one stack slot and a copy of the current state to another;
    # choosing the shadow makes every handler self-loop and hides the prologue's
    # real initial-state write. Better a flattened function than a destroyed one.
    # See ticket for the state-var disambiguation fix.
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
        branch_witness_map=branch_witness_map,
        branch_witness_emu=branch_witness_emu,
        entry_bridge_corridor_blocks=entry_bridge_corridor_blocks,
        entry_bridge_requires_witness=entry_bridge_requires_witness,
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
    loop_carrier_route_blocks = _loop_carrier_route_blocks(
        flow_graph,
        dispatcher,
        transitions,
        fact_view,
    )
    if loop_carrier_route_blocks and logger.info_on:
        logger.info(
            "unflat minimal unflatten: loop_carrier_routes=%s",
            ",".join("blk%d" % b for b in sorted(loop_carrier_route_blocks)),
        )
    latch_redirects, latch_suppressed = build_loop_carrier_latch_redirects(
        flow_graph,
        transitions,
        fact_view,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        state_var_stkoff=int(state_var_stkoff),
    )
    if latch_suppressed:
        mods = [
            m
            for m in mods
            if not (
                isinstance(m, (RedirectGoto, RedirectBranch))
                and int(m.from_serial) in latch_suppressed
            )
        ]
    if latch_redirects:
        mods = list(mods) + latch_redirects
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
    guard_candidates = build_loop_carrier_guard_transitions(
        flow_graph,
        dispatcher,
        transitions,
        handler_transitions,
        fact_view,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    guard_lowerings, guard_suppressed = lower_conditional_transition_candidates(
        guard_candidates
    )
    if guard_suppressed:
        mods = [
            m
            for m in mods
            if not (
                isinstance(m, (RedirectGoto, RedirectBranch))
                and int(m.from_serial) in guard_suppressed
            )
        ]
        arm_mods = [
            m
            for m in arm_mods
            if not (
                isinstance(m, (RedirectGoto, RedirectBranch))
                and int(m.from_serial) in guard_suppressed
            )
        ]
    if arm_mods:
        mods = list(mods) + arm_mods
    if guard_lowerings:
        mods = list(mods) + guard_lowerings
    output_store_retargets = build_output_store_retargets(
        flow_graph,
        fact_view,
    )
    if guard_suppressed:
        output_store_retargets = [
            m
            for m in output_store_retargets
            if not (
                isinstance(m, RetargetOutputStore)
                and int(m.block_serial) in guard_suppressed
            )
        ]
    if output_store_retargets:
        mods = list(mods) + output_store_retargets
    alias_scalarizations = build_local_alias_scalarizations(
        flow_graph,
        fact_view,
    )
    if guard_suppressed:
        alias_scalarizations = [
            m
            for m in alias_scalarizations
            if not (
                isinstance(m, ScalarizeLocalAliasAccess)
                and int(m.block_serial) in guard_suppressed
            )
        ]
    if alias_scalarizations:
        mods = list(mods) + alias_scalarizations
    if logger.info_on:
        n_cond = sum(1 for h in handler_transitions if h.is_conditional)
        logger.info(
            "unflat minimal unflatten: conditional_handlers=%d arm_redirects_added=%d "
            "loop_guards=%d suppressed=%d",
            n_cond,
            len(arm_mods),
            len(guard_lowerings),
            len(guard_suppressed),
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
        guard_candidates = build_folded_loop_guard_transitions(
            flow_graph,
            dispatcher,
            transitions,
            fact_view,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
        )
        guard_lowerings, suppressed = lower_conditional_transition_candidates(
            guard_candidates
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
    # NON-state-variable use. For the shadow-carrier shape the accumulator reaches the
    # terminal/guard only through carrier copies (``var_18 = var_378`` /
    # ``var_84 = var_378``); bypassing those blocks lets IDA backfill the slot from the
    # prologue (0 / failed-flag) and DCE the whole ``var_378`` computation (207->17).
    # Vetoing such a redirect keeps that back-edge on the dispatcher (engine-style
    # residual) so the carrier stays on-path. Gated ``D810_USE_DEF_VETO`` (default OFF
    # -> byte-identical); the state variable's own severance is the unflattening and is
    # never vetoed.
    if use_def_safety is not None and live_function is not None:
        # Conservative bail (ticket llr-wlzb): on a shape where unflattening would
        # orphan a non-state carrier (the pointer-indirected accumulator whose
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
