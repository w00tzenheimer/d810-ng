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

from collections.abc import Callable
from dataclasses import dataclass, replace
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
from d810.analyses.control_flow.detached_handler_island import (
    AppliedDetachedSnippetDirectBoundaryPort,
    AppliedDetachedSnippetConditionalBoundaryPort,
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetConditionalBoundaryPort,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    HandlerTransition,
    StateWriteTransition,
    _source_local_constant_register_write,
    block_has_live_carrier_write,
    recover_handler_transitions,
    resolve_materialized_handler_exit_states,
    resolve_materialized_handler_transition_targets,
    recover_state_write_transitions_via_partitioned_fixpoint,
    transition_uses_terminal_stack_alias_guard,
    transitions_use_terminal_stack_alias_guard,
    resolve_materialized_indirect_transfer_targets,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
    condition_code_predicate,
    find_unique_target_entry_block,
    is_conditional_handler_bridge_kind,
    lookup_state_keyed_transfer_target,
    plan_resolver_proven_indirect_call_neutralizations,
    unique_materialized_equality_target_eas,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
)
from d810.analyses.control_flow.route_predicate import DecisionDag
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.analyses.control_flow.state_machine_analysis import (
    _is_stop_block,
    run_snapshot_constant_fixpoint,
)
from d810.analyses.value_flow import (
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    OBSERVABLE_OUTPUT_FACT_TYPE,
    POINTS_TO_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    project_value_flow_facts,
)
from d810.core import logging
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.typing import Mapping
from d810.core.observability_preanalysis import (
    observe_branch_witness_decisions,
    observe_exit_path_shortcut_decisions,
)
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    block_label,
)
from d810.ir.flowgraph import BlockKind, InsnKind, OperandKind
from d810.ir.maturity import MaturityEnvelope
from d810.ir.semantics import PredicateKind
from d810.transforms.exit_path_liveness_policy import (
    exit_path_blocks_live_violations,
    evaluate_exit_path_shortcut,
    live_in_variables,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    LowerConditionalStateTransition,
    NopInstructions,
    PreserveLivePredicateCondition,
    RedirectBranch,
    RedirectGoto,
    RetargetOutputStore,
    ScalarizeLocalAliasAccess,
    SyntheticCounterBoundCondition,
    SyntheticRegisterNonzeroCondition,
    SyntheticStackValueEqualsCondition,
    ZeroStateWrite,
)
from d810.transforms.plan import PatchPlan, compile_patch_plan
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.exit_path_effect_emission import (
    plan_state_exit_path_effect_lowerings,
)
from d810.transforms.dispatcher_corridor_coverage import (
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    FULL_UNFLATTENING_CLAIM_METADATA,
    USE_DEF_SEVERANCE_AUDIT_METADATA,
    UNFLATTEN_COMPLETION_STATUS_METADATA,
    analyze_dispatcher_corridor_coverage,
    build_dispatcher_removal_preflight_proof,
)
from d810.transforms.use_def_redirect_filter import (
    audit_use_def_severances,
    severance_bail_enabled,
)

logger = logging.getLogger("d810.transforms.minimal_unflatten_emit")

TERMINAL_CARRIER_CONVERGENCE_METADATA = "terminal_carrier_convergence"
TERMINAL_CARRIER_CONVERGENCE_REASON_METADATA = "terminal_carrier_convergence_reason"

__all__ = [
    "ConditionalStateTransitionCandidate",
    "emit_minimal_unflatten",
    "build_state_write_redirects",
    "build_conditional_arm_redirects",
    "build_exact_terminal_state_route_redirects",
    "build_materialized_state_route_redirects",
    "build_source_keyed_handler_redirects",
    "build_materialized_conditional_handler_bridges",
    "build_stack_carried_state_selector_lowerings",
    "build_resolver_proven_indirect_call_neutralizations",
    "build_shared_merge_conditional_redirects",
    "build_loop_guard_exit_redirects",
    "build_folded_loop_guard_lowerings",
    "build_folded_loop_guard_transitions",
    "build_local_alias_scalarizations",
    "build_output_store_retargets",
    "build_loop_carrier_latch_redirects",
    "build_loop_carrier_guard_lowerings",
    "build_loop_carrier_guard_transitions",
    "lower_conditional_transition_candidates",
    "TERMINAL_CARRIER_CONVERGENCE_METADATA",
    "TERMINAL_CARRIER_CONVERGENCE_REASON_METADATA",
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


@dataclass(frozen=True, slots=True)
class BootstrapEntryRouteProof:
    """One exact, already-applied entry-prefix route in the current snapshot."""

    source_serial: int
    handler_serial: int
    state: int
    source_anchor_ea: int
    handler_anchor_ea: int


@dataclass(frozen=True, slots=True)
class ConditionalEntryBridgeProof:
    """One exact live entry predicate routed to two known handlers."""

    source_serial: int
    predicate_ea: int
    false_target_serial: int
    true_target_serial: int
    true_is_taken: bool = True


@dataclass(frozen=True, slots=True)
class ConditionalEntryBridgePlan:
    """One atomic resolver-proven conditional entry tree or forest."""

    proofs: tuple[ConditionalEntryBridgeProof, ...]
    root_source_serials: tuple[int, ...]


def lower_conditional_transition_candidates(
    candidates: (
        tuple[ConditionalStateTransitionCandidate, ...]
        | list[ConditionalStateTransitionCandidate]
    ),
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


def _routes_to_function_return(
    flow_graph, start: int, *, disp: int, bound: int = 16
) -> bool:
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


def _exact_native_terminal_redirect_target(
    flow_graph,
    target_handler: int | None,
) -> int | None:
    """Map an exact native epilogue target onto the MBA's canonical STOP."""
    if target_handler is None:
        return None
    target = flow_graph.get_block(int(target_handler))
    if target is None or target.nsucc != 0:
        return int(target_handler)
    if _is_stop_block(target):
        return int(target_handler)
    stop_targets = {
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if _is_stop_block(block)
    }
    return next(iter(stop_targets)) if len(stop_targets) == 1 else int(target_handler)


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
    entry_bridge_exit_path_blocks: tuple[int, ...],
    entry_bridge_requires_witness: bool,
    allow_multi_entry_witness_fallback: bool,
    cut_exit_path_uses: bool,
    _add,
) -> None:
    """Apply entry-bridge redirects, gated on exact branch witness resolution.

    When a ``BranchWitnessMap`` is available, resolve the exact branch witness
    path for ``initial_state_u`` and apply exit-path liveness before shortcutting.
    Abstain / conflict / unsafe exit path preserves CFG (no redirects emitted).
    Witness-required entry bridges fall back to exit-path liveness when no
    provider supplied a map: live stack/register definitions preserve CFG;
    live-safe exit paths keep legacy endpoint shortcutting.
    """
    if branch_witness_map is None:
        if entry_bridge_requires_witness:
            exit_path_blocks = tuple(
                sorted({int(block) for block in entry_bridge_exit_path_blocks})
            ) or (int(disp),)
            unsafe = exit_path_blocks_live_violations(
                flow_graph,
                exit_path_blocks,
                int(first),
                state_var_stkoff,
                source_blocks=tuple(sorted(int(p) for p in prologue_preds)),
                old_target=int(disp),
                cut_exit_path_uses=cut_exit_path_uses,
            )
            reason = (
                "no_provider_exit_path_liveness_unsafe"
                if unsafe
                else "no_provider_exit_path_live_safe_endpoint"
            )
            _observe_branch_witness_result(
                flow_graph,
                state=initial_state_u,
                dispatcher_entry_block=disp,
                witness_result=BranchWitnessAbstain(reason),
            )
            _observe_exit_path_shortcut_decision(
                flow_graph,
                source_blocks=prologue_preds,
                old_target=disp,
                shortcut_target=first,
                witness_result=BranchWitnessAbstain(reason),
                decision_reason=reason,
                decision_allowed=not unsafe,
                exit_path_blocks=exit_path_blocks,
                live_definitions=tuple(sorted(unsafe)),
            )
            if not unsafe:
                if logger.info_on:
                    logger.info(
                        "unflat entry bridge: LEGACY_ENDPOINT state=0x%X "
                        "reason=%s target=%s exit_path=%s",
                        initial_state_u,
                        reason,
                        _format_block_label(flow_graph, first),
                        _format_block_labels(flow_graph, exit_path_blocks),
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
                    "reason=%s target=%s exit_path=%s live=%s",
                    initial_state_u,
                    reason,
                    _format_block_label(flow_graph, first),
                    _format_block_labels(flow_graph, exit_path_blocks),
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
        flow_graph,
        dispatcher,
        initial_state_u,
        state_var_stkoff,
        branch_witness_map=branch_witness_map,
        emu=branch_witness_emu,
    )
    _observe_branch_witness_result(
        flow_graph,
        state=initial_state_u,
        dispatcher_entry_block=disp,
        witness_result=witness,
    )
    decision = evaluate_exit_path_shortcut(
        flow_graph, witness, int(first), state_var_stkoff
    )
    _observe_exit_path_shortcut_decision(
        flow_graph,
        source_blocks=prologue_preds,
        old_target=disp,
        shortcut_target=first,
        witness_result=witness,
        decision_reason=decision.reason,
        decision_allowed=decision.allowed,
        exit_path_blocks=decision.exit_path_blocks,
        live_definitions=decision.live_definitions,
    )
    if not decision.allowed:
        if (
            allow_multi_entry_witness_fallback
            and isinstance(witness, BranchWitnessAbstain)
            and witness.reason == "selected_successor_not_dispatcher_endpoint"
        ):
            exit_path_blocks = tuple(
                sorted({int(block) for block in entry_bridge_exit_path_blocks})
            ) or (int(disp),)
            unsafe = exit_path_blocks_live_violations(
                flow_graph,
                exit_path_blocks,
                int(first),
                state_var_stkoff,
                source_blocks=tuple(sorted(int(p) for p in prologue_preds)),
                old_target=int(disp),
                cut_exit_path_uses=cut_exit_path_uses,
            )
            _observe_exit_path_shortcut_decision(
                flow_graph,
                source_blocks=prologue_preds,
                old_target=disp,
                shortcut_target=first,
                witness_result=witness,
                decision_reason=(
                    "multi_entry_exact_map_live_safe"
                    if not unsafe
                    else "multi_entry_exact_map_liveness_unsafe"
                ),
                decision_allowed=not unsafe,
                exit_path_blocks=exit_path_blocks,
                live_definitions=tuple(sorted(unsafe)),
            )
            if not unsafe:
                if logger.info_on:
                    logger.info(
                        "unflat entry bridge: MULTI_ENTRY_EXACT state=0x%X "
                        "reason=selected_successor_not_dispatcher_endpoint "
                        "target=%s exit_path=%s",
                        initial_state_u,
                        _format_block_label(flow_graph, first),
                        _format_block_labels(flow_graph, exit_path_blocks),
                    )
                for entry_pred in sorted(prologue_preds):
                    epblk = flow_graph.get_block(int(entry_pred))
                    if epblk is None:
                        continue
                    _add(int(entry_pred), disp, int(first), two_way=(epblk.nsucc == 2))
                return
        if logger.info_on:
            logger.info(
                "unflat entry bridge: PRESERVED state=0x%X reason=%s "
                "target=%s exit_path=%s",
                initial_state_u,
                decision.reason,
                _format_block_label(flow_graph, first),
                _format_block_labels(flow_graph, decision.exit_path_blocks),
            )
        return  # preserve CFG
    for entry_pred in sorted(prologue_preds):
        epblk = flow_graph.get_block(int(entry_pred))
        if epblk is None:
            continue
        _add(int(entry_pred), disp, int(first), two_way=(epblk.nsucc == 2))


def _has_multi_entry_forward_chain(
    transitions: tuple[StateWriteTransition, ...],
    first_handler: int,
    *,
    min_edges: int = 3,
) -> bool:
    """Whether recovered redirects form a non-cyclic chain from the entry target."""

    next_by_source: dict[int, int] = {}
    multi_entry_sources: set[int] = set()
    for transition in transitions:
        if transition.next_state is None or transition.target_handler is None:
            continue
        if transition.is_return:
            continue
        source = int(transition.write_block)
        target = int(transition.target_handler)
        if source == target:
            continue
        next_by_source.setdefault(source, target)
        if transition.via_block is not None:
            multi_entry_sources.add(source)

    seen: set[int] = set()
    current = int(first_handler)
    edges = 0
    used_multi_entry = False
    while current in next_by_source:
        if current in seen:
            return False
        seen.add(current)
        used_multi_entry = used_multi_entry or current in multi_entry_sources
        current = int(next_by_source[current])
        edges += 1
    return used_multi_entry and edges >= min_edges


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
            rows.append(
                {
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
                }
            )
    elif isinstance(witness_result, BranchWitnessAbstain):
        rows.append(
            {
                "state": int(state),
                "dispatcher_entry_block": dispatcher_entry_block,
                "outcome": "abstained",
                "reason": witness_result.reason,
            }
        )
    elif isinstance(witness_result, BranchWitnessConflict):
        rows.append(
            {
                "state": int(state),
                "dispatcher_entry_block": dispatcher_entry_block,
                "outcome": "conflict",
                "reason": ";".join(str(r) for r in witness_result.reasons),
            }
        )
    if rows:
        observe_branch_witness_decisions(func_ea=func_ea, rows=tuple(rows))


def _observe_exit_path_shortcut_decision(
    flow_graph: object,
    *,
    source_blocks: set[int],
    old_target: int,
    shortcut_target: int,
    witness_result: object,
    decision_reason: str,
    decision_allowed: bool,
    exit_path_blocks: tuple[int, ...] = (),
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
            "exit_path_blocks": tuple(int(b) for b in exit_path_blocks),
            "rejected_successors": tuple(rejected_successors),
            "outcome": "allowed" if decision_allowed else "rejected",
            "reason": decision_reason,
            "live_definitions": tuple(
                {"kind": kind, "value": int(value)} for kind, value in live_definitions
            ),
        }
        for source_block in sorted(source_blocks)
    ]
    if rows:
        observe_exit_path_shortcut_decisions(func_ea=func_ea, rows=tuple(rows))


def _state_predicate_successor_for_value(
    block: object,
    *,
    state_var_stkoff: int,
    value: int,
) -> int | None:
    """Return the successor selected when a state-slot predicate sees ``value``."""

    succs = tuple(int(s) for s in getattr(block, "succs", ()) or ())
    if len(succs) != 2:
        return None
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if not insns:
        return None
    tail = insns[-1]
    if not getattr(tail, "is_conditional_jump", False):
        return None
    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    left_state = int(state_var_stkoff) in _mop_stack_refs(left)
    right_state = int(state_var_stkoff) in _mop_stack_refs(right)
    left_value = _mop_number_value(left)
    right_value = _mop_number_value(right)
    compares_value = (
        left_state and right_value is not None and int(right_value) == int(value)
    ) or (right_state and left_value is not None and int(left_value) == int(value))
    if not compares_value:
        return None
    predicate = getattr(tail, "branch_predicate", None)
    if predicate is PredicateKind.EQ:
        return succs[1]
    if predicate is PredicateKind.NE:
        return succs[0]
    return None


def _terminal_alias_materializer_parent_redirects(
    flow_graph,
    transition: StateWriteTransition,
    *,
    initial_state: int | None,
    state_var_stkoff: int | None,
) -> tuple[tuple[int, int, int], ...]:
    """Retarget infeasible sibling edges through the proven alias materializer.

    A terminal stack-alias proof means ``src -> via`` is the path that sets the
    terminal state-store pointer to the dispatcher state slot before ``via`` stores
    the terminal state and result carrier.  In the nested OLLVM join shape the
    parent is a two-way state predicate with successors ``{src, via}``; for the
    current dispatcher state, only the ``src`` arm is feasible, while the sibling
    ``via`` arm keeps the shared dispatcher fallback alive and structures as a
    residual loop.  When the parent predicate structurally selects ``src`` for the
    recovered initial state, fold the sibling arm back through ``src``.
    """

    if initial_state is None or state_var_stkoff is None:
        return ()
    if not transition_uses_terminal_stack_alias_guard(transition):
        return ()
    vb = transition.via_block
    if vb is None:
        return ()
    src = int(transition.write_block)
    via = int(vb)
    src_block = flow_graph.get_block(src)
    if src_block is None or tuple(int(s) for s in src_block.succs) != (via,):
        return ()
    out: list[tuple[int, int, int]] = []
    for parent_serial in tuple(int(p) for p in getattr(src_block, "preds", ()) or ()):
        parent = flow_graph.get_block(parent_serial)
        if parent is None or int(getattr(parent, "nsucc", 0)) != 2:
            continue
        succs = tuple(int(s) for s in getattr(parent, "succs", ()) or ())
        if set(succs) != {src, via}:
            continue
        selected = _state_predicate_successor_for_value(
            parent,
            state_var_stkoff=int(state_var_stkoff),
            value=int(initial_state),
        )
        if selected != src:
            continue
        out.append((parent_serial, via, src))
    return tuple(out)


def _recover_register_conditional_entry(
    flow_graph,
    dispatcher,
    disp: int,
    *,
    state_var_reg: int,
    materialized_indirect_transfers: tuple[MaterializedIndirectTransfer, ...] = (),
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    materialized_handler_by_state: Mapping[int, int] | None = None,
    condition_chain_handlers: frozenset[int] = frozenset(),
    entry_bridge_evidence: EntryBridgeEvidence | None = None,
) -> list[tuple[int, int, int]]:
    """Recover a prologue conditional carried in a NON-state register.

    Some comparison-tree dispatchers select their initial dispatch state in a
    scratch register while the state var itself carries a non-leaf decoy. The state-var fixpoint
    therefore recovers no leaf arm transition, but the conditional's *values* still
    route through the dispatcher's equality leaves.

    Walk back from the dispatcher through single-predecessor prologue glue to the
    prologue MERGE (the first block with >= 2 prologue-reachable predecessors),
    fold each merge-predecessor's registers with the register-domain fixpoint, and
    for every predecessor whose folded register value is a dispatcher leaf yield
    ``(pred, merge, handler)``. An asymmetric arm containing a range pivot rather
    than a leaf is simply absent from the result --
    the raw-target pass (step 2) owns it. Returns ``[]`` when no register
    conditional feeds the dispatcher, so non-conditional prologues are untouched.
    """
    entry = flow_graph.entry_serial
    # Prologue reachability: blocks reached from the function entry WITHOUT passing
    # through the dispatcher (so handler back-edges never count as prologue paths).
    prologue_reach: set[int] = set()
    stack = [int(entry)]
    while stack:
        s = stack.pop()
        if s in prologue_reach or s == int(disp):
            continue
        blk = flow_graph.get_block(s)
        if blk is None:
            continue
        prologue_reach.add(s)
        stack.extend(int(x) for x in blk.succs if int(x) != int(disp))

    merge: int | None = None
    if entry_bridge_evidence is not None:
        source_store_ea = int(entry_bridge_evidence.source_store_ea)
        anchored_merges = tuple(
            int(block.serial)
            for block in flow_graph.blocks.values()
            if any(
                int(instruction.ea) == source_store_ea
                for instruction in block.insn_snapshots
            )
        )
        if len(anchored_merges) != 1:
            return []
        anchored_merge = anchored_merges[0]
        if anchored_merge not in prologue_reach or anchored_merge == int(disp):
            return []
        merge = anchored_merge
    else:
        # Backward glue walk: from the dispatcher, follow the unique
        # prologue-reachable predecessor chain until a merge (>= 2
        # prologue-reachable preds) is found.
        cur = int(disp)
        visited: set[int] = set()
        while True:
            blk = flow_graph.get_block(cur)
            if blk is None:
                return []
            p_reach = [int(p) for p in blk.preds if int(p) in prologue_reach]
            if len(p_reach) >= 2:
                merge = cur
                break
            if len(p_reach) == 1:
                nxt = p_reach[0]
                if nxt in visited:
                    return []
                visited.add(nxt)
                cur = nxt
                continue
            return []  # no merge on the prologue path -> not a conditional entry

    merge_blk = flow_graph.get_block(merge)
    if merge_blk is None:
        return []
    fp = run_snapshot_constant_fixpoint(flow_graph, -1)
    routes: list[tuple[int, int, int]] = []

    def _materialized_target(state: int) -> int | None:
        targets = {
            int(route.target_handler_serial)
            for route in materialized_state_routes
            if (int(route.state_constant) & 0xFFFFFFFF) == (int(state) & 0xFFFFFFFF)
        }
        if len(targets) != 1:
            return None
        target = next(iter(targets))
        if condition_chain_handlers and target not in condition_chain_handlers:
            return None
        return target

    def _exact_equality_target(state: int) -> int | None:
        state_u = int(state) & 0xFFFFFFFF
        candidates: set[int] = set()
        for transfer in materialized_indirect_transfers:
            selector = transfer.selector_state_constant
            compared = transfer.selector_compare_constant
            if selector is None and (
                compared is None
                or (int(compared) & 0xFFFFFFFF) != state_u
                or transfer.condition_code not in (4, 5)
            ):
                continue
            if selector is not None and (int(selector) & 0xFFFFFFFF) != state_u:
                continue
            target = lookup_state_keyed_transfer_target(
                flow_graph,
                transfer,
                state_u,
                state_var_reg=int(state_var_reg),
            )
            if target is None:
                continue
            target_block = flow_graph.get_block(int(target))
            if target_block is None or target_block.kind is BlockKind.EXTERNAL:
                continue
            candidates.add(int(target))
        return next(iter(candidates)) if len(candidates) == 1 else None

    def _portable_handler_target(state: int) -> int | None:
        if not materialized_handler_by_state:
            return None
        target = materialized_handler_by_state.get(int(state) & 0xFFFFFFFF)
        if target is None:
            return None
        target = int(target)
        target_block = flow_graph.get_block(target)
        if target_block is None or target_block.kind is BlockKind.EXTERNAL:
            return None
        if condition_chain_handlers and target not in condition_chain_handlers:
            return None
        return target

    def _resolve_state_target(value: int) -> int | None:
        handler = _exact_equality_target(int(value))
        if handler is None:
            handler = _portable_handler_target(int(value))
        if handler is None:
            handler = dispatcher.lookup(int(value) & 0xFFFFFFFF)
            if (
                handler is not None
                and condition_chain_handlers
                and int(handler) not in condition_chain_handlers
            ):
                handler = None
        if handler is None:
            handler = _materialized_target(int(value))
        return int(handler) if handler is not None else None

    prologue_preds = tuple(
        int(pred) for pred in merge_blk.preds if int(pred) in prologue_reach
    )
    if len(prologue_preds) < 2:
        return []
    pred_register_maps = tuple(fp.out_reg_maps.get(pred, {}) for pred in prologue_preds)
    shared_registers = set(pred_register_maps[0])
    for register_map in pred_register_maps[1:]:
        shared_registers &= set(register_map)

    # Select ONE register across the whole merge.  Choosing the first
    # dispatcher-valued register independently on each predecessor can mix
    # unrelated registers and route both arms to a coincidental state.  A real
    # conditional carrier is present on every arm and changes value across the
    # merge.  If more than one such register proves a different route set, fail
    # closed instead of guessing.
    candidate_route_sets: set[tuple[tuple[int, int, int], ...]] = set()
    for register in sorted(shared_registers):
        values = tuple(
            int(register_map[register]) & 0xFFFFFFFF
            for register_map in pred_register_maps
        )
        if len(set(values)) < 2:
            continue
        register_routes = tuple(
            (pred, int(merge), handler)
            for pred, value in zip(prologue_preds, values)
            for handler in (_resolve_state_target(value),)
            if handler is not None
        )
        if register_routes:
            candidate_route_sets.add(register_routes)

    if len(candidate_route_sets) != 1:
        return []
    routes.extend(next(iter(candidate_route_sets)))
    # Require at least one resolvable arm AND >= 2 prologue arms overall (a genuine
    # conditional); a single prologue arm is the scalar-initial-state case.
    if not routes:
        return []
    if logger.info_on:
        logger.info(
            "unflat register-conditional entry routes: %s",
            [
                (
                    _format_block_label(flow_graph, pred),
                    _format_block_label(flow_graph, merge_serial),
                    _format_block_label(flow_graph, handler),
                )
                for pred, merge_serial, handler in routes
            ],
        )
    return routes


def _strict_one_way_path_enters_region(
    flow_graph,
    start_serial: int,
    region_serials: frozenset[int],
    *,
    state_var_reg: int,
    resolver_cut_endpoint_serials: frozenset[int] = frozenset(),
    max_hops: int = 8,
) -> frozenset[tuple[str, int]] | None:
    """Prove a transparent route and return register defs it bypasses.

    Hex-Rays can split one conditional arm into a one-way trampoline before
    the comparison-tree block.  Optional NOPs, one terminal GOTO, and
    register copies and address formation are structurally transparent.  Their
    destinations are returned so the caller can independently prove they are
    dead at every direct handler target before bypassing them.
    """
    current = int(start_serial)
    region = frozenset(int(serial) for serial in region_serials)
    seen: set[int] = set()
    bypassed_definitions: set[tuple[str, int]] = set()
    for _hop in range(int(max_hops) + 1):
        if current in region:
            return frozenset(bypassed_definitions)
        if current in seen:
            return None
        seen.add(current)
        block = flow_graph.get_block(current)
        if block is None or int(block.nsucc) != 1:
            return None
        semantic_insns = tuple(
            instruction
            for instruction in block.insn_snapshots
            if instruction.kind is not InsnKind.NOP
        )
        goto_insns = tuple(
            instruction
            for instruction in semantic_insns
            if instruction.kind is InsnKind.GOTO
        )
        transparent_moves = tuple(
            instruction
            for instruction in semantic_insns
            if instruction.kind is InsnKind.MOV
            and instruction.l is not None
            and instruction.l.kind in {OperandKind.REGISTER, OperandKind.ADDRESS}
            and instruction.d is not None
            and instruction.d.kind is OperandKind.REGISTER
            and instruction.d.reg is not None
            and int(instruction.d.reg) != int(state_var_reg)
        )
        standard_transparent = (
            len(goto_insns) <= 1
            and len(goto_insns) + len(transparent_moves) == len(semantic_insns)
            and (not goto_insns or semantic_insns[-1] is goto_insns[0])
        )
        if standard_transparent:
            pass
        elif current in resolver_cut_endpoint_serials:
            if len(goto_insns) != 1 or semantic_insns[-1] is not goto_insns[0]:
                return None
            pure_definitions: set[tuple[str, int]] = set()
            for instruction in semantic_insns[:-1]:
                if instruction.kind in {
                    InsnKind.CALL,
                    InsnKind.COND_JUMP,
                    InsnKind.EQUALITY_JUMP,
                    InsnKind.GOTO,
                    InsnKind.INDIRECT_JUMP,
                    InsnKind.RET,
                    InsnKind.STORE,
                    InsnKind.TABLE_JUMP,
                }:
                    return None
                destination = instruction.d
                if (
                    destination is None
                    or destination.kind is not OperandKind.REGISTER
                    or destination.reg is None
                    or int(destination.reg) == int(state_var_reg)
                ):
                    return None
                pure_definitions.add(("reg", int(destination.reg)))
            bypassed_definitions.update(pure_definitions)
        else:
            return None
        successor = int(block.succs[0])
        if goto_insns:
            destination = goto_insns[0].d
            if (
                destination is not None
                and destination.block_ref is not None
                and int(destination.block_ref) != successor
            ):
                return None
        bypassed_definitions.update(
            ("reg", int(instruction.d.reg)) for instruction in transparent_moves
        )
        current = successor
    return None


def _strict_paths_converge_on_indirect_endpoint(
    flow_graph,
    start_serials: tuple[int, ...],
    *,
    state_var_reg: int,
    expected_endpoint_serial: int | None = None,
    max_hops: int = 8,
) -> tuple[frozenset[tuple[str, int]], ...] | None:
    """Prove pure one-way arms converge on one unresolved indirect jump.

    Detached PREOPT snippets can retain the native computed-jump router after
    the state-cell load has already folded into the branch at the snippet
    root.  Bypassing that router is safe only when every arm reaches the same
    terminal indirect jump through NOPs, terminal GOTOs, and register copies.
    Copy destinations are returned for the caller's handler-liveness veto.
    """
    if len(start_serials) < 2:
        return None

    endpoints: list[int] = []
    path_definitions: list[frozenset[tuple[str, int]]] = []
    for start_serial in start_serials:
        current = int(start_serial)
        seen: set[int] = set()
        definitions: set[tuple[str, int]] = set()
        endpoint: int | None = None
        for _hop in range(int(max_hops) + 1):
            if current in seen:
                return None
            seen.add(current)
            block = flow_graph.get_block(current)
            if block is None:
                return None
            semantic_insns = tuple(
                instruction
                for instruction in block.insn_snapshots
                if instruction.kind is not InsnKind.NOP
            )
            if int(block.nsucc) == 0:
                if (
                    len(semantic_insns) != 1
                    or semantic_insns[0].kind is not InsnKind.INDIRECT_JUMP
                ):
                    return None
                endpoint = current
                break
            if int(block.nsucc) != 1:
                return None
            goto_insns = tuple(
                instruction
                for instruction in semantic_insns
                if instruction.kind is InsnKind.GOTO
            )
            register_copies = tuple(
                instruction
                for instruction in semantic_insns
                if instruction.kind is InsnKind.MOV
                and instruction.l is not None
                and instruction.l.kind is OperandKind.REGISTER
                and instruction.d is not None
                and instruction.d.kind is OperandKind.REGISTER
                and instruction.d.reg is not None
                and int(instruction.d.reg) != int(state_var_reg)
            )
            if (
                len(goto_insns) > 1
                or len(goto_insns) + len(register_copies) != len(semantic_insns)
                or (goto_insns and semantic_insns[-1] is not goto_insns[0])
            ):
                return None
            successor = int(block.succs[0])
            if goto_insns:
                destination = goto_insns[0].d
                if (
                    destination is not None
                    and destination.block_ref is not None
                    and int(destination.block_ref) != successor
                ):
                    return None
            definitions.update(
                ("reg", int(instruction.d.reg)) for instruction in register_copies
            )
            current = successor
        if endpoint is None:
            return None
        endpoints.append(endpoint)
        path_definitions.append(frozenset(definitions))

    if len(set(endpoints)) != 1:
        return None
    if expected_endpoint_serial is not None and endpoints[0] != int(
        expected_endpoint_serial
    ):
        return None
    return tuple(path_definitions)


def _applied_resolver_cut_conditional_endpoints(
    flow_graph,
    evidence_rows: tuple[AppliedDetachedSnippetConditionalBoundaryPort, ...],
    *,
    router_blocks: frozenset[int],
    state_var_reg: int,
) -> dict[int, frozenset[tuple[str, int]]]:
    """Bind exact applied resolver-cut predicates whose arms enter routers."""
    routers = frozenset(int(serial) for serial in router_blocks)
    endpoints: dict[int, frozenset[tuple[str, int]]] = {}

    def anchored_blocks(anchor_eas: tuple[int, ...]) -> set[int]:
        anchors = {int(ea) for ea in anchor_eas}
        return {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if any(int(insn.ea) in anchors for insn in block.insn_snapshots)
        }

    for evidence in evidence_rows:
        port = evidence.port
        if (
            port.resolver_kind != "resolver_proven_register_compare_cut"
            or port.logical_source_anchor_ea is not None
            or port.taken_target_ea == port.fallthrough_target_ea
        ):
            continue
        predicate_blocks = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.nsucc) == 2
            and block.insn_snapshots
            and block.insn_snapshots[-1].is_conditional_jump
            and int(block.insn_snapshots[-1].ea) == int(port.predicate_ea)
        }
        taken_targets = anchored_blocks(evidence.taken_target_anchor_eas)
        fallthrough_targets = anchored_blocks(evidence.fallthrough_target_anchor_eas)
        if logger.info_on:
            logger.info(
                "applied resolver-cut conditional candidate: predicate=0x%X "
                "predicate_blocks=%s taken_blocks=%s fallthrough_blocks=%s "
                "taken_router=%s fallthrough_router=%s",
                int(port.predicate_ea),
                [
                    _format_block_label(flow_graph, serial)
                    for serial in sorted(predicate_blocks)
                ],
                [
                    _format_block_label(flow_graph, serial)
                    for serial in sorted(taken_targets)
                ],
                [
                    _format_block_label(flow_graph, serial)
                    for serial in sorted(fallthrough_targets)
                ],
                bool(taken_targets and taken_targets <= routers),
                bool(fallthrough_targets and fallthrough_targets <= routers),
            )
        if (
            len(predicate_blocks) != 1
            or len(taken_targets) != 1
            or len(fallthrough_targets) != 1
        ):
            continue
        endpoint = next(iter(predicate_blocks))
        taken_target = next(iter(taken_targets))
        fallthrough_target = next(iter(fallthrough_targets))
        if (
            taken_target not in routers
            or fallthrough_target not in routers
            or taken_target == fallthrough_target
        ):
            continue
        block = flow_graph.get_block(endpoint)
        assert block is not None
        tail = block.insn_snapshots[-1]
        taken_start = tail.d.block_ref if tail.d is not None else None
        if taken_start is None or int(taken_start) not in block.succs:
            continue
        fallthrough_starts = tuple(
            int(successor)
            for successor in block.succs
            if int(successor) != int(taken_start)
        )
        if len(fallthrough_starts) != 1:
            continue
        taken_proof = _strict_one_way_path_enters_region(
            flow_graph,
            int(taken_start),
            frozenset({taken_target}),
            state_var_reg=int(state_var_reg),
        )
        fallthrough_proof = _strict_one_way_path_enters_region(
            flow_graph,
            fallthrough_starts[0],
            frozenset({fallthrough_target}),
            state_var_reg=int(state_var_reg),
        )
        if taken_proof is None or fallthrough_proof is None:
            if logger.info_on:
                logger.info(
                    "applied resolver-cut conditional abstained: predicate=0x%X "
                    "gate=arm_path taken=%s fallthrough=%s",
                    int(port.predicate_ea),
                    taken_proof is not None,
                    fallthrough_proof is not None,
                )
            continue
        definitions = frozenset({*taken_proof, *fallthrough_proof})
        existing = endpoints.get(endpoint)
        if existing is not None and existing != definitions:
            endpoints.pop(endpoint, None)
            continue
        endpoints[endpoint] = definitions
    return endpoints


def _strict_paths_converge_on_applied_conditional_endpoint(
    flow_graph,
    start_serials: tuple[int, ...],
    endpoint_definitions: Mapping[int, frozenset[tuple[str, int]]],
    *,
    state_var_reg: int,
    max_hops: int = 8,
) -> tuple[frozenset[tuple[str, int]], ...] | None:
    """Prove pure one-way arms converge on one receipt-bound predicate."""
    if len(start_serials) < 2 or not endpoint_definitions:
        return None
    endpoints: list[int] = []
    path_definitions: list[frozenset[tuple[str, int]]] = []
    forbidden_kinds = {
        InsnKind.CALL,
        InsnKind.COND_JUMP,
        InsnKind.EQUALITY_JUMP,
        InsnKind.GOTO,
        InsnKind.INDIRECT_JUMP,
        InsnKind.RET,
        InsnKind.STORE,
        InsnKind.TABLE_JUMP,
    }
    for start_serial in start_serials:
        current = int(start_serial)
        seen: set[int] = set()
        definitions: set[tuple[str, int]] = set()
        endpoint: int | None = None
        for _hop in range(int(max_hops) + 1):
            if current in endpoint_definitions:
                endpoint = current
                definitions.update(endpoint_definitions[current])
                break
            if current in seen:
                return None
            seen.add(current)
            block = flow_graph.get_block(current)
            if block is None or int(block.nsucc) != 1:
                return None
            semantic_insns = tuple(
                instruction
                for instruction in block.insn_snapshots
                if instruction.kind is not InsnKind.NOP
            )
            goto_insns = tuple(
                instruction
                for instruction in semantic_insns
                if instruction.kind is InsnKind.GOTO
            )
            if len(goto_insns) > 1 or (
                goto_insns and semantic_insns[-1] is not goto_insns[0]
            ):
                return None
            for instruction in semantic_insns[:-1] if goto_insns else semantic_insns:
                destination = instruction.d
                if (
                    instruction.kind in forbidden_kinds
                    or destination is None
                    or destination.kind is not OperandKind.REGISTER
                    or destination.reg is None
                    or int(destination.reg) == int(state_var_reg)
                ):
                    return None
                definitions.add(("reg", int(destination.reg)))
            successor = int(block.succs[0])
            if goto_insns:
                destination = goto_insns[0].d
                if (
                    destination is not None
                    and destination.block_ref is not None
                    and int(destination.block_ref) != successor
                ):
                    return None
            current = successor
        if endpoint is None:
            return None
        endpoints.append(endpoint)
        path_definitions.append(frozenset(definitions))
    if len(set(endpoints)) != 1:
        return None
    return tuple(path_definitions)


def _resolver_cut_endpoint_serials(
    flow_graph,
    evidence_rows: tuple[AppliedDetachedSnippetDirectBoundaryPort, ...],
    router_blocks: frozenset[int],
) -> frozenset[int]:
    """Imported endpoints whose exact resolver target enters this router."""

    def matching_blocks(anchor_eas: tuple[int, ...]) -> set[int]:
        anchors = {int(ea) for ea in anchor_eas}
        return {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if any(int(insn.ea) in anchors for insn in block.insn_snapshots)
        }

    endpoints: set[int] = set()
    for evidence in evidence_rows:
        if evidence.port.delivery_mode != "terminal_goto":
            continue
        endpoint_blocks = matching_blocks(evidence.endpoint_anchor_eas)
        target_blocks = matching_blocks(evidence.target_anchor_eas)
        if logger.info_on:
            logger.info(
                "resolver-cut endpoint mapping: source=0x%X endpoint_anchors=%s "
                "endpoint_blocks=%s target=0x%X target_anchors=%s target_blocks=%s",
                int(evidence.port.source_instruction_ea),
                tuple(hex(int(ea)) for ea in evidence.endpoint_anchor_eas),
                tuple(
                    _format_block_label(flow_graph, serial)
                    for serial in sorted(endpoint_blocks)
                ),
                int(evidence.port.target_ea),
                tuple(hex(int(ea)) for ea in evidence.target_anchor_eas),
                tuple(
                    _format_block_label(flow_graph, serial)
                    for serial in sorted(target_blocks)
                ),
            )
        if len(endpoint_blocks) != 1 or len(target_blocks) != 1:
            continue
        endpoint_root = next(iter(endpoint_blocks))
        target_block = next(iter(target_blocks))
        if target_block not in router_blocks:
            continue
        corridor: set[int] = set()
        visiting: set[int] = set()
        memo: dict[int, bool] = {}

        def reaches_exact_target(serial: int) -> bool:
            serial = int(serial)
            if serial == target_block:
                return True
            if serial in memo:
                return memo[serial]
            if serial in visiting or serial in router_blocks or len(corridor) >= 32:
                return False
            block = flow_graph.get_block(serial)
            if block is None or int(block.nsucc) == 0:
                return False
            visiting.add(serial)
            corridor.add(serial)
            valid_path = all(
                reaches_exact_target(int(successor)) for successor in block.succs
            )
            visiting.remove(serial)
            memo[serial] = valid_path
            return valid_path

        if not reaches_exact_target(endpoint_root):
            continue
        endpoints.update(corridor)
    return frozenset(endpoints)


def _resolver_proven_live_terminal_endpoint_serials(
    flow_graph,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    imported_endpoint_serials: frozenset[int],
) -> frozenset[int]:
    """Return unique live ``ijmp`` endpoints with exact two-arm replay.

    PREOPT import can clone the handler that owns an equality state while the
    original live handler still owns a folded stack predicate.  A detached
    static replay authorizes that original handler only when it names one
    unambiguous live indirect-jump instruction and proves both branch arms.
    Imported resolver-cut endpoints are excluded so clone ownership cannot
    replace the live dispatcher frontier.
    """
    endpoints: set[int] = set()
    for transfer in transfers:
        true_target_ea = transfer.true_target_ea
        false_target_ea = transfer.false_target_ea
        if (
            transfer.resolver_kind != "detached_static_fixpoint"
            or condition_code_predicate(transfer.condition_code) is None
            or true_target_ea is None
            or false_target_ea is None
            or int(true_target_ea) == int(false_target_ea)
            or {int(true_target_ea), int(false_target_ea)}
            != {int(target_ea) for target_ea in transfer.target_eas}
        ):
            continue
        matching = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.serial) not in imported_endpoint_serials
            and any(
                instruction.kind is InsnKind.INDIRECT_JUMP
                and int(instruction.ea) == int(transfer.source_jmp_ea)
                for instruction in block.insn_snapshots
            )
        }
        if len(matching) == 1:
            endpoints.update(matching)
    return frozenset(endpoints)


def _native_stack_carried_choice_owners(
    flow_graph,
    choices: tuple[MaterializedIndirectTransfer, ...],
    *,
    eligible_serials: frozenset[int],
    imported_serials: frozenset[int],
    carrier_vd_stkoffs_by_store_ea: Mapping[int, int],
    native_consumer_serials_by_load_ea: Mapping[int, int],
) -> tuple[
    dict[MaterializedIndirectTransfer, int],
    frozenset[MaterializedIndirectTransfer],
]:
    """Choose the live semantic owner of each native stack-carried choice.

    PREOPT can import the native load/re-entry block as a detached clone while
    LOCOPT keeps the same selector as a connected comparison of the top-level
    stack cell.  At CALLS-pre that comparison can still use a BST threshold;
    state equality appears only after route rewrites.  Prefer exactly one such
    connected folded consumer.  If none exists, retain the unique native
    load-EA owner.  Multiple folded consumers are ambiguous and deliberately
    suppress the choice instead of falling back to a clone.
    """
    owners: dict[MaterializedIndirectTransfer, int] = {}
    folded_owners: set[MaterializedIndirectTransfer] = set()
    eligible = frozenset(int(serial) for serial in eligible_serials)
    imported = frozenset(int(serial) for serial in imported_serials)

    for choice in choices:
        if (
            choice.resolver_kind != "static_stack_carried_state_choice"
            or choice.state_carrier_store_ea is None
            or choice.predicate_true_state is None
            or choice.predicate_false_state is None
        ):
            continue
        store_ea = int(choice.state_carrier_store_ea)
        carrier_stkoff = carrier_vd_stkoffs_by_store_ea.get(store_ea)
        if carrier_stkoff is None:
            continue
        states = frozenset(
            {
                int(choice.predicate_true_state) & 0xFFFFFFFF,
                int(choice.predicate_false_state) & 0xFFFFFFFF,
            }
        )
        if len(states) != 2:
            continue

        live_folded_candidates: set[int] = set()
        for block in flow_graph.blocks.values():
            if (
                int(block.serial) not in eligible
                or int(block.serial) in imported
                or int(block.npred) == 0
                or int(block.nsucc) != 2
                or not block.insn_snapshots
            ):
                continue
            tail = block.insn_snapshots[-1]
            if not tail.is_conditional_jump:
                continue
            stack_operands = tuple(
                operand
                for operand in (tail.l, tail.r)
                if operand is not None
                and operand.kind is OperandKind.STACK
                and operand.stkoff is not None
            )
            number_operands = tuple(
                operand
                for operand in (tail.l, tail.r)
                if operand is not None
                and operand.kind is OperandKind.NUMBER
                and operand.value is not None
            )
            if (
                len(stack_operands) == 1
                and len(number_operands) == 1
                and int(stack_operands[0].stkoff) == int(carrier_stkoff)
            ):
                live_folded_candidates.add(int(block.serial))

        if len(live_folded_candidates) == 1:
            owners[choice] = next(iter(live_folded_candidates))
            folded_owners.add(choice)
            continue
        if live_folded_candidates:
            continue

        native_candidates = {
            int(serial)
            for load_ea in choice.state_carrier_consumer_load_eas
            if (
                (serial := native_consumer_serials_by_load_ea.get(int(load_ea)))
                is not None
                and int(serial) in eligible
                and flow_graph.get_block(int(serial)) is not None
            )
        }
        if len(native_candidates) == 1:
            owners[choice] = next(iter(native_candidates))

    return owners, frozenset(folded_owners)


def build_stack_carried_state_selector_lowerings(
    flow_graph,
    dispatcher,
    *,
    state_var_reg: int | None,
    dispatcher_region_serials: frozenset[int],
    handler_serials: frozenset[int],
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    materialized_indirect_transfers: tuple[MaterializedIndirectTransfer, ...] = (),
    imported_direct_boundary_evidence: tuple[
        AppliedDetachedSnippetDirectBoundaryPort, ...
    ] = (),
    imported_conditional_boundary_evidence: tuple[
        AppliedDetachedSnippetConditionalBoundaryPort, ...
    ] = (),
    imported_native_eas_by_serial: Mapping[int, frozenset[int]] | None = None,
    handler_entry_eas_by_serial: Mapping[int, int] | None = None,
    state_carrier_vd_stkoffs_by_store_ea: Mapping[int, int] | None = None,
    native_carrier_consumer_serials_by_load_ea: Mapping[int, int] | None = None,
) -> list[object]:
    """Lower a two-valued stack-ferried state at its live handler consumer.

    A prologue diamond may select one of two dispatcher states into a stack
    cell.  Much later, a handler reloads that cell into the register-resident
    state variable and enters the comparison tree.  Recover the two constants
    from the unique reaching-definition diamond and replace the handler's
    router edge with ``stack_cell == state`` routed directly to both handlers.

    The proof is intentionally strict: one cell write in the whole snapshot,
    one canonical two-arm merge, two distinct folded constants, one consumer
    load, and two known handler targets.  Any ambiguity abstains.
    """
    if state_var_reg is None or not dispatcher_region_serials or not handler_serials:
        return []

    state_register = int(state_var_reg)
    router_blocks = frozenset(int(serial) for serial in dispatcher_region_serials)
    resolver_cut_endpoints = _resolver_cut_endpoint_serials(
        flow_graph,
        imported_direct_boundary_evidence,
        router_blocks,
    )
    resolver_proven_terminal_endpoints = (
        _resolver_proven_live_terminal_endpoint_serials(
            flow_graph,
            materialized_indirect_transfers,
            imported_endpoint_serials=resolver_cut_endpoints,
        )
    )
    if logger.info_on and imported_conditional_boundary_evidence:
        logger.info(
            "applied conditional boundary inventory: %s",
            [
                {
                    "predicate": f"0x{int(evidence.port.predicate_ea):X}",
                    "kind": evidence.port.resolver_kind,
                    "logical_source": (
                        None
                        if evidence.port.logical_source_anchor_ea is None
                        else f"0x{int(evidence.port.logical_source_anchor_ea):X}"
                    ),
                }
                for evidence in imported_conditional_boundary_evidence
            ],
        )
    applied_conditional_endpoints = _applied_resolver_cut_conditional_endpoints(
        flow_graph,
        imported_conditional_boundary_evidence,
        router_blocks=router_blocks,
        state_var_reg=state_register,
    )
    if logger.info_on:
        logger.info(
            "applied resolver-cut conditional endpoints: %s",
            {
                _format_block_label(flow_graph, serial): sorted(definitions)
                for serial, definitions in sorted(applied_conditional_endpoints.items())
            },
        )
    handler_entry_eas = handler_entry_eas_by_serial or {}
    imported_native_eas = imported_native_eas_by_serial or {}
    carrier_vd_stkoffs = state_carrier_vd_stkoffs_by_store_ea or {}
    native_consumer_serials = native_carrier_consumer_serials_by_load_ea or {}
    portable_choice_owners, folded_portable_choice_owners = (
        _native_stack_carried_choice_owners(
            flow_graph,
            materialized_indirect_transfers,
            eligible_serials=frozenset(
                {
                    *(int(serial) for serial in handler_serials),
                    *(int(serial) for serial in dispatcher_region_serials),
                }
            ),
            imported_serials=frozenset(int(serial) for serial in imported_native_eas),
            carrier_vd_stkoffs_by_store_ea=carrier_vd_stkoffs,
            native_consumer_serials_by_load_ea=native_consumer_serials,
        )
    )
    portable_owner_serials = frozenset(portable_choice_owners.values())
    equality_targets = unique_materialized_equality_target_eas(
        materialized_indirect_transfers,
        state_register,
        validated_candidate_target_eas=frozenset(
            int(ea) for ea in handler_entry_eas.values()
        ),
    )
    exact_handler_targets: dict[int, int] = {}
    for state, target_ea in equality_targets.items():
        matching_serials = {
            int(serial)
            for serial, entry_ea in handler_entry_eas.items()
            if int(entry_ea) == int(target_ea)
            and flow_graph.get_block(int(serial)) is not None
        }
        if len(matching_serials) == 1:
            exact_handler_targets[int(state) & 0xFFFFFFFF] = next(
                iter(matching_serials)
            )
    known_handlers = frozenset(
        {
            *(int(serial) for serial in handler_serials),
            *(int(serial) for serial in exact_handler_targets.values()),
        }
    )
    fixpoint = run_snapshot_constant_fixpoint(flow_graph, -1)
    if logger.info_on:
        logger.info(
            "stack-carried selector scan: state_reg=%d handlers=%d routers=%d "
            "native_consumers=%s",
            state_register,
            len(known_handlers),
            len(router_blocks),
            {
                f"0x{int(load_ea):X}": (
                    _format_block_label(flow_graph, int(serial))
                    if flow_graph.get_block(int(serial)) is not None
                    else "missing"
                )
                for load_ea, serial in sorted(native_consumer_serials.items())
            },
        )
    writes_by_stkoff: dict[int, list[tuple[object, object]]] = {}
    for block in flow_graph.blocks.values():
        for instruction in block.insn_snapshots:
            destination = instruction.d
            if (
                instruction.kind is InsnKind.MOV
                and destination is not None
                and destination.kind is OperandKind.STACK
                and destination.stkoff is not None
            ):
                writes_by_stkoff.setdefault(int(destination.stkoff), []).append(
                    (block, instruction)
                )

    route_targets: dict[int, set[int]] = {
        int(state): {int(target)} for state, target in exact_handler_targets.items()
    }
    for route in materialized_state_routes:
        state = int(route.state_constant) & 0xFFFFFFFF
        # A unique imported equality target is the exact owner of this state.
        # Later route recovery can still retain the pre-import comparison leaf
        # as a snapshot-local endpoint; unioning that stale owner with the exact
        # target would turn a proven two-arm selector into an ambiguity.
        if state in exact_handler_targets:
            continue
        target = int(route.target_handler_serial)
        if target not in known_handlers:
            continue
        route_targets.setdefault(
            state,
            set(),
        ).add(target)

    def resolve_state_target(state: int) -> int | None:
        state_u = int(state) & 0xFFFFFFFF
        live_target = dispatcher.lookup(state_u)
        if live_target is not None and int(live_target) in known_handlers:
            # Imported equality evidence proves the semantic state mapping, but
            # the current dispatcher map owns the maturity-local live frontier.
            # Never replace that live handler with a detached clone.
            return int(live_target)
        exact = route_targets.get(state_u, set())
        if len(exact) > 1:
            return None
        if exact:
            return next(iter(exact))
        return None

    def resolve_folded_native_state_target(state: int) -> int | None:
        """Prefer exact ownership after a native choice reaches a live source."""
        state_u = int(state) & 0xFFFFFFFF
        exact = route_targets.get(state_u, set())
        if len(exact) > 1:
            return None
        if exact:
            return next(iter(exact))
        return resolve_state_target(state_u)

    lowerings: list[object] = []
    for consumer in flow_graph.blocks.values():
        if (
            int(consumer.serial) not in known_handlers
            and int(consumer.serial) not in router_blocks
        ) or int(consumer.nsucc) != 2:
            continue
        loads = []
        for instruction in consumer.insn_snapshots:
            source = instruction.l
            destination = instruction.d
            if (
                instruction.kind is InsnKind.MOV
                and source is not None
                and source.kind is OperandKind.STACK
                and source.stkoff is not None
                and destination is not None
                and destination.kind is OperandKind.REGISTER
                and destination.reg is not None
                and int(destination.reg) == state_register
            ):
                loads.append(instruction)
        tail = consumer.insn_snapshots[-1] if consumer.insn_snapshots else None
        if tail is None or not tail.is_conditional_jump or int(tail.ea) <= 0:
            if logger.info_on:
                logger.info(
                    "stack-carried selector abstained: source=%s "
                    "tail_kind=%s tail_ea=0x%X conditional=%s",
                    _format_block_label(flow_graph, int(consumer.serial)),
                    None if tail is None else tail.kind.value,
                    0 if tail is None else int(tail.ea),
                    False if tail is None else tail.is_conditional_jump,
                )
            continue
        direct_stack_operands = tuple(
            operand
            for operand in (tail.l, tail.r)
            if operand is not None
            and operand.kind is OperandKind.STACK
            and operand.stkoff is not None
        )
        direct_number_operands = tuple(
            operand
            for operand in (tail.l, tail.r)
            if operand is not None and operand.kind is OperandKind.NUMBER
        )
        direct_folded_stack_source = (
            len(direct_stack_operands) == 1 and len(direct_number_operands) == 1
        )
        loaded_stack_source = loads[0].l if len(loads) == 1 else None
        load_matches_direct_source = (
            direct_folded_stack_source
            and loaded_stack_source is not None
            and loaded_stack_source.stkoff is not None
            and int(loaded_stack_source.stkoff) == int(direct_stack_operands[0].stkoff)
        )
        if load_matches_direct_source:
            stack_source = loaded_stack_source
        elif direct_folded_stack_source:
            stack_source = direct_stack_operands[0]
        elif loaded_stack_source is not None:
            stack_source = loaded_stack_source
        elif int(consumer.serial) in portable_owner_serials:
            stack_source = None
        else:
            continue
        if stack_source is not None and stack_source.stkoff is None:
            continue
        successor_paths = tuple(
            (
                int(successor),
                _strict_one_way_path_enters_region(
                    flow_graph,
                    int(successor),
                    router_blocks,
                    state_var_reg=state_register,
                    resolver_cut_endpoint_serials=resolver_cut_endpoints,
                ),
            )
            for successor in consumer.succs
        )
        if not all(proof is not None for _successor, proof in successor_paths):
            converged_definitions = None
            if (
                direct_folded_stack_source
                and int(consumer.serial) in exact_handler_targets.values()
            ):
                converged_definitions = _strict_paths_converge_on_indirect_endpoint(
                    flow_graph,
                    tuple(int(successor) for successor in consumer.succs),
                    state_var_reg=state_register,
                )
            elif direct_folded_stack_source:
                terminal_proofs = []
                for endpoint_serial in sorted(resolver_proven_terminal_endpoints):
                    proof = _strict_paths_converge_on_indirect_endpoint(
                        flow_graph,
                        tuple(int(successor) for successor in consumer.succs),
                        state_var_reg=state_register,
                        expected_endpoint_serial=endpoint_serial,
                    )
                    if proof is not None:
                        terminal_proofs.append(proof)
                if len(terminal_proofs) == 1:
                    converged_definitions = terminal_proofs[0]
            if converged_definitions is None and (
                direct_folded_stack_source or loaded_stack_source is not None
            ):
                converged_definitions = (
                    _strict_paths_converge_on_applied_conditional_endpoint(
                        flow_graph,
                        tuple(int(successor) for successor in consumer.succs),
                        applied_conditional_endpoints,
                        state_var_reg=state_register,
                    )
                )
            if converged_definitions is None:
                if logger.info_on:
                    logger.info(
                        "stack-carried selector abstained: source=%s "
                        "dispatcher_paths=%s",
                        _format_block_label(flow_graph, int(consumer.serial)),
                        [
                            (
                                _format_block_label(flow_graph, successor),
                                proof is not None,
                                tuple(
                                    instruction.kind.value
                                    for instruction in (
                                        flow_graph.get_block(successor).insn_snapshots
                                        if flow_graph.get_block(successor) is not None
                                        else ()
                                    )
                                ),
                            )
                            for successor, proof in successor_paths
                        ],
                    )
                continue
            successor_paths = tuple(
                (int(successor), definitions)
                for successor, definitions in zip(
                    consumer.succs,
                    converged_definitions,
                )
            )
        consumer_instruction_eas = {
            int(instruction.ea) for instruction in consumer.insn_snapshots
        }
        portable_choices = {
            transfer
            for transfer in materialized_indirect_transfers
            if transfer.resolver_kind == "static_stack_carried_state_choice"
            and transfer.state_carrier_store_ea is not None
            and transfer.state_carrier_ida_stkoff is not None
            and transfer.predicate_true_state is not None
            and transfer.predicate_false_state is not None
            and int(transfer.state_carrier_store_ea) in carrier_vd_stkoffs
            and portable_choice_owners.get(transfer) == int(consumer.serial)
        }
        if logger.info_on and int(consumer.serial) in set(
            native_consumer_serials.values()
        ):
            logger.info(
                "native stack-carried selector match: source=%s choices=%d "
                "instruction_eas=%s",
                _format_block_label(flow_graph, int(consumer.serial)),
                len(portable_choices),
                [f"0x{int(ea):X}" for ea in sorted(consumer_instruction_eas)],
            )
        if len(portable_choices) == 1:
            portable_choice = next(iter(portable_choices))
            assert portable_choice.state_carrier_store_ea is not None
            assert portable_choice.predicate_true_state is not None
            assert portable_choice.predicate_false_state is not None
            true_state = int(portable_choice.predicate_true_state) & 0xFFFFFFFF
            false_state = int(portable_choice.predicate_false_state) & 0xFFFFFFFF
            resolve_portable_target = (
                resolve_folded_native_state_target
                if portable_choice in folded_portable_choice_owners
                else resolve_state_target
            )
            true_target = resolve_portable_target(true_state)
            false_target = resolve_portable_target(false_state)
            matching_load_eas = tuple(
                sorted(
                    int(load_ea)
                    for load_ea in portable_choice.state_carrier_consumer_load_eas
                    if portable_choice in folded_portable_choice_owners
                    or int(load_ea) in consumer_instruction_eas
                    or native_consumer_serials.get(int(load_ea)) == int(consumer.serial)
                )
            )
            if (
                true_target is not None
                and false_target is not None
                and int(true_target) != int(false_target)
                and len(matching_load_eas) == 1
            ):
                bypassed_register_definitions = frozenset(
                    definition
                    for _successor, definitions in successor_paths
                    for definition in (definitions or ())
                )
                target_live = set()
                if bypassed_register_definitions:
                    live_in = live_in_variables(
                        flow_graph,
                        None,
                        cut_entry_blocks=router_blocks,
                    )
                    target_live = live_in.get(int(true_target), set()) | live_in.get(
                        int(false_target), set()
                    )
                if not (bypassed_register_definitions & target_live):
                    lowerings.append(
                        LowerConditionalStateTransition(
                            source_serial=int(consumer.serial),
                            old_dispatcher_serial=int(consumer.succs[0]),
                            rewrite_from_ea=int(tail.ea),
                            condition_operand=SyntheticStackValueEqualsCondition(
                                stack_stkoff=int(
                                    carrier_vd_stkoffs[
                                        int(portable_choice.state_carrier_store_ea)
                                    ]
                                ),
                                stack_size=max(
                                    1,
                                    int(portable_choice.predicate_size or 0),
                                ),
                                value=true_state,
                            ),
                            false_target_serial=int(false_target),
                            true_target_serial=int(true_target),
                            proof_id=(
                                "stack_carried_state_selector_native:"
                                f"source_ea=0x{int(consumer.start_ea):X}:"
                                f"store_ea=0x{int(portable_choice.state_carrier_store_ea):X}:"
                                f"load_ea=0x{int(matching_load_eas[0]):X}"
                            ),
                            reason=(
                                "resolver_proven_native_stack_carried_state_selector"
                            ),
                        )
                    )
                    continue
                if logger.info_on:
                    logger.info(
                        "native stack-carried selector abstained: source=%s "
                        "store_ea=0x%X loads=%s states=(0x%X,0x%X) "
                        "targets=%s severed_live=%s",
                        _format_block_label(flow_graph, int(consumer.serial)),
                        int(portable_choice.state_carrier_store_ea),
                        [f"0x{int(ea):X}" for ea in matching_load_eas],
                        true_state,
                        false_state,
                        (true_target, false_target),
                        sorted(bypassed_register_definitions & target_live),
                    )
            elif logger.info_on:
                logger.info(
                    "native stack-carried selector abstained: source=%s "
                    "store_ea=0x%X loads=%s states=(0x%X,0x%X) targets=%s",
                    _format_block_label(flow_graph, int(consumer.serial)),
                    int(portable_choice.state_carrier_store_ea),
                    [f"0x{int(ea):X}" for ea in matching_load_eas],
                    true_state,
                    false_state,
                    (true_target, false_target),
                )
        if stack_source is None or stack_source.stkoff is None:
            continue
        stack_offset = int(stack_source.stkoff)
        stores = writes_by_stkoff.get(stack_offset, [])
        if logger.info_on:
            logger.info(
                "stack-carried selector candidate: source=%s cell=%d writes=%d",
                _format_block_label(flow_graph, int(consumer.serial)),
                stack_offset,
                len(stores),
            )
        if len(stores) != 1:
            continue
        store_block, store_instruction = stores[0]
        store_source = store_instruction.l
        if (
            store_source is None
            or store_source.kind is not OperandKind.REGISTER
            or store_source.reg is None
        ):
            continue
        carrier_register = int(store_source.reg)
        store_predecessors = tuple(int(pred) for pred in store_block.preds)
        if len(store_predecessors) != 2:
            continue

        diamond_roots = []
        for branch_serial in store_predecessors:
            other_serial = next(
                pred for pred in store_predecessors if pred != branch_serial
            )
            branch_block = flow_graph.get_block(branch_serial)
            other_block = flow_graph.get_block(other_serial)
            if branch_block is None or other_block is None:
                continue
            if (
                int(branch_block.nsucc) == 2
                and set(int(successor) for successor in branch_block.succs)
                == {int(store_block.serial), other_serial}
                and tuple(int(successor) for successor in other_block.succs)
                == (int(store_block.serial),)
            ):
                diamond_roots.append(branch_serial)
        if len(diamond_roots) != 1:
            if logger.info_on:
                logger.info(
                    "stack-carried selector abstained: source=%s cell=%d "
                    "diamond_roots=%s",
                    _format_block_label(flow_graph, int(consumer.serial)),
                    stack_offset,
                    diamond_roots,
                )
            continue

        states = {
            int(fixpoint.out_reg_maps.get(pred, {}).get(carrier_register)) & 0xFFFFFFFF
            for pred in store_predecessors
            if carrier_register in fixpoint.out_reg_maps.get(pred, {})
        }
        if len(states) != 2:
            if logger.info_on:
                logger.info(
                    "stack-carried selector abstained: source=%s cell=%d "
                    "folded_states=%s store=%s carrier_reg=%d pred_maps=%s",
                    _format_block_label(flow_graph, int(consumer.serial)),
                    stack_offset,
                    [hex(state) for state in sorted(states)],
                    _format_block_label(flow_graph, int(store_block.serial)),
                    carrier_register,
                    [
                        {
                            "pred": _format_block_label(flow_graph, pred),
                            "carrier": fixpoint.out_reg_maps.get(pred, {}).get(
                                carrier_register
                            ),
                            "insns": tuple(
                                (
                                    instruction.kind.value,
                                    hex(int(instruction.ea)),
                                    (
                                        instruction.d.kind.value
                                        if instruction.d is not None
                                        else None
                                    ),
                                    (
                                        instruction.d.reg
                                        if instruction.d is not None
                                        else None
                                    ),
                                    (
                                        instruction.l.kind.value
                                        if instruction.l is not None
                                        else None
                                    ),
                                    (
                                        instruction.l.value
                                        if instruction.l is not None
                                        else None
                                    ),
                                )
                                for instruction in (
                                    flow_graph.get_block(pred).insn_snapshots
                                    if flow_graph.get_block(pred) is not None
                                    else ()
                                )
                            ),
                        }
                        for pred in store_predecessors
                    ],
                )
            continue
        true_state, false_state = sorted(states)
        true_target = resolve_state_target(true_state)
        false_target = resolve_state_target(false_state)
        if (
            true_target is None
            or false_target is None
            or int(true_target) == int(false_target)
        ):
            if logger.info_on:
                logger.info(
                    "stack-carried selector abstained: source=%s cell=%d "
                    "states=(0x%X,0x%X) targets=(%s,%s)",
                    _format_block_label(flow_graph, int(consumer.serial)),
                    stack_offset,
                    true_state,
                    false_state,
                    true_target,
                    false_target,
                )
            continue
        bypassed_register_definitions = frozenset(
            definition
            for _successor, definitions in successor_paths
            for definition in (definitions or ())
        )
        if bypassed_register_definitions:
            live_in = live_in_variables(
                flow_graph,
                None,
                cut_entry_blocks=router_blocks,
            )
            target_live = live_in.get(int(true_target), set()) | live_in.get(
                int(false_target), set()
            )
            unsafe = bypassed_register_definitions & target_live
            if unsafe:
                if logger.info_on:
                    logger.info(
                        "stack-carried selector abstained: source=%s "
                        "targets=(%s,%s) bypassed_live_defs=%s",
                        _format_block_label(flow_graph, int(consumer.serial)),
                        _format_block_label(flow_graph, int(true_target)),
                        _format_block_label(flow_graph, int(false_target)),
                        sorted(unsafe),
                    )
                continue
        lowerings.append(
            LowerConditionalStateTransition(
                source_serial=int(consumer.serial),
                old_dispatcher_serial=int(consumer.succs[0]),
                rewrite_from_ea=int(tail.ea),
                condition_operand=SyntheticStackValueEqualsCondition(
                    stack_stkoff=stack_offset,
                    stack_size=max(1, int(stack_source.size)),
                    value=true_state,
                ),
                false_target_serial=int(false_target),
                true_target_serial=int(true_target),
                proof_id=(
                    "stack_carried_state_selector:"
                    f"source_ea=0x{int(consumer.start_ea):X}:"
                    f"store_ea=0x{int(store_instruction.ea):X}"
                ),
                reason="resolver_proven_stack_carried_state_selector",
            )
        )
    return lowerings


def _unique_materialized_state_target(
    routes: tuple[MaterializedStateRoute, ...],
    state_constant: int,
    handler_serials: frozenset[int],
) -> int | None:
    """Return one exact resolver-owned handler for a concrete state."""
    state = int(state_constant) & 0xFFFFFFFF
    handlers = frozenset(int(serial) for serial in handler_serials)
    candidates = {
        int(route.target_handler_serial)
        for route in routes
        if (int(route.state_constant) & 0xFFFFFFFF) == state
        and (not handlers or int(route.target_handler_serial) in handlers)
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def build_materialized_state_entry_bridges(
    flow_graph,
    routes: tuple[MaterializedStateRoute, ...],
    *,
    dispatcher_region_serials: frozenset[int],
    authoritative_handler_serials: frozenset[int],
) -> list[object]:
    """Bypass a proven router edge from the live function-entry prefix.

    A materialized computed-goto resolver can prove the state written by a
    prologue block and the exact handler that owns that state even when the
    comparison-tree adapter cannot recover a scalar ``initial_state``.  Accept
    that source-keyed evidence only when the source is reachable from the
    function entry without crossing either the dispatcher region or a handler,
    and its sole successor is a proven router block.  Conflicting targets for
    the same edge abstain.
    """
    routers = frozenset(int(serial) for serial in dispatcher_region_serials)
    handlers = frozenset(int(serial) for serial in authoritative_handler_serials)
    if not routes or not routers or not handlers:
        return []

    entry_prefix: set[int] = set()
    pending = [int(flow_graph.entry_serial or 0)]
    while pending:
        serial = pending.pop()
        if serial in entry_prefix or serial in routers or serial in handlers:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        entry_prefix.add(serial)
        pending.extend(
            int(successor)
            for successor in block.succs
            if int(successor) not in entry_prefix
        )

    candidates: dict[tuple[int, int], set[int]] = {}
    for route in routes:
        source = int(route.source_block_serial)
        target = int(route.target_handler_serial)
        if source not in entry_prefix or target not in handlers:
            continue
        block = flow_graph.get_block(source)
        if block is None or block.nsucc != 1:
            continue
        old_target = int(block.succs[0])
        if old_target not in routers:
            continue
        candidates.setdefault((source, old_target), set()).add(target)

    return [
        RedirectGoto(
            from_serial=source,
            old_target=old_target,
            new_target=next(iter(targets)),
        )
        for (source, old_target), targets in sorted(candidates.items())
        if len(targets) == 1
    ]


def build_materialized_state_route_redirects(
    flow_graph,
    routes: tuple[MaterializedStateRoute, ...],
    *,
    state_var_reg: int | None,
    dispatcher_region_serials: frozenset[int],
    authoritative_handler_serials: frozenset[int],
    handler_entry_eas_by_serial: Mapping[int, int] | None = None,
) -> list[object]:
    """Rebind a proven state edge from a router or external placeholder.

    Hex-Rays represents a target outside the generated MBA as an empty
    ``EXTERNAL`` block.  Importing that target's body does not automatically
    retarget an already-live predecessor of the placeholder.  Rebind only when
    the source itself performs the exact immediate state-register write and
    the old edge either enters the proven dispatcher region or names the same
    native handler entry as the authoritative imported target. A two-way
    source whose successors are both dispatcher blocks is the conditional
    boundary-port form of the same route: collapse its dispatcher-only tail
    only when native replay proves one unambiguous state and handler target.
    Dispatcher bypass additionally requires native replay to prove this write
    owns a handler exit; an equality-ownership row alone may name the handler's
    own entry state and would otherwise manufacture a self-loop. A clone-local
    row may inherit exit ownership only from one unique replay row with the
    same handler, state, and target.
    """
    handlers = frozenset(int(serial) for serial in authoritative_handler_serials)
    routers = frozenset(int(serial) for serial in dispatcher_region_serials)
    handler_entry_eas = handler_entry_eas_by_serial or {}
    if state_var_reg is None or not routes or not handlers:
        return []

    replay_exit_targets: dict[tuple[int, int], set[int]] = {}
    for route in routes:
        source_handler = route.source_handler_serial
        if not route.handler_exit_proven or source_handler is None:
            continue
        replay_exit_targets.setdefault(
            (
                int(source_handler),
                int(route.state_constant) & 0xFFFFFFFF,
            ),
            set(),
        ).add(int(route.target_handler_serial))

    candidates: dict[tuple[int, int], set[int]] = {}
    two_way_candidates: dict[int, set[tuple[int, int]]] = {}
    for route in routes:
        source = int(route.source_block_serial)
        state = int(route.state_constant) & 0xFFFFFFFF
        target = int(route.target_handler_serial)
        source_block = flow_graph.get_block(source)
        exact_deferred_handler_exit = bool(
            route.handler_exit_proven and route.source_handler_serial is not None
        )
        local_state_write = _source_local_constant_register_write(
            flow_graph,
            source,
            state_var_reg,
        )
        corroborated_targets = replay_exit_targets.get((source, state), set())
        exact_clone_local_handler_exit = bool(
            source in handlers
            and local_state_write == state
            and target != source
            and corroborated_targets == {target}
        )
        exact_handler_exit = (
            exact_deferred_handler_exit or exact_clone_local_handler_exit
        )
        if (
            source_block is not None
            and source_block.nsucc == 2
            and exact_deferred_handler_exit
        ):
            two_way_candidates.setdefault(source, set()).add((state, target))
            continue
        if target not in handlers:
            continue
        if (
            source_block is None
            or source_block.nsucc != 1
            or (not exact_deferred_handler_exit and local_state_write != state)
        ):
            continue
        old_target = int(source_block.succs[0])
        if old_target == target:
            continue
        old_block = flow_graph.get_block(old_target)
        target_entry_ea = handler_entry_eas.get(target)
        exact_external_placeholder = bool(
            old_block is not None
            and old_block.kind is BlockKind.EXTERNAL
            and target_entry_ea is not None
            and int(old_block.start_ea) == int(target_entry_ea)
        )
        if old_target in routers and not exact_handler_exit:
            continue
        if (
            old_target not in routers
            and not exact_external_placeholder
            and not exact_handler_exit
        ):
            continue
        candidates.setdefault((source, old_target), set()).add(target)

    redirects: list[object] = [
        RedirectGoto(
            from_serial=source,
            old_target=old_target,
            new_target=next(iter(targets)),
        )
        for (source, old_target), targets in sorted(candidates.items())
        if len(targets) == 1
    ]
    for source, route_keys in sorted(two_way_candidates.items()):
        if len(route_keys) != 1:
            continue
        _state, target = next(iter(route_keys))
        source_block = flow_graph.get_block(source)
        if (
            target not in handlers
            or source_block is None
            or source_block.nsucc != 2
            or any(int(successor) not in routers for successor in source_block.succs)
        ):
            continue
        redirects.append(ConvertToGoto(block_serial=source, goto_target=target))
    return redirects


def _preserve_deferred_materialized_handler_exit_paths(
    modifications: list[object],
    routes: tuple[MaterializedStateRoute, ...],
) -> list[object]:
    """Keep a handler's path to a replay-proven successor-owned exit.

    Optimization can split the state write from the handler entry. Native
    replay then keys the exact route to the successor block while the coarse
    dispatcher fold still sees the handler's entry-state constant and proposes
    ``handler -> handler``. That self-redirect would bypass the stronger exit
    proof, so preserve the existing parent edge and let the successor-owned
    redirect carry the transition.
    """
    deferred_handlers = {
        int(route.source_handler_serial)
        for route in routes
        if route.handler_exit_proven
        and route.source_handler_serial is not None
        and int(route.source_block_serial) != int(route.source_handler_serial)
    }
    if not deferred_handlers:
        return list(modifications)
    return [
        modification
        for modification in modifications
        if not (
            isinstance(modification, (RedirectGoto, RedirectBranch))
            and int(modification.from_serial) in deferred_handlers
            and int(modification.new_target) == int(modification.from_serial)
        )
    ]


def _rebind_materialized_state_route_sources(
    flow_graph,
    routes: tuple[MaterializedStateRoute, ...],
    *,
    legacy_handler_by_state: Mapping[int, int] | None,
    materialized_handler_by_state: Mapping[int, int] | None,
    imported_native_eas_by_serial: Mapping[int, frozenset[int]] | None,
) -> tuple[MaterializedStateRoute, ...]:
    """Project handler-exit routes onto their exact PREOPT handler owner.

    Native handler replay can produce an exact exit route before equality
    evidence replaces that handler with its imported PREOPT clone.  Applying the
    route to the legacy source then rewrites a block no entry edge will reach.
    Rebind only a route owned directly by the replaced handler, and only when the
    imported owner's origin registry contains an instruction EA from that native
    handler.  Conflicting replacements and interior-block routes abstain.
    """
    legacy_handlers = legacy_handler_by_state or {}
    exact_handlers = materialized_handler_by_state or {}
    imported_origins = imported_native_eas_by_serial or {}
    if not routes or not legacy_handlers or not exact_handlers or not imported_origins:
        return routes

    owners_by_legacy_handler: dict[int, set[int]] = {}
    for state, legacy_handler in legacy_handlers.items():
        exact_handler = exact_handlers.get(int(state) & 0xFFFFFFFF)
        if exact_handler is None:
            continue
        legacy_handler = int(legacy_handler)
        exact_handler = int(exact_handler)
        if legacy_handler == exact_handler or exact_handler not in imported_origins:
            continue
        owners_by_legacy_handler.setdefault(legacy_handler, set()).add(exact_handler)

    rebound: list[MaterializedStateRoute] = []
    ownership_rows: list[tuple[int, int, tuple[int, ...]]] = []
    for route in routes:
        native_source = int(route.source_block_serial)
        source_handler = route.source_handler_serial
        if source_handler is None or native_source != int(source_handler):
            rebound.append(route)
            continue
        owner_candidates = owners_by_legacy_handler.get(native_source, set())
        if len(owner_candidates) != 1:
            rebound.append(route)
            continue
        imported_source = next(iter(owner_candidates))
        native_block = flow_graph.get_block(native_source)
        imported_block = flow_graph.get_block(imported_source)
        if native_block is None or imported_block is None:
            rebound.append(route)
            continue
        native_instruction_eas = frozenset(
            int(instruction.ea)
            for instruction in native_block.insn_snapshots
            if int(instruction.ea) > 0
        )
        if not native_instruction_eas:
            rebound.append(route)
            continue
        matched_eas = tuple(
            sorted(
                native_instruction_eas.intersection(
                    int(ea) for ea in imported_origins[imported_source]
                )
            )
        )
        if not matched_eas:
            rebound.append(route)
            continue
        rebound.append(
            replace(
                route,
                source_block_serial=imported_source,
                source_handler_serial=imported_source,
            )
        )
        ownership_rows.append((native_source, imported_source, matched_eas))

    if ownership_rows and logger.info_on:
        logger.info(
            "unflat materialized route source ownership: %s",
            [
                {
                    "native": _format_block_label(flow_graph, native_source),
                    "imported": _format_block_label(flow_graph, imported_source),
                    "native_eas": [f"0x{ea:X}" for ea in matched_eas],
                }
                for native_source, imported_source, matched_eas in ownership_rows
            ],
        )
    return tuple(dict.fromkeys(rebound))


def build_state_write_redirects(
    flow_graph,
    dispatcher,
    transitions: tuple[StateWriteTransition, ...],
    *,
    dispatcher_entry_serial: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
    branch_witness_map: object | None = None,
    branch_witness_emu: object | None = None,
    entry_bridge_exit_path_blocks: tuple[int, ...] = (),
    entry_bridge_requires_witness: bool = False,
    strict_pre_header_prologue: bool = False,
    allow_multi_entry_entry_bridge: bool = False,
    entry_bridge_cut_exit_path_uses: bool = False,
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    materialized_indirect_transfers: tuple[MaterializedIndirectTransfer, ...] = (),
    materialized_handler_by_state: Mapping[int, int] | None = None,
    condition_chain_handlers: frozenset[int] = frozenset(),
    infer_unmatched_returns: bool = True,
    entry_bridge_evidence: EntryBridgeEvidence | None = None,
    conditional_entry_bridge: ConditionalEntryBridgePlan | None = None,
    exact_entry_bridge_present: bool = False,
    protected_edges: frozenset[tuple[int, int]] = frozenset(),
    dynamic_entry_bridge_edges: frozenset[tuple[int, int]] = frozenset(),
) -> list[object]:
    """Build the redirect modifications that linearize the interval-set graph.

    One redirect per dispatcher back-edge: ``P -> dispatcher`` becomes
    ``P -> route(state_written_by_P)`` (or ``-> default`` when the state routes
    to the exit).  Prologue back-edges are excluded here and handled by the
    entry bridge so the function entry is never sent to the shared-return block.
    """
    mods: list[object] = []
    seen: set[tuple[str, int, int, int]] = set()
    seen_convert: set[tuple[int, int]] = set()
    default_target = dispatcher.default_target
    disp = int(dispatcher_entry_serial) if dispatcher_entry_serial is not None else None

    def _add(src: int, old: int, new: int | None, *, two_way: bool) -> None:
        if new is None or int(old) == int(new):
            return
        if (int(src), int(old)) in protected_edges:
            return
        key = ("B" if two_way else "G", int(src), int(old), int(new))
        if key in seen:
            return
        seen.add(key)
        if two_way:
            mods.append(
                RedirectBranch(
                    from_serial=int(src), old_target=int(old), new_target=int(new)
                )
            )
        else:
            mods.append(
                RedirectGoto(
                    from_serial=int(src), old_target=int(old), new_target=int(new)
                )
            )

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

    def _convert(src: int, target: int | None) -> None:
        if target is None:
            return
        key = (int(src), int(target))
        if key in seen_convert:
            return
        seen_convert.add(key)
        mods.append(ConvertToGoto(block_serial=int(src), goto_target=int(target)))

    def _resolve_state_target(state: int) -> int | None:
        exact_target = _unique_materialized_state_target(
            materialized_state_routes,
            state,
            condition_chain_handlers,
        )
        return (
            exact_target
            if exact_target is not None
            else dispatcher.lookup(int(state) & 0xFFFFFFFF)
        )

    # Prologue dispatcher edges are bridged to route(initial_state); their own
    # state write (the initial state) would route there anyway, but routing them
    # via the bridge keeps the function-entry path explicit and avoids ever
    # redirecting the entry to the shared-return block.
    prologue_preds: set[int] = set()
    if disp is not None and conditional_entry_bridge is None:
        if strict_pre_header_prologue and pre_header_serial is not None:
            prologue_preds = {int(pre_header_serial)}
        else:
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

    # A pointer-aliased terminal state write (``reg = &state; *reg = val`` -- the
    # ``state_store_through_stack_address_alias[_terminal_guard]`` proof) is the
    # AUTHORITATIVE next-state for its source edge: it accounts for the indirect
    # store a syntactic global fold cannot see.  When a NON-guard sibling
    # transition is also recovered for the SAME ``(write_block, via_block)`` -- the
    # naive ``multi_entry_global_fold`` reading that still sees the pre-store state
    # -- its redirect contradicts the guard: it re-points the source AWAY from the
    # via block that performs the store, orphaning that block (and the terminal
    # route through it), so the whole plan is rejected ``terminal_ok=False`` and
    # the loop survives (ticket d81-u3cg).  Defer to the guard: skip the sibling.
    # Empty for every shape without a terminal stack-alias guard -> byte-identical.
    terminal_guard_source_edges = {
        (
            int(t.write_block),
            int(t.via_block) if t.via_block is not None else -1,
        )
        for t in transitions
        if transition_uses_terminal_stack_alias_guard(t)
    }

    if disp is not None:
        for transition in transitions:
            src = int(transition.write_block)
            if src in prologue_preds:
                continue  # handled by the entry bridge below
            if (
                not infer_unmatched_returns
                and transition.is_return
                and transition.next_state is None
            ):
                continue
            vb = transition.via_block
            if (
                terminal_guard_source_edges
                and not transition_uses_terminal_stack_alias_guard(transition)
                and (src, int(vb) if vb is not None else -1)
                in terminal_guard_source_edges
            ):
                continue  # the terminal stack-alias guard owns this source edge
            # ``via_block`` set => bypass a shared (pure state-glue) back-edge:
            # redirect ``src -> via_block`` onto the routed handler.  Otherwise
            # sever ``src -> dispatcher``.
            old = int(vb) if vb is not None else disp
            exact_terminal_delivery = bool(
                transition.proof is not None
                and transition.proof.kind == "computed_goto_exact_terminal_delivery"
            )
            new = (
                _exact_native_terminal_redirect_target(
                    flow_graph,
                    transition.target_handler,
                )
                if transition.is_return and exact_terminal_delivery
                else (
                    _return_redirect_target(
                        flow_graph,
                        transition.target_handler,
                        default_target=default_target,
                    )
                    if transition.is_return
                    else transition.target_handler
                )
            )
            # Terminal stack-alias split: ``src -> vb`` reaches a shared block that
            # writes the non-state result carrier, writes the terminal dispatcher
            # state, then conditionally returns or re-enters the dispatcher. Keep
            # ``src -> vb`` intact so the carrier executes, and redirect only the
            # via block's dispatcher edge onto the proven terminal successor.
            if (
                vb is not None
                and new is not None
                and transition_uses_terminal_stack_alias_guard(transition)
            ):
                for (
                    parent,
                    old_sibling,
                    alias_src,
                ) in _terminal_alias_materializer_parent_redirects(
                    flow_graph,
                    transition,
                    initial_state=initial_state,
                    state_var_stkoff=state_var_stkoff,
                ):
                    _convert(parent, alias_src)
                vbi = int(vb)
                if vbi not in emitted_via_self:
                    emitted_via_self.add(vbi)
                    vb_block = flow_graph.get_block(vbi)
                    if vb_block is not None:
                        if int(getattr(vb_block, "nsucc", 0)) == 2:
                            _convert(vbi, int(new))
                        else:
                            _add(vbi, disp, int(new), two_way=False)
                continue
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
                            vbi,
                            disp,
                            int(return_via[vbi]),
                            two_way=(vb_block.nsucc == 2),
                        )
                continue  # the return_pred -> via_block edge stays intact
            src_block = flow_graph.get_block(src)
            if src_block is None:
                continue
            if vb is None and block_has_unresolved_indirect_state_store(
                src_block, state_var_stkoff
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
                            _format_block_label(flow_graph, witness.selected_successor),
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
    # current CFG and only shortcut when exit-path liveness is safe.  Abstain /
    # conflict / unsafe exit path preserves the original prologue -> dispatcher
    # edges.
    # Conditional entry bridge: when the prologue selects the initial
    # state CONDITIONALLY -- two-or-more prologue predecessors each writing a
    # DISTINCT leaf state to the state var, then merging into the dispatcher -- a single scalar
    # ``initial_state`` cannot express it. Bridge EACH arm past the dispatcher to
    # its own handler. Fires only when >= 2 prologue preds resolve to DISTINCT
    # handler states, so the proven single-initial-state path below is untouched
    # for every non-conditional entry.
    conditional_entry_arms: set[int] = set()
    if (
        disp is not None
        and initial_state is None
        and len(prologue_preds) >= 2
        and not exact_entry_bridge_present
        and not dynamic_entry_bridge_edges
    ):
        arm_routes: list[tuple[int, int]] = []  # (write_block, handler)
        for t in transitions:
            wb = int(t.write_block)
            if wb not in prologue_preds or t.is_return or t.next_state is None:
                continue
            handler = _resolve_state_target(int(t.next_state))
            if handler is None:
                continue
            arm_routes.append((wb, int(handler)))
        if (
            len({wb for wb, _h in arm_routes}) >= 2
            and len({h for _wb, h in arm_routes}) >= 2
        ):
            for wb, handler in arm_routes:
                wb_block = flow_graph.get_block(wb)
                if wb_block is None:
                    continue
                _add(wb, disp, handler, two_way=(wb_block.nsucc == 2))
                conditional_entry_arms.add(wb)
            if logger.info_on:
                logger.info(
                    "unflat conditional entry bridge: %d arms -> %s",
                    len(conditional_entry_arms),
                    sorted({h for _wb, h in arm_routes}),
                )

    # Register-conditional entry: the prologue's initial state may
    # live in a NON-state register while the
    # state var carries a decoy. Bridge each resolvable arm past the dispatcher to its
    # handler. Gated on the register path (``state_var_reg`` set) so the stack goldens
    # never pay the walk-back/fixpoint cost and are byte-identical.
    register_entry_arms: set[int] = set()
    if (
        disp is not None
        and initial_state is None
        and state_var_reg is not None
        and not conditional_entry_arms
        and conditional_entry_bridge is None
        and not exact_entry_bridge_present
        and not dynamic_entry_bridge_edges
    ):
        for pred, merge, handler in _recover_register_conditional_entry(
            flow_graph,
            dispatcher,
            disp,
            state_var_reg=int(state_var_reg),
            materialized_indirect_transfers=materialized_indirect_transfers,
            materialized_state_routes=materialized_state_routes,
            materialized_handler_by_state=materialized_handler_by_state,
            condition_chain_handlers=condition_chain_handlers,
            entry_bridge_evidence=entry_bridge_evidence,
        ):
            pred_block = flow_graph.get_block(pred)
            if pred_block is None:
                continue
            _add(pred, merge, handler, two_way=(pred_block.nsucc == 2))
            register_entry_arms.add(pred)
        if register_entry_arms and logger.info_on:
            logger.info(
                "unflat register-conditional entry bridge: %d arms",
                len(register_entry_arms),
            )

    if (
        initial_state is not None
        and disp is not None
        and not conditional_entry_arms
        and not register_entry_arms
        and not exact_entry_bridge_present
        and not dynamic_entry_bridge_edges
    ):
        first = _resolve_state_target(int(initial_state))
        if first is not None:
            multi_entry_entry_bridge_safe = (
                allow_multi_entry_entry_bridge
                and _has_multi_entry_forward_chain(transitions, int(first))
            )
            _apply_entry_bridge(
                flow_graph,
                dispatcher,
                disp,
                first,
                int(initial_state) & 0xFFFFFFFF,
                prologue_preds,
                state_var_stkoff,
                branch_witness_map,
                branch_witness_emu,
                entry_bridge_exit_path_blocks,
                entry_bridge_requires_witness,
                multi_entry_entry_bridge_safe,
                entry_bridge_cut_exit_path_uses,
                _add,
            )

    return _preserve_fully_resolved_state_forks(
        flow_graph,
        mods,
        handler_entries={int(target) for target in dispatcher.all_targets()},
        excluded_fork_serials=({disp} if disp is not None else set()),
    )


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


def _exact_live_state_edge_keys(
    flow_graph,
    routes: tuple[MaterializedStateRoute, ...],
) -> set[tuple[int, int]]:
    """Return exact live edges that weaker recovery must not retarget."""
    keys: set[tuple[int, int]] = set()
    for route in routes:
        if route.proof_kind != "exact_live_state_edge":
            continue
        source = int(route.source_block_serial)
        target = int(route.target_handler_serial)
        source_block = flow_graph.get_block(source)
        if source_block is None or target not in {
            int(successor) for successor in source_block.succs
        }:
            continue
        keys.add((source, target))
    return keys


def _anchor_blocks(
    flow_graph,
    anchor_eas: tuple[int, ...],
) -> set[int]:
    anchors = {int(ea) for ea in anchor_eas}
    if not anchors:
        return set()
    unique_matches: set[int] = set()
    for anchor in anchors:
        matches = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.start_ea) == anchor
            or any(
                int(instruction.ea) == anchor for instruction in block.insn_snapshots
            )
        }
        if len(matches) == 1:
            unique_matches.update(matches)
    return unique_matches


def _applied_direct_boundary_edge_keys(
    flow_graph,
    evidence_rows: tuple[AppliedDetachedSnippetDirectBoundaryPort, ...],
) -> set[tuple[int, int]]:
    """Project applied PREOPT direct ports onto exact live graph edges."""
    keys: set[tuple[int, int]] = set()
    for evidence in evidence_rows:
        port = evidence.port
        source_candidates = _anchor_blocks(
            flow_graph,
            evidence.endpoint_anchor_eas,
        )
        target_candidates = _anchor_blocks(
            flow_graph,
            evidence.target_anchor_eas,
        )
        native_source_starts = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.start_ea) == int(port.endpoint_block_ea)
        }
        native_target_starts = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.start_ea) == int(port.target_ea)
        }
        if native_source_starts:
            source_candidates = native_source_starts
        if not target_candidates and native_target_starts:
            target_candidates = native_target_starts
        exact_edges = {
            (int(source), int(target))
            for source in source_candidates
            for target in target_candidates
            if (source_block := flow_graph.get_block(int(source))) is not None
            and int(target) in {int(successor) for successor in source_block.succs}
        }
        if len(exact_edges) == 1:
            keys.update(exact_edges)
            continue

        if (
            port.delivery_mode != "terminal_goto"
            or port.endpoint_owner.value != DetachedSnippetBoundaryPortOwner.LIVE.value
        ):
            continue
        endpoint_ea = int(port.endpoint_block_ea)
        folded_edges: set[tuple[int, int]] = set()
        for target in target_candidates:
            target_block = flow_graph.get_block(int(target))
            if target_block is None:
                continue
            for predecessor in target_block.preds:
                source_block = flow_graph.get_block(int(predecessor))
                if source_block is None or int(target) not in {
                    int(successor) for successor in source_block.succs
                }:
                    continue
                source_eas = {
                    int(source_block.start_ea),
                    *(
                        int(instruction.ea)
                        for instruction in source_block.insn_snapshots
                        if int(instruction.ea) > 0
                    ),
                }
                if source_eas and max(source_eas) <= endpoint_ea:
                    folded_edges.add((int(predecessor), int(target)))
        if len(folded_edges) == 1:
            keys.update(folded_edges)
    return keys


def _resolver_proven_dynamic_entry_edges(
    flow_graph,
    evidence_rows: tuple[AppliedDetachedSnippetDirectBoundaryPort, ...],
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    imported_native_eas_by_serial: Mapping[int, frozenset[int]] | None = None,
) -> frozenset[tuple[int, int]]:
    """Return live entry edges whose exact target is a dispatcher router.

    A computed-goto landing is not necessarily a semantic handler. Some BST
    dispatchers land in another routing subtree which reloads the state from a
    stack carrier before selecting the first handler. The already-applied
    PREOPT port is then the complete entry bridge: preserve it and suppress a
    scalar shortcut inferred from a transient value in the same native
    register.
    """
    router_eas = frozenset(
        int(router_ea)
        for transfer in transfers
        for router_ea in transfer.dispatcher_router_eas
    )
    if not router_eas:
        return frozenset()

    edges: set[tuple[int, int]] = set()
    for evidence in evidence_rows:
        port = evidence.port
        if (
            port.endpoint_owner.value != DetachedSnippetBoundaryPortOwner.LIVE.value
            or int(port.target_ea) not in router_eas
        ):
            continue
        exact_edges = _applied_direct_boundary_edge_keys(flow_graph, (evidence,))
        for source, target in exact_edges:
            if int(source) in _entry_prefix_blocks(flow_graph, int(target)):
                edges.add((int(source), int(target)))

    imported_origins = imported_native_eas_by_serial or {}
    imported_blocks = frozenset(int(serial) for serial in imported_origins)
    if imported_origins and logger.info_on:
        logger.info(
            "dynamic router entry candidates: %s",
            [
                {
                    "target": _format_block_label(flow_graph, int(target)),
                    "router_eas": [
                        f"0x{int(ea):X}"
                        for ea in sorted(
                            router_eas.intersection(int(ea) for ea in native_eas)
                        )
                    ],
                    "preds": [
                        {
                            "source": _format_block_label(flow_graph, int(source)),
                            "imported": int(source) in imported_blocks,
                            "entry_prefix": int(source)
                            in _entry_prefix_blocks(flow_graph, int(target)),
                        }
                        for source in (
                            ()
                            if flow_graph.get_block(int(target)) is None
                            else flow_graph.get_block(int(target)).preds
                        )
                    ],
                }
                for target, native_eas in imported_origins.items()
                if router_eas.intersection(int(ea) for ea in native_eas)
                and flow_graph.get_block(int(target)) is not None
                and flow_graph.get_block(int(target)).preds
            ],
        )
    for target, native_eas in imported_origins.items():
        target = int(target)
        if not router_eas.intersection(int(ea) for ea in native_eas):
            continue
        target_block = flow_graph.get_block(target)
        if target_block is None:
            continue
        entry_prefix = _entry_prefix_blocks(flow_graph, target)
        for source in target_block.preds:
            source = int(source)
            source_block = flow_graph.get_block(source)
            source_has_native_owner = source == int(flow_graph.entry_serial) or (
                source_block is not None
                and int(source_block.start_ea) != int(flow_graph.func_ea)
            )
            if (
                source in imported_blocks
                or source not in entry_prefix
                or source_block is None
                or not source_has_native_owner
                or target not in {int(successor) for successor in source_block.succs}
            ):
                continue
            edges.add((source, target))
    return frozenset(edges)


def _applied_conditional_boundary_edge_keys(
    flow_graph,
    evidence_rows: tuple[AppliedDetachedSnippetConditionalBoundaryPort, ...],
) -> set[tuple[int, int]]:
    """Project applied PREOPT conditional arms onto their live corridors.

    ``LowerConditionalStateTransition`` materializes each arm through a one-way
    helper block.  The applied port owns both the predicate edge into that
    helper and the helper corridor into the proven target.  We retain an arm
    only when its predicate block and its complete one-way path are unique;
    ambiguous or pruned arms contribute no protection.
    """

    def _target_candidates(anchor_eas: tuple[int, ...], target_ea: int) -> set[int]:
        anchored = _anchor_blocks(flow_graph, anchor_eas)
        if anchored:
            return anchored
        return {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.start_ea) == int(target_ea)
        }

    def _unique_arm_path(
        source: int,
        targets: set[int],
    ) -> tuple[tuple[int, int], ...] | None:
        source_block = flow_graph.get_block(int(source))
        if source_block is None or source_block.nsucc != 2 or not targets:
            return None
        paths: set[tuple[tuple[int, int], ...]] = set()
        for successor in source_block.succs:
            current = int(successor)
            edges: list[tuple[int, int]] = [(int(source), current)]
            seen = {int(source)}
            while current not in seen:
                seen.add(current)
                if current in targets:
                    paths.add(tuple(edges))
                    break
                block = flow_graph.get_block(current)
                if block is None or block.nsucc != 1:
                    break
                next_block = int(block.succs[0])
                edges.append((current, next_block))
                current = next_block
        return next(iter(paths)) if len(paths) == 1 else None

    keys: set[tuple[int, int]] = set()
    for evidence in evidence_rows:
        port = evidence.port
        predicate_blocks = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if any(
                int(instruction.ea) == int(port.predicate_ea)
                for instruction in block.insn_snapshots
            )
        }
        if len(predicate_blocks) != 1:
            continue
        source = next(iter(predicate_blocks))
        arm_paths = (
            _unique_arm_path(
                source,
                _target_candidates(
                    evidence.taken_target_anchor_eas,
                    int(port.taken_target_ea),
                ),
            ),
            _unique_arm_path(
                source,
                _target_candidates(
                    evidence.fallthrough_target_anchor_eas,
                    int(port.fallthrough_target_ea),
                ),
            ),
        )
        for path in arm_paths:
            if path is not None:
                keys.update(path)
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
    } | {int(m.block_serial) for m in mods if isinstance(m, ConvertToGoto)}


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
    token = _stack_token_for_stkoff(mop.stkoff if mop is not None else None)
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
        if (
            str(getattr(sub_kind, "value", sub_kind)) == "load"
            and _mop_stack_token(sub_r) == alias_token
        ):
            return _mop_size(mop)
        for child in (getattr(mop, "sub_l", None), sub_r):
            size = _mop_references_alias_load(child, alias_token)
            if size > 0:
                return size
    return 0


def _insn_references_alias(insn, alias_token: str) -> bool:
    for operand in (
        getattr(insn, "l", None),
        getattr(insn, "r", None),
        getattr(insn, "d", None),
    ):
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
    for operand in (
        getattr(insn, "l", None),
        getattr(insn, "r", None),
        getattr(insn, "d", None),
    ):
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
                mods.append(
                    RetargetOutputStore(
                        block_serial=int(serial),
                        host_ea=int(host_ea),
                        host_opcode=int(host_opcode),
                        alias_token=alias,
                        output_token=output_token,
                        host_text_sha1=_instruction_text_digest(text),
                        value_size=source_size or None,
                        reason="output_store_retarget",
                    )
                )
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
    stkoff = _int_or_none(mop.stkoff)
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
    for operand in (
        getattr(insn, "l", None),
        getattr(insn, "r", None),
        getattr(insn, "d", None),
    ):
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
            mods.append(
                RedirectBranch(from_serial=src, old_target=old, new_target=int(new))
            )
        else:
            mods.append(
                RedirectGoto(from_serial=src, old_target=old, new_target=int(new))
            )
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
    spine can sever the predicate/body exit_path.  Instead, recover one first-class
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


def _unique_planned_redirect_targets(
    modifications: tuple[object, ...],
) -> dict[int, int]:
    targets_by_source: dict[int, set[int]] = {}
    for modification in modifications:
        if isinstance(modification, (RedirectGoto, RedirectBranch)):
            source = int(modification.from_serial)
            target = int(modification.new_target)
        elif isinstance(modification, ConvertToGoto):
            source = int(modification.block_serial)
            target = int(modification.goto_target)
        else:
            continue
        targets_by_source.setdefault(source, set()).add(target)
    return {
        source: next(iter(targets))
        for source, targets in targets_by_source.items()
        if len(targets) == 1
    }


def _one_way_arm_planned_target(
    flow_graph,
    start_serial: int,
    planned_targets: dict[int, int],
    handler_entries: set[int],
) -> int | None:
    """Find an exact planned target along one unsplit fork arm."""
    current = int(start_serial)
    visited: set[int] = set()
    while current not in visited:
        visited.add(current)
        target = planned_targets.get(current)
        if target is not None:
            return target
        if current in handler_entries:
            return None
        block = flow_graph.get_block(current)
        if block is None or block.nsucc != 1:
            return None
        current = int(block.succs[0])
    return None


def _successor_is_fully_resolved_state_fork(
    flow_graph,
    successor_serial: int,
    planned_targets: dict[int, int],
    handler_entries: set[int],
) -> bool:
    """Whether both arms of a live fork have distinct exact handler targets."""
    fork = flow_graph.get_block(int(successor_serial))
    if fork is None or fork.nsucc != 2:
        return False
    arm_targets = tuple(
        _one_way_arm_planned_target(
            flow_graph,
            int(arm_serial),
            planned_targets,
            handler_entries,
        )
        for arm_serial in fork.succs
    )
    return (
        all(target is not None for target in arm_targets) and len(set(arm_targets)) == 2
    )


def _preserve_fully_resolved_state_forks(
    flow_graph,
    modifications: list[object],
    *,
    handler_entries: set[int],
    excluded_fork_serials: set[int],
) -> list[object]:
    """Drop parent redirects that would bypass two stronger arm routes."""
    planned_targets = _unique_planned_redirect_targets(tuple(modifications))
    result: list[object] = []
    for modification in modifications:
        if not isinstance(modification, RedirectGoto):
            result.append(modification)
            continue
        source = flow_graph.get_block(int(modification.from_serial))
        if (
            source is not None
            and source.nsucc == 1
            and int(modification.old_target) not in excluded_fork_serials
            and _successor_is_fully_resolved_state_fork(
                flow_graph,
                int(modification.old_target),
                planned_targets,
                handler_entries,
            )
        ):
            continue
        result.append(modification)
    return result


def build_source_keyed_handler_redirects(
    flow_graph,
    handler_transitions: tuple[HandlerTransition, ...],
    *,
    protected_edges: frozenset[tuple[int, int]] = frozenset(),
) -> list[object]:
    """Emit exact one-way redirects owned by snapshot-local handler evidence.

    Both materialized state routes and resolver transfer-exit register snapshots
    name the current block that owns the proven route.  Rewrite a one-way edge
    directly, or the exact path-selected arm of a two-way owner, and abstain if
    multiple facts disagree.  ``protected_edges`` carries stronger, already-live
    topology (for example a resolver-proven PREOPT boundary edge) that replayed
    source-keyed state evidence must not replace.
    """
    handler_entries = {int(transition.handler) for transition in handler_transitions}
    candidates: dict[tuple[int, int], set[int]] = {}
    terminal_candidates: dict[int, set[int]] = {}
    for transition in handler_transitions:
        for arm in transition.arms:
            source = arm.source_keyed_block
            target = arm.target_handler
            if source is None or target is None:
                continue
            if int(source) not in arm.ordered_path:
                continue
            if arm.is_return:
                source_block = flow_graph.get_block(int(source))
                if source_block is None or source_block.nsucc != 1:
                    continue
                old = int(source_block.succs[0])
                if old != int(target):
                    continue
                terminal_target = flow_graph.get_block(int(target))
                if terminal_target is None or terminal_target.nsucc != 0:
                    continue
                canonical_stop = _exact_native_terminal_redirect_target(
                    flow_graph,
                    int(target),
                )
                if canonical_stop is not None and int(canonical_stop) != int(target):
                    candidates.setdefault((int(source), old), set()).add(
                        int(canonical_stop)
                    )
                continue
            exit_serial = arm.exit_block
            if (
                exit_serial is not None
                and arm.ordered_path
                and int(arm.ordered_path[-1]) == int(exit_serial)
            ):
                exit_block = flow_graph.get_block(int(exit_serial))
                if (
                    exit_block is not None
                    and exit_block.nsucc == 0
                    and len(exit_block.preds) > 1
                ):
                    # A shared computed-goto suffix cannot be converted as a
                    # whole block: doing so assigns one arm's route to every
                    # predecessor.  Bypass only the predecessor edge owned by
                    # this exact ordered path.  Calls and stores are observable,
                    # so never skip a shared terminal containing either.
                    if any(
                        insn.kind in (InsnKind.CALL, InsnKind.STORE)
                        for insn in exit_block.insn_snapshots
                    ):
                        continue
                    if len(arm.ordered_path) < 2:
                        continue
                    predecessor = int(arm.ordered_path[-2])
                    predecessor_block = flow_graph.get_block(predecessor)
                    if (
                        predecessor_block is None
                        or predecessor_block.nsucc != 1
                        or tuple(int(succ) for succ in predecessor_block.succs)
                        != (int(exit_serial),)
                        or predecessor not in {int(pred) for pred in exit_block.preds}
                    ):
                        continue
                    candidates.setdefault(
                        (predecessor, int(exit_serial)),
                        set(),
                    ).add(int(target))
                    continue
            block = flow_graph.get_block(int(source))
            if block is None or block.nsucc not in (0, 1, 2):
                continue
            if block.nsucc == 0:
                if block.kind in (BlockKind.STOP, BlockKind.EXTERNAL):
                    continue
                terminal_candidates.setdefault(int(source), set()).add(int(target))
                continue
            if block.nsucc == 1:
                old = int(block.succs[0])
            else:
                if arm.branch_block is not None:
                    continue
                try:
                    source_index = arm.ordered_path.index(int(source))
                except ValueError:
                    continue
                if source_index + 1 >= len(arm.ordered_path):
                    continue
                old = int(arm.ordered_path[source_index + 1])
                if old not in {int(succ) for succ in block.succs}:
                    continue
                old_block = flow_graph.get_block(old)
                if old_block is not None:
                    old_successors = tuple(int(succ) for succ in old_block.succs)
                    if (
                        len(old_successors) == 1
                        and old_successors[0] in handler_entries
                    ):
                        # This arm already has a live, unique handler edge.
                        # A state observed before the selecting branch can be
                        # overwritten inside the arm; do not replace that
                        # stronger edge with stale handler-tail evidence.
                        continue
            if (int(source), int(old)) in protected_edges:
                continue
            if old == int(target):
                continue
            candidates.setdefault((int(source), old), set()).add(int(target))
    redirects: list[object] = []
    for source, targets in sorted(terminal_candidates.items()):
        if len(targets) != 1:
            continue
        redirects.append(
            ConvertToGoto(
                block_serial=source,
                goto_target=next(iter(targets)),
            )
        )
    for (source, old), targets in sorted(candidates.items()):
        if len(targets) != 1:
            continue
        block = flow_graph.get_block(int(source))
        if block is None:
            continue
        redirect_type = RedirectBranch if block.nsucc == 2 else RedirectGoto
        redirects.append(
            redirect_type(
                from_serial=source,
                old_target=old,
                new_target=next(iter(targets)),
            )
        )
    return redirects


def build_exact_terminal_state_route_redirects(
    flow_graph,
    routes: tuple[MaterializedStateRoute, ...],
    *,
    state_var_reg: int | None,
) -> list[object]:
    """Project exact terminal state writers onto the canonical STOP."""
    candidates: dict[tuple[int, int], set[int]] = {}
    for route in routes:
        if route.proof_kind != "terminal_state_route":
            continue
        source = int(route.source_block_serial)
        state = int(route.state_constant) & 0xFFFFFFFF
        if (
            _source_local_constant_register_write(
                flow_graph,
                source,
                state_var_reg,
            )
            != state
        ):
            continue
        source_block = flow_graph.get_block(source)
        target = flow_graph.get_block(int(route.target_handler_serial))
        if (
            source_block is None
            or source_block.nsucc != 1
            or target is None
            or target.nsucc != 0
        ):
            continue
        old = int(source_block.succs[0])
        canonical_stop = _exact_native_terminal_redirect_target(
            flow_graph,
            int(route.target_handler_serial),
        )
        if canonical_stop is None or old == int(canonical_stop):
            continue
        candidates.setdefault((source, old), set()).add(int(canonical_stop))
    return [
        RedirectGoto(
            from_serial=source,
            old_target=old,
            new_target=next(iter(targets)),
        )
        for (source, old), targets in sorted(candidates.items())
        if len(targets) == 1
    ]


def _prefer_exact_terminal_route_fragments(
    modifications: list[object],
    terminal_redirects: list[object],
) -> list[object]:
    """Make each exact terminal route the sole CFG rewrite for its source.

    A source-local terminal state write and a rebound zero-successor target
    prove one complete terminal fragment.  A coarse state transition for the
    same source must not race that fragment in the deferred gateway: whichever
    rewrite happens first would make the sibling stale, and equal-priority
    conflict resolution can then select the non-terminal target.  Keep
    instruction-local edits, but replace every same-source CFG rewrite with the
    one exact terminal redirect.  Ambiguous terminal claims abstain.
    """
    terminal_by_source: dict[int, set[tuple[int, int]]] = {}
    terminal_mod_by_key: dict[tuple[int, int, int], object] = {}
    for modification in terminal_redirects:
        if not isinstance(modification, RedirectGoto):
            continue
        source = int(modification.from_serial)
        edge = (int(modification.old_target), int(modification.new_target))
        terminal_by_source.setdefault(source, set()).add(edge)
        terminal_mod_by_key[(source, *edge)] = modification

    authoritative = {
        source: next(iter(edges))
        for source, edges in terminal_by_source.items()
        if len(edges) == 1
    }
    if not authoritative:
        return list(modifications)

    result: list[object] = []
    for modification in modifications:
        if isinstance(modification, (RedirectGoto, RedirectBranch)):
            source = int(modification.from_serial)
        elif isinstance(modification, ConvertToGoto):
            source = int(modification.block_serial)
        elif isinstance(modification, LowerConditionalStateTransition):
            source = int(modification.source_serial)
        else:
            result.append(modification)
            continue
        if source not in authoritative:
            result.append(modification)

    for source, (old_target, new_target) in sorted(authoritative.items()):
        result.append(terminal_mod_by_key[(source, old_target, new_target)])
    return result


def _exact_terminal_state_writer_sources(
    flow_graph,
    routes: tuple[MaterializedStateRoute, ...],
    *,
    state_var_reg: int | None,
) -> set[int]:
    """Return terminal-route sources that perform the proven state write."""
    sources: set[int] = set()
    for route in routes:
        if route.proof_kind != "terminal_state_route":
            continue
        source = int(route.source_block_serial)
        state = int(route.state_constant) & 0xFFFFFFFF
        target = flow_graph.get_block(int(route.target_handler_serial))
        if (
            target is not None
            and target.nsucc == 0
            and _source_local_constant_register_write(
                flow_graph,
                source,
                state_var_reg,
            )
            == state
        ):
            sources.add(source)
    return sources


def _one_way_path_reaches(
    flow_graph,
    start_serial: int,
    target_serial: int,
    *,
    max_hops: int = 8,
) -> bool:
    current = int(start_serial)
    target = int(target_serial)
    seen: set[int] = set()
    for _hop in range(int(max_hops) + 1):
        if current == target:
            return True
        if current in seen:
            return False
        seen.add(current)
        block = flow_graph.get_block(current)
        if block is None or len(block.succs) != 1:
            return False
        current = int(block.succs[0])
    return False


def _break_terminal_switch_dispatcher_cycle(
    flow_graph,
    modifications: list[object],
    *,
    dispatcher_entry_serial: int,
) -> tuple[list[object], int | None]:
    """Retire an N-way dispatcher without leaving a detached switch cycle.

    When exactly one handler redirect replaces a path back to the dispatcher
    with a one-way terminal path, redirect that shared backedge onto the same
    terminal handler.  The extra edit is semantically inert after entry-path
    rewiring, but it makes the detached dispatcher residue acyclic so Hex-Rays
    can remove it instead of spinning in its global optimizer.
    """
    dispatcher_serial = int(dispatcher_entry_serial)
    dispatcher_block = flow_graph.get_block(dispatcher_serial)
    if dispatcher_block is None or dispatcher_block.kind is not BlockKind.N_WAY:
        return list(modifications), None
    stop_serials = tuple(
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if _is_stop_block(block)
    )
    if not stop_serials:
        return list(modifications), None
    candidates = [
        modification
        for modification in modifications
        if isinstance(modification, RedirectGoto)
        and _one_way_path_reaches(
            flow_graph,
            int(modification.old_target),
            dispatcher_serial,
        )
        and any(
            _one_way_path_reaches(
                flow_graph,
                int(modification.new_target),
                stop_serial,
            )
            for stop_serial in stop_serials
        )
    ]
    if len(candidates) != 1:
        return list(modifications), None
    preserved = candidates[0]
    cleanup_source = int(preserved.old_target)
    cleanup_block = flow_graph.get_block(cleanup_source)
    if (
        cleanup_block is None
        or tuple(int(succ) for succ in cleanup_block.succs)
        != (dispatcher_serial,)
    ):
        return list(modifications), None
    return (
        [
            *modifications,
            RedirectGoto(
                from_serial=cleanup_source,
                old_target=dispatcher_serial,
                new_target=int(preserved.new_target),
            ),
        ],
        cleanup_source,
    )


def _reconcile_conditional_bridge_target(
    flow_graph,
    exact_target: int | None,
    state_target: int | None,
) -> int | None:
    if exact_target is None:
        return state_target
    if state_target is None or int(exact_target) == int(state_target):
        return exact_target
    if _one_way_path_reaches(flow_graph, int(state_target), int(exact_target)):
        return exact_target
    return None


def build_materialized_conditional_handler_bridges(
    flow_graph,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    dispatcher=None,
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    handler_entry_eas_by_serial: Mapping[int, int] | None = None,
    imported_native_eas_by_serial: Mapping[int, frozenset[int]] | None = None,
    applied_conditional_boundary_evidence: tuple[
        AppliedDetachedSnippetConditionalBoundaryPort, ...
    ] = (),
) -> list[object]:
    """Restore exact handler predicates folded to one-way residual routes.

    CALLS preanalysis records a resolver-proven predicate and both state-routed
    target EAs before a later materialization round folds the branch.  Preserve
    any still-live predicate; reconstruct a folded predicate only for the
    legacy ``reg != 0`` shape.  Reconnect it only when the current source,
    stale edge, and both target blocks are unique in this snapshot.
    """
    handler_entry_eas = handler_entry_eas_by_serial or {}
    imported_native_eas = imported_native_eas_by_serial or {}
    imported_serials = frozenset(int(serial) for serial in imported_native_eas)
    live_connected_imported = {
        int(serial)
        for serial in imported_serials
        for block in (flow_graph.get_block(int(serial)),)
        if block is not None
        and any(int(pred) not in imported_serials for pred in block.preds)
    }
    frontier = list(live_connected_imported)
    while frontier:
        current = frontier.pop()
        block = flow_graph.get_block(int(current))
        if block is None:
            continue
        for successor in block.succs:
            successor = int(successor)
            if (
                successor in imported_serials
                and successor not in live_connected_imported
            ):
                live_connected_imported.add(successor)
                frontier.append(successor)
    imported_shadow_serials = imported_serials.difference(live_connected_imported)
    late_logical_source_predicates = frozenset(
        int(port.predicate_ea)
        for evidence in applied_conditional_boundary_evidence
        for port in (evidence.port,)
        if port.logical_source_anchor_ea is not None
        and int(port.logical_source_anchor_ea) > 0
        and int(port.logical_source_anchor_ea) != int(port.predicate_ea)
        and port.predicate_ida_stkoff is not None
        and port.predicate_size is not None
        and int(port.predicate_size) > 0
        and (port.predicate_stack_value is not None or port.condition_code in (4, 5))
    )
    ordered_handler_entry_eas = tuple(
        sorted({int(entry_ea) for entry_ea in handler_entry_eas.values()})
    )

    def map_target_entry(target_ea: int) -> int | None:
        target = int(target_ea)
        next_entry_ea = next(
            (entry_ea for entry_ea in ordered_handler_entry_eas if entry_ea > target),
            None,
        )
        return find_unique_target_entry_block(
            flow_graph,
            target,
            next_target_ea=next_entry_ea,
        )

    def map_authoritative_handler_entry(target_ea: int) -> int | None:
        matches = {
            int(serial)
            for serial, entry_ea in handler_entry_eas.items()
            if int(entry_ea) == int(target_ea)
            and flow_graph.get_block(int(serial)) is not None
        }
        return next(iter(matches)) if len(matches) == 1 else None

    candidates: dict[
        tuple[int, int, int],
        set[tuple[int, int, int, int]],
    ] = {}
    live_candidates: dict[tuple[int, int], set[int]] = {}
    live_preserved_candidates: dict[
        tuple[int, int, int],
        set[tuple[int, int, bool, int]],
    ] = {}
    route_target_candidates: dict[tuple[int, int], set[int]] = {}
    for route in materialized_state_routes:
        if flow_graph.get_block(int(route.target_handler_serial)) is None:
            continue
        route_target_candidates.setdefault(
            (
                int(route.source_block_serial),
                int(route.state_constant) & 0xFFFFFFFF,
            ),
            set(),
        ).add(int(route.target_handler_serial))
    for transfer in transfers:
        if int(transfer.source_jmp_ea) in late_logical_source_predicates:
            continue
        trace_exact_live = bool(
            is_conditional_handler_bridge_kind(transfer.resolver_kind)
            and transfer.predicate_preserve_live
        )
        if (
            not is_conditional_handler_bridge_kind(transfer.resolver_kind)
            or (
                not transfer.predicate_preserve_live
                and (transfer.condition_code != 5 or transfer.predicate_size is None)
            )
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
        ):
            continue
        predicate_anchor_eas = {int(transfer.source_jmp_ea)}
        if transfer.predicate_predecessor_ea is not None:
            predicate_anchor_eas.add(int(transfer.predicate_predecessor_ea))
        predicate_matches = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if any(
                int(insn.ea) == int(transfer.source_jmp_ea)
                for insn in block.insn_snapshots
            )
        }
        if len(predicate_matches) != 1:
            live_predicate_matches = {
                int(serial)
                for serial in predicate_matches
                if flow_graph.get_block(int(serial)) is not None
                and flow_graph.get_block(int(serial)).preds
                and flow_graph.get_block(int(serial)).insn_snapshots
                and flow_graph.get_block(int(serial))
                .insn_snapshots[-1]
                .is_conditional_jump
                and int(flow_graph.get_block(int(serial)).insn_snapshots[-1].ea)
                == int(transfer.source_jmp_ea)
            }
            if len(live_predicate_matches) == 1:
                predicate_matches = live_predicate_matches
        if not predicate_matches:
            imported_predicate_matches = {
                int(serial)
                for serial, native_eas in imported_native_eas.items()
                for block in (flow_graph.get_block(int(serial)),)
                if int(transfer.source_jmp_ea) in native_eas
                and block is not None
                and block.insn_snapshots
                and block.insn_snapshots[-1].is_conditional_jump
            }
            if len(imported_predicate_matches) == 1:
                predicate_matches = imported_predicate_matches
        handler_source_matches = {
            int(serial)
            for serial, entry_ea in handler_entry_eas.items()
            for block in (flow_graph.get_block(int(serial)),)
            if int(entry_ea) == int(transfer.source_block_ea)
            and block is not None
            and block.insn_snapshots
            and block.insn_snapshots[-1].is_conditional_jump
            and (
                int(transfer.source_jmp_ea)
                in imported_native_eas.get(int(serial), frozenset())
                or any(
                    int(insn.ea) in predicate_anchor_eas
                    for insn in block.insn_snapshots
                )
            )
        }
        # A native predicate and its imported semantic clone can both survive
        # into CALLS.  The exact-EA copy is then often dispatcher residue,
        # while ``handler_entry_eas`` identifies the clone that owns the live
        # materialized handler.  Prefer that unique portable owner; otherwise
        # the rewrite lands on a block Hex-Rays later deletes and leaves the
        # reachable clone routed through stale state handlers.
        authoritative_source_matches = (
            handler_source_matches if len(handler_source_matches) == 1 else set()
        )
        source_matches = (
            authoritative_source_matches
            or predicate_matches
            or {
                int(block.serial)
                for block in flow_graph.blocks.values()
                if (
                    int(block.start_ea) == int(transfer.source_block_ea)
                    and int(block.serial) not in imported_native_eas
                )
                or any(
                    int(insn.ea) in predicate_anchor_eas
                    for insn in block.insn_snapshots
                )
            }
        )
        if len(source_matches) != 1:
            if trace_exact_live:
                logger.info(
                    "conditional bridge exact-live abstained: predicate=0x%X "
                    "gate=source_match matches=%s source_ea=0x%X",
                    int(transfer.source_jmp_ea),
                    sorted(int(serial) for serial in source_matches),
                    int(transfer.source_block_ea),
                )
            continue
        source = next(iter(source_matches))
        source_block = flow_graph.get_block(source)
        if source_block is None or source_block.nsucc not in {1, 2}:
            if trace_exact_live:
                logger.info(
                    "conditional bridge exact-live abstained: predicate=0x%X "
                    "gate=source_shape source=blk%d@0x%X nsucc=%s",
                    int(transfer.source_jmp_ea),
                    int(source),
                    (
                        int(transfer.source_block_ea)
                        if source_block is None
                        else int(source_block.start_ea)
                    ),
                    None if source_block is None else int(source_block.nsucc),
                )
            continue
        source_instructions = tuple(source_block.insn_snapshots)
        predicate_eas = [int(insn.ea) for insn in source_instructions]
        authoritative_imported_source = bool(
            int(source) in imported_native_eas
            and int(transfer.source_jmp_ea) in imported_native_eas[int(source)]
        )
        true_target_from_ea = map_target_entry(int(transfer.true_target_ea))
        false_target_from_ea = map_target_entry(int(transfer.false_target_ea))
        true_target_from_state = (
            dispatcher.lookup(int(transfer.predicate_true_state) & 0xFFFFFFFF)
            if dispatcher is not None and transfer.predicate_true_state is not None
            else None
        )
        false_target_from_state = (
            dispatcher.lookup(int(transfer.predicate_false_state) & 0xFFFFFFFF)
            if dispatcher is not None and transfer.predicate_false_state is not None
            else None
        )
        true_target_from_route = None
        if transfer.predicate_true_state is not None:
            route_candidates = set().union(
                *(
                    route_target_candidates.get(
                        (
                            int(route_source),
                            int(transfer.predicate_true_state) & 0xFFFFFFFF,
                        ),
                        set(),
                    )
                    for route_source in {
                        int(source),
                        *(int(succ) for succ in source_block.succs),
                    }
                )
            )
            if len(route_candidates) == 1:
                true_target_from_route = next(iter(route_candidates))
        false_target_from_route = None
        if transfer.predicate_false_state is not None:
            route_candidates = set().union(
                *(
                    route_target_candidates.get(
                        (
                            int(route_source),
                            int(transfer.predicate_false_state) & 0xFFFFFFFF,
                        ),
                        set(),
                    )
                    for route_source in {
                        int(source),
                        *(int(succ) for succ in source_block.succs),
                    }
                )
            )
            if len(route_candidates) == 1:
                false_target_from_route = next(iter(route_candidates))
        if transfer.predicate_preserve_live:
            # Only a source-keyed materialized route is contradictory
            # evidence here.  A dispatcher lookup may merely be its broad
            # default interval, so it cannot veto an exact handler-entry EA.
            true_route_had_candidate = true_target_from_route is not None
            false_route_had_candidate = false_target_from_route is not None

            def route_matches_exact_target(
                route_serial: int | None,
                exact_target_ea: int,
            ) -> bool:
                if route_serial is None:
                    return False
                route = int(route_serial)
                route_block = flow_graph.get_block(route)
                if route_block is None:
                    return False
                target_ea = int(exact_target_ea)
                if int(route_block.start_ea) == target_ea:
                    return True
                later_route_eas = sorted(
                    {
                        int(instruction.ea)
                        for instruction in route_block.insn_snapshots
                        if int(instruction.ea) > target_ea
                    }
                )
                if (
                    later_route_eas
                    and int(route_block.start_ea) <= target_ea
                    and find_unique_target_entry_block(
                        flow_graph,
                        target_ea,
                        next_target_ea=int(later_route_eas[0]) + 1,
                        excluded_serials=frozenset(
                            imported_shadow_serials.difference({route})
                        ),
                    )
                    == route
                ):
                    return True
                mapped_entry_ea = handler_entry_eas.get(route)
                if mapped_entry_ea is not None:
                    if int(mapped_entry_ea) == int(exact_target_ea):
                        return True
                    exact_entry = map_target_entry(int(exact_target_ea))
                    exact_block = (
                        flow_graph.get_block(int(exact_entry))
                        if exact_entry is not None
                        else None
                    )
                    if (
                        exact_block is not None
                        and exact_block.insn_snapshots
                        and int(exact_block.start_ea)
                        <= int(mapped_entry_ea)
                        <= max(
                            int(instruction.ea)
                            for instruction in exact_block.insn_snapshots
                        )
                    ):
                        return True
                    mapped_native_entry = find_unique_target_entry_block(
                        flow_graph,
                        int(mapped_entry_ea),
                    )
                    return (
                        exact_entry is not None
                        and mapped_native_entry is not None
                        and _one_way_path_reaches(
                            flow_graph,
                            int(exact_entry),
                            int(mapped_native_entry),
                        )
                    )
                if not later_route_eas or int(route_block.start_ea) > target_ea:
                    return False
                folded_owner = find_unique_target_entry_block(
                    flow_graph,
                    target_ea,
                    next_target_ea=int(later_route_eas[0]) + 1,
                )
                return folded_owner == route

            if not route_matches_exact_target(
                true_target_from_route,
                int(transfer.true_target_ea),
            ):
                true_target_from_route = None
            if not route_matches_exact_target(
                false_target_from_route,
                int(transfer.false_target_ea),
            ):
                false_target_from_route = None
            if true_target_from_route is None and route_matches_exact_target(
                true_target_from_state,
                int(transfer.true_target_ea),
            ):
                true_target_from_route = int(true_target_from_state)
            if false_target_from_route is None and route_matches_exact_target(
                false_target_from_state,
                int(transfer.false_target_ea),
            ):
                false_target_from_route = int(false_target_from_state)
            # The portable handler-entry index is itself exact target-EA
            # authority.  It is the reference-style fallback when a rebound
            # imported predicate has no source-local state-route row.  Never
            # use it to paper over a contradictory route candidate: that case
            # remains an atomic abstention.
            if (
                true_target_from_route is None
                and not true_route_had_candidate
                and authoritative_imported_source
            ):
                true_target_from_route = map_authoritative_handler_entry(
                    int(transfer.true_target_ea)
                )
            if (
                false_target_from_route is None
                and not false_route_had_candidate
                and authoritative_imported_source
            ):
                false_target_from_route = map_authoritative_handler_entry(
                    int(transfer.false_target_ea)
                )
            if (
                true_target_from_ea is not None
                and true_target_from_route is not None
                and _one_way_path_reaches(
                    flow_graph,
                    int(true_target_from_route),
                    int(true_target_from_ea),
                )
            ):
                true_target_from_route = int(true_target_from_ea)
            if (
                false_target_from_ea is not None
                and false_target_from_route is not None
                and _one_way_path_reaches(
                    flow_graph,
                    int(false_target_from_route),
                    int(false_target_from_ea),
                )
            ):
                false_target_from_route = int(false_target_from_ea)
        true_target_without_route = _reconcile_conditional_bridge_target(
            flow_graph,
            true_target_from_ea,
            true_target_from_state,
        )
        true_target = (
            true_target_from_route
            if true_target_from_route is not None
            else true_target_without_route
        )
        false_target_without_route = _reconcile_conditional_bridge_target(
            flow_graph,
            false_target_from_ea,
            false_target_from_state,
        )
        false_target = (
            false_target_from_route
            if false_target_from_route is not None
            else false_target_without_route
        )
        if transfer.predicate_preserve_live and (
            true_target_from_route is None or false_target_from_route is None
        ):
            if trace_exact_live:
                logger.info(
                    "conditional bridge exact-live abstained: predicate=0x%X "
                    "gate=atomic_routes source=blk%d@0x%X true_route=%s "
                    "false_route=%s",
                    int(transfer.source_jmp_ea),
                    int(source),
                    int(source_block.start_ea),
                    true_target_from_route,
                    false_target_from_route,
                )
            continue
        if source_block.nsucc == 2:
            if transfer.predicate_true_is_taken is None:
                if trace_exact_live:
                    logger.info(
                        "conditional bridge exact-live abstained: predicate=0x%X "
                        "gate=arm_polarity source=blk%d@0x%X",
                        int(transfer.source_jmp_ea),
                        int(source),
                        int(source_block.start_ea),
                    )
                continue
            predicate = next(
                (
                    insn
                    for insn in reversed(source_instructions)
                    if int(insn.ea) == int(transfer.source_jmp_ea)
                ),
                None,
            )
            if (
                predicate is None
                and int(source) in imported_native_eas
                and int(transfer.source_jmp_ea) in imported_native_eas[int(source)]
                and source_instructions
                and source_instructions[-1].is_conditional_jump
            ):
                predicate = source_instructions[-1]
            taken = (
                int(predicate.d.block_ref)
                if predicate is not None
                and predicate.d is not None
                and predicate.d.block_ref is not None
                else None
            )
            successors = tuple(int(succ) for succ in source_block.succs)
            if taken is None or taken not in successors:
                if trace_exact_live:
                    logger.info(
                        "conditional bridge exact-live abstained: predicate=0x%X "
                        "gate=taken_successor source=blk%d@0x%X taken=%s successors=%s",
                        int(transfer.source_jmp_ea),
                        int(source),
                        int(source_block.start_ea),
                        taken,
                        successors,
                    )
                continue
            taken_target = (
                true_target if transfer.predicate_true_is_taken else false_target
            )
            preserve_exact_predicate = (
                transfer.predicate_preserve_live
                and true_target_from_route is not None
                and false_target_from_route is not None
            )
            if preserve_exact_predicate:
                if trace_exact_live:
                    logger.info(
                        "conditional bridge exact-live resolved: predicate=0x%X "
                        "source=blk%d@0x%X true=%s false=%s true_ea=%s "
                        "false_ea=%s true_state=%s false_state=%s "
                        "true_route=%s false_route=%s",
                        int(transfer.source_jmp_ea),
                        int(source),
                        int(source_block.start_ea),
                        true_target,
                        false_target,
                        true_target_from_ea,
                        false_target_from_ea,
                        true_target_from_state,
                        false_target_from_state,
                        true_target_from_route,
                        false_target_from_route,
                    )
                if (
                    true_target is None
                    or false_target is None
                    or int(true_target) == int(false_target)
                ):
                    continue
                if trace_exact_live:
                    logger.info(
                        "conditional bridge exact-live planned: predicate=0x%X "
                        "source=blk%d@0x%X old=blk%d@0x%X false=blk%d@0x%X "
                        "true=blk%d@0x%X mode=preserve",
                        int(transfer.source_jmp_ea),
                        int(source),
                        int(source_block.start_ea),
                        int(taken),
                        int(flow_graph.get_block(int(taken)).start_ea),
                        int(false_target),
                        int(flow_graph.get_block(int(false_target)).start_ea),
                        int(true_target),
                        int(flow_graph.get_block(int(true_target)).start_ea),
                    )
                live_preserved_candidates.setdefault(
                    (source, int(predicate.ea), int(taken)),
                    set(),
                ).add(
                    (
                        int(false_target),
                        int(true_target),
                        bool(transfer.predicate_true_is_taken),
                        int(transfer.source_jmp_ea),
                    )
                )
                continue
            if taken_target is None:
                if trace_exact_live:
                    logger.info(
                        "conditional bridge exact-live abstained: predicate=0x%X "
                        "gate=taken_target source=blk%d@0x%X true=%s false=%s "
                        "true_ea=%s false_ea=%s true_state=%s false_state=%s "
                        "true_route=%s false_route=%s",
                        int(transfer.source_jmp_ea),
                        int(source),
                        int(source_block.start_ea),
                        true_target,
                        false_target,
                        true_target_from_ea,
                        false_target_from_ea,
                        true_target_from_state,
                        false_target_from_state,
                        true_target_from_route,
                        false_target_from_route,
                    )
                continue
            if trace_exact_live:
                logger.info(
                    "conditional bridge exact-live planned: predicate=0x%X "
                    "source=blk%d@0x%X old=blk%d@0x%X target=blk%d@0x%X "
                    "mode=one_arm true=%s false=%s true_ea=%s false_ea=%s "
                    "true_state=%s false_state=%s true_route=%s false_route=%s",
                    int(transfer.source_jmp_ea),
                    int(source),
                    int(source_block.start_ea),
                    int(taken),
                    int(flow_graph.get_block(int(taken)).start_ea),
                    int(taken_target),
                    int(flow_graph.get_block(int(taken_target)).start_ea),
                    true_target,
                    false_target,
                    true_target_from_ea,
                    false_target_from_ea,
                    true_target_from_state,
                    false_target_from_state,
                    true_target_from_route,
                    false_target_from_route,
                )
            live_candidates.setdefault((source, taken), set()).add(int(taken_target))
            continue

        if (
            true_target is None
            or false_target is None
            or int(true_target) == int(false_target)
        ):
            continue

        # A folded one-way branch must be reconstructed, so unlike the live
        # two-way path above it requires an exact register identity.
        if transfer.predicate_register is None:
            continue

        # A register-vs-register comparison is safe while its original 2-way
        # branch is live (handled above), but cannot be reconstructed as the
        # legacy synthetic ``register != 0`` condition after folding.
        if (
            transfer.predicate_compare_register is not None
            or transfer.predicate_compare_constant is not None
        ):
            continue

        if int(transfer.source_jmp_ea) in predicate_eas:
            rewrite_ea = int(transfer.source_jmp_ea)
        else:
            if transfer.predicate_predecessor_ea is None:
                continue
            try:
                predecessor_index = predicate_eas.index(
                    int(transfer.predicate_predecessor_ea)
                )
            except ValueError:
                continue
            if predecessor_index + 1 >= len(source_instructions):
                continue
            rewrite_ea = int(source_instructions[predecessor_index + 1].ea)
        old = int(source_block.succs[0])
        key = (source, rewrite_ea, old)
        candidates.setdefault(key, set()).add(
            (
                int(false_target),
                int(true_target),
                int(transfer.predicate_register),
                int(transfer.predicate_size),
            )
        )

    result: list[object] = []
    for (source, predicate_ea, old), proofs in sorted(
        live_preserved_candidates.items()
    ):
        semantic_proofs = {
            (false_target, true_target, true_is_taken)
            for (
                false_target,
                true_target,
                true_is_taken,
                _native_predicate_ea,
            ) in proofs
        }
        if len(semantic_proofs) != 1:
            continue
        false_target, true_target, true_is_taken = next(iter(semantic_proofs))
        native_predicate_ea = min(
            int(proof_native_ea)
            for (
                proof_false_target,
                proof_true_target,
                proof_true_is_taken,
                proof_native_ea,
            ) in proofs
            if (
                int(proof_false_target),
                int(proof_true_target),
                bool(proof_true_is_taken),
            )
            == (
                int(false_target),
                int(true_target),
                bool(true_is_taken),
            )
        )
        predicate_proof = f"predicate_ea=0x{predicate_ea:X}"
        if int(native_predicate_ea) != int(predicate_ea):
            predicate_proof += f":native_predicate_ea=0x{native_predicate_ea:X}"
        result.append(
            LowerConditionalStateTransition(
                source_serial=int(source),
                old_dispatcher_serial=int(old),
                rewrite_from_ea=int(predicate_ea),
                condition_operand=PreserveLivePredicateCondition(
                    predicate_ea=int(predicate_ea),
                    true_is_taken=bool(true_is_taken),
                ),
                false_target_serial=int(false_target),
                true_target_serial=int(true_target),
                proof_id=(
                    "conditional_handler_bridge:"
                    f"source_ea=0x{flow_graph.get_block(source).start_ea:X}:"
                    f"{predicate_proof}"
                ),
                reason="resolver_proven_live_conditional_handler_bridge",
            )
        )
    for (source, old), targets in sorted(live_candidates.items()):
        if len(targets) != 1:
            continue
        target = next(iter(targets))
        if int(old) == int(target):
            continue
        result.append(
            RedirectBranch(
                from_serial=int(source),
                old_target=int(old),
                new_target=int(target),
            )
        )
    for (source, predicate_ea, old), proofs in sorted(candidates.items()):
        if len(proofs) != 1:
            continue
        false_target, true_target, predicate_reg, predicate_size = next(iter(proofs))
        result.append(
            LowerConditionalStateTransition(
                source_serial=source,
                old_dispatcher_serial=old,
                rewrite_from_ea=predicate_ea,
                condition_operand=SyntheticRegisterNonzeroCondition(
                    predicate_reg=predicate_reg,
                    predicate_size=predicate_size,
                ),
                false_target_serial=false_target,
                true_target_serial=true_target,
                proof_id=(
                    "conditional_handler_bridge:"
                    f"source_ea=0x{flow_graph.get_block(source).start_ea:X}:"
                    f"predicate_ea=0x{predicate_ea:X}"
                ),
                reason="resolver_proven_conditional_handler_bridge",
            )
        )
    return result


def _prove_materialized_conditional_entry_bridge(
    flow_graph,
    modifications: tuple[object, ...],
    *,
    dispatcher_entry_serial: int,
    handler_serials: frozenset[int],
) -> ConditionalEntryBridgeProof | None:
    """Prove that one exact live entry-prefix predicate reaches two handlers.

    The conditional bridge builder already checked predicate identity,
    polarity, and exact state-to-handler arm routing. This projection accepts
    that proof as the function's entry bridge only when its source is reachable
    before crossing either the dispatcher or any handler entry. Handler-local
    predicates therefore cannot satisfy the entry safety gate.
    """
    dispatcher_entry = int(dispatcher_entry_serial)
    handlers = frozenset(int(serial) for serial in handler_serials)
    if not handlers:
        return None

    entry_prefix: set[int] = set()
    pending = [int(flow_graph.entry_serial)]
    boundaries = set(handlers)
    boundaries.add(dispatcher_entry)
    while pending:
        serial = pending.pop()
        if serial in entry_prefix or serial in boundaries:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        entry_prefix.add(serial)
        pending.extend(int(successor) for successor in block.succs)

    candidates: set[ConditionalEntryBridgeProof] = set()
    for modification in modifications:
        if not isinstance(modification, LowerConditionalStateTransition):
            continue
        condition = modification.condition_operand
        if not isinstance(condition, PreserveLivePredicateCondition):
            continue
        source = int(modification.source_serial)
        false_target = int(modification.false_target_serial)
        true_target = int(modification.true_target_serial)
        if (
            source not in entry_prefix
            or false_target == true_target
            or false_target not in handlers
            or true_target not in handlers
        ):
            continue
        source_block = flow_graph.get_block(source)
        predicate_ea = int(condition.predicate_ea)
        if (
            source_block is None
            or source_block.nsucc != 2
            or not any(
                instruction.is_conditional_jump and int(instruction.ea) == predicate_ea
                for instruction in source_block.insn_snapshots
            )
        ):
            continue
        candidates.add(
            ConditionalEntryBridgeProof(
                source_serial=source,
                predicate_ea=predicate_ea,
                false_target_serial=false_target,
                true_target_serial=true_target,
            )
        )
    return next(iter(candidates)) if len(candidates) == 1 else None


def _prove_bound_bootstrap_entry_routes(
    flow_graph,
    evidence_rows: tuple[BootstrapRouteBindingEvidence, ...],
    *,
    dispatcher_entry_serial: int,
) -> tuple[BootstrapEntryRouteProof, ...]:
    """Rebind exact PREOPT routes and confirm their current live entry edges.

    A bootstrap route is source-scoped; it is not a scalar initial state for
    sibling prologue arms.  The proof therefore accepts only an already-applied
    ``source -> handler`` edge reachable before crossing the dispatcher.  It can
    satisfy the safety gate without redirecting any unresolved sibling arm.
    """
    if not evidence_rows:
        return ()
    dispatcher = int(dispatcher_entry_serial)
    entry_prefix = _entry_prefix_blocks(flow_graph, dispatcher)

    def rebind(identity) -> int | None:
        starts = {
            int(interval.start_ea) for interval in identity.native_ranges.intervals
        }
        matches = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.start_ea) in starts
        }
        return next(iter(matches)) if len(matches) == 1 else None

    candidates_by_source: dict[int, set[BootstrapEntryRouteProof]] = {}
    for evidence in evidence_rows:
        source = rebind(evidence.source_identity)
        handler = rebind(evidence.handler_identity)
        if source is None or handler is None or handler == dispatcher:
            continue
        source_block = flow_graph.get_block(source)
        if (
            source_block is None
            or source not in entry_prefix
            or handler not in tuple(int(serial) for serial in source_block.succs)
        ):
            continue
        proof = BootstrapEntryRouteProof(
            source_serial=source,
            handler_serial=handler,
            state=int(evidence.route.state) & 0xFFFFFFFF,
            source_anchor_ea=int(evidence.route.source_anchor_ea),
            handler_anchor_ea=int(evidence.route.handler_anchor_ea),
        )
        candidates_by_source.setdefault(source, set()).add(proof)
    return tuple(
        sorted(
            (
                next(iter(candidates))
                for candidates in candidates_by_source.values()
                if len(candidates) == 1
            ),
            key=lambda proof: (
                int(proof.source_anchor_ea),
                int(proof.state),
                int(proof.handler_anchor_ea),
            ),
        )
    )


def _plan_imported_conditional_entry_bridges(
    flow_graph,
    evidence_rows: tuple[AppliedDetachedSnippetConditionalBoundaryPort, ...],
    *,
    dispatcher_entry_serial: int,
    handler_serials: frozenset[int],
    state_var_reg: int | None,
    imported_native_eas_by_serial: Mapping[int, frozenset[int]] | None = None,
    handler_entry_eas_by_serial: Mapping[int, int] | None = None,
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    dispatcher: object | None = None,
) -> ConditionalEntryBridgePlan | None:
    """Bind applied PREOPT conditional ports as one atomic entry forest.

    The importer records instruction anchors from each exact created arm block.
    The source predicate must still be the exact live two-way tail. When an arm
    anchor survives, its current path must agree through only acyclic one-way
    glue. When CALLS DCE removes every arm anchor, the already-applied port may
    fall back only to that exact predicate's surviving non-dispatcher arm.

    A target explicitly marked as another boundary source is an internal node,
    not a handler. Every such node must bind to exactly one other proven
    predicate in the entry prefix, and every leaf must terminate at an
    authoritative handler. The whole forest abstains on ambiguity, a missing
    internal source, or a cycle.
    """
    dispatcher_entry = int(dispatcher_entry_serial)
    if not evidence_rows or state_var_reg is None:
        return None
    imported_origins = imported_native_eas_by_serial or {}
    handler_entry_eas = handler_entry_eas_by_serial or {}
    handlers = frozenset(int(serial) for serial in handler_serials)

    def resolve_anchors(anchor_eas: tuple[int, ...]) -> int | None:
        anchors = {int(ea) for ea in anchor_eas}
        matches = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if any(int(insn.ea) in anchors for insn in block.insn_snapshots)
        }
        return next(iter(matches)) if len(matches) == 1 else None

    def resolve_target(
        target_ea: int,
        owner: DetachedSnippetBoundaryPortOwner,
        anchor_eas: tuple[int, ...],
    ) -> int | None:
        if owner == DetachedSnippetBoundaryPortOwner.IMPORTED:
            exact_matches = {
                int(serial)
                for serial, native_eas in imported_origins.items()
                if int(target_ea) in native_eas
            }
            if len(exact_matches) == 1:
                return next(iter(exact_matches))
            if not exact_matches:
                range_matches = {
                    int(serial)
                    for serial, native_eas in imported_origins.items()
                    if native_eas
                    and min(native_eas) <= int(target_ea) <= max(native_eas)
                }
                if len(range_matches) == 1:
                    return next(iter(range_matches))
        return resolve_anchors(anchor_eas)

    def resolve_source(
        port: DetachedSnippetConditionalBoundaryPort,
    ) -> tuple[int, ...]:
        logical_anchor = port.logical_source_anchor_ea
        if (
            logical_anchor is None
            or int(logical_anchor) <= 0
            or int(logical_anchor) == int(port.predicate_ea)
        ):
            return tuple(
                int(block.serial)
                for block in flow_graph.blocks.values()
                if block.insn_snapshots
                and block.insn_snapshots[-1].is_conditional_jump
                and int(block.insn_snapshots[-1].ea) == int(port.predicate_ea)
            )

        owner = port.logical_source_owner or port.source_owner
        if owner == DetachedSnippetBoundaryPortOwner.IMPORTED:
            matches = {
                int(serial)
                for serial, native_eas in imported_origins.items()
                if int(logical_anchor) in native_eas
            }
        else:
            matches = {
                int(block.serial)
                for block in flow_graph.blocks.values()
                if any(
                    int(instruction.ea) == int(logical_anchor)
                    for instruction in block.insn_snapshots
                )
            }
        return tuple(
            sorted(
                serial
                for serial in matches
                for block in (flow_graph.get_block(serial),)
                if block is not None
                and block.insn_snapshots
                and block.insn_snapshots[-1].is_conditional_jump
            )
        )

    def authoritative_state_target(state: int | None) -> int | None:
        if state is None:
            return None
        target = _unique_materialized_state_target(
            materialized_state_routes,
            int(state),
            frozenset(int(serial) for serial in handler_serials),
        )
        if target is not None:
            return int(target)
        if dispatcher is None:
            return None
        mapped = dispatcher.lookup(int(state) & 0xFFFFFFFF)
        return None if mapped is None else int(mapped)

    def canonical_handler_target(
        target_ea: int,
    ) -> tuple[int | None, bool]:
        matches = {
            int(serial)
            for serial, entry_ea in handler_entry_eas.items()
            if int(serial) in handlers
            and int(entry_ea) == int(target_ea)
            and flow_graph.get_block(int(serial)) is not None
        }
        if len(matches) > 1:
            return None, True
        return (next(iter(matches)), False) if matches else (None, False)

    resolved: list[
        tuple[
            AppliedDetachedSnippetConditionalBoundaryPort,
            int | None,
            int | None,
            bool,
            bool,
        ]
    ] = []
    for evidence in evidence_rows:
        port = evidence.port
        if (
            port.state_register is None
            or int(port.state_register) != int(state_var_reg)
            or port.taken_state is None
            or port.fallthrough_state is None
            or (
                int(port.taken_state) & 0xFFFFFFFF
                == int(port.fallthrough_state) & 0xFFFFFFFF
            )
        ):
            continue
        taken_target = resolve_target(
            int(port.taken_target_ea),
            port.taken_target_owner,
            evidence.taken_target_anchor_eas,
        )
        fallthrough_target = resolve_target(
            int(port.fallthrough_target_ea),
            port.fallthrough_target_owner,
            evidence.fallthrough_target_anchor_eas,
        )
        taken_handler_target, taken_handler_ambiguous = (
            (None, False)
            if port.taken_target_is_boundary_source
            else canonical_handler_target(int(port.taken_target_ea))
        )
        fallthrough_handler_target, fallthrough_handler_ambiguous = (
            (None, False)
            if port.fallthrough_target_is_boundary_source
            else canonical_handler_target(int(port.fallthrough_target_ea))
        )
        if taken_handler_ambiguous or fallthrough_handler_ambiguous:
            logger.info(
                "imported conditional entry abstained: predicate=0x%X "
                "gate=handler_entry_ea taken_ea=0x%X "
                "fallthrough_ea=0x%X",
                int(port.predicate_ea),
                int(port.taken_target_ea),
                int(port.fallthrough_target_ea),
            )
            continue
        taken_state_target = (
            None
            if port.taken_target_is_boundary_source
            else authoritative_state_target(port.taken_state)
        )
        fallthrough_state_target = (
            None
            if port.fallthrough_target_is_boundary_source
            else authoritative_state_target(port.fallthrough_state)
        )
        taken_authoritative = (
            taken_handler_target is not None or taken_state_target is not None
        )
        fallthrough_authoritative = (
            fallthrough_handler_target is not None
            or fallthrough_state_target is not None
        )
        if taken_handler_target is not None:
            taken_target = _reconcile_conditional_bridge_target(
                flow_graph,
                taken_handler_target,
                taken_state_target,
            )
            if taken_target is None:
                continue
        elif taken_state_target is not None:
            taken_target = taken_state_target
        if fallthrough_handler_target is not None:
            fallthrough_target = _reconcile_conditional_bridge_target(
                flow_graph,
                fallthrough_handler_target,
                fallthrough_state_target,
            )
            if fallthrough_target is None:
                continue
        elif fallthrough_state_target is not None:
            fallthrough_target = fallthrough_state_target
        if (
            taken_target is not None
            and fallthrough_target is not None
            and taken_target == fallthrough_target
        ):
            logger.info(
                "imported conditional entry abstained: predicate=0x%X "
                "gate=target_anchor taken=%s fallthrough=%s "
                "taken_anchors=%s fallthrough_anchors=%s",
                int(port.predicate_ea),
                (
                    None
                    if taken_target is None
                    else _format_block_label(flow_graph, taken_target)
                ),
                (
                    None
                    if fallthrough_target is None
                    else _format_block_label(flow_graph, fallthrough_target)
                ),
                ["0x%X" % int(ea) for ea in evidence.taken_target_anchor_eas[:4]],
                ["0x%X" % int(ea) for ea in evidence.fallthrough_target_anchor_eas[:4]],
            )
            continue
        resolved.append(
            (
                evidence,
                taken_target,
                fallthrough_target,
                taken_authoritative,
                fallthrough_authoritative,
            )
        )

    if not resolved or not handlers:
        return None

    def arm_reaches_target(start_serial: int, target_serial: int) -> bool:
        current = int(start_serial)
        target = int(target_serial)
        visited: set[int] = set()
        while current != target:
            if current in visited or current in handlers or current == dispatcher_entry:
                return False
            visited.add(current)
            block = flow_graph.get_block(current)
            if block is None or len(block.succs) != 1:
                return False
            current = int(block.succs[0])
        return True

    candidate_rows: dict[
        int,
        set[tuple[ConditionalEntryBridgeProof, int, int, bool, bool]],
    ] = {}
    for (
        evidence,
        taken_target,
        fallthrough_target,
        taken_authoritative,
        fallthrough_authoritative,
    ) in resolved:
        port = evidence.port
        source_matches = resolve_source(port)
        if len(source_matches) != 1:
            logger.info(
                "imported conditional entry abstained: predicate=0x%X "
                "logical_source=%s gate=source_match matches=%s",
                int(port.predicate_ea),
                (
                    None
                    if port.logical_source_anchor_ea is None
                    else "0x%X" % int(port.logical_source_anchor_ea)
                ),
                [_format_block_label(flow_graph, serial) for serial in source_matches],
            )
            continue
        source = source_matches[0]
        source_block = flow_graph.get_block(source)
        if source_block is None or source_block.nsucc != 2:
            logger.info(
                "imported conditional entry abstained: predicate=0x%X "
                "source=%s gate=target_bind taken=%s fallthrough=%s",
                int(port.predicate_ea),
                _format_block_label(flow_graph, source),
                (
                    None
                    if taken_target is None
                    else _format_block_label(flow_graph, taken_target)
                ),
                (
                    None
                    if fallthrough_target is None
                    else _format_block_label(flow_graph, fallthrough_target)
                ),
            )
            continue
        predicate = source_block.insn_snapshots[-1]
        live_predicate_ea = int(predicate.ea)
        taken_start = predicate.d.block_ref
        if taken_start is None:
            continue
        source_successors = tuple(int(successor) for successor in source_block.succs)
        taken_start = int(taken_start)
        if taken_start not in source_successors:
            continue
        fallthrough_starts = tuple(
            successor for successor in source_successors if successor != taken_start
        )
        if len(fallthrough_starts) != 1:
            continue
        taken_proof_target = (
            int(taken_target) if taken_target is not None else int(taken_start)
        )
        fallthrough_proof_target = (
            int(fallthrough_target)
            if fallthrough_target is not None
            else int(fallthrough_starts[0])
        )
        taken_reaches = taken_authoritative or (
            taken_start != dispatcher_entry
            and flow_graph.get_block(taken_start) is not None
            if taken_target is None
            else arm_reaches_target(taken_start, int(taken_target))
        )
        fallthrough_reaches = fallthrough_authoritative or (
            fallthrough_starts[0] != dispatcher_entry
            and flow_graph.get_block(fallthrough_starts[0]) is not None
            if fallthrough_target is None
            else arm_reaches_target(fallthrough_starts[0], int(fallthrough_target))
        )
        if not taken_reaches or not fallthrough_reaches:
            logger.info(
                "imported conditional entry abstained: predicate=0x%X "
                "source=%s gate=arm_path taken_start=%s taken_target=%s "
                "taken_reaches=%s fallthrough_start=%s "
                "fallthrough_target=%s fallthrough_reaches=%s",
                int(port.predicate_ea),
                _format_block_label(flow_graph, source),
                _format_block_label(flow_graph, taken_start),
                (
                    "applied-arm"
                    if taken_target is None
                    else _format_block_label(flow_graph, taken_target)
                ),
                taken_reaches,
                _format_block_label(flow_graph, fallthrough_starts[0]),
                (
                    "applied-arm"
                    if fallthrough_target is None
                    else _format_block_label(flow_graph, fallthrough_target)
                ),
                fallthrough_reaches,
            )
            continue
        true_is_taken = (
            bool(port.predicate_true_is_taken)
            if port.predicate_true_is_taken in (True, False)
            else True
        )
        proof = ConditionalEntryBridgeProof(
            source_serial=source,
            predicate_ea=live_predicate_ea,
            false_target_serial=(
                fallthrough_proof_target if true_is_taken else taken_proof_target
            ),
            true_target_serial=(
                taken_proof_target if true_is_taken else fallthrough_proof_target
            ),
            true_is_taken=true_is_taken,
        )
        candidate_rows.setdefault(source, set()).add(
            (
                proof,
                taken_proof_target,
                fallthrough_proof_target,
                bool(port.taken_target_is_boundary_source),
                bool(port.fallthrough_target_is_boundary_source),
            )
        )

    if not candidate_rows:
        return None
    entry_prefix: set[int] = set()
    pending = [int(flow_graph.entry_serial)]
    boundaries = {*handlers, dispatcher_entry}
    while pending:
        serial = pending.pop()
        if serial in entry_prefix or serial in boundaries:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        entry_prefix.add(serial)
        pending.extend(int(successor) for successor in block.succs)

    candidate_rows = {
        source: rows
        for source, rows in candidate_rows.items()
        if source in entry_prefix
    }
    if not candidate_rows or any(len(rows) != 1 for rows in candidate_rows.values()):
        if logger.info_on:
            logger.info(
                "imported conditional entry forest abstained: "
                "gate=prefix_candidates rows=%s",
                {
                    _format_block_label(flow_graph, source): len(rows)
                    for source, rows in sorted(candidate_rows.items())
                },
            )
        return None
    candidates = {source: next(iter(rows)) for source, rows in candidate_rows.items()}
    terminal_targets = {
        *handlers,
        *(
            target
            for _source, (
                _proof,
                taken,
                fallthrough,
                taken_is_source,
                fallthrough_is_source,
            ) in candidates.items()
            for target, is_source in (
                (taken, taken_is_source),
                (fallthrough, fallthrough_is_source),
            )
            if not is_source
        ),
    }

    internal_targets: set[int] = set()
    for source, (
        _proof,
        taken,
        fallthrough,
        taken_is_source,
        fallthrough_is_source,
    ) in candidates.items():
        for target, is_source in (
            (taken, taken_is_source),
            (fallthrough, fallthrough_is_source),
        ):
            if is_source:
                if target not in candidates:
                    logger.info(
                        "imported conditional entry forest abstained: "
                        "source=%s target=%s gate=missing_boundary_source",
                        _format_block_label(flow_graph, source),
                        _format_block_label(flow_graph, target),
                    )
                    return None
                internal_targets.add(target)
            elif target not in terminal_targets:
                return None

    roots = tuple(sorted(set(candidates).difference(internal_targets)))
    if not roots:
        if logger.info_on:
            logger.info(
                "imported conditional entry forest abstained: gate=no_roots nodes=%s",
                [
                    _format_block_label(flow_graph, source)
                    for source in sorted(candidates)
                ],
            )
        return None

    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(source: int) -> bool:
        if source in visiting:
            return False
        if source in visited:
            return True
        visiting.add(source)
        (
            _proof,
            taken,
            fallthrough,
            taken_is_source,
            fallthrough_is_source,
        ) = candidates[source]
        for target, is_source in (
            (taken, taken_is_source),
            (fallthrough, fallthrough_is_source),
        ):
            if is_source and not visit(target):
                return False
        visiting.remove(source)
        visited.add(source)
        return True

    if not all(visit(root) for root in roots) or visited != set(candidates):
        if logger.info_on:
            logger.info(
                "imported conditional entry forest abstained: "
                "gate=forest_shape roots=%s visited=%s nodes=%s",
                [_format_block_label(flow_graph, source) for source in roots],
                [_format_block_label(flow_graph, source) for source in sorted(visited)],
                [
                    _format_block_label(flow_graph, source)
                    for source in sorted(candidates)
                ],
            )
        return None
    proofs = tuple(candidates[source][0] for source in sorted(candidates))
    if logger.info_on:
        logger.info(
            "imported conditional entry forest proven: roots=%s nodes=%d predicates=%s",
            [_format_block_label(flow_graph, source) for source in roots],
            len(proofs),
            ["0x%X" % proof.predicate_ea for proof in proofs],
        )
    return ConditionalEntryBridgePlan(
        proofs=proofs,
        root_source_serials=roots,
    )


def _lower_conditional_entry_bridge(
    flow_graph,
    proof: ConditionalEntryBridgeProof,
) -> LowerConditionalStateTransition | None:
    """Retarget both arms of one exact entry predicate to proven handlers."""
    source = flow_graph.get_block(int(proof.source_serial))
    predicate = None if source is None else source.insn_snapshots[-1]
    if (
        source is None
        or source.nsucc != 2
        or predicate is None
        or not predicate.is_conditional_jump
        or int(predicate.ea) != int(proof.predicate_ea)
        or predicate.d is None
        or predicate.d.block_ref is None
    ):
        return None
    return LowerConditionalStateTransition(
        source_serial=int(proof.source_serial),
        old_dispatcher_serial=int(predicate.d.block_ref),
        rewrite_from_ea=int(proof.predicate_ea),
        condition_operand=PreserveLivePredicateCondition(
            predicate_ea=int(proof.predicate_ea),
            true_is_taken=bool(proof.true_is_taken),
        ),
        false_target_serial=int(proof.false_target_serial),
        true_target_serial=int(proof.true_target_serial),
        proof_id=(
            "resolver_proven_conditional_entry_bridge:"
            f"predicate_ea=0x{int(proof.predicate_ea):X}"
        ),
        reason="resolver_proven_conditional_entry_bridge",
    )


def _lower_conditional_entry_bridge_plan(
    flow_graph,
    plan: ConditionalEntryBridgePlan,
) -> tuple[LowerConditionalStateTransition, ...]:
    """Lower every node of an entry forest, or abstain atomically."""
    lowerings: list[LowerConditionalStateTransition] = []
    for proof in plan.proofs:
        lowering = _lower_conditional_entry_bridge(flow_graph, proof)
        if lowering is None:
            return ()
        lowerings.append(lowering)
    return tuple(lowerings)


def _normalize_degenerate_branch_redirects(
    flow_graph,
    modifications: list[object],
) -> list[object]:
    """Replace duplicate-successor branch rewrites with an explicit goto."""
    successors = {
        int(serial): [int(succ) for succ in block.succs]
        for serial, block in flow_graph.blocks.items()
    }
    normalized: list[object] = []
    for modification in modifications:
        if isinstance(modification, ConvertToGoto):
            successors[int(modification.block_serial)] = [int(modification.goto_target)]
            normalized.append(modification)
            continue
        if not isinstance(modification, (RedirectGoto, RedirectBranch)):
            normalized.append(modification)
            continue
        source = int(modification.from_serial)
        old = int(modification.old_target)
        new = int(modification.new_target)
        current = successors.get(source, [])
        if old not in current:
            normalized.append(modification)
            continue
        if isinstance(modification, RedirectBranch) and old != new and new in current:
            replacement = ConvertToGoto(block_serial=source, goto_target=new)
            successors[source] = [new]
            normalized.append(replacement)
            continue
        current[current.index(old)] = new
        normalized.append(modification)
    return normalized


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
    infer_unmatched_returns: bool = True,
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

    Materialized computed-goto dispatchers can have handler arms whose state
    target is not yet proven.  Such an unmatched arm must remain on its original
    edge: treating ``next_state is None`` as a return can redirect a live body
    arm to the function exit and make the body disappear under DCE.  Callers for
    that profile set ``infer_unmatched_returns=False``; the default preserves the
    established stack-state behavior byte-for-byte.

    """
    disp = int(dispatcher_entry_serial) if dispatcher_entry_serial is not None else None
    if disp is None:
        return []
    dispatcher_block = flow_graph.get_block(disp)
    dispatcher_children = (
        {int(successor) for successor in dispatcher_block.succs}
        if dispatcher_block is not None
        else set()
    )
    default_target = dispatcher.default_target
    sources = existing_sources if existing_sources is not None else set()
    carriers = {int(b) for b in (carrier_via_blocks or ())}
    mods: list[object] = []
    candidate_order: list[tuple[str, int, int]] = []
    candidate_new_targets: dict[tuple[str, int, int], set[int]] = {}
    candidate_mods: dict[tuple[str, int, int], object] = {}

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
        edge_key = ("B" if two_way else "G", int(src), int(old))
        new_targets = candidate_new_targets.setdefault(edge_key, set())
        if int(new) in new_targets:
            return
        if not new_targets:
            candidate_order.append(edge_key)
        new_targets.add(int(new))
        if two_way:
            mod = RedirectBranch(
                from_serial=int(src), old_target=int(old), new_target=int(new)
            )
        else:
            mod = RedirectGoto(
                from_serial=int(src), old_target=int(old), new_target=int(new)
            )
        candidate_mods[edge_key] = mod

    for handler in handler_transitions:
        if not handler.is_conditional:
            continue
        write_blocks = {
            int(a.write_block) for a in handler.arms if a.write_block is not None
        }
        shared_write_block = len(write_blocks) == 1
        for arm in handler.arms:
            if not infer_unmatched_returns and arm.next_state is None:
                continue
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
            # A computed-goto BST can enter one of the dispatch root's two
            # range-navigation children after a unique per-arm glue block. The
            # distant scan boundary is then shared and is not a direct root
            # predecessor. Redirect the unique glue edge instead: its semantic
            # writes still execute, while the state-dependent routing spine is
            # bypassed with the arm's proven target.
            arm_successor = _arm_branch_successor(arm)
            if arm.branch_block is not None and arm_successor is not None:
                arm_block = flow_graph.get_block(int(arm_successor))
                if arm_block is not None:
                    arm_succs = tuple(int(successor) for successor in arm_block.succs)
                    arm_preds = tuple(
                        int(predecessor) for predecessor in arm_block.preds
                    )
                    if (
                        len(arm_succs) == 1
                        and arm_succs[0] in dispatcher_children
                        and arm_preds == (int(arm.branch_block),)
                    ):
                        _add(int(arm_successor), arm_succs[0], new)
                        continue
            wb = arm.write_block
            if wb is None:
                continue
            wb_block = flow_graph.get_block(int(wb))
            if wb_block is None or disp not in tuple(int(s) for s in wb_block.succs):
                continue
            _add(int(wb), disp, new)
    for edge_key in candidate_order:
        targets = candidate_new_targets.get(edge_key, set())
        if len(targets) != 1:
            kind, src, old = edge_key
            logger.debug(
                "suppressing conflicting conditional arm redirects: kind=%s src=%s old=%s targets=%s",
                kind,
                src,
                old,
                sorted(targets),
            )
            continue
        mod = candidate_mods.get(edge_key)
        if mod is not None:
            mods.append(mod)
    return mods


def _recover_initial_state(
    flow_graph,
    transitions: tuple[StateWriteTransition, ...],
    dispatcher_entry_serial: int,
    pre_header_serial: int | None,
    *,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
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

    # A materialized comparison tree can place pure routing blocks between the
    # prologue's state write and the recovered dispatcher entry.  Transition
    # recovery intentionally scans dispatcher back-edges, so that earlier entry
    # write may not appear in ``transitions``.  Walk backwards only through the
    # entry-reachable prefix (the dispatcher is a cut) and require every path's
    # first state write to prove the same constant.
    if state_var_stkoff is None and state_var_reg is None:
        return None

    entry_prefix = _entry_prefix_blocks(flow_graph, dispatcher_entry_serial)
    pending = [(serial, frozenset()) for serial in sorted(prologue_preds)]
    constants: set[int] = set()
    while pending:
        serial, path = pending.pop()
        if serial in path:
            return None
        block = flow_graph.get_block(serial)
        if block is None:
            return None
        found_write = False
        for instruction in reversed(block.insn_snapshots):
            if instruction.kind is not InsnKind.MOV:
                continue
            destination = instruction.d
            writes_register = (
                state_var_reg is not None
                and destination.kind is OperandKind.REGISTER
                and destination.reg == int(state_var_reg)
            )
            writes_stack = (
                state_var_stkoff is not None
                and destination.kind is OperandKind.STACK
                and destination.stkoff == int(state_var_stkoff)
            )
            if not writes_register and not writes_stack:
                continue
            found_write = True
            value = _mop_number_value(instruction.l)
            if value is None:
                return None
            constants.add(int(value) & 0xFFFFFFFF)
            if len(constants) != 1:
                return None
            break
        if found_write:
            continue
        predecessors = [
            int(predecessor)
            for predecessor in block.preds
            if int(predecessor) in entry_prefix
        ]
        if not predecessors:
            return None
        next_path = path | {serial}
        pending.extend((predecessor, next_path) for predecessor in predecessors)
    return next(iter(constants)) if len(constants) == 1 else None


def _entry_prefix_blocks(flow_graph, dispatcher_entry_serial: int) -> set[int]:
    """Blocks reachable from function entry without traversing the dispatcher."""
    dispatcher = int(dispatcher_entry_serial)
    seen: set[int] = set()
    pending = [int(flow_graph.entry_serial)]
    while pending:
        serial = pending.pop()
        if serial in seen or serial == dispatcher:
            continue
        seen.add(serial)
        block = flow_graph.get_block(serial)
        if block is not None:
            pending.extend(int(successor) for successor in block.succs)
    return seen


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
    seen = _entry_prefix_blocks(flow_graph, disp)

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
    native_key: NativePreanalysisKey,
    block_serial_for_native_identity: (
        Callable[[StableBlockIdentity], int | None] | None
    ) = None,
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

    if block_serial_for_native_identity is None:
        return []

    disp = int(dispatcher_entry_serial)

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
        guard_ea = int(guard_ea)
        guard_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(guard_ea, guard_ea + 1),),
            native_key=native_key,
        )
        guard_serial = block_serial_for_native_identity(guard_identity)
        if guard_serial is None or guard_serial not in self_loop_guards:
            continue
        guard_serial = int(guard_serial)
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
    native_key: NativePreanalysisKey,
    block_serial_for_native_identity: (
        Callable[[StableBlockIdentity], int | None] | None
    ) = None,
):
    """Compatibility wrapper: recover then lower folded guard transitions."""
    return lower_conditional_transition_candidates(
        build_folded_loop_guard_transitions(
            flow_graph,
            dispatcher,
            transitions,
            fact_view,
            dispatcher_entry_serial=dispatcher_entry_serial,
            native_key=native_key,
            block_serial_for_native_identity=(block_serial_for_native_identity),
        )
    )


def _block_reaches_target(
    flow_graph, start: int, target: int, *, bound: int = 128
) -> bool:
    """Bounded forward reachability: ``True`` if ``target`` is reachable from ``start``."""
    seen: set[int] = set()
    stack = [int(start)]
    steps = 0
    while stack and steps < bound:
        steps += 1
        cur = stack.pop()
        if cur == int(target):
            return True
        if cur in seen:
            continue
        seen.add(cur)
        block = flow_graph.get_block(cur)
        if block is None:
            continue
        for s in block.succs:
            if int(s) not in seen:
                stack.append(int(s))
    return False


def build_loop_guard_exit_redirects(
    flow_graph,
    dispatcher,
    handler_transitions: tuple[HandlerTransition, ...],
    *,
    dispatcher_entry_serial: int,
    infer_unmatched_returns: bool = True,
) -> list[object]:
    """Redirect a loop-guard-exit dispatcher's terminal handler to the exit corridor.

    A ``while(state != K){switch(state){...}}`` flattener has NO dispatcher
    ``default_target``: the loop exit is the guard block's ``state == K`` arm -- a
    corridor OUTSIDE the state machine that reaches the function return.  The
    handler that writes the exit sentinel ``K`` leaves the loop through that
    corridor, but ``K`` spuriously routes back to a handler row (the dispatcher
    still has a ``K -> handler`` interval), so the back-edge model classifies it
    as an ordinary self-transition and never wires the exit.  Once every
    dispatcher back-edge is severed, that corridor is orphaned and the function's
    terminal becomes unreachable -- the mutation backend then correctly REJECTS
    the whole plan (``all reachable terminal routes became unreachable``) and the
    function stays flattened.

    Detect each handler whose recovered arm leaves the loop into a PURE exit
    corridor -- an ``exit_block`` that reaches a function return but can NOT reach
    the dispatcher again -- and redirect that handler's own loop-ward out-edge
    onto the exit block.  The handler body still executes; only its loop-back is
    replaced by the return corridor.

    Fires ONLY when the dispatcher has no ``default_target`` (the loop-guard
    shape); a dispatcher with an explicit default already routes its exit through
    the ``is_return`` back-edge model and is left byte-identical.
    """
    if dispatcher.default_target is not None:
        return []
    disp = int(dispatcher_entry_serial)
    mods: list[object] = []
    seen_edges: set[tuple[int, int]] = set()
    for handler in handler_transitions:
        hb = flow_graph.get_block(int(handler.handler))
        if hb is None:
            continue
        for arm in handler.arms:
            if not infer_unmatched_returns and arm.next_state is None:
                continue
            exit_block = arm.exit_block
            if exit_block is None or int(exit_block) == disp:
                continue
            # A PURE exit corridor: reaches a return but never re-enters the
            # dispatcher.  Handlers that loop back end their scan at a
            # dispatcher-predecessor (which DOES reach the dispatcher) and are
            # excluded here.
            if _block_reaches_target(flow_graph, int(exit_block), disp):
                continue
            if not _routes_to_function_return(flow_graph, int(exit_block), disp=disp):
                continue
            # Redirect the handler entry's loop-ward out-edge (the successor that
            # still reaches the dispatcher, i.e. the shared glue / back-edge tail)
            # onto the exit corridor.
            glue: int | None = None
            for s in (int(x) for x in hb.succs):
                if s == int(exit_block):
                    continue
                if _block_reaches_target(flow_graph, s, disp):
                    glue = s
                    break
            if glue is None:
                continue
            key = (int(handler.handler), int(glue))
            if key in seen_edges:
                continue
            if hb.nsucc == 2:
                # Retargeting a 2-way handler's edge is only expressible when the
                # loop-ward edge IS the conditional JUMP arm (BLOCK_TARGET_CHANGE
                # cannot retarget a fall-through).  Bail otherwise -- leave the
                # function flattened rather than mis-wire the exit.
                if _conditional_jump_target(hb) != int(glue):
                    continue
                seen_edges.add(key)
                mods.append(
                    RedirectBranch(
                        from_serial=int(handler.handler),
                        old_target=int(glue),
                        new_target=int(exit_block),
                    )
                )
            else:
                seen_edges.add(key)
                mods.append(
                    RedirectGoto(
                        from_serial=int(handler.handler),
                        old_target=int(glue),
                        new_target=int(exit_block),
                    )
                )
    return mods


def _conditional_jump_target(block) -> int | None:
    """Return the taken (jump) target serial of a 2-way block's conditional tail.

    ``BLOCK_TARGET_CHANGE`` (``RedirectBranch``) retargets ONLY this arm; the
    block's other successor is the fall-through.  The target is the ``mop_b``
    operand of the tail conditional jump (historically ``insn.d.block_ref``).
    """
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if not insns:
        return None
    tail = insns[-1]
    if not getattr(tail, "is_conditional_jump", False):
        return None
    for mop in (
        getattr(tail, "d", None),
        getattr(tail, "r", None),
        getattr(tail, "l", None),
    ):
        ref = getattr(mop, "block_ref", None) if mop is not None else None
        if ref is not None:
            return int(ref)
    return None


def build_shared_merge_conditional_redirects(
    flow_graph,
    dispatcher,
    handler_transitions: tuple[HandlerTransition, ...],
    *,
    dispatcher_entry_serial: int,
) -> tuple[list[object], set[int]]:
    """Correctly materialize an OLLVM ``state = cond ? A : B`` conditional handler.

    The flattener lowers ``state = cond ? A : B`` as::

        branch:  <work>; reg = <state B>;  jcc(cond) @merge
        interm:  reg = <state A>                       (falls through into merge)
        merge:   state = reg; goto <loop-back>

    so both arms converge on ONE shared ``merge`` block that the recovery folds to
    a distinct next-state per incoming path.  The generic passes mishandle this:
    the back-edge model emits BOTH (conflicting) ``merge -> route`` redirects, and
    :func:`build_conditional_arm_redirects` retargets the branch's FALL-THROUGH
    arm -- which ``BLOCK_TARGET_CHANGE`` cannot express (it retargets only the
    conditional JUMP arm).  The conditional is dropped and Hex-Rays folds the
    function down to the fall-through arm alone (the ``3*(a1-5)/2`` miscompile).

    Materialize it correctly: retarget the branch's real JUMP arm with a valid
    ``BLOCK_TARGET_CHANGE`` and redirect the fall-through arm's block with a goto.
    Reads the branch's actual jump target so the arm polarity is never assumed.

    Returns ``(redirects, suppressed_sources)``.  The caller must drop every
    existing redirect whose ``from_serial`` is in ``suppressed_sources`` (the
    wrong arm redirect on the branch + both conflicting merge redirects) BEFORE
    appending ``redirects``.  Detection is strictly shape-gated; a handler that
    does not match this exact OLLVM select shape contributes nothing.
    """
    default_target = dispatcher.default_target
    redirects: list[object] = []
    suppressed: set[int] = set()

    def _route(arm) -> int | None:
        if arm.is_return:
            return default_target
        return arm.target_handler

    for handler in handler_transitions:
        if not handler.is_conditional or len(handler.arms) != 2:
            continue
        branch = handler.arms[0].branch_block
        if branch is None or any(a.branch_block != branch for a in handler.arms):
            continue
        succ0 = _arm_branch_successor(handler.arms[0])
        succ1 = _arm_branch_successor(handler.arms[1])
        if succ0 is None or succ1 is None or int(succ0) == int(succ1):
            continue
        path0 = handler.arms[0].ordered_path
        path1 = handler.arms[1].ordered_path
        # Shared merge M = the branch-successor lying on BOTH arm paths (the direct
        # arm's first hop, revisited by the indirect arm); intermediate I = the
        # other branch-successor, a 1-way alt-state assignment feeding M.
        if succ0 in path1 and succ1 not in path0:
            merge, direct_arm, inter, indirect_arm = (
                int(succ0),
                handler.arms[0],
                int(succ1),
                handler.arms[1],
            )
        elif succ1 in path0 and succ0 not in path1:
            merge, direct_arm, inter, indirect_arm = (
                int(succ1),
                handler.arms[1],
                int(succ0),
                handler.arms[0],
            )
        else:
            continue
        branch_block = flow_graph.get_block(int(branch))
        inter_block = flow_graph.get_block(int(inter))
        merge_block = flow_graph.get_block(int(merge))
        if branch_block is None or inter_block is None or merge_block is None:
            continue
        if branch_block.nsucc != 2:
            continue
        # I must be a 1-way block whose sole successor is M (the alt-state write).
        if tuple(int(s) for s in inter_block.succs) != (int(merge),):
            continue
        direct_route = _route(direct_arm)
        indirect_route = _route(indirect_arm)
        if direct_route is None or indirect_route is None:
            continue
        # Read the branch's real jump target; only one of {M, I} may be it.
        jump_target = _conditional_jump_target(branch_block)
        if jump_target is None or jump_target not in (int(merge), int(inter)):
            continue
        if jump_target == int(merge):
            # M is the jump arm (OLLVM standard: `jcc @merge`); I is fall-through.
            #   B --jump--> M            ==> B --jump--> route(direct)
            #   B --fall--> I --> M      ==> I --> route(indirect)   (M orphaned)
            redirects.append(
                RedirectBranch(
                    from_serial=int(branch),
                    old_target=int(merge),
                    new_target=int(direct_route),
                )
            )
            redirects.append(
                RedirectGoto(
                    from_serial=int(inter),
                    old_target=int(merge),
                    new_target=int(indirect_route),
                )
            )
        else:
            # I is the jump arm; M is the fall-through.
            #   B --jump--> I --> M      ==> B --jump--> route(indirect)  (I orphaned)
            #   B --fall--> M            ==> M --> route(direct)
            merge_succs = tuple(int(s) for s in merge_block.succs)
            if len(merge_succs) != 1:
                continue
            redirects.append(
                RedirectBranch(
                    from_serial=int(branch),
                    old_target=int(inter),
                    new_target=int(indirect_route),
                )
            )
            redirects.append(
                RedirectGoto(
                    from_serial=int(merge),
                    old_target=int(merge_succs[0]),
                    new_target=int(direct_route),
                )
            )
        suppressed.add(int(branch))
        suppressed.add(int(merge))
    return redirects, suppressed


def build_resolver_proven_indirect_call_neutralizations(
    flow_graph,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    modifications: tuple[object, ...],
    *,
    handler_serials: frozenset[int],
) -> list[NopInstructions]:
    """NOP stale call lifts only when one planned handler edge replaces them."""
    redirected_targets: dict[int, set[int]] = {}
    for modification in modifications:
        if not isinstance(modification, RedirectGoto):
            continue
        redirected_targets.setdefault(int(modification.from_serial), set()).add(
            int(modification.new_target)
        )
    plans = plan_resolver_proven_indirect_call_neutralizations(
        transfers,
        flow_graph,
        redirected_targets_by_source={
            source: tuple(sorted(targets))
            for source, targets in redirected_targets.items()
        },
        allowed_target_serials=handler_serials,
    )
    return [
        NopInstructions(
            block_serial=int(plan.source_block_serial),
            insn_eas=(int(plan.source_jmp_ea),),
        )
        for plan in plans
    ]


def _must_reject_fragment_for_use_def_audit(
    use_def_audit: object,
    *,
    legacy_bail: bool = False,
) -> bool:
    """Whether a confirmed non-state severance vetoes the whole fragment.

    Coverage reporting may describe a full or partial dispatcher retirement, but
    it never weakens this hard use-def safety boundary.  ``legacy_bail`` is the
    S1A emitter-only compatibility policy; the global redirect-filter caller
    does not pass it.
    """
    return bool(
        getattr(use_def_audit, "executed", False)
        and int(getattr(use_def_audit, "severance_count", 0)) > 0
        and (
            getattr(use_def_audit, "enforced", False)
            or bool(legacy_bail)
        )
    )


def emit_minimal_unflatten(
    flow_graph,
    dispatcher,
    *,
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef],
    snapshot_id: str | None = None,
    source_generation: int | None = None,
    source_maturity: MaturityEnvelope | None = None,
    state_var_stkoff: int | None,
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
    entry_bridge_exit_path_blocks: tuple[int, ...] = (),
    entry_bridge_requires_witness: bool = False,
    exit_path_effect_recovery: bool = False,
    recover_multi_entry_back_edges: bool = False,
    state_var_reg: int | None = None,
    materialized_indirect_transfers: tuple[MaterializedIndirectTransfer, ...] = (),
    imported_direct_boundary_evidence: tuple[
        AppliedDetachedSnippetDirectBoundaryPort, ...
    ] = (),
    imported_conditional_boundary_evidence: tuple[
        AppliedDetachedSnippetConditionalBoundaryPort, ...
    ] = (),
    imported_native_eas_by_serial: Mapping[int, frozenset[int]] | None = None,
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    legacy_handler_by_state: Mapping[int, int] | None = None,
    materialized_handler_by_state: Mapping[int, int] | None = None,
    handler_entry_eas_by_serial: Mapping[int, int] | None = None,
    state_carrier_vd_stkoffs_by_store_ea: Mapping[int, int] | None = None,
    native_carrier_consumer_serials_by_load_ea: Mapping[int, int] | None = None,
    materialized_computed_goto_profile: bool = False,
    condition_chain_dag: DecisionDag | None = None,
    condition_chain_handlers: frozenset[int] = frozenset(),
    authoritative_handler_serials: frozenset[int] = frozenset(),
    missing_materialized_handler_targets: tuple[tuple[int, int], ...] = (),
    dispatcher_region_serials: frozenset[int] = frozenset(),
    entry_bridge_evidence: EntryBridgeEvidence | None = None,
    bound_bootstrap_routes: tuple[BootstrapRouteBindingEvidence, ...] = (),
    block_serial_for_native_identity: (
        Callable[[StableBlockIdentity], int | None] | None
    ) = None,
    native_key: NativePreanalysisKey | None = None,
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
    whole-fragment use-def audit.  Evidence for a redirect that would orphan a
    NON-state-variable use is retained in plan metadata; when
    ``D810_USE_DEF_VETO=1`` the complete fragment is rejected atomically.  The
    legacy ``D810_S1A_SEVERANCE_BAIL=1`` applies the same whole-fragment
    rejection only to this S1A emitter.  The state variable itself is
    intentionally severed (that is the unflattening) and never counted as a
    non-state violation.
    """

    # These facts are intentionally false until the *final* whole-fragment
    # audit has run.  A plan can still be a normal partial unflatten, but it
    # cannot obtain the narrow dispatcher-retirement allowance from an absent
    # capability, an environment toggle, or a per-redirect filtering pass.
    dispatcher_removal_safety: dict[str, bool] = {
        "fragment_atomic": False,
        "non_state_use_def_veto": False,
        "non_state_use_def_checked": False,
        "non_state_use_def_severances_zero": False,
    }
    dispatcher_state_plumbing_serials: frozenset[int] = frozenset()

    def compile_modifications(modifications) -> PatchPlan:
        return compile_patch_plan(
            modifications,
            flow_graph,
            snapshot_id=snapshot_id,
            source_generation=source_generation,
            source_maturity=source_maturity,
            block_refs_by_serial=block_refs_by_serial,
        )

    def attach_dispatcher_removal_preflight_proof(
        plan: PatchPlan,
        coverage,
    ) -> PatchPlan:
        """Attach a fail-closed exact proof for intended router removal.

        This does not relax any producer safety gate.  It merely gives the
        transaction preflight enough typed topology evidence to distinguish a
        removed comparison forest from a lost handler/body island.
        """
        if dispatcher_entry_serial is None:
            return plan
        projected = project_patch_plan(
            flow_graph,
            plan,
            snapshot_id=plan.snapshot_id,
        )
        authoritative_handlers = (
            frozenset(int(serial) for serial in authoritative_handler_serials)
            if authoritative_handler_serials
            else frozenset(
                int(row.target)
                for row in getattr(dispatcher, "_rows", ())
                if getattr(row, "target", None) is not None
                and int(row.target) != int(dispatcher_entry_serial)
            )
        )
        proof = build_dispatcher_removal_preflight_proof(
            flow_graph,
            post_graph=projected.graph,
            coverage=coverage,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            authoritative_handler_serials=authoritative_handlers,
            dispatcher_region_serials=frozenset(
                int(serial) for serial in dispatcher_region_serials
            ),
            producer_safety=dispatcher_removal_safety,
            state_plumbing_serials=dispatcher_state_plumbing_serials,
        )
        if logger.info_on:
            logger.info(
                "unflat dispatcher removal preflight proof: status=%s reason=%s "
                "handlers=%d/%d terminals=%d/%d lost=%s",
                "accepted" if proof.passed else "rejected",
                proof.reason,
                len(proof.post_reachable_handlers),
                len(proof.authoritative_handlers),
                len(proof.post_reachable_terminals),
                len(proof.pre_reachable_terminals),
                ",".join(anchor.label for anchor in proof.lost_block_anchors)
                or "none",
            )
        return plan.with_metadata(
            **{DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata()}
        )

    def log_dispatcher_coverage(coverage) -> None:
        if not logger.info_on:
            return
        residual_labels = ", ".join(
            corridor.label for corridor in coverage.residual_corridors[:16]
        )
        logger.info(
            "unflat dispatcher corridor coverage: status=%s planned_status=%s "
            "covered=%d residual=%d "
            "enumeration_complete=%s full_unflattening_claim=%s residual_paths=%s",
            coverage.completion_status,
            coverage.planned_completion_status,
            len(coverage.covered_corridors),
            len(coverage.residual_corridors),
            coverage.enumeration_complete,
            coverage.full_unflattening_claim,
            residual_labels or "none",
        )

    def compile_with_dispatcher_coverage(modifications) -> PatchPlan:
        coverage = analyze_dispatcher_corridor_coverage(
            flow_graph,
            modifications=tuple(modifications),
            dispatcher_entry_serial=dispatcher_entry_serial,
        )
        plan = compile_modifications(modifications)
        plan = plan.with_metadata(
            **{
                DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
                UNFLATTEN_COMPLETION_STATUS_METADATA: coverage.completion_status,
                FULL_UNFLATTENING_CLAIM_METADATA: coverage.full_unflattening_claim,
            }
        )
        plan = attach_dispatcher_removal_preflight_proof(plan, coverage)
        log_dispatcher_coverage(coverage)
        return plan

    if dispatcher_entry_serial is None:
        return compile_with_dispatcher_coverage(())
    if materialized_computed_goto_profile and missing_materialized_handler_targets:
        if logger.info_on:
            logger.info(
                "unflat materialized handler-map gate: rejected entire fragment "
                "missing=%s",
                ",".join(
                    "state=0x%08X@0x%X" % (state, target_ea)
                    for state, target_ea in missing_materialized_handler_targets
                ),
            )
        return compile_with_dispatcher_coverage(())
    # A register-resident state variable (``state_var_reg`` set and
    # ``state_var_stkoff`` None) carries no stack
    # offset. ``_soff`` is the None-safe int form threaded into the stkoff-keyed
    # refinement helpers below; the core transition recovery reads the register
    # cell via ``state_var_reg`` (the partitioned fixpoint already tracks it in
    # ``out_reg_maps``). ``state_var_reg is None`` -> ``_soff == int(stkoff)`` and
    # every path is byte-identical to the stack behaviour.
    _soff = int(state_var_stkoff) if state_var_stkoff is not None else None
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
        state_var_stkoff,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        recover_terminal_tail=is_indirect,
        initial_state=initial_state,
        emu=emu,
        live_block_for=live_block_for,
        include_multi_entry_back_edges=(
            recover_multi_entry_back_edges or materialized_computed_goto_profile
        ),
        state_var_reg=state_var_reg,
        dispatcher_region_serials=(
            dispatcher_region_serials
            if materialized_computed_goto_profile
            and (
                state_var_reg is not None
                or imported_direct_boundary_evidence
                or imported_conditional_boundary_evidence
            )
            else frozenset()
        ),
    )
    dispatcher_state_plumbing_serials = frozenset(
        int(transition.write_block)
        for transition in transitions
        if getattr(transition, "proof", None) is not None
        and bool(getattr(transition.proof, "trusted", False))
    )
    if materialized_computed_goto_profile:
        materialized_state_routes = _rebind_materialized_state_route_sources(
            flow_graph,
            materialized_state_routes,
            legacy_handler_by_state=legacy_handler_by_state,
            materialized_handler_by_state=materialized_handler_by_state,
            imported_native_eas_by_serial=imported_native_eas_by_serial,
        )
    bootstrap_entry_routes = _prove_bound_bootstrap_entry_routes(
        flow_graph,
        bound_bootstrap_routes,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    route_handler_serials = frozenset(
        {
            *(int(serial) for serial in condition_chain_handlers),
            *(int(proof.handler_serial) for proof in bootstrap_entry_routes),
        }
    )
    if materialized_computed_goto_profile:
        route_handler_serials = frozenset(
            {
                *(int(serial) for serial in route_handler_serials),
                *(int(serial) for serial in authoritative_handler_serials),
                *(
                    int(route.target_handler_serial)
                    for route in materialized_state_routes
                ),
            }
        )
    materialized_entry_route_mods = (
        build_materialized_state_entry_bridges(
            flow_graph,
            materialized_state_routes,
            dispatcher_region_serials=frozenset(
                {
                    int(dispatcher_entry_serial),
                    *(int(serial) for serial in dispatcher_region_serials),
                }
            ),
            authoritative_handler_serials=route_handler_serials,
        )
        if materialized_computed_goto_profile
        else []
    )
    materialized_state_route_mods = (
        build_materialized_state_route_redirects(
            flow_graph,
            materialized_state_routes,
            state_var_reg=state_var_reg,
            dispatcher_region_serials=dispatcher_region_serials,
            authoritative_handler_serials=route_handler_serials,
            handler_entry_eas_by_serial=handler_entry_eas_by_serial,
        )
        if materialized_computed_goto_profile
        else []
    )
    # Resolver-target evidence is an opt-in, fail-closed refinement for the
    # false-terminal default route of a materialized computed goto. Exact
    # dispatcher rows remain authoritative; the helper returns every unrelated
    # transition byte-identically.
    transitions = resolve_materialized_indirect_transfer_targets(
        transitions,
        flow_graph,
        dispatcher,
        materialized_indirect_transfers,
        materialized_state_routes=materialized_state_routes,
        condition_chain_dag=condition_chain_dag,
        condition_chain_handlers=route_handler_serials,
        state_var_reg=state_var_reg,
    )
    conditional_boundary_edges = _applied_conditional_boundary_edge_keys(
        flow_graph,
        imported_conditional_boundary_evidence,
    )
    direct_boundary_edges = _applied_direct_boundary_edge_keys(
        flow_graph,
        imported_direct_boundary_evidence,
    )
    dynamic_entry_bridge_edges = _resolver_proven_dynamic_entry_edges(
        flow_graph,
        imported_direct_boundary_evidence,
        materialized_indirect_transfers,
        imported_native_eas_by_serial=imported_native_eas_by_serial,
    )
    if dynamic_entry_bridge_edges:
        # The live resolver port already enters a router that reloads the
        # dynamic state. A scalar source-keyed bridge would bypass that reload.
        materialized_entry_route_mods = []
        materialized_state_route_mods = [
            modification
            for modification in materialized_state_route_mods
            if not (
                isinstance(modification, (RedirectGoto, RedirectBranch))
                and (
                    int(modification.from_serial),
                    int(modification.old_target),
                )
                in dynamic_entry_bridge_edges
            )
        ]
    conditional_bridge_mods = build_materialized_conditional_handler_bridges(
        flow_graph,
        materialized_indirect_transfers,
        dispatcher=dispatcher,
        materialized_state_routes=materialized_state_routes,
        handler_entry_eas_by_serial=handler_entry_eas_by_serial,
        imported_native_eas_by_serial=imported_native_eas_by_serial,
        applied_conditional_boundary_evidence=(imported_conditional_boundary_evidence),
    )
    native_stack_carrier_choice_count = len(
        {
            (
                int(transfer.state_carrier_store_ea),
                tuple(int(ea) for ea in transfer.state_carrier_consumer_load_eas),
            )
            for transfer in materialized_indirect_transfers
            if transfer.resolver_kind == "static_stack_carried_state_choice"
            and transfer.state_carrier_store_ea is not None
            and transfer.state_carrier_consumer_load_eas
        }
    )
    native_stack_carrier_lowerings: list[object] = []
    if materialized_computed_goto_profile and state_var_reg is not None:
        native_stack_carrier_lowerings = build_stack_carried_state_selector_lowerings(
            flow_graph,
            dispatcher,
            state_var_reg=int(state_var_reg),
            dispatcher_region_serials=dispatcher_region_serials,
            handler_serials=route_handler_serials,
            materialized_state_routes=materialized_state_routes,
            materialized_indirect_transfers=materialized_indirect_transfers,
            imported_direct_boundary_evidence=(imported_direct_boundary_evidence),
            imported_conditional_boundary_evidence=(
                imported_conditional_boundary_evidence
            ),
            imported_native_eas_by_serial=imported_native_eas_by_serial,
            handler_entry_eas_by_serial=handler_entry_eas_by_serial,
            state_carrier_vd_stkoffs_by_store_ea=(state_carrier_vd_stkoffs_by_store_ea),
            native_carrier_consumer_serials_by_load_ea=(
                native_carrier_consumer_serials_by_load_ea
            ),
        )
        conditional_bridge_mods.extend(native_stack_carrier_lowerings)
    native_stack_carrier_lowering_count = sum(
        1
        for lowering in native_stack_carrier_lowerings
        if isinstance(lowering, LowerConditionalStateTransition)
        and lowering.reason == "resolver_proven_native_stack_carried_state_selector"
    )
    native_stack_carrier_closure = bool(native_stack_carrier_choice_count) and (
        native_stack_carrier_lowering_count == native_stack_carrier_choice_count
    )
    protected_boundary_edges = frozenset(
        {*conditional_boundary_edges, *dynamic_entry_bridge_edges}
    )
    if protected_boundary_edges:
        if logger.info_on:
            for modification in conditional_bridge_mods:
                if (
                    isinstance(modification, LowerConditionalStateTransition)
                    and (
                        int(modification.source_serial),
                        int(modification.old_dispatcher_serial),
                    )
                    in protected_boundary_edges
                ):
                    logger.info(
                        "conditional bridge suppressed: source=%s old=%s "
                        "gate=protected_boundary_edge reason=%s",
                        _format_block_label(
                            flow_graph,
                            int(modification.source_serial),
                        ),
                        _format_block_label(
                            flow_graph,
                            int(modification.old_dispatcher_serial),
                        ),
                        modification.reason,
                    )
        conditional_bridge_mods = [
            mod
            for mod in conditional_bridge_mods
            if not (
                isinstance(mod, (RedirectGoto, RedirectBranch))
                and (int(mod.from_serial), int(mod.old_target))
                in protected_boundary_edges
            )
            and not (
                isinstance(mod, LowerConditionalStateTransition)
                and (int(mod.source_serial), int(mod.old_dispatcher_serial))
                in protected_boundary_edges
            )
        ]
    materialized_conditional_entry_bridge = (
        _prove_materialized_conditional_entry_bridge(
            flow_graph,
            tuple(conditional_bridge_mods),
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            handler_serials=route_handler_serials,
        )
    )
    imported_conditional_entry_bridge = (
        None
        if native_stack_carrier_closure
        else _plan_imported_conditional_entry_bridges(
            flow_graph,
            imported_conditional_boundary_evidence,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            handler_serials=route_handler_serials,
            state_var_reg=state_var_reg,
            imported_native_eas_by_serial=imported_native_eas_by_serial,
            handler_entry_eas_by_serial=handler_entry_eas_by_serial,
            materialized_state_routes=materialized_state_routes,
            dispatcher=dispatcher,
        )
    )
    if native_stack_carrier_closure and logger.info_on:
        logger.info(
            "imported conditional entry forest superseded: native_stack_carriers=%d",
            native_stack_carrier_choice_count,
        )
    if imported_conditional_entry_bridge is not None:
        conditional_entry_bridge = (
            imported_conditional_entry_bridge
            if materialized_conditional_entry_bridge is None
            or materialized_conditional_entry_bridge
            in imported_conditional_entry_bridge.proofs
            else None
        )
        if conditional_entry_bridge is None and logger.info_on:
            logger.info(
                "conditional entry bridge abstained: gate=evidence_conflict "
                "materialized=%s imported=%s",
                materialized_conditional_entry_bridge,
                imported_conditional_entry_bridge,
            )
    elif materialized_conditional_entry_bridge is not None:
        conditional_entry_bridge = ConditionalEntryBridgePlan(
            proofs=(materialized_conditional_entry_bridge,),
            root_source_serials=(materialized_conditional_entry_bridge.source_serial,),
        )
    else:
        conditional_entry_bridge = None
    if conditional_entry_bridge is not None:
        # A resolver-proven two-arm entry predicate is stronger than a direct
        # bootstrap edge recovered from one of its arms.  Retarget the live
        # predicate atomically and stop treating that one arm as the complete
        # entry bridge.
        entry_lowerings = _lower_conditional_entry_bridge_plan(
            flow_graph,
            conditional_entry_bridge,
        )
        if len(entry_lowerings) == len(conditional_entry_bridge.proofs):
            dynamic_entry_bridge_edges = frozenset()
            entry_sources = {
                int(proof.source_serial) for proof in conditional_entry_bridge.proofs
            }
            if logger.info_on:
                for modification in conditional_bridge_mods:
                    if (
                        isinstance(
                            modification,
                            LowerConditionalStateTransition,
                        )
                        and int(modification.source_serial) in entry_sources
                    ):
                        logger.info(
                            "conditional bridge replaced: source=%s "
                            "gate=conditional_entry_forest reason=%s",
                            _format_block_label(
                                flow_graph,
                                int(modification.source_serial),
                            ),
                            modification.reason,
                        )
            conditional_bridge_mods = [
                modification
                for modification in conditional_bridge_mods
                if not (
                    isinstance(modification, LowerConditionalStateTransition)
                    and int(modification.source_serial) in entry_sources
                )
            ]
            conditional_bridge_mods.extend(entry_lowerings)
        else:
            conditional_entry_bridge = None
    terminal_carrier_convergence = transitions_use_terminal_stack_alias_guard(
        transitions
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
        unresolved_rows = []
        for transition in transitions:
            if (
                transition.next_state is not None
                and transition.target_handler is not None
            ):
                continue
            source = _format_block_label(flow_graph, int(transition.write_block))
            via = (
                "none"
                if transition.via_block is None
                else _format_block_label(flow_graph, int(transition.via_block))
            )
            proof = (
                "unattributed"
                if transition.proof is None
                else f"{transition.proof.oracle_kind}:{transition.proof.kind}"
            )
            unresolved_rows.append(
                f"{source}(via={via},arm={transition.branch_arm},proof={proof})"
            )
        if unresolved_rows:
            logger.info(
                "unflat unresolved transition rows: %s",
                ", ".join(unresolved_rows),
            )
    # Recover the initial state from the prologue's own state-write fold when the
    # caller could not supply it. The comparison-range evidence collapses to a
    # single catch-all on a wide equality chain, so
    # ``range_evidence.initial_state`` is None -- but the prologue is a dispatcher
    # predecessor too, so its folded next-state (already in ``transitions``) IS
    # the initial state. Without it the entry bridge is skipped and removing the
    # dispatcher orphans every handler.
    recovered_initial_state = (
        None
        if dynamic_entry_bridge_edges
        else _recover_initial_state(
            flow_graph,
            transitions,
            int(dispatcher_entry_serial),
            pre_header_serial,
            state_var_stkoff=_soff,
            state_var_reg=state_var_reg,
        )
    )
    if dynamic_entry_bridge_edges:
        initial_state = None
    if recovered_initial_state is not None:
        # Entry-only reaching definitions outrank a range-walk hint.  The latter
        # can name an arbitrary mid-chain state when the dispatcher is a wide
        # comparison tree, while the former is cut at the dispatcher and proves
        # the state actually carried by the first dispatch.
        initial_state = recovered_initial_state
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
            bridged = bool(dynamic_entry_bridge_edges) or (
                initial_state is not None
                and (
                    _unique_materialized_state_target(
                        materialized_state_routes,
                        int(initial_state),
                        route_handler_serials,
                    )
                    is not None
                    or dispatcher.lookup(int(initial_state) & 0xFFFFFFFF) is not None
                )
            )
            if dynamic_entry_bridge_edges and logger.info_on:
                logger.info(
                    "unflat entry bridge: EXACT_DYNAMIC_ROUTER edges=%s",
                    ",".join(
                        "%s->%s"
                        % (
                            _format_block_label(flow_graph, source),
                            _format_block_label(flow_graph, target),
                        )
                        for source, target in sorted(dynamic_entry_bridge_edges)
                    ),
                )
            if not bridged and conditional_entry_bridge is not None:
                bridged = True
                if logger.info_on:
                    proofs_by_source = {
                        int(proof.source_serial): proof
                        for proof in conditional_entry_bridge.proofs
                    }
                    logger.info(
                        "unflat entry bridge: EXACT_CONDITIONAL_FOREST "
                        "roots=%s nodes=%d predicates=%s",
                        ",".join(
                            _format_block_label(flow_graph, source)
                            for source in conditional_entry_bridge.root_source_serials
                        ),
                        len(conditional_entry_bridge.proofs),
                        ",".join(
                            "0x%X" % proofs_by_source[source].predicate_ea
                            for source in conditional_entry_bridge.root_source_serials
                        ),
                    )
            if not bridged and materialized_entry_route_mods:
                bridged = True
                if logger.info_on:
                    logger.info(
                        "unflat entry bridge: EXACT_STATE_ROUTE edges=%s",
                        ",".join(
                            "%s->%s"
                            % (
                                _format_block_label(flow_graph, mod.from_serial),
                                _format_block_label(flow_graph, mod.new_target),
                            )
                            for mod in materialized_entry_route_mods
                        ),
                    )
            if not bridged and bootstrap_entry_routes:
                bridged = True
                if logger.info_on:
                    logger.info(
                        "unflat entry bridge: EXACT_BOOTSTRAP routes=%s",
                        [
                            (
                                _format_block_label(flow_graph, proof.source_serial),
                                "0x%X" % int(proof.state),
                                _format_block_label(flow_graph, proof.handler_serial),
                            )
                            for proof in bootstrap_entry_routes
                        ],
                    )
            # d81-3rja step 1: a register-conditional prologue (the initial state is
            # carried in a scratch register while the state var holds a decoy) is
            # bridged by the register-conditional pass in build_state_write_redirects,
            # so the scalar ``initial_state`` may legitimately be absent -- do not bail.
            if not bridged and state_var_reg is not None:
                bridged = bool(
                    _recover_register_conditional_entry(
                        flow_graph,
                        dispatcher,
                        int(dispatcher_entry_serial),
                        state_var_reg=int(state_var_reg),
                        materialized_indirect_transfers=materialized_indirect_transfers,
                        materialized_state_routes=materialized_state_routes,
                        materialized_handler_by_state=materialized_handler_by_state,
                        condition_chain_handlers=route_handler_serials,
                        entry_bridge_evidence=entry_bridge_evidence,
                    )
                )
            if not bridged:
                if logger.info_on:
                    logger.info(
                        "unflat minimal unflatten: BAILED (no entry bridge: "
                        "initial_state=%s) -- leaving function intact",
                        initial_state,
                    )
                return compile_with_dispatcher_coverage(())
    mods = build_state_write_redirects(
        flow_graph,
        dispatcher,
        transitions,
        dispatcher_entry_serial=dispatcher_entry_serial,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        state_var_stkoff=_soff,
        state_var_reg=state_var_reg,
        branch_witness_map=branch_witness_map,
        branch_witness_emu=branch_witness_emu,
        entry_bridge_exit_path_blocks=entry_bridge_exit_path_blocks,
        entry_bridge_requires_witness=entry_bridge_requires_witness,
        strict_pre_header_prologue=recover_multi_entry_back_edges,
        allow_multi_entry_entry_bridge=recover_multi_entry_back_edges,
        entry_bridge_cut_exit_path_uses=(
            materialized_computed_goto_profile and state_var_reg is not None
        ),
        materialized_indirect_transfers=materialized_indirect_transfers,
        materialized_state_routes=materialized_state_routes,
        materialized_handler_by_state=materialized_handler_by_state,
        condition_chain_handlers=route_handler_serials,
        infer_unmatched_returns=not materialized_computed_goto_profile,
        entry_bridge_evidence=entry_bridge_evidence,
        conditional_entry_bridge=conditional_entry_bridge,
        exact_entry_bridge_present=bool(
            bootstrap_entry_routes or materialized_entry_route_mods
        ),
        protected_edges=frozenset(
            {
                *conditional_boundary_edges,
                *direct_boundary_edges,
                *dynamic_entry_bridge_edges,
            }
        ),
        dynamic_entry_bridge_edges=dynamic_entry_bridge_edges,
    )
    if materialized_entry_route_mods:
        existing_entry_redirects = {
            (
                int(mod.from_serial),
                int(mod.old_target),
                int(mod.new_target),
            )
            for mod in mods
            if isinstance(mod, (RedirectGoto, RedirectBranch))
        }
        mods = list(mods) + [
            mod
            for mod in materialized_entry_route_mods
            if (
                int(mod.from_serial),
                int(mod.old_target),
                int(mod.new_target),
            )
            not in existing_entry_redirects
        ]
    # Conditional/multi-arm transitions (ticket llr-aga1): the back-edge model
    # above emits one redirect per dispatcher predecessor and collapses a
    # 2-way-branching handler onto a single next-state, fragmenting the recovered
    # graph into disconnected cycles (the ``5/44`` reachability symptom). The
    # per-handler multi-arm model (recover_handler_transitions) recovers BOTH
    # arms; emit the missing arm redirects additively, vetoed on any source edge
    # the back-edge model already resolved so the unconditional case stays
    # byte-identical.
    # The multi-arm scanner reads either state storage form. The loop-carrier
    # refinements remain stack-only because they specifically inspect stack alias
    # plumbing, but a register-resident handler can still select distinct next
    # states on its two branch arms.
    if _soff is not None:
        handler_transitions = recover_handler_transitions(
            flow_graph,
            dispatcher,
            _soff,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            dispatcher_region_serials=dispatcher_region_serials,
            authoritative_handler_serials=route_handler_serials,
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
            state_var_stkoff=_soff,
        )
    else:
        handler_transitions = recover_handler_transitions(
            flow_graph,
            dispatcher,
            None,
            state_var_reg=state_var_reg,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            dispatcher_region_serials=dispatcher_region_serials,
            authoritative_handler_serials=route_handler_serials,
        )
        latch_redirects, latch_suppressed = [], set()
    handler_transitions = resolve_materialized_handler_transition_targets(
        handler_transitions,
        materialized_state_routes,
        route_handler_serials,
        dispatcher_block_serials=dispatcher_region_serials,
    )
    handler_transitions = resolve_materialized_handler_exit_states(
        handler_transitions,
        materialized_state_routes,
        route_handler_serials,
    )
    terminal_state_writer_sources = _exact_terminal_state_writer_sources(
        flow_graph,
        materialized_state_routes,
        state_var_reg=state_var_reg,
    )
    terminal_state_route_mods = build_exact_terminal_state_route_redirects(
        flow_graph,
        materialized_state_routes,
        state_var_reg=state_var_reg,
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
    exact_live_state_edges = _exact_live_state_edge_keys(
        flow_graph,
        materialized_state_routes,
    )
    exact_live_state_edges.update(conditional_boundary_edges)
    exact_live_state_edges.update(dynamic_entry_bridge_edges)
    exact_live_state_edges.update(
        _applied_direct_boundary_edge_keys(
            flow_graph,
            imported_direct_boundary_evidence,
        )
    )
    source_keyed_mods = build_source_keyed_handler_redirects(
        flow_graph,
        handler_transitions,
        protected_edges=frozenset(
            {
                *exact_live_state_edges,
                *_existing_redirect_keys(materialized_state_route_mods),
            }
        ),
    )
    source_keyed_edges = _existing_redirect_keys(source_keyed_mods)
    source_keyed_edges.update(_existing_redirect_keys(terminal_state_route_mods))
    source_keyed_edges.update(exact_live_state_edges)
    if source_keyed_edges:
        mods = [
            mod
            for mod in mods
            if not (
                isinstance(mod, (RedirectGoto, RedirectBranch))
                and (int(mod.from_serial), int(mod.old_target)) in source_keyed_edges
            )
        ]
    if source_keyed_mods:
        mods = list(mods) + source_keyed_mods
        # Source-keyed evidence may resolve both arms of an imported handler
        # fork after the coarse back-edge pass already planned a parent
        # redirect.  Re-run the existing fork-preservation gate now that the
        # stronger arm routes are present so the parent cannot bypass them.
        mods = _preserve_fully_resolved_state_forks(
            flow_graph,
            list(mods),
            handler_entries=set(route_handler_serials),
            excluded_fork_serials={int(dispatcher_entry_serial)},
        )
    if terminal_state_route_mods:
        existing_terminal_redirects = {
            (
                int(mod.from_serial),
                int(mod.old_target),
                int(mod.new_target),
            )
            for mod in mods
            if isinstance(mod, (RedirectGoto, RedirectBranch))
        }
        mods = list(mods) + [
            mod
            for mod in terminal_state_route_mods
            if (
                int(mod.from_serial),
                int(mod.old_target),
                int(mod.new_target),
            )
            not in existing_terminal_redirects
        ]
    if materialized_state_route_mods:
        exact_route_edges = _existing_redirect_keys(materialized_state_route_mods)
        mods = [
            mod
            for mod in mods
            if not (
                isinstance(mod, (RedirectGoto, RedirectBranch))
                and (int(mod.from_serial), int(mod.old_target)) in exact_route_edges
            )
        ]
        mods = list(mods) + materialized_state_route_mods
    if terminal_state_writer_sources:
        if logger.info_on:
            for modification in conditional_bridge_mods:
                if (
                    isinstance(modification, LowerConditionalStateTransition)
                    and int(modification.old_dispatcher_serial)
                    in terminal_state_writer_sources
                ):
                    logger.info(
                        "conditional bridge suppressed: source=%s old=%s "
                        "gate=terminal_state_writer reason=%s",
                        _format_block_label(
                            flow_graph,
                            int(modification.source_serial),
                        ),
                        _format_block_label(
                            flow_graph,
                            int(modification.old_dispatcher_serial),
                        ),
                        modification.reason,
                    )
        conditional_bridge_mods = [
            mod
            for mod in conditional_bridge_mods
            if not (
                (
                    isinstance(mod, (RedirectGoto, RedirectBranch))
                    and int(mod.old_target) in terminal_state_writer_sources
                )
                or (
                    isinstance(mod, LowerConditionalStateTransition)
                    and int(mod.old_dispatcher_serial) in terminal_state_writer_sources
                )
            )
        ]
    if conditional_bridge_mods:
        bridge_sources = {
            (
                int(mod.source_serial)
                if isinstance(mod, LowerConditionalStateTransition)
                else int(mod.from_serial)
            )
            for mod in conditional_bridge_mods
        }
        mods = [
            mod
            for mod in mods
            if not (
                isinstance(mod, (RedirectGoto, RedirectBranch))
                and int(mod.from_serial) in bridge_sources
            )
        ]
        mods = list(mods) + conditional_bridge_mods
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
                state_var_stkoff=_soff,
                default_target=dispatcher.default_target,
            )
        ),
        infer_unmatched_returns=not materialized_computed_goto_profile,
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
    if is_indirect and native_key is not None:
        guard_candidates = build_folded_loop_guard_transitions(
            flow_graph,
            dispatcher,
            transitions,
            fact_view,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            native_key=native_key,
            block_serial_for_native_identity=(block_serial_for_native_identity),
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
    mods = _preserve_deferred_materialized_handler_exit_paths(
        list(mods),
        materialized_state_routes,
    )
    # Do not filter individual sibling redirects here.  For the exceptional
    # dispatcher-retirement allowance, use-def safety is fragment-atomic and
    # is audited only after every lowering has been assembled below.
    if exit_path_effect_recovery and _soff is not None:
        exit_path_effect_plan = plan_state_exit_path_effect_lowerings(
            flow_graph=flow_graph,
            modifications=tuple(mods),
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            state_var_stkoff=_soff,
        )
        if exit_path_effect_plan.modifications:
            terminal_anchors = {
                int(site.anchor_serial)
                for site in exit_path_effect_plan.supported_sites
            }
            mods = [
                mod
                for mod in mods
                if not (
                    isinstance(mod, RedirectGoto)
                    and int(mod.from_serial) in terminal_anchors
                    and int(mod.old_target) == int(dispatcher_entry_serial)
                )
            ]
            mods = list(mods) + list(exit_path_effect_plan.modifications)
            if logger.info_on:
                logger.info(
                    "unflat minimal unflatten: exit_path_effect_lowering sites=%d "
                    "exit_path_effect_summaries=%d anchors=%s",
                    len(exit_path_effect_plan.supported_sites),
                    len(exit_path_effect_plan.exit_path_effect_summaries),
                    ",".join(str(anchor) for anchor in sorted(terminal_anchors)),
                )
    if logger.info_on:
        n_return = sum(1 for t in transitions if t.is_return)
        n_transition_rows_unresolved = sum(
            1 for t in transitions if t.next_state is None
        )
        reached, total, unreached = _reachability(
            flow_graph, dispatcher, mods, int(dispatcher_entry_serial)
        )
        logger.info(
            "unflat minimal unflatten: back_edges=%d return_edges=%d "
            "transition_rows_unresolved=%d "
            "redirects=%d reachable_handlers=%d/%d unreached=%s",
            len(transitions),
            n_return,
            n_transition_rows_unresolved,
            len(mods),
            reached,
            total,
            ",".join("blk%d" % b for b in unreached[:20]),
        )
    # Shared-merge conditional handlers (ticket d81-c733): an OLLVM
    # ``state = cond ? A : B`` handler whose two arms converge on one shared merge
    # block is mishandled by the generic passes above -- the back-edge model emits
    # conflicting merge redirects and the conditional-arm pass retargets the
    # branch's fall-through arm (which the backend cannot express), dropping the
    # conditional entirely.  Re-materialize the diamond correctly from the branch's
    # real jump target; strictly shape-gated so non-matching handlers are
    # untouched.
    cond_redirects, cond_suppressed = build_shared_merge_conditional_redirects(
        flow_graph,
        dispatcher,
        handler_transitions,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    if cond_suppressed:
        mods = [
            m
            for m in mods
            if not (
                isinstance(m, (RedirectGoto, RedirectBranch))
                and int(m.from_serial) in cond_suppressed
            )
        ]
    if cond_redirects:
        # A handler already resolved correctly by the back-edge model (its arms
        # write to DISTINCT glue blocks, e.g. state_comparison) matches the same
        # shape; re-emitting the identical redirect is a no-op but keep the plan
        # duplicate-free so the backend never sees two edits for one edge.
        _existing = {
            (type(m).__name__, int(m.from_serial), int(m.old_target), int(m.new_target))
            for m in mods
            if isinstance(m, (RedirectGoto, RedirectBranch))
        }
        for m in cond_redirects:
            key = (
                type(m).__name__,
                int(m.from_serial),
                int(m.old_target),
                int(m.new_target),
            )
            if key not in _existing:
                mods = list(mods) + [m]
                _existing.add(key)
    # Loop-guard exit (ticket d81-c733): a ``while(state != K)`` flattener with no
    # dispatcher default routes its terminal through the guard's exit arm.  Wire
    # the sentinel-writing handler to that exit corridor so severing the
    # dispatcher back-edges does not orphan the function's return.
    exit_redirects = build_loop_guard_exit_redirects(
        flow_graph,
        dispatcher,
        handler_transitions,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        infer_unmatched_returns=not materialized_computed_goto_profile,
    )
    if exit_redirects:
        mods = list(mods) + exit_redirects
    indirect_call_neutralizations = (
        build_resolver_proven_indirect_call_neutralizations(
            flow_graph,
            materialized_indirect_transfers,
            tuple(mods),
            handler_serials=route_handler_serials,
        )
        if materialized_computed_goto_profile
        else []
    )
    if indirect_call_neutralizations:
        mods = list(mods) + indirect_call_neutralizations
    mods = _prefer_exact_terminal_route_fragments(
        list(mods),
        terminal_state_route_mods,
    )
    mods, terminal_switch_cleanup_source = _break_terminal_switch_dispatcher_cycle(
        flow_graph,
        list(mods),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    if terminal_switch_cleanup_source is not None and logger.info_on:
        logger.info(
            "unflat switch retirement: breaking detached dispatcher cycle "
            "cleanup_source=%s",
            _format_block_label(flow_graph, terminal_switch_cleanup_source),
        )
    mods = _normalize_degenerate_branch_redirects(flow_graph, list(mods))
    legacy_severance_bail = severance_bail_enabled()
    use_def_audit = audit_use_def_severances(
        mods,
        use_def_safety=use_def_safety,
        live_function=live_function,
        pre_cfg=flow_graph,
        state_var_stkoff=_soff,
        enforce=True if legacy_severance_bail else None,
    )
    dispatcher_removal_safety = {
        "fragment_atomic": use_def_audit.clean,
        "non_state_use_def_veto": use_def_audit.clean,
        "non_state_use_def_checked": use_def_audit.executed,
        "non_state_use_def_severances_zero": (
            use_def_audit.executed and use_def_audit.severance_count == 0
        ),
    }
    use_def_audit_metadata = use_def_audit.to_metadata(
        function_ea=int(flow_graph.func_ea)
    )
    coverage = analyze_dispatcher_corridor_coverage(
        flow_graph,
        modifications=tuple(mods),
        dispatcher_entry_serial=dispatcher_entry_serial,
    )
    if _must_reject_fragment_for_use_def_audit(
        use_def_audit,
        legacy_bail=legacy_severance_bail,
    ):
        if logger.info_on:
            logger.info(
                "unflat minimal unflatten: fragment-atomic dispatcher retirement "
                "rejected %d non-state use-def severance(s)",
                use_def_audit.severance_count,
            )
        return compile_with_dispatcher_coverage(()).with_metadata(
            **{USE_DEF_SEVERANCE_AUDIT_METADATA: use_def_audit_metadata}
        )
    if not use_def_audit.clean and logger.info_on:
        logger.info(
            "unflat minimal unflatten: narrow dispatcher-retirement proof "
            "abstained use_def_executed=%s severances=%d reason=%s",
            use_def_audit.executed,
            use_def_audit.severance_count,
            use_def_audit.failure_reason or "none",
        )
    plan = compile_modifications(list(mods)).with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            UNFLATTEN_COMPLETION_STATUS_METADATA: coverage.completion_status,
            FULL_UNFLATTENING_CLAIM_METADATA: coverage.full_unflattening_claim,
            USE_DEF_SEVERANCE_AUDIT_METADATA: use_def_audit_metadata,
        }
    )
    plan = attach_dispatcher_removal_preflight_proof(plan, coverage)
    log_dispatcher_coverage(coverage)
    if terminal_carrier_convergence:
        plan = plan.with_metadata(
            **{
                TERMINAL_CARRIER_CONVERGENCE_METADATA: True,
                TERMINAL_CARRIER_CONVERGENCE_REASON_METADATA: (
                    "region_partitioned_fixpoint:stack_address_alias_terminal_guard"
                ),
            }
        )
    return plan


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
        if isinstance(m, ConvertToGoto):
            rewired[int(m.block_serial)] = [int(m.goto_target)]
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
