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

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
import operator

from d810.core.logging import getLogger
from d810.analyses.control_flow.state_machine_analysis import (
    _SnapshotProjectionCache,
    _constant_dest_locator_snapshot,
    _forward_eval_insn,
    _is_call_insn,
    _is_goto_insn,
    _is_nop_insn,
    _is_stop_block,
    _transfer_snapshot_constant_block,
    run_snapshot_constant_fixpoint,
)
from d810.analyses.control_flow.concrete_state_route import (
    ConcreteStateRoute,
    resolve_concrete_state_route,
)
from d810.analyses.control_flow.graph_checks import reachable_from_adjacency
from d810.analyses.value_flow.global_init_fold import (
    compute_initializer_stable_global_reads,
)
from d810.analyses.value_flow.state_write import (
    forward_eval_instruction,
    isolate_temporaries_for_forward_evaluation,
)
from d810.analyses.data_flow.concolic import (
    AbstractEvidence,
    ConcolicValue,
    ConcreteStore,
    EmulationCapability,
    LocationRef,
    PrecisionStatus,
    fold_exact,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
    lookup_materialized_state_route,
    lookup_state_keyed_transfer_target,
    lookup_singleton_transfer_target,
    route_materialized_transfer_chain,
    route_transfer_target_through_condition_chain,
)
from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.analyses.control_flow.state_carrier import (
    ExactCarrierStateWrite,
    ExactStateTransformFeeder,
    expected_u32_state_identities,
    observes_u32_carrier_feeder_candidate,
    observes_u32_state_feeder_candidate,
    observes_u32_state_transform_feeder_candidate,
    prove_exact_u32_carrier_state_write,
    prove_exact_u32_state_transform_feeder,
)
from d810.capabilities.providers import get_condition_chain_walkers
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    OperandKind,
)
from d810.ir.insn_projection import (
    InstructionProjection,
    is_effect_free_operand_tree,
    operand_kinds,
    operand_snapshots,
    operand_stack_offsets,
    operand_stack_refs,
    operand_storages,
    project_instruction,
    project_instruction_sequence,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import Instruction
from d810.ir.locations import WeakStackSlot
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_mop_snapshot,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode

logger = getLogger(__name__)


_ROUTE_OP_FOR_PREDICATE = {
    PredicateKind.EQ: "jz",
    PredicateKind.NE: "jnz",
    PredicateKind.UGT: "ja",
    PredicateKind.UGE: "jae",
    PredicateKind.ULT: "jb",
    PredicateKind.ULE: "jbe",
    PredicateKind.SGT: "jg",
    PredicateKind.SGE: "jge",
    PredicateKind.SLT: "jl",
    PredicateKind.SLE: "jle",
}


def _storage_dest_locator(
    storage: Varnode | WeakStackSlot | None,
    kind: OperandKind | None,
) -> tuple[str, int] | None:
    """``("stk"|"reg", offset)`` for a STACK/REGISTER operand, else ``None``.

    Canonical-Instruction equivalent of
    :func:`~d810.analyses.control_flow.state_machine_analysis._constant_dest_locator_snapshot`,
    byte-identical including its ``kind`` gate: the legacy locator only matched
    operands whose *operand* kind is ``STACK`` / ``REGISTER``
    (``_is_stack_operand`` / ``_is_register_operand``), so an ``LVAR`` operand
    (which :func:`~d810.ir.varnode.varnode_from_mop_snapshot` may promote to a
    ``Space.STACK`` view) located to ``None``.  ``kind`` (from
    :func:`~d810.ir.insn_projection.operand_kinds`) reproduces that gate exactly;
    the offset then comes from the slot-aligned ``Varnode`` storage view (a
    ``STACK`` operand whose offset was not recovered is a ``WeakStackSlot`` ->
    ``None``, matching the legacy ``_stack_offset`` miss).
    """
    if kind is OperandKind.STACK:
        if isinstance(storage, Varnode) and storage.space is Space.STACK:
            return ("stk", int(storage.offset))
        return None
    if kind is OperandKind.REGISTER:
        if isinstance(storage, Varnode) and storage.space is Space.REGISTER:
            return ("reg", int(storage.offset))
        return None
    return None


def _storage_const_value(storage: Varnode | WeakStackSlot | None) -> int | None:
    """Numeric constant for a CONST storage view, else ``None``."""
    if not isinstance(storage, Varnode) or storage.space is not Space.CONST:
        return None
    return int(storage.offset)


def _storage_global_offset(storage: Varnode | WeakStackSlot | None) -> int | None:
    """Global address for a GLOBAL storage view, else ``None``."""
    if not isinstance(storage, Varnode) or storage.space is not Space.GLOBAL:
        return None
    return int(storage.offset)


# Default bound on the handler-local corridor scan.  Real OLLVM handler bodies
# (entry -> work -> const-load -> shared MBA suffix -> dispatcher) are short; a
# small bound keeps the scan O(handler) and prevents runaway on malformed CFGs.
_MAX_CORRIDOR_DEPTH = 24
_SEEDED_PATH_STATE_POP_BUDGET = 50_000

__all__ = [
    "CandidatePrefixAlternateCorridorProof",
    "CandidatePrefixObservation",
    "CandidatePrefixStatus",
    "CandidateScopedPrefixAuthority",
    "TransitionArm",
    "HandlerTransition",
    "recover_handler_transitions",
    "resolve_materialized_handler_exit_states",
    "resolve_materialized_handler_transition_targets",
    "StateWriteTransition",
    "TransitionProof",
    "enrich_native_bound_transition_routes",
    "transition_uses_terminal_stack_alias_guard",
    "transitions_use_terminal_stack_alias_guard",
    "block_has_live_carrier_write",
    "recover_state_write_transitions",
    "recover_state_write_transitions_via_fixpoint",
    "recover_state_write_transitions_via_multicell_fixpoint",
    "recover_state_write_transitions_via_partitioned_fixpoint",
    "observe_candidate_scoped_prefix_authority",
    "collect_candidate_prefix_alternate_corridor_proofs",
    "build_current_u32_decision_forest",
    "route_current_u32_decision_forest",
    "validate_candidate_prefix_alternate_corridor_proof",
    "diff_back_edge_transitions",
    "diff_back_edge_transitions_partitioned",
]

#: The oracle that resolves a back-edge next-state after the S4 C3 flip: the sound
#: region-partitioned multi-cell constant fixpoint (run_snapshot_constant_fixpoint).
_FIXPOINT_ORACLE = "region_partitioned_fixpoint"
_DAG_RECONCILIATION_ORACLE = "decision_dag_state_route_reconciliation"
_DAG_RECONCILIATION_KIND = "decision_dag_reconciled"
_STATE_TRANSFORM_DAG_ORACLE = "exact_state_transform_decision_dag_route"
_STATE_TRANSFORM_DAG_KIND = "state_transform_decision_dag_reconciled"
_SOURCE_CARRIER_DAG_ORACLE = "exact_source_carrier_decision_dag_route"
_SOURCE_CARRIER_DAG_KIND = "source_carrier_decision_dag_reconciled"
_KIND_STACK_ADDRESS_ALIAS_STORE = "stack_address_alias_store"
_KIND_STACK_ADDRESS_ALIAS_STORE_PARTITIONED = "stack_address_alias_store_partitioned"
_KIND_STACK_ADDRESS_ALIAS_TERMINAL_GUARD = "stack_address_alias_terminal_guard"
_KIND_STACK_ADDRESS_ALIAS_TERMINAL_GUARD_PARTITIONED = (
    "stack_address_alias_terminal_guard_partitioned"
)
_TERMINAL_STACK_ALIAS_GUARD_KINDS = frozenset(
    {
        _KIND_STACK_ADDRESS_ALIAS_TERMINAL_GUARD,
        _KIND_STACK_ADDRESS_ALIAS_TERMINAL_GUARD_PARTITIONED,
    }
)

#: The reduced-product CONCRETE leg (ticket llr-xauw): a prove-exact-or-abstain
#: ``EmulationCapability`` consulted ONLY where the abstract fixpoint fold left a
#: back-edge next-state at ``⊥`` (read_key miss).  Its ``ExactResult`` is still
#: cross-checked against the abstract floor by ``fold_exact`` before it is trusted,
#: so a wrong emulation forfeits precision, never correctness.  It NEVER overrides a
#: fixpoint-resolved transition -- it only fills genuine ⊥ gaps.
_EMULATION_ORACLE = "emulation_concrete_leg"

#: Proof KINDS for the reduced-product CONCRETE leg (ticket llr-a93i): one per
#: recovery SITE the prove-exact-or-abstain emulator can serve, so the proof
#: distribution names WHERE the concrete oracle fired -- initial-state vs back-edge
#: vs conditional-arm -- not merely THAT it fired.  All four share the
#: ``_EMULATION_ORACLE`` oracle (the oracle is the evidence SOURCE; the kind is the
#: recovery SITE), and every one is ``fold_exact``-gated before it is trusted.
#:
#: * ``initial_state_concrete_fold``   -- the prologue/entry-init state write folded
#:   by the emulator seeded from entry constants + static-initializer facts (Slice 2).
#: * ``back_edge_concrete_fold``       -- a single dispatcher back-edge's next-state,
#:   every incoming edge agreeing on one concrete value (Slice 3).
#: * ``concrete_fold_partitioned``     -- the per-immediate-predecessor split of a
#:   back-edge (one distinct concrete next-state per incoming edge).
#: * ``conditional_arm_concrete_fold`` -- a runtime-guarded branch arm of a handler,
#:   folded as one conditional transition per arm (Slice 4).
_KIND_INITIAL_STATE_CONCRETE_FOLD = "initial_state_concrete_fold"
_KIND_BACK_EDGE_CONCRETE_FOLD = "back_edge_concrete_fold"
_KIND_CONCRETE_FOLD_PARTITIONED = "concrete_fold_partitioned"
_KIND_CONDITIONAL_ARM_CONCRETE_FOLD = "conditional_arm_concrete_fold"


def _resolve_dispatcher_route(
    dispatcher: object,
    state: int,
) -> ConcreteStateRoute | None:
    """Resolve one state through every route provider on *dispatcher*.

    The normal config-v2 router is an :class:`IntervalDispatcher`, while some
    native/materialized adapters expose an exact ``resolve_target`` alongside
    their interval ``lookup_row``.  Do not impose precedence between those
    providers: when both are present, the shared resolver requires agreement.
    A missing or malformed route therefore remains unresolved.
    """
    def _method(name: str):
        try:
            candidate = getattr(dispatcher, name, None)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
            return None
        return candidate if callable(candidate) else None

    exact = dispatcher if _method("resolve_target") is not None else None
    interval = dispatcher if _method("lookup_row") is not None else None
    return resolve_concrete_state_route(
        state,
        exact_dispatcher_map=exact,
        interval_dispatcher=interval,
    )


def _resolved_dispatcher_target(dispatcher: object, state: int) -> int | None:
    route = _resolve_dispatcher_route(dispatcher, state)
    return None if route is None else int(route.target_block)


def _seed_concrete_store(
    out_stk: dict[int, int], out_reg: dict[int, int]
) -> ConcreteStore:
    """Project a fixpoint OUT store (stkoff/regid -> int) into a ``ConcreteStore``.

    The seeded store the concrete leg evaluates the back-edge block over: every
    converged stack/register constant at the immediate predecessor's exit becomes a
    resolved ``LocationRef`` cell, so an opaque ``state = reg_a ^ reg_b`` write whose
    operands are program values defined upstream resolves (the abstract meet
    collapses them to ⊥; the concrete leg reads them from the predecessor OUT).
    Width 8 mirrors the u64-masked state lattice; the backend's ``_seed_maps`` only
    reads STACK / REGISTER cells.
    """
    cells: dict[LocationRef, int] = {}
    for off, val in out_stk.items():
        cells[LocationRef.stack(int(off), 8)] = int(val)
    for reg, val in out_reg.items():
        cells[LocationRef.reg(int(reg), 8)] = int(val)
    return ConcreteStore.of(cells)


def _emulate_unresolved_state(
    emu: EmulationCapability,
    live_block: object,
    seeded_store: ConcreteStore,
    state_cell: LocationRef,
    *,
    spine_floor: "AbstractEvidence | None" = None,
    strict_floor: bool = False,
) -> int | None:
    """Consult the concrete leg for a single ⊥ back-edge, or ``None`` on abstain.

    Steps ``live_block`` over ``seeded_store`` via the injected
    :class:`EmulationCapability`, then ``fold_exact``-validates the outcome against the
    abstract floor ``spine_floor``.  Returns the proven concrete next-state
    (width-masked) or ``None`` when the emulator abstains / the fold is dropped.

    The floor seam (ticket llr-1d8u / P4):

    * ``spine_floor=None`` (DEFAULT) -> floor = ``AbstractEvidence.top(8)``, which is
      byte-identical to the historical ``ConcolicValue.top(8).abstract`` floor the
      ``llr-xauw`` reduced-product CONCRETE leg used.  ``AbstractEvidence.top()``
      ``contains`` every value, so soundness rests on the emulator's own
      prove-exact-or-abstain block-stepper -- the unchanged legacy behaviour.
    * ``spine_floor`` non-``⊤`` -> the AI spine's per-context ``σ#_in(c)`` projection.
      ``fold_exact`` then does REAL work: an ``ExactResult`` whose value the floor does
      NOT contain (an unsound/over-eager emulator) is dropped, so the concrete claim is
      validated against a non-trivial sound floor (the §7 (b) gate).
    * ``strict_floor=True`` (the P4 reduced-product caller) -> early-return ``None``
      ("stay ⊤") when the floor is ``⊤``.  This closes the Z3-proven VACUOUS gate: a
      ⊤ floor admits every value, so refining a ⊤ cell on its strength is unsound;
      the reduced-product path must therefore have a non-trivial floor or stay ⊤.
      The DEFAULT (``strict_floor=False``) NEVER early-returns, so every existing
      caller is behaviour-identical.
    """
    floor = spine_floor if spine_floor is not None else AbstractEvidence.top(8)
    if strict_floor and floor.is_top():
        # Reduced-product gate (b): a ⊤ floor cannot establish completeness
        # (γ(⊤) is everything), so refining on its strength is the vacuous/unsound
        # gate the Z3 proof flagged. Stay ⊤. (truth reduced_product_cff_refinement/
        # is_sound_iff; ticket llr-1d8u §0.1.)
        if logger.info_on:
            logger.info("emu-consult: ⊤ floor under strict_floor -> stay ⊤ (abstain)")
        return None
    if live_block is None:
        if logger.info_on:
            logger.info("emu-consult: no live block -> abstain")
        return None
    try:
        outcome = emu.eval_block(live_block, seeded_store)
    except Exception:  # noqa: BLE001 — an emulator failure means "cannot prove" -> abstain
        logger.debug("emulation concrete leg raised; abstaining", exc_info=True)
        if logger.info_on:
            logger.info(
                "emu-consult: blk=%s store_cells=%d -> RAISED (abstain)",
                getattr(live_block, "serial", "?"),
                len(getattr(seeded_store, "cells", {})),
            )
        return None
    folded = fold_exact(
        ConcolicValue(None, None, floor, floor.width, PrecisionStatus.ABSTRACT),
        outcome,
        state_cell,
    )
    resolved = folded.status is PrecisionStatus.CONCRETE and folded.concrete is not None
    # Observability (ticket llr-a93i, Slice 3): record every concrete-leg consult --
    # candidate block, seed richness, the emulator's outcome ADT, and whether
    # ``fold_exact`` accepted it -- so "does the real HexRaysBlockEmulator ever fold a
    # production back-edge?" is answerable from the log, not inferred from a 0-count in
    # the proof histogram.
    if logger.info_on:
        logger.info(
            "emu-consult: blk=%s store_cells=%d outcome=%s reason=%r folded=%s%s",
            getattr(live_block, "serial", "?"),
            len(getattr(seeded_store, "cells", {})),
            type(outcome).__name__,
            getattr(outcome, "reason", ""),
            resolved,
            (" value=0x%x" % (int(folded.concrete) & 0xFFFFFFFF)) if resolved else "",
        )
    if not resolved:
        return None
    return int(folded.concrete) & 0xFFFFFFFF


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
    route_source_kinds: tuple[str, ...] = ()


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

    write_block: int  # redirect source (the back-edge, or a predecessor
    # of it when the back-edge is a per-predecessor split)
    next_state: int | None  # folded state-var value entering the dispatcher
    target_handler: int | None  # dispatcher route of next_state (None unresolved)
    is_return: bool  # routes to exit/STOP/default, or unresolved
    branch_arm: int | None  # succ index of the dispatcher edge (None => 1-way)
    via_block: int | None = None  # when set, redirect ``write_block -> via_block``
    # (bypass the shared back-edge) instead of
    # ``write_block -> dispatcher``
    proof: "TransitionProof | None" = None  # typed provenance (d81-t9ok); the
    # authoritative fixpoint emitter attaches
    # it, None = unattributed (legacy fold)
    preserve_via_block: bool = False  # clone the source-specific via path instead
    # of bypassing semantic feeder instructions


def _attach_route_source_kinds(
    transitions: tuple[StateWriteTransition, ...],
    dispatcher: object,
) -> tuple[StateWriteTransition, ...]:
    """Carry concrete-route provenance onto accepted typed transition proofs."""
    enriched: list[StateWriteTransition] = []
    for transition in transitions:
        state = transition.next_state
        target = transition.target_handler
        if state is None or target is None:
            enriched.append(transition)
            continue
        route = _resolve_dispatcher_route(dispatcher, int(state))
        if route is None or int(route.target_block) != int(target):
            enriched.append(transition)
            continue
        proof = transition.proof
        if proof is None:
            proof = TransitionProof(
                _FIXPOINT_ORACLE,
                "routed",
                not transition.is_return,
                route_source_kinds=route.source_kinds,
            )
        elif proof.route_source_kinds != route.source_kinds:
            proof = replace(proof, route_source_kinds=route.source_kinds)
        enriched.append(replace(transition, proof=proof))
    return tuple(enriched)


def enrich_native_bound_transition_routes(
    transitions: tuple[StateWriteTransition, ...],
    routes: tuple[NativeBoundTransitionRoute, ...],
    *,
    dispatcher_region_serials: frozenset[int] = frozenset(),
) -> tuple[StateWriteTransition, ...]:
    """Fill or corroborate state-write rows from exact native-bound evidence.

    This is intentionally a pure join performed after all normal
    fixpoint/emulator providers have run.  A singleton native route may fill an
    unresolved row, or corroborate a fully resolved row when its exact
    ``(state, target)`` agrees; in the latter case the typed native-bound proof
    becomes the route authority.  Multiple disagreeing routes for one source
    abstain as a group.  The source EA has already been rebound to the current
    ``write_block``/``via_block`` by the Hex-Rays adapter.
    """
    if not transitions or not routes:
        return transitions

    candidates_by_source: dict[
        int, dict[tuple[int, int], list[NativeBoundTransitionRoute]]
    ] = {}
    dispatcher_serials = {int(serial) for serial in dispatcher_region_serials}
    for route in routes:
        try:
            source = int(route.source_block_serial)
            state = int(route.state_constant)
            target = int(route.target_handler_serial)
            native_ea = int(route.source_instruction_ea)
        except (AttributeError, TypeError, ValueError):
            continue
        if not 0 <= state <= 0xFFFFFFFF:
            continue
        if source < 0 or target < 0 or target in dispatcher_serials:
            continue
        if not 0 <= native_ea < 0xFFFFFFFFFFFFFFFF:
            continue
        candidates_by_source.setdefault(source, {}).setdefault(
            (state, target), []
        ).append(route)

    enriched: list[StateWriteTransition] = []
    for transition in transitions:
        source_serials = {int(transition.write_block)}
        if transition.via_block is not None:
            source_serials.add(int(transition.via_block))
        matches: dict[tuple[int, int], list[NativeBoundTransitionRoute]] = {}
        for source in source_serials:
            for route_key, source_routes in candidates_by_source.get(source, {}).items():
                matches.setdefault(route_key, []).extend(source_routes)
        if len(matches) != 1:
            enriched.append(transition)
            continue
        route_key, source_routes = next(iter(matches.items()))
        route = min(
            source_routes,
            key=lambda candidate: (
                str(candidate.fact_id),
                int(candidate.source_instruction_ea),
            ),
        )
        state, target = route_key
        if (
            transition.next_state is not None
            or transition.target_handler is not None
        ):
            if (
                transition.next_state != state
                or transition.target_handler != target
            ):
                enriched.append(transition)
                continue
            enriched.append(
                replace(
                    transition,
                    proof=TransitionProof(
                        "native_bound_transition_route",
                        "native_bound_route",
                        True,
                        reason=(
                            f"fact_id={route.fact_id};"
                            f"native_ea=0x{int(route.source_instruction_ea):X}"
                        ),
                    ),
                )
            )
            continue
        enriched.append(
            replace(
                transition,
                next_state=state,
                target_handler=target,
                is_return=False,
                proof=TransitionProof(
                    "native_bound_transition_route",
                    "native_bound_route",
                    True,
                    reason=(
                        f"fact_id={route.fact_id};"
                        f"native_ea=0x{int(route.source_instruction_ea):X}"
                    ),
                ),
            )
        )
    return tuple(enriched)


def _source_local_constant_register_write(
    flow_graph: FlowGraph,
    source_serial: int,
    state_var_reg: int | None,
) -> int | None:
    """Return the final source-local immediate state-register write, if exact."""
    if state_var_reg is None:
        return None
    block = flow_graph.get_block(int(source_serial))
    if block is None:
        return None
    result: int | None = None
    for instruction in block.insn_snapshots:
        left, _right, destination = operand_storages(instruction)
        if _reg_of(destination) != int(state_var_reg):
            continue
        value = _number_value(left) if instruction.kind is InsnKind.MOV else None
        result = int(value) & 0xFFFFFFFF if value is not None else None
    return result


def _block_writes_state_cell(ctx: "_ResolverContext", block: BlockSnapshot) -> bool:
    """Whether *block* directly writes the configured dispatcher state cell.

    The multi-entry scan is allowed to move a transition anchor away from the
    dispatcher's immediate predecessor, but it must still anchor on an actual
    state writer.  Reading a constant inherited from an earlier block is not
    proof that this block owns the transition.
    """
    for instruction in block.insn_snapshots:
        _left, _right, destination = operand_storages(instruction)
        _left_kind, _right_kind, destination_kind = operand_kinds(instruction)
        if ctx.state_var_reg is not None:
            if _storage_dest_locator(destination, destination_kind) == (
                "reg",
                int(ctx.state_var_reg),
            ):
                return True
            continue
        if ctx.state_var_gaddr is not None:
            if _storage_global_offset(destination) == int(ctx.state_var_gaddr):
                return True
            continue
        if _storage_dest_locator(destination, destination_kind) == (
            "stk",
            int(ctx.effective_stkoff),
        ):
            return True
    return False


@dataclass(frozen=True, slots=True)
class _ExactStateNormalizerStep:
    """One exact pure constant rewrite feeding a decision-DAG node."""

    observed: bool
    valid: bool
    state: int | None = None
    feeder_serial: int | None = None
    dag_entry_serial: int | None = None


@dataclass(frozen=True, slots=True)
class _DecisionDagStateRoute:
    """One exact route, including any pure state-normalizer leaves."""

    target: int
    certified_targets: frozenset[int]


@dataclass(frozen=True, slots=True)
class _ExactDirectDecisionDagEntry:
    """Current-snapshot proof for ``state writer -> internal DAG node``."""

    normalized_state: int
    source_serial: int
    source_ea: int
    entry_serial: int
    entry_ea: int
    branch_ea: int
    state_identity: StorageIdentity
    comparison: RouteComparison
    comparisons: tuple[tuple[int, RouteComparison], ...]
    aliases: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class _DirectDecisionDagEntryObservation:
    """Tri-state observation without widening unrelated transition shapes."""

    observed: bool
    proof: _ExactDirectDecisionDagEntry | None = None


_MAX_DIRECT_ENTRY_ROUTE_COMPARISONS = 256


class CandidatePrefixStatus(Enum):
    NOT_APPLICABLE = "not_applicable"
    VALID = "valid"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class CandidateScopedPrefixAuthority:
    """Current-invocation authority for one omitted comparison prefix."""

    prefix_serial: int
    prefix_ea: int
    branch_ea: int
    root_serial: int
    state_identity: StorageIdentity
    comparison: RouteComparison


@dataclass(frozen=True, slots=True)
class CandidatePrefixAlternateCorridorProof:
    """Exact source context in which an omitted prefix cannot enter its root."""

    normalized_state: int
    source_serial: int
    source_ea: int
    feeder_serial: int | None
    feeder_ea: int | None
    prefix_serial: int
    prefix_ea: int
    root_serial: int
    root_ea: int
    state_identity: StorageIdentity


@dataclass(frozen=True, slots=True)
class CandidatePrefixObservation:
    status: CandidatePrefixStatus
    authority: CandidateScopedPrefixAuthority | None = None


# Preserve the existing private test seam while exposing only the immutable
# observation values needed by emitter orchestration.
_CandidatePrefixStatus = CandidatePrefixStatus
_CandidateScopedPrefixAuthority = CandidateScopedPrefixAuthority
_CandidatePrefixObservation = CandidatePrefixObservation


def _raw_branch_mentions_state_identity(
    block: BlockSnapshot,
    expected_identities: frozenset[StorageIdentity],
) -> bool:
    """Observe same-state conditional parents broadly before strict validation."""

    if not expected_identities:
        return False
    for instruction in block.insn_snapshots:
        if (
            instruction.control_transfer_kind
            is not ControlTransferKind.CONDITIONAL_BRANCH
        ):
            continue
        if any(
            storage_identity_from_mop_snapshot(operand) in expected_identities
            for operand in operand_snapshots(instruction)
        ):
            return True
    return False


def _validate_candidate_scoped_prefix(
    flow_graph: FlowGraph,
    serial: int,
    *,
    root_serial: int,
    expected_identities: frozenset[StorageIdentity],
) -> _CandidateScopedPrefixAuthority | None:
    """Bind one pure ordered U32 ``state OP const`` prefix to the current CFG."""

    block = flow_graph.get_block(int(serial))
    root = flow_graph.get_block(int(root_serial))
    if block is None or root is None:
        return None
    successors = tuple(int(target) for target in block.succs)
    if (
        len(successors) != 2
        or successors[0] == successors[1]
        or int(serial) in successors
        or int(root_serial) not in successors
        or int(serial) not in tuple(int(pred) for pred in root.preds)
        or any(
            (target_block := flow_graph.get_block(target)) is None
            or int(serial) not in tuple(int(pred) for pred in target_block.preds)
            for target in successors
        )
    ):
        return None

    block_ea = int(block.native_start_ea or block.start_ea)
    raw_instructions = tuple(block.insn_snapshots)
    raw_branches = tuple(
        instruction
        for instruction in raw_instructions
        if instruction.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(raw_branches) != 1:
        return None
    raw_branch = raw_branches[0]
    branch_ea = int(raw_branch.native_ea or raw_branch.ea)
    if (
        not 0 < block_ea < 0xFFFFFFFFFFFFFFFF
        or branch_ea < block_ea
        or not 0 < branch_ea < 0xFFFFFFFFFFFFFFFF
        or bool(raw_branch.is_call)
        or raw_branch.call_kind is not None
        or any(
            instruction is not raw_branch and instruction.kind is not InsnKind.NOP
            for instruction in raw_instructions
        )
        or not all(
            is_effect_free_operand_tree(operand)
            for instruction in raw_instructions
            for operand in operand_snapshots(instruction)
        )
    ):
        return None

    instructions = InstructionProjection.from_block(block)
    branches = tuple(
        instruction
        for instruction in instructions
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(branches) != 1:
        return None
    branch = branches[0]
    if (
        branch.effects
        or branch.memory is not None
        or branch.control is None
        or branch.control.target not in successors
        or branch.control.predicate not in _ROUTE_OP_FOR_PREDICATE
        or len(branch.inputs) != 2
    ):
        return None
    for instruction in instructions:
        if instruction is branch:
            continue
        if not (
            instruction.operation is ValueOpKind.VENDOR
            and not instruction.inputs
            and instruction.result is None
            and not instruction.effects
            and instruction.memory is None
            and instruction.control is None
        ):
            return None

    state_operand, constant_operand = branch.inputs
    state_identity = storage_identity_from_varnode(state_operand)
    if (
        int(state_operand.size) != 4
        or state_identity not in expected_identities
        or constant_operand.space is not Space.CONST
        or int(constant_operand.size) != 4
    ):
        return None
    true_target = int(branch.control.target)
    false_targets = tuple(target for target in successors if target != true_target)
    if len(false_targets) != 1 or state_identity is None:
        return None
    comparison = RouteComparison(
        serial=int(serial),
        op=_ROUTE_OP_FOR_PREDICATE[branch.control.predicate],
        const=int(constant_operand.offset) & 0xFFFFFFFF,
        true_target=true_target,
        false_target=false_targets[0],
    )
    return _CandidateScopedPrefixAuthority(
        prefix_serial=int(serial),
        prefix_ea=block_ea,
        branch_ea=branch_ea,
        root_serial=int(root_serial),
        state_identity=state_identity,
        comparison=comparison,
    )


def _observe_candidate_scoped_prefix(
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> _CandidatePrefixObservation:
    """Discover one same-state predecessor omitted immediately above DAG root."""

    # An empty comparison set is a switch-table/materialized-dispatch profile,
    # not an OLLVM comparison DAG with an omitted ordered prefix.  Applying the
    # prefix veto here would let an unrelated state comparison above the switch
    # root suppress the profile before its own route recovery runs.
    if not decision_dag.nodes:
        return _CandidatePrefixObservation(_CandidatePrefixStatus.NOT_APPLICABLE)

    root_serial = int(decision_dag.root)
    root = flow_graph.get_block(root_serial)
    if root is None:
        return _CandidatePrefixObservation(_CandidatePrefixStatus.NOT_APPLICABLE)
    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    predecessor_candidates = {int(pred) for pred in root.preds} | {
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if root_serial in tuple(int(succ) for succ in block.succs)
    }
    observed: list[int] = []
    for predecessor in sorted(predecessor_candidates):
        if predecessor in decision_dag.nodes:
            continue
        block = flow_graph.get_block(predecessor)
        if block is None:
            continue
        if _raw_branch_mentions_state_identity(block, expected_identities):
            observed.append(predecessor)
    if not observed:
        return _CandidatePrefixObservation(_CandidatePrefixStatus.NOT_APPLICABLE)
    if len(observed) != 1:
        return _CandidatePrefixObservation(_CandidatePrefixStatus.INVALID)
    authority = _validate_candidate_scoped_prefix(
        flow_graph,
        observed[0],
        root_serial=root_serial,
        expected_identities=expected_identities,
    )
    if authority is None:
        return _CandidatePrefixObservation(_CandidatePrefixStatus.INVALID)
    return _CandidatePrefixObservation(_CandidatePrefixStatus.VALID, authority)


def observe_candidate_scoped_prefix_authority(
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> CandidatePrefixObservation:
    """Observe one current-snapshot prefix before transition recovery."""

    return _observe_candidate_scoped_prefix(
        flow_graph,
        decision_dag,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )


def _revalidate_candidate_scoped_prefix_authority(
    flow_graph: FlowGraph,
    authority: CandidateScopedPrefixAuthority,
    *,
    root_serial: int,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> bool:
    """Rebind an already-selected authority without rediscovering candidates."""

    if int(authority.root_serial) != int(root_serial):
        return False
    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    current = _validate_candidate_scoped_prefix(
        flow_graph,
        int(authority.prefix_serial),
        root_serial=int(root_serial),
        expected_identities=expected_identities,
    )
    return current == authority


def _candidate_prefix_selects_root(
    authority: _CandidateScopedPrefixAuthority,
    state: int,
) -> bool:
    dag = DecisionDag(
        32,
        {int(authority.prefix_serial): authority.comparison},
        root=int(authority.prefix_serial),
    )
    return dag.route(int(state) & 0xFFFFFFFF) == int(authority.root_serial)


@dataclass(frozen=True, slots=True)
class _CandidatePrefixTransitionEntry:
    """Current-graph proof that one transition physically enters a prefix."""

    enters_prefix: bool
    feeder_serial: int | None = None


def _candidate_prefix_transition_entry(
    flow_graph: FlowGraph,
    transition: StateWriteTransition,
    authority: CandidateScopedPrefixAuthority,
) -> _CandidatePrefixTransitionEntry | None:
    """Classify direct and one-feeder prefix entrants, failing closed on drift."""

    source_serial = int(transition.write_block)
    source = flow_graph.get_block(source_serial)
    prefix_serial = int(authority.prefix_serial)
    prefix = flow_graph.get_block(prefix_serial)
    if source is None or prefix is None:
        return None
    source_successors = tuple(int(target) for target in source.succs)
    via_serial = (
        None if transition.via_block is None else int(transition.via_block)
    )

    direct_observed = bool(
        via_serial == prefix_serial or prefix_serial in source_successors
    )
    if direct_observed:
        if (
            via_serial != prefix_serial
            or source_successors != (prefix_serial,)
            or source_serial not in tuple(int(pred) for pred in prefix.preds)
        ):
            return None
        return _CandidatePrefixTransitionEntry(True)

    if via_serial is None:
        return _CandidatePrefixTransitionEntry(False)
    feeder = flow_graph.get_block(via_serial)
    if feeder is None:
        return None
    feeder_successors = tuple(int(target) for target in feeder.succs)
    feeder_observed = bool(
        prefix_serial in feeder_successors
        or via_serial in tuple(int(pred) for pred in prefix.preds)
    )
    if not feeder_observed:
        return _CandidatePrefixTransitionEntry(False)
    if (
        source_successors != (via_serial,)
        or source_serial not in tuple(int(pred) for pred in feeder.preds)
        or feeder_successors != (prefix_serial,)
        or via_serial not in tuple(int(pred) for pred in prefix.preds)
    ):
        return None
    return _CandidatePrefixTransitionEntry(True, feeder_serial=via_serial)


def collect_candidate_prefix_alternate_corridor_proofs(
    flow_graph: FlowGraph,
    transitions: tuple[StateWriteTransition, ...],
    authority: CandidateScopedPrefixAuthority,
) -> tuple[CandidatePrefixAlternateCorridorProof, ...] | None:
    """Bind trusted prefix-alternate partitions to the current physical CFG."""

    current = _validate_candidate_scoped_prefix(
        flow_graph,
        int(authority.prefix_serial),
        root_serial=int(authority.root_serial),
        expected_identities=frozenset((authority.state_identity,)),
    )
    if current != authority:
        return None
    prefix = _stable_flow_block(flow_graph, int(authority.prefix_serial))
    root = _stable_flow_block(flow_graph, int(authority.root_serial))
    if prefix is None or root is None:
        return None

    proofs: list[CandidatePrefixAlternateCorridorProof] = []
    for transition in transitions:
        entry = _candidate_prefix_transition_entry(flow_graph, transition, authority)
        if entry is None:
            return None
        if not entry.enters_prefix:
            continue
        proof = transition.proof
        if (
            transition.next_state is None
            or proof is None
            or not proof.trusted
            or proof.oracle_kind != _FIXPOINT_ORACLE
            or proof.kind != "predecessor_partitioned"
        ):
            continue
        state = int(transition.next_state) & 0xFFFFFFFF
        if _candidate_prefix_selects_root(authority, state):
            continue
        source = _stable_flow_block(flow_graph, int(transition.write_block))
        feeder = (
            None
            if entry.feeder_serial is None
            else _stable_flow_block(flow_graph, int(entry.feeder_serial))
        )
        if source is None or (entry.feeder_serial is not None and feeder is None):
            return None
        proofs.append(
            CandidatePrefixAlternateCorridorProof(
                normalized_state=state,
                source_serial=int(source.serial),
                source_ea=int(source.native_start_ea or source.start_ea),
                feeder_serial=(
                    None if feeder is None else int(feeder.serial)
                ),
                feeder_ea=(
                    None
                    if feeder is None
                    else int(feeder.native_start_ea or feeder.start_ea)
                ),
                prefix_serial=int(prefix.serial),
                prefix_ea=int(prefix.native_start_ea or prefix.start_ea),
                root_serial=int(root.serial),
                root_ea=int(root.native_start_ea or root.start_ea),
                state_identity=authority.state_identity,
            )
        )
    return tuple(proofs)


def validate_candidate_prefix_alternate_corridor_proof(
    flow_graph: FlowGraph,
    proof: CandidatePrefixAlternateCorridorProof,
    *,
    dispatcher_entry_serial: int,
) -> bool:
    """Revalidate one exact alternate-arm partition against the current CFG."""

    if int(proof.root_serial) != int(dispatcher_entry_serial):
        return False
    current = _validate_candidate_scoped_prefix(
        flow_graph,
        int(proof.prefix_serial),
        root_serial=int(proof.root_serial),
        expected_identities=frozenset((proof.state_identity,)),
    )
    if current is None or current.state_identity != proof.state_identity:
        return False
    if _candidate_prefix_selects_root(current, int(proof.normalized_state)):
        return False

    source = _stable_flow_block(flow_graph, int(proof.source_serial))
    prefix = _stable_flow_block(flow_graph, int(proof.prefix_serial))
    root = _stable_flow_block(flow_graph, int(proof.root_serial))
    if source is None or prefix is None or root is None:
        return False
    if (
        int(source.native_start_ea or source.start_ea) != int(proof.source_ea)
        or int(prefix.native_start_ea or prefix.start_ea) != int(proof.prefix_ea)
        or int(root.native_start_ea or root.start_ea) != int(proof.root_ea)
    ):
        return False

    prefix_serial = int(proof.prefix_serial)
    source_serial = int(proof.source_serial)
    feeder_serial = proof.feeder_serial
    if feeder_serial is None:
        return (
            tuple(int(target) for target in source.succs) == (prefix_serial,)
            and source_serial in tuple(int(pred) for pred in prefix.preds)
        )

    feeder = _stable_flow_block(flow_graph, int(feeder_serial))
    if (
        feeder is None
        or proof.feeder_ea is None
        or int(feeder.native_start_ea or feeder.start_ea) != int(proof.feeder_ea)
    ):
        return False
    return (
        tuple(int(target) for target in source.succs) == (int(feeder_serial),)
        and source_serial in tuple(int(pred) for pred in feeder.preds)
        and tuple(int(target) for target in feeder.succs) == (prefix_serial,)
        and int(feeder_serial) in tuple(int(pred) for pred in prefix.preds)
    )


def _attach_candidate_prefix_provenance(
    transition: StateWriteTransition,
    authority: _CandidateScopedPrefixAuthority,
) -> StateWriteTransition:
    proof = transition.proof
    if proof is None:
        return transition
    source_kind = "candidate_scoped_prefix_arm"
    reason = (
        f"{source_kind}:prefix_ea=0x{authority.prefix_ea:x}:"
        f"branch_ea=0x{authority.branch_ea:x}:"
        f"root={authority.root_serial}"
    )
    return replace(
        transition,
        proof=replace(
            proof,
            reason=f"{proof.reason};{reason}" if proof.reason else reason,
            route_source_kinds=tuple(sorted({*proof.route_source_kinds, source_kind})),
        ),
    )


def _has_exact_state_transform_proof(transition: StateWriteTransition) -> bool:
    proof = transition.proof
    if (
        transition.next_state is None
        or proof is None
        or proof.oracle_kind != "region_partitioned_fixpoint"
    ):
        return False
    if proof.kind in {"predecessor_partitioned", "transitive_glue_partitioned"}:
        # The recovery row is only a concrete source/via/state hint here.  The
        # current graph transform proof below independently recomputes the
        # state before any route authority is granted.
        return True
    if proof.kind == "partial_predecessor_partitioned":
        # Each surviving row from the partial provider is independently
        # concrete; unresolved sibling edges remain on the dispatcher.  The
        # current-graph transform receipt below still has to recompute this
        # row's exact state before it can gain route authority.
        return bool(proof.trusted)
    return bool(proof.kind == "multi_entry_global_fold" and proof.trusted)


def _attach_state_transform_feeder_provenance(
    transition: StateWriteTransition,
    proof: ExactStateTransformFeeder,
) -> StateWriteTransition:
    transition_proof = transition.proof
    if transition_proof is None:
        return transition
    source_kind = "state_transform_feeder"
    reason = (
        f"{source_kind}:op={proof.operation.value}:"
        f"source_ea=0x{proof.source_ea:x}:"
        f"feeder_ea=0x{proof.feeder_ea:x}:"
        f"root_ea=0x{proof.comparison_entry_ea:x}"
    )
    return replace(
        transition,
        proof=replace(
            transition_proof,
            reason=(
                f"{transition_proof.reason};{reason}"
                if transition_proof.reason
                else reason
            ),
            route_source_kinds=tuple(
                sorted({*transition_proof.route_source_kinds, source_kind})
            ),
        ),
    )


def _attach_preserved_feeder_clone_provenance(
    transition: StateWriteTransition,
) -> StateWriteTransition:
    proof = transition.proof
    if proof is None:
        return transition
    source_kind = "preserved_feeder_clone"
    return replace(
        transition,
        proof=replace(
            proof,
            reason=(
                f"{proof.reason};{source_kind}" if proof.reason else source_kind
            ),
            route_source_kinds=tuple(
                sorted({*proof.route_source_kinds, source_kind})
            ),
        ),
    )
def _stable_flow_block(flow_graph: FlowGraph, serial: int) -> BlockSnapshot | None:
    block = flow_graph.get_block(int(serial))
    if block is None:
        return None
    ea = int(block.start_ea)
    if not 0 < ea < 0xFFFFFFFFFFFFFFFF:
        return None
    return block


def _bound_decision_dag_route(
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    state: int,
    *,
    root: int,
) -> tuple[int, tuple[int, ...]] | None:
    """Resolve one unique U32 DAG path and bind every edge to the source CFG."""

    if int(decision_dag.width) != 32 or int(root) not in {
        *decision_dag.nodes,
        *decision_dag.aliases,
    }:
        return None
    normalized = int(state) & 0xFFFFFFFF
    try:
        route_dag = (
            decision_dag
            if int(root) == int(decision_dag.root)
            else DecisionDag(
                int(decision_dag.width),
                decision_dag.nodes,
                root=int(root),
                aliases=decision_dag.aliases,
            )
        )
        matches = tuple(
            path
            for path in route_dag.resolve_paths()
            if path.domain.contains(normalized)
            and path.path
            and int(path.path[0]) == int(root)
        )
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return None
    if len(matches) != 1:
        return None
    resolved = matches[0]
    path = tuple(int(serial) for serial in resolved.path)
    target = int(resolved.target)
    if target in decision_dag.nodes or target in decision_dag.aliases:
        return None
    for source, destination in zip(path, (*path[1:], target), strict=True):
        source_block = _stable_flow_block(flow_graph, source)
        destination_block = _stable_flow_block(flow_graph, destination)
        if destination_block is None and destination == target:
            terminal = flow_graph.get_block(destination)
            if _is_stop_block(terminal):
                # Hex-Rays STOP blocks use BADADDR rather than a native EA.
                # They are valid final DAG leaves when the selected incoming
                # edge is still reciprocal; intermediate aliases remain
                # stable-EA bound above.
                destination_block = terminal
        if (
            source_block is None
            or destination_block is None
            or destination not in {int(succ) for succ in source_block.succs}
            or source not in {int(pred) for pred in destination_block.preds}
        ):
            return None
    return target, path


def route_current_u32_decision_forest(
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    state: int,
    *,
    entry_serial: int,
) -> tuple[int, tuple[int, ...]] | None:
    """Route through an exact current-snapshot U32 forest entry.

    This is the public analyses-layer adapter for the graph-bound route replay
    already used by transition reconciliation.  The evaluator remains
    :class:`DecisionDag`; this wrapper additionally binds every selected edge
    reciprocally to ``flow_graph``.
    """

    return _bound_decision_dag_route(
        flow_graph,
        decision_dag,
        state,
        root=int(entry_serial),
    )


def _is_exact_pure_xdu_route_prefix(
    raw_instructions: tuple[InsnSnapshot, ...],
    raw_branch: InsnSnapshot,
    value_prefix: tuple[Instruction, ...],
    *,
    expected_identities: frozenset[StorageIdentity],
) -> bool:
    """Recognize the exact pure XDU expansion observed before a route tail.

    Hex-Rays may retain ``xdu (state + const), reg`` in a comparison block.
    Canonical projection expands that one raw instruction into ``ADD`` followed
    by ``ZEXT``.  It remains routing-only evidence only when the expansion is
    exact, writes neither recovered state identity nor memory, and precedes the
    sole branch.  Other arithmetic prefixes remain fail-closed.
    """

    raw_prefix = tuple(
        instruction
        for instruction in raw_instructions
        if instruction is not raw_branch and instruction.kind is not InsnKind.NOP
    )
    if len(raw_prefix) != 1:
        return False
    xdu = raw_prefix[0]
    if (
        bool(xdu.is_call)
        or xdu.call_kind is not None
        or tuple(project_instruction_sequence(xdu)) != value_prefix
    ):
        return False
    if len(value_prefix) != 2:
        return False
    add, zext = value_prefix
    if (
        add.operation is not ValueOpKind.ADD
        or zext.operation is not ValueOpKind.ZEXT
        or add.effects
        or add.memory is not None
        or add.control is not None
        or zext.effects
        or zext.memory is not None
        or zext.control is not None
        or len(add.inputs) != 2
        or add.result is None
        or add.result.space is not Space.TEMP
        or int(add.result.size) != 4
        or storage_identity_from_varnode(add.inputs[0]) not in expected_identities
        or add.inputs[1].space is not Space.CONST
        or int(add.inputs[1].size) != 4
        or zext.inputs != (add.result,)
        or zext.result is None
        or zext.result.space is not Space.REGISTER
        or int(zext.result.size) != 8
    ):
        return False
    return storage_identity_from_varnode(zext.result) not in expected_identities


def _current_u32_route_comparison(
    flow_graph: FlowGraph,
    serial: int,
    *,
    expected_identities: frozenset[StorageIdentity],
) -> tuple[RouteComparison, StorageIdentity, int, int] | None:
    """Rebuild one pure U32 comparison from the current reciprocal CFG."""

    block = _stable_flow_block(flow_graph, int(serial))
    if block is None:
        return None
    successors = tuple(int(target) for target in block.succs)
    if (
        len(successors) != 2
        or successors[0] == successors[1]
        or int(serial) in successors
    ):
        return None
    for target in successors:
        target_block = _stable_flow_block(flow_graph, target)
        if target_block is None:
            terminal = flow_graph.get_block(target)
            if not _is_stop_block(terminal):
                return None
            target_block = terminal
        if int(serial) not in tuple(int(pred) for pred in target_block.preds):
            return None

    raw_instructions = tuple(block.insn_snapshots)
    raw_branches = tuple(
        instruction
        for instruction in raw_instructions
        if instruction.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(raw_branches) != 1:
        return None
    raw_branch = raw_branches[0]
    block_ea = int(block.native_start_ea or block.start_ea)
    branch_ea = int(raw_branch.native_ea or raw_branch.ea)
    if (
        branch_ea < block_ea
        or not 0 < branch_ea < 0xFFFFFFFFFFFFFFFF
        or bool(raw_branch.is_call)
        or raw_branch.call_kind is not None
        or not all(
            is_effect_free_operand_tree(operand)
            for operand in operand_snapshots(raw_branch)
        )
    ):
        return None

    instructions = InstructionProjection.from_block(block)
    branches = tuple(
        instruction
        for instruction in instructions
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(branches) != 1:
        return None
    branch = branches[0]
    if (
        branch.effects
        or branch.memory is not None
        or branch.control is None
        or branch.control.target not in successors
        or branch.control.predicate not in _ROUTE_OP_FOR_PREDICATE
        or len(branch.inputs) != 2
    ):
        return None
    nonbranch = tuple(instruction for instruction in instructions if instruction is not branch)
    vendor_shells = tuple(
        instruction
        for instruction in nonbranch
        if instruction.operation is ValueOpKind.VENDOR
        and not instruction.inputs
        and instruction.result is None
        and not instruction.effects
        and instruction.memory is None
        and instruction.control is None
    )
    value_prefix = tuple(
        instruction for instruction in nonbranch if instruction not in vendor_shells
    )
    if value_prefix and not _is_exact_pure_xdu_route_prefix(
        raw_instructions,
        raw_branch,
        value_prefix,
        expected_identities=expected_identities,
    ):
        return None
    if len(vendor_shells) + len(value_prefix) != len(nonbranch):
        return None

    state_operand, constant_operand = branch.inputs
    state_identity = storage_identity_from_varnode(state_operand)
    if (
        int(state_operand.size) != 4
        or state_identity not in expected_identities
        or constant_operand.space is not Space.CONST
        or int(constant_operand.size) != 4
    ):
        return None
    true_target = int(branch.control.target)
    false_targets = tuple(target for target in successors if target != true_target)
    if len(false_targets) != 1 or state_identity is None:
        return None
    comparison = RouteComparison(
        serial=int(serial),
        op=_ROUTE_OP_FOR_PREDICATE[branch.control.predicate],
        const=int(constant_operand.offset) & 0xFFFFFFFF,
        true_target=true_target,
        false_target=false_targets[0],
    )
    return comparison, state_identity, block_ea, branch_ea


def _current_u32_route_alias(
    flow_graph: FlowGraph,
    serial: int,
) -> int | None:
    """Rebuild one exact reciprocal control-only GOTO alias."""

    block = _stable_flow_block(flow_graph, int(serial))
    if block is None:
        return None
    successors = tuple(int(target) for target in block.succs)
    if len(successors) != 1 or successors[0] == int(serial):
        return None
    target = _stable_flow_block(flow_graph, successors[0])
    if target is None or int(serial) not in tuple(int(pred) for pred in target.preds):
        return None

    raw_instructions = tuple(block.insn_snapshots)
    if not raw_instructions:
        return (
            successors[0]
            if getattr(block, "tail_kind", None) is InsnKind.GOTO
            else None
        )
    non_nops = tuple(
        instruction
        for instruction in raw_instructions
        if instruction.kind is not InsnKind.NOP
    )
    if (
        len(non_nops) != 1
        or non_nops[0].kind is not InsnKind.GOTO
        or bool(non_nops[0].is_call)
        or non_nops[0].call_kind is not None
        or not all(
            is_effect_free_operand_tree(operand)
            for instruction in raw_instructions
            for operand in operand_snapshots(instruction)
        )
    ):
        return None
    instructions = InstructionProjection.from_block(block)
    gotos = tuple(
        instruction
        for instruction in instructions
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.GOTO
    )
    if len(gotos) != 1 or any(
        instruction is not gotos[0]
        and not (
            instruction.operation is ValueOpKind.VENDOR
            and not instruction.inputs
            and instruction.result is None
            and not instruction.effects
            and instruction.memory is None
            and instruction.control is None
        )
        for instruction in instructions
    ):
        return None
    control = gotos[0].control
    if control is None or (
        control.target is not None and int(control.target) != successors[0]
    ):
        return None
    return successors[0]


def _current_u32_route_forest_entry(
    flow_graph: FlowGraph,
    entry_serial: int,
    decision_dag: DecisionDag,
    *,
    expected_identities: frozenset[StorageIdentity],
) -> DecisionDag | None:
    """Collect a bounded current comparison closure from one physical entry."""

    route_dag = build_current_u32_decision_forest(
        flow_graph,
        entry_serial,
        expected_identities=expected_identities,
        reference_dag=decision_dag,
    )
    if route_dag is None:
        return None
    return route_dag


def build_current_u32_decision_forest(
    flow_graph: FlowGraph,
    entry_serial: int,
    *,
    expected_identities: frozenset[StorageIdentity],
    reference_dag: DecisionDag | None = None,
) -> DecisionDag | None:
    """Rebuild one bounded pure U32 comparison forest from the current CFG.

    ``reference_dag`` is optional authority supplied by recovery.  When
    present, every overlapping comparison must match it exactly and aliases
    remain outside this structural adapter.  With no reference, the returned
    forest is still current-graph authority: every comparison is rebuilt from
    stable instructions and reciprocal edges before the existing
    :class:`DecisionDag` evaluator is used.
    """

    pending = [int(entry_serial)]
    comparisons: dict[int, RouteComparison] = {}
    aliases: dict[int, int] = {}
    visited: set[int] = set()
    while pending:
        serial = int(pending.pop())
        if serial in visited:
            continue
        visited.add(serial)
        if len(visited) > _MAX_DIRECT_ENTRY_ROUTE_COMPARISONS:
            return None
        current = _current_u32_route_comparison(
            flow_graph,
            serial,
            expected_identities=expected_identities,
        )
        if current is None:
            alias_target = _current_u32_route_alias(flow_graph, serial)
            expected_alias = (
                None if reference_dag is None else reference_dag.aliases.get(serial)
            )
            if alias_target is not None:
                if reference_dag is not None and expected_alias != alias_target:
                    return None
                aliases[serial] = int(alias_target)
                pending.append(int(alias_target))
                continue
            if expected_alias is not None:
                return None
            block = flow_graph.get_block(serial)
            if block is not None and _raw_branch_mentions_state_identity(
                block,
                expected_identities,
            ):
                return None
            continue
        comparison = current[0]
        if reference_dag is not None and serial in reference_dag.aliases:
            return None
        selected = (
            None if reference_dag is None else reference_dag.nodes.get(serial)
        )
        if selected is not None and selected != comparison:
            return None
        comparisons[serial] = comparison
        pending.extend((int(comparison.true_target), int(comparison.false_target)))

    if int(entry_serial) not in comparisons:
        return None
    try:
        route_dag = DecisionDag(
            32,
            comparisons,
            root=int(entry_serial),
            aliases=aliases,
        )
        resolved_paths = tuple(route_dag.resolve_paths())
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return None
    if any(
        int(path.target) in route_dag.nodes or int(path.target) in route_dag.aliases
        for path in resolved_paths
    ):
        return None
    return route_dag


def _observe_direct_internal_decision_dag_entry(
    transition: StateWriteTransition,
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> _DirectDecisionDagEntryObservation:
    """Bind a direct state writer to the internal DAG node it actually enters.

    The source's concrete state is replayed with the existing snapshot constant
    transfer.  This receipt therefore scopes routing to the physical edge
    without trusting a root-scoped interval row or adding another evaluator.
    """

    if transition_uses_terminal_stack_alias_guard(transition):
        # This proof owns a source-sensitive edge into a shared semantic guard:
        # the same guard writes through an alias only on the terminal source
        # path.  Its state comparison does not make it a dispatcher-internal
        # entry, and treating it as one discards the guard-preserving redirect.
        return _DirectDecisionDagEntryObservation(False)
    if transition.via_block is None:
        return _DirectDecisionDagEntryObservation(False)
    entry_serial = int(transition.via_block)
    if entry_serial == int(decision_dag.root):
        return _DirectDecisionDagEntryObservation(False)

    source = _stable_flow_block(flow_graph, int(transition.write_block))
    entry = _stable_flow_block(flow_graph, entry_serial)
    if source is None or entry is None:
        return _DirectDecisionDagEntryObservation(
            entry_serial in decision_dag.nodes
        )
    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    current = _current_u32_route_comparison(
        flow_graph,
        entry_serial,
        expected_identities=expected_identities,
    )
    if current is None:
        observed = bool(
            entry_serial in decision_dag.nodes
            or _raw_branch_mentions_state_identity(
                entry,
                expected_identities,
            )
        )
        return _DirectDecisionDagEntryObservation(observed)
    if (
        tuple(int(target) for target in source.succs) != (entry_serial,)
        or int(source.serial) not in tuple(int(pred) for pred in entry.preds)
        or transition.next_state is None
        or transition.proof is None
        or not transition.proof.trusted
        or transition.proof.oracle_kind != _FIXPOINT_ORACLE
        or transition.proof.kind
        not in {"predecessor_partitioned", "multi_entry_global_fold"}
    ):
        return _DirectDecisionDagEntryObservation(True)

    route_forest = _current_u32_route_forest_entry(
        flow_graph,
        entry_serial,
        decision_dag,
        expected_identities=expected_identities,
    )
    if route_forest is None:
        return _DirectDecisionDagEntryObservation(True)
    comparison, state_identity, entry_ea, branch_ea = current

    projected = InstructionProjection.from_block(source)
    if not any(
        instruction.result is not None
        and int(instruction.result.size) == 4
        and storage_identity_from_varnode(instruction.result) == state_identity
        for instruction in projected
    ):
        return _DirectDecisionDagEntryObservation(True)
    transfer_stkoff = (
        int(state_var_stkoff)
        if state_var_stkoff is not None
        else -(1 << 63)
    )
    out_stk, out_reg = _transfer_snapshot_constant_block(
        source,
        {},
        {},
        transfer_stkoff,
    )
    if state_identity.kind is StorageIdentityKind.STACK:
        current_state = out_stk.get(int(state_identity.offset))
    elif state_identity.kind is StorageIdentityKind.REGISTER:
        current_state = out_reg.get(int(state_identity.offset))
    else:
        current_state = None
    normalized_state = int(transition.next_state) & 0xFFFFFFFF
    if current_state is None or (int(current_state) & 0xFFFFFFFF) != normalized_state:
        return _DirectDecisionDagEntryObservation(True)

    return _DirectDecisionDagEntryObservation(
        True,
        _ExactDirectDecisionDagEntry(
            normalized_state=normalized_state,
            source_serial=int(source.serial),
            source_ea=int(source.native_start_ea or source.start_ea),
            entry_serial=entry_serial,
            entry_ea=entry_ea,
            branch_ea=branch_ea,
            state_identity=state_identity,
            comparison=comparison,
            comparisons=tuple(sorted(route_forest.nodes.items())),
            aliases=tuple(sorted(route_forest.aliases.items())),
        ),
    )


def _is_semantic_internal_route_leaf(
    block: BlockSnapshot | None,
    *,
    expected_state_identities: frozenset[StorageIdentity],
) -> bool:
    """Recognize an explicit semantic boundary below a physical route forest.

    A sibling comparison forest can terminate at a conditional over a different
    program variable rather than at a handler listed by the selected root DAG.
    That conditional is semantic control flow, not dispatcher plumbing.  Keep
    this deliberately narrow: effects/memory are semantic, as is a real
    conditional with at least one typed operand identity disjoint from the
    recovered state cell.  Empty blocks, gotos, NOP/vendor shells, and malformed
    comparisons remain untrusted leaves.
    """

    if block is None:
        return False
    for instruction in InstructionProjection.from_block(block):
        if instruction.effects or instruction.memory is not None:
            return True
        control = instruction.control
        if control is None or control.predicate is None:
            continue
        operand_identities = frozenset(
            identity
            for operand in instruction.inputs
            if (identity := storage_identity_from_varnode(operand)) is not None
        )
        if operand_identities and operand_identities.isdisjoint(
            expected_state_identities
        ):
            return True
    return False


def _pure_move_instruction(instruction: Instruction) -> bool:
    return bool(
        instruction.operation is ValueOpKind.MOVE
        and not instruction.effects
        and instruction.memory is None
        and instruction.control is None
        and len(instruction.inputs) == 1
        and instruction.result is not None
    )


def _exact_state_normalizer_step(
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    leaf_serial: int,
    *,
    expected_state_identities: frozenset[StorageIdentity],
) -> _ExactStateNormalizerStep:
    """Recognize exactly ``CONST -> carrier -> state -> DAG``.

    A normal decision-DAG leaf remains semantic.  The only leaf considered a
    normalizer candidate is one with a typed constant carrier write whose sole
    successor contains the matching carrier-to-state move and whose sole
    successor is a DAG node.  Effects/unknown operations in either candidate
    block invalidate the route instead of being skipped.
    """

    normalizer = _stable_flow_block(flow_graph, int(leaf_serial))
    if normalizer is None or tuple(int(s) for s in normalizer.succs) == ():
        return _ExactStateNormalizerStep(False, False)
    if len(normalizer.succs) != 1:
        return _ExactStateNormalizerStep(False, False)
    feeder_serial = int(normalizer.succs[0])
    feeder = _stable_flow_block(flow_graph, feeder_serial)
    if feeder is None or len(feeder.succs) != 1:
        return _ExactStateNormalizerStep(False, False)
    dag_entry = int(feeder.succs[0])
    if dag_entry not in decision_dag.nodes:
        return _ExactStateNormalizerStep(False, False)

    normalizer_instructions = InstructionProjection.from_block(normalizer)
    feeder_instructions = InstructionProjection.from_block(feeder)
    constant_moves = tuple(
        instruction
        for instruction in normalizer_instructions
        if instruction.operation is ValueOpKind.MOVE
        and len(instruction.inputs) == 1
        and instruction.inputs[0].space is Space.CONST
        and instruction.result is not None
        and instruction.result.space in {Space.REGISTER, Space.TEMP}
        and int(instruction.inputs[0].size) > 0
        and int(instruction.inputs[0].size) == int(instruction.result.size)
    )
    matching_pairs = tuple(
        (constant_move, feeder_move)
        for constant_move in constant_moves
        for feeder_move in feeder_instructions
        if feeder_move.operation is ValueOpKind.MOVE
        and len(feeder_move.inputs) == 1
        and feeder_move.inputs[0] == constant_move.result
        and feeder_move.result is not None
        and feeder_move.result.space in {
            Space.STACK,
            Space.REGISTER,
            Space.LVAR,
            Space.TEMP,
        }
        and int(feeder_move.result.size) == int(constant_move.result.size)
    )
    if not matching_pairs:
        return _ExactStateNormalizerStep(False, False)

    # A normal handler commonly ends in an explicit pure GOTO after writing its
    # next state.  That is a semantic DAG leaf, not a hidden normalizer.  Any
    # effectful/unknown extra instruction, however, makes an otherwise matching
    # skipped-normalizer shape unsafe and therefore invalid.
    if len(normalizer_instructions) != 1:
        extras_are_pure_gotos = all(
            instruction.control is not None
            and instruction.control.transfer is ControlTransferKind.GOTO
            and not instruction.effects
            and instruction.memory is None
            for instruction in normalizer_instructions
            if instruction not in constant_moves
        )
        if extras_are_pure_gotos and len(constant_moves) == 1:
            return _ExactStateNormalizerStep(False, False)
        return _ExactStateNormalizerStep(True, False)
    if len(feeder_instructions) != 1 or len(matching_pairs) != 1:
        return _ExactStateNormalizerStep(True, False)

    constant_move, feeder_move = matching_pairs[0]
    if not _pure_move_instruction(constant_move) or not _pure_move_instruction(
        feeder_move
    ):
        return _ExactStateNormalizerStep(True, False)
    bits = int(constant_move.result.size) * 8
    if (
        bits <= 0
        or bits != int(decision_dag.width)
        or int(feeder_move.result.size) != 4
        or storage_identity_from_varnode(feeder_move.result)
        not in expected_state_identities
    ):
        return _ExactStateNormalizerStep(True, False)
    return _ExactStateNormalizerStep(
        True,
        True,
        int(constant_move.inputs[0].offset) & ((1 << bits) - 1),
        feeder_serial,
        dag_entry,
    )


def _route_state_through_decision_dag(
    transition: StateWriteTransition,
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    entry_serial: int | None = None,
    semantic_transition_sources: frozenset[int] = frozenset(),
) -> _DecisionDagStateRoute | None:
    """Route one transition state from its exact comparison entry."""

    if transition.next_state is None or int(decision_dag.width) != 32:
        return None
    state = int(transition.next_state) & 0xFFFFFFFF
    root = int(decision_dag.root if entry_serial is None else entry_serial)
    if root not in {
        int(serial) for serial in (*decision_dag.nodes, *decision_dag.aliases)
    }:
        return None
    expected_state_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    seen: set[tuple[int, int]] = set()
    targets: set[int] = set()
    for _ in range(8):
        bound_route = _bound_decision_dag_route(
            flow_graph,
            decision_dag,
            state,
            root=root,
        )
        if bound_route is None:
            return None
        target, _path = bound_route
        targets.add(target)
        step = _exact_state_normalizer_step(
            flow_graph,
            decision_dag,
            target,
            expected_state_identities=expected_state_identities,
        )
        if not step.observed:
            return _DecisionDagStateRoute(target, frozenset(targets))
        if not step.valid and target in semantic_transition_sources:
            # A handler may contain real semantic work and end with the same
            # carrier/state suffix as a pure normalizer.  When this exact leaf
            # is independently present as a recovered transition source in the
            # same fragment, keep the incoming route at the handler.  Its own
            # outgoing transition is reconciled separately, so any bad state
            # write, carrier, DAG path, or provider evidence still rejects the
            # complete fragment atomically.
            return _DecisionDagStateRoute(target, frozenset(targets))
        if (
            not step.valid
            or step.state is None
            or step.feeder_serial is None
            or step.dag_entry_serial is None
            or transition.via_block is None
            or int(transition.via_block) != int(step.feeder_serial)
        ):
            return None
        key = (target, int(step.state))
        if key in seen:
            return None
        seen.add(key)
        state = int(step.state)
        root = int(step.dag_entry_serial)
    return None


def _transition_has_exact_route_authority(transition: StateWriteTransition) -> bool:
    proof = transition.proof
    if proof is None:
        return False
    if proof.oracle_kind == "native_bound_transition_route":
        return True
    if proof.kind.startswith("computed_goto_") or "materialized" in proof.kind:
        return True
    return bool(
        set(proof.route_source_kinds)
        & {"exact", "materialized", "native_bound"}
    )


def _prior_exact_route_sources(transition: StateWriteTransition) -> set[str]:
    proof = transition.proof
    if proof is None:
        return set()
    sources = set(proof.route_source_kinds)
    if proof.oracle_kind == "native_bound_transition_route":
        sources.add("native_bound")
    elif proof.kind.startswith("computed_goto_") or "materialized" in proof.kind:
        sources.add("materialized")
    return sources




def _is_weak_region_seeded_interval_state(
    transition: StateWriteTransition,
) -> bool:
    """Return whether carrier evidence may replace this coarse state hint.

    ``region_seeded`` interval-only rows describe the state inferred at a
    region boundary; they are not a source-local definition.  Every stronger,
    mixed, malformed, or unattributed provider remains conflict-authoritative.
    """

    proof = transition.proof
    return bool(
        proof is not None
        and proof.trusted
        and proof.oracle_kind == "region_partitioned_fixpoint"
        and proof.kind == "region_seeded"
        and tuple(proof.route_source_kinds) == ("interval",)
    )


def _dispatcher_provider_targets(
    dispatcher: object,
    state: int,
    *,
    condition_chain_handlers: frozenset[int],
) -> tuple[frozenset[int], frozenset[str]] | None:
    """Collect exact/range targets without precedence; malformed conflicts fail."""

    normalized = int(state) & 0xFFFFFFFF
    targets: set[int] = set()
    sources: set[str] = set()
    try:
        resolve_target = getattr(dispatcher, "resolve_target", None)
        lookup_row = getattr(dispatcher, "lookup_row", None)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return None
    try:
        exact = resolve_target(normalized) if callable(resolve_target) else None
        row = lookup_row(normalized) if callable(lookup_row) else None
        interval = None if row is None else getattr(row, "target", None)
        if exact is not None:
            exact_i = int(exact)
            if not condition_chain_handlers or exact_i in condition_chain_handlers:
                targets.add(exact_i)
                sources.add("exact")
        if interval is not None:
            interval_i = int(interval)
            if not condition_chain_handlers or interval_i in condition_chain_handlers:
                targets.add(interval_i)
                sources.add("interval")
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return None
    if len(targets) > 1:
        return None
    return frozenset(targets), frozenset(sources)


def _reject_decision_dag_reconciliation(
    reason: str,
    flow_graph: FlowGraph,
    transition: StateWriteTransition,
) -> None:
    """Publish the exact fragment-atomic DecisionDag rejection boundary."""

    source = flow_graph.get_block(int(transition.write_block))
    via = (
        flow_graph.get_block(int(transition.via_block))
        if transition.via_block is not None
        else None
    )
    source_ea = (
        0
        if source is None
        else int(source.native_start_ea or source.start_ea)
    )
    via_label = (
        "none"
        if via is None
        else (
            f"blk{int(via.serial)}@0x"
            f"{int(via.native_start_ea or via.start_ea):X}"
        )
    )
    logger.warning(
        "decision-DAG reconciliation rejected fragment: reason=%s "
        "source=blk%d@0x%X via=%s state=%s",
        reason,
        int(transition.write_block),
        source_ea,
        via_label,
        (
            "none"
            if transition.next_state is None
            else f"0x{int(transition.next_state) & 0xFFFFFFFF:08X}"
        ),
    )
    return None


def _fully_partitioned_state_transform_glues(
    transitions: tuple[StateWriteTransition, ...],
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> frozenset[int]:
    """Find shared transforms exhaustively split by concrete source rows.

    This grants omission authority only for a redundant unresolved aggregate
    row.  Every concrete source partition must still obtain its own exact
    transform, DAG, and provider proof during reconciliation.
    """

    by_glue: dict[int, set[int]] = {}
    for transition in transitions:
        proof = transition.proof
        if (
            transition.via_block is None
            or transition.next_state is None
            or proof is None
            or not proof.trusted
            or proof.oracle_kind != _FIXPOINT_ORACLE
            or proof.kind != "transitive_glue_partitioned"
        ):
            continue
        by_glue.setdefault(int(transition.via_block), set()).add(
            int(transition.write_block)
        )

    complete: set[int] = set()
    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    for glue_serial, sources in by_glue.items():
        glue = _stable_flow_block(flow_graph, glue_serial)
        if (
            glue is None
            or not observes_u32_state_transform_feeder_candidate(
                flow_graph,
                glue_serial,
            )
            or set(int(pred) for pred in glue.preds) != sources
            or any(
                (source := _stable_flow_block(flow_graph, source_serial)) is None
                or tuple(int(target) for target in source.succs) != (glue_serial,)
                for source_serial in sources
            )
            or len(glue.succs) != 1
        ):
            continue
        state_feeder_serial = int(glue.succs[0])
        state_feeder = _stable_flow_block(flow_graph, state_feeder_serial)
        if (
            state_feeder is None
            or glue_serial not in tuple(int(pred) for pred in state_feeder.preds)
            or not observes_u32_state_feeder_candidate(
                flow_graph,
                state_feeder_serial,
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
            )
            or len(state_feeder.succs) != 1
            or int(state_feeder.succs[0]) not in decision_dag.nodes
            or not expected_identities
        ):
            continue
        complete.add(glue_serial)
    return frozenset(complete)


def _reconcile_transition_routes_with_decision_dag(
    transitions: tuple[StateWriteTransition, ...],
    flow_graph: FlowGraph,
    dispatcher: object,
    decision_dag: DecisionDag,
    materialized_state_routes: tuple[MaterializedStateRoute, ...],
    *,
    condition_chain_handlers: frozenset[int],
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    candidate_prefix_authority: CandidateScopedPrefixAuthority | None = None,
) -> tuple[StateWriteTransition, ...] | None:
    """Recompute each concrete route from immutable source/DAG evidence."""

    terminal_guard_source_edges = {
        (
            int(transition.write_block),
            int(transition.via_block)
            if transition.via_block is not None
            else -1,
        )
        for transition in transitions
        if transition_uses_terminal_stack_alias_guard(transition)
    }
    if terminal_guard_source_edges:
        # The guarded alias proof is source-sensitive authority for this exact
        # physical edge.  A generic fold can also observe the pre-store state
        # on the same edge; reconciling that sibling first would reject the
        # fragment before the guard-preserving transition reaches the emitter.
        transitions = tuple(
            transition
            for transition in transitions
            if transition_uses_terminal_stack_alias_guard(transition)
            or (
                int(transition.write_block),
                int(transition.via_block)
                if transition.via_block is not None
                else -1,
            )
            not in terminal_guard_source_edges
        )

    if candidate_prefix_authority is None:
        prefix_observation = _observe_candidate_scoped_prefix(
            flow_graph,
            decision_dag,
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
        )
        if prefix_observation.status is _CandidatePrefixStatus.INVALID:
            return None
        prefix_authority = prefix_observation.authority
    else:
        if not _revalidate_candidate_scoped_prefix_authority(
            flow_graph,
            candidate_prefix_authority,
            root_serial=int(decision_dag.root),
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
        ):
            return None
        prefix_authority = candidate_prefix_authority
    semantic_transition_sources = frozenset(
        int(transition.write_block)
        for transition in transitions
        if transition.next_state is not None
        and flow_graph.get_block(int(transition.write_block)) is not None
    )
    fully_partitioned_transform_glues = _fully_partitioned_state_transform_glues(
        transitions,
        flow_graph,
        decision_dag,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    reconciled: list[StateWriteTransition] = []
    for transition in transitions:
        if (
            transition.next_state is None
            and int(transition.write_block) in fully_partitioned_transform_glues
        ):
            # This is the unresolved aggregate row for a shared transform
            # whose complete concrete source partition is present below.
            # Each source row is independently re-proven; the aggregate must
            # not survive as a synthetic return edge.
            continue
        if transition.next_state is None and observes_u32_state_transform_feeder_candidate(
            flow_graph,
            int(transition.write_block),
        ):
            # A transform-shaped glue with an incomplete source partition is
            # not terminal authority.  Retaining its unresolved row as a
            # return would mix an aggregate recovery sentinel into the route
            # plan, so fail the fragment atomically.
            return _reject_decision_dag_reconciliation(
                "incomplete_state_transform_partition",
                flow_graph,
                transition,
            )
        if transition.next_state is None and transition.is_return:
            # An independently classified terminal edge has no state value to
            # route through the comparison DAG.  Its concrete STOP target may
            # be implicit in the dispatcher's default route, so retain both
            # explicit and targetless return sentinels byte-identically.
            reconciled.append(transition)
            continue
        if transition_uses_terminal_stack_alias_guard(transition):
            # This proof already binds the exact source-sensitive edge through
            # the shared guard to its terminal successor.  Routing its state
            # from the dispatcher root is the wrong question: the guarded
            # store and branch occur before that re-entry and deliberately
            # select the terminal arm.  Preserve the stronger receipt after
            # the generic sibling on this edge has been removed above.
            reconciled.append(transition)
            continue
        source = flow_graph.get_block(int(transition.write_block))
        source_successors = (
            () if source is None else tuple(int(target) for target in source.succs)
        )
        feeder_serial = (
            int(transition.via_block)
            if transition.via_block is not None
            else (source_successors[0] if len(source_successors) == 1 else None)
        )
        prefix_entry = (
            _CandidatePrefixTransitionEntry(False)
            if prefix_authority is None
            else _candidate_prefix_transition_entry(
                flow_graph,
                transition,
                prefix_authority,
            )
        )
        if prefix_entry is None:
            return _reject_decision_dag_reconciliation(
                "candidate_prefix_entry",
                flow_graph,
                transition,
            )
        if (
            prefix_authority is not None
            and prefix_entry.enters_prefix
            and transition.next_state is not None
            and transition.proof is not None
            and transition.proof.oracle_kind == "region_partitioned_fixpoint"
            and transition.proof.kind == "predecessor_partitioned"
            and not _candidate_prefix_selects_root(
                prefix_authority,
                int(transition.next_state),
            )
        ):
            # This exact physical source partition selects the prefix's
            # untouched sibling arm.  No redirect will be emitted, so the
            # feeder need not also be proven safe to bypass.  In particular,
            # semantic suffix instructions after the state assignment remain
            # on the original path instead of turning conservative omission
            # into a fragment-wide rejection.
            continue
        direct_entry_observation = (
            _DirectDecisionDagEntryObservation(False)
            if prefix_entry.enters_prefix
            else _observe_direct_internal_decision_dag_entry(
                transition,
                flow_graph,
                decision_dag,
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
            )
        )
        if direct_entry_observation.observed and direct_entry_observation.proof is None:
            return _reject_decision_dag_reconciliation(
                "direct_internal_dag_entry",
                flow_graph,
                transition,
            )
        direct_entry_proof = direct_entry_observation.proof
        required_comparison_serials = {
            int(serial) for serial in (*decision_dag.nodes, *decision_dag.aliases)
        }
        if prefix_entry.feeder_serial is not None and prefix_authority is not None:
            required_comparison_serials.add(int(prefix_authority.prefix_serial))
        transform_observed = bool(
            feeder_serial is not None
            and int(feeder_serial) != int(decision_dag.root)
            and int(feeder_serial) not in decision_dag.nodes
            and len(source_successors) == 1
            and source_successors[0] == int(feeder_serial)
            and observes_u32_state_transform_feeder_candidate(
                flow_graph,
                int(feeder_serial),
            )
        )
        transform_route_forest: DecisionDag | None = None
        if transform_observed and feeder_serial is not None:
            feeder = _stable_flow_block(flow_graph, int(feeder_serial))
            feeder_successors = (
                ()
                if feeder is None
                else tuple(int(target) for target in feeder.succs)
            )
            if (
                len(feeder_successors) == 1
                and feeder_successors[0] not in decision_dag.nodes
            ):
                comparison_entry = feeder_successors[0]
                transform_route_forest = _current_u32_route_forest_entry(
                    flow_graph,
                    comparison_entry,
                    decision_dag,
                    expected_identities=expected_u32_state_identities(
                        state_var_stkoff=state_var_stkoff,
                        state_var_reg=state_var_reg,
                    ),
                )
                if transform_route_forest is not None:
                    required_comparison_serials.add(comparison_entry)
        carrier_observed = bool(
            feeder_serial is not None
            and int(feeder_serial) != int(decision_dag.root)
            and int(feeder_serial) not in decision_dag.nodes
            and (state_var_stkoff is not None or state_var_reg is not None)
            and len(source_successors) == 1
            and source_successors[0] == int(feeder_serial)
            and observes_u32_carrier_feeder_candidate(
                flow_graph,
                int(transition.write_block),
                int(feeder_serial),
            )
        )
        transform_proof: ExactStateTransformFeeder | None = None
        carrier_proof: ExactCarrierStateWrite | None = None
        if transform_observed:
            if not _has_exact_state_transform_proof(transition):
                return _reject_decision_dag_reconciliation(
                    "state_transform_hint",
                    flow_graph,
                    transition,
                )
            assert transition.next_state is not None
            transform_proof = prove_exact_u32_state_transform_feeder(
                flow_graph,
                int(transition.write_block),
                int(feeder_serial),
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
                required_comparison_serials=frozenset(required_comparison_serials),
                expected_state=int(transition.next_state),
            )
            if transform_proof is None:
                return _reject_decision_dag_reconciliation(
                    "state_transform_feeder_proof",
                    flow_graph,
                    transition,
                )
        elif carrier_observed:
            carrier_proof = prove_exact_u32_carrier_state_write(
                flow_graph,
                int(transition.write_block),
                int(feeder_serial),
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
                required_comparison_serials=frozenset(required_comparison_serials),
            )
            if carrier_proof is None:
                return _reject_decision_dag_reconciliation(
                    "carrier_feeder_proof",
                    flow_graph,
                    transition,
                )

        effective = transition
        source_carrier_filled = False
        weak_state_superseded = False
        if carrier_proof is not None:
            carrier_state = int(carrier_proof.state) & 0xFFFFFFFF
            if (
                transition.next_state is not None
                and (int(transition.next_state) & 0xFFFFFFFF) != carrier_state
            ):
                if not _is_weak_region_seeded_interval_state(transition):
                    return _reject_decision_dag_reconciliation(
                        "carrier_state_disagreement",
                        flow_graph,
                        transition,
                    )
                weak_state_superseded = True
            source_carrier_filled = transition.next_state is None or weak_state_superseded
            effective = replace(
                transition,
                next_state=carrier_state,
                target_handler=None if weak_state_superseded else transition.target_handler,
                via_block=int(carrier_proof.feeder_serial),
                preserve_via_block=bool(carrier_proof.requires_feeder_clone),
            )

        entered_candidate_prefix = False
        if prefix_authority is not None:
            effective_prefix_entry = _candidate_prefix_transition_entry(
                flow_graph,
                effective,
                prefix_authority,
            )
            if effective_prefix_entry is None:
                return _reject_decision_dag_reconciliation(
                    "effective_candidate_prefix_entry",
                    flow_graph,
                    effective,
                )
            if effective_prefix_entry.enters_prefix:
                if effective.next_state is None:
                    return _reject_decision_dag_reconciliation(
                        "candidate_prefix_missing_state",
                        flow_graph,
                        effective,
                    )
                if not _candidate_prefix_selects_root(
                    prefix_authority,
                    int(effective.next_state),
                ):
                    # This physical edge enters the comparison prefix, but its
                    # concrete state selects the untouched sibling arm.  Omit
                    # the redirect rather than routing it from the downstream
                    # DAG root it never reaches.
                    continue
                if (
                    effective.proof is None
                    or (
                        not effective.proof.trusted
                        and transform_proof is None
                        and carrier_proof is None
                    )
                ):
                    return _reject_decision_dag_reconciliation(
                        "candidate_prefix_untrusted_state",
                        flow_graph,
                        effective,
                    )
                entered_candidate_prefix = True

        route_entry = int(decision_dag.root)
        exact_comparison_entry = (
            transform_proof.comparison_entry_serial
            if transform_proof is not None
            else (
                carrier_proof.comparison_entry_serial
                if carrier_proof is not None
                else None
            )
        )
        if (
            exact_comparison_entry is not None
            and int(exact_comparison_entry)
            in {*decision_dag.nodes, *decision_dag.aliases}
        ):
            route_entry = int(exact_comparison_entry)
        elif transform_route_forest is not None and exact_comparison_entry is not None:
            route_entry = int(exact_comparison_entry)
        elif direct_entry_proof is not None:
            route_entry = int(direct_entry_proof.entry_serial)
        route_dag = (
                DecisionDag(
                    32,
                    dict(direct_entry_proof.comparisons),
                    root=int(direct_entry_proof.entry_serial),
                    aliases=dict(direct_entry_proof.aliases),
                )
            if direct_entry_proof is not None
            else (
                transform_route_forest
                if transform_route_forest is not None
                else decision_dag
            )
        )
        route = _route_state_through_decision_dag(
            effective,
            flow_graph,
            route_dag,
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
            entry_serial=route_entry,
            semantic_transition_sources=semantic_transition_sources,
        )
        if route is None or effective.next_state is None:
            return _reject_decision_dag_reconciliation(
                "decision_dag_route",
                flow_graph,
                effective,
            )
        state = int(effective.next_state) & 0xFFFFFFFF

        exact_targets: set[int] = set()
        authority_sources: set[str] = set()
        prior_exact = _transition_has_exact_route_authority(effective)
        if prior_exact and effective.target_handler is not None:
            exact_targets.add(int(effective.target_handler))
            authority_sources.update(_prior_exact_route_sources(effective))

        route_sources = {int(effective.write_block)}
        if effective.via_block is not None:
            route_sources.add(int(effective.via_block))
        materialized_targets = {
            int(item.target_handler_serial)
            for item in materialized_state_routes
            if int(item.source_block_serial) in route_sources
            and (int(item.state_constant) & 0xFFFFFFFF) == state
        }
        if len(materialized_targets) > 1:
            return _reject_decision_dag_reconciliation(
                "materialized_route_conflict",
                flow_graph,
                effective,
            )
        if materialized_targets:
            exact_targets.update(materialized_targets)
            authority_sources.add("materialized")

        physical_route_forest = bool(
            direct_entry_proof is not None or transform_route_forest is not None
        )
        if not physical_route_forest:
            provider = _dispatcher_provider_targets(
                dispatcher,
                state,
                condition_chain_handlers=condition_chain_handlers,
            )
            if provider is None:
                return _reject_decision_dag_reconciliation(
                    "dispatcher_provider_conflict",
                    flow_graph,
                    effective,
                )
            provider_targets, provider_sources = provider
            exact_targets.update(provider_targets)
            authority_sources.update(provider_sources)
        else:
            # The dispatcher providers describe routes from the selected DAG
            # root.  This transition has already bypassed that root, so those
            # rows are out of scope; the current physical entry/path is the
            # route authority.  Source-bound materialized evidence above still
            # participates in consensus.
            authority_sources.add("internal_decision_dag_entry")
            route_target_block = flow_graph.get_block(int(route.target))
            expected_state_identities = expected_u32_state_identities(
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
            )
            route_target_writes_state = bool(
                route_target_block is not None
                and any(
                    instruction.result is not None
                    and int(instruction.result.size) == 4
                    and storage_identity_from_varnode(instruction.result)
                    in expected_state_identities
                    for instruction in InstructionProjection.from_block(
                        route_target_block
                    )
                )
            )
            if (
                condition_chain_handlers
                and int(route.target) not in condition_chain_handlers
                and not _is_stop_block(route_target_block)
                and not route_target_writes_state
                and not _is_semantic_internal_route_leaf(
                    route_target_block,
                    expected_state_identities=expected_state_identities,
                )
            ):
                return _reject_decision_dag_reconciliation(
                    "internal_dag_entry_nonhandler",
                    flow_graph,
                    effective,
                )
        if any(target not in route.certified_targets for target in exact_targets):
            return _reject_decision_dag_reconciliation(
                "route_authority_disagreement",
                flow_graph,
                effective,
            )
        if (
            prior_exact
            and not physical_route_forest
            and effective.target_handler is not None
            and int(effective.target_handler) == int(route.target)
        ):
            resolved_exact = (
                _attach_candidate_prefix_provenance(
                    effective,
                    prefix_authority,
                )
                if entered_candidate_prefix and prefix_authority is not None
                else effective
            )
            if transform_proof is not None:
                resolved_exact = _attach_state_transform_feeder_provenance(
                    resolved_exact,
                    transform_proof,
                )
            if carrier_proof is not None and carrier_proof.requires_feeder_clone:
                resolved_exact = _attach_preserved_feeder_clone_provenance(
                    resolved_exact
                )
            reconciled.append(resolved_exact)
            continue

        transform_hint_upgraded = bool(
            transform_proof is not None
            and transition.proof is not None
            and not transition.proof.trusted
        )
        if source_carrier_filled:
            reason = "exact_source_carrier_u32;decision_dag_final_route"
            if weak_state_superseded:
                reason += (
                    ";superseded="
                    "region_partitioned_fixpoint:region_seeded:interval"
                )
            proof = TransitionProof(
                _SOURCE_CARRIER_DAG_ORACLE,
                _SOURCE_CARRIER_DAG_KIND,
                True,
                reason=reason,
                route_source_kinds=("decision_dag", "source_carrier"),
            )
        elif transform_hint_upgraded:
            proof = TransitionProof(
                _STATE_TRANSFORM_DAG_ORACLE,
                _STATE_TRANSFORM_DAG_KIND,
                True,
                reason="exact_state_transform;decision_dag_final_route",
                route_source_kinds=tuple(
                    sorted({"decision_dag", *authority_sources})
                ),
            )
        else:
            prior_reason = (
                effective.proof.reason
                if prior_exact and effective.proof is not None
                else ""
            )
            reason = (
                "internal_decision_dag_entry;decision_dag_final_route"
                if physical_route_forest
                else "decision_dag_final_route"
            )
            if prior_reason:
                reason += f";prior={prior_reason}"
            proof = TransitionProof(
                _DAG_RECONCILIATION_ORACLE,
                _DAG_RECONCILIATION_KIND,
                True,
                reason=reason,
                route_source_kinds=tuple(sorted({"decision_dag", *authority_sources})),
            )
        resolved_transition = replace(
            effective,
            target_handler=int(route.target),
            is_return=_is_stop_block(flow_graph.get_block(int(route.target))),
            proof=proof,
        )
        if entered_candidate_prefix and prefix_authority is not None:
            resolved_transition = _attach_candidate_prefix_provenance(
                resolved_transition,
                prefix_authority,
            )
        if transform_proof is not None:
            resolved_transition = _attach_state_transform_feeder_provenance(
                resolved_transition,
                transform_proof,
            )
        if carrier_proof is not None and carrier_proof.requires_feeder_clone:
            resolved_transition = _attach_preserved_feeder_clone_provenance(
                resolved_transition
            )
        reconciled.append(resolved_transition)
    return tuple(reconciled)




def resolve_materialized_indirect_transfer_targets(
    transitions: tuple[StateWriteTransition, ...],
    flow_graph: FlowGraph,
    dispatcher,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    materialized_state_routes: tuple[MaterializedStateRoute, ...] = (),
    condition_chain_dag: DecisionDag | None = None,
    condition_chain_handlers: frozenset[int] = frozenset(),
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
    candidate_prefix_authority: CandidateScopedPrefixAuthority | None = None,
) -> tuple[StateWriteTransition, ...]:
    """Reconnect concrete router misses using resolver-materialization proof.

    Exact dispatcher routes (including default/STOP rows) remain authoritative.
    Only a concrete state whose router lookup is absent can be upgraded, and
    only when a singleton resolver target is anchored in the transition source
    and maps uniquely onto this FlowGraph.  Every other transition is returned
    byte-identically, including unresolved and terminal transitions.
    """
    if condition_chain_dag is not None and condition_chain_dag.nodes:
        reconciled = _reconcile_transition_routes_with_decision_dag(
            transitions,
            flow_graph,
            dispatcher,
            condition_chain_dag,
            materialized_state_routes,
            condition_chain_handlers=condition_chain_handlers,
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
            candidate_prefix_authority=candidate_prefix_authority,
        )
        if reconciled is None:
            materialized_midtree_refinement = bool(
                transfers
                and not materialized_state_routes
            )
            if not materialized_midtree_refinement:
                return ()
            # A legacy materialized-indirect transfer intentionally refines a
            # false-terminal/default transition below.  That shape is outside
            # the source-carrier DAG reconciliation contract, so preserve the
            # original tuple and let the existing materialization proof decide
            # it; actionable C-route conflicts remain fragment-atomic.
            reconciled = transitions
        transitions = reconciled
    if not transfers and not materialized_state_routes:
        return transitions
    comparison_evidence_active = bool(condition_chain_handlers)
    resolved: list[StateWriteTransition] = []
    for transition in transitions:
        # Native-bound routes are a distinct current-MBA authority.  Once the
        # enrichment helper has attached one, a computed-goto/materialization
        # refinement must not replace that proof or target.
        if (
            transition.proof is not None
            and transition.proof.oracle_kind == "native_bound_transition_route"
            and transition.proof.kind == "native_bound_route"
        ):
            resolved.append(transition)
            continue
        route_sources = (
            (int(transition.via_block), int(transition.write_block))
            if transition.via_block is not None
            else (int(transition.write_block),)
        )
        source_local_terminal_routes: set[tuple[int, int]] = set()
        for route in materialized_state_routes:
            if (
                route.proof_kind != "terminal_state_route"
                or int(route.source_block_serial) not in route_sources
            ):
                continue
            state_write = _source_local_constant_register_write(
                flow_graph,
                int(route.source_block_serial),
                state_var_reg,
            )
            if state_write is None or state_write != (
                int(route.state_constant) & 0xFFFFFFFF
            ):
                continue
            target = flow_graph.get_block(int(route.target_handler_serial))
            if target is not None and target.nsucc == 0:
                source_local_terminal_routes.add(
                    (
                        state_write,
                        int(route.target_handler_serial),
                    )
                )
        if len(source_local_terminal_routes) == 1:
            terminal_state, terminal_target = next(iter(source_local_terminal_routes))
            resolved.append(
                replace(
                    transition,
                    next_state=int(terminal_state),
                    target_handler=int(terminal_target),
                    is_return=True,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        "computed_goto_exact_terminal_delivery",
                        True,
                        reason="source_local_terminal_state_write",
                    ),
                )
            )
            continue
        state = transition.next_state
        explicit_terminal_targets: set[int] = set()
        if state is not None:
            normalized_state = int(state) & 0xFFFFFFFF
            for route in materialized_state_routes:
                if (
                    route.proof_kind != "terminal_state_route"
                    or int(route.source_block_serial) not in route_sources
                    or (int(route.state_constant) & 0xFFFFFFFF) != normalized_state
                ):
                    continue
                target = flow_graph.get_block(int(route.target_handler_serial))
                if target is not None and target.nsucc == 0:
                    explicit_terminal_targets.add(int(route.target_handler_serial))
        if len(explicit_terminal_targets) == 1:
            resolved.append(
                replace(
                    transition,
                    target_handler=next(iter(explicit_terminal_targets)),
                    is_return=True,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        "computed_goto_exact_terminal_delivery",
                        True,
                        reason="explicit_source_state_terminal_route",
                    ),
                )
            )
            continue
        default = dispatcher.default_target
        routed = (
            _resolved_dispatcher_target(dispatcher, int(state))
            if state is not None
            else None
        )
        exact_equality_target = None
        dispatcher_has_exact_point = False
        if state is not None:
            try:
                routed_row = dispatcher.lookup_row(int(state) & 0xFFFFFFFF)
            except AttributeError:
                routed_row = None
            dispatcher_has_exact_point = bool(
                routed_row is not None and int(routed_row.hi) == int(routed_row.lo) + 1
            )
            exact_equality_candidates = {
                int(target)
                for transfer in transfers
                if transfer.resolver_kind == "static_equality_route"
                and (
                    target := lookup_state_keyed_transfer_target(
                        flow_graph,
                        transfer,
                        int(state),
                        state_var_reg=state_var_reg,
                    )
                )
                is not None
            }
            if len(exact_equality_candidates) == 1:
                exact_equality_target = next(iter(exact_equality_candidates))
        exact_terminal_deliveries: set[int] = set()
        if state is not None:
            for transfer in transfers:
                if transfer.resolver_kind != "static_fixpoint":
                    continue
                target = lookup_state_keyed_transfer_target(
                    flow_graph,
                    transfer,
                    int(state),
                    state_var_reg=state_var_reg,
                )
                if target is None:
                    continue
                target_block = flow_graph.get_block(int(target))
                if target_block is not None and target_block.nsucc == 0:
                    exact_terminal_deliveries.add(int(target))
        if len(exact_terminal_deliveries) == 1:
            resolved.append(
                replace(
                    transition,
                    target_handler=next(iter(exact_terminal_deliveries)),
                    is_return=True,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        "computed_goto_exact_terminal_delivery",
                        True,
                        reason="static_patch_plan_selects_exact_terminal_arm",
                    ),
                )
            )
            continue
        terminal_router_miss = bool(
            transition.is_return
            and (
                transition.target_handler is None
                or (
                    default is not None
                    and int(transition.target_handler) == int(default)
                )
            )
        )
        has_exact_handler_route = (
            routed is not None
            and (default is None or int(routed) != int(default))
            and (
                not comparison_evidence_active
                or int(routed) in condition_chain_handlers
            )
        )
        is_default_terminal = (
            transition.target_handler is not None
            and default is not None
            and int(transition.target_handler) == int(default)
            and transition.is_return
        )
        if (
            state is None
            or (
                transition.target_handler is not None
                and not is_default_terminal
                and (
                    not comparison_evidence_active
                    or int(transition.target_handler) in condition_chain_handlers
                )
            )
            or not transition.is_return
            or has_exact_handler_route
        ):
            resolved.append(transition)
            continue
        exact_state_target = None
        for route_source in route_sources:
            exact_state_target = lookup_materialized_state_route(
                materialized_state_routes,
                source_block_serial=route_source,
                state_constant=int(state),
                handler_serials=condition_chain_handlers,
            )
            if exact_state_target is not None:
                break
        if exact_state_target is not None:
            resolved.append(
                replace(
                    transition,
                    target_handler=int(exact_state_target),
                    is_return=False,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        "computed_goto_state_route",
                        True,
                        reason="resolver_proven_materialized_state_route",
                    ),
                )
            )
            continue
        # A source-keyed MaterializedStateRoute is stronger than a global
        # state-keyed equality leaf: it proves the route for this exact state
        # write partition.  Consult the equality leaf only after that stronger
        # evidence is absent, and only to rescue a transition already classified
        # as terminal/unresolved.  Healthy coarse-router transitions remain
        # authoritative.
        if (
            exact_equality_target is not None
            and terminal_router_miss
            and not dispatcher_has_exact_point
        ):
            resolved.append(
                replace(
                    transition,
                    target_handler=int(exact_equality_target),
                    is_return=False,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        "computed_goto_exact_equality_route",
                        True,
                        reason="resolver_proven_exact_state_target_for_terminal_miss",
                    ),
                )
            )
            continue
        if not transfers:
            resolved.append(transition)
            continue
        if comparison_evidence_active:
            chain_target = route_materialized_transfer_chain(
                flow_graph,
                transfers,
                start_block=int(transition.write_block),
                state_constant=int(state),
                state_var_reg=state_var_reg,
                handler_serials=condition_chain_handlers,
            )
            if chain_target is not None:
                resolved.append(
                    replace(
                        transition,
                        target_handler=int(chain_target),
                        is_return=False,
                        proof=TransitionProof(
                            _FIXPOINT_ORACLE,
                            "computed_goto_logical_cfg",
                            True,
                            reason="resolver_proven_materialized_transfer_chain",
                        ),
                    )
                )
                continue
        candidates: set[int] = set()
        for transfer in transfers:
            target = lookup_state_keyed_transfer_target(
                flow_graph,
                transfer,
                int(state),
                state_var_reg=state_var_reg,
            )
            if target is None:
                target = lookup_singleton_transfer_target(
                    flow_graph,
                    transfer,
                    int(transition.write_block),
                    transition.via_block,
                )
            if target is None:
                continue
            if comparison_evidence_active:
                if condition_chain_dag is not None:
                    target = route_transfer_target_through_condition_chain(
                        flow_graph,
                        condition_chain_dag,
                        int(target),
                        int(state),
                        condition_chain_handlers,
                    )
                elif int(target) not in condition_chain_handlers:
                    target = None
            if target is not None:
                candidates.add(int(target))
        if len(candidates) != 1:
            resolved.append(transition)
            continue
        target = next(iter(candidates))
        resolved.append(
            replace(
                transition,
                target_handler=int(target),
                is_return=False,
                proof=TransitionProof(
                    _FIXPOINT_ORACLE,
                    "computed_goto_target",
                    True,
                    reason="resolver_proven_materialized_indirect_target",
                ),
            )
        )
    return tuple(resolved)


def transition_uses_terminal_stack_alias_guard(transition: object) -> bool:
    """Return whether one transition used the terminal guarded stack-alias proof."""

    proof = getattr(transition, "proof", None)
    return (
        proof is not None
        and getattr(proof, "oracle_kind", None) == _FIXPOINT_ORACLE
        and getattr(proof, "kind", None) in _TERMINAL_STACK_ALIAS_GUARD_KINDS
        and bool(getattr(proof, "trusted", False))
    )


def transitions_use_terminal_stack_alias_guard(transitions: object) -> bool:
    """Return whether recovery used the terminal guarded stack-alias state proof."""

    for transition in tuple(transitions or ()):
        if transition_uses_terminal_stack_alias_guard(transition):
            return True
    return False


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
    for insn in blk.insn_snapshots:
        left, right, dest = operand_storages(insn)
        l_kind, r_kind, d_kind = operand_kinds(insn)
        if _storage_dest_locator(dest, d_kind) != ("stk", soff):
            continue
        if (
            _storage_dest_locator(right, r_kind) is not None
            or _storage_const_value(right) is not None
        ):
            continue  # binary op (add/xor/...) -> not a pure copy
        lloc = _storage_dest_locator(left, l_kind)
        if lloc is not None and lloc[0] == "stk" and lloc[1] != soff:
            source = int(lloc[1])  # last copy into state_var wins
    return source


def _detect_global_state_var(flow_graph, dispatcher_entry_serial: int) -> int | None:
    """Return the global address the dispatcher compares as its state var, or ``None``.

    Hex-Rays can forward-substitute a ``state = global`` copy into the dispatcher
    so the loop header compares a *global* directly (Approov
    ``approov_vm_dispatcher`` at GLBOPT1: ``jz $qword_180021320, #0xF6A1F``).  The
    stack state-var detection then picks a now-dead decoy slot and every back-edge
    is unresolved.  When the dispatcher-entry compare reads a global, that global
    IS the effective state variable; return its address so the recovery folds the
    handlers' next-state writes to it.  Returns ``None`` for the ordinary
    stack/register state var (no behaviour change).
    """
    blk = flow_graph.get_block(int(dispatcher_entry_serial))
    if blk is None:
        return None
    for insn in blk.insn_snapshots:
        if not (
            insn.is_conditional_jump
            or insn.kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
        ):
            continue
        # The dispatcher head compares the state var: its compared operand (or a
        # nested compared subexpression) names the global.  Read the compared
        # operands off the canonical slot-aligned storage views (was ``insn.l`` /
        # ``insn.r``) -- a GLOBAL operand projects to ``Varnode(Space.GLOBAL,
        # gaddr, size)``; the storage view tolerates a partial/duck-typed live
        # operand exactly as the previous ``storage_identity_from_mop_snapshot``
        # path did (an unrecovered global folds to ``Space.UNKNOWN`` -> ``None``).
        left, right, _dest = operand_storages(insn)
        for storage in (left, right):
            g = _storage_global_offset(storage)
            if g is not None:
                return g
        # Nested compared sub-expression (was the ``sub_l`` / ``sub_r`` walk):
        # the projection flattens a SUBINSN branch operand's leaves to ``Varnode``
        # inputs, so a GLOBAL leaf surfaces as a ``Space.GLOBAL`` input.  Guarded
        # because a partial/duck-typed live operand cannot supply a full nested
        # tree -- mirroring the original ``_operand_gaddr`` try/except tolerance.
        try:
            inputs = project_instruction(insn).inputs
        except (AttributeError, TypeError, ValueError):
            continue
        for value in inputs:
            g = _storage_global_offset(value)
            if g is not None:
                return g
    return None


def _compute_foldable_global_reads(
    flow_graph, dispatcher_entry_serial: int, initial_handler_serial: int | None
):
    """Reaching-defs-sound ``{read_ea: {gaddr: init}}`` for data-dependent globals.

    Computed over EVERY global the function reads: a handler can compute its next
    state from a writable global it later mutates (Approov: ``state = (qword |=
    0xF6A20)``), and the read folds to the global's static ``.data`` initializer
    ONLY where reaching-defs proves no store reaches it.

    The reaching-defs is anchored at the INITIAL handler (the dispatcher's target
    for the entry state), with the dispatcher entry as a *barrier* whose incoming
    edges are cut.  A flattened handler routes back through the dispatcher by the
    state value, so on the raw CFG the initial handler's own back-edge would make
    its first read look store-reachable via an infeasible self-loop.  Anchoring at
    the initial handler + cutting the dispatcher gives the real straight-line
    execution prefix: the initial handler runs first, before any handler store, so
    its global read is store-free; every other handler is reached only through the
    (cut) dispatcher and is therefore NOT folded (its store-freeness is unproven --
    a prior handler may have mutated the global).  Sound per read site, strictly
    narrower than blanket ``fold_writable_constants``.  Empty when no initial
    handler is known or no IDB read seam.
    """
    if initial_handler_serial is None:
        return {}
    fetch = getattr(get_condition_chain_walkers(), "fetch_idb_value", None)
    if fetch is None:
        return {}
    return compute_initializer_stable_global_reads(
        flow_graph,
        fetch,
        barrier_serials={int(dispatcher_entry_serial)},
        entry_override=int(initial_handler_serial),
    )


def block_has_live_carrier_write(
    block: BlockSnapshot,
    state_var_stkoff: int | None = None,
    *,
    state_var_reg: int | None = None,
) -> bool:
    """``True`` if *block* writes a non-state value (a "carrier") besides the
    state-var write / control flow.

    A predecessor-partitioned back-edge ``via_block`` is normally pure state-glue:
    its only effect is the dispatcher-state write that the unflatten emitter folds
    away, so the emitter bypasses it (``ip -> route(state)``) and lets the orphaned
    block DCE.  But a conditional handler whose two arms write the next state in
    separate blocks and then *converge* on one shared block can carry a LIVE
    non-state assignment on that shared block (the Approov ``v4 = a1`` carrier that
    executes on BOTH arms before re-entering the dispatcher).  Bypassing such a
    block drops the carrier and corrupts the recovered value.

    Detected conservatively: the block holds at least one instruction that is not a
    goto / nop, whose destination is a stack/register/lvar slot *other than* the
    state-var slot (a side-effecting data write the bypass would silently drop), or
    a call (whose side effects must not be skipped).  Pure state-glue blocks (only
    the state write + goto, or only a widen of the state slot) return ``False`` and
    keep the existing bypass behaviour byte-identical.
    """
    if state_var_stkoff is None and state_var_reg is None:
        # Without either state identity there is no sound way to distinguish
        # the state-plumbing write from a live carrier.  Treat the block as
        # effectful so callers fail closed rather than bypassing unknown work.
        return True
    soff = int(state_var_stkoff) if state_var_stkoff is not None else None
    sreg = int(state_var_reg) if state_var_reg is not None else None
    for insn in block.insn_snapshots:
        if _is_goto_insn(insn) or _is_nop_insn(insn):
            continue
        if _is_call_insn(insn):
            return True
        _left, _right, dest = operand_storages(insn)
        _l_kind, _r_kind, d_kind = operand_kinds(insn)
        dloc = _storage_dest_locator(dest, d_kind)
        if dloc is None:
            continue  # no resolvable data destination (control flow / unknown)
        kind, ident = dloc
        if kind == "stk" and soff is not None and int(ident) == soff:
            continue  # the state-var write itself -- folded/bypassed as glue
        if kind == "reg" and sreg is not None and int(ident) == sreg:
            continue  # the state-var write itself -- folded/bypassed as glue
        return True  # a write to some other slot -> a live carrier
    return False


def _resolve_back_edge_states(
    flow_graph,
    *,
    dispatcher,
    state_var_stkoff: int,
    dispatcher_entry: int,
    max_depth: int,
    state_var_gaddr: int | None = None,
    foldable_global_reads: object | None = None,
    target_back_edges: frozenset[int] | None = None,
    _path_state_pop_budget: object | None = None,
) -> dict[int, dict[int | None, set[int]]]:
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

    ``state_var_gaddr`` / ``foldable_global_reads`` enable a *global* state
    variable (see :func:`recover_state_write_transitions_via_partitioned_fixpoint`):
    next-state writes/reads of that global are tracked/folded, and the recorded
    state is read from the gaddr key instead of the stack offset.
    """

    disp = int(dispatcher_entry)
    soff = int(state_var_stkoff)
    read_key = int(state_var_gaddr) if state_var_gaddr is not None else soff
    if _path_state_pop_budget is None:
        path_state_pop_budget = _SEEDED_PATH_STATE_POP_BUDGET
    else:
        if isinstance(_path_state_pop_budget, bool):
            raise TypeError("path-state pop budget must be an integer")
        try:
            path_state_pop_budget = operator.index(_path_state_pop_budget)
        except TypeError as error:
            raise TypeError("path-state pop budget must be an integer") from error
        if path_state_pop_budget < 0:
            raise ValueError("path-state pop budget must be non-negative")
    projection_cache = _SnapshotProjectionCache()
    region_entries: set[int] = {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None
    }
    entry = getattr(flow_graph, "entry_serial", None)
    if entry is not None:
        region_entries.add(int(entry))
    region_entries.discard(disp)

    # Region seeding is the penultimate provider.  When the higher-ranked
    # providers defer only selected physical back-edges, restrict this expensive
    # walk to their exact reverse ancestor slice.  The filtered slice is trusted
    # only for a fully reciprocal FlowGraph; any missing block or one-sided edge
    # falls back to the byte-identical legacy whole-graph walk.
    relevant_serials: frozenset[int] | None = None
    if target_back_edges is not None:
        targets = frozenset(int(serial) for serial in target_back_edges)
        reverse_seen: set[int] = set(targets)
        pending = list(sorted(targets, reverse=True))
        topology_consistent = True

        for serial in sorted(int(value) for value in flow_graph.blocks):
            block = flow_graph.get_block(serial)
            if block is None:
                topology_consistent = False
                break
            for succ in tuple(int(value) for value in block.succs):
                succ_block = flow_graph.get_block(succ)
                if succ_block is None or serial not in tuple(
                    int(value) for value in succ_block.preds
                ):
                    topology_consistent = False
                    break
            if not topology_consistent:
                break
            for pred in tuple(int(value) for value in block.preds):
                pred_block = flow_graph.get_block(pred)
                if pred_block is None or serial not in tuple(
                    int(value) for value in pred_block.succs
                ):
                    topology_consistent = False
                    break
            if not topology_consistent:
                break

        while pending and topology_consistent:
            serial = pending.pop()
            block = flow_graph.get_block(serial)
            if block is None:
                topology_consistent = False
                break
            if serial == disp:
                continue
            for pred in tuple(int(value) for value in block.preds):
                if pred not in reverse_seen:
                    reverse_seen.add(pred)
                    if pred != disp:
                        pending.append(pred)

        if topology_consistent:
            relevant_serials = frozenset(reverse_seen)
            region_entries.intersection_update(relevant_serials)

    # Region-entry seed: the dispatch key that routes to each region. A masked /
    # switch-table dispatcher (``switch(state & MASK)``) reaches handler ``H`` iff
    # ``state & MASK == key``, and the handler writes ``state = (state & ~MASK) | M``;
    # folding that write to ``M`` needs the incoming low bits, which ARE that key.
    # Seeding the state var with it lets the forward fold resolve the masked-OR/XOR
    # write that an empty seed cannot. Restricted to *point* rows (``hi == lo + 1``,
    # an exact single-state key) so range-row condition-chain routers (the equality-chain
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
    consumed_path_states = 0

    def _target_identity(serial: int) -> str:
        block = flow_graph.get_block(int(serial))
        if block is None:
            return f"blk{int(serial)}@<unknown>"
        native_ea = getattr(block, "native_start_ea", None)
        ea = int(block.start_ea if native_ea is None else native_ea)
        return f"blk{int(serial)}@0x{ea:X}"

    for start in sorted(region_entries):
        seed_stk = {soff: entry_seed[start]} if start in entry_seed else {}
        stack: list[tuple[int, dict, dict, frozenset[int], int, int | None]] = [
            (start, seed_stk, {}, frozenset({start}), 0, None)
        ]
        while stack:
            if consumed_path_states >= path_state_pop_budget:
                logger.warning(
                    "region-seeded DFS path-state budget exhausted: "
                    "target_back_edges=%s budget=%d consumed=%d",
                    (
                        None
                        if target_back_edges is None
                        else tuple(
                            _target_identity(int(value))
                            for value in sorted(target_back_edges)
                        )
                    ),
                    path_state_pop_budget,
                    consumed_path_states,
                )
                return {}
            consumed_path_states += 1
            blk_serial, in_stk, in_reg, visited, depth, parent = stack.pop()
            block = flow_graph.get_block(blk_serial)
            if block is None:
                continue
            out_stk, out_reg = _transfer_snapshot_constant_block(
                block,
                dict(in_stk),
                dict(in_reg),
                soff,
                state_var_gaddr=state_var_gaddr,
                foldable_global_reads=foldable_global_reads,
                _projection_cache=projection_cache,
            )
            succs = tuple(int(s) for s in block.succs)
            if disp in succs:
                # This block branches back into the dispatcher -- it is a
                # back-edge (the region's transition point).  Record the folded
                # state keyed by the edge we arrived on, and STOP: do not walk
                # past it into the *next* region.
                value = out_stk.get(read_key)
                if value is not None and (
                    target_back_edges is None or blk_serial in target_back_edges
                ):
                    back_edge_states.setdefault(blk_serial, {}).setdefault(
                        parent, set()
                    ).add(int(value) & 0xFFFFFFFF)
                continue
            if depth >= max_depth:
                continue
            for succ in succs:
                if succ == disp or succ in visited:
                    continue
                if relevant_serials is not None and succ not in relevant_serials:
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
        routed = _resolved_dispatcher_target(dispatcher, state)
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
                    if ip_block is not None
                    and ip_block.nsucc > 1
                    and pred in [int(s) for s in ip_block.succs]
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

    return _attach_route_source_kinds(tuple(out), dispatcher)


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
        routed = _resolved_dispatcher_target(dispatcher, state)
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
    return _attach_route_source_kinds(tuple(out), dispatcher)


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
        routed = _resolved_dispatcher_target(dispatcher, state)
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
    return _attach_route_source_kinds(tuple(out), dispatcher)


@dataclass(frozen=True, slots=True)
class _ResolverContext:
    """The per-function inputs the ranked next-state providers share (ticket llr-xauw).

    Bundles the converged fixpoint, the seeded region fold, the optional concrete
    leg, and the ``classify`` / ``arm_of`` closures so each provider is a small
    function of ``(ctx, pred, block, arm)`` -- the single ``resolve_next_state``
    sink walks them in rank order.  Pure data; ``classify``/``arm_of`` are the same
    closures the emit loop built, so every emitted transition is byte-identical.
    """

    flow_graph: object
    fp: object
    dispatcher_entry: int
    read_key: int
    effective_stkoff: int
    state_var_gaddr: int | None
    foldable_global_reads: object | None
    seeded: dict
    emu: object | None
    live_block_for: object | None
    state_cell: object | None
    classify: object
    arm_of: object
    #: Register id of a register-resident state variable. When set, the ranked
    #: providers read the folded next-state from the fixpoint's REGISTER map
    #: (``fp.out_reg_maps[serial][state_var_reg]``) instead of the stack map
    #: (``fp.out_stk_maps[serial][read_key]``). ``None`` -> the stack path is
    #: byte-identical (the register map is simply never consulted).
    state_var_reg: int | None = None


@dataclass(frozen=True, slots=True)
class _DeferredSeededResolution:
    """A direct back-edge unresolved by every provider ranked above seeding."""

    pred: int
    block: object
    arm: int | None
    edge_states: tuple[tuple[int, int], ...]
    ambiguous: bool


def _folded_state_from_maps(
    ctx: "_ResolverContext",
    out_stk: dict,
    out_reg: dict,
) -> int | None:
    """Read the state-var's folded constant from a (stk, reg) map pair.

    d81-3rja: a register-resident state variable (``ctx.state_var_reg`` set) reads
    the folded next-state from the register map; the stack-resident default reads
    the stack map keyed by ``ctx.read_key`` (byte-identical to the pre-change
    ``out_stk.get(ctx.read_key)``).
    """
    if ctx.state_var_reg is not None:
        return out_reg.get(int(ctx.state_var_reg))
    return out_stk.get(ctx.read_key)


def _folded_state_at(ctx: "_ResolverContext", serial: int) -> int | None:
    """Read the state-var's converged OUT constant at ``serial`` (reg or stack)."""
    return _folded_state_from_maps(
        ctx,
        ctx.fp.out_stk_maps.get(serial, {}),
        ctx.fp.out_reg_maps.get(serial, {}),
    )


def _reg_of(storage: Varnode | WeakStackSlot | None) -> int | None:
    """Register id for a REGISTER storage view, else ``None``.

    Canonical equivalent of the legacy ``insn.l.kind is REGISTER -> insn.l.reg``
    read: a register operand projects to ``Varnode(Space.REGISTER, id, size)``.
    """
    if isinstance(storage, Varnode) and storage.space is Space.REGISTER:
        return int(storage.offset)
    return None


def _number_value(storage: Varnode | WeakStackSlot | None) -> int | None:
    """Numeric constant for a CONST storage view, else ``None``.

    Canonical equivalent of the legacy ``insn.l.kind is NUMBER -> insn.l.value``
    read: a number operand projects to ``Varnode(Space.CONST, value, size)``.
    """
    if isinstance(storage, Varnode) and storage.space is Space.CONST:
        return int(storage.offset)
    return None


def _constant_operand_value(
    storage: Varnode | WeakStackSlot | None,
    stack_offset: int | None,
    stk_map: dict[int, int],
    reg_map: dict[int, int],
) -> int | None:
    """Concrete value of a compared operand under the const env, else ``None``.

    ``storage`` is the canonical ``operand_storages`` view and ``stack_offset``
    the matching :func:`~d810.ir.insn_projection.operand_stack_offsets` entry
    (the address-of-stack decode the ``Varnode`` view collapses).  Mirrors the
    legacy ``NUMBER -> value`` / ``&stack -> stk_map`` / ``REGISTER -> reg_map``
    resolution order byte-for-byte.
    """
    value = _number_value(storage)
    if value is not None:
        return int(value)
    if stack_offset is not None:
        return stk_map.get(int(stack_offset))
    reg = _reg_of(storage)
    if reg is not None:
        return reg_map.get(int(reg))
    return None


def _as_signed(value: int, width: int) -> int:
    bits = max(1, int(width) * 8)
    mask = (1 << bits) - 1
    value = int(value) & mask
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _predicate_holds(
    predicate: PredicateKind | None,
    left: int,
    right: int,
    *,
    width: int,
) -> bool | None:
    if predicate is PredicateKind.EQ:
        return int(left) == int(right)
    if predicate is PredicateKind.NE:
        return int(left) != int(right)
    if predicate is PredicateKind.ULT:
        return int(left) < int(right)
    if predicate is PredicateKind.ULE:
        return int(left) <= int(right)
    if predicate is PredicateKind.UGT:
        return int(left) > int(right)
    if predicate is PredicateKind.UGE:
        return int(left) >= int(right)
    if predicate is PredicateKind.SLT:
        return _as_signed(left, width) < _as_signed(right, width)
    if predicate is PredicateKind.SLE:
        return _as_signed(left, width) <= _as_signed(right, width)
    if predicate is PredicateKind.SGT:
        return _as_signed(left, width) > _as_signed(right, width)
    if predicate is PredicateKind.SGE:
        return _as_signed(left, width) >= _as_signed(right, width)
    if predicate is PredicateKind.TRUTHY:
        return int(left) != 0
    return None


def _conditional_taken_fallthrough(
    block: BlockSnapshot,
    succs: tuple[int, ...],
) -> tuple[int, int] | None:
    tail = block.tail
    if tail is None:
        return None
    # The branch's taken target (was ``tail.d.block_ref``) is read off the
    # canonical ``Instruction.control.target``, never the raw ``insn.d`` slot.
    control = project_instruction(tail).control
    taken = control.target if control is not None else None
    if taken is not None and int(taken) in succs:
        fallthrough = next((succ for succ in succs if int(succ) != int(taken)), None)
        if fallthrough is not None:
            return int(taken), int(fallthrough)
    # Hex-Rays snapshot succ ordering is fallthrough, taken for m_jcc blocks.
    if len(succs) == 2:
        return int(succs[1]), int(succs[0])
    return None


def _concrete_successors(
    block: BlockSnapshot,
    stk_map: dict[int, int],
    reg_map: dict[int, int],
) -> tuple[int, ...]:
    succs = tuple(int(s) for s in block.succs)
    if len(succs) != 2:
        return succs
    tail = block.tail
    if tail is None or not tail.is_conditional_jump:
        return succs
    predicate = tail.branch_predicate
    left_storage, right_storage, _dest = operand_storages(tail)
    left_off, right_off, _doff = operand_stack_offsets(tail)
    left = _constant_operand_value(left_storage, left_off, stk_map, reg_map)
    if predicate is PredicateKind.TRUTHY:
        right = 0
    else:
        right = _constant_operand_value(right_storage, right_off, stk_map, reg_map)
    if left is None or right is None:
        return succs
    width = int(tail.compare_width or 4)
    holds = _predicate_holds(predicate, int(left), int(right), width=width)
    targets = _conditional_taken_fallthrough(block, succs)
    if holds is None or targets is None:
        return succs
    taken, fallthrough = targets
    return (taken if holds else fallthrough,)


def _collect_alias_corridor(
    flow_graph: object,
    *,
    back_edge_serial: int,
    dispatcher_entry: int,
    max_blocks: int = 16,
) -> tuple[int, ...]:
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return (int(back_edge_serial),)
    current = int(back_edge_serial)
    seen: set[int] = set()
    path: list[int] = []
    while current not in seen and len(path) < max_blocks:
        seen.add(current)
        path.append(current)
        block = get_block(current)
        if block is None:
            break
        preds = [
            int(pred)
            for pred in tuple(getattr(block, "preds", ()) or ())
            if int(pred) != int(dispatcher_entry)
        ]
        if len(preds) != 1:
            break
        current = preds[0]
    return tuple(reversed(path))


def _alias_map_for_path(
    flow_graph: object, path_blocks: tuple[int, ...]
) -> dict[int, int]:
    get_block = getattr(flow_graph, "get_block", None)
    aliases: dict[int, int] = {}
    if not callable(get_block):
        return aliases
    for serial in path_blocks:
        block = get_block(int(serial))
        if block is None:
            continue
        for insn in block.insn_snapshots:
            if insn.kind is not InsnKind.MOV:
                continue
            _l, _r, dest = operand_storages(insn)
            dst_reg = _reg_of(dest)
            if dst_reg is None:
                continue
            offset = operand_stack_offsets(insn)[0]
            if offset is None:
                aliases.pop(dst_reg, None)
            else:
                aliases[dst_reg] = int(offset)
    return aliases


def _store_target_offset(insn: InsnSnapshot, aliases: dict[int, int]) -> int | None:
    _l, _r, target = operand_storages(insn)
    offset = operand_stack_offsets(insn)[2]
    if offset is not None:
        return int(offset)
    reg = _reg_of(target)
    if reg is not None:
        return aliases.get(reg)
    return None


def _alias_offset_after_block_for_reg(
    flow_graph: object,
    *,
    serial: int,
    target_reg: int,
    dispatcher_entry: int,
    visited: frozenset[tuple[str, int, int]] = frozenset(),
    max_blocks: int = 16,
) -> int | None:
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return None
    key = ("after", int(serial), int(target_reg))
    if key in visited or len(visited) >= max_blocks:
        return None
    block = get_block(int(serial))
    if block is None:
        return None

    aliases: dict[int, int] = {}
    entry_offset = _alias_offset_at_block_entry_for_reg(
        flow_graph,
        block=block,
        target_reg=int(target_reg),
        dispatcher_entry=int(dispatcher_entry),
        visited=visited | {key},
        max_blocks=max_blocks,
    )
    if entry_offset is not None:
        aliases[int(target_reg)] = int(entry_offset)

    for insn in block.insn_snapshots:
        if insn.kind is not InsnKind.MOV:
            continue
        _l, _r, dest = operand_storages(insn)
        if _reg_of(dest) != int(target_reg):
            continue
        offset = operand_stack_offsets(insn)[0]
        if offset is None:
            aliases.pop(int(target_reg), None)
        else:
            aliases[int(target_reg)] = int(offset)
    return aliases.get(int(target_reg))


def _alias_offset_at_block_entry_for_reg(
    flow_graph: object,
    *,
    block: object,
    target_reg: int,
    dispatcher_entry: int,
    visited: frozenset[tuple[str, int, int]] = frozenset(),
    max_blocks: int = 16,
) -> int | None:
    block_serial = getattr(block, "serial", None)
    if block_serial is None:
        return None
    key = ("entry", int(block_serial), int(target_reg))
    if key in visited or len(visited) >= max_blocks:
        return None
    pred_serials = [
        int(pred)
        for pred in tuple(getattr(block, "preds", ()) or ())
        if int(pred) != int(dispatcher_entry)
    ]
    if not pred_serials:
        return None

    offsets: list[int] = []
    for pred_serial in pred_serials:
        offset = _alias_offset_after_block_for_reg(
            flow_graph,
            serial=int(pred_serial),
            target_reg=int(target_reg),
            dispatcher_entry=int(dispatcher_entry),
            visited=visited | {key},
            max_blocks=max_blocks,
        )
        if offset is None:
            return None
        offsets.append(int(offset))
    if offsets and len(set(offsets)) == 1:
        return offsets[0]
    return None


def _incoming_alias_offset_for_reg(
    ctx: _ResolverContext,
    *,
    block: object,
    target_reg: int,
) -> int | None:
    block_serial = getattr(block, "serial", None)
    if block_serial is not None:
        same_block = _alias_map_for_path(ctx.flow_graph, (int(block_serial),)).get(
            int(target_reg)
        )
        if same_block is not None:
            return int(same_block)

    return _alias_offset_at_block_entry_for_reg(
        ctx.flow_graph,
        block=block,
        target_reg=int(target_reg),
        dispatcher_entry=int(ctx.dispatcher_entry),
    )


def _resolve_stack_alias_state_store(
    ctx: _ResolverContext,
    *,
    pred: int,
    block: object,
) -> int | None:
    path = _collect_alias_corridor(
        ctx.flow_graph,
        back_edge_serial=int(pred),
        dispatcher_entry=int(ctx.dispatcher_entry),
    )
    aliases = _alias_map_for_path(ctx.flow_graph, path)
    for insn in block.insn_snapshots:
        if insn.kind is not InsnKind.STORE:
            continue
        target = _store_target_offset(insn, aliases)
        if target is None:
            _l, _r, dest = operand_storages(insn)
            target_reg = _reg_of(dest)
            if target_reg is not None:
                target = _incoming_alias_offset_for_reg(
                    ctx,
                    block=block,
                    target_reg=int(target_reg),
                )
        if target is None or int(target) != int(ctx.effective_stkoff):
            continue
        left, _r, _d = operand_storages(insn)
        value = _number_value(left)
        if value is not None:
            return int(value) & 0xFFFFFFFF
    return None


def _resolve_stack_alias_state_store_from_predecessor(
    ctx: _ResolverContext,
    *,
    predecessor: int,
    block: object,
) -> int | None:
    aliases = _alias_map_for_path(
        ctx.flow_graph,
        _collect_alias_corridor(
            ctx.flow_graph,
            back_edge_serial=int(predecessor),
            dispatcher_entry=int(ctx.dispatcher_entry),
        ),
    )
    for insn in block.insn_snapshots:
        if insn.kind is not InsnKind.STORE:
            continue
        target = _store_target_offset(insn, aliases)
        if target is None or int(target) != int(ctx.effective_stkoff):
            continue
        left, _r, _d = operand_storages(insn)
        value = _number_value(left)
        if value is not None:
            return int(value) & 0xFFFFFFFF
    return None


def _terminal_guard_successor_for_state(
    block: BlockSnapshot,
    *,
    state: int,
    state_var_stkoff: int,
    dispatcher_entry: int,
) -> int | None:
    succs = tuple(int(succ) for succ in block.succs)
    if len(succs) != 2 or int(dispatcher_entry) not in succs:
        return None
    tail = block.tail
    if tail is None or not tail.is_conditional_jump:
        return None
    left_storage, right_storage, _dest = operand_storages(tail)
    left_refs, right_refs, _dest_refs = operand_stack_refs(tail)
    left_state = int(state_var_stkoff) in left_refs
    right_state = int(state_var_stkoff) in right_refs
    left_value = _number_value(left_storage)
    right_value = _number_value(right_storage)

    def _matches_state(value: int | None) -> bool:
        if value is None:
            return False
        if int(value) == int(state):
            return True
        return (int(value) & 0xFFFFFFFF) == (int(state) & 0xFFFFFFFF)

    compares_state = (left_state and _matches_state(right_value)) or (
        right_state and _matches_state(left_value)
    )
    if not compares_state:
        return None
    predicate = tail.branch_predicate
    if predicate is PredicateKind.EQ:
        target = int(succs[1])
    elif predicate is PredicateKind.NE:
        target = int(succs[0])
    else:
        return None
    if target == int(dispatcher_entry):
        return None
    return target


def _provider_global_fold(ctx: _ResolverContext, pred, block, arm):
    """[floor] Unambiguous global/const fold from the converged fixpoint (B1 case).

    When the fixpoint already folded the back-edge predecessor's state slot to a
    single value, redirect the back-edge itself.  ``None`` -> defer to the next
    provider (the abstract per-edge fold partitions by immediate predecessor).
    """
    value = _folded_state_at(ctx, pred)
    if value is None:
        return None
    state = int(value) & 0xFFFFFFFF
    target, is_ret = ctx.classify(state)
    return [
        StateWriteTransition(
            pred,
            state,
            target,
            is_ret,
            arm,
            proof=TransitionProof(_FIXPOINT_ORACLE, "global_fold", not is_ret),
        )
    ]


def _abstract_partition_states(ctx: _ResolverContext, block):
    """Per-immediate-predecessor abstract fold of a back-edge, or ``(None, True)``.

    Applies the back-edge block's transfer to each immediate predecessor's converged
    OUT store separately -- the same partitioning :func:`_resolve_back_edge_states`
    does by walking per region.  Returns ``(edge_states, ambiguous)``: ``ambiguous``
    is ``True`` (and ``edge_states`` partial) the moment any incoming edge cannot
    fold (``⊥``), the exact gap the concrete leg / seeded fold fill.
    """
    edge_states: dict[int, int] = {}
    ambiguous = False
    for ip in sorted(int(p) for p in block.preds):
        ip_block = ctx.flow_graph.get_block(ip)
        if ip_block is None:
            ambiguous = True
            continue
        out_stk, out_reg = _transfer_snapshot_constant_block(
            block,
            dict(ctx.fp.out_stk_maps.get(ip, {})),
            dict(ctx.fp.out_reg_maps.get(ip, {})),
            ctx.effective_stkoff,
            state_var_gaddr=ctx.state_var_gaddr,
            foldable_global_reads=ctx.foldable_global_reads,
        )
        ev = _folded_state_from_maps(ctx, out_stk, out_reg)
        if ev is None:
            # ⊥ on this edge.  Keep scanning: the surviving edges are each
            # independently proven and the partial-partition floor provider
            # (ticket d81-asrt) can still redirect them.  ``edge_states`` is only
            # READ when ``ambiguous`` is False, so collecting the rest cannot
            # change any behaviour that the early return used to produce.
            ambiguous = True
            continue
        edge_states[int(ip)] = int(ev) & 0xFFFFFFFF
    return edge_states, ambiguous


def _provider_predecessor_partitioned(ctx, pred, block, arm, edge_states, ambiguous):
    """[floor] Predecessor-partitioned opaque split / region-agreed plain redirect.

    Reads the abstract per-edge fold (``edge_states``).  A distinct state per
    immediate predecessor -> one ``via_block`` redirect each (the opaque
    ``reg ^ reg`` split, ``predecessor_partitioned``); every edge agreeing on one
    state -> a plain back-edge redirect (``region_agreed``).  ``None`` -> defer.
    """
    if ambiguous:
        return None
    distinct = set(edge_states.values())
    if edge_states and len(distinct) > 1:
        out: list[StateWriteTransition] = []
        for ip, state in sorted(edge_states.items()):
            target, is_ret = ctx.classify(state)
            ip_arm = ctx.arm_of(ctx.flow_graph.get_block(int(ip)), pred)
            out.append(
                StateWriteTransition(
                    int(ip),
                    state,
                    target,
                    is_ret,
                    ip_arm,
                    via_block=pred,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE, "predecessor_partitioned", not is_ret
                    ),
                )
            )
        return out
    if len(distinct) == 1:
        state = next(iter(distinct))
        target, is_ret = ctx.classify(state)
        return [
            StateWriteTransition(
                pred,
                state,
                target,
                is_ret,
                arm,
                proof=TransitionProof(_FIXPOINT_ORACLE, "region_agreed", not is_ret),
            )
        ]
    return None


def _provider_partial_predecessor_partitioned(ctx, pred, block, arm, edge_states):
    """[floor] Partition the PROVEN incoming edges of a partly-⊥ shared store.

    A flattened function may funnel every handler's next state through ONE shared
    store block (``state = ecx``; VM_DecryptPacket blk4 has 19 predecessors).  The
    full partition above is all-or-nothing: a single ⊥ edge discards every proven
    partition and drops the whole back-edge to ``unresolved``.  When that store is
    the only path back to the dispatcher, the unresolved return severs every
    handler from the entry component and the projected rewrite is rejected
    wholesale by the reachability preflight -- i.e. one ⊥ edge costs the entire
    function.

    Each surviving edge is independently proven by the same abstract transfer the
    full partition uses, so redirecting them is exactly as sound.  The ⊥ edges are
    NOT redirected: they keep their natural path into the shared store and on to
    the dispatcher, which stays live as a residual for those states only.

    Ranked at the floor, below every existing provider, so a back-edge that any
    other provider resolves is byte-identical (ticket d81-asrt).
    """
    out: list[StateWriteTransition] = []
    for ip, state in sorted(edge_states.items()):
        target, is_ret = ctx.classify(state)
        ip_arm = ctx.arm_of(ctx.flow_graph.get_block(int(ip)), pred)
        out.append(
            StateWriteTransition(
                int(ip),
                state,
                target,
                is_ret,
                ip_arm,
                via_block=pred,
                proof=TransitionProof(
                    _FIXPOINT_ORACLE, "partial_predecessor_partitioned", not is_ret
                ),
            )
        )
    out.extend(_transitive_glue_partition_transitions(ctx, pred, block, edge_states))
    return out if len(out) >= 2 else None


def _block_folds_strictly(ctx, blk, in_stk, in_reg) -> bool:
    """Every tracked-destination write in ``blk`` folds from KNOWN inputs."""
    stk_map = dict(in_stk)
    reg_map = dict(in_reg)
    for insn in blk.insn_snapshots:
        dest_locator = _constant_dest_locator_snapshot(insn)
        if dest_locator is None:
            continue
        projected_sequence = project_instruction_sequence(insn)
        # The canonical sequence contains one extra TEMP-producing instruction
        # per nested SUBINSN.  This is intentionally the projection boundary:
        # portable analyses must not inspect InsnSnapshot operand slots.
        nested_subinsn = len(projected_sequence) > 1
        expected_nested_value: int | None = None
        if nested_subinsn:
            expected_nested_value = _projected_nested_output_value(
                projected_sequence, stk_map, reg_map
            )
            if expected_nested_value is None:
                return False
        else:
            left, right, _dest = operand_storages(insn)
            left_kind, right_kind, _dk = operand_kinds(insn)
            for storage, kind in ((left, left_kind), (right, right_kind)):
                if storage is None:
                    continue
                if _storage_const_value(storage) is not None:
                    continue
                locator = _storage_dest_locator(storage, kind)
                if locator is None:
                    return False
                space, ident = locator
                source_map = stk_map if space == 'stk' else reg_map
                if source_map.get(int(ident)) is None:
                    return False
        if nested_subinsn:
            # The shared evaluator stores TEMP and REGISTER cells in the same
            # map.  Never replay a canonical nested TEMP sequence into the
            # real recovery map: TEMP 0/1 would alias r0/r1 and change a later
            # state write.  The shadow proof above has already evaluated the
            # expression exactly, so materialize only its proven destination.
            space, ident = dest_locator
            output_map = stk_map if space == "stk" else reg_map
            output_map[int(ident)] = int(expected_nested_value)
            continue
        _forward_eval_insn(insn, stk_map, reg_map, ctx.effective_stkoff,
                           mba=None, state_var_lvar_idx=None)
    return True


_STRICT_PROJECTED_VALUE_OPS = frozenset(
    {
        ValueOpKind.MOVE,
        ValueOpKind.ZEXT,
        ValueOpKind.SEXT,
        ValueOpKind.ADD,
        ValueOpKind.SUB,
        ValueOpKind.AND,
        ValueOpKind.OR,
        ValueOpKind.XOR,
        ValueOpKind.MUL,
    }
)


def _projected_nested_output_value(
    sequence: tuple[Instruction, ...],
    stk_map,
    reg_map,
) -> int | None:
    """Prove a nested expression and return its canonical output value.

    ``operand_storages`` deliberately represents a ``SUBINSN`` root as
    ``UNKNOWN``. Treating that storage as an ordinary unlocatable leaf rejects a
    supported expression *before* the canonical sequence can evaluate its
    temporary producer. Here we only admit operations the portable evaluator
    implements and require every projected input to be known. The parent result
    is redirected to a fresh proof TEMP in a shadow map, so an in-place
    ``edx = f(edx, ...)`` can still read the old ``edx`` while the proof remains
    independent of a stale destination-map value.
    """
    known_temps: set[Varnode] = set()
    if not sequence:
        return None
    for projected in sequence:
        operation = projected.operation
        if operation not in _STRICT_PROJECTED_VALUE_OPS:
            return None
        expected_inputs = (
            1
            if operation in {ValueOpKind.MOVE, ValueOpKind.ZEXT, ValueOpKind.SEXT}
            else 2
        )
        if len(projected.inputs) != expected_inputs or projected.result is None:
            return None
        for value in projected.inputs:
            if value.space is Space.CONST:
                continue
            if value.space is Space.STACK:
                if stk_map.get(int(value.offset)) is not None:
                    continue
                return None
            if value.space is Space.REGISTER:
                if reg_map.get(int(value.offset)) is not None:
                    continue
                return None
            if value.space is Space.TEMP and value in known_temps:
                continue
            return None
        if projected.result.space is Space.TEMP:
            known_temps.add(projected.result)
    proof_stk_map = dict(stk_map)
    proof_reg_map = dict(reg_map)
    shadow_sequence, proof_temp_offset = _shadow_nested_temp_sequence(
        sequence,
        occupied_register_offsets=frozenset(int(offset) for offset in proof_reg_map),
    )
    for instruction in shadow_sequence:
        forward_eval_instruction(
            instruction,
            proof_stk_map,
            proof_reg_map,
            state_var_stkoff=-(1 << 63),
        )
    return proof_reg_map.get(proof_temp_offset)


def _shadow_nested_temp_sequence(
    sequence: tuple[Instruction, ...],
    *,
    occupied_register_offsets: frozenset[int],
) -> tuple[tuple[Instruction, ...], int]:
    """Move every projected TEMP into a private evaluator namespace.

    ``forward_eval_instruction`` intentionally shares one map for portable
    registers and temporaries.  At this recovery boundary the surrounding map
    is a live register environment, so canonical temporaries must be remapped
    before proof evaluation.  The last instruction gets a dedicated result
    TEMP; callers materialize only that value into the original destination.
    """
    shadow, proof_offset = isolate_temporaries_for_forward_evaluation(
        sequence,
        occupied_register_offsets=occupied_register_offsets,
        isolate_final_result=True,
    )
    if proof_offset is None:
        raise ValueError("nested projected sequence lacks a proof result")
    return shadow, proof_offset


def _transfer_snapshot_constant_block_nested_safe(
    block,
    in_stk_map: dict[int, int],
    in_reg_map: dict[int, int],
    state_var_stkoff: int,
    *,
    state_var_gaddr: int | None = None,
    foldable_global_reads: object | None = None,
) -> tuple[dict[int, int], dict[int, int]]:
    """Transfer a strictly admitted glue block without leaking TEMP aliases."""
    stk_map = dict(in_stk_map)
    reg_map = dict(in_reg_map)
    for insn in block.insn_snapshots:
        sequence = project_instruction_sequence(insn)
        if len(sequence) <= 1:
            _forward_eval_insn(
                insn,
                stk_map,
                reg_map,
                state_var_stkoff,
                mba=None,
                state_var_lvar_idx=None,
                state_var_gaddr=state_var_gaddr,
                foldable_global_reads=foldable_global_reads,
            )
            continue
        destination = _constant_dest_locator_snapshot(insn)
        value = _projected_nested_output_value(sequence, stk_map, reg_map)
        if destination is None or value is None:
            # The caller has already applied the strict admissibility gate;
            # retain this defensive fail-closed transfer for future callers.
            return dict(in_stk_map), dict(in_reg_map)
        space, ident = destination
        output_map = stk_map if space == "stk" else reg_map
        output_map[int(ident)] = int(value)
    return stk_map, reg_map


def _transitive_glue_partition_transitions(ctx, pred, block, edge_states):
    """Partition one level further through a bottom pure-state-glue predecessor."""
    out: list[StateWriteTransition] = []
    for ip in sorted(int(p) for p in block.preds):
        if ip in edge_states or ip == int(ctx.dispatcher_entry):
            continue
        glue = ctx.flow_graph.get_block(ip)
        if glue is None:
            continue
        if tuple(int(s) for s in glue.succs) != (int(block.serial),):
            continue
        grandparents = sorted(int(gp) for gp in glue.preds
                              if int(gp) != int(ctx.dispatcher_entry))
        if len(grandparents) < 2:
            continue
        resolved: dict[int, int] = {}
        for gp in grandparents:
            if ctx.flow_graph.get_block(gp) is None:
                break
            in_stk = dict(ctx.fp.out_stk_maps.get(gp, {}))
            in_reg = dict(ctx.fp.out_reg_maps.get(gp, {}))
            if not _block_folds_strictly(ctx, glue, in_stk, in_reg):
                break
            g_stk, g_reg = _transfer_snapshot_constant_block_nested_safe(
                glue, in_stk, in_reg, ctx.effective_stkoff,
                state_var_gaddr=ctx.state_var_gaddr,
                foldable_global_reads=ctx.foldable_global_reads)
            o_stk, o_reg = _transfer_snapshot_constant_block(
                block, g_stk, g_reg, ctx.effective_stkoff,
                state_var_gaddr=ctx.state_var_gaddr,
                foldable_global_reads=ctx.foldable_global_reads)
            ev = _folded_state_from_maps(ctx, o_stk, o_reg)
            if ev is None:
                break
            resolved[gp] = int(ev) & 0xFFFFFFFF
        if len(resolved) != len(grandparents):
            continue
        for gp, state in sorted(resolved.items()):
            target, is_ret = ctx.classify(state)
            gp_arm = ctx.arm_of(ctx.flow_graph.get_block(gp), ip)
            out.append(StateWriteTransition(
                gp, state, target, is_ret, gp_arm, via_block=ip,
                proof=TransitionProof(_FIXPOINT_ORACLE, "transitive_glue_partitioned", not is_ret)))
    return out


def _provider_emulation(ctx, pred, block, arm, ambiguous):
    """[refine] The reduced-product CONCRETE leg -- ⊥-only, fold_exact-gated.

    Consulted ONLY where the abstract per-edge fold landed at ``⊥`` (``ambiguous``):
    seeds the prove-exact-or-abstain emulator per immediate predecessor from its
    converged OUT store, steps the live back-edge block, and ``fold_exact``-validates
    each result.  ``None`` -> abstain (defer to the seeded fold) -- a partial
    emulation never half-resolves a back-edge.  Never reached for an
    abstract-resolved edge, so it can only forfeit precision, never corrupt.
    """
    if not ambiguous:
        return None
    if ctx.emu is None or ctx.live_block_for is None or ctx.state_cell is None:
        return None
    emu_states = _emulate_partition_states(
        ctx.emu, ctx.live_block_for, ctx.state_cell, ctx.fp, block, pred
    )
    if emu_states is None:
        return None
    out: list[StateWriteTransition] = []
    _emit_partition_transitions(
        out,
        emu_states,
        pred,
        arm,
        ctx.flow_graph,
        ctx.classify,
        ctx.arm_of,
        oracle_kind=_EMULATION_ORACLE,
        single_kind=_KIND_BACK_EDGE_CONCRETE_FOLD,
        split_kind=_KIND_CONCRETE_FOLD_PARTITIONED,
    )
    return out


def _provider_stack_address_alias(ctx, pred, block, arm):
    """[floor] State write through a register proven to be ``&state_slot``.

    This handles OLLVM corridors where a handler materializes stack addresses into
    registers, then writes the next dispatcher state via ``m_stx value, ds, reg``.
    The proof is local: follow a unique predecessor corridor that excludes the
    dispatcher, collect only ``reg = &stack_slot`` definitions, and accept a state
    transition only when the store target alias is the configured state slot.
    """

    state = _resolve_stack_alias_state_store(ctx, pred=int(pred), block=block)
    if state is None:
        partitioned: list[StateWriteTransition] = []
        for ip in sorted(
            int(p)
            for p in tuple(getattr(block, "preds", ()) or ())
            if int(p) != int(ctx.dispatcher_entry)
        ):
            ip_state = _resolve_stack_alias_state_store_from_predecessor(
                ctx,
                predecessor=int(ip),
                block=block,
            )
            if ip_state is None:
                continue
            terminal_target = _terminal_guard_successor_for_state(
                block,
                state=int(ip_state),
                state_var_stkoff=int(ctx.effective_stkoff),
                dispatcher_entry=int(ctx.dispatcher_entry),
            )
            terminal_guard = terminal_target is not None
            if not terminal_guard:
                target, is_ret = ctx.classify(ip_state)
            else:
                target, is_ret = int(terminal_target), False
            ip_arm = ctx.arm_of(ctx.flow_graph.get_block(int(ip)), pred)
            partitioned.append(
                StateWriteTransition(
                    int(ip),
                    int(ip_state),
                    target,
                    is_ret,
                    ip_arm,
                    via_block=pred,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        (
                            _KIND_STACK_ADDRESS_ALIAS_TERMINAL_GUARD_PARTITIONED
                            if terminal_guard
                            else _KIND_STACK_ADDRESS_ALIAS_STORE_PARTITIONED
                        ),
                        not is_ret,
                        reason=(
                            "predecessor_state_store_through_stack_address_alias_terminal_guard"
                            if terminal_guard
                            else "predecessor_state_store_through_stack_address_alias"
                        ),
                    ),
                )
            )
        return partitioned or None
    terminal_target = _terminal_guard_successor_for_state(
        block,
        state=int(state),
        state_var_stkoff=int(ctx.effective_stkoff),
        dispatcher_entry=int(ctx.dispatcher_entry),
    )
    terminal_guard = terminal_target is not None
    if not terminal_guard:
        target, is_ret = ctx.classify(state)
    else:
        target, is_ret = int(terminal_target), False
    return [
        StateWriteTransition(
            int(pred),
            int(state),
            target,
            is_ret,
            arm,
            proof=TransitionProof(
                _FIXPOINT_ORACLE,
                (
                    _KIND_STACK_ADDRESS_ALIAS_TERMINAL_GUARD
                    if terminal_guard
                    else _KIND_STACK_ADDRESS_ALIAS_STORE
                ),
                not is_ret,
                reason=(
                    "state_store_through_stack_address_alias_terminal_guard"
                    if terminal_guard
                    else "state_store_through_stack_address_alias"
                ),
            ),
        )
    ]


def _provider_region_seeded(ctx, pred, block, arm):
    """[floor] The seeded per-region fold (masked-OR / state-reading write).

    The global meet collapses the state var to ⊥ at the dispatcher join, so a
    ``state = (state & ~MASK) | M`` write never folds via the fixpoint; seeding each
    region's entry with its dispatch key makes it fold to ``M``.  ``None`` -> defer
    to the unresolved sink.
    """
    out: list[StateWriteTransition] = []
    if _emit_seeded_back_edge(
        out,
        ctx.seeded.get(pred, {}),
        pred,
        arm,
        ctx.flow_graph,
        ctx.classify,
        ctx.arm_of,
    ):
        return out
    return None


def _resolve_next_state_before_seeded(
    ctx: _ResolverContext, pred, block, arm
) -> list[StateWriteTransition] | _DeferredSeededResolution:
    """Run every provider above region seeding, or return a deferred record.

    Priority (the proof is the only differentiator -- PART A, ticket llr-xauw):

      [floor]  predecessor_partitioned split -> global_fold -> region_agreed
      [refine] emulation_oracle  (⊥-only; seeded ConcreteStore; fold_exact-gated)
      [floor]  region_seeded
      [future] (clean extension point for symbolic/solver providers)
      else     -> unresolved (routed to the shared return)

    The first provider to return a non-``None`` list wins; the abstract per-edge
    fold is computed once and shared by the partitioned + emulation providers (the
    concrete leg fires only where the abstract fold is ⊥).

    A distinct predecessor-partitioned split is ranked before ``global_fold`` because
    a shared merge block may do ``state = temp`` after each incoming edge assigns a
    different constant to ``temp``.  The global meet can fail to resolve that temp
    and leave the incoming dispatcher state in the state slot, producing a stale
    self-loop route.  When every immediate predecessor independently folds to a
    concrete next-state, those edge-local writes are the real transition anchors.
    """
    # The abstract per-edge fold, computed once: it gates BOTH the predecessor-
    # partitioned floor provider (non-⊥) and the emulation refine provider (⊥).
    edge_states, ambiguous = _abstract_partition_states(ctx, block)

    # [floor] predecessor-partitioned split.  Prefer this over a stale global_fold
    # when a shared state-write merge has one concrete next-state per incoming edge.
    if not ambiguous and len(set(edge_states.values())) > 1:
        edges = _provider_predecessor_partitioned(
            ctx, pred, block, arm, edge_states, ambiguous
        )
        if edges is not None:
            return edges

    # [floor] unambiguous global/const fold (the B1 case).
    edges = _provider_global_fold(ctx, pred, block, arm)
    if edges is not None:
        return edges

    # [floor] region-agreed plain redirect from the per-edge fold.
    edges = _provider_predecessor_partitioned(
        ctx, pred, block, arm, edge_states, ambiguous
    )
    if edges is not None:
        return edges

    # [refine] the reduced-product CONCRETE leg -- BEFORE the seeded fold can mask a
    # ⊥ with a stale dispatch-key self-loop.
    edges = _provider_emulation(ctx, pred, block, arm, ambiguous)
    if edges is not None:
        return edges

    # [floor] local address-alias state write.  This sits below the ordinary
    # abstract and concrete legs, and above the seeded fallback/unresolved sink.
    edges = _provider_stack_address_alias(ctx, pred, block, arm)
    if edges is not None:
        return edges

    return _DeferredSeededResolution(
        pred=int(pred),
        block=block,
        arm=arm,
        edge_states=tuple(sorted((int(key), int(value)) for key, value in edge_states.items())),
        ambiguous=bool(ambiguous),
    )


def _finish_deferred_state_resolution(
    ctx: _ResolverContext,
    deferred: _DeferredSeededResolution,
) -> list[StateWriteTransition]:
    """Finish the legacy seeded -> partial -> unresolved provider tail."""
    pred = int(deferred.pred)
    block = deferred.block
    arm = deferred.arm

    # [floor] the seeded per-region fold (masked-OR / state-reading write).
    edges = _provider_region_seeded(ctx, pred, block, arm)
    if edges is not None:
        return edges

    # [floor] partial predecessor partition: redirect the edges that DID fold when
    # only some of a shared store's incoming edges are ⊥.  Below every provider
    # above, so it only ever replaces the unresolved sink.
    if deferred.ambiguous:
        edges = _provider_partial_predecessor_partitioned(
            ctx, pred, block, arm, dict(deferred.edge_states)
        )
        if edges is not None:
            return edges

    # [future] symbolic / solver providers slot in here, ranked below the floor and
    # the concrete leg, above the unresolved sink.

    # else -> unresolved: route the back-edge to the shared return.
    return [
        StateWriteTransition(
            pred,
            None,
            None,
            True,
            arm,
            proof=TransitionProof(_FIXPOINT_ORACLE, "unresolved", False),
        )
    ]


def _resolve_next_state(ctx: _ResolverContext, pred, block, arm):
    """Resolve one row using the complete ranked provider sequence."""
    resolved = _resolve_next_state_before_seeded(ctx, pred, block, arm)
    if isinstance(resolved, _DeferredSeededResolution):
        return _finish_deferred_state_resolution(ctx, resolved)
    return resolved


def recover_state_write_transitions_via_partitioned_fixpoint(
    flow_graph,
    dispatcher,
    state_var_stkoff: int | None,
    *,
    dispatcher_entry_serial: int,
    recover_terminal_tail: bool = False,
    initial_state: int | None = None,
    emu: "EmulationCapability | None" = None,
    live_block_for: "object | None" = None,
    include_multi_entry_back_edges: bool = False,
    state_var_reg: int | None = None,
    dispatcher_region_serials: frozenset[int] = frozenset(),
    candidate_prefix_authority: CandidateScopedPrefixAuthority | None = None,
    include_entry_unreachable_back_edges: bool = False,
    state_route_resolver: Callable[[int], int | None] | None = None,
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

    Reduced-product CONCRETE leg (ticket llr-xauw): ``emu`` is an optional
    prove-exact-or-abstain :class:`EmulationCapability`; ``live_block_for`` maps a
    block serial to the live backend block the emulator steps.  Both default to
    ``None`` -> EXACTLY the abstract-only behaviour above (no change).  When supplied,
    a back-edge whose abstract per-edge fold lands at ``⊥`` (the opaque
    ``reg ^ reg``-next-state writers whose operands live in OTHER blocks) is consulted
    against the concrete leg, SEEDED from the immediate predecessor's converged OUT
    store; a fold that ``fold_exact``-validates emits a RESOLVED transition tagged
    ``_EMULATION_ORACLE``.  The consult fires ONLY at the genuine ⊥ gap -- it never
    overrides a fixpoint-resolved transition.
    """
    state_cell = (
        LocationRef.stack(int(state_var_stkoff), 8)
        if emu is not None and state_var_stkoff is not None
        else None
    )
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    entry_reachable = reachable_from_adjacency(
        flow_graph.as_adjacency_dict(), int(flow_graph.entry_serial)
    )
    if candidate_prefix_authority is not None and not (
        _revalidate_candidate_scoped_prefix_authority(
            flow_graph,
            candidate_prefix_authority,
            root_serial=disp,
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
        )
    ):
        return ()
    default = dispatcher.default_target
    # d81-3rja: a register-resident state var carries no stack offset. The
    # constant fixpoint tracks it in ``out_reg_maps`` regardless; the providers
    # read it via ``ctx.state_var_reg``. Use a sentinel stack offset (-1) that
    # matches no real stack write so the stack-keyed alias / seeded / global-fold
    # fallbacks stay inert (they contribute nothing for the register path, which
    # is resolved by the reg-aware ``_provider_global_fold`` / abstract partition).
    if state_var_stkoff is not None:
        effective_stkoff = _resolve_state_var_alias(
            flow_graph, disp, int(state_var_stkoff)
        )
    else:
        effective_stkoff = -1
    # A handler can write its NEXT state through a global it reads (Approov:
    # ``state = (qword |= 0xF6A20)`` where ``qword`` is a zero-initialised ``.data``
    # global).  ``state_var_gaddr`` flags the rarer case where a global IS the
    # dispatcher state variable (Hex-Rays forward-substituted the ``state = global``
    # copy into the header); ``None`` for the ordinary stack/register state var.
    # ``foldable_global_reads`` folds reaching-defs-stable global reads to their
    # static initializer -- anchored at the INITIAL handler (the dispatcher target
    # for the entry state), which runs before any handler store -- so the
    # data-dependent next-state resolves.  None/empty -> unchanged behaviour.
    state_var_gaddr = _detect_global_state_var(flow_graph, disp)
    initial_handler = (
        _resolved_dispatcher_target(dispatcher, int(initial_state))
        if initial_state is not None
        else None
    )
    foldable_global_reads = _compute_foldable_global_reads(
        flow_graph, disp, initial_handler
    )
    read_key = int(state_var_gaddr) if state_var_gaddr is not None else effective_stkoff
    if foldable_global_reads and logger.debug_on:
        logger.debug(
            "partitioned_fixpoint: global init folds (init_handler=%s) %s",
            initial_handler,
            {
                hex(ea): {hex(g): hex(v) for g, v in m.items()}
                for ea, m in foldable_global_reads.items()
            },
        )
    fp = run_snapshot_constant_fixpoint(
        flow_graph,
        effective_stkoff,
        state_var_gaddr=state_var_gaddr,
        foldable_global_reads=foldable_global_reads,
    )
    seeded: dict[int, dict[int | None, set[int]]] = {}

    def _classify(state: int) -> tuple[int | None, bool]:
        if state_route_resolver is not None:
            routed = state_route_resolver(int(state) & 0xFFFFFFFF)
            if routed is None:
                # A current-snapshot resolver can abstain for a nested or
                # otherwise non-authoritative router.  That is unknown route
                # evidence, not proof of a terminal/default state; leave the
                # row eligible for the downstream reconciliation providers.
                return None, False
        else:
            routed = _resolved_dispatcher_target(dispatcher, state)
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

    # Every direct back-edge first runs the providers above the expensive seeded
    # fallback.  Only deferred rows trigger one exact-target seeded walk, then
    # resume at the unchanged seeded -> partial -> unresolved tail.
    resolver_ctx = _ResolverContext(
        flow_graph=flow_graph,
        fp=fp,
        dispatcher_entry=disp,
        read_key=read_key,
        effective_stkoff=effective_stkoff,
        state_var_gaddr=state_var_gaddr,
        foldable_global_reads=foldable_global_reads,
        seeded=seeded,
        emu=emu,
        live_block_for=live_block_for,
        state_cell=state_cell,
        classify=_classify,
        arm_of=_arm,
        state_var_reg=state_var_reg,
    )
    direct_results: list[
        list[StateWriteTransition] | _DeferredSeededResolution
    ] = []
    deferred: list[_DeferredSeededResolution] = []
    visited_sources: set[int] = set()
    for pred in sorted(int(p) for p in disp_block.preds):
        if pred not in entry_reachable and not include_entry_unreachable_back_edges:
            continue
        if pred in dispatcher_region_serials:
            continue
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        visited_sources.add(pred)
        arm = succs.index(disp) if len(succs) > 1 else None
        resolved = _resolve_next_state_before_seeded(resolver_ctx, pred, block, arm)
        direct_results.append(resolved)
        if isinstance(resolved, _DeferredSeededResolution):
            deferred.append(resolved)

    if deferred:
        seeded = _resolve_back_edge_states(
            flow_graph,
            dispatcher=dispatcher,
            state_var_stkoff=effective_stkoff,
            dispatcher_entry=disp,
            max_depth=_MAX_CORRIDOR_DEPTH,
            state_var_gaddr=state_var_gaddr,
            foldable_global_reads=foldable_global_reads,
            target_back_edges=frozenset(row.pred for row in deferred),
        )
        resolver_ctx = replace(resolver_ctx, seeded=seeded)

    if logger.debug_on:
        logger.debug(
            "partitioned_fixpoint: disp=%d preds=%s seeded_back_edges=%s",
            disp,
            sorted(int(p) for p in disp_block.preds),
            {k: sorted({s for v in m.values() for s in v}) for k, m in seeded.items()},
        )

    # Flatten in physical predecessor order.  Deferring seeded work must not
    # reorder transitions relative to the legacy one-pass provider loop.
    direct_groups: list[tuple[int, tuple[StateWriteTransition, ...]]] = []
    direct_sources = tuple(
        pred
        for pred in sorted(int(p) for p in disp_block.preds)
        if pred in visited_sources
    )
    for pred, resolved in zip(direct_sources, direct_results, strict=True):
        if isinstance(resolved, _DeferredSeededResolution):
            rows = tuple(_finish_deferred_state_resolution(resolver_ctx, resolved))
        else:
            rows = tuple(resolved)
        direct_groups.append((int(pred), rows))

    if candidate_prefix_authority is None:
        out = [row for _pred, rows in direct_groups for row in rows]
    else:
        scoped_groups = _recover_candidate_prefix_feeder_transition_groups(
            resolver_ctx,
            flow_graph,
            candidate_prefix_authority,
            already_visited=visited_sources,
        )
        if scoped_groups is None:
            return ()
        out = [
            row
            for _source, rows in sorted(
                (*direct_groups, *scoped_groups),
                key=lambda item: int(item[0]),
            )
            for row in rows
        ]

    if include_multi_entry_back_edges:
        out.extend(
            _recover_multi_entry_state_write_transitions(
                resolver_ctx,
                flow_graph,
                dispatcher_entry=disp,
                already_visited=visited_sources,
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
    return _attach_route_source_kinds(tuple(out), dispatcher)


def _reaches_dispatcher_entry(
    flow_graph,
    start_serial: int,
    dispatcher_entry: int,
    *,
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> bool:
    """Whether ``start_serial`` flows back into the anchored dispatcher entry."""

    target = int(dispatcher_entry)
    seen: set[int] = set()
    stack: list[tuple[int, int]] = [(int(start_serial), 0)]
    while stack:
        serial, depth = stack.pop()
        if serial == target:
            return True
        if serial in seen or depth >= max_depth:
            continue
        seen.add(serial)
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        for succ in tuple(int(s) for s in getattr(block, "succs", ()) or ()):
            if succ not in seen:
                stack.append((succ, depth + 1))
    return False


def _recover_candidate_prefix_feeder_transition_groups(
    ctx: _ResolverContext,
    flow_graph: FlowGraph,
    authority: CandidateScopedPrefixAuthority,
    *,
    already_visited: set[int],
) -> tuple[tuple[int, tuple[StateWriteTransition, ...]], ...] | None:
    """Recover exact direct writers and partitioned immediate prefix feeders.

    This is deliberately narrower than multi-entry recovery: it inspects only
    reciprocal immediate predecessors of the validated prefix and invokes the
    existing above-seeded provider stack exactly once per state-writing block.
    A multi-predecessor feeder is accepted only when that call returns one
    concrete ``predecessor_partitioned`` row for every reciprocal sole source
    edge.  It never receives seeded/global path authority.  Targetless or
    untrusted concrete rows are retained only so reconciliation can omit an
    exactly selected untouched prefix arm; they cannot authorize a redirect.
    Any missing or unresolved source partition rejects the scoped fragment
    atomically.  Malformed authority or contradictory physical topology also
    rejects globally.
    """

    prefix_serial = int(authority.prefix_serial)
    prefix = flow_graph.get_block(prefix_serial)
    if prefix is None:
        return None
    listed_predecessors = {int(pred) for pred in prefix.preds}
    forward_predecessors = {
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if prefix_serial in tuple(int(succ) for succ in block.succs)
    }
    if listed_predecessors != forward_predecessors:
        return None
    groups: list[tuple[int, tuple[StateWriteTransition, ...]]] = []
    for feeder_serial in sorted(listed_predecessors):
        if feeder_serial in already_visited:
            continue
        feeder = flow_graph.get_block(feeder_serial)
        if (
            feeder is None
            or tuple(int(succ) for succ in feeder.succs) != (prefix_serial,)
        ):
            return None
        if not _block_writes_state_cell(ctx, feeder):
            continue
        resolved = _resolve_next_state_before_seeded(
            ctx,
            feeder_serial,
            feeder,
            None,
        )
        if isinstance(resolved, _DeferredSeededResolution):
            return None

        partitioned = tuple(
            edge
            for edge in resolved
            if edge.proof is not None
            and edge.proof.oracle_kind == _FIXPOINT_ORACLE
            and edge.proof.kind == "predecessor_partitioned"
        )
        if partitioned:
            source_serials = tuple(sorted(int(pred) for pred in feeder.preds))
            rows_by_source = {int(edge.write_block): edge for edge in partitioned}
            if (
                len(partitioned) != len(resolved)
                or len(rows_by_source) != len(partitioned)
                or tuple(rows_by_source) != source_serials
            ):
                return None
            feeder_groups: list[
                tuple[int, tuple[StateWriteTransition, ...]]
            ] = []
            evidence_complete = True
            for source_serial in source_serials:
                source = flow_graph.get_block(source_serial)
                edge = rows_by_source[source_serial]
                if (
                    source is None
                    or tuple(int(succ) for succ in source.succs) != (feeder_serial,)
                    or source_serial
                    not in tuple(int(pred) for pred in feeder.preds)
                    or edge.via_block != feeder_serial
                ):
                    return None
                if edge.next_state is None or edge.proof is None:
                    evidence_complete = False
                    break
                feeder_groups.append((source_serial, (edge,)))
            if not evidence_complete:
                return None
            groups.extend(feeder_groups)
            continue

        # Preserve the already-proven direct ``writer -> prefix`` case.  A
        # multi-predecessor state writer that did not produce a complete split
        # is an observed feeder, not a direct writer, and must abstain as a group.
        if len(tuple(int(pred) for pred in feeder.preds)) > 1:
            return None
        exact = tuple(
            edge
            for edge in resolved
            if int(edge.write_block) == feeder_serial
            and edge.next_state is not None
            and edge.target_handler is not None
            and not edge.is_return
            and edge.proof is not None
            and edge.proof.trusted
        )
        routes = {
            (int(edge.next_state), int(edge.target_handler)) for edge in exact
        }
        if len(exact) != 1 or len(routes) != 1:
            return None
        edge = exact[0]
        groups.append(
            (
                feeder_serial,
                (replace(edge, via_block=prefix_serial, branch_arm=None),),
            )
        )
    return tuple(groups)


def _recover_multi_entry_state_write_transitions(
    ctx: _ResolverContext,
    flow_graph,
    *,
    dispatcher_entry: int,
    already_visited: set[int],
) -> tuple[StateWriteTransition, ...]:
    """Recover state-write exits that re-enter a dispatcher region away from entry.

    Nested condition-chain dispatchers can route handlers into a shared inner
    compare/suffix block instead of directly back to the anchored dispatcher
    entry.  The ordinary predecessor scan misses those state writes entirely.
    When the caller has already proven this multi-entry shape, scan one-way
    state writers whose sole successor reaches the anchored dispatcher and emit
    them as ``via_block`` splits: redirect ``writer -> successor`` onto the
    folded routed handler.

    Region-seeded evidence intentionally remains direct-backedge-only.  The
    seeded map keys blocks whose successors contain ``dispatcher_entry``;
    eligible multi-entry writers have one successor that is not the dispatcher.
    Therefore higher-ranked providers may resolve them, but a state-reading
    upstream writer cannot acquire new authority from the direct seeded map.
    """

    out: list[StateWriteTransition] = []
    emitted: set[tuple[int, int | None, int | None]] = set()
    disp = int(dispatcher_entry)
    for serial in sorted(int(s) for s in flow_graph.blocks):
        if serial == disp or serial in already_visited:
            continue
        block = flow_graph.get_block(serial)
        if block is None or int(getattr(block, "nsucc", 0)) != 1:
            continue
        if not _block_writes_state_cell(ctx, block):
            continue
        succ = int(block.succs[0])
        if succ == disp:
            continue
        if not _reaches_dispatcher_entry(flow_graph, succ, disp):
            continue

        # A shared state-transform feeder may have several constant-defining
        # physical predecessors.  Treating the feeder itself as the transition
        # source collapses those distinct states onto one edge and cannot be
        # replayed from an empty constant environment.  Reuse the existing
        # predecessor-partitioned provider before considering the coarser
        # global fold, and retain the real ``source -> feeder`` edges.
        if len(tuple(int(pred) for pred in block.preds)) > 1:
            partitioned = _resolve_next_state_before_seeded(
                ctx,
                serial,
                block,
                None,
            )
            if not isinstance(partitioned, _DeferredSeededResolution):
                source_serials = tuple(sorted(int(pred) for pred in block.preds))
                partition_observed = any(
                    edge.proof is not None
                    and edge.proof.oracle_kind == _FIXPOINT_ORACLE
                    and edge.proof.kind == "predecessor_partitioned"
                    for edge in partitioned
                )
                rows_by_source = {
                    int(edge.write_block): edge
                    for edge in partitioned
                    if edge.proof is not None
                    and edge.proof.oracle_kind == _FIXPOINT_ORACLE
                    and edge.proof.kind == "predecessor_partitioned"
                }
                if (
                    len(partitioned) == len(source_serials)
                    and len(rows_by_source) == len(partitioned)
                    and tuple(rows_by_source) == source_serials
                ):
                    exact_partition = True
                    staged: list[StateWriteTransition] = []
                    for source_serial in source_serials:
                        source = flow_graph.get_block(source_serial)
                        edge = rows_by_source[source_serial]
                        if (
                            source is None
                            or tuple(int(target) for target in source.succs)
                            != (serial,)
                            or source_serial
                            not in tuple(int(pred) for pred in block.preds)
                            or edge.via_block != serial
                            or edge.next_state is None
                            or edge.proof is None
                        ):
                            exact_partition = False
                            break
                        staged.append(replace(edge, branch_arm=None))
                    if exact_partition:
                        out.extend(staged)
                        continue
                if partition_observed:
                    # A provider observed distinct physical partitions but
                    # they did not bind every reciprocal source edge exactly.
                    # Never fall through and collapse them onto the shared
                    # feeder's coarser global route.
                    continue

        resolved_edges = tuple(
            edge
            for edge in _resolve_next_state(ctx, serial, block, None)
            if edge.next_state is not None
            and edge.target_handler is not None
            and not edge.is_return
        )
        # A partitioned result names distinct incoming predecessor edges.  This
        # scan only has one physical ``serial -> succ`` edge to rewrite, so
        # collapsing those routes onto it would emit competing redirects and
        # arbitrarily erase one arm.  The predecessor blocks are scanned in
        # their own iterations and retain their precise ``pred -> serial``
        # routes; abstain from this coarser corridor edge.
        routes = {
            (int(edge.next_state), int(edge.target_handler)) for edge in resolved_edges
        }
        if len(routes) != 1:
            continue

        for edge in resolved_edges[:1]:
            target = int(edge.target_handler)
            if target in {serial, succ}:
                continue
            key = (serial, int(edge.next_state), target)
            if key in emitted:
                continue
            emitted.add(key)
            out.append(
                replace(
                    edge,
                    write_block=serial,
                    branch_arm=None,
                    via_block=succ,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE,
                        "multi_entry_global_fold",
                        True,
                        reason="state_write_reenters_dispatcher_region_via_successor",
                    ),
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
                serial,
                state,
                target,
                False,
                arm,
                via_block=old,
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
                pred,
                state,
                target,
                is_ret,
                arm,
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
                    int(ip),
                    state,
                    target,
                    is_ret,
                    ip_arm,
                    via_block=pred,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE, "region_seeded_partitioned", not is_ret
                    ),
                )
            )
        return True
    return False


def _emulate_partition_states(emu, live_block_for, state_cell, fp, block, pred):
    """Per-immediate-predecessor concrete next-states for a ⊥ back-edge, or ``None``.

    The reduced-product CONCRETE leg (ticket llr-xauw).  For each immediate
    predecessor ``ip`` of the back-edge ``block``, the prove-exact-or-abstain
    emulator steps the live back-edge block (resolved by serial through
    ``live_block_for``) SEEDED from ``ip``'s converged OUT store;
    :func:`_emulate_unresolved_state` ``fold_exact``-validates each result before it
    is trusted.  Returns ``{ip -> state}`` only when EVERY incoming edge resolves;
    ``None`` on the first abstain (the caller then falls through to the unchanged
    seeded/unresolved logic -- a partial emulation never half-resolves a back-edge).
    """
    edge_states: dict[int, int] = {}
    for ip in sorted(int(p) for p in block.preds):
        concrete = _emulate_unresolved_state(
            emu,
            live_block_for(int(pred)),
            _seed_concrete_store(
                dict(fp.out_stk_maps.get(ip, {})),
                dict(fp.out_reg_maps.get(ip, {})),
            ),
            state_cell,
        )
        if concrete is None:
            return None  # any ⊥ residual -> abstain wholesale (stay seeded/unresolved)
        edge_states[int(ip)] = int(concrete) & 0xFFFFFFFF
    return edge_states or None


def _emit_partition_transitions(
    out: list,
    edge_states: dict[int, int],
    pred: int,
    arm: int | None,
    flow_graph,
    classify,
    arm_of,
    *,
    oracle_kind: str,
    single_kind: str,
    split_kind: str,
) -> None:
    """Emit the back-edge redirect(s) for a per-predecessor state map.

    Mirrors the global/seeded emit shape: every incoming edge agreeing on one state
    -> a plain ``pred -> route(state)`` redirect; a distinct state per immediate
    predecessor -> one ``via_block=pred`` split each.  ``oracle_kind``/``single_kind``
    /``split_kind`` stamp the :class:`TransitionProof` so the proof distribution
    distinguishes the concrete leg from the abstract oracle.
    """
    distinct = set(edge_states.values())
    if len(distinct) == 1:
        state = next(iter(distinct))
        target, is_ret = classify(state)
        out.append(
            StateWriteTransition(
                pred,
                state,
                target,
                is_ret,
                arm,
                proof=TransitionProof(oracle_kind, single_kind, not is_ret),
            )
        )
        return
    for ip, state in sorted(edge_states.items()):
        target, is_ret = classify(state)
        ip_block = flow_graph.get_block(int(ip))
        ip_arm = arm_of(ip_block, pred) if ip_block is not None else None
        out.append(
            StateWriteTransition(
                int(ip),
                state,
                target,
                is_ret,
                ip_arm,
                via_block=pred,
                proof=TransitionProof(oracle_kind, split_kind, not is_ret),
            )
        )


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

    next_state: int | None  # folded next-state value (None => no write found)
    target_handler: int | None  # dispatcher route of next_state (None when unresolved)
    is_return: bool  # routes to exit/STOP, or no next-state at all
    branch_block: (
        int | None
    )  # the 2-way block that selected this arm (None => unconditional)
    write_block: int | None  # block whose state-var write produced next_state
    exit_block: int | None  # last block of the scanned path (the boundary)
    ordered_path: tuple[int, ...] = ()  # handler-local blocks visited (entry..exit)
    source_keyed_block: int | None = None  # exact route owner in this snapshot


@dataclass(frozen=True, slots=True)
class HandlerTransition:
    """All outgoing edges recovered for one handler block."""

    handler: int  # handler entry block serial
    states: tuple[int, ...]  # representative states the dispatcher routes here
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
        if row.target is not None
        and int(row.target) != (int(default) if default is not None else None)
    }


def _default_corridor_has_state_transition(
    flow_graph,
    dispatcher,
    default_target: int | None,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    dispatcher_entry_serial: int | None,
    dispatcher_region_serials: frozenset[int],
    handler_entries: set[int],
    max_depth: int,
) -> bool:
    """Return whether the dispatcher's fall-through is a live handler corridor.

    ``IntervalDispatcher.default_target`` identifies the no-match edge, not its
    semantic role.  Equality-chain fall-through blocks can still write a valid
    next state before re-entering the dispatcher; treating every default target
    as an exit drops that handler and strands its effects.  This probe is kept
    deliberately narrow: a non-STOP default block must have a bounded scan with
    a concrete state write that resolves through the dispatcher table.  A trap or
    an unresolved/open corridor therefore remains excluded.
    """
    if default_target is None:
        return False
    target = int(default_target)
    block = flow_graph.get_block(target)
    if block is None or _is_stop_block(block):
        return False
    paths = _scan_handler(
        flow_graph,
        target,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
        dispatcher_entry_serial=dispatcher_entry_serial,
        dispatcher_region_serials=dispatcher_region_serials,
        handler_entries=set(handler_entries) | {target},
        max_depth=max_depth,
    )
    for next_state, _branch_block, _ordered_path in paths:
        if next_state is None:
            continue
        routed = _resolved_dispatcher_target(dispatcher, int(next_state))
        if routed is not None:
            return True
    return False


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
    state_var_stkoff: int | None,
    state_var_reg: int | None = None,
    dispatcher_entry_serial: int | None,
    dispatcher_region_serials: frozenset[int] = frozenset(),
    handler_entries: set[int],
    max_depth: int = _MAX_CORRIDOR_DEPTH,
    initial_stk: dict[int, int] | None = None,
    initial_reg: dict[int, int] | None = None,
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
    effective_stkoff = int(state_var_stkoff) if state_var_stkoff is not None else -1

    def _current_state(stk: dict, reg: dict) -> int | None:
        if state_var_reg is not None:
            return reg.get(int(state_var_reg))
        return stk.get(effective_stkoff)

    # stack frames: (block, stk_map, reg_map, branch_block, visited, depth, path)
    stack: list[
        tuple[int, dict, dict, int | None, frozenset[int], int, tuple[int, ...]]
    ] = [
        (
            int(entry),
            dict(initial_stk or {}),
            dict(initial_reg or {}),
            None,
            frozenset({int(entry)}),
            0,
            (int(entry),),
        )
    ]

    while stack:
        blk_serial, stk, reg, branch, visited, depth, path = stack.pop()
        block = flow_graph.get_block(blk_serial)
        if block is None:
            results.append((_current_state(stk, reg), branch, path))
            continue

        # Fold this block's state-var write into the carried const env.
        nstk, nreg = _transfer_snapshot_constant_block(
            block, dict(stk), dict(reg), effective_stkoff
        )
        running_state = _current_state(nstk, nreg)

        succs = _concrete_successors(block, nstk, nreg)

        def _is_boundary_succ(s: int) -> bool:
            if dispatcher_entry_serial is not None and s == int(
                dispatcher_entry_serial
            ):
                return True
            if s in dispatcher_region_serials:
                return True
            if s in handler_entries and s != int(entry):
                return True
            succ_block = flow_graph.get_block(s)
            return _is_stop_block(succ_block)

        onward = [s for s in succs if s not in visited and not _is_boundary_succ(s)]

        terminal = (
            not succs or _is_stop_block(block) or not onward or depth >= max_depth
        )
        if terminal:
            results.append((running_state, branch, path))
            continue

        # A 2-way block whose arms continue is a state-selecting branch -- EXCEPT a
        # 2-way that branches straight to the dispatcher entry (one successor IS the
        # dispatcher back-edge).  That block is the loop-back / pre-header join every
        # handler funnels through, not a state selector; attributing the branch there
        # points the conditional-arm redirect at the dispatcher pre-header instead of
        # the real in-handler selector (the identity-switch ``state = cond ? a : b``
        # shape, where the selector is upstream and the arms reconverge before looping
        # back). Keeping the prior branch in that case leaves the attribution on the
        # true upstream selector. Narrow exclusion (dispatcher-edge only) so the
        # equality-chain conditional handlers (hodur) keep their existing attribution.
        branches_to_dispatcher = (
            dispatcher_entry_serial is not None
            and int(dispatcher_entry_serial) in succs
        )
        new_branch = (
            blk_serial if (len(succs) >= 2 and not branches_to_dispatcher) else branch
        )
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
        routed = _resolved_dispatcher_target(dispatcher, int(next_state))
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
    state_var_stkoff: int | None,
    *,
    state_var_reg: int | None = None,
    dispatcher_entry_serial: int | None = None,
    dispatcher_region_serials: frozenset[int] = frozenset(),
    authoritative_handler_serials: frozenset[int] = frozenset(),
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> tuple[HandlerTransition, ...]:
    """Recover each handler's outgoing transition(s) via the minimal model.

    Args:
        flow_graph: a :class:`d810.ir.flowgraph.FlowGraph` snapshot.
        dispatcher: an :class:`IntervalDispatcher` (state value -> handler block).
        state_var_stkoff: the dispatcher state variable's stack offset, when
            state is stack-resident.
        state_var_reg: the dispatcher state variable's register id, when it is
            register-resident.
        dispatcher_entry_serial: the dispatcher block the handlers loop back to;
            used as a scan boundary.  Falls back to the dispatcher's most-routed
            block when not supplied is intentionally NOT done — callers should
            pass it.
        dispatcher_region_serials: every comparison/router block in the same
            dispatcher.  A computed-goto BST may have several live re-entry
            nodes, so all of them are handler-scan boundaries; otherwise the
            scan crosses the router and attributes the next handler's write to
            the current handler.
        authoritative_handler_serials: exact equality/resolver handler entries.
            When supplied, these replace coarse interval-leaf targets as scan
            boundaries; a range partition may end at handler glue that must
            remain inside the current handler corridor.
        max_depth: corridor-scan bound.

    Returns:
        One :class:`HandlerTransition` per handler block, ordered by serial.
    """

    if state_var_stkoff is None and state_var_reg is None:
        return ()

    effective_stkoff = int(state_var_stkoff) if state_var_stkoff is not None else -1
    handler_entries = (
        {int(serial) for serial in authoritative_handler_serials}
        if authoritative_handler_serials
        else _handler_entries(dispatcher)
    )
    default_target = getattr(dispatcher, "default_target", None)
    if _default_corridor_has_state_transition(
        flow_graph,
        dispatcher,
        int(default_target) if default_target is not None else None,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
        dispatcher_entry_serial=dispatcher_entry_serial,
        dispatcher_region_serials=dispatcher_region_serials,
        handler_entries=handler_entries,
        max_depth=max_depth,
    ):
        handler_entries.add(int(default_target))
    states_by_handler = _states_by_handler(dispatcher)
    seed_stk: dict[int, int] = {}
    seed_reg: dict[int, int] = {}
    if dispatcher_entry_serial is not None:
        dispatcher_entry = flow_graph.get_block(int(dispatcher_entry_serial))
        if dispatcher_entry is not None:
            seed_stk, seed_reg = _transfer_snapshot_constant_block(
                dispatcher_entry,
                {},
                {},
                effective_stkoff,
            )
            if state_var_stkoff is not None:
                seed_stk.pop(effective_stkoff, None)
    results: list[HandlerTransition] = []

    for handler in sorted(handler_entries):
        paths = _scan_handler(
            flow_graph,
            handler,
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
            dispatcher_entry_serial=dispatcher_entry_serial,
            dispatcher_region_serials=dispatcher_region_serials,
            handler_entries=handler_entries,
            max_depth=max_depth,
            initial_stk=seed_stk,
            initial_reg=seed_reg,
        )
        # Dedup arms by next_state: identical next-states on multiple paths are
        # the same edge (a degenerate branch), not a conditional.
        seen: dict[object, TransitionArm] = {}
        for next_state, branch_block, ordered_path in paths:
            if next_state is not None:
                key: object = int(next_state) & 0xFFFFFFFF
            elif branch_block is not None:
                try:
                    branch_index = ordered_path.index(int(branch_block))
                except ValueError:
                    branch_index = -1
                branch_successor = (
                    int(ordered_path[branch_index + 1])
                    if branch_index >= 0 and branch_index + 1 < len(ordered_path)
                    else None
                )
                key = (None, int(branch_block), branch_successor)
            else:
                key = None
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


def resolve_materialized_handler_transition_targets(
    transitions: tuple[HandlerTransition, ...],
    routes: tuple[MaterializedStateRoute, ...],
    handler_serials: frozenset[int],
    *,
    dispatcher_block_serials: frozenset[int] = frozenset(),
) -> tuple[HandlerTransition, ...]:
    """Override coarse handler-arm routes with exact snapshot-local evidence.

    A :class:`MaterializedStateRoute` identifies a state-write block and its
    concrete-dispatch target in the *same* FlowGraph snapshot.  Accept it only
    when ``(source block, state)`` identifies exactly one handler arm globally,
    the target is an authoritative handler, and all matching facts agree.  A
    recovered non-router handler target is already stronger than this fallback
    evidence and is preserved; only unresolved/return arms or targets still in
    the dispatcher region may be refined to a different handler.
    """
    if not routes or not handler_serials:
        return transitions
    exact_owner_matches: dict[tuple[int, int], set[tuple[int, int]]] = {}
    fallback_matches: dict[tuple[int, int], set[tuple[int, int]]] = {}
    for route in routes:
        target = int(route.target_handler_serial)
        if target not in handler_serials:
            continue
        state = int(route.state_constant) & 0xFFFFFFFF
        source_handler = route.source_handler_serial
        if (
            source_handler is not None
            and int(route.source_block_serial) == int(source_handler)
            and not route.handler_exit_proven
        ):
            continue
        matches = [
            (transition_index, arm_index)
            for transition_index, transition in enumerate(transitions)
            for arm_index, arm in enumerate(transition.arms)
            if arm.next_state is not None
            and (int(arm.next_state) & 0xFFFFFFFF) == state
            and int(route.source_block_serial) in arm.ordered_path
            and (
                source_handler is None or int(transition.handler) == int(source_handler)
            )
        ]
        if len(matches) == 1:
            destination = (
                exact_owner_matches if source_handler is not None else fallback_matches
            )
            destination.setdefault(matches[0], set()).add(
                (target, int(route.source_block_serial))
            )

    resolved: list[HandlerTransition] = []
    for transition_index, transition in enumerate(transitions):
        arms: list[TransitionArm] = []
        for arm_index, arm in enumerate(transition.arms):
            key = (transition_index, arm_index)
            exact_owner = key in exact_owner_matches
            facts = (
                exact_owner_matches[key]
                if exact_owner
                else fallback_matches.get(key, set())
            )
            corroborated_exact_owner = bool(
                exact_owner
                and len(facts) == 1
                and fallback_matches.get(key, set()) == facts
            )
            if len(facts) != 1:
                arms.append(arm)
                continue
            target, source = next(iter(facts))
            if arm.target_handler is not None and not arm.is_return:
                existing_target = int(arm.target_handler)
                if (
                    existing_target != int(target)
                    and existing_target not in dispatcher_block_serials
                    and not corroborated_exact_owner
                ):
                    arms.append(
                        replace(arm, source_keyed_block=int(source))
                        if exact_owner
                        else arm
                    )
                    continue
                if existing_target == int(target) and not exact_owner:
                    arms.append(arm)
                    continue
            arms.append(
                replace(
                    arm,
                    target_handler=int(target),
                    is_return=False,
                    source_keyed_block=int(source),
                )
            )
        resolved.append(replace(transition, arms=tuple(arms)))
    return tuple(resolved)


def resolve_materialized_handler_exit_states(
    transitions: tuple[HandlerTransition, ...],
    routes: tuple[MaterializedStateRoute, ...],
    handler_serials: frozenset[int],
) -> tuple[HandlerTransition, ...]:
    """Recover a handler-exit state write dropped from live microcode.

    Handler replay publishes an exact snapshot-local route even when Hex-Rays
    removed the state-register write.  Consume it only when one route source
    identifies one unresolved arm globally and its target is authoritative.
    An explicit terminal delivery outranks an ordinary replay route from the
    same source: the replay can inherit the incoming state after Hex-Rays folds
    the terminal state write, while the terminal route names the exact native
    endpoint.
    """
    if not routes or not handler_serials:
        return transitions
    conditional_arm_candidates: dict[tuple[int, int], set[tuple[int, int, int]]] = {}
    terminal_candidates: dict[tuple[int, int], set[tuple[int, int, int]]] = {}
    owned_candidates: dict[tuple[int, int], set[tuple[int, int, int]]] = {}
    fallback_candidates: dict[tuple[int, int], set[tuple[int, int, int]]] = {}
    clone_targets_by_handler_state: dict[tuple[int, int], set[int]] = {}
    for route in routes:
        if route.source_handler_serial is not None or route.handler_exit_proven:
            continue
        target = int(route.target_handler_serial)
        if target not in handler_serials:
            continue
        key = (
            int(route.source_block_serial),
            int(route.state_constant) & 0xFFFFFFFF,
        )
        clone_targets_by_handler_state.setdefault(key, set()).add(target)
    for route in routes:
        target = int(route.target_handler_serial)
        if target not in handler_serials:
            continue
        source = int(route.source_block_serial)
        source_handler = route.source_handler_serial
        matches: list[tuple[int, int]] = []
        for transition_index, transition in enumerate(transitions):
            if source_handler is not None and int(transition.handler) != int(
                source_handler
            ):
                continue
            for arm_index, arm in enumerate(transition.arms):
                missing_state_on_path = (
                    arm.next_state is None and source in arm.ordered_path
                )
                exact_exit_owner = (
                    arm.exit_block is not None
                    and source == int(arm.exit_block)
                    and arm.target_handler is not None
                    and int(arm.target_handler) == int(transition.handler)
                )
                handler_owned_self_loop = (
                    bool(route.handler_exit_proven)
                    and source_handler is not None
                    and source == int(source_handler)
                    and source == int(transition.handler)
                    and source in arm.ordered_path
                    and arm.next_state is not None
                    and (int(arm.next_state) & 0xFFFFFFFF)
                    in {int(state) & 0xFFFFFFFF for state in transition.states}
                    and arm.target_handler is not None
                    and int(arm.target_handler) == int(transition.handler)
                    and not arm.is_return
                )
                clone_owned_self_loop = False
                if (
                    bool(route.handler_exit_proven)
                    and source_handler is not None
                    and source == int(source_handler)
                    and source == int(transition.handler)
                    and source in arm.ordered_path
                    and arm.next_state is not None
                    and (int(arm.next_state) & 0xFFFFFFFF)
                    in {int(state) & 0xFFFFFFFF for state in transition.states}
                    and arm.target_handler is not None
                    and not arm.is_return
                ):
                    clone_targets = clone_targets_by_handler_state.get(
                        (
                            int(transition.handler),
                            int(arm.next_state) & 0xFFFFFFFF,
                        ),
                        set(),
                    )
                    clone_owned_self_loop = clone_targets == {int(arm.target_handler)}
                if (
                    missing_state_on_path
                    or exact_exit_owner
                    or handler_owned_self_loop
                    or clone_owned_self_loop
                ):
                    matches.append((transition_index, arm_index))
        if len(matches) == 1:
            destination = (
                terminal_candidates
                if route.proof_kind == "terminal_state_route"
                else (
                    conditional_arm_candidates
                    if route.proof_kind == "conditional_arm"
                    else (
                        owned_candidates
                        if source_handler is not None
                        else fallback_candidates
                    )
                )
            )
            destination.setdefault(matches[0], set()).add(
                (
                    int(route.state_constant) & 0xFFFFFFFF,
                    target,
                    source,
                )
            )

    resolved: list[HandlerTransition] = []
    for transition_index, transition in enumerate(transitions):
        arms: list[TransitionArm] = []
        for arm_index, arm in enumerate(transition.arms):
            key = (transition_index, arm_index)
            facts = (
                terminal_candidates[key]
                if key in terminal_candidates
                else (
                    conditional_arm_candidates[key]
                    if key in conditional_arm_candidates
                    else (
                        owned_candidates[key]
                        if key in owned_candidates
                        else fallback_candidates.get(key, set())
                    )
                )
            )
            if len(facts) != 1:
                arms.append(arm)
                continue
            state, target, source = next(iter(facts))
            arms.append(
                replace(
                    arm,
                    next_state=int(state),
                    target_handler=int(target),
                    is_return=key in terminal_candidates,
                    source_keyed_block=int(source),
                )
            )
        resolved.append(replace(transition, arms=tuple(arms)))
    return tuple(resolved)
