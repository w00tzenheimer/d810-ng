"""Portable evidence for a resolver-materialized indirect transfer.

The resolver may prove the native target of an indirect jump before byte-patch
materialization makes that transfer visible to Hex-Rays.  This module keeps that
proof independent of IDA and maps it back onto a post-materialization FlowGraph
only when both the source anchor and the target block are unambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.conditional_jump_eval import predicate_jump_taken
from d810.analyses.control_flow.route_predicate import DecisionDag
from d810.core.typing import Mapping, Sequence
from d810.ir.semantics import PredicateKind
from d810.ir.flowgraph import FlowGraph, InsnKind, InsnSnapshot, MopSnapshot


@dataclass(frozen=True, slots=True)
class MaterializedIndirectTransfer:
    """One resolver-proven native transfer retained through materialization.

    ``materialized_anchor_eas`` names instructions introduced or retained by the
    byte patch.  Recovery matches those EAs in snapshot blocks; it never reads
    raw bytes.  A two-way record carries predicate provenance but is intentionally
    not accepted by :func:`lookup_singleton_transfer_target` until an arm-aware
    consumer can prove its polarity.
    """

    source_jmp_ea: int
    source_block_ea: int
    materialized_anchor_eas: tuple[int, ...]
    target_eas: tuple[int, ...]
    next_target_ea: int | None = None
    condition_code: int | None = None
    true_target_ea: int | None = None
    false_target_ea: int | None = None
    #: Exact state constant tested by a residual equality fragment, if proven.
    selector_state_constant: int | None = None
    #: Predicate evidence retained by the static resolver before Hex-Rays drops
    #: the detached comparison edge from its connected microcode CFG.
    selector_state_var_reg: int | None = None
    selector_compare_constant: int | None = None
    selector_state_on_left: bool | None = None
    #: Resolver-proven function-invariant Hex-Rays mreg values.  Consumers use
    #: these only to fill missing microcode snapshot cells; path-local values
    #: remain authoritative.
    context_register_values: tuple[tuple[int, int], ...] = ()
    #: Exact singleton mreg values at ``source_block_ea`` from the resolver's
    #: static fixpoint.  Path-local concrete state still wins on merge.
    source_register_values: tuple[tuple[int, int], ...] = ()
    #: Exact singleton mreg values on arrival at the transfer's unique target.
    #: This is deliberately separate from ``source_register_values``: detached
    #: handler replay may seed only evidence captured after the selected arm
    #: has reached that target.
    target_register_values: tuple[tuple[int, int], ...] = ()
    #: Exact singleton mreg snapshots at every resolver block entry.  One
    #: transfer in a function may carry the shared tuple; consumers aggregate.
    corridor_register_snapshots: tuple[
        tuple[int, tuple[tuple[int, int], ...]], ...
    ] = ()
    resolver_kind: str = "static_fixpoint"
    #: Exclusive end of the byte region owned by this materialization.  This is
    #: stronger than instruction-start anchors when a later planner must prove
    #: that a replacement sequence fits without guessing instruction lengths.
    materialized_region_end_ea: int | None = None
    #: Exact native handler-body ranges captured before byte delivery rewrites
    #: the indirect back-edge and makes later CFG traversal over-approximate.
    owned_native_ranges: tuple[tuple[int, int], ...] = ()
    #: A live CALLS-maturity handler predicate that later residual routing may
    #: fold to a one-way edge.  These fields describe the boolean ``reg != 0``
    #: value only; ``true_target_ea``/``false_target_ea`` carry its exact arms.
    predicate_register: int | None = None
    predicate_size: int | None = None
    #: Optional right-hand register for a live ``left != right`` predicate.
    #: ``None`` retains the original ``register != 0`` shape.
    predicate_compare_register: int | None = None
    #: Optional nonzero right-hand constant for a live comparison predicate.
    predicate_compare_constant: int | None = None
    predicate_predecessor_ea: int | None = None
    #: Concrete dispatcher states selected by the normalized ``reg != 0``
    #: predicate.  These survive maturity-local target-EA folding and let the
    #: current dispatcher model rebind each arm to its live handler block.
    predicate_true_state: int | None = None
    predicate_false_state: int | None = None
    #: Whether the normalized nonzero arm was the original branch's taken
    #: successor.  Required only while that live 2-way predicate still exists.
    predicate_true_is_taken: bool | None = None
    #: The existing live conditional must be preserved and both arms rebound.
    #: Set only when exact predicate-EA handler replay, rather than a native
    #: residual corridor, authorized the bridge.
    predicate_preserve_live: bool = False
    #: Stable native entry of the recovered dispatcher that authorized this
    #: row.  Consumers use it only as a CFG cut point; maturity-local block
    #: serials never cross the evidence boundary.
    dispatcher_entry_ea: int | None = None
    #: Stable native entries of every block in the recovered dispatcher region.
    #: Boundary consumers cut only edges entering this proven set.
    dispatcher_router_eas: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class MaterializedStateRoute:
    """One exact logical-CFG route proven for a concrete state write.

    The producer keys this evidence by the portable microcode block that owns
    the state-write/back-edge partition.  Consumers may use it only for the
    same block and state and only when the target remains a known handler or a
    resolver-proven terminal endpoint in the current FlowGraph.
    """

    source_block_serial: int
    state_constant: int
    target_handler_serial: int
    #: Handler entry that produced this route during native handler replay.
    #: ``None`` means the route came from a state-write anchor instead.
    source_handler_serial: int | None = None
    #: Native replay reached a resolver-owned handler exit after proving the
    #: state write.  This can authorize the handler block itself as edge owner
    #: when Hex-Rays folded the exit instruction into that block.
    handler_exit_proven: bool = False
    #: Evidence class used only to rank facts for the same arm.  A live
    #: conditional-arm route is branch-local and outranks generic state-write
    #: candidates that happen to share its source block.
    proof_kind: str = "state_route"


@dataclass(frozen=True, slots=True)
class TerminalReturnCarrierRequest:
    """Request exact early-maturity return-value evidence for one terminal arm.

    The CALLS graph proves that ``source_handler_ea`` writes ``state_constant``
    and routes directly to the real return epilogue at ``terminal_target_ea``.
    An IDA-backed producer may use this portable request to capture a return
    register assignment before CALLS drops it; the request itself carries no
    native instruction semantics.
    """

    source_handler_ea: int
    terminal_target_ea: int
    state_var_reg: int
    state_constant: int


@dataclass(frozen=True, slots=True)
class ResidualStateRouteBridgePlan:
    """One profile-gated logical edge for an unpatchable state route."""

    source_block_serial: int
    target_block_serial: int
    source_write_ea: int
    target_ea: int
    state_constant: int


def plan_terminal_return_carrier_requests(
    flow_graph: FlowGraph,
    routes: Sequence[MaterializedStateRoute],
    *,
    state_var_reg: int,
) -> tuple[TerminalReturnCarrierRequest, ...]:
    """Project exact terminal routes to unambiguous early-maturity requests.

    Only routes explicitly classified by their producer as terminal qualify.
    Conflicting terminal targets for the same source/state pair abstain rather
    than selecting a return value from topology alone.
    """
    candidates: dict[tuple[int, int], set[int]] = {}
    for route in routes:
        if route.proof_kind != "terminal_state_route":
            continue
        source = flow_graph.get_block(int(route.source_block_serial))
        target = flow_graph.get_block(int(route.target_handler_serial))
        if (
            source is None
            or target is None
            or int(source.start_ea) <= 0
            or int(target.start_ea) <= 0
            or int(source.start_ea) == int(target.start_ea)
        ):
            continue
        key = (
            int(source.start_ea),
            int(route.state_constant) & 0xFFFFFFFF,
        )
        candidates.setdefault(key, set()).add(int(target.start_ea))

    return tuple(
        TerminalReturnCarrierRequest(
            source_handler_ea=source_ea,
            terminal_target_ea=next(iter(target_eas)),
            state_var_reg=int(state_var_reg),
            state_constant=state_constant,
        )
        for (source_ea, state_constant), target_eas in sorted(candidates.items())
        if len(target_eas) == 1
    )


@dataclass(frozen=True, slots=True)
class ResidualIndirectCallNeutralizationPlan:
    """One native indirect jump that Hex-Rays mis-lifted as a call.

    The plan is emitted only when the static resolver proves the native jump,
    the current microcode has one exact call-shaped instruction at that EA,
    and the state-machine lowering independently replaces the block's sole
    dispatcher edge with one known handler edge.
    """

    source_block_serial: int
    source_jmp_ea: int
    redirected_target_serial: int


_NATIVE_JUMP_RESOLVER_KINDS = frozenset(
    {"static_fixpoint", "detached_static_fixpoint"}
)


def _operand_contains_call(operand: MopSnapshot | None) -> bool:
    if operand is None:
        return False
    if operand.sub_kind is InsnKind.CALL:
        return True
    return (
        _operand_contains_call(operand.sub_l)
        or _operand_contains_call(operand.sub_r)
        or any(_operand_contains_call(argument) for argument in operand.args)
    )


def _instruction_is_call_artifact(instruction: InsnSnapshot) -> bool:
    return bool(
        instruction.is_call
        or instruction.kind is InsnKind.CALL
        or _operand_contains_call(instruction.l)
        or _operand_contains_call(instruction.r)
        or _operand_contains_call(instruction.d)
    )


def plan_resolver_proven_indirect_call_neutralizations(
    transfers: Sequence[MaterializedIndirectTransfer],
    flow_graph: FlowGraph,
    *,
    redirected_targets_by_source: Mapping[int, Sequence[int]],
    allowed_target_serials: frozenset[int],
) -> tuple[ResidualIndirectCallNeutralizationPlan, ...]:
    """Neutralize only stale call artifacts replaced by a proven handler edge.

    A native ``jmp reg`` can reach CALLS as a nested or top-level ``m_icall``.
    NOPing that instruction is safe only after two independent proofs agree:
    the static resolver identifies the exact native jump EA, and the unflatten
    plan supplies one unique replacement edge to a known handler.  Missing,
    ambiguous, or already-live edges abstain.
    """
    plans: set[ResidualIndirectCallNeutralizationPlan] = set()
    for transfer in transfers:
        if (
            transfer.resolver_kind not in _NATIVE_JUMP_RESOLVER_KINDS
            or int(transfer.source_jmp_ea) <= 0
            or not transfer.target_eas
        ):
            continue
        source_matches = tuple(
            block
            for block in flow_graph.blocks.values()
            if any(
                int(instruction.ea) == int(transfer.source_jmp_ea)
                and _instruction_is_call_artifact(instruction)
                for instruction in block.insn_snapshots
            )
        )
        if len(source_matches) != 1:
            continue
        source = source_matches[0]
        if int(source.nsucc) != 1:
            continue
        redirected_targets = {
            int(target)
            for target in redirected_targets_by_source.get(
                int(source.serial), ()
            )
        }
        if len(redirected_targets) != 1:
            continue
        redirected_target = next(iter(redirected_targets))
        if (
            redirected_target not in allowed_target_serials
            or flow_graph.get_block(redirected_target) is None
            or redirected_target in source.succs
        ):
            continue
        plans.add(
            ResidualIndirectCallNeutralizationPlan(
                source_block_serial=int(source.serial),
                source_jmp_ea=int(transfer.source_jmp_ea),
                redirected_target_serial=redirected_target,
            )
        )
    return tuple(
        sorted(
            plans,
            key=lambda plan: (
                int(plan.source_jmp_ea),
                int(plan.source_block_serial),
                int(plan.redirected_target_serial),
            ),
        )
    )


def plan_residual_state_route_bridges(
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    live_blocks_by_ea: Mapping[int, int],
    one_way_source_blocks: frozenset[int],
) -> tuple[ResidualStateRouteBridgePlan, ...]:
    """Plan unambiguous live-MBA edges from residual route evidence.

    The producer retains every proven source because early-maturity boundary
    capture needs the complete native transfer relation.  This legacy LOCOPT
    bridge has a narrower ownership rule: activating two detached roots for the
    same ``(state, target)`` can replace a still-live dispatcher frontier with
    an imported clone.  After rejecting ambiguous per-source rows, therefore,
    bind only the deterministic lowest-EA source for each state/target pair.

    Every selected source must still bind by stable EA to a one-way block at
    the current maturity, so no payload branch can be erased.  The unselected
    same-state sources remain on the dispatcher and are handled by ordinary
    state-machine lowering.
    """
    by_source: dict[int, set[ResidualStateRouteBridgePlan]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "residual_state_route_evidence"
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        source_ea = int(transfer.source_jmp_ea)
        target_ea = int(transfer.target_eas[0])
        source_serial = live_blocks_by_ea.get(source_ea)
        target_serial = live_blocks_by_ea.get(target_ea)
        if (
            source_serial is None
            or target_serial is None
            or int(source_serial) not in one_way_source_blocks
            or int(source_serial) == int(target_serial)
        ):
            continue
        plan = ResidualStateRouteBridgePlan(
            source_block_serial=int(source_serial),
            target_block_serial=int(target_serial),
            source_write_ea=source_ea,
            target_ea=target_ea,
            state_constant=int(transfer.selector_state_constant) & 0xFFFFFFFF,
        )
        by_source.setdefault(int(source_serial), set()).add(plan)
    unambiguous_sources = tuple(
        next(iter(plans))
        for plans in by_source.values()
        if len(plans) == 1
    )
    by_state_target: dict[
        tuple[int, int],
        list[ResidualStateRouteBridgePlan],
    ] = {}
    for plan in unambiguous_sources:
        by_state_target.setdefault(
            (int(plan.state_constant), int(plan.target_ea)),
            [],
        ).append(plan)
    return tuple(
        sorted(
            (
                min(
                    plans,
                    key=lambda plan: (
                        int(plan.source_write_ea),
                        int(plan.source_block_serial),
                    ),
                )
                for plans in by_state_target.values()
            ),
            key=lambda plan: (
                int(plan.source_write_ea),
                int(plan.target_ea),
            ),
        )
    )


def unique_materialized_equality_target_eas(
    transfers: Sequence[MaterializedIndirectTransfer],
    state_var_reg: int,
    *,
    validated_candidate_target_eas: frozenset[int] = frozenset(),
) -> dict[int, int]:
    """Project exact equality evidence to one handler EA per state.

    Resolver-owned equality routes are authoritative when present.  The live
    condition-chain map supplies a fallback for states whose detached equality
    fragment was never materialized.  Ambiguous resolver evidence abstains and
    is never replaced by a weaker fallback.
    """
    primary: dict[int, set[int]] = {}
    fallback: dict[int, set[int]] = {}
    expected_register = int(state_var_reg)
    for transfer in transfers:
        if transfer.selector_state_var_reg != expected_register:
            continue
        state: int | None = None
        target: int | None = None
        if transfer.resolver_kind == "static_equality_fixpoint":
            if transfer.selector_compare_constant is None:
                continue
            state = int(transfer.selector_compare_constant) & 0xFFFFFFFF
            if transfer.condition_code == 4:
                target = transfer.true_target_ea
            elif transfer.condition_code == 5:
                target = transfer.false_target_ea
        elif transfer.resolver_kind in {
            "static_handler_entry_route",
            "static_equality_route",
            "residual_state_route_evidence",
            "residual_state_route",
        }:
            if (
                transfer.selector_state_constant is not None
                and len(transfer.target_eas) == 1
            ):
                state = int(transfer.selector_state_constant) & 0xFFFFFFFF
                target = int(transfer.target_eas[0])
        elif transfer.resolver_kind == "static_equality_candidate":
            if (
                transfer.selector_state_constant is not None
                and len(transfer.target_eas) == 1
                and int(transfer.target_eas[0])
                in validated_candidate_target_eas
            ):
                state = int(transfer.selector_state_constant) & 0xFFFFFFFF
                target = int(transfer.target_eas[0])
        elif transfer.resolver_kind == "condition_chain_handler_evidence":
            if (
                transfer.selector_state_constant is not None
                and len(transfer.target_eas) == 1
            ):
                state = int(transfer.selector_state_constant) & 0xFFFFFFFF
                target = int(transfer.target_eas[0])
        else:
            continue
        if state is None or target is None or int(target) not in transfer.target_eas:
            continue
        candidates = (
            fallback
            if transfer.resolver_kind == "condition_chain_handler_evidence"
            else primary
        )
        candidates.setdefault(state, set()).add(int(target))

    result: dict[int, int] = {}
    for state in primary.keys() | fallback.keys():
        primary_targets = primary.get(state, set())
        if primary_targets:
            if len(primary_targets) == 1:
                result[state] = next(iter(primary_targets))
            continue
        fallback_targets = fallback.get(state, set())
        if len(fallback_targets) == 1:
            result[state] = next(iter(fallback_targets))
    return result


def exact_materialized_handler_override_serial(
    *,
    target_ea: int,
    target_serial: int,
    target_native_identity_ea: int,
    imported_target_eas: frozenset[int],
) -> int | None:
    """Accept only an exact native entry or a registered imported root.

    A target EA merely contained in a live block can name a comparison-tree
    router after Hex-Rays merges blocks.  Such containment is not strong enough
    to replace the state-to-handler map.  Imported detached roots are the one
    exception: their synthetic block start may be the function entry, while
    the importer registry preserves the exact native target identity.
    """
    target = int(target_ea)
    if target in imported_target_eas or int(target_native_identity_ea) == target:
        return int(target_serial)
    return None


def materialized_terminal_target_eas_by_source(
    transfers: Sequence[MaterializedIndirectTransfer],
    state_var_reg: int,
) -> dict[int, tuple[int, ...]]:
    """Project detached terminal evidence to exact target EAs when possible.

    A detached fixpoint may stop at the two native BST roots even though its
    source register snapshot proves one concrete state.  In that case the
    unique equality map is stronger and selects the live handler EA.  Missing,
    non-singleton, or ambiguous state evidence preserves the original target
    set so the terminal planner abstains as before.
    """
    equality_targets = unique_materialized_equality_target_eas(
        transfers,
        int(state_var_reg),
    )
    candidates: dict[int, set[int]] = {}
    for transfer in transfers:
        if transfer.resolver_kind not in {
            "static_fixpoint",
            "detached_static_fixpoint",
        }:
            continue
        targets = {int(target_ea) for target_ea in transfer.target_eas}
        if len(targets) > 1:
            state_values = {
                int(value) & 0xFFFFFFFF
                for register, value in transfer.source_register_values
                if int(register) == int(state_var_reg)
            }
            if len(state_values) == 1:
                exact_target = equality_targets.get(next(iter(state_values)))
                if exact_target is not None:
                    targets = {int(exact_target)}
        candidates.setdefault(int(transfer.source_jmp_ea), set()).update(targets)
    return {
        source_ea: tuple(sorted(targets))
        for source_ea, targets in candidates.items()
        if targets
    }


def merge_materialized_handler_maps(
    exact_state_to_handler: Mapping[int, int],
    condition_chain_handler_state_map: Mapping[int, int],
    condition_chain_state_to_handler: Mapping[int, int] | None = None,
) -> tuple[dict[int, tuple[int, ...]], dict[int, int], frozenset[int]]:
    """Merge exact and comparison-tree handler maps without guessing.

    The preliminary dispatcher map can lose equality leaves that remain in the
    production condition-chain model.  Replay needs both views, but accepts a
    state only when every producer agrees on its handler.  Conflicting states
    are omitted while the full handler set remains available for target
    validation.
    """
    candidates: dict[int, set[int]] = {}
    for state, handler in exact_state_to_handler.items():
        candidates.setdefault(int(state) & 0xFFFFFFFF, set()).add(int(handler))
    for handler, state in condition_chain_handler_state_map.items():
        candidates.setdefault(int(state) & 0xFFFFFFFF, set()).add(int(handler))
    for state, handler in (condition_chain_state_to_handler or {}).items():
        candidates.setdefault(int(state) & 0xFFFFFFFF, set()).add(int(handler))

    handler_serials = frozenset(
        handler for handlers in candidates.values() for handler in handlers
    )
    handler_targets = {
        state: next(iter(handlers))
        for state, handlers in candidates.items()
        if len(handlers) == 1
    }
    states_by_handler: dict[int, list[int]] = {}
    for state, handler in handler_targets.items():
        states_by_handler.setdefault(int(handler), []).append(int(state))
    handler_states = {
        handler: tuple(sorted(states))
        for handler, states in states_by_handler.items()
    }
    return handler_states, handler_targets, handler_serials


def override_materialized_handler_targets(
    handler_targets: Mapping[int, int],
    handler_serials: frozenset[int],
    overrides_by_state: Mapping[int, int],
) -> tuple[dict[int, tuple[int, ...]], dict[int, int], frozenset[int]]:
    """Replace known state owners with stronger live-handler evidence.

    Overrides are derived from unique equality evidence, so they may restore a
    state omitted by the merged dispatcher maps.  The original handler serials
    remain authoritative CFG endpoints, while imported live roots join that
    set for route validation.
    """
    updated_targets = {
        int(state) & 0xFFFFFFFF: int(handler)
        for state, handler in handler_targets.items()
    }
    applied_targets: set[int] = set()
    for state, handler in overrides_by_state.items():
        normalized_state = int(state) & 0xFFFFFFFF
        updated_targets[normalized_state] = int(handler)
        applied_targets.add(int(handler))

    states_by_handler: dict[int, list[int]] = {}
    for state, handler in updated_targets.items():
        states_by_handler.setdefault(int(handler), []).append(int(state))
    updated_states = {
        handler: tuple(sorted(states))
        for handler, states in states_by_handler.items()
    }
    return (
        updated_states,
        updated_targets,
        frozenset((*handler_serials, *applied_targets)),
    )


def lookup_materialized_state_route(
    routes: tuple[MaterializedStateRoute, ...],
    *,
    source_block_serial: int,
    state_constant: int,
    handler_serials: frozenset[int],
) -> int | None:
    """Return the unique exact handler route for ``(source, state)``.

    Duplicate agreeing facts are harmless.  Conflicting targets, a target no
    longer present in the recovered handler set, or missing handler authority
    all abstain.
    """
    if not handler_serials:
        return None
    source = int(source_block_serial)
    state = int(state_constant) & 0xFFFFFFFF
    candidates = {
        int(route.target_handler_serial)
        for route in routes
        if int(route.source_block_serial) == source
        and (int(route.state_constant) & 0xFFFFFFFF) == state
    }
    if len(candidates) != 1 or not candidates.issubset(handler_serials):
        return None
    return next(iter(candidates))


_CC_PREDICATES = {
    2: PredicateKind.ULT,
    3: PredicateKind.UGE,
    4: PredicateKind.EQ,
    5: PredicateKind.NE,
    6: PredicateKind.ULE,
    7: PredicateKind.UGT,
    12: PredicateKind.SLT,
    13: PredicateKind.SGE,
    14: PredicateKind.SLE,
    15: PredicateKind.SGT,
}


def condition_code_predicate(condition_code: int | None) -> PredicateKind | None:
    """Translate one proven x86 condition-code nibble to portable semantics."""
    if condition_code is None:
        return None
    return _CC_PREDICATES.get(int(condition_code))


def _block_eas(block) -> frozenset[int]:
    """All native instruction anchors represented by a snapshot block."""
    eas = {int(block.start_ea)}
    tail = getattr(block, "tail", None)
    if tail is not None:
        eas.add(int(tail.ea))
    eas.update(int(insn.ea) for insn in tuple(getattr(block, "insn_snapshots", ()) or ()))
    return frozenset(eas)


def find_unique_target_block(
    flow_graph: FlowGraph,
    target_ea: int,
    next_target_ea: int | None = None,
) -> int | None:
    """Map one native target label to one snapshot block, or abstain.

    Exact start/tail/instruction matches are authoritative and must identify one
    block.  If an exact label was folded away, an optional *bounded* label
    interval may select the unique earliest later micro-instruction.  Without a
    next label there is no safe interval, so a non-exact target abstains.
    """
    target = int(target_ea)
    exact = [
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if target in _block_eas(block)
    ]
    if len(exact) == 1:
        return exact[0]
    if exact:
        return None
    if next_target_ea is None or int(next_target_ea) <= target:
        return None

    candidates: list[tuple[int, int]] = []
    interval_end = int(next_target_ea)
    for serial, block in flow_graph.blocks.items():
        later = sorted(ea for ea in _block_eas(block) if target < ea < interval_end)
        if later:
            candidates.append((later[0], int(serial)))
    if not candidates:
        return None
    earliest = min(ea for ea, _serial in candidates)
    serials = {serial for ea, serial in candidates if ea == earliest}
    return next(iter(serials)) if len(serials) == 1 else None


def find_unique_target_entry_block(
    flow_graph: FlowGraph,
    target_ea: int,
    next_target_ea: int | None = None,
) -> int | None:
    """Map a control-flow label, preferring its unique exact block start.

    Hex-Rays may retain the target instruction EA as provenance in a predecessor
    while also creating the real target block at that EA.  A unique block start
    is the stronger CFG identity; otherwise the conservative generic mapper and
    its optional bounded interval remain authoritative.
    """
    target = int(target_ea)
    starts = {
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if int(block.start_ea) == target
    }
    if len(starts) == 1:
        return next(iter(starts))
    if starts:
        return None
    return find_unique_target_block(flow_graph, target, next_target_ea)


def lookup_singleton_transfer_target(
    flow_graph: FlowGraph,
    transfer: MaterializedIndirectTransfer,
    source_block: int,
    via_block: int | None = None,
) -> int | None:
    """Resolve a one-target proof associated with one transition source.

    This intentionally consumes neither multi-target records, state-keyed
    records, nor a source that lacks a post-materialization anchor.  A target
    attached to one selector state is not an unconditional singleton when a
    caller asks about a different state; the state-aware lookup must own it.
    """
    if len(transfer.target_eas) != 1:
        return None
    if (
        transfer.selector_state_constant is not None
        or transfer.selector_state_var_reg is not None
        or transfer.selector_compare_constant is not None
        or transfer.selector_state_on_left is not None
    ):
        return None
    source_serials = {int(source_block)}
    if via_block is not None:
        source_serials.add(int(via_block))
    anchors = frozenset(int(ea) for ea in transfer.materialized_anchor_eas)
    if not anchors:
        return None
    if not any(
        anchors.intersection(_block_eas(block))
        for serial in source_serials
        if (block := flow_graph.get_block(serial)) is not None
    ):
        return None
    return find_unique_target_entry_block(
        flow_graph,
        int(transfer.target_eas[0]),
        transfer.next_target_ea,
    )


def lookup_state_keyed_transfer_target(
    flow_graph: FlowGraph,
    transfer: MaterializedIndirectTransfer,
    state_constant: int,
    *,
    state_var_reg: int | None = None,
) -> int | None:
    """Resolve the equality arm proven for one exact selector state.

    Residual microcode records the compared state constant together with native
    x86 condition-code polarity and both resolver-proven targets.  A completed
    equality-route replay may instead carry one already-selected target for the
    exact state.  Other predicates, missing fields, a mismatched state, or a
    target that cannot be mapped uniquely all abstain.
    """
    selector = transfer.selector_state_constant
    if selector is not None:
        if (int(selector) & 0xFFFFFFFF) != (int(state_constant) & 0xFFFFFFFF):
            return None
        if len(transfer.target_eas) == 1 and transfer.condition_code is None:
            target_ea = int(transfer.target_eas[0])
        elif transfer.condition_code == 4:
            target_ea = transfer.true_target_ea
        elif transfer.condition_code == 5:
            target_ea = transfer.false_target_ea
        else:
            return None
    else:
        if (
            state_var_reg is None
            or transfer.selector_state_var_reg is None
            or int(transfer.selector_state_var_reg) != int(state_var_reg)
            or transfer.selector_compare_constant is None
            or transfer.selector_state_on_left is None
        ):
            return None
        predicate = condition_code_predicate(transfer.condition_code)
        if predicate is None:
            return None
        if transfer.selector_state_on_left:
            left, right = int(state_constant), int(transfer.selector_compare_constant)
        else:
            left, right = int(transfer.selector_compare_constant), int(state_constant)
        taken = predicate_jump_taken(predicate, left, right, operand_size=4)
        if taken is None:
            return None
        target_ea = transfer.true_target_ea if taken else transfer.false_target_ea
    if target_ea is None or int(target_ea) not in {
        int(target) for target in transfer.target_eas
    }:
        return None
    return find_unique_target_entry_block(
        flow_graph,
        int(target_ea),
        transfer.next_target_ea,
    )


def route_materialized_transfer_chain(
    flow_graph: FlowGraph,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    start_block: int,
    state_constant: int,
    state_var_reg: int | None,
    handler_serials: frozenset[int],
    max_depth: int = 64,
) -> int | None:
    """Execute the resolver-proven logical CFG to one known handler.

    Hex-Rays may retain only a comparison's fallthrough and detach its taken
    target.  The resolver record still carries both targets and the exact state
    predicate.  At each live block, choose the latest anchored transfer whose
    predicate is provable for *state_constant*, then continue from its resolved
    target.  One-successor glue is followed directly.  Cycles, ambiguity, and
    non-handler leaves abstain.
    """
    current = int(start_block)
    seen: set[int] = set()
    for depth in range(int(max_depth)):
        if depth > 0 and current in handler_serials:
            return current
        if current in seen:
            return None
        seen.add(current)
        block = flow_graph.get_block(current)
        if block is None:
            return None
        anchors = _block_eas(block)
        matches = sorted(
            (
                transfer
                for transfer in transfers
                if (
                    int(transfer.source_block_ea) == int(block.start_ea)
                    or anchors.intersection(transfer.materialized_anchor_eas)
                )
            ),
            key=lambda transfer: int(transfer.source_jmp_ea),
            reverse=True,
        )
        target = None
        selected_targets: set[int] = set()
        latest_jmp_ea = int(matches[0].source_jmp_ea) if matches else None
        for transfer in matches:
            if int(transfer.source_jmp_ea) != latest_jmp_ea:
                break
            candidate = lookup_state_keyed_transfer_target(
                flow_graph,
                transfer,
                int(state_constant),
                state_var_reg=state_var_reg,
            )
            if candidate is None:
                candidate = lookup_singleton_transfer_target(
                    flow_graph,
                    transfer,
                    current,
                )
            if candidate is not None:
                selected_targets.add(int(candidate))
        if len(selected_targets) > 1:
            return None
        if selected_targets:
            target = next(iter(selected_targets))
        if target is not None:
            current = int(target)
            continue
        if len(block.succs) != 1:
            return None
        current = int(block.succs[0])
    return None


def route_transfer_target_through_condition_chain(
    flow_graph: FlowGraph,
    decision_dag: DecisionDag,
    target_block: int,
    state_constant: int,
    handler_serials: frozenset[int],
    *,
    max_glue_hops: int = 8,
) -> int | None:
    """Route from a resolver-proven condition-chain entry to one known handler.

    A materialized computed goto may enter the comparison tree below its global
    root.  Follow only deterministic one-successor glue until reaching either a
    known handler or a decision-DAG node, then evaluate the existing DAG from
    that exact root.  A default/spine leaf, forked glue, cycle, or unknown block
    abstains; none is reclassified as a return.
    """
    current = int(target_block)
    seen: set[int] = set()
    for _ in range(int(max_glue_hops) + 1):
        if current in decision_dag.nodes:
            # Range backfill can provisionally classify an internal comparison
            # node as a handler.  In this resolver-routing context the explicit
            # decision-DAG ownership is stronger: stopping on the alias would
            # skip the comparison and select the wrong equality handler.
            routed = int(decision_dag.route_from(current, int(state_constant)))
            return routed if routed in handler_serials else None
        if current in handler_serials:
            return current
        if current in seen:
            return None
        seen.add(current)
        block = flow_graph.get_block(current)
        if block is None or len(block.succs) != 1:
            return None
        current = int(block.succs[0])
    return None


__all__ = [
    "MaterializedIndirectTransfer",
    "MaterializedStateRoute",
    "ResidualIndirectCallNeutralizationPlan",
    "TerminalReturnCarrierRequest",
    "condition_code_predicate",
    "find_unique_target_block",
    "find_unique_target_entry_block",
    "lookup_state_keyed_transfer_target",
    "lookup_singleton_transfer_target",
    "materialized_terminal_target_eas_by_source",
    "merge_materialized_handler_maps",
    "override_materialized_handler_targets",
    "plan_resolver_proven_indirect_call_neutralizations",
    "plan_terminal_return_carrier_requests",
    "route_materialized_transfer_chain",
    "route_transfer_target_through_condition_chain",
    "unique_materialized_equality_target_eas",
]
