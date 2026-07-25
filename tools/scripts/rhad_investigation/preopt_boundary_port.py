"""Plan closure-owned resolver-transfer ports for the PREOPT experiment.

The planner is portable and mutation-free. It classifies stable native-EA
proofs by whether their endpoints belong to the imported union or the live
PREOPT MBA. A later capture adapter resolves the exact PREOPT corridor and
delivery shape; this module never stores maturity-local block serials.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    TerminalReturnCarrierRequest,
)
from d810.core.typing import Collection, Mapping, Sequence


_MASK32 = 0xFFFFFFFF


class PreoptBoundaryEndpointOwner(str, Enum):
    """Which side of the single import owns one stable native endpoint."""

    IMPORTED = "imported"
    LIVE = "live"


class PreoptBoundaryPortAbstentionReason(str, Enum):
    """Why a relevant resolver proof cannot become a closure port."""

    MISSING_SOURCE_OWNER = "missing_source_owner"
    MISSING_TARGET_OWNER = "missing_target_owner"
    INCOMPLETE_EVIDENCE = "incomplete_evidence"
    CONFLICTING_SOURCE = "conflicting_source"
    MISSING_STATE_HANDLER = "missing_state_handler"
    AMBIGUOUS_STATE_HANDLER = "ambiguous_state_handler"
    UNRESOLVED_STATE_DEFINITION = "unresolved_state_definition"
    MISSING_PREDICATE_SOURCE = "missing_predicate_source"
    AMBIGUOUS_ROUTE = "ambiguous_route"
    UNRESOLVED_ROUTE = "unresolved_route"
    CONVERGED_CONDITIONAL_ARMS = "converged_conditional_arms"


@dataclass(frozen=True, slots=True)
class PreoptDirectBoundaryPort:
    """One source-sensitive one-way resolver transfer."""

    source_block_ea: int
    source_instruction_ea: int
    target_ea: int
    state_register: int
    state_constant: int
    source_owner: PreoptBoundaryEndpointOwner
    target_owner: PreoptBoundaryEndpointOwner
    resolver_kind: str


@dataclass(frozen=True, slots=True)
class PreoptConditionalBoundaryPort:
    """One predicate with arms oriented to native taken/fallthrough control."""

    source_block_ea: int
    predicate_ea: int
    taken_target_ea: int
    fallthrough_target_ea: int
    state_register: int | None
    taken_state: int | None
    fallthrough_state: int | None
    source_owner: PreoptBoundaryEndpointOwner
    taken_target_owner: PreoptBoundaryEndpointOwner
    fallthrough_target_owner: PreoptBoundaryEndpointOwner
    resolver_kind: str
    logical_source_anchor_ea: int | None = None
    predicate_ida_stkoff: int | None = None
    predicate_size: int | None = None
    condition_code: int | None = None


@dataclass(frozen=True, slots=True)
class PreoptConditionalTopologyFact:
    """Native arm orientation for one exact PREOPT conditional tail."""

    source_block_ea: int
    predicate_ea: int
    taken_successor_ea: int
    fallthrough_successor_ea: int

    def __post_init__(self) -> None:
        if int(self.taken_successor_ea) == int(self.fallthrough_successor_ea):
            raise ValueError("conditional topology requires two distinct arms")


@dataclass(frozen=True, slots=True)
class PreoptBoundaryPortAbstention:
    source_ea: int
    reason: PreoptBoundaryPortAbstentionReason
    target_ea: int | None = None


@dataclass(frozen=True, slots=True)
class PreoptBoundaryPortPlan:
    direct: tuple[PreoptDirectBoundaryPort, ...]
    conditional: tuple[PreoptConditionalBoundaryPort, ...]
    abstentions: tuple[PreoptBoundaryPortAbstention, ...]


def classify_preopt_boundary_endpoint_owner(
    ea: int,
    *,
    block_ea: int | None,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
    preferred_owner: PreoptBoundaryEndpointOwner | None = None,
) -> PreoptBoundaryEndpointOwner | None:
    address = int(ea)
    block_address = None if block_ea is None else int(block_ea)
    imported = block_address in imported_block_ranges or any(
        int(start_ea) <= address < int(end_ea)
        for start_ea, end_ea in imported_block_ranges.values()
    )
    live = {int(native_ea) for native_ea in live_native_eas}
    is_live = address in live or (block_address is not None and block_address in live)
    if preferred_owner is PreoptBoundaryEndpointOwner.IMPORTED:
        return preferred_owner if imported else None
    if preferred_owner is PreoptBoundaryEndpointOwner.LIVE:
        return preferred_owner if is_live else None
    if imported:
        return PreoptBoundaryEndpointOwner.IMPORTED
    if is_live:
        return PreoptBoundaryEndpointOwner.LIVE
    return None


def _handler_target(
    state_payload_handler_eas: Mapping[int, Collection[int]],
    state: int,
) -> tuple[int | None, PreoptBoundaryPortAbstentionReason | None]:
    targets = {
        int(target_ea)
        for target_ea in state_payload_handler_eas.get(
            int(state) & _MASK32,
            (),
        )
        if int(target_ea) > 0
    }
    if not targets:
        return None, PreoptBoundaryPortAbstentionReason.MISSING_STATE_HANDLER
    if len(targets) != 1:
        return None, PreoptBoundaryPortAbstentionReason.AMBIGUOUS_STATE_HANDLER
    return next(iter(targets)), None


def _direct_port(
    transfer: MaterializedIndirectTransfer,
    *,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> tuple[PreoptDirectBoundaryPort | None, PreoptBoundaryPortAbstention | None]:
    if (
        transfer.selector_state_var_reg is None
        or transfer.selector_state_constant is None
        or len(transfer.target_eas) != 1
    ):
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.INCOMPLETE_EVIDENCE,
        )
    source_owner = classify_preopt_boundary_endpoint_owner(
        int(transfer.source_jmp_ea),
        block_ea=None,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    target_ea = int(transfer.target_eas[0])
    target_owner = classify_preopt_boundary_endpoint_owner(
        target_ea,
        block_ea=target_ea,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    if (
        source_owner is not PreoptBoundaryEndpointOwner.IMPORTED
        and target_owner is not PreoptBoundaryEndpointOwner.IMPORTED
    ):
        return None, None
    if source_owner is None:
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
            target_ea,
        )
    if target_owner is None:
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
            target_ea,
        )
    return (
        PreoptDirectBoundaryPort(
            source_block_ea=int(transfer.source_block_ea),
            source_instruction_ea=int(transfer.source_jmp_ea),
            target_ea=target_ea,
            state_register=int(transfer.selector_state_var_reg),
            state_constant=int(transfer.selector_state_constant) & _MASK32,
            source_owner=source_owner,
            target_owner=target_owner,
            resolver_kind=str(transfer.resolver_kind),
        ),
        None,
    )


def _conditional_port(
    transfer: MaterializedIndirectTransfer,
    *,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None,
) -> tuple[
    PreoptConditionalBoundaryPort | None,
    PreoptBoundaryPortAbstention | None,
]:
    if (
        transfer.condition_code != 5
        or transfer.true_target_ea is None
        or transfer.false_target_ea is None
        or transfer.predicate_true_state is None
        or transfer.predicate_false_state is None
        or transfer.predicate_true_is_taken is None
        or transfer.selector_state_var_reg is None
        or len(transfer.target_eas) != 2
    ):
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.INCOMPLETE_EVIDENCE,
        )
    normalized_true_target = int(transfer.true_target_ea)
    normalized_false_target = int(transfer.false_target_ea)
    if {
        normalized_true_target,
        normalized_false_target,
    } != {int(target_ea) for target_ea in transfer.target_eas}:
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.INCOMPLETE_EVIDENCE,
        )
    true_state = int(transfer.predicate_true_state) & _MASK32
    false_state = int(transfer.predicate_false_state) & _MASK32
    if state_payload_handler_eas is not None:
        true_target, true_error = _handler_target(
            state_payload_handler_eas,
            true_state,
        )
        false_target, false_error = _handler_target(
            state_payload_handler_eas,
            false_state,
        )
        target_error = true_error or false_error
        if target_error is not None:
            return None, PreoptBoundaryPortAbstention(
                int(transfer.source_jmp_ea),
                target_error,
            )
        assert true_target is not None
        assert false_target is not None
        normalized_true_target = int(true_target)
        normalized_false_target = int(false_target)
    source_owner = classify_preopt_boundary_endpoint_owner(
        int(transfer.source_jmp_ea),
        block_ea=None,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    true_owner = classify_preopt_boundary_endpoint_owner(
        normalized_true_target,
        block_ea=normalized_true_target,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    false_owner = classify_preopt_boundary_endpoint_owner(
        normalized_false_target,
        block_ea=normalized_false_target,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    if source_owner is None:
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
        )
    missing_target = next(
        (
            target_ea
            for target_ea, owner in (
                (normalized_true_target, true_owner),
                (normalized_false_target, false_owner),
            )
            if owner is None
        ),
        None,
    )
    if missing_target is not None:
        return None, PreoptBoundaryPortAbstention(
            int(transfer.source_jmp_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
            int(missing_target),
        )
    assert true_owner is not None
    assert false_owner is not None
    if bool(transfer.predicate_true_is_taken):
        taken_target = normalized_true_target
        fallthrough_target = normalized_false_target
        taken_state = true_state
        fallthrough_state = false_state
        taken_owner = true_owner
        fallthrough_owner = false_owner
    else:
        taken_target = normalized_false_target
        fallthrough_target = normalized_true_target
        taken_state = false_state
        fallthrough_state = true_state
        taken_owner = false_owner
        fallthrough_owner = true_owner
    return (
        PreoptConditionalBoundaryPort(
            source_block_ea=int(transfer.source_block_ea),
            predicate_ea=int(transfer.source_jmp_ea),
            taken_target_ea=taken_target,
            fallthrough_target_ea=fallthrough_target,
            state_register=int(transfer.selector_state_var_reg),
            taken_state=taken_state,
            fallthrough_state=fallthrough_state,
            source_owner=source_owner,
            taken_target_owner=taken_owner,
            fallthrough_target_owner=fallthrough_owner,
            resolver_kind=str(transfer.resolver_kind),
        ),
        None,
    )


def _conditional_semantic_key(
    row: PreoptConditionalBoundaryPort,
) -> tuple[object, ...]:
    return (
        int(row.source_block_ea),
        int(row.predicate_ea),
        int(row.taken_target_ea),
        int(row.fallthrough_target_ea),
        None if row.state_register is None else int(row.state_register),
        None if row.taken_state is None else int(row.taken_state),
        None if row.fallthrough_state is None else int(row.fallthrough_state),
        row.source_owner,
        row.taken_target_owner,
        row.fallthrough_target_owner,
        row.logical_source_anchor_ea,
        row.predicate_ida_stkoff,
        row.predicate_size,
        row.condition_code,
    )


def _resolve_exact_conditional_route(
    start_ea: int,
    *,
    exact_targets_by_source_ea: Mapping[int, Collection[int]],
    stable_endpoint_eas: Collection[int],
) -> tuple[
    int | None,
    PreoptBoundaryPortAbstentionReason | None,
    int | None,
]:
    """Follow a singleton exact-edge corridor to one stable endpoint."""
    stable = {int(ea) for ea in stable_endpoint_eas}
    current = int(start_ea)
    visited: set[int] = set()
    while current not in stable:
        if current in visited:
            return (
                None,
                PreoptBoundaryPortAbstentionReason.UNRESOLVED_ROUTE,
                current,
            )
        visited.add(current)
        targets = {
            int(target_ea)
            for target_ea in exact_targets_by_source_ea.get(current, ())
            if int(target_ea) > 0
        }
        if not targets:
            return (
                None,
                PreoptBoundaryPortAbstentionReason.UNRESOLVED_ROUTE,
                current,
            )
        if len(targets) != 1:
            return (
                None,
                PreoptBoundaryPortAbstentionReason.AMBIGUOUS_ROUTE,
                current,
            )
        current = next(iter(targets))
    return current, None, None


def merge_preopt_exact_route_targets(
    current: Mapping[int, Collection[int]],
    *,
    exact_routes: Collection[tuple[int, int]],
) -> dict[int, set[int]]:
    """Overlay stronger source-sensitive routes without hiding conflicts."""
    merged = {
        int(source_ea): {int(target_ea) for target_ea in target_eas}
        for source_ea, target_eas in current.items()
    }
    exact_by_source: dict[int, set[int]] = {}
    for source_ea, target_ea in exact_routes:
        if int(source_ea) <= 0 or int(target_ea) <= 0:
            continue
        exact_by_source.setdefault(int(source_ea), set()).add(int(target_ea))
    merged.update(exact_by_source)
    return merged


def derive_preopt_fixed_source_arm_routes(
    topology: Sequence[PreoptConditionalTopologyFact],
    *,
    source_sensitive_targets_by_source_ea: Mapping[int, Collection[int]],
) -> tuple[tuple[int, int], ...]:
    """Bind the arm retaining a source state when its peer overrides it."""
    derived: set[tuple[int, int]] = set()
    for fact in topology:
        source_targets = {
            int(target_ea)
            for target_ea in source_sensitive_targets_by_source_ea.get(
                int(fact.source_block_ea), ()
            )
        }
        taken_targets = {
            int(target_ea)
            for target_ea in source_sensitive_targets_by_source_ea.get(
                int(fact.taken_successor_ea), ()
            )
        }
        fallthrough_targets = {
            int(target_ea)
            for target_ea in source_sensitive_targets_by_source_ea.get(
                int(fact.fallthrough_successor_ea), ()
            )
        }
        if len(source_targets) != 1:
            continue
        source_target = next(iter(source_targets))
        if (
            len(taken_targets) == 1
            and not fallthrough_targets
            and next(iter(taken_targets)) != source_target
        ):
            derived.add((int(fact.fallthrough_successor_ea), source_target))
        elif (
            len(fallthrough_targets) == 1
            and not taken_targets
            and next(iter(fallthrough_targets)) != source_target
        ):
            derived.add((int(fact.taken_successor_ea), source_target))
    return tuple(sorted(derived))


def exclude_preopt_conditional_topology_with_planned_predicates(
    topology: Sequence[PreoptConditionalTopologyFact],
    planned: Sequence[PreoptConditionalBoundaryPort],
) -> tuple[PreoptConditionalTopologyFact, ...]:
    """Do not replace a stronger plan for the same physical predicate.

    PREOPT can move the block entry while retaining the native predicate EA.
    The predicate instruction is therefore the stable physical identity; the
    source block entry is not.
    """
    planned_predicates = {int(row.predicate_ea) for row in planned}
    return tuple(
        row for row in topology if int(row.predicate_ea) not in planned_predicates
    )


def plan_preopt_conditional_routing_boundary_ports(
    topology: Sequence[PreoptConditionalTopologyFact],
    *,
    exact_targets_by_source_ea: Mapping[int, Collection[int]],
    stable_endpoint_eas: Collection[int],
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> PreoptBoundaryPortPlan:
    """Restore native predicates whose arms have exact endpoint corridors.

    This is deliberately state-agnostic.  Each native arm must traverse only
    singleton, resolver/direct proven edges and terminate at one distinct,
    owned endpoint.  Missing or conflicting evidence abstains.
    """
    conditional: list[PreoptConditionalBoundaryPort] = []
    abstentions: list[PreoptBoundaryPortAbstention] = []
    for fact in topology:
        taken_target, taken_error, taken_failure_ea = _resolve_exact_conditional_route(
            int(fact.taken_successor_ea),
            exact_targets_by_source_ea=exact_targets_by_source_ea,
            stable_endpoint_eas=stable_endpoint_eas,
        )
        fallthrough_target, fallthrough_error, fallthrough_failure_ea = (
            _resolve_exact_conditional_route(
                int(fact.fallthrough_successor_ea),
                exact_targets_by_source_ea=exact_targets_by_source_ea,
                stable_endpoint_eas=stable_endpoint_eas,
            )
        )
        route_error = taken_error or fallthrough_error
        if route_error is not None:
            abstentions.append(
                PreoptBoundaryPortAbstention(
                    int(fact.predicate_ea),
                    route_error,
                    (
                        taken_failure_ea
                        if taken_error is not None
                        else fallthrough_failure_ea
                    ),
                )
            )
            continue
        assert taken_target is not None
        assert fallthrough_target is not None
        if taken_target == fallthrough_target:
            abstentions.append(
                PreoptBoundaryPortAbstention(
                    int(fact.predicate_ea),
                    PreoptBoundaryPortAbstentionReason.CONVERGED_CONDITIONAL_ARMS,
                    taken_target,
                )
            )
            continue
        source_owner = classify_preopt_boundary_endpoint_owner(
            int(fact.predicate_ea),
            block_ea=int(fact.source_block_ea),
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
        )
        taken_owner = classify_preopt_boundary_endpoint_owner(
            taken_target,
            block_ea=taken_target,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
        )
        fallthrough_owner = classify_preopt_boundary_endpoint_owner(
            fallthrough_target,
            block_ea=fallthrough_target,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
        )
        if source_owner is None:
            abstentions.append(
                PreoptBoundaryPortAbstention(
                    int(fact.predicate_ea),
                    PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
                )
            )
            continue
        missing_target = next(
            (
                target_ea
                for target_ea, owner in (
                    (taken_target, taken_owner),
                    (fallthrough_target, fallthrough_owner),
                )
                if owner is None
            ),
            None,
        )
        if missing_target is not None:
            abstentions.append(
                PreoptBoundaryPortAbstention(
                    int(fact.predicate_ea),
                    PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
                    int(missing_target),
                )
            )
            continue
        assert taken_owner is not None
        assert fallthrough_owner is not None
        conditional.append(
            PreoptConditionalBoundaryPort(
                source_block_ea=int(fact.source_block_ea),
                predicate_ea=int(fact.predicate_ea),
                taken_target_ea=taken_target,
                fallthrough_target_ea=fallthrough_target,
                state_register=None,
                taken_state=None,
                fallthrough_state=None,
                source_owner=source_owner,
                taken_target_owner=taken_owner,
                fallthrough_target_owner=fallthrough_owner,
                resolver_kind="preopt_resolver_conditional_routing",
            )
        )
    return PreoptBoundaryPortPlan(
        direct=(),
        conditional=tuple(
            sorted(
                conditional,
                key=lambda row: (row.source_block_ea, row.predicate_ea),
            )
        ),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    row.source_ea,
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


def plan_preopt_terminal_return_boundary_ports(
    topology: Sequence[PreoptConditionalTopologyFact],
    requests: Sequence[TerminalReturnCarrierRequest],
    *,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> PreoptBoundaryPortPlan:
    """Restore only the exact native arm proven to reach a return epilogue.

    A terminal request identifies a native predicate and one terminal target.
    The sibling remains the predicate's immediate native successor: resolving
    that sibling through the state machine would turn an exact one-arm proof
    into an invented two-arm proof.
    """
    requests_by_predicate: dict[int, list[TerminalReturnCarrierRequest]] = {}
    for request in requests:
        requests_by_predicate.setdefault(int(request.source_handler_ea), []).append(
            request
        )

    candidates: list[PreoptConditionalBoundaryPort] = []
    abstentions: list[PreoptBoundaryPortAbstention] = []
    for fact in topology:
        fact_requests = requests_by_predicate.get(int(fact.predicate_ea), ())
        for request in fact_requests:
            terminal_target = int(request.terminal_target_ea)
            taken_is_terminal = terminal_target == int(fact.taken_successor_ea)
            fallthrough_is_terminal = terminal_target == int(
                fact.fallthrough_successor_ea
            )
            if taken_is_terminal == fallthrough_is_terminal:
                abstentions.append(
                    PreoptBoundaryPortAbstention(
                        int(fact.predicate_ea),
                        PreoptBoundaryPortAbstentionReason.UNRESOLVED_ROUTE,
                        terminal_target,
                    )
                )
                continue

            source_owner = classify_preopt_boundary_endpoint_owner(
                int(fact.predicate_ea),
                block_ea=int(fact.source_block_ea),
                imported_block_ranges=imported_block_ranges,
                live_native_eas=live_native_eas,
            )
            taken_owner = classify_preopt_boundary_endpoint_owner(
                int(fact.taken_successor_ea),
                block_ea=int(fact.taken_successor_ea),
                imported_block_ranges=imported_block_ranges,
                live_native_eas=live_native_eas,
            )
            fallthrough_owner = classify_preopt_boundary_endpoint_owner(
                int(fact.fallthrough_successor_ea),
                block_ea=int(fact.fallthrough_successor_ea),
                imported_block_ranges=imported_block_ranges,
                live_native_eas=live_native_eas,
            )
            if source_owner is None:
                abstentions.append(
                    PreoptBoundaryPortAbstention(
                        int(fact.predicate_ea),
                        PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
                    )
                )
                continue
            missing_target = next(
                (
                    target_ea
                    for target_ea, owner in (
                        (int(fact.taken_successor_ea), taken_owner),
                        (
                            int(fact.fallthrough_successor_ea),
                            fallthrough_owner,
                        ),
                    )
                    if owner is None
                ),
                None,
            )
            if missing_target is not None:
                abstentions.append(
                    PreoptBoundaryPortAbstention(
                        int(fact.predicate_ea),
                        PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
                        missing_target,
                    )
                )
                continue
            assert taken_owner is not None
            assert fallthrough_owner is not None
            if PreoptBoundaryEndpointOwner.IMPORTED not in {
                source_owner,
                taken_owner,
                fallthrough_owner,
            }:
                continue

            state_constant = int(request.state_constant) & _MASK32
            candidates.append(
                PreoptConditionalBoundaryPort(
                    source_block_ea=int(fact.source_block_ea),
                    predicate_ea=int(fact.predicate_ea),
                    taken_target_ea=int(fact.taken_successor_ea),
                    fallthrough_target_ea=int(fact.fallthrough_successor_ea),
                    state_register=int(request.state_var_reg),
                    taken_state=(state_constant if taken_is_terminal else None),
                    fallthrough_state=(
                        state_constant if fallthrough_is_terminal else None
                    ),
                    source_owner=source_owner,
                    taken_target_owner=taken_owner,
                    fallthrough_target_owner=fallthrough_owner,
                    resolver_kind="preopt_terminal_return_boundary",
                )
            )

    conditional, merge_abstentions = coalesce_preopt_conditional_boundary_ports(
        candidates
    )
    return PreoptBoundaryPortPlan(
        direct=(),
        conditional=conditional,
        abstentions=tuple(
            sorted(
                {*abstentions, *merge_abstentions},
                key=lambda row: (
                    int(row.source_ea),
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


def coalesce_preopt_conditional_boundary_ports(
    rows: Sequence[PreoptConditionalBoundaryPort],
) -> tuple[
    tuple[PreoptConditionalBoundaryPort, ...],
    tuple[PreoptBoundaryPortAbstention, ...],
]:
    """Collapse duplicate proofs while rejecting semantic disagreement."""
    rows_by_source: dict[tuple[int, int], list[PreoptConditionalBoundaryPort]] = {}
    for row in rows:
        rows_by_source.setdefault(
            (int(row.source_block_ea), int(row.predicate_ea)),
            [],
        ).append(row)

    conditional: list[PreoptConditionalBoundaryPort] = []
    abstentions: list[PreoptBoundaryPortAbstention] = []
    for (_source_block_ea, predicate_ea), candidates in sorted(rows_by_source.items()):
        semantic_keys = {
            _conditional_semantic_key(candidate) for candidate in candidates
        }
        if len(semantic_keys) != 1:
            abstentions.append(
                PreoptBoundaryPortAbstention(
                    predicate_ea,
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )
            continue
        conditional.append(candidates[0])
    return (
        tuple(
            sorted(
                conditional,
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.predicate_ea),
                    int(row.taken_target_ea),
                    int(row.fallthrough_target_ea),
                ),
            )
        ),
        tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    int(row.source_ea),
                    row.reason.value,
                ),
            )
        ),
    )


def plan_preopt_resolver_boundary_ports(
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None = None,
) -> PreoptBoundaryPortPlan:
    """Select source-sensitive resolver cuts across live/imported owners.

    Direct rows are needed only when at least one endpoint is imported because
    the state-cut planner handles fully live direct transfers.  A complete
    conditional proof remains actionable when every endpoint is live: Hex-Rays
    may preserve the predicate while pruning or retargeting both state arms at
    a later PREOPT callback.
    """
    direct_by_source: dict[tuple[int, int], set[PreoptDirectBoundaryPort]] = {}
    conditional_by_source: dict[
        tuple[int, int], set[PreoptConditionalBoundaryPort]
    ] = {}
    abstentions: set[PreoptBoundaryPortAbstention] = set()

    for transfer in transfers:
        if transfer.resolver_kind == "residual_state_route_evidence":
            port, abstention = _direct_port(
                transfer,
                imported_block_ranges=imported_block_ranges,
                live_native_eas=live_native_eas,
            )
            if port is not None:
                direct_by_source.setdefault(
                    (port.source_block_ea, port.source_instruction_ea),
                    set(),
                ).add(port)
            if abstention is not None:
                abstentions.add(abstention)
            continue
        if transfer.resolver_kind != "conditional_handler_bridge":
            continue
        port, abstention = _conditional_port(
            transfer,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
            state_payload_handler_eas=state_payload_handler_eas,
        )
        if port is not None:
            conditional_by_source.setdefault(
                (port.source_block_ea, port.predicate_ea),
                set(),
            ).add(port)
        if abstention is not None:
            abstentions.add(abstention)

    direct: list[PreoptDirectBoundaryPort] = []
    conditional: list[PreoptConditionalBoundaryPort] = []
    for (_source_block_ea, source_ea), candidates in sorted(direct_by_source.items()):
        if len(candidates) == 1:
            direct.append(next(iter(candidates)))
        else:
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    source_ea,
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )
    for (_source_block_ea, source_ea), candidates in sorted(
        conditional_by_source.items()
    ):
        if len(candidates) == 1:
            conditional.append(next(iter(candidates)))
        else:
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    source_ea,
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )

    conditional_by_block: dict[int, list[PreoptConditionalBoundaryPort]] = {}
    for row in conditional:
        conditional_by_block.setdefault(int(row.source_block_ea), []).append(row)
    conflicting_conditional_blocks = {
        source_block_ea
        for source_block_ea, rows in conditional_by_block.items()
        if len(rows) != 1
    }
    for source_block_ea in sorted(conflicting_conditional_blocks):
        rows = conditional_by_block[source_block_ea]
        abstentions.add(
            PreoptBoundaryPortAbstention(
                min(int(row.predicate_ea) for row in rows),
                PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
            )
        )
    conditional = [
        row
        for row in conditional
        if int(row.source_block_ea) not in conflicting_conditional_blocks
    ]

    surviving_direct: list[PreoptDirectBoundaryPort] = []
    surviving_conditional: list[PreoptConditionalBoundaryPort] = []
    direct_by_block: dict[int, list[PreoptDirectBoundaryPort]] = {}
    for row in direct:
        direct_by_block.setdefault(int(row.source_block_ea), []).append(row)
    for row in conditional:
        sibling_direct = direct_by_block.pop(int(row.source_block_ea), [])
        proven_arms = {
            (int(row.taken_target_ea), int(row.taken_state)),
            (int(row.fallthrough_target_ea), int(row.fallthrough_state)),
        }
        if any(
            int(direct_row.state_register) != int(row.state_register)
            or (
                int(direct_row.target_ea),
                int(direct_row.state_constant),
            )
            not in proven_arms
            for direct_row in sibling_direct
        ):
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    int(row.predicate_ea),
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )
            continue
        surviving_conditional.append(row)
    for rows in direct_by_block.values():
        surviving_direct.extend(rows)
    direct = surviving_direct
    conditional = surviving_conditional

    return PreoptBoundaryPortPlan(
        direct=tuple(
            sorted(
                direct,
                key=lambda row: (
                    row.source_block_ea,
                    row.source_instruction_ea,
                    row.target_ea,
                    row.state_constant,
                ),
            )
        ),
        conditional=tuple(
            sorted(
                conditional,
                key=lambda row: (
                    row.source_block_ea,
                    row.predicate_ea,
                    row.fallthrough_target_ea,
                    row.taken_target_ea,
                ),
            )
        ),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    row.source_ea,
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


__all__ = [
    "PreoptBoundaryEndpointOwner",
    "PreoptBoundaryPortAbstention",
    "PreoptBoundaryPortAbstentionReason",
    "PreoptBoundaryPortPlan",
    "PreoptConditionalBoundaryPort",
    "PreoptConditionalTopologyFact",
    "PreoptDirectBoundaryPort",
    "classify_preopt_boundary_endpoint_owner",
    "coalesce_preopt_conditional_boundary_ports",
    "derive_preopt_fixed_source_arm_routes",
    "exclude_preopt_conditional_topology_with_planned_predicates",
    "merge_preopt_exact_route_targets",
    "plan_preopt_conditional_routing_boundary_ports",
    "plan_preopt_resolver_boundary_ports",
    "plan_preopt_terminal_return_boundary_ports",
]
