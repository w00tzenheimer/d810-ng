"""Portable proof and planning for a detached conditional handler island."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    is_conditional_handler_bridge_kind,
)
from d810.core.typing import Mapping


@dataclass(frozen=True, slots=True)
class ConditionalHandlerBridgePlan:
    """Direct live-microcode arms for one resolver-proven predicate."""

    source_predicate_ea: int
    predicate_register: int
    predicate_size: int
    false_state: int
    true_state: int
    false_target_ea: int
    true_target_ea: int
    state_register: int | None = None
    state_size: int = 4
    predicate_compare_register: int | None = None
    predicate_compare_constant: int | None = None


@dataclass(frozen=True, slots=True)
class ConditionalHandlerTargetTopology:
    """Snapshot-local shape of one exact state target before LOCOPT DCE."""

    target_ea: int
    router_block: int
    dispatcher_block: int
    predecessor_blocks: tuple[int, ...]
    successor_blocks: tuple[int, ...]


def plan_conditional_handler_bridges(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    state_targets: Mapping[int, int],
    state_register: int | None = None,
    state_size: int = 4,
) -> tuple[ConditionalHandlerBridgePlan, ...]:
    """Plan exact predicate arms while every detached block is still live.

    A conditional bridge is accepted only when its two state paths agree with
    the independently resolved equality state map.  Conflicting records for
    the same predicate contaminate that predicate and force abstention.
    """
    candidates: dict[
        int,
        set[tuple[ConditionalHandlerBridgePlan, int, int, int, int]],
    ] = {}
    for transfer in transfers:
        if (
            not is_conditional_handler_bridge_kind(transfer.resolver_kind)
            or transfer.condition_code not in (4, 5)
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.predicate_true_is_taken is None
            or transfer.predicate_register is None
            or transfer.predicate_size is None
        ):
            continue
        source_ea = int(transfer.source_jmp_ea)
        true_target = int(transfer.true_target_ea)
        false_target = int(transfer.false_target_ea)
        true_state = int(transfer.predicate_true_state) & 0xFFFFFFFF
        false_state = int(transfer.predicate_false_state) & 0xFFFFFFFF
        if (
            source_ea <= 0
            or true_target <= 0
            or false_target <= 0
            or true_target == false_target
            or true_state == false_state
        ):
            continue
        plan = ConditionalHandlerBridgePlan(
            source_predicate_ea=source_ea,
            predicate_register=int(transfer.predicate_register),
            predicate_size=int(transfer.predicate_size),
            false_state=false_state,
            true_state=true_state,
            false_target_ea=false_target,
            true_target_ea=true_target,
            state_register=(
                int(state_register) if state_register is not None else None
            ),
            state_size=int(state_size),
            predicate_compare_register=transfer.predicate_compare_register,
            predicate_compare_constant=transfer.predicate_compare_constant,
        )
        candidates.setdefault(source_ea, set()).add(
            (plan, true_state, false_state, true_target, false_target)
        )

    plans: list[ConditionalHandlerBridgePlan] = []
    for source_ea in sorted(candidates):
        proofs = candidates[source_ea]
        if len(proofs) != 1:
            continue
        plan, true_state, false_state, true_target, false_target = next(
            iter(proofs)
        )
        if (
            state_targets.get(true_state) != true_target
            or state_targets.get(false_state) != false_target
        ):
            continue
        plans.append(plan)
    return tuple(plans)


def conditional_bridge_requires_pre_dce_preservation(
    plan: ConditionalHandlerBridgePlan,
    *,
    target_topologies: Mapping[int, ConditionalHandlerTargetTopology],
) -> bool:
    """Whether one logical arm owns a multi-block payload only via its router.

    A single-block state handler can survive until CALLS through its normal
    ``handler -> dispatcher`` edge.  A multi-block handler whose entry is owned
    solely by the equality-router leaf can instead be discarded during LOCOPT
    before CALLS has a chance to redirect the selecting predicate.  Preserve
    only that bounded shape.  An extra non-router predecessor is independent
    liveness evidence, so it forces abstention for that target.
    """
    return bool(
        conditional_bridge_pre_dce_target_eas(
            plan,
            target_topologies=target_topologies,
        )
    )


def conditional_bridge_pre_dce_target_eas(
    plan: ConditionalHandlerBridgePlan,
    *,
    target_topologies: Mapping[int, ConditionalHandlerTargetTopology],
    imported_target_eas: frozenset[int] = frozenset(),
) -> tuple[int, ...]:
    """Return the exact arms whose payload entry is owned only by its router."""
    result: list[int] = []
    for target_ea in (int(plan.false_target_ea), int(plan.true_target_ea)):
        if target_ea in imported_target_eas:
            result.append(target_ea)
            continue
        topology = target_topologies.get(target_ea)
        if topology is None or int(topology.target_ea) != target_ea:
            continue
        predecessors = tuple(int(block) for block in topology.predecessor_blocks)
        successors = tuple(int(block) for block in topology.successor_blocks)
        if (
            predecessors == (int(topology.router_block),)
            and len(successors) == 1
            and successors[0] != int(topology.dispatcher_block)
        ):
            result.append(target_ea)
    return tuple(result)


def conditional_bridge_route_evidence_converged(
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> bool:
    """Whether every residual predicate state has an exact equality route."""
    predicate_states = {
        int(state) & 0xFFFFFFFF
        for transfer in transfers
        if is_conditional_handler_bridge_kind(transfer.resolver_kind)
        for state in (
            transfer.predicate_true_state,
            transfer.predicate_false_state,
        )
        if state is not None
    }
    residual_states = {
        int(transfer.selector_state_constant) & 0xFFFFFFFF
        for transfer in transfers
        if transfer.resolver_kind == "residual_state_route"
        and transfer.selector_state_constant is not None
        and (int(transfer.selector_state_constant) & 0xFFFFFFFF)
        in predicate_states
    }
    exact_route_states = {
        int(transfer.selector_state_constant) & 0xFFFFFFFF
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_route"
        and transfer.selector_state_constant is not None
    }
    return bool(residual_states) and residual_states.issubset(exact_route_states)


@dataclass(frozen=True, slots=True)
class DetachedRouteEvidence:
    """One microcode-proven route from a live predicate to a detached handler."""

    source_predicate_ea: int
    detached_entry_ea: int


@dataclass(frozen=True, slots=True)
class DetachedSnippetRoutePlan:
    """One exact one-way route whose native target is absent from the live MBA."""

    source_ea: int
    target_ea: int
    state_constant: int
    evidence_kind: str = "residual_state_route_evidence"
    owned_native_ranges: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class DetachedSnippetReplacementEvidence:
    """Normalized proof that a cached handler owns a lost conditional arm."""

    target_ea: int
    conditional_branch_ea: int
    conditional_target_eas: tuple[int, int]
    terminal_exit_eas: tuple[int, ...]
    calls_verify_safe: bool
    contains_calls: bool = False


@dataclass(frozen=True, slots=True)
class DetachedSnippetReplacementPlan:
    """Exact CALLS-time replacement of one folded live handler template."""

    target_ea: int
    selector_states: tuple[int, ...]
    conditional_branch_ea: int
    conditional_target_eas: tuple[int, int]
    terminal_routes: tuple[tuple[int, int], ...]


def plan_live_handler_template_replacements(
    evidence: tuple[DetachedSnippetReplacementEvidence, ...],
    *,
    state_targets: Mapping[int, int],
    complete_live_branch_eas: frozenset[int],
    resolver_targets: Mapping[int, tuple[int, ...]],
) -> tuple[DetachedSnippetReplacementPlan, ...]:
    """Select cached handler templates whose conditional arm was folded away.

    The handler must be selected by exact equality evidence, its conditional
    instruction must be absent or lack complete two-arm state semantics, and
    every terminal indirect exit must have one resolver target.  Captured calls
    are accepted only when the backend has already proven the SDK
    ``MBL_CALL``/``mop_f`` invariant.  Conflicting topology for one target
    contaminates that target.
    """
    by_target: dict[int, set[DetachedSnippetReplacementEvidence]] = {}
    for row in evidence:
        by_target.setdefault(int(row.target_ea), set()).add(row)

    plans: list[DetachedSnippetReplacementPlan] = []
    for target_ea, rows in sorted(by_target.items()):
        if len(rows) != 1 or target_ea <= 0:
            continue
        row = next(iter(rows))
        branch_ea = int(row.conditional_branch_ea)
        branch_targets = tuple(int(ea) for ea in row.conditional_target_eas)
        terminal_exits = tuple(
            dict.fromkeys(int(ea) for ea in row.terminal_exit_eas)
        )
        selector_states = tuple(
            sorted(
                int(state) & 0xFFFFFFFF
                for state, target in state_targets.items()
                if int(target) == target_ea
            )
        )
        if (
            not row.calls_verify_safe
            or branch_ea <= 0
            or branch_ea in complete_live_branch_eas
            or len(branch_targets) != 2
            or any(target <= 0 for target in branch_targets)
            or branch_targets[0] == branch_targets[1]
            or not terminal_exits
            or any(exit_ea <= 0 for exit_ea in terminal_exits)
            or not selector_states
        ):
            continue

        terminal_routes: list[tuple[int, int]] = []
        for exit_ea in terminal_exits:
            targets = tuple(
                dict.fromkeys(
                    int(target)
                    for target in resolver_targets.get(int(exit_ea), ())
                    if int(target) > 0
                )
            )
            if len(targets) != 1:
                terminal_routes = []
                break
            terminal_routes.append((int(exit_ea), int(targets[0])))
        if len(terminal_routes) != len(terminal_exits):
            continue
        plans.append(
            DetachedSnippetReplacementPlan(
                target_ea=target_ea,
                selector_states=selector_states,
                conditional_branch_ea=branch_ea,
                conditional_target_eas=branch_targets,
                terminal_routes=tuple(terminal_routes),
            )
        )
    return tuple(plans)


@dataclass(frozen=True, slots=True)
class DetachedSnippetTerminalEvidence:
    """Native provenance for one imported zero-way indirect exit."""

    imported_exit_ea: int
    native_exit_ea: int


@dataclass(frozen=True, slots=True)
class DetachedSnippetTerminalRoutePlan:
    """One exact resolver-target edge for an imported terminal exit."""

    source_block_serial: int
    target_block_serial: int
    native_exit_ea: int
    target_ea: int


def select_boundary_owned_terminal_source_blocks(
    *,
    source_native_ea_by_block: Mapping[int, int],
    predecessor_blocks_by_source: Mapping[int, frozenset[int]],
    redirect_endpoint_blocks_by_old_successor_ea: Mapping[
        int,
        frozenset[int],
    ],
) -> frozenset[int]:
    """Select terminal blocks wholly bypassed by applied redirect ports.

    A stable old-successor match is necessary but not sufficient: every live
    predecessor of the terminal must be an endpoint that was redirected away
    from that successor.  This prevents one applied port from hiding an
    unrelated incoming path.  A terminal with no predecessors is safe to
    suppress once an applied redirect port proves that it is an obsolete
    successor.
    """
    selected: set[int] = set()
    for source_block, native_ea in source_native_ea_by_block.items():
        if int(native_ea) not in redirect_endpoint_blocks_by_old_successor_ea:
            continue
        covering_endpoints = redirect_endpoint_blocks_by_old_successor_ea[
            int(native_ea)
        ]
        predecessors = predecessor_blocks_by_source.get(
            int(source_block),
            frozenset(),
        )
        if predecessors.issubset(covering_endpoints):
            selected.add(int(source_block))
    return frozenset(selected)


def plan_detached_snippet_terminal_routes(
    evidence: tuple[DetachedSnippetTerminalEvidence, ...],
    *,
    resolver_targets: Mapping[int, tuple[int, ...]],
    source_blocks_by_imported_ea: Mapping[int, int],
    target_blocks_by_ea: Mapping[int, int],
    zero_way_source_blocks: frozenset[int],
    already_routed_source_blocks: frozenset[int] = frozenset(),
) -> tuple[DetachedSnippetTerminalRoutePlan, ...]:
    """Join imported exits to unique native resolver targets, or abstain.

    No unmatched state is treated as a return.  A source is admitted only when
    its imported instruction has one native origin, that native jump has one
    resolver target, and both endpoint blocks are unique in the live graph.
    Conflicting proofs for the same source contaminate the whole source.
    """
    candidates: dict[int, set[DetachedSnippetTerminalRoutePlan]] = {}
    for row in evidence:
        targets = tuple(
            dict.fromkeys(
                int(target)
                for target in resolver_targets.get(int(row.native_exit_ea), ())
            )
        )
        if len(targets) != 1:
            continue
        source = source_blocks_by_imported_ea.get(int(row.imported_exit_ea))
        target_ea = targets[0]
        target = target_blocks_by_ea.get(target_ea)
        if (
            source is None
            or target is None
            or int(source) not in zero_way_source_blocks
            or int(source) in already_routed_source_blocks
            or int(source) == int(target)
        ):
            continue
        candidates.setdefault(int(source), set()).add(
            DetachedSnippetTerminalRoutePlan(
                source_block_serial=int(source),
                target_block_serial=int(target),
                native_exit_ea=int(row.native_exit_ea),
                target_ea=int(target_ea),
            )
        )
    return tuple(
        next(iter(plans))
        for _source, plans in sorted(candidates.items())
        if len(plans) == 1
    )


def merge_detached_snippet_ranges(
    ranges: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    """Return sorted, non-overlapping snippet ranges accepted by Hex-Rays."""
    normalized = sorted(
        (int(start), int(end))
        for start, end in ranges
        if int(start) < int(end)
    )
    merged: list[tuple[int, int]] = []
    for start, end in normalized:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        previous_start, previous_end = merged[-1]
        merged[-1] = (previous_start, max(previous_end, end))
    return tuple(merged)


class DetachedSnippetBoundaryPortOwner(str, Enum):
    """Which MBA owns one stable-EA boundary-port endpoint."""

    IMPORTED = "imported"
    LIVE = "live"


@dataclass(frozen=True, slots=True)
class DetachedSnippetDirectBoundaryPort:
    """One proven direct route with stable native-EA identity."""

    source_block_ea: int
    source_instruction_ea: int
    endpoint_block_ea: int
    old_successor_eas: tuple[int, ...]
    target_ea: int
    state_register: int | None
    state_constant: int | None
    source_owner: DetachedSnippetBoundaryPortOwner
    endpoint_owner: DetachedSnippetBoundaryPortOwner
    target_owner: DetachedSnippetBoundaryPortOwner
    delivery_mode: str
    resolver_kind: str
    old_successor_owners: tuple[DetachedSnippetBoundaryPortOwner, ...] = ()


def make_resolver_cut_boundary_port(
    *,
    source_block_ea: int,
    source_instruction_ea: int,
    target_ea: int,
    source_owner: DetachedSnippetBoundaryPortOwner,
    target_owner: DetachedSnippetBoundaryPortOwner,
    provenance: str,
) -> DetachedSnippetDirectBoundaryPort:
    """Represent one exact indirect cut without inventing state evidence."""
    return DetachedSnippetDirectBoundaryPort(
        source_block_ea=int(source_block_ea),
        source_instruction_ea=int(source_instruction_ea),
        endpoint_block_ea=int(source_block_ea),
        old_successor_eas=(),
        target_ea=int(target_ea),
        state_register=None,
        state_constant=None,
        source_owner=source_owner,
        endpoint_owner=source_owner,
        target_owner=target_owner,
        delivery_mode="terminal_goto",
        resolver_kind=str(provenance),
    )


@dataclass(frozen=True, slots=True)
class DetachedSnippetConditionalBoundaryPort:
    """One predicate with replacement arms and optional surviving old arms."""

    source_block_ea: int
    predicate_ea: int
    old_taken_target_ea: int | None
    old_fallthrough_target_ea: int | None
    taken_target_ea: int
    fallthrough_target_ea: int
    state_register: int | None
    taken_state: int | None
    fallthrough_state: int | None
    source_owner: DetachedSnippetBoundaryPortOwner
    taken_target_owner: DetachedSnippetBoundaryPortOwner
    fallthrough_target_owner: DetachedSnippetBoundaryPortOwner
    resolver_kind: str
    old_taken_target_owner: DetachedSnippetBoundaryPortOwner | None = None
    old_fallthrough_target_owner: DetachedSnippetBoundaryPortOwner | None = None
    logical_source_anchor_ea: int | None = None
    predicate_ida_stkoff: int | None = None
    predicate_size: int | None = None
    condition_code: int | None = None


@dataclass(frozen=True, slots=True)
class AppliedDetachedSnippetConditionalBoundaryPort:
    """One applied conditional port with maturity-stable arm anchors.

    The native target EA can name the middle of a PREOPT union block after
    backwards dependency closure.  Each anchor tuple therefore retains the
    instruction EAs of the exact created target block selected by the importer.
    No maturity-local block serial or live Hex-Rays object crosses this seam.
    """

    port: DetachedSnippetConditionalBoundaryPort
    taken_target_anchor_eas: tuple[int, ...]
    fallthrough_target_anchor_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AppliedDetachedSnippetDirectBoundaryPort:
    """One applied direct port with maturity-stable endpoint anchors.

    The native endpoint and target can both belong to the imported PREOPT
    union.  The anchor tuples retain the exact blocks selected by the atomic
    importer without leaking maturity-local block serials across the boundary.
    """

    port: DetachedSnippetDirectBoundaryPort
    endpoint_anchor_eas: tuple[int, ...]
    target_anchor_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DetachedSnippetBoundaryPorts:
    """Conflict-free immutable port captures attached to one template."""

    direct: tuple[DetachedSnippetDirectBoundaryPort, ...]
    conditional: tuple[DetachedSnippetConditionalBoundaryPort, ...]


def normalize_detached_snippet_boundary_ports(
    direct: tuple[DetachedSnippetDirectBoundaryPort, ...],
    conditional: tuple[DetachedSnippetConditionalBoundaryPort, ...],
) -> DetachedSnippetBoundaryPorts:
    """Deduplicate exact port captures and reject conflicting source proofs."""
    direct_by_source: dict[
        tuple[int, int, int, str, str], DetachedSnippetDirectBoundaryPort
    ] = {}
    for port in direct:
        source = (
            int(port.source_block_ea),
            int(port.source_instruction_ea),
            int(port.endpoint_block_ea),
            port.source_owner.value,
            port.endpoint_owner.value,
        )
        previous = direct_by_source.setdefault(source, port)
        if previous != port:
            raise ValueError(
                "conflicting direct boundary port for "
                f"source=0x{source[0]:X} instruction=0x{source[1]:X}"
            )

    conditional_by_source: dict[
        tuple[int, int, str], DetachedSnippetConditionalBoundaryPort
    ] = {}
    for port in conditional:
        source = (
            int(port.source_block_ea),
            int(port.predicate_ea),
            port.source_owner.value,
        )
        previous = conditional_by_source.setdefault(source, port)
        if previous != port:
            raise ValueError(
                "conflicting conditional boundary port for "
                f"source=0x{source[0]:X} predicate=0x{source[1]:X}"
            )

    direct_source_instructions = {
        (source_block_ea, source_instruction_ea, source_owner)
        for (
            source_block_ea,
            source_instruction_ea,
            _endpoint_block_ea,
            source_owner,
            _endpoint_owner,
        ) in direct_by_source
    }
    overlap = direct_source_instructions.intersection(conditional_by_source)
    if overlap:
        source_block_ea, source_instruction_ea, _source_owner = min(overlap)
        raise ValueError(
            "conflicting boundary port kinds for "
            f"source=0x{source_block_ea:X} instruction=0x{source_instruction_ea:X}"
        )
    return DetachedSnippetBoundaryPorts(
        direct=tuple(
            port
            for _source, port in sorted(direct_by_source.items())
        ),
        conditional=tuple(
            port
            for _source, port in sorted(conditional_by_source.items())
        ),
    )


def select_unique_block_native_ea(
    block_start_ea: int,
    instruction_eas: tuple[int, ...],
) -> int | None:
    """Select a stable native block identity, including empty external blocks."""
    start_ea = int(block_start_ea)
    candidates = tuple(
        sorted(
            {
                int(ea)
                for ea in instruction_eas
                if 0 < int(ea) < 0xFFFFFFFFFFFFFFFF
            }
        )
    )
    if start_ea in candidates:
        return start_ea
    if candidates:
        return candidates[0]
    if 0 < start_ea < 0xFFFFFFFFFFFFFFFF:
        return start_ea
    return None


def block_intersects_owned_ranges(
    block_start_ea: int,
    instruction_eas: tuple[int, ...],
    ranges: tuple[tuple[int, int], ...],
) -> bool:
    """Whether a native block anchor or instruction belongs to the ranges."""
    candidates = {int(block_start_ea)}
    candidates.update(int(ea) for ea in instruction_eas)
    return any(
        int(start_ea) <= candidate < int(end_ea)
        for candidate in candidates
        for start_ea, end_ea in ranges
    )


def plan_detached_snippet_routes(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    live_eas: frozenset[int],
    live_target_eas: frozenset[int] | None = None,
) -> tuple[DetachedSnippetRoutePlan, ...]:
    """Select unique static routes that require explicit snippet materialization."""
    routable_target_eas = (
        live_eas if live_target_eas is None else live_target_eas
    )
    condition_chain_targets: dict[int, set[int]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind == "condition_chain_handler_evidence"
            and transfer.selector_state_constant is not None
            and len(transfer.target_eas) == 1
        ):
            state = int(transfer.selector_state_constant) & 0xFFFFFFFF
            condition_chain_targets.setdefault(state, set()).add(
                int(transfer.target_eas[0])
            )
    candidates: dict[
        tuple[int, int],
        set[DetachedSnippetRoutePlan],
    ] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind
            in {
                "static_handler_entry_route",
                "static_equality_candidate",
                "residual_state_route_evidence",
                "residual_state_route",
            }
            and transfer.selector_state_constant is not None
            and len(transfer.target_eas) == 1
        ):
            state = int(transfer.selector_state_constant) & 0xFFFFFFFF
            target_ea = int(transfer.target_eas[0])
        elif (
            transfer.resolver_kind == "static_equality_fixpoint"
            and transfer.selector_compare_constant is not None
            and transfer.condition_code in (4, 5)
        ):
            state = int(transfer.selector_compare_constant) & 0xFFFFFFFF
            selected_target = (
                transfer.true_target_ea
                if transfer.condition_code == 4
                else transfer.false_target_ea
            )
            if selected_target is None:
                continue
            target_ea = int(selected_target)
            if target_ea not in transfer.target_eas:
                continue
            if not transfer.materialized_anchor_eas:
                continue
            source_ea = int(transfer.materialized_anchor_eas[0])
        else:
            continue
        if transfer.resolver_kind in {
            "static_handler_entry_route",
            "static_equality_candidate",
            "residual_state_route_evidence",
            "residual_state_route",
        }:
            source_ea = int(transfer.source_jmp_ea)
        if transfer.resolver_kind == "static_handler_entry_route":
            if live_target_eas is None:
                continue
            if not transfer.owned_native_ranges:
                continue
            live_router_targets = condition_chain_targets.get(state, set())
            if len(live_router_targets) != 1 or target_ea in live_router_targets:
                continue
        target_proven_live = target_ea in routable_target_eas
        if (
            source_ea <= 0
            or target_ea <= 0
            or target_proven_live
            or (
                transfer.resolver_kind
                in {
                    "static_handler_entry_route",
                    "residual_state_route_evidence",
                    "residual_state_route",
                }
                and source_ea not in live_eas
            )
        ):
            continue
        plan = DetachedSnippetRoutePlan(
            source_ea,
            target_ea,
            state,
            transfer.resolver_kind,
            (
                transfer.owned_native_ranges
                if transfer.resolver_kind == "static_handler_entry_route"
                else ()
            ),
        )
        candidates.setdefault((source_ea, state), set()).add(plan)
    return tuple(
        sorted(
            (
                next(iter(plans))
                for plans in candidates.values()
                if len(plans) == 1
            ),
            key=lambda plan: (plan.source_ea, plan.target_ea, plan.state_constant),
        )
    )


def select_detached_snippet_capture_ranges(
    plans: tuple[DetachedSnippetRoutePlan, ...],
    *,
    target_ea: int,
) -> tuple[tuple[int, int], ...] | None:
    """Return unique pre-patch owned ranges, or ``None`` for normal discovery."""
    candidates = {
        tuple((int(start_ea), int(end_ea)) for start_ea, end_ea in plan.owned_native_ranges)
        for plan in plans
        if plan.evidence_kind == "static_handler_entry_route"
        and int(plan.target_ea) == int(target_ea)
        and plan.owned_native_ranges
    }
    if not candidates:
        return None
    if len(candidates) != 1:
        return ()
    return next(iter(candidates))


@dataclass(frozen=True, slots=True)
class ConditionalRouteEvidence:
    """The two concrete arms of the same live microcode predicate."""

    source_predicate_ea: int
    condition_code: int
    true_target_ea: int
    false_target_ea: int


@dataclass(frozen=True, slots=True)
class DetachedSourcePath:
    """A unique conditional arm whose target is the detached handler."""

    source_predicate_ea: int
    detached_entry_ea: int
    live_sibling_target_ea: int
    detached_is_true: bool


@dataclass(frozen=True, slots=True)
class DetachedHandlerIslandCandidate:
    """Normalized backend facts required to rehost one detached handler."""

    source_path: DetachedSourcePath
    detached_end_ea: int
    call_target_ea: int
    call_argument_ida_stkoff: int
    predicate_ida_stkoff: int
    state_register: int
    condition_code: int
    inherited_state: int
    taken_state: int
    state_targets: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class DetachedHandlerIslandPlan:
    """Backend-neutral recipe for a live conditional handler island."""

    source_predicate_ea: int
    detached_entry_ea: int
    detached_end_ea: int
    call_target_ea: int
    call_argument_ida_stkoff: int
    predicate_ida_stkoff: int
    state_register: int
    false_state: int
    true_state: int
    false_target_ea: int
    true_target_ea: int


def select_detached_source_path(
    *,
    residual_routes: tuple[DetachedRouteEvidence, ...],
    conditional_routes: tuple[ConditionalRouteEvidence, ...],
) -> DetachedSourcePath | None:
    """Pair one residual target with exactly one arm of one live predicate.

    The residual route can be emitted by a later transfer site than the live
    predicate that selects the detached payload.  The stable identity shared by
    both proofs is therefore the resolved target EA, not the producer EA.
    """
    matches: list[DetachedSourcePath] = []
    for residual in residual_routes:
        for conditional in conditional_routes:
            detached = int(residual.detached_entry_ea)
            true_target = int(conditional.true_target_ea)
            false_target = int(conditional.false_target_ea)
            if true_target == false_target:
                continue
            if detached == true_target:
                matches.append(
                    DetachedSourcePath(
                        source_predicate_ea=int(conditional.source_predicate_ea),
                        detached_entry_ea=detached,
                        live_sibling_target_ea=false_target,
                        detached_is_true=True,
                    )
                )
            elif detached == false_target:
                matches.append(
                    DetachedSourcePath(
                        source_predicate_ea=int(conditional.source_predicate_ea),
                        detached_entry_ea=detached,
                        live_sibling_target_ea=true_target,
                        detached_is_true=False,
                    )
                )
    return matches[0] if len(matches) == 1 else None


def _unique_state_targets(
    rows: tuple[tuple[int, int], ...],
) -> dict[int, int] | None:
    targets: dict[int, int] = {}
    for state, target in rows:
        normalized_state = int(state) & 0xFFFFFFFF
        normalized_target = int(target)
        existing = targets.get(normalized_state)
        if existing is not None and existing != normalized_target:
            return None
        targets[normalized_state] = normalized_target
    return targets


def plan_detached_handler_island(
    candidate: DetachedHandlerIslandCandidate,
) -> DetachedHandlerIslandPlan | None:
    """Resolve both internal predicate arms or fail closed."""
    source_path = candidate.source_path
    if (
        int(source_path.source_predicate_ea) <= 0
        or int(source_path.detached_entry_ea) <= 0
        or int(source_path.live_sibling_target_ea) <= 0
        or int(candidate.detached_end_ea) <= int(source_path.detached_entry_ea)
        or int(candidate.call_target_ea) <= 0
        or int(candidate.call_argument_ida_stkoff) < 0
        or int(candidate.predicate_ida_stkoff) < 0
        or int(candidate.state_register) < 0
        or int(candidate.condition_code) not in (4, 5)
    ):
        return None
    inherited_state = int(candidate.inherited_state) & 0xFFFFFFFF
    taken_state = int(candidate.taken_state) & 0xFFFFFFFF
    if inherited_state == taken_state:
        return None
    state_targets = _unique_state_targets(candidate.state_targets)
    if state_targets is None:
        return None

    if int(candidate.condition_code) == 5:
        false_state, true_state = inherited_state, taken_state
    else:
        false_state, true_state = taken_state, inherited_state
    false_target = state_targets.get(false_state)
    true_target = state_targets.get(true_state)
    if (
        false_target is None
        or true_target is None
        or int(false_target) == int(true_target)
    ):
        return None
    return DetachedHandlerIslandPlan(
        source_predicate_ea=int(source_path.source_predicate_ea),
        detached_entry_ea=int(source_path.detached_entry_ea),
        detached_end_ea=int(candidate.detached_end_ea),
        call_target_ea=int(candidate.call_target_ea),
        call_argument_ida_stkoff=int(candidate.call_argument_ida_stkoff),
        predicate_ida_stkoff=int(candidate.predicate_ida_stkoff),
        state_register=int(candidate.state_register),
        false_state=false_state,
        true_state=true_state,
        false_target_ea=int(false_target),
        true_target_ea=int(true_target),
    )


__all__ = [
    "ConditionalHandlerBridgePlan",
    "ConditionalHandlerTargetTopology",
    "ConditionalRouteEvidence",
    "AppliedDetachedSnippetConditionalBoundaryPort",
    "AppliedDetachedSnippetDirectBoundaryPort",
    "conditional_bridge_requires_pre_dce_preservation",
    "conditional_bridge_route_evidence_converged",
    "DetachedHandlerIslandCandidate",
    "DetachedHandlerIslandPlan",
    "DetachedRouteEvidence",
    "DetachedSnippetRoutePlan",
    "DetachedSnippetBoundaryPortOwner",
    "DetachedSnippetBoundaryPorts",
    "DetachedSnippetConditionalBoundaryPort",
    "DetachedSnippetDirectBoundaryPort",
    "DetachedSnippetReplacementEvidence",
    "DetachedSnippetReplacementPlan",
    "DetachedSnippetTerminalEvidence",
    "DetachedSnippetTerminalRoutePlan",
    "DetachedSourcePath",
    "plan_detached_handler_island",
    "plan_detached_snippet_routes",
    "plan_live_handler_template_replacements",
    "plan_detached_snippet_terminal_routes",
    "select_boundary_owned_terminal_source_blocks",
    "merge_detached_snippet_ranges",
    "make_resolver_cut_boundary_port",
    "normalize_detached_snippet_boundary_ports",
    "plan_conditional_handler_bridges",
    "select_detached_source_path",
]
