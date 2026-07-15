"""Capture PREOPT source corridors for closure-owned resolver ports."""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from d810.core.typing import Collection, Mapping
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetConditionalBoundaryPort,
    DetachedSnippetDirectBoundaryPort,
)

try:
    from .preopt_boundary_port import (
        PreoptBoundaryEndpointOwner,
        PreoptBoundaryPortPlan,
        PreoptConditionalBoundaryPort,
        PreoptDirectBoundaryPort,
    )
except ImportError:  # Direct execution from this investigation directory.
    from preopt_boundary_port import (
        PreoptBoundaryEndpointOwner,
        PreoptBoundaryPortPlan,
        PreoptConditionalBoundaryPort,
        PreoptDirectBoundaryPort,
    )


class PreoptPortTailKind(str, Enum):
    NONE = "none"
    OTHER = "other"
    GOTO = "goto"
    CALL = "call"
    INDIRECT = "indirect"
    CONDITIONAL = "conditional"
    RETURN = "return"


class PreoptPortDeliveryMode(str, Enum):
    TERMINAL_GOTO = "terminal_goto"
    REDIRECT_EDGE = "redirect_edge"
    PRESERVE_CALL = "preserve_call"
    PRESERVE_CONDITIONAL = "preserve_conditional"


def canonical_snippet_stack_offset(
    vd_offset: int,
    return_address_size: int,
) -> int:
    """Convert snippet ``mop_S`` offsets to caller-frame stack offsets."""
    offset = int(vd_offset)
    return_size = int(return_address_size)
    if return_size < 0 or offset < return_size:
        raise ValueError("snippet stack offset lies inside the return address")
    return offset - return_size


class PreoptPortCaptureAbstentionReason(str, Enum):
    MISSING_SOURCE_BLOCK = "missing_source_block"
    SOURCE_INSTRUCTION_MISSING = "source_instruction_missing"
    MISSING_CORRIDOR_BLOCK = "missing_corridor_block"
    BRANCHING_CORRIDOR = "branching_corridor"
    CYCLIC_CORRIDOR = "cyclic_corridor"
    UNPROVEN_INDIRECT = "unproven_indirect"
    TERMINAL_SOURCE = "terminal_source"
    PREDICATE_NOT_TAIL = "predicate_not_tail"
    CONDITIONAL_SHAPE_MISMATCH = "conditional_shape_mismatch"
    MISSING_SUCCESSOR_IDENTITY = "missing_successor_identity"
    CORRIDOR_LIMIT = "corridor_limit"
    SOURCE_STATE_WRITE_MISMATCH = "source_state_write_mismatch"
    NO_SOURCE_SENSITIVE_FRONTIER = "no_source_sensitive_frontier"


@dataclass(frozen=True, slots=True)
class PreoptPortBlockFact:
    start_ea: int
    end_ea: int
    instruction_eas: tuple[int, ...] = ()
    successor_eas: tuple[int, ...] = ()
    successors_complete: bool = True
    register_constant_writes: tuple[tuple[int, int, int], ...] = ()
    register_write_eas: tuple[tuple[int, int], ...] = ()
    register_copy_writes: tuple[tuple[int, int, int], ...] = ()
    register_stack_loads: tuple[tuple[int, int, int, int], ...] = ()
    stack_register_stores: tuple[tuple[int, int, int, int], ...] = ()
    has_synthetic_function_exit_successor: bool = False
    has_side_effects: bool = False
    tail_ea: int | None = None
    taken_successor_ea: int | None = None
    fallthrough_successor_ea: int | None = None
    tail_kind: PreoptPortTailKind = PreoptPortTailKind.NONE

    def __post_init__(self) -> None:
        if int(self.end_ea) <= int(self.start_ea):
            raise ValueError("PREOPT port block range must be non-empty")


@dataclass(frozen=True, slots=True)
class PreoptPortBoundaryEdge:
    source_block_ea: int
    dispatcher_target_ea: int


@dataclass(frozen=True, slots=True)
class CapturedDirectBoundaryPort:
    request: PreoptDirectBoundaryPort
    corridor_block_eas: tuple[int, ...]
    frontier_edges: tuple[PreoptPortBoundaryEdge, ...]
    delivery_mode: PreoptPortDeliveryMode
    terminal_endpoint_block_eas: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class CapturedConditionalBoundaryPort:
    request: PreoptConditionalBoundaryPort
    source_block_ea: int
    predicate_ea: int
    old_taken_target_ea: int | None
    old_fallthrough_target_ea: int | None
    taken_target_ea: int
    fallthrough_target_ea: int
    delivery_mode: PreoptPortDeliveryMode = (
        PreoptPortDeliveryMode.PRESERVE_CONDITIONAL
    )


@dataclass(frozen=True, slots=True)
class PreoptPortCaptureAbstention:
    source_ea: int
    reason: PreoptPortCaptureAbstentionReason
    block_ea: int | None = None


@dataclass(frozen=True, slots=True)
class CapturedPreoptBoundaryPorts:
    direct: tuple[CapturedDirectBoundaryPort, ...]
    conditional: tuple[CapturedConditionalBoundaryPort, ...]
    abstentions: tuple[PreoptPortCaptureAbstention, ...]


@dataclass(frozen=True, slots=True)
class PreoptDirectOwnerBinding:
    """One coherent source/endpoint owner pair for a captured direct port."""

    source_owner: PreoptBoundaryEndpointOwner
    endpoint_owner: PreoptBoundaryEndpointOwner
    old_successor_owners: tuple[PreoptBoundaryEndpointOwner, ...] = ()


class PreoptClosureCrossingAbstentionReason(str, Enum):
    """Why one live-to-imported native CFG crossing was not captured."""

    MISSING_SOURCE_BLOCK = "missing_source_block"
    SOURCE_NOT_LIVE = "source_not_live"
    INCOMPLETE_SUCCESSORS = "incomplete_successors"
    TOPOLOGY_MISMATCH = "topology_mismatch"
    MISSING_SOURCE_ANCHOR = "missing_source_anchor"
    UNKNOWN_OLD_TARGET_OWNER = "unknown_old_target_owner"


@dataclass(frozen=True, slots=True)
class PreoptClosureCrossingAbstention:
    source_ea: int
    reason: PreoptClosureCrossingAbstentionReason
    target_eas: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class CapturedPreoptClosureCrossings:
    """Exact native CFG edges crossing from live PREOPT into the import."""

    direct: tuple[DetachedSnippetDirectBoundaryPort, ...]
    conditional: tuple[DetachedSnippetConditionalBoundaryPort, ...]
    abstentions: tuple[PreoptClosureCrossingAbstention, ...]


def exclude_closure_conditionals_superseded_by_captured(
    crossings: CapturedPreoptClosureCrossings,
    captured: CapturedPreoptBoundaryPorts,
) -> CapturedPreoptClosureCrossings:
    """Prefer captured replacement arms for the same native predicate.

    A captured conditional carries resolver-proven replacement targets.  The
    closure crossing for the same physical source/predicate only preserves the
    weaker native crossing shape and must not compete with that replacement at
    normalization time.
    """
    captured_keys = {
        (int(row.source_block_ea), int(row.predicate_ea))
        for row in captured.conditional
    }
    return replace(
        crossings,
        conditional=tuple(
            row
            for row in crossings.conditional
            if (int(row.source_block_ea), int(row.predicate_ea))
            not in captured_keys
        ),
    )


def captured_port_instruction_eas(
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
) -> frozenset[int]:
    """Index native instruction EAs that survived PREOPT source generation."""
    return frozenset(
        int(instruction_ea)
        for block in blocks_by_ea.values()
        for instruction_ea in block.instruction_eas
    )


def semantic_delta_block_entry_eas(
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    *,
    live_native_eas: Collection[int],
    requested_root_eas: Collection[int] = (),
) -> frozenset[int]:
    """Select generated blocks whose native semantics are not fully live."""
    live = {int(ea) for ea in live_native_eas}
    owned = {
        int(block.start_ea)
        for block in blocks_by_ea.values()
        if int(block.start_ea) not in live
        or any(
            int(instruction_ea) not in live
            for instruction_ea in block.instruction_eas
        )
    }
    for requested_root_ea in requested_root_eas:
        cursor = int(requested_root_ea)
        transparent_chain: list[int] = []
        visited: set[int] = set()
        while cursor not in owned and cursor not in visited:
            visited.add(cursor)
            block = blocks_by_ea.get(cursor)
            successors = (
                ()
                if block is None
                else tuple(dict.fromkeys(int(ea) for ea in block.successor_eas))
            )
            if (
                block is None
                or block.instruction_eas
                or block.has_side_effects
                or not block.successors_complete
                or len(successors) != 1
            ):
                break
            transparent_chain.append(cursor)
            cursor = successors[0]
        if cursor in owned:
            owned.update(transparent_chain)
    return frozenset(owned)


def capture_preopt_live_to_imported_crossings(
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    proven_internal_edges: Collection[tuple[int, int]],
    imported_block_eas: Collection[int],
    live_native_eas: Collection[int],
    excluded_source_eas: Collection[int] = (),
) -> CapturedPreoptClosureCrossings:
    """Capture exact ownership crossings omitted by partial block import.

    The generated PREOPT CFG already proves these native edges.  They need an
    explicit port only when semantic-delta ownership keeps the source in the
    live MBA but replaces one or both successor blocks with imported copies.
    The old and replacement endpoints can therefore share one native EA while
    having distinct owners.
    """
    imported = {int(ea) for ea in imported_block_eas}
    live = {int(ea) for ea in live_native_eas}
    excluded_sources = {int(ea) for ea in excluded_source_eas}
    targets_by_source: dict[int, set[int]] = {}
    for source_ea, target_ea in proven_internal_edges:
        targets_by_source.setdefault(int(source_ea), set()).add(int(target_ea))

    direct: list[DetachedSnippetDirectBoundaryPort] = []
    conditional: list[DetachedSnippetConditionalBoundaryPort] = []
    abstentions: list[PreoptClosureCrossingAbstention] = []
    for source_ea, edge_targets in sorted(targets_by_source.items()):
        if (
            source_ea in imported
            or source_ea in excluded_sources
            or edge_targets.isdisjoint(imported)
        ):
            continue
        if source_ea not in live:
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.SOURCE_NOT_LIVE,
                    tuple(sorted(edge_targets)),
                )
            )
            continue
        source = blocks_by_ea.get(source_ea)
        if source is None:
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.MISSING_SOURCE_BLOCK,
                    tuple(sorted(edge_targets)),
                )
            )
            continue
        if not source.successors_complete:
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.INCOMPLETE_SUCCESSORS,
                    tuple(sorted(edge_targets)),
                )
            )
            continue

        successors = {int(ea) for ea in source.successor_eas}
        if successors != edge_targets or len(successors) not in (1, 2):
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.TOPOLOGY_MISMATCH,
                    tuple(sorted(edge_targets)),
                )
            )
            continue
        if not successors.issubset(live):
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.UNKNOWN_OLD_TARGET_OWNER,
                    tuple(sorted(successors - live)),
                )
            )
            continue

        source_instruction_ea = (
            int(source.tail_ea)
            if source.tail_ea is not None
            else (
                int(source.instruction_eas[-1])
                if source.instruction_eas
                else None
            )
        )
        if source_instruction_ea is None:
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.MISSING_SOURCE_ANCHOR,
                    tuple(sorted(successors)),
                )
            )
            continue

        if len(successors) == 1:
            target_ea = next(iter(successors))
            direct.append(
                DetachedSnippetDirectBoundaryPort(
                    source_block_ea=source_ea,
                    source_instruction_ea=source_instruction_ea,
                    endpoint_block_ea=source_ea,
                    old_successor_eas=(target_ea,),
                    target_ea=target_ea,
                    state_register=None,
                    state_constant=None,
                    source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                    endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                    target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    delivery_mode=(
                        PreoptPortDeliveryMode.PRESERVE_CALL.value
                        if source.tail_kind is PreoptPortTailKind.CALL
                        else PreoptPortDeliveryMode.REDIRECT_EDGE.value
                    ),
                    resolver_kind="native_semantic_closure_crossing",
                    old_successor_owners=(
                        DetachedSnippetBoundaryPortOwner.LIVE,
                    ),
                )
            )
            continue

        taken_ea = source.taken_successor_ea
        fallthrough_ea = source.fallthrough_successor_ea
        if (
            source.tail_kind is not PreoptPortTailKind.CONDITIONAL
            or taken_ea is None
            or fallthrough_ea is None
            or {int(taken_ea), int(fallthrough_ea)} != successors
        ):
            abstentions.append(
                PreoptClosureCrossingAbstention(
                    source_ea,
                    PreoptClosureCrossingAbstentionReason.TOPOLOGY_MISMATCH,
                    tuple(sorted(successors)),
                )
            )
            continue
        conditional.append(
            DetachedSnippetConditionalBoundaryPort(
                source_block_ea=source_ea,
                predicate_ea=source_instruction_ea,
                old_taken_target_ea=int(taken_ea),
                old_fallthrough_target_ea=int(fallthrough_ea),
                taken_target_ea=int(taken_ea),
                fallthrough_target_ea=int(fallthrough_ea),
                state_register=None,
                taken_state=None,
                fallthrough_state=None,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                taken_target_owner=(
                    DetachedSnippetBoundaryPortOwner.IMPORTED
                    if int(taken_ea) in imported
                    else DetachedSnippetBoundaryPortOwner.LIVE
                ),
                fallthrough_target_owner=(
                    DetachedSnippetBoundaryPortOwner.IMPORTED
                    if int(fallthrough_ea) in imported
                    else DetachedSnippetBoundaryPortOwner.LIVE
                ),
                resolver_kind="native_semantic_closure_crossing",
                old_taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                old_fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            )
        )

    return CapturedPreoptClosureCrossings(
        direct=tuple(direct),
        conditional=tuple(conditional),
        abstentions=tuple(abstentions),
    )


def direct_endpoint_delivery_mode(
    captured: CapturedDirectBoundaryPort,
    *,
    old_successor_eas: Collection[int],
) -> PreoptPortDeliveryMode:
    """Choose delivery per endpoint in a possibly mixed captured corridor."""
    if not tuple(old_successor_eas):
        if captured.delivery_mode is PreoptPortDeliveryMode.PRESERVE_CALL:
            return PreoptPortDeliveryMode.PRESERVE_CALL
        return PreoptPortDeliveryMode.TERMINAL_GOTO
    return captured.delivery_mode


def state_transition_owned_endpoint_eas(
    captured: CapturedPreoptBoundaryPorts,
) -> frozenset[int]:
    """Return endpoints whose transfer is owned by state-transition proof."""
    return frozenset(
        {
            int(edge.source_block_ea)
            for row in captured.direct
            for edge in row.frontier_edges
        }
        | {
            int(endpoint_ea)
            for row in captured.direct
            for endpoint_ea in row.terminal_endpoint_block_eas
        }
    )


def classify_captured_endpoint_owner(
    ea: int,
    *,
    imported_block_eas: Collection[int],
    live_native_eas: Collection[int],
    preferred_owner: PreoptBoundaryEndpointOwner | None = None,
) -> PreoptBoundaryEndpointOwner | None:
    """Rebind planned ownership to the blocks in the captured union."""
    address = int(ea)
    imported = address in {int(block_ea) for block_ea in imported_block_eas}
    live = address in {int(native_ea) for native_ea in live_native_eas}
    if preferred_owner is PreoptBoundaryEndpointOwner.IMPORTED:
        return preferred_owner if imported else None
    if preferred_owner is PreoptBoundaryEndpointOwner.LIVE:
        return preferred_owner if live else None
    if imported:
        return PreoptBoundaryEndpointOwner.IMPORTED
    if live:
        return PreoptBoundaryEndpointOwner.LIVE
    return None


def select_captured_direct_owner_bindings(
    request: PreoptDirectBoundaryPort,
    *,
    endpoint_ea: int,
    old_successor_eas: Collection[int] = (),
    imported_block_eas: Collection[int],
    live_native_eas: Collection[int],
) -> tuple[PreoptDirectOwnerBinding, ...]:
    """Select every coherent owner-specific copy of one native direct port.

    Prefer same-graph source/endpoint pairs.  A cross-graph pair is retained
    only when the captured topology has no graph that owns both native EAs.
    This keeps the original live-to-imported boundary behavior while allowing
    duplicated PREOPT native blocks to receive one explicit port per owner.
    """
    imported = {int(block_ea) for block_ea in imported_block_eas}
    live = {int(native_ea) for native_ea in live_native_eas}
    source_ea = int(request.source_block_ea)
    endpoint = int(endpoint_ea)
    old_successors = tuple(int(ea) for ea in old_successor_eas)
    coherent = tuple(
        PreoptDirectOwnerBinding(
            owner,
            owner,
            (owner,) * len(old_successors),
        )
        for owner, owned_eas in (
            (PreoptBoundaryEndpointOwner.IMPORTED, imported),
            (PreoptBoundaryEndpointOwner.LIVE, live),
        )
        if source_ea in owned_eas
        and endpoint in owned_eas
    )
    if coherent:
        return coherent
    source_owner = classify_captured_endpoint_owner(
        source_ea,
        imported_block_eas=imported,
        live_native_eas=live,
        preferred_owner=request.source_owner,
    )
    endpoint_owner = classify_captured_endpoint_owner(
        endpoint,
        imported_block_eas=imported,
        live_native_eas=live,
    )
    if source_owner is None or endpoint_owner is None:
        return ()
    old_owners: list[PreoptBoundaryEndpointOwner] = []
    for old_successor in old_successors:
        old_owner = classify_captured_endpoint_owner(
            old_successor,
            imported_block_eas=imported,
            live_native_eas=live,
            preferred_owner=endpoint_owner,
        )
        if old_owner is None:
            return ()
        old_owners.append(old_owner)
    return (
        PreoptDirectOwnerBinding(
            source_owner,
            endpoint_owner,
            tuple(old_owners),
        ),
    )


def exclude_ports_satisfied_by_internal_edges(
    captured: CapturedPreoptBoundaryPorts,
    *,
    proven_internal_edges: Collection[tuple[int, int]],
) -> CapturedPreoptBoundaryPorts:
    """Drop imported overlays already expressed by the generated native CFG."""
    internal_edges = {
        (int(source_ea), int(target_ea))
        for source_ea, target_ea in proven_internal_edges
    }
    direct = tuple(
        row
        for row in captured.direct
        if not (
            row.request.source_owner
            == PreoptBoundaryEndpointOwner.IMPORTED
            and row.request.target_owner
            == PreoptBoundaryEndpointOwner.IMPORTED
            and any(
                (
                    int(frontier.dispatcher_target_ea),
                    int(row.request.target_ea),
                )
                in internal_edges
                for frontier in row.frontier_edges
            )
        )
    )
    return CapturedPreoptBoundaryPorts(
        direct=direct,
        conditional=captured.conditional,
        abstentions=captured.abstentions,
    )


def exclude_direct_endpoints_superseded_by_conditionals(
    captured: CapturedPreoptBoundaryPorts,
) -> CapturedPreoptBoundaryPorts:
    """Drop old-arm direct endpoints bypassed by a proven conditional port.

    A replacement conditional targets the resolved handlers directly.  When a
    later live state-write port begins in one of that conditional's old arms,
    mutating the same fused PREOPT block as both a conditional and a terminal
    goto would be contradictory.  The conditional proof owns that old arm.
    """
    predicates_by_old_arm: dict[int, set[int]] = {}
    conditional_sources = {
        (row.request.source_owner, int(row.source_block_ea))
        for row in captured.conditional
    }
    for row in captured.conditional:
        if row.request.source_owner is not PreoptBoundaryEndpointOwner.LIVE:
            continue
        for old_target_ea in (
            row.old_taken_target_ea,
            row.old_fallthrough_target_ea,
        ):
            if old_target_ea is None:
                continue
            predicates_by_old_arm.setdefault(int(old_target_ea), set()).add(
                int(row.predicate_ea)
            )

    direct: list[CapturedDirectBoundaryPort] = []
    for row in captured.direct:
        source_instruction_ea = int(row.request.source_instruction_ea)

        def superseded(endpoint_ea: int) -> bool:
            return (
                (
                    row.request.source_owner,
                    int(endpoint_ea),
                )
                in conditional_sources
                or (
                    row.request.source_owner
                    is PreoptBoundaryEndpointOwner.LIVE
                    and any(
                        predicate_ea < source_instruction_ea
                        for predicate_ea in predicates_by_old_arm.get(
                            int(endpoint_ea), ()
                        )
                    )
                )
            )

        frontier_edges = tuple(
            edge
            for edge in row.frontier_edges
            if not superseded(int(edge.source_block_ea))
        )
        terminal_endpoint_block_eas = tuple(
            endpoint_ea
            for endpoint_ea in row.terminal_endpoint_block_eas
            if not superseded(int(endpoint_ea))
        )
        if not frontier_edges and not terminal_endpoint_block_eas:
            continue
        direct.append(
            replace(
                row,
                frontier_edges=frontier_edges,
                terminal_endpoint_block_eas=terminal_endpoint_block_eas,
            )
        )
    return CapturedPreoptBoundaryPorts(
        direct=tuple(direct),
        conditional=captured.conditional,
        abstentions=captured.abstentions,
    )


def _source_block(
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    *,
    source_block_ea: int,
    source_instruction_ea: int,
) -> PreoptPortBlockFact | None:
    exact = blocks_by_ea.get(int(source_block_ea))
    if exact is not None and int(source_instruction_ea) in exact.instruction_eas:
        return exact
    candidates = tuple(
        block
        for block in blocks_by_ea.values()
        if int(source_instruction_ea) in block.instruction_eas
    )
    return candidates[0] if len(candidates) == 1 else None


_UNKNOWN_REACHING_DEFINITION = -1
_TOP_REACHING_DEFINITION = -2
_MAX_REACHING_DEFINITIONS = 64


def _block_register_writes(
    block: PreoptPortBlockFact,
    register: int,
) -> tuple[int, ...]:
    writes = {
        int(write_ea)
        for write_register, write_ea in block.register_write_eas
        if int(write_register) == int(register)
    }
    writes.update(
        int(write_ea)
        for write_register, _constant, write_ea in block.register_constant_writes
        if int(write_register) == int(register)
    )
    order = {
        int(instruction_ea): index
        for index, instruction_ea in enumerate(block.instruction_eas)
    }
    return tuple(
        sorted(
            writes,
            key=lambda write_ea: (order.get(int(write_ea), -1), int(write_ea)),
        )
    )


def _join_reaching_definitions(
    definitions: Collection[int],
) -> frozenset[int]:
    normalized = {int(definition) for definition in definitions}
    if (
        _TOP_REACHING_DEFINITION in normalized
        or len(normalized) > _MAX_REACHING_DEFINITIONS
    ):
        return frozenset({_TOP_REACHING_DEFINITION})
    return frozenset(normalized)


def reaching_register_definitions(
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    register: int,
) -> tuple[dict[int, frozenset[int]], dict[int, frozenset[int]]]:
    predecessors: dict[int, set[int]] = {
        int(block_ea): set() for block_ea in blocks_by_ea
    }
    for block_ea, block in blocks_by_ea.items():
        for successor_ea in block.successor_eas:
            if int(successor_ea) in predecessors:
                predecessors[int(successor_ea)].add(int(block_ea))

    in_definitions = {
        int(block_ea): frozenset() for block_ea in blocks_by_ea
    }
    out_definitions = {
        int(block_ea): frozenset() for block_ea in blocks_by_ea
    }
    iteration_limit = max(1, len(blocks_by_ea) * 2)
    for _iteration in range(iteration_limit):
        changed = False
        for block_ea, block in sorted(blocks_by_ea.items()):
            predecessor_eas = predecessors[int(block_ea)]
            if predecessor_eas:
                incoming = _join_reaching_definitions(
                    definition
                    for predecessor_ea in predecessor_eas
                    for definition in out_definitions[predecessor_ea]
                )
                if not incoming:
                    incoming = frozenset({_UNKNOWN_REACHING_DEFINITION})
            else:
                incoming = frozenset({_UNKNOWN_REACHING_DEFINITION})
            writes = _block_register_writes(block, int(register))
            outgoing = (
                frozenset({int(writes[-1])}) if writes else incoming
            )
            if (
                incoming != in_definitions[int(block_ea)]
                or outgoing != out_definitions[int(block_ea)]
            ):
                in_definitions[int(block_ea)] = incoming
                out_definitions[int(block_ea)] = outgoing
                changed = True
        if not changed:
            break
    return in_definitions, out_definitions


def _expand_resolver_router_bridges(
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    dispatcher_entry_eas: Collection[int],
    resolver_targets_by_source_block_ea: Mapping[int, Collection[int]],
    state_registers: Collection[int],
) -> frozenset[int]:
    router_eas = {int(ea) for ea in dispatcher_entry_eas}
    state_regs = {int(register) for register in state_registers}
    while True:
        additions: set[int] = set()
        for source_ea, target_eas in resolver_targets_by_source_block_ea.items():
            source = int(source_ea)
            fact = blocks_by_ea.get(source)
            targets = {int(target_ea) for target_ea in target_eas}
            if (
                source in router_eas
                or fact is None
                or not targets
                or not targets.issubset(router_eas)
                or fact.has_side_effects
                or any(
                    int(register) in state_regs
                    for register, _write_ea in fact.register_write_eas
                )
            ):
                continue
            additions.add(source)
        if not additions:
            return frozenset(router_eas)
        router_eas.update(additions)


def _capture_direct(
    request: PreoptDirectBoundaryPort,
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    dispatcher_entry_eas: Collection[int],
    resolver_cut_instruction_eas: Collection[int],
    in_definitions: Mapping[int, frozenset[int]],
    out_definitions: Mapping[int, frozenset[int]],
    proven_pruned_conditional_direct_source_eas: Collection[int],
) -> tuple[
    CapturedDirectBoundaryPort | None,
    PreoptPortCaptureAbstention | None,
]:
    source = _source_block(
        blocks_by_ea,
        source_block_ea=int(request.source_block_ea),
        source_instruction_ea=int(request.source_instruction_ea),
    )
    if source is None:
        return None, PreoptPortCaptureAbstention(
            int(request.source_instruction_ea),
            PreoptPortCaptureAbstentionReason.MISSING_SOURCE_BLOCK,
            int(request.source_block_ea),
        )
    if int(request.source_instruction_ea) not in source.instruction_eas:
        return None, PreoptPortCaptureAbstention(
            int(request.source_instruction_ea),
            PreoptPortCaptureAbstentionReason.SOURCE_INSTRUCTION_MISSING,
            int(source.start_ea),
        )

    source_write_ea = int(request.source_instruction_ea)
    source_writes = _block_register_writes(source, int(request.state_register))
    if source_write_ea not in source_writes:
        return None, PreoptPortCaptureAbstention(
            source_write_ea,
            PreoptPortCaptureAbstentionReason.SOURCE_STATE_WRITE_MISMATCH,
            int(source.start_ea),
        )
    literal_values = {
        int(constant) & 0xFFFFFFFF
        for register, constant, write_ea in source.register_constant_writes
        if int(register) == int(request.state_register)
        and int(write_ea) == source_write_ea
    }
    if literal_values and literal_values != {
        int(request.state_constant) & 0xFFFFFFFF
    }:
        return None, PreoptPortCaptureAbstention(
            source_write_ea,
            PreoptPortCaptureAbstentionReason.SOURCE_STATE_WRITE_MISMATCH,
            int(source.start_ea),
        )

    dispatcher_entries = {int(ea) for ea in dispatcher_entry_eas}
    resolver_cut_instructions = {
        int(ea) for ea in resolver_cut_instruction_eas
    }
    singleton_source = frozenset({source_write_ea})
    corridor = {
        int(block_ea)
        for block_ea in blocks_by_ea
        if int(block_ea) not in dispatcher_entries
        and source_write_ea in out_definitions[int(block_ea)]
    }
    incomplete_block = next(
        (
            block_ea
            for block_ea in sorted(corridor)
            if not blocks_by_ea[block_ea].successors_complete
        ),
        None,
    )
    if incomplete_block is not None:
        return None, PreoptPortCaptureAbstention(
            source_write_ea,
            PreoptPortCaptureAbstentionReason.MISSING_SUCCESSOR_IDENTITY,
            int(incomplete_block),
        )
    unproven_indirect = next(
        (
            block_ea
            for block_ea in sorted(corridor)
            if blocks_by_ea[block_ea].tail_kind
            is PreoptPortTailKind.INDIRECT
            and (
                blocks_by_ea[block_ea].tail_ea is None
                or int(blocks_by_ea[block_ea].tail_ea)
                not in resolver_cut_instructions
            )
        ),
        None,
    )
    if unproven_indirect is not None:
        return None, PreoptPortCaptureAbstention(
            source_write_ea,
            PreoptPortCaptureAbstentionReason.UNPROVEN_INDIRECT,
            int(unproven_indirect),
        )
    frontier_edges = {
        PreoptPortBoundaryEdge(int(block_ea), int(successor_ea))
        for block_ea, block in blocks_by_ea.items()
        if out_definitions[int(block_ea)] == singleton_source
        for successor_ea in block.successor_eas
        if int(successor_ea) in dispatcher_entries
    }
    terminal_endpoints = {
        int(block_ea)
        for block_ea, block in blocks_by_ea.items()
        if out_definitions[int(block_ea)] == singleton_source
        and block.tail_kind is PreoptPortTailKind.INDIRECT
        and block.tail_ea is not None
        and int(block.tail_ea) in resolver_cut_instructions
    }
    ordered_corridor = tuple(sorted(corridor))
    ordered_frontier = tuple(
        sorted(
            frontier_edges,
            key=lambda edge: (
                int(edge.source_block_ea),
                int(edge.dispatcher_target_ea),
            ),
        )
    )
    ordered_terminal_endpoints = tuple(sorted(terminal_endpoints))
    if ordered_frontier or ordered_terminal_endpoints:
        frontier_sources = {
            int(edge.source_block_ea) for edge in ordered_frontier
        }
        mode = (
            PreoptPortDeliveryMode.PRESERVE_CALL
            if ordered_frontier
            and frontier_sources
            and all(
                blocks_by_ea[source_ea].tail_kind is PreoptPortTailKind.CALL
                for source_ea in frontier_sources
            )
            else (
                PreoptPortDeliveryMode.REDIRECT_EDGE
                if ordered_frontier
                else PreoptPortDeliveryMode.TERMINAL_GOTO
            )
        )
        return (
            CapturedDirectBoundaryPort(
                request=request,
                corridor_block_eas=ordered_corridor,
                frontier_edges=ordered_frontier,
                delivery_mode=mode,
                terminal_endpoint_block_eas=ordered_terminal_endpoints,
            ),
            None,
        )
    if (
        request.source_owner is PreoptBoundaryEndpointOwner.LIVE
        and source.successors_complete
        and not source.successor_eas
        and not source.has_synthetic_function_exit_successor
        and (
            source.tail_kind is PreoptPortTailKind.GOTO
            or (
                source.tail_kind is PreoptPortTailKind.CONDITIONAL
                and int(source.start_ea)
                in {
                    int(ea)
                    for ea in proven_pruned_conditional_direct_source_eas
                }
            )
        )
        and out_definitions[int(source.start_ea)] == singleton_source
    ):
        return (
            CapturedDirectBoundaryPort(
                request=request,
                corridor_block_eas=(int(source.start_ea),),
                frontier_edges=(),
                delivery_mode=PreoptPortDeliveryMode.TERMINAL_GOTO,
                terminal_endpoint_block_eas=(int(source.start_ea),),
            ),
            None,
        )
    if (
        request.source_owner is PreoptBoundaryEndpointOwner.LIVE
        and source.successors_complete
        and not source.successor_eas
        and not source.has_synthetic_function_exit_successor
        and source.tail_kind is PreoptPortTailKind.CALL
        and source.tail_ea is not None
        and out_definitions[int(source.start_ea)] == singleton_source
    ):
        return (
            CapturedDirectBoundaryPort(
                request=request,
                corridor_block_eas=(int(source.start_ea),),
                frontier_edges=(),
                delivery_mode=PreoptPortDeliveryMode.PRESERVE_CALL,
                terminal_endpoint_block_eas=(int(source.start_ea),),
            ),
            None,
        )
    return None, PreoptPortCaptureAbstention(
        source_write_ea,
        PreoptPortCaptureAbstentionReason.NO_SOURCE_SENSITIVE_FRONTIER,
        int(source.start_ea),
    )


def _capture_conditional(
    request: PreoptConditionalBoundaryPort,
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
) -> tuple[
    CapturedConditionalBoundaryPort | None,
    PreoptPortCaptureAbstention | None,
]:
    source = _source_block(
        blocks_by_ea,
        source_block_ea=int(request.source_block_ea),
        source_instruction_ea=int(request.predicate_ea),
    )
    if source is None:
        return None, PreoptPortCaptureAbstention(
            int(request.predicate_ea),
            PreoptPortCaptureAbstentionReason.MISSING_SOURCE_BLOCK,
            int(request.source_block_ea),
        )
    if int(source.tail_ea or -1) != int(request.predicate_ea):
        return None, PreoptPortCaptureAbstention(
            int(request.predicate_ea),
            PreoptPortCaptureAbstentionReason.PREDICATE_NOT_TAIL,
            int(source.start_ea),
        )
    if (
        request.source_owner is PreoptBoundaryEndpointOwner.LIVE
        and source.successors_complete
        and source.tail_kind is PreoptPortTailKind.CONDITIONAL
        and not source.successor_eas
    ):
        return (
            CapturedConditionalBoundaryPort(
                request=request,
                source_block_ea=int(source.start_ea),
                predicate_ea=int(request.predicate_ea),
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=int(request.taken_target_ea),
                fallthrough_target_ea=int(request.fallthrough_target_ea),
            ),
            None,
        )
    if (
        not source.successors_complete
        or source.tail_kind is not PreoptPortTailKind.CONDITIONAL
        or len(source.successor_eas) != 2
    ):
        return None, PreoptPortCaptureAbstention(
            int(request.predicate_ea),
            PreoptPortCaptureAbstentionReason.CONDITIONAL_SHAPE_MISMATCH,
            int(source.start_ea),
        )
    old_taken_target_ea = source.taken_successor_ea
    old_fallthrough_target_ea = source.fallthrough_successor_ea
    if (
        old_taken_target_ea is None
        or old_fallthrough_target_ea is None
        or old_taken_target_ea == old_fallthrough_target_ea
        or {int(old_taken_target_ea), int(old_fallthrough_target_ea)}
        != {int(successor_ea) for successor_ea in source.successor_eas}
    ):
        return None, PreoptPortCaptureAbstention(
            int(request.predicate_ea),
            PreoptPortCaptureAbstentionReason.MISSING_SUCCESSOR_IDENTITY,
            int(source.start_ea),
        )
    return (
        CapturedConditionalBoundaryPort(
            request=request,
            source_block_ea=int(source.start_ea),
            predicate_ea=int(request.predicate_ea),
            old_taken_target_ea=int(old_taken_target_ea),
            old_fallthrough_target_ea=int(old_fallthrough_target_ea),
            taken_target_ea=int(request.taken_target_ea),
            fallthrough_target_ea=int(request.fallthrough_target_ea),
        ),
        None,
    )


def capture_preopt_boundary_ports(
    plan: PreoptBoundaryPortPlan,
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    live_blocks_by_ea: Mapping[int, PreoptPortBlockFact] | None = None,
    dispatcher_entry_eas: Collection[int],
    resolver_cut_instruction_eas: Collection[int] = (),
    resolver_targets_by_source_block_ea: Mapping[
        int, Collection[int]
    ] | None = None,
    proven_pruned_conditional_direct_source_eas: Collection[int] = (),
) -> CapturedPreoptBoundaryPorts:
    """Capture exact PREOPT endpoints without carrying block serials."""
    direct: list[CapturedDirectBoundaryPort] = []
    conditional: list[CapturedConditionalBoundaryPort] = []
    abstentions: list[PreoptPortCaptureAbstention] = []
    source_graphs = {
        PreoptBoundaryEndpointOwner.IMPORTED: blocks_by_ea,
        PreoptBoundaryEndpointOwner.LIVE: (
            blocks_by_ea
            if live_blocks_by_ea is None
            else live_blocks_by_ea
        ),
    }
    definitions_by_owner: dict[
        PreoptBoundaryEndpointOwner,
        dict[int, tuple[dict[int, frozenset[int]], dict[int, frozenset[int]]]],
    ] = {}
    expanded_dispatcher_eas_by_owner: dict[
        PreoptBoundaryEndpointOwner, frozenset[int]
    ] = {}
    for owner, source_blocks in source_graphs.items():
        owner_registers = {
            int(request.state_register)
            for request in plan.direct
            if request.source_owner is owner
        }
        definitions_by_register = {
            register: reaching_register_definitions(source_blocks, register)
            for register in owner_registers
        }
        definitions_by_owner[owner] = definitions_by_register
        expanded_dispatcher_eas_by_owner[owner] = (
            _expand_resolver_router_bridges(
                source_blocks,
                dispatcher_entry_eas,
                resolver_targets_by_source_block_ea or {},
                definitions_by_register,
            )
        )
    for request in plan.direct:
        source_blocks = source_graphs[request.source_owner]
        in_definitions, out_definitions = definitions_by_owner[
            request.source_owner
        ][
            int(request.state_register)
        ]
        captured, abstention = _capture_direct(
            request,
            blocks_by_ea=source_blocks,
            dispatcher_entry_eas=expanded_dispatcher_eas_by_owner[
                request.source_owner
            ],
            resolver_cut_instruction_eas=resolver_cut_instruction_eas,
            in_definitions=in_definitions,
            out_definitions=out_definitions,
            proven_pruned_conditional_direct_source_eas=(
                proven_pruned_conditional_direct_source_eas
            ),
        )
        if captured is not None:
            direct.append(captured)
        if abstention is not None:
            abstentions.append(abstention)
    for request in plan.conditional:
        captured, abstention = _capture_conditional(
            request,
            blocks_by_ea=source_graphs[request.source_owner],
        )
        if captured is not None:
            conditional.append(captured)
        if abstention is not None:
            abstentions.append(abstention)
    return CapturedPreoptBoundaryPorts(
        direct=tuple(direct),
        conditional=tuple(conditional),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    row.source_ea,
                    row.reason.value,
                    row.block_ea is None,
                    row.block_ea or 0,
                ),
            )
        ),
    )


__all__ = [
    "CapturedPreoptClosureCrossings",
    "CapturedConditionalBoundaryPort",
    "CapturedDirectBoundaryPort",
    "CapturedPreoptBoundaryPorts",
    "PreoptPortBlockFact",
    "PreoptPortBoundaryEdge",
    "PreoptPortCaptureAbstention",
    "PreoptPortCaptureAbstentionReason",
    "PreoptPortDeliveryMode",
    "PreoptPortTailKind",
    "PreoptClosureCrossingAbstention",
    "PreoptClosureCrossingAbstentionReason",
    "capture_preopt_boundary_ports",
    "capture_preopt_live_to_imported_crossings",
    "captured_port_instruction_eas",
    "canonical_snippet_stack_offset",
    "direct_endpoint_delivery_mode",
    "exclude_closure_conditionals_superseded_by_captured",
    "exclude_direct_endpoints_superseded_by_conditionals",
    "exclude_ports_satisfied_by_internal_edges",
    "reaching_register_definitions",
    "semantic_delta_block_entry_eas",
]
