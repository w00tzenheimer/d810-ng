"""Lower bound canonical route evidence into a portable semantic fragment."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

from d810.analyses.control_flow.semantic_route_evidence import (
    BoundCanonicalSemanticEvidence,
    BoundSemanticBlock,
    CanonicalSemanticEvidence,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    semantic_route_proof_reaches_consumer,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    stable_block_identities_refine_at_anchor,
    stable_block_identity_semantic_anchor,
    stable_block_identity_from_snapshot,
    stable_block_identity_token,
)
from d810.ir.directed_graph import tarjan_scc
from d810.ir.flowgraph import FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentBoundaryPort,
    FragmentBoundaryPortKind,
    FragmentConditionalSelectEnvelope,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentDirectTransferRewrite,
    FragmentEdge,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentStoragePredicateMaterialization,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
    FragmentValueSite,
)


class CanonicalSemanticFragmentRejected(ValueError):
    """Bound canonical evidence cannot form one closed portable fragment."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "canonical_semantic_fragment_rejected",
        anchor_ea: int | None = None,
        payload: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = str(reason_code)
        self.anchor_ea = None if anchor_ea is None else int(anchor_ea)
        self.payload = dict(payload or {})


@dataclass(frozen=True, slots=True)
class _NestedStateRouteProjectionDecision:
    """One portable nested-route projection decision for diagnostics."""

    route_proof_id: str
    source_anchor_ea: int
    disposition: str
    reason: str
    projection_round: int
    source_block_ids: tuple[str, ...] = ()
    corridor_block_ids: tuple[str, ...] = ()

    def diagnostic_payload(self) -> dict[str, object]:
        return {
            "route_proof_id": self.route_proof_id,
            "source_anchor_ea": f"0x{int(self.source_anchor_ea):X}",
            "disposition": self.disposition,
            "reason": self.reason,
            "projection_round": int(self.projection_round),
            "source_block_ids": self.source_block_ids,
            "corridor_block_ids": self.corridor_block_ids,
        }


@dataclass(frozen=True, slots=True)
class _CallBackedNestedRouteStaging:
    """Exact imported owners that one call-backed route must keep staged."""

    route_proof_id: str
    block_ids: frozenset[str]
    exact_instruction_eas_by_block_id: Mapping[str, frozenset[int]]


def _identity_contains(
    owner: StableBlockIdentity,
    candidate: StableBlockIdentity,
) -> bool:
    return bool(
        _identity_ranges_contain(owner, candidate)
        and candidate.exact_instruction_eas.issubset(owner.exact_instruction_eas)
    )


def _identity_ranges_contain(
    owner: StableBlockIdentity,
    candidate: StableBlockIdentity,
) -> bool:
    return bool(
        owner.native_key == candidate.native_key
        and all(
            any(
                int(owner_interval.start_ea) <= int(candidate_interval.start_ea)
                and int(candidate_interval.end_ea) <= int(owner_interval.end_ea)
                for owner_interval in owner.native_ranges.intervals
            )
            for candidate_interval in candidate.native_ranges.intervals
        )
    )


def _identity_ranges_overlap(
    left: StableBlockIdentity,
    right: StableBlockIdentity,
) -> bool:
    return bool(
        left.native_key == right.native_key
        and any(
            max(int(left_interval.start_ea), int(right_interval.start_ea))
            < min(int(left_interval.end_ea), int(right_interval.end_ea))
            for left_interval in left.native_ranges.intervals
            for right_interval in right.native_ranges.intervals
        )
    )


def _unique_plan_block(
    plan: FragmentPlan,
    identity: StableBlockIdentity,
    anchor_ea: int,
    *,
    roles: frozenset[FragmentBlockRole],
    description: str,
) -> FragmentBlock:
    anchor_ea = int(anchor_ea)
    matches = tuple(
        block
        for block in plan.blocks
        if block.role in roles
        and block.stable_identity is not None
        and anchor_ea in block.stable_identity.exact_instruction_eas
        and _identity_contains(block.stable_identity, identity)
    )
    if len(matches) != 1:
        raise CanonicalSemanticFragmentRejected(
            f"{description} 0x{anchor_ea:X} requires one normalization-plan "
            f"owner, observed {len(matches)}",
            reason_code="normalization_plan_owner_count_mismatch",
            anchor_ea=anchor_ea,
            payload={
                "description": description,
                "owner_count": len(matches),
            },
        )
    return matches[0]


def _current_route_source(
    graph: FlowGraph,
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
    retained_identity: StableBlockIdentity,
    state_write_identity: StableBlockIdentity,
    state_write_ea: int,
    delivery_ea: int,
    corridor_instruction_eas: tuple[int, ...],
) -> tuple[int, StableBlockIdentity]:
    state_write_ea = int(state_write_ea)
    delivery_ea = int(delivery_ea)
    current_blocks = tuple(
        (block, identity)
        for serial, block in graph.blocks.items()
        if (identity := current_identity_by_serial.get(int(serial))) is not None
    )
    matches = tuple(
        (block, identity)
        for block, identity in current_blocks
        if _identity_contains(retained_identity, identity)
        and _identity_contains(identity, state_write_identity)
        and state_write_ea in identity.exact_instruction_eas
    )
    if len(matches) != 1:
        raise CanonicalSemanticFragmentRejected(
            f"canonical route state write 0x{state_write_ea:X} requires one "
            f"current source owner, observed {len(matches)}",
            reason_code="current_route_source_owner_count_mismatch",
            anchor_ea=state_write_ea,
            payload={
                "owner_count": len(matches),
                "owner_labels": tuple(
                    f"blk{int(block.serial)}@0x{int(block.start_ea):X}"
                    for block, _identity in matches
                ),
            },
        )
    source_block, source_identity = matches[0]
    source_serial = int(source_block.serial)

    for corridor_ea in tuple(int(ea) for ea in corridor_instruction_eas):
        materialized_owners = tuple(
            block
            for block, _identity in current_blocks
            if corridor_ea
            in {
                int(block.start_ea),
                *(int(instruction.ea) for instruction in block.insn_snapshots),
            }
        )
        if not materialized_owners:
            continue
        if (
            len(materialized_owners) != 1
            or int(materialized_owners[0].serial) != source_serial
        ):
            raise CanonicalSemanticFragmentRejected(
                "canonical route corridor has split current-graph ownership "
                f"at 0x{corridor_ea:X}",
                reason_code="split_route_corridor_ownership",
                anchor_ea=corridor_ea,
                payload={
                    "delivery_ea": f"0x{delivery_ea:X}",
                    "source_owner": (
                        f"blk{source_serial}@0x{int(source_block.start_ea):X}"
                    ),
                    "materialized_owner_labels": tuple(
                        f"blk{int(block.serial)}@0x{int(block.start_ea):X}"
                        for block in materialized_owners
                    ),
                },
            )
    return source_serial, source_identity


def _claim_current_external_identity(
    serial: int,
    identity: StableBlockIdentity,
    *,
    owner_serial_by_identity: dict[StableBlockIdentity, int],
) -> None:
    """Reject two current blocks that claim the same portable identity."""
    serial = int(serial)
    existing_serial = owner_serial_by_identity.get(identity)
    if existing_serial is None:
        owner_serial_by_identity[identity] = serial
        return
    if existing_serial == serial:
        return
    anchor_ea = stable_block_identity_semantic_anchor(identity)
    raise CanonicalSemanticFragmentRejected(
        "canonical external stable identity has multiple current owners",
        reason_code="external_identity_ambiguous",
        anchor_ea=anchor_ea,
        payload={
            "candidate_owner": f"blk{serial}@0x{anchor_ea:X}",
            "existing_owner": f"blk{existing_serial}@0x{anchor_ea:X}",
            "stable_identity": identity.diagnostic_label(),
        },
    )


def _current_owners_contained_by_identity(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
) -> tuple[tuple[int, int], ...]:
    """Return current block serials and anchors wholly owned by one identity."""
    owners = []
    for serial, block in graph.blocks.items():
        current_identity = current_identity_by_serial.get(int(serial))
        if current_identity is None or not _identity_contains(
            identity,
            current_identity,
        ):
            continue
        owners.append((int(block.serial), int(block.start_ea)))
    return tuple(owners)


def _current_owners_containing_identity(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
) -> tuple[tuple[int, int, StableBlockIdentity], ...]:
    """Return current blocks that uniquely cover a portable native identity."""
    owners = []
    for serial, block in graph.blocks.items():
        current_identity = current_identity_by_serial.get(int(serial))
        if (
            current_identity is None
            or current_identity.native_key != identity.native_key
            or not all(
                current_identity.native_ranges.contains(interval.start_ea)
                for interval in identity.native_ranges.intervals
            )
        ):
            continue
        owners.append(
            (
                int(block.serial),
                int(block.start_ea),
                current_identity,
            )
        )
    return tuple(owners)


def _current_identity_inventory_for_boundary(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    boundary_anchor_ea: int,
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
) -> tuple[dict[str, object], ...]:
    """Describe live identities that touch one rejected portable boundary."""
    boundary_anchor_ea = int(boundary_anchor_ea)
    inventory: list[dict[str, object]] = []
    for serial, current_identity in sorted(current_identity_by_serial.items()):
        contains_anchor = current_identity.native_ranges.contains(boundary_anchor_ea)
        overlaps_boundary = _identity_ranges_overlap(current_identity, identity)
        if not contains_anchor and not overlaps_boundary:
            continue
        block = graph.blocks[int(serial)]
        inventory.append(
            {
                "block": f"blk{int(serial)}@0x{int(block.start_ea):X}",
                "contains_anchor": contains_anchor,
                "overlaps_boundary_identity": overlaps_boundary,
                "stable_identity": current_identity.diagnostic_label(),
            }
        )
    return tuple(inventory)


def _normalization_incoming_operation_inventory(
    graph: FlowGraph,
    plan: FragmentPlan,
    boundary_block_id: str,
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
) -> tuple[dict[str, object], ...]:
    """Describe complete plan operations that enter one unpublished block."""
    inventory: list[dict[str, object]] = []
    for operation in plan.operations:
        if not any(
            edge.target_block_id == boundary_block_id for edge in operation.edges
        ):
            continue
        source = plan.block(operation.source_block_id)
        source_identity = source.stable_identity
        source_owners = (
            ()
            if source_identity is None
            else _current_owners_containing_identity(
                graph,
                source_identity,
                current_identity_by_serial=current_identity_by_serial,
            )
        )
        inventory.append(
            {
                "operation_id": operation.operation_id,
                "source_block_id": source.block_id,
                "source_anchor_ea": f"0x{int(source.semantic_anchor_ea):X}",
                "source_identity": (
                    None
                    if source_identity is None
                    else source_identity.diagnostic_label()
                ),
                "source_owner_labels": tuple(
                    f"blk{serial}@0x{anchor_ea:X}"
                    for serial, anchor_ea, _identity in source_owners
                ),
                "source_current_identity_inventory": (
                    ()
                    if source_identity is None
                    else _current_identity_inventory_for_boundary(
                        graph,
                        source_identity,
                        int(source.semantic_anchor_ea),
                        current_identity_by_serial=current_identity_by_serial,
                    )
                ),
                "edges": tuple(
                    {
                        "role": edge.role.value,
                        "target_block_id": edge.target_block_id,
                        "target_anchor_ea": (
                            f"0x{int(plan.block(edge.target_block_id).semantic_anchor_ea):X}"
                        ),
                        "target_identity": (
                            None
                            if plan.block(edge.target_block_id).stable_identity is None
                            else plan.block(
                                edge.target_block_id
                            ).stable_identity.diagnostic_label()
                        ),
                        "enters_boundary": edge.target_block_id == boundary_block_id,
                    }
                    for edge in operation.edges
                ),
            }
        )
    return tuple(inventory)


def _portable_dispatcher_scc_witnesses(
    graph: FlowGraph,
    prohibited_serials: tuple[int, ...],
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
    modified_current_serials: frozenset[int],
) -> tuple[int, ...]:
    """Keep one uniquely rebound witness for equivalent dispatcher SCC roles.

    If any current node in an unchanged dispatcher SCC remains entry-reachable,
    every node in that SCC remains reachable.  One portable witness therefore
    proves absence for the whole component.  A component without a uniquely
    owned stable identity is left unchanged so the backend still rejects it
    rather than selecting a snapshot-local block.
    """
    identity_counts = Counter(current_identity_by_serial.values())
    selected: set[int] = set()
    adjacency = {
        int(serial): tuple(int(successor) for successor in graph.successors(serial))
        for serial in graph.blocks
    }
    prohibited_set = frozenset(int(serial) for serial in prohibited_serials)
    for component in tarjan_scc(adjacency):
        members = tuple(
            serial for serial in prohibited_serials if int(serial) in component
        )
        if component.intersection(modified_current_serials):
            selected.update(int(serial) for serial in members)
            continue
        if len(members) <= 1:
            selected.update(int(serial) for serial in members)
            continue
        candidates = tuple(
            int(serial)
            for serial in members
            if (
                (identity := current_identity_by_serial.get(int(serial))) is not None
                and identity_counts[identity] == 1
            )
        )
        if not candidates:
            selected.update(int(serial) for serial in members)
            continue
        selected.add(
            min(
                candidates,
                key=lambda serial: stable_block_identity_token(
                    current_identity_by_serial[serial]
                ),
            )
        )
    selected.update(prohibited_set.difference(adjacency))
    return tuple(
        int(serial) for serial in prohibited_serials if int(serial) in selected
    )


def _merged_imported_ranges(
    blocks: Iterable[FragmentBlock],
    operations: tuple[FragmentOperation, ...],
) -> tuple[NativeEaInterval, ...]:
    intervals = [
        interval
        for block in blocks
        for interval in block.stable_identity.native_ranges.intervals
    ]
    for operation in operations:
        normalization = operation.computed_branch_normalization
        if normalization is None or not isinstance(
            normalization.conditional_select_envelope,
            FragmentImportedConditionalSelectEnvelope,
        ):
            continue
        envelope = normalization.conditional_select_envelope
        intervals.extend(envelope.selected_value_identity.native_ranges.intervals)
        intervals.extend(envelope.join_identity.native_ranges.intervals)
    intervals.sort(key=lambda interval: (int(interval.start_ea), int(interval.end_ea)))
    merged = []
    for interval in intervals:
        if not merged or int(interval.start_ea) > int(merged[-1].end_ea):
            merged.append(interval)
            continue
        previous = merged[-1]
        merged[-1] = type(previous)(
            int(previous.start_ea),
            max(int(previous.end_ea), int(interval.end_ea)),
        )
    return tuple(merged)


def _prohibited_frontend_replacement_ids(
    graph: FlowGraph,
    plan: FragmentPlan,
    *,
    prohibited_dispatcher_serials: frozenset[int],
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
) -> frozenset[str]:
    """Find frontend replacements whose current owners must disappear."""
    prohibited_identities = tuple(
        (
            serial,
            graph.blocks.get(serial),
            current_identity_by_serial.get(serial),
        )
        for serial in sorted(prohibited_dispatcher_serials)
    )
    replacement_ids: set[str] = set()
    for block in plan.blocks:
        identity = block.stable_identity
        if block.role is not FragmentBlockRole.REPLACEMENT or identity is None:
            continue
        matches = tuple(
            (serial, current_block, current_identity)
            for serial, current_block, current_identity in prohibited_identities
            if current_block is not None
            and current_identity is not None
            and (
                stable_block_identities_refine_at_anchor(
                    identity,
                    current_identity,
                    block.semantic_anchor_ea,
                )
                or (
                    int(current_block.start_ea) == int(block.semantic_anchor_ea)
                    and _identity_contains(identity, current_identity)
                )
            )
        )
        if len(matches) > 1:
            raise CanonicalSemanticFragmentRejected(
                "frontend replacement refines multiple prohibited current owners",
                reason_code="prohibited_replacement_owner_ambiguous",
                anchor_ea=int(block.semantic_anchor_ea),
                payload={
                    "replacement_block_id": block.block_id,
                    "current_owner_labels": tuple(
                        f"blk{serial}@0x{int(current_block.start_ea):X}"
                        for serial, current_block, _identity in matches
                    ),
                },
            )
        if matches:
            replacement_ids.add(block.block_id)
    return frozenset(replacement_ids)


def _as_imported_frontend_operation(
    plan: FragmentPlan,
    operation: FragmentOperation,
) -> FragmentOperation:
    """Convert one validated live split envelope into portable import proof."""
    normalization = operation.computed_branch_normalization
    envelope = (
        None if normalization is None else normalization.conditional_select_envelope
    )
    if not isinstance(envelope, FragmentConditionalSelectEnvelope):
        source = plan.block(operation.source_block_id)
        raise CanonicalSemanticFragmentRejected(
            "prohibited frontend replacement lacks a portable split envelope",
            reason_code="prohibited_replacement_envelope_unsupported",
            anchor_ea=int(source.semantic_anchor_ea),
            payload={"operation_id": operation.operation_id},
        )
    selected = plan.block(envelope.selected_value_block_id)
    join = plan.block(envelope.join_block_id)
    if selected.stable_identity is None or join.stable_identity is None:
        raise CanonicalSemanticFragmentRejected(
            "prohibited frontend replacement split owners lack stable identity",
            reason_code="prohibited_replacement_split_identity_missing",
            anchor_ea=int(envelope.predicate_ea),
            payload={"operation_id": operation.operation_id},
        )
    return replace(
        operation,
        computed_branch_normalization=replace(
            normalization,
            conditional_select_envelope=(
                FragmentImportedConditionalSelectEnvelope(
                    source_branch_ea=int(envelope.predicate_ea),
                    selected_value_ea=int(envelope.predicate_ea),
                    selected_value_identity=selected.stable_identity,
                    join_identity=join.stable_identity,
                )
            ),
        ),
    )


def _receipted_semantic_operation_closes_boundary(
    operation: FragmentOperation,
    native_body: FragmentNativeBody,
    normalization_authority: NormalizationWorkItemAuthority,
) -> bool:
    """Return whether one prior publication fully owns a semantic boundary."""
    if (
        operation.source_block_id not in native_body.block_ids
        or operation.operation_id not in normalization_authority.published_operation_ids
    ):
        return False
    if operation.roles in {
        frozenset({SemanticEdgeRole.DIRECT}),
        frozenset({SemanticEdgeRole.CALL_FALLTHROUGH}),
    }:
        return True
    return bool(
        operation.roles
        == frozenset(
            {
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
        and operation.computed_branch_normalization is not None
    )


def _detached_target_component(
    graph: FlowGraph,
    plan: FragmentPlan,
    target: FragmentBlock,
    *,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
    canonical_proof_id: str,
    normalization_authority: NormalizationWorkItemAuthority,
    allow_unresolved_published_boundaries: bool,
    prohibited_dispatcher_serials: frozenset[int],
    replaced_current_owner_serials: frozenset[int],
    required_staged_destination_ids: frozenset[str],
    required_exact_instruction_eas_by_block_id: Mapping[str, frozenset[int]],
) -> tuple[
    tuple[FragmentBlock, ...],
    tuple[FragmentOperation, ...],
    FragmentNativeBody,
]:
    native_body_id = target.native_body_id
    native_bodies = tuple(
        body for body in plan.native_bodies if body.body_id == native_body_id
    )
    if len(native_bodies) != 1:
        raise CanonicalSemanticFragmentRejected(
            "detached canonical target requires one normalization native body"
        )
    (native_body,) = native_bodies
    native_block_ids = frozenset(native_body.block_ids)
    operation_by_source = {
        operation.source_block_id: operation for operation in plan.operations
    }
    reimportable_replacement_ids = _prohibited_frontend_replacement_ids(
        graph,
        plan,
        prohibited_dispatcher_serials=prohibited_dispatcher_serials,
        current_identity_by_serial=current_identity_by_serial,
    )
    proof_owned_reimport_source_ids = frozenset(
        operation.source_block_id
        for operation in plan.operations
        if operation.operation_id in native_body.proof_ids
        and any(
            edge.target_block_id in reimportable_replacement_ids
            for edge in operation.edges
        )
    )
    selected_ids: set[str] = set()
    selected_operation_ids: set[str] = set()
    published_imported_identity_by_id: dict[str, StableBlockIdentity] = {}
    pending = [target.block_id]
    while pending:
        block_id = pending.pop()
        if block_id in selected_ids:
            continue
        if (
            block_id not in native_block_ids
            and block_id not in reimportable_replacement_ids
        ):
            raise CanonicalSemanticFragmentRejected(
                "detached canonical target component escapes its native body"
            )
        selected_ids.add(block_id)
        operation = operation_by_source.get(block_id)
        if operation is None:
            if block_id in reimportable_replacement_ids:
                raise CanonicalSemanticFragmentRejected(
                    "prohibited frontend replacement lacks semantic topology",
                    reason_code="prohibited_replacement_topology_missing",
                    anchor_ea=int(plan.block(block_id).semantic_anchor_ea),
                    payload={"replacement_block_id": block_id},
                )
            if block_id not in native_body.terminal_block_ids:
                raise CanonicalSemanticFragmentRejected(
                    "detached canonical target component lacks closed topology"
                )
            continue
        selected_operation_ids.add(operation.operation_id)
        for edge in operation.edges:
            edge_target = plan.block(edge.target_block_id)
            if edge_target.role is FragmentBlockRole.IMPORTED:
                if edge_target.native_body_id != native_body.body_id:
                    raise CanonicalSemanticFragmentRejected(
                        "detached canonical target crosses native-body ownership"
                    )
                current_owners = _current_owners_containing_identity(
                    graph,
                    edge_target.stable_identity,
                    current_identity_by_serial=current_identity_by_serial,
                )
                prohibited_owners = tuple(
                    owner
                    for owner in current_owners
                    if int(owner[0]) in prohibited_dispatcher_serials
                )
                if prohibited_owners:
                    nonprohibited_owners = tuple(
                        owner
                        for owner in current_owners
                        if int(owner[0]) not in prohibited_dispatcher_serials
                    )
                    if nonprohibited_owners:
                        raise CanonicalSemanticFragmentRejected(
                            "imported body identity has mixed prohibited and "
                            "published current owners",
                            reason_code=("imported_boundary_current_owner_mixed"),
                            anchor_ea=int(edge_target.semantic_anchor_ea),
                            payload={
                                "boundary_block_id": edge_target.block_id,
                                "current_owner_labels": tuple(
                                    f"blk{serial}@0x{anchor_ea:X}"
                                    for serial, anchor_ea, _identity in current_owners
                                ),
                            },
                        )
                    pending.append(edge_target.block_id)
                    continue
                replaced_current_owners = tuple(
                    owner
                    for owner in current_owners
                    if int(owner[0]) in replaced_current_owner_serials
                )
                if replaced_current_owners:
                    retained_current_owners = tuple(
                        owner
                        for owner in current_owners
                        if int(owner[0]) not in replaced_current_owner_serials
                    )
                    if retained_current_owners:
                        raise CanonicalSemanticFragmentRejected(
                            "imported body identity has mixed replaced and "
                            "retained current owners",
                            reason_code=("imported_boundary_replaced_owner_mixed"),
                            anchor_ea=int(edge_target.semantic_anchor_ea),
                            payload={
                                "boundary_block_id": edge_target.block_id,
                                "current_owner_labels": tuple(
                                    f"blk{serial}@0x{anchor_ea:X}"
                                    for serial, anchor_ea, _identity in current_owners
                                ),
                            },
                        )
                    pending.append(edge_target.block_id)
                    continue
                if edge_target.block_id != target.block_id and len(current_owners) > 1:
                    raise CanonicalSemanticFragmentRejected(
                        "published imported boundary has multiple current owners",
                        reason_code=(
                            "published_imported_boundary_current_owner_ambiguous"
                        ),
                        anchor_ea=int(edge_target.semantic_anchor_ea),
                        payload={
                            "boundary_block_id": edge_target.block_id,
                            "current_owner_labels": tuple(
                                f"blk{serial}@0x{anchor_ea:X}"
                                for serial, anchor_ea, _identity in current_owners
                            ),
                        },
                    )
                if edge_target.block_id in required_staged_destination_ids:
                    pending.append(edge_target.block_id)
                    continue
                if edge_target.block_id != target.block_id and len(current_owners) == 1:
                    if edge_target.block_id in proof_owned_reimport_source_ids:
                        pending.append(edge_target.block_id)
                        continue
                    if (
                        edge_target.block_id not in native_body.terminal_block_ids
                        and not _receipted_semantic_operation_closes_boundary(
                            operation_by_source[edge_target.block_id],
                            native_body,
                            normalization_authority,
                        )
                        and not allow_unresolved_published_boundaries
                    ):
                        unresolved_operation = operation_by_source[edge_target.block_id]
                        incoming_source = plan.block(operation.source_block_id)
                        owner_serial, owner_anchor_ea, _identity = current_owners[0]
                        raise CanonicalSemanticFragmentRejected(
                            "published imported boundary retains unresolved "
                            "semantic topology",
                            reason_code=(
                                "published_imported_boundary_topology_unresolved"
                            ),
                            anchor_ea=int(edge_target.semantic_anchor_ea),
                            payload={
                                "boundary_block_id": edge_target.block_id,
                                "current_owner": (
                                    f"blk{owner_serial}@0x{owner_anchor_ea:X}"
                                ),
                                "operation_id": unresolved_operation.operation_id,
                                "incoming_operation_id": operation.operation_id,
                                "incoming_source_block_id": operation.source_block_id,
                                "incoming_source_anchor_ea": (
                                    f"0x{int(incoming_source.semantic_anchor_ea):X}"
                                ),
                                "incoming_edge_role": edge.role.value,
                            },
                        )
                    selected_ids.add(edge_target.block_id)
                    published_imported_identity_by_id[edge_target.block_id] = (
                        current_owners[0][2]
                    )
                    continue
                pending.append(edge_target.block_id)
            elif edge_target.block_id in reimportable_replacement_ids:
                pending.append(edge_target.block_id)
            else:
                selected_ids.add(edge_target.block_id)

    selected_operations = tuple(
        operation
        for operation in plan.operations
        if operation.operation_id in selected_operation_ids
    )
    selected_native_imported_ids = frozenset(
        block_id
        for block_id in selected_ids
        if (
            plan.block(block_id).role is FragmentBlockRole.IMPORTED
            and block_id not in published_imported_identity_by_id
        )
    )
    selected_reimported_ids = frozenset(
        selected_ids.intersection(reimportable_replacement_ids)
    )
    selected_import_source_ids = selected_native_imported_ids | selected_reimported_ids
    required_exact_instruction_eas_by_block_id = {
        str(block_id): frozenset(int(ea) for ea in exact_instruction_eas)
        for block_id, exact_instruction_eas in (
            required_exact_instruction_eas_by_block_id.items()
        )
        if exact_instruction_eas
    }
    unstaged_required_ids = frozenset(
        required_exact_instruction_eas_by_block_id
    ).difference(selected_import_source_ids)
    if unstaged_required_ids:
        first_block_id = min(unstaged_required_ids)
        required_eas = required_exact_instruction_eas_by_block_id[first_block_id]
        raise CanonicalSemanticFragmentRejected(
            "proof-owned exact anchors require a staged imported block",
            reason_code="proof_owned_exact_anchor_staged_owner_missing",
            anchor_ea=(
                int(target.semantic_anchor_ea)
                if not required_eas
                else min(required_eas)
            ),
            payload={
                "block_id": first_block_id,
                "required_exact_instruction_eas": tuple(
                    f"0x{int(ea):X}" for ea in sorted(required_eas)
                ),
            },
        )
    scoped_body_id = f"{native_body.body_id}:canonical:{canonical_proof_id}"
    boundary_id_by_source_id: dict[str, str] = {}
    projected_boundary_by_id: dict[str, FragmentBlock] = {}
    for block in plan.blocks:
        if (
            block.block_id not in selected_ids
            or block.block_id in selected_import_source_ids
        ):
            continue
        identity = published_imported_identity_by_id.get(
            block.block_id,
            block.stable_identity,
        )
        if (
            block.role
            not in {
                FragmentBlockRole.EXTERNAL,
                FragmentBlockRole.IMPORTED,
                FragmentBlockRole.REPLACEMENT,
            }
            or identity is None
        ):
            raise CanonicalSemanticFragmentRejected(
                "detached canonical target has an unpublished boundary role",
                reason_code="detached_boundary_role_unsupported",
                anchor_ea=int(block.semantic_anchor_ea),
                payload={
                    "block_id": block.block_id,
                    "block_role": block.role.value,
                },
            )
        projected_id = f"native[{stable_block_identity_token(identity)}]"
        projected = FragmentBlock(
            block_id=projected_id,
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=(stable_block_identity_semantic_anchor(identity)),
            stable_identity=identity,
        )
        existing = projected_boundary_by_id.get(projected_id)
        if existing is not None and existing != projected:
            raise CanonicalSemanticFragmentRejected(
                "detached canonical target boundary identity is ambiguous",
                reason_code="detached_boundary_identity_ambiguous",
                anchor_ea=int(projected.semantic_anchor_ea),
                payload={
                    "candidate_block_id": block.block_id,
                    "projected_block_id": projected_id,
                },
            )
        projected_boundary_by_id[projected_id] = projected
        boundary_id_by_source_id[block.block_id] = projected_id

    imported_id_by_source_id: dict[str, str] = {}
    imported_identity_by_source_id: dict[str, StableBlockIdentity] = {}
    occupied_block_ids = {
        *(block.block_id for block in plan.blocks),
        *projected_boundary_by_id,
    }
    for source_id in sorted(selected_import_source_ids):
        source = plan.block(source_id)
        identity = source.stable_identity
        if identity is None:
            raise CanonicalSemanticFragmentRejected(
                "detached imported block lacks stable identity",
                reason_code=(
                    "prohibited_replacement_identity_missing"
                    if source_id in selected_reimported_ids
                    else "detached_import_identity_missing"
                ),
                anchor_ea=int(source.semantic_anchor_ea),
                payload={"source_block_id": source_id},
            )
        required_exact_eas = required_exact_instruction_eas_by_block_id.get(
            source_id,
            frozenset(),
        )
        out_of_range_eas = tuple(
            ea
            for ea in sorted(required_exact_eas)
            if not identity.native_ranges.contains(ea)
        )
        if out_of_range_eas:
            raise CanonicalSemanticFragmentRejected(
                "proof-owned exact anchor escapes its staged native ranges",
                reason_code="proof_owned_exact_anchor_range_mismatch",
                anchor_ea=int(out_of_range_eas[0]),
                payload={
                    "block_id": source_id,
                    "block_identity": identity.diagnostic_label(),
                    "out_of_range_eas": tuple(
                        f"0x{int(ea):X}" for ea in out_of_range_eas
                    ),
                },
            )
        refined_identity = identity
        if not required_exact_eas.issubset(identity.exact_instruction_eas):
            refined_identity = StableBlockIdentity.from_intervals(
                identity.native_ranges.intervals,
                native_key=identity.native_key,
                exact_instruction_eas=(
                    identity.exact_instruction_eas | required_exact_eas
                ),
            )
        imported_identity_by_source_id[source_id] = refined_identity
        if source_id not in selected_reimported_ids and refined_identity == identity:
            continue
        imported_id = (
            f"native[{stable_block_identity_token(refined_identity)}]:imported"
        )
        if imported_id in occupied_block_ids and imported_id != source_id:
            raise CanonicalSemanticFragmentRejected(
                "detached imported block identity conflicts",
                reason_code=(
                    "prohibited_replacement_import_id_conflict"
                    if source_id in selected_reimported_ids
                    else "detached_import_id_conflict"
                ),
                anchor_ea=int(source.semantic_anchor_ea),
                payload={
                    "source_block_id": source_id,
                    "imported_block_id": imported_id,
                },
            )
        occupied_block_ids.add(imported_id)
        imported_id_by_source_id[source_id] = imported_id

    selected_imported_blocks: list[FragmentBlock] = []
    for block in plan.blocks:
        if block.block_id in selected_native_imported_ids:
            selected_imported_blocks.append(
                replace(
                    block,
                    block_id=imported_id_by_source_id.get(
                        block.block_id,
                        block.block_id,
                    ),
                    stable_identity=imported_identity_by_source_id[block.block_id],
                    native_body_id=scoped_body_id,
                )
            )
            continue
        if block.block_id not in selected_reimported_ids:
            continue
        selected_imported_blocks.append(
            FragmentBlock(
                block_id=imported_id_by_source_id[block.block_id],
                role=FragmentBlockRole.IMPORTED,
                materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
                semantic_anchor_ea=int(block.semantic_anchor_ea),
                stable_identity=imported_identity_by_source_id[block.block_id],
                native_body_id=scoped_body_id,
            )
        )

    rewritten_operations: list[FragmentOperation] = []
    for operation in selected_operations:
        rewritten = (
            _as_imported_frontend_operation(plan, operation)
            if operation.source_block_id in selected_reimported_ids
            else operation
        )
        rewritten_operations.append(
            replace(
                rewritten,
                source_block_id=imported_id_by_source_id.get(
                    rewritten.source_block_id,
                    rewritten.source_block_id,
                ),
                edges=tuple(
                    replace(
                        edge,
                        target_block_id=imported_id_by_source_id.get(
                            edge.target_block_id,
                            boundary_id_by_source_id.get(
                                edge.target_block_id,
                                edge.target_block_id,
                            ),
                        ),
                    )
                    for edge in rewritten.edges
                ),
            )
        )
    selected_operations = tuple(rewritten_operations)
    selected_blocks = (
        *tuple(projected_boundary_by_id.values()),
        *selected_imported_blocks,
    )
    selected_native_body = FragmentNativeBody(
        body_id=scoped_body_id,
        block_ids=tuple(block.block_id for block in selected_imported_blocks),
        entry_block_ids=(
            imported_id_by_source_id.get(target.block_id, target.block_id),
        ),
        terminal_block_ids=tuple(
            imported_id_by_source_id.get(block_id, block_id)
            for block_id in native_body.terminal_block_ids
            if block_id in selected_native_imported_ids
        ),
        native_ranges=_merged_imported_ranges(
            selected_imported_blocks,
            selected_operations,
        ),
        proof_ids=tuple(
            dict.fromkeys(
                (
                    str(canonical_proof_id),
                    *(operation.operation_id for operation in selected_operations),
                )
            )
        ),
    )
    return selected_blocks, selected_operations, selected_native_body


def _canonical_composition_proofs(
    evidence: CanonicalSemanticEvidence,
) -> tuple[SemanticRouteProof, SemanticRouteProof | None]:
    """Select one live route and its exact downstream imported consumer."""
    direct = tuple(
        proof
        for proof in evidence.route_proofs
        if (
            proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
            and proof.shape is SemanticRouteShape.DIRECT
            and len(proof.destinations) == 1
            and proof.predicate is None
            and not proof.carriers
            and proof.terminal_return_carrier is None
            and proof.state_write is not None
        )
    )
    if len(direct) != 1:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition requires one complete direct state assignment"
        )
    (root_proof,) = direct
    consumers = tuple(
        proof for proof in evidence.route_proofs if proof is not root_proof
    )
    if not consumers:
        return root_proof, None
    if len(consumers) != 1:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition requires at most one downstream semantic consumer"
        )
    (consumer,) = consumers
    if (
        consumer.proof_kind is not SemanticRouteProofKind.STATE_CHOICE
        or consumer.shape is not SemanticRouteShape.CONDITIONAL
        or len(consumer.destinations) != 2
        or consumer.predicate is None
        or consumer.predicate.kind is not SemanticPredicateKind.STORAGE_EQUALS
        or len(consumer.carriers) != 1
        or consumer.state_write is not None
        or consumer.terminal_return_carrier is not None
        or consumer.source_owner_identity != consumer.source_identity
        or consumer.source_owner_anchor_ea != consumer.source_anchor_ea
        or not semantic_route_proof_reaches_consumer(
            root_proof,
            consumer,
        )
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition downstream consumer is not one complete "
            "imported state choice"
        )
    return root_proof, consumer


def _direct_transfer_rewrite(
    proof: SemanticRouteProof,
) -> FragmentDirectTransferRewrite | None:
    """Carry one proved direct route into detached rewrite coordinates."""
    if proof.shape is not SemanticRouteShape.DIRECT:
        return None
    delivery_region = proof.delivery_region
    if delivery_region is None:
        raise CanonicalSemanticFragmentRejected(
            "direct semantic route lacks its exact delivery region",
            reason_code="direct_route_delivery_region_missing",
            anchor_ea=int(proof.source_anchor_ea),
            payload={"route_proof_id": proof.proof_id},
        )
    if proof.state_write is not None:
        owner_identity = proof.state_write.identity
        owner_anchor_ea = int(proof.state_write.instruction_ea)
    elif proof.source_owner_identity is not None:
        if proof.source_owner_anchor_ea is None:
            raise CanonicalSemanticFragmentRejected(
                "direct semantic route owner lacks its exact anchor"
            )
        owner_identity = proof.source_owner_identity
        owner_anchor_ea = int(proof.source_owner_anchor_ea)
    else:
        owner_identity = proof.source_identity
        owner_anchor_ea = int(proof.source_anchor_ea)
    corridor_instruction_eas = (
        (int(proof.source_anchor_ea),)
        if proof.state_write is None
        else proof.state_write.corridor_instruction_eas
    )
    if corridor_instruction_eas[-1] != int(proof.source_anchor_ea):
        raise CanonicalSemanticFragmentRejected(
            "direct semantic route corridor does not end at its rewrite anchor",
            reason_code="direct_route_rewrite_corridor_incomplete",
            anchor_ea=int(proof.source_anchor_ea),
            payload={"route_proof_id": proof.proof_id},
        )
    return FragmentDirectTransferRewrite(
        route_proof_id=proof.proof_id,
        owner_identity=owner_identity,
        owner_anchor_ea=owner_anchor_ea,
        rewrite_anchor_ea=int(proof.source_anchor_ea),
        delivery_region=delivery_region,
        proof_corridor_instruction_eas=corridor_instruction_eas,
        superseded_instruction_eas=(int(proof.source_anchor_ea),),
    )


def _with_semantic_imported_consumer(
    plan: FragmentPlan,
    proof: SemanticRouteProof,
) -> FragmentPlan:
    """Replace one imported raw dispatcher operation with its semantic choice."""
    source = _unique_plan_block(
        plan,
        proof.source_identity,
        proof.source_anchor_ea,
        roles=frozenset({FragmentBlockRole.IMPORTED}),
        description="canonical imported semantic consumer",
    )
    if source.native_body_id is None:
        raise CanonicalSemanticFragmentRejected(
            "canonical imported semantic consumer lacks native-body ownership"
        )
    destinations = tuple(
        _unique_plan_block(
            plan,
            destination.target_identity,
            destination.target_anchor_ea,
            roles=frozenset(
                {
                    FragmentBlockRole.EXTERNAL,
                    FragmentBlockRole.IMPORTED,
                    FragmentBlockRole.REPLACEMENT,
                }
            ),
            description="canonical imported semantic destination",
        )
        for destination in proof.destinations
    )
    if any(
        destination.role is FragmentBlockRole.IMPORTED
        and destination.native_body_id != source.native_body_id
        for destination in destinations
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical imported semantic choice crosses native-body ownership"
        )
    source_operations = tuple(
        operation
        for operation in plan.operations
        if operation.source_block_id == source.block_id
    )
    if len(source_operations) != 1:
        raise CanonicalSemanticFragmentRejected(
            "canonical imported semantic consumer requires one raw operation"
        )
    (raw_operation,) = source_operations
    semantic_operation = FragmentOperation(
        operation_id=f"route:{proof.proof_id}",
        source_block_id=source.block_id,
        edges=tuple(
            FragmentEdge(
                role=destination.role,
                target_block_id=target.block_id,
            )
            for destination, target in zip(
                proof.destinations,
                destinations,
                strict=True,
            )
        ),
        predicate_anchor_ea=int(proof.source_anchor_ea),
        direct_transfer_rewrite=_direct_transfer_rewrite(proof),
    )
    native_bodies = tuple(
        replace(
            body,
            terminal_block_ids=tuple(
                block_id
                for block_id in body.terminal_block_ids
                if block_id != source.block_id
            ),
            proof_ids=tuple(
                dict.fromkeys(
                    (
                        *(
                            proof_id
                            for proof_id in body.proof_ids
                            if proof_id != raw_operation.operation_id
                        ),
                        proof.proof_id,
                    )
                )
            ),
        )
        if body.body_id == source.native_body_id
        else body
        for body in plan.native_bodies
    )
    return replace(
        plan,
        operations=tuple(
            semantic_operation if operation is raw_operation else operation
            for operation in plan.operations
        ),
        native_bodies=native_bodies,
    )


def _with_nested_imported_state_routes(
    plan: FragmentPlan,
    available_evidence: CanonicalSemanticEvidence,
    *,
    component_block_ids: frozenset[str],
    excluded_proof_ids: frozenset[str],
    projection_round: int,
    claimed_source_proof_ids: Mapping[str, str],
    claimed_corridor_proof_ids: Mapping[str, str],
) -> tuple[
    FragmentPlan,
    tuple[SemanticRouteProof, ...],
    tuple[_NestedStateRouteProjectionDecision, ...],
]:
    """Replace reachable imported dispatcher exits with canonical state routes.

    Frontend normalization retains the native selector topology so later
    canonical passes can inspect it.  Once a state assignment or terminal
    return and its delivery corridor are proved, however, the generic selector
    edge is no longer authoritative.  This projection replaces only routes
    whose complete write-to-delivery corridor already belongs to the selected
    detached component.  It never expands the work item merely because another
    route is present elsewhere in the normalization inventory.
    """
    imported_component_blocks = tuple(
        block
        for block in plan.blocks
        if (
            block.block_id in component_block_ids
            and block.role is FragmentBlockRole.IMPORTED
            and block.stable_identity is not None
        )
    )
    operation_by_source: dict[str, list[FragmentOperation]] = {}
    for operation in plan.operations:
        operation_by_source.setdefault(
            operation.source_block_id,
            [],
        ).append(operation)

    replacements: list[
        tuple[
            SemanticRouteProof,
            FragmentBlock,
            FragmentOperation,
            FragmentBlock,
        ]
    ] = []
    decisions: list[_NestedStateRouteProjectionDecision] = []
    claimed_source_ids = dict(claimed_source_proof_ids)
    claimed_corridor_ids = dict(claimed_corridor_proof_ids)
    for proof in available_evidence.route_proofs:
        if (
            proof.proof_id in excluded_proof_ids
            or proof.proof_kind
            not in {
                SemanticRouteProofKind.STATE_ASSIGNMENT,
                SemanticRouteProofKind.TERMINAL_RETURN,
            }
            or proof.shape is not SemanticRouteShape.DIRECT
            or len(proof.destinations) != 1
            or proof.state_write is None
            or proof.source_anchor_ea not in proof.source_identity.exact_instruction_eas
        ):
            continue
        source_matches = tuple(
            block
            for block in imported_component_blocks
            if (
                block.stable_identity is not None
                and block.stable_identity.native_ranges.contains(
                    int(proof.source_anchor_ea)
                )
                and _identity_ranges_contain(
                    block.stable_identity,
                    proof.source_identity,
                )
            )
        )
        if not source_matches:
            decisions.append(
                _NestedStateRouteProjectionDecision(
                    route_proof_id=proof.proof_id,
                    source_anchor_ea=int(proof.source_anchor_ea),
                    disposition="skipped",
                    reason="source_not_in_component",
                    projection_round=int(projection_round),
                )
            )
            continue
        if len(source_matches) != 1:
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state route has multiple imported sources",
                reason_code="nested_state_route_source_ambiguous",
                anchor_ea=int(proof.source_anchor_ea),
                payload={
                    "route_proof_id": proof.proof_id,
                    "source_block_ids": tuple(
                        block.block_id for block in source_matches
                    ),
                },
            )
        (source,) = source_matches
        corridor_owner_ids: list[str] = []
        for corridor_ea in proof.state_write.corridor_instruction_eas:
            owners = tuple(
                block
                for block in imported_component_blocks
                if block.stable_identity is not None
                and block.stable_identity.native_ranges.contains(int(corridor_ea))
            )
            if len(owners) != 1:
                raise CanonicalSemanticFragmentRejected(
                    "nested canonical state route corridor is not wholly "
                    "owned by its imported component",
                    reason_code="nested_state_route_corridor_owner_mismatch",
                    anchor_ea=int(corridor_ea),
                    payload={
                        "route_proof_id": proof.proof_id,
                        "owner_block_ids": tuple(block.block_id for block in owners),
                    },
                )
            corridor_owner_ids.append(owners[0].block_id)
        source_operations = tuple(operation_by_source.get(source.block_id, ()))
        if len(source_operations) != 1:
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state route requires one raw imported operation",
                reason_code="nested_state_route_operation_count_mismatch",
                anchor_ea=int(proof.source_anchor_ea),
                payload={
                    "route_proof_id": proof.proof_id,
                    "operation_ids": tuple(
                        operation.operation_id for operation in source_operations
                    ),
                    "corridor_block_ids": tuple(dict.fromkeys(corridor_owner_ids)),
                },
            )
        destination_evidence = proof.destinations[0]
        destination = _unique_plan_block(
            plan,
            destination_evidence.target_identity,
            destination_evidence.target_anchor_ea,
            roles=frozenset(
                {
                    FragmentBlockRole.EXTERNAL,
                    FragmentBlockRole.IMPORTED,
                    FragmentBlockRole.REPLACEMENT,
                }
            ),
            description="nested canonical state-route destination",
        )
        if (
            destination.role is FragmentBlockRole.IMPORTED
            and destination.native_body_id != source.native_body_id
        ):
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state route crosses native-body ownership",
                reason_code="nested_state_route_native_body_mismatch",
                anchor_ea=int(proof.source_anchor_ea),
                payload={"route_proof_id": proof.proof_id},
            )
        existing_proof_id = claimed_source_ids.setdefault(
            source.block_id,
            proof.proof_id,
        )
        if existing_proof_id != proof.proof_id:
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state routes compete for one imported source",
                reason_code="nested_state_route_source_conflict",
                anchor_ea=int(proof.source_anchor_ea),
                payload={
                    "route_proof_ids": (
                        existing_proof_id,
                        proof.proof_id,
                    ),
                    "source_block_id": source.block_id,
                },
            )
        for corridor_block_id in dict.fromkeys(corridor_owner_ids):
            existing_corridor_proof_id = claimed_corridor_ids.setdefault(
                corridor_block_id,
                proof.proof_id,
            )
            if existing_corridor_proof_id != proof.proof_id:
                raise CanonicalSemanticFragmentRejected(
                    "nested canonical state routes overlap one imported corridor",
                    reason_code="nested_state_route_corridor_conflict",
                    anchor_ea=int(proof.source_anchor_ea),
                    payload={
                        "route_proof_ids": (
                            existing_corridor_proof_id,
                            proof.proof_id,
                        ),
                        "corridor_block_id": corridor_block_id,
                    },
                )
        replacements.append(
            (
                proof,
                source,
                source_operations[0],
                destination,
            )
        )
        decisions.append(
            _NestedStateRouteProjectionDecision(
                route_proof_id=proof.proof_id,
                source_anchor_ea=int(proof.source_anchor_ea),
                disposition="projected",
                reason="semantic_route_projected",
                projection_round=int(projection_round),
                source_block_ids=(source.block_id,),
                corridor_block_ids=tuple(dict.fromkeys(corridor_owner_ids)),
            )
        )

    if not replacements:
        return plan, (), tuple(decisions)

    replacement_by_operation_id = {
        raw_operation.operation_id: FragmentOperation(
            operation_id=f"route:{proof.proof_id}",
            source_block_id=source.block_id,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target_block_id=destination.block_id,
                ),
            ),
        )
        for proof, source, raw_operation, destination in replacements
    }
    raw_operation_ids = frozenset(replacement_by_operation_id)
    proof_ids_by_body: dict[str, list[str]] = {}
    source_ids_by_body: dict[str, set[str]] = {}
    for proof, source, _raw_operation, _destination in replacements:
        if source.native_body_id is None:
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state route lacks native-body ownership"
            )
        proof_ids_by_body.setdefault(
            source.native_body_id,
            [],
        ).append(proof.proof_id)
        source_ids_by_body.setdefault(
            source.native_body_id,
            set(),
        ).add(source.block_id)

    return (
        replace(
            plan,
            operations=tuple(
                replacement_by_operation_id.get(
                    operation.operation_id,
                    operation,
                )
                for operation in plan.operations
            ),
            native_bodies=tuple(
                replace(
                    body,
                    terminal_block_ids=tuple(
                        block_id
                        for block_id in body.terminal_block_ids
                        if block_id not in source_ids_by_body.get(body.body_id, set())
                    ),
                    proof_ids=tuple(
                        dict.fromkeys(
                            (
                                *(
                                    proof_id
                                    for proof_id in body.proof_ids
                                    if proof_id not in raw_operation_ids
                                ),
                                *proof_ids_by_body.get(body.body_id, ()),
                            )
                        )
                    ),
                )
                if body.body_id in proof_ids_by_body
                else body
                for body in plan.native_bodies
            ),
        ),
        tuple(proof for proof, *_rest in replacements),
        tuple(decisions),
    )


def _call_backed_nested_route_staging_requirements(
    plan: FragmentPlan,
    available_evidence: CanonicalSemanticEvidence,
    *,
    native_body_id: str,
    excluded_proof_ids: frozenset[str],
) -> tuple[_CallBackedNestedRouteStaging, ...]:
    """Keep only exact call-backed route corridors detached until projection."""
    imported_blocks = tuple(
        block
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
        and block.native_body_id == native_body_id
        and block.stable_identity is not None
    )
    operation_by_source: dict[str, list[FragmentOperation]] = {}
    for operation in plan.operations:
        operation_by_source.setdefault(operation.source_block_id, []).append(operation)

    requirements: list[_CallBackedNestedRouteStaging] = []
    for proof in available_evidence.route_proofs:
        state_write = proof.state_write
        if (
            proof.proof_id in excluded_proof_ids
            or proof.proof_kind is not SemanticRouteProofKind.STATE_ASSIGNMENT
            or proof.shape is not SemanticRouteShape.DIRECT
            or state_write is None
            or state_write.authority_transfer_ea is None
        ):
            continue
        source_matches = tuple(
            block
            for block in imported_blocks
            if block.stable_identity is not None
            and block.stable_identity.native_ranges.contains(proof.source_anchor_ea)
            and _identity_ranges_contain(
                block.stable_identity,
                proof.source_identity,
            )
        )
        if not source_matches:
            continue
        if len(source_matches) != 1:
            raise CanonicalSemanticFragmentRejected(
                "call-backed nested route has multiple imported delivery owners",
                reason_code="call_backed_route_source_owner_ambiguous",
                anchor_ea=int(proof.source_anchor_ea),
                payload={
                    "route_proof_id": proof.proof_id,
                    "source_block_ids": tuple(
                        block.block_id for block in source_matches
                    ),
                },
            )
        (source,) = source_matches
        source_operations = tuple(operation_by_source.get(source.block_id, ()))
        normalization = (
            None
            if len(source_operations) != 1
            else source_operations[0].computed_branch_normalization
        )
        if (
            normalization is None
            or int(normalization.normalization_start_ea) != int(proof.source_anchor_ea)
            or int(normalization.unresolved_transfer_ea)
            != int(state_write.authority_transfer_ea)
        ):
            raise CanonicalSemanticFragmentRejected(
                "call-backed nested route does not own its normalized transfer",
                reason_code="call_backed_route_transfer_authority_mismatch",
                anchor_ea=int(state_write.authority_transfer_ea),
                payload={
                    "route_proof_id": proof.proof_id,
                    "source_block_id": source.block_id,
                    "operation_ids": tuple(
                        operation.operation_id for operation in source_operations
                    ),
                    "expected_normalization_start_ea": (
                        f"0x{int(proof.source_anchor_ea):X}"
                    ),
                    "expected_authority_transfer_ea": (
                        f"0x{int(state_write.authority_transfer_ea):X}"
                    ),
                },
            )

        corridor_owner_by_ea: dict[int, FragmentBlock] = {}
        for corridor_ea in state_write.corridor_instruction_eas:
            owners = tuple(
                block
                for block in imported_blocks
                if block.stable_identity is not None
                and block.stable_identity.native_ranges.contains(corridor_ea)
            )
            if len(owners) != 1:
                raise CanonicalSemanticFragmentRejected(
                    "call-backed nested route corridor lacks one imported owner",
                    reason_code="call_backed_route_corridor_owner_mismatch",
                    anchor_ea=int(corridor_ea),
                    payload={
                        "route_proof_id": proof.proof_id,
                        "owner_block_ids": tuple(block.block_id for block in owners),
                    },
                )
            corridor_owner_by_ea[int(corridor_ea)] = owners[0]
        corridor_owner_ids = tuple(
            corridor_owner_by_ea[int(corridor_ea)].block_id
            for corridor_ea in state_write.corridor_instruction_eas
        )
        ordered_owner_ids = tuple(
            owner_id
            for index, owner_id in enumerate(corridor_owner_ids)
            if index == 0 or owner_id != corridor_owner_ids[index - 1]
        )
        state_write_owner = corridor_owner_by_ea[int(state_write.instruction_ea)]
        if (
            not ordered_owner_ids
            or ordered_owner_ids[-1] != source.block_id
            or len(ordered_owner_ids) != len(set(ordered_owner_ids))
            or state_write_owner.stable_identity is None
            or not _identity_ranges_contain(
                state_write_owner.stable_identity,
                state_write.identity,
            )
        ):
            raise CanonicalSemanticFragmentRejected(
                "call-backed nested route corridor is not an ordered delivery path",
                reason_code="call_backed_route_corridor_order_mismatch",
                anchor_ea=int(state_write.instruction_ea),
                payload={
                    "route_proof_id": proof.proof_id,
                    "corridor_block_ids": ordered_owner_ids,
                    "source_block_id": source.block_id,
                },
            )
        for call_ea in state_write.preserved_call_instruction_eas:
            call_owner = corridor_owner_by_ea[int(call_ea)]
            call_operations = tuple(operation_by_source.get(call_owner.block_id, ()))
            call_owner_index = ordered_owner_ids.index(call_owner.block_id)
            expected_successor_id = (
                None
                if call_owner_index + 1 == len(ordered_owner_ids)
                else ordered_owner_ids[call_owner_index + 1]
            )
            if (
                len(call_operations) != 1
                or expected_successor_id is None
                or tuple(edge.role for edge in call_operations[0].edges)
                != (SemanticEdgeRole.CALL_FALLTHROUGH,)
                or call_operations[0].edges[0].target_block_id != expected_successor_id
            ):
                raise CanonicalSemanticFragmentRejected(
                    "call-backed nested route does not preserve its call edge",
                    reason_code="call_backed_route_call_edge_mismatch",
                    anchor_ea=int(call_ea),
                    payload={
                        "route_proof_id": proof.proof_id,
                        "call_owner_block_id": call_owner.block_id,
                        "expected_successor_block_id": expected_successor_id,
                        "operation_ids": tuple(
                            operation.operation_id for operation in call_operations
                        ),
                    },
                )
        required_exact_eas_by_block_id: dict[str, set[int]] = {}
        for corridor_ea, owner in corridor_owner_by_ea.items():
            required_exact_eas_by_block_id.setdefault(owner.block_id, set()).add(
                int(corridor_ea)
            )
        requirements.append(
            _CallBackedNestedRouteStaging(
                route_proof_id=proof.proof_id,
                block_ids=frozenset(required_exact_eas_by_block_id),
                exact_instruction_eas_by_block_id={
                    block_id: frozenset(exact_eas)
                    for block_id, exact_eas in (required_exact_eas_by_block_id.items())
                },
            )
        )

    return tuple(requirements)


def _nested_terminal_effects(
    blocks: tuple[FragmentBlock, ...],
    operations: tuple[FragmentOperation, ...],
    proofs: tuple[SemanticRouteProof, ...],
) -> tuple[
    tuple[FragmentReturnCarrier, ...],
    tuple[FragmentTerminalReturn, ...],
    tuple[FragmentTerminalRoute, ...],
]:
    """Project terminal carrier, return, and route as one detached fragment."""
    block_by_id = {block.block_id: block for block in blocks}
    operation_by_id = {operation.operation_id: operation for operation in operations}
    return_carriers: list[FragmentReturnCarrier] = []
    terminal_returns: list[FragmentTerminalReturn] = []
    terminal_routes: list[FragmentTerminalRoute] = []
    return_by_block_id: dict[str, FragmentTerminalReturn] = {}
    for proof in proofs:
        if proof.proof_kind is not SemanticRouteProofKind.TERMINAL_RETURN:
            continue
        carrier = proof.terminal_return_carrier
        operation_id = f"route:{proof.proof_id}"
        operation = operation_by_id.get(operation_id)
        if (
            carrier is None
            or operation is None
            or len(operation.edges) != 1
            or operation.edges[0].role is not SemanticEdgeRole.DIRECT
        ):
            raise CanonicalSemanticFragmentRejected(
                "nested terminal route lacks one complete direct operation",
                reason_code="nested_terminal_route_operation_missing",
                anchor_ea=int(proof.source_anchor_ea),
                payload={"route_proof_id": proof.proof_id},
            )
        source = block_by_id.get(operation.source_block_id)
        destination = block_by_id.get(operation.edges[0].target_block_id)
        if (
            source is None
            or destination is None
            or source.role
            not in {
                FragmentBlockRole.IMPORTED,
                FragmentBlockRole.REPLACEMENT,
            }
            or destination.role
            not in {
                FragmentBlockRole.IMPORTED,
                FragmentBlockRole.REPLACEMENT,
            }
        ):
            raise CanonicalSemanticFragmentRejected(
                "nested terminal route is not wholly staged",
                reason_code="nested_terminal_route_staged_owner_missing",
                anchor_ea=int(proof.source_anchor_ea),
                payload={
                    "route_proof_id": proof.proof_id,
                    "operation_id": operation.operation_id,
                    "source_block_id": (None if source is None else source.block_id),
                    "source_role": (None if source is None else source.role.value),
                    "source_identity": (
                        None
                        if source is None
                        else source.stable_identity.diagnostic_label()
                    ),
                    "destination_block_id": (
                        None if destination is None else destination.block_id
                    ),
                    "destination_role": (
                        None if destination is None else destination.role.value
                    ),
                    "destination_identity": (
                        None
                        if destination is None
                        else destination.stable_identity.diagnostic_label()
                    ),
                    "target_block_id": operation.edges[0].target_block_id,
                },
            )
        carrier_id = f"return-carrier:{proof.proof_id}"
        return_carriers.append(
            FragmentReturnCarrier(
                carrier_id=carrier_id,
                block_id=source.block_id,
                state_write_ea=int(carrier.state_write_ea),
                carrier_ea=int(carrier.carrier_ea),
                operation=carrier.operation,
                source=FragmentReturnSource(
                    kind=FragmentReturnSourceKind(carrier.source.kind.value),
                    width=int(carrier.source.width),
                    storage_identity=carrier.source.storage_identity,
                    constant=carrier.source.constant,
                ),
                return_width=int(carrier.return_width),
                corridor_instruction_eas=tuple(
                    int(ea) for ea in carrier.corridor_instruction_eas
                ),
            )
        )
        terminal_return = return_by_block_id.get(destination.block_id)
        if terminal_return is None:
            terminal_return = FragmentTerminalReturn(
                return_id=(
                    f"terminal-return:0x{int(carrier.request.terminal_target_ea):X}"
                ),
                block_id=destination.block_id,
                instruction_ea=int(carrier.terminal_return_ea),
                return_width=int(carrier.return_width),
            )
            return_by_block_id[destination.block_id] = terminal_return
            terminal_returns.append(terminal_return)
        elif terminal_return.instruction_ea != int(
            carrier.terminal_return_ea
        ) or terminal_return.return_width != int(carrier.return_width):
            raise CanonicalSemanticFragmentRejected(
                "nested terminal routes disagree on their shared return",
                reason_code="nested_terminal_return_conflict",
                anchor_ea=int(carrier.request.terminal_target_ea),
                payload={"route_proof_id": proof.proof_id},
            )
        terminal_routes.append(
            FragmentTerminalRoute(
                terminal_route_id=f"terminal-route:{proof.proof_id}",
                operation_id=operation_id,
                carrier_id=carrier_id,
                return_id=terminal_return.return_id,
            )
        )
    return tuple(return_carriers), tuple(terminal_returns), tuple(terminal_routes)


def _resolved_detached_target_component(
    graph: FlowGraph,
    normalization_plan: FragmentPlan,
    target: FragmentBlock,
    available_evidence: CanonicalSemanticEvidence,
    *,
    canonical_proof_ids: tuple[str, ...],
    excluded_proof_ids: frozenset[str],
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
    normalization_authority: NormalizationWorkItemAuthority,
    prohibited_dispatcher_serials: frozenset[int],
    replaced_current_owner_serials: frozenset[int],
) -> tuple[
    tuple[FragmentBlock, ...],
    tuple[FragmentOperation, ...],
    FragmentNativeBody,
    tuple[SemanticRouteProof, ...],
    tuple[_NestedStateRouteProjectionDecision, ...],
    tuple[FragmentReturnCarrier, ...],
    tuple[FragmentTerminalReturn, ...],
    tuple[FragmentTerminalRoute, ...],
]:
    """Resolve every nested state route before exposing one target component."""
    target_native_body_id = target.native_body_id
    if target_native_body_id is None:
        raise CanonicalSemanticFragmentRejected(
            "detached canonical target lacks native-body ownership"
        )
    call_backed_staging_requirements = _call_backed_nested_route_staging_requirements(
        normalization_plan,
        available_evidence,
        native_body_id=target_native_body_id,
        excluded_proof_ids=excluded_proof_ids,
    )
    provisional_required_staged_ids = frozenset(
        block_id
        for requirement in call_backed_staging_requirements
        for block_id in requirement.block_ids
    )
    effective_normalization_plan = normalization_plan
    selected_proof_ids = set(excluded_proof_ids)
    nested_route_proof_list: list[SemanticRouteProof] = []
    nested_decision_by_proof_id: dict[
        str,
        _NestedStateRouteProjectionDecision,
    ] = {}
    claimed_nested_source_ids: dict[str, str] = {}
    claimed_nested_corridor_ids: dict[str, str] = {}
    projection_round_limit = len(available_evidence.route_proofs) + 1
    for projection_round in range(1, projection_round_limit + 1):
        provisional_target_blocks, _operations, _native_body = (
            _detached_target_component(
                graph,
                effective_normalization_plan,
                target,
                current_identity_by_serial=current_identity_by_serial,
                canonical_proof_id="+".join(
                    (
                        *canonical_proof_ids,
                        *(item.proof_id for item in nested_route_proof_list),
                    )
                ),
                normalization_authority=normalization_authority,
                allow_unresolved_published_boundaries=True,
                prohibited_dispatcher_serials=prohibited_dispatcher_serials,
                replaced_current_owner_serials=replaced_current_owner_serials,
                required_staged_destination_ids=(provisional_required_staged_ids),
                required_exact_instruction_eas_by_block_id={},
            )
        )
        (
            projected_plan,
            projected_proofs,
            projection_decisions,
        ) = _with_nested_imported_state_routes(
            effective_normalization_plan,
            available_evidence,
            component_block_ids=frozenset(
                block.block_id for block in provisional_target_blocks
            ),
            excluded_proof_ids=frozenset(selected_proof_ids),
            projection_round=int(projection_round),
            claimed_source_proof_ids=claimed_nested_source_ids,
            claimed_corridor_proof_ids=claimed_nested_corridor_ids,
        )
        for decision in projection_decisions:
            nested_decision_by_proof_id[decision.route_proof_id] = decision
        if not projected_proofs:
            break
        projected_proof_ids = tuple(item.proof_id for item in projected_proofs)
        if (
            len(set(projected_proof_ids)) != len(projected_proof_ids)
            or set(projected_proof_ids).intersection(selected_proof_ids)
            or projected_plan == effective_normalization_plan
        ):
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state-route projection made no monotonic progress",
                reason_code="nested_state_route_projection_no_progress",
                anchor_ea=int(target.semantic_anchor_ea),
                payload={"route_proof_ids": projected_proof_ids},
            )
        projected_decision_by_proof_id = {
            decision.route_proof_id: decision
            for decision in projection_decisions
            if decision.disposition == "projected"
        }
        if set(projected_decision_by_proof_id) != set(projected_proof_ids):
            raise CanonicalSemanticFragmentRejected(
                "nested canonical state-route projection lost its ownership proof",
                reason_code="nested_state_route_projection_receipt_mismatch",
                anchor_ea=int(target.semantic_anchor_ea),
                payload={"route_proof_ids": projected_proof_ids},
            )
        for projected_proof in projected_proofs:
            decision = projected_decision_by_proof_id[projected_proof.proof_id]
            if len(decision.source_block_ids) != 1 or not decision.corridor_block_ids:
                raise CanonicalSemanticFragmentRejected(
                    "nested canonical state-route projection lacks owned topology",
                    reason_code="nested_state_route_projection_ownership_missing",
                    anchor_ea=int(projected_proof.source_anchor_ea),
                    payload={"route_proof_id": projected_proof.proof_id},
                )
            claimed_nested_source_ids[decision.source_block_ids[0]] = (
                projected_proof.proof_id
            )
            for corridor_block_id in decision.corridor_block_ids:
                claimed_nested_corridor_ids[corridor_block_id] = (
                    projected_proof.proof_id
                )
        effective_normalization_plan = projected_plan
        nested_route_proof_list.extend(projected_proofs)
        selected_proof_ids.update(projected_proof_ids)
    else:
        raise CanonicalSemanticFragmentRejected(
            "nested canonical state-route projection exceeded its proof bound",
            reason_code="nested_state_route_projection_bound_exceeded",
            anchor_ea=int(target.semantic_anchor_ea),
        )
    nested_route_proofs = tuple(nested_route_proof_list)
    nested_route_decisions = tuple(
        nested_decision_by_proof_id[item.proof_id]
        for item in available_evidence.route_proofs
        if item.proof_id in nested_decision_by_proof_id
    )
    try:
        nested_route_proof_ids = frozenset(
            proof.proof_id for proof in nested_route_proofs
        )
        selected_call_backed_requirements = tuple(
            requirement
            for requirement in call_backed_staging_requirements
            if requirement.route_proof_id in nested_route_proof_ids
        )
        required_staged_destination_ids: set[str] = {
            block_id
            for requirement in selected_call_backed_requirements
            for block_id in requirement.block_ids
        }
        required_exact_instruction_eas_by_block_id: dict[str, set[int]] = {}
        for requirement in selected_call_backed_requirements:
            for (
                block_id,
                exact_instruction_eas,
            ) in requirement.exact_instruction_eas_by_block_id.items():
                required_exact_instruction_eas_by_block_id.setdefault(
                    block_id,
                    set(),
                ).update(int(ea) for ea in exact_instruction_eas)
        operation_by_id = {
            operation.operation_id: operation
            for operation in effective_normalization_plan.operations
        }
        for proof in nested_route_proofs:
            if proof.proof_kind is not SemanticRouteProofKind.TERMINAL_RETURN:
                continue
            carrier = proof.terminal_return_carrier
            operation = operation_by_id.get(f"route:{proof.proof_id}")
            if carrier is None or operation is None:
                raise CanonicalSemanticFragmentRejected(
                    "nested terminal proof lacks its staged operation or carrier",
                    reason_code="nested_terminal_route_operation_missing",
                    anchor_ea=int(proof.source_anchor_ea),
                    payload={"route_proof_id": proof.proof_id},
                )
            required_exact_instruction_eas_by_block_id.setdefault(
                operation.source_block_id,
                set(),
            ).update(int(ea) for ea in carrier.corridor_instruction_eas)
            for destination in proof.destinations:
                destination_block = _unique_plan_block(
                    effective_normalization_plan,
                    destination.target_identity,
                    destination.target_anchor_ea,
                    roles=frozenset(
                        {
                            FragmentBlockRole.EXTERNAL,
                            FragmentBlockRole.IMPORTED,
                            FragmentBlockRole.REPLACEMENT,
                        }
                    ),
                    description="nested terminal destination",
                )
                required_staged_destination_ids.add(destination_block.block_id)
                required_exact_instruction_eas_by_block_id.setdefault(
                    destination_block.block_id,
                    set(),
                ).add(int(carrier.terminal_return_ea))
        target_blocks, target_operations, native_body = _detached_target_component(
            graph,
            effective_normalization_plan,
            target,
            current_identity_by_serial=current_identity_by_serial,
            canonical_proof_id="+".join(
                (
                    *canonical_proof_ids,
                    *(item.proof_id for item in nested_route_proofs),
                )
            ),
            normalization_authority=normalization_authority,
            allow_unresolved_published_boundaries=False,
            prohibited_dispatcher_serials=prohibited_dispatcher_serials,
            replaced_current_owner_serials=replaced_current_owner_serials,
            required_staged_destination_ids=frozenset(required_staged_destination_ids),
            required_exact_instruction_eas_by_block_id={
                block_id: frozenset(exact_instruction_eas)
                for block_id, exact_instruction_eas in (
                    required_exact_instruction_eas_by_block_id.items()
                )
            },
        )
    except CanonicalSemanticFragmentRejected as exc:
        if not nested_route_decisions:
            raise
        raise CanonicalSemanticFragmentRejected(
            str(exc),
            reason_code=exc.reason_code,
            anchor_ea=exc.anchor_ea,
            payload={
                **exc.payload,
                "nested_state_route_projection": tuple(
                    decision.diagnostic_payload() for decision in nested_route_decisions
                ),
            },
        ) from exc
    nested_rewrite_by_operation_id = {
        f"route:{item.proof_id}": _direct_transfer_rewrite(item)
        for item in nested_route_proofs
    }
    target_operations = tuple(
        replace(
            operation,
            direct_transfer_rewrite=nested_rewrite_by_operation_id[
                operation.operation_id
            ],
        )
        if operation.operation_id in nested_rewrite_by_operation_id
        else operation
        for operation in target_operations
    )
    return_carriers, terminal_returns, terminal_routes = _nested_terminal_effects(
        target_blocks,
        target_operations,
        nested_route_proofs,
    )
    return (
        target_blocks,
        target_operations,
        native_body,
        nested_route_proofs,
        nested_route_decisions,
        return_carriers,
        terminal_returns,
        terminal_routes,
    )


def compose_canonical_semantic_fragment_plan(
    graph: FlowGraph,
    normalization_plan: FragmentPlan,
    evidence: CanonicalSemanticEvidence,
    *,
    available_evidence: CanonicalSemanticEvidence,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
    normalization_authority: NormalizationWorkItemAuthority,
    prohibited_dispatcher_serials: Iterable[int] = (),
) -> FragmentPlan:
    """Compose one live canonical route with one unpublished native target body."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("canonical composition requires a FlowGraph")
    if not isinstance(normalization_plan, FragmentPlan):
        raise TypeError("canonical composition requires a normalization plan")
    if (
        normalization_plan.publication_purpose
        is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition requires frontend-normalization intent"
        )
    if not isinstance(evidence, CanonicalSemanticEvidence):
        raise TypeError("canonical composition requires canonical evidence")
    if not isinstance(available_evidence, CanonicalSemanticEvidence):
        raise TypeError("canonical composition available evidence must be canonical")
    if (
        available_evidence.native_key != evidence.native_key
        or available_evidence.generation != evidence.generation
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition available evidence generation drifted",
            reason_code="canonical_available_evidence_generation_drift",
            anchor_ea=int(graph.func_ea),
            payload={
                "work_item_generation": int(evidence.generation),
                "available_generation": int(available_evidence.generation),
            },
        )
    current_identity_by_serial = {
        int(serial): identity for serial, identity in current_identity_by_serial.items()
    }
    all_prohibited_serials = tuple(
        dict.fromkeys(int(value) for value in prohibited_dispatcher_serials)
    )
    prohibited_serial_set = frozenset(all_prohibited_serials)
    if any(
        not isinstance(identity, StableBlockIdentity)
        for identity in current_identity_by_serial.values()
    ):
        raise TypeError("canonical composition current identity authority is invalid")
    unknown_serials = frozenset(current_identity_by_serial).difference(
        int(serial) for serial in graph.blocks
    )
    if unknown_serials:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition current identity authority is stale",
            reason_code="current_identity_authority_stale",
            anchor_ea=int(graph.func_ea),
            payload={"unknown_serials": tuple(sorted(unknown_serials))},
        )
    if any(
        identity.native_key != evidence.native_key
        for identity in current_identity_by_serial.values()
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition current identity authority drifted",
            reason_code="current_identity_authority_native_key_drift",
            anchor_ea=int(graph.func_ea),
        )
    if evidence.native_key != normalization_plan.native_key:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition native authority does not match"
        )
    if not isinstance(
        normalization_authority,
        NormalizationWorkItemAuthority,
    ):
        raise TypeError(
            "canonical composition requires normalization work-item authority"
        )
    if (
        normalization_authority.evidence_generation != evidence.generation
        or normalization_authority.source_plan_id != normalization_plan.plan_id
        or normalization_authority.source_atomic_group_id
        != normalization_plan.atomic_group_id
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition normalization authority drifted",
            reason_code="normalization_work_item_authority_drift",
            anchor_ea=int(graph.func_ea),
            payload={
                "authority_generation": (normalization_authority.evidence_generation),
                "evidence_generation": int(evidence.generation),
                "source_plan_id": normalization_authority.source_plan_id,
            },
        )
    proof, imported_consumer = _canonical_composition_proofs(evidence)
    effective_normalization_plan = (
        normalization_plan
        if imported_consumer is None
        else _with_semantic_imported_consumer(
            normalization_plan,
            imported_consumer,
        )
    )

    source = _unique_plan_block(
        effective_normalization_plan,
        proof.source_identity,
        proof.source_anchor_ea,
        roles=frozenset({FragmentBlockRole.EXTERNAL}),
        description="canonical route source",
    )
    retained_source_identity = source.stable_identity
    if retained_source_identity is None:
        raise CanonicalSemanticFragmentRejected(
            "canonical route source lacks stable identity"
        )
    state_write = proof.state_write
    if (
        not _identity_contains(retained_source_identity, state_write.identity)
        or state_write.instruction_ea
        not in retained_source_identity.exact_instruction_eas
        or state_write.corridor_instruction_eas[-1] != int(proof.source_anchor_ea)
        or any(
            ea not in retained_source_identity.exact_instruction_eas
            for ea in state_write.corridor_instruction_eas
        )
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical state-write corridor is not owned by its live source"
        )
    source_serial, source_identity = _current_route_source(
        graph,
        current_identity_by_serial=current_identity_by_serial,
        retained_identity=retained_source_identity,
        state_write_identity=state_write.identity,
        state_write_ea=state_write.instruction_ea,
        delivery_ea=proof.source_anchor_ea,
        corridor_instruction_eas=state_write.corridor_instruction_eas,
    )
    source_anchor_ea = int(state_write.instruction_ea)
    (destination,) = proof.destinations
    target = _unique_plan_block(
        effective_normalization_plan,
        destination.target_identity,
        destination.target_anchor_ea,
        roles=frozenset({FragmentBlockRole.IMPORTED}),
        description="canonical route target",
    )
    (
        target_blocks,
        target_operations,
        native_body,
        _nested_route_proofs,
        _nested_route_decisions,
        nested_return_carriers,
        nested_terminal_returns,
        nested_terminal_routes,
    ) = _resolved_detached_target_component(
        graph,
        effective_normalization_plan,
        target,
        available_evidence,
        canonical_proof_ids=tuple(item.proof_id for item in evidence.route_proofs),
        excluded_proof_ids=frozenset(item.proof_id for item in evidence.route_proofs),
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=normalization_authority,
        prohibited_dispatcher_serials=prohibited_serial_set,
        replaced_current_owner_serials=frozenset(),
    )
    if imported_consumer is not None:
        predicate = imported_consumer.predicate
        operation_id = f"route:{imported_consumer.proof_id}"
        matching_operations = tuple(
            operation
            for operation in target_operations
            if operation.operation_id == operation_id
        )
        if (
            predicate is None
            or predicate.kind is not SemanticPredicateKind.STORAGE_EQUALS
            or predicate.storage_identity is None
            or predicate.compare_constant is None
            or len(matching_operations) != 1
        ):
            raise CanonicalSemanticFragmentRejected(
                "canonical imported semantic consumer lacks one complete "
                "storage predicate operation"
            )
        target_operations = tuple(
            (
                replace(
                    operation,
                    storage_predicate_materialization=(
                        FragmentStoragePredicateMaterialization(
                            predicate_kind=PredicateKind.EQ,
                            storage_identity=predicate.storage_identity,
                            width=int(predicate.width),
                            compare_constant=int(predicate.compare_constant),
                            cut_after_ea=int(imported_consumer.source_anchor_ea),
                        )
                    ),
                )
                if operation.operation_id == operation_id
                else operation
            )
            for operation in target_operations
        )
    target_external_blocks = tuple(
        block for block in target_blocks if block.role is FragmentBlockRole.EXTERNAL
    )
    target_imported_blocks = tuple(
        block for block in target_blocks if block.role is FragmentBlockRole.IMPORTED
    )
    if len(target_external_blocks) + len(target_imported_blocks) != len(target_blocks):
        raise CanonicalSemanticFragmentRejected(
            "detached canonical target projection retained an unpublished block"
        )

    original_id = f"route:{proof.proof_id}:original"
    replacement_id = f"route:{proof.proof_id}:replacement"
    blocks: list[FragmentBlock] = list(target_external_blocks)
    external_id_by_serial: dict[int, str] = {}
    external_owner_serial_by_identity: dict[StableBlockIdentity, int] = {}
    for boundary in target_external_blocks:
        identity = boundary.stable_identity
        if identity is None:
            raise CanonicalSemanticFragmentRejected(
                "projected canonical boundary lacks stable identity"
            )
        current_owners = _current_owners_contained_by_identity(
            graph,
            identity,
            current_identity_by_serial=current_identity_by_serial,
        )
        if len(current_owners) > 1:
            raise CanonicalSemanticFragmentRejected(
                "projected canonical boundary has multiple current owners",
                reason_code="projected_boundary_current_owner_ambiguous",
                anchor_ea=int(boundary.semantic_anchor_ea),
                payload={
                    "boundary_block_id": boundary.block_id,
                    "current_owner_labels": tuple(
                        f"blk{serial}@0x{anchor_ea:X}"
                        for serial, anchor_ea in current_owners
                    ),
                    "stable_identity": identity.diagnostic_label(),
                },
            )
        if not current_owners:
            continue
        ((owner_serial, owner_anchor_ea),) = current_owners
        existing_boundary_id = external_id_by_serial.get(owner_serial)
        if (
            existing_boundary_id is not None
            and existing_boundary_id != boundary.block_id
        ):
            raise CanonicalSemanticFragmentRejected(
                "projected canonical boundaries share one current owner",
                reason_code="projected_boundary_current_owner_alias",
                anchor_ea=int(boundary.semantic_anchor_ea),
                payload={
                    "candidate_block_id": boundary.block_id,
                    "existing_block_id": existing_boundary_id,
                    "current_owner": (f"blk{owner_serial}@0x{owner_anchor_ea:X}"),
                },
            )
        _claim_current_external_identity(
            owner_serial,
            identity,
            owner_serial_by_identity=external_owner_serial_by_identity,
        )
        external_id_by_serial[owner_serial] = boundary.block_id

    def external_block_id(serial: int) -> str:
        serial = int(serial)
        existing = external_id_by_serial.get(serial)
        if existing is not None:
            return existing
        block = graph.blocks.get(serial)
        if block is None:
            raise CanonicalSemanticFragmentRejected(
                f"canonical composition references absent block {serial}"
            )
        identity = current_identity_by_serial.get(serial)
        if identity is None:
            raise CanonicalSemanticFragmentRejected(
                "canonical fragment external block lacks current identity authority",
                reason_code="current_external_identity_missing",
                anchor_ea=int(block.start_ea),
                payload={
                    "block": f"blk{serial}@0x{int(block.start_ea):X}",
                },
            )
        _claim_current_external_identity(
            serial,
            identity,
            owner_serial_by_identity=(external_owner_serial_by_identity),
        )
        semantic_anchor_ea = stable_block_identity_semantic_anchor(identity)
        block_id = f"native[{stable_block_identity_token(identity)}]"
        existing_block = next(
            (item for item in blocks if item.block_id == block_id),
            None,
        )
        if existing_block is not None:
            if (
                existing_block.role is not FragmentBlockRole.EXTERNAL
                or existing_block.stable_identity != identity
            ):
                raise CanonicalSemanticFragmentRejected(
                    "canonical external identity conflicts with target boundary",
                    reason_code="external_identity_conflict",
                    anchor_ea=semantic_anchor_ea,
                    payload={
                        "block_id": block_id,
                        "current_owner": (f"blk{serial}@0x{semantic_anchor_ea:X}"),
                    },
                )
            external_id_by_serial[serial] = block_id
            return block_id
        blocks.append(
            FragmentBlock(
                block_id=block_id,
                role=FragmentBlockRole.EXTERNAL,
                materialization=(FragmentBlockMaterialization.REUSE_PUBLISHED),
                semantic_anchor_ea=semantic_anchor_ea,
                stable_identity=identity,
            )
        )
        external_id_by_serial[serial] = block_id
        return block_id

    blocks.extend(
        (
            FragmentBlock(
                block_id=original_id,
                role=FragmentBlockRole.ORIGINAL,
                materialization=(FragmentBlockMaterialization.REUSE_PUBLISHED),
                semantic_anchor_ea=source_anchor_ea,
                stable_identity=source_identity,
            ),
            FragmentBlock(
                block_id=replacement_id,
                role=FragmentBlockRole.REPLACEMENT,
                materialization=(FragmentBlockMaterialization.CLONE_PUBLISHED),
                semantic_anchor_ea=source_anchor_ea,
                stable_identity=source_identity,
                replaces_block_id=original_id,
            ),
            *target_imported_blocks,
        )
    )

    def semantic_point_block_id(point: SemanticCorridorPoint) -> str:
        candidates = tuple(
            block
            for block in blocks
            if block.role is not FragmentBlockRole.ORIGINAL
            and block.stable_identity is not None
            and stable_block_identities_refine_at_anchor(
                block.stable_identity,
                point.identity,
                point.anchor_ea,
            )
        )
        if len(candidates) == 1:
            return candidates[0].block_id
        if candidates:
            raise CanonicalSemanticFragmentRejected(
                "canonical semantic corridor has multiple projected owners",
                reason_code="projected_semantic_corridor_owner_ambiguous",
                anchor_ea=int(point.anchor_ea),
                payload={
                    "candidate_block_ids": tuple(
                        block.block_id for block in candidates
                    ),
                },
            )
        current_owners = tuple(
            int(serial)
            for serial, identity in current_identity_by_serial.items()
            if stable_block_identities_refine_at_anchor(
                identity,
                point.identity,
                point.anchor_ea,
            )
        )
        if len(current_owners) != 1:
            raise CanonicalSemanticFragmentRejected(
                "canonical semantic corridor requires one current or staged owner",
                reason_code="semantic_corridor_owner_count_mismatch",
                anchor_ea=int(point.anchor_ea),
                payload={
                    "owner_labels": tuple(
                        (f"blk{serial}@0x{int(graph.blocks[serial].start_ea):X}")
                        for serial in current_owners
                    ),
                },
            )
        return external_block_id(current_owners[0])

    data_flow_obligations: list[FragmentDataFlowObligation] = []
    if imported_consumer is not None:
        predicate = imported_consumer.predicate
        if (
            predicate is None
            or predicate.kind is not SemanticPredicateKind.STORAGE_EQUALS
            or predicate.storage_identity is None
        ):
            raise CanonicalSemanticFragmentRejected(
                "canonical imported consumer lacks one portable storage predicate"
            )
        for point in predicate.corridor:
            semantic_point_block_id(point)
        predicate_value_id = f"predicate:{imported_consumer.proof_id}"
        data_flow_obligations.append(
            FragmentDataFlowObligation(
                obligation_id=f"{predicate_value_id}:use-def",
                role=FragmentDataFlowRole.CONDITION,
                definition=FragmentValueSite(
                    site_id=f"{predicate_value_id}:definition",
                    block_id=semantic_point_block_id(predicate.origin),
                    value_id=predicate_value_id,
                    instruction_ea=int(predicate.origin.anchor_ea),
                    storage_identity=predicate.storage_identity,
                    width=int(predicate.width),
                ),
                uses=(
                    FragmentValueSite(
                        site_id=f"{predicate_value_id}:consumer",
                        block_id=semantic_point_block_id(predicate.consumer),
                        value_id=predicate_value_id,
                        instruction_ea=int(predicate.consumer.anchor_ea),
                        storage_identity=predicate.storage_identity,
                        width=int(predicate.width),
                    ),
                ),
            )
        )
        for carrier in imported_consumer.carriers:
            for point in carrier.corridor:
                semantic_point_block_id(point)
            carrier_value_id = (
                f"carrier:{imported_consumer.proof_id}:{carrier.carrier_id}"
            )
            data_flow_obligations.append(
                FragmentDataFlowObligation(
                    obligation_id=f"{carrier_value_id}:use-def",
                    role=FragmentDataFlowRole.CARRIER,
                    definition=FragmentValueSite(
                        site_id=f"{carrier_value_id}:definition",
                        block_id=semantic_point_block_id(carrier.definition),
                        value_id=carrier_value_id,
                        instruction_ea=int(carrier.definition.anchor_ea),
                        storage_identity=carrier.storage_identity,
                        width=int(carrier.width),
                    ),
                    uses=tuple(
                        FragmentValueSite(
                            site_id=f"{carrier_value_id}:consumer:{index}",
                            block_id=semantic_point_block_id(consumer),
                            value_id=carrier_value_id,
                            instruction_ea=int(consumer.anchor_ea),
                            storage_identity=carrier.storage_identity,
                            width=int(carrier.width),
                        )
                        for index, consumer in enumerate(carrier.consumers)
                    ),
                )
            )

    prohibited_witness_serials = _portable_dispatcher_scc_witnesses(
        graph,
        all_prohibited_serials,
        current_identity_by_serial=current_identity_by_serial,
        modified_current_serials=frozenset({source_serial}),
    )
    outside_predecessors = tuple(
        int(predecessor)
        for predecessor in graph.predecessors(source_serial)
        if int(predecessor) not in prohibited_serial_set
    )
    if not outside_predecessors:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition source has no published predecessor"
        )
    for predecessor in outside_predecessors:
        external_block_id(predecessor)
    prohibited_ids = tuple(
        external_block_id(serial) for serial in prohibited_witness_serials
    )
    if len(native_body.entry_block_ids) != 1:
        raise CanonicalSemanticFragmentRejected(
            "canonical detached target requires one imported entry",
            reason_code="detached_target_entry_count_mismatch",
            anchor_ea=int(target.semantic_anchor_ea),
            payload={"entry_block_ids": native_body.entry_block_ids},
        )
    (target_entry_block_id,) = native_body.entry_block_ids

    operations = (
        FragmentOperation(
            operation_id=f"route:{proof.proof_id}",
            source_block_id=replacement_id,
            direct_transfer_rewrite=_direct_transfer_rewrite(proof),
            edges=(
                FragmentEdge(
                    role=destination.role,
                    target_block_id=target_entry_block_id,
                ),
            ),
        ),
        *target_operations,
    )
    return FragmentPlan(
        plan_id=(f"canonical-composition:{evidence.atomic_group_id}:{proof.proof_id}"),
        atomic_group_id=evidence.atomic_group_id,
        publication_purpose=(FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING),
        native_key=evidence.native_key,
        blocks=tuple(blocks),
        roots=(replacement_id,),
        owned_originals=(original_id,),
        prohibited_dispatcher_blocks=prohibited_ids,
        operations=operations,
        normalization_authority=normalization_authority,
        native_bodies=(native_body,),
        data_flow_obligations=tuple(data_flow_obligations),
        return_carriers=nested_return_carriers,
        terminal_returns=nested_terminal_returns,
        terminal_routes=nested_terminal_routes,
    )


def compose_canonical_semantic_boundary_fragment_plan(
    graph: FlowGraph,
    normalization_plan: FragmentPlan,
    *,
    boundary_anchor_ea: int,
    available_evidence: CanonicalSemanticEvidence,
    current_identity_by_serial: Mapping[int, StableBlockIdentity],
    normalization_authority: NormalizationWorkItemAuthority,
    prohibited_dispatcher_serials: Iterable[int] = (),
    temporary_dispatcher_entry_port_obligation_id: str | None = None,
) -> FragmentPlan:
    """Resolve one published imported boundary as a closed canonical root."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("canonical boundary composition requires a FlowGraph")
    if not isinstance(normalization_plan, FragmentPlan):
        raise TypeError("canonical boundary composition requires a normalization plan")
    if (
        normalization_plan.publication_purpose
        is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical boundary composition requires frontend-normalization intent"
        )
    if not isinstance(available_evidence, CanonicalSemanticEvidence):
        raise TypeError("canonical boundary composition requires canonical evidence")
    if not isinstance(normalization_authority, NormalizationWorkItemAuthority):
        raise TypeError(
            "canonical boundary composition requires normalization work-item authority"
        )
    if (
        available_evidence.native_key != normalization_plan.native_key
        or normalization_authority.evidence_generation != available_evidence.generation
        or normalization_authority.source_plan_id != normalization_plan.plan_id
        or normalization_authority.source_atomic_group_id
        != normalization_plan.atomic_group_id
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical boundary composition authority drifted",
            reason_code="normalization_work_item_authority_drift",
            anchor_ea=int(boundary_anchor_ea),
        )
    current_identity_by_serial = {
        int(serial): identity for serial, identity in current_identity_by_serial.items()
    }
    if any(
        not isinstance(identity, StableBlockIdentity)
        for identity in current_identity_by_serial.values()
    ):
        raise TypeError("canonical boundary current identity authority is invalid")
    unknown_serials = frozenset(current_identity_by_serial).difference(
        int(serial) for serial in graph.blocks
    )
    if unknown_serials:
        raise CanonicalSemanticFragmentRejected(
            "canonical boundary current identity authority is stale",
            reason_code="current_identity_authority_stale",
            anchor_ea=int(boundary_anchor_ea),
            payload={"unknown_serials": tuple(sorted(unknown_serials))},
        )
    if any(
        identity.native_key != available_evidence.native_key
        for identity in current_identity_by_serial.values()
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical boundary current identity authority drifted",
            reason_code="current_identity_authority_native_key_drift",
            anchor_ea=int(boundary_anchor_ea),
        )

    boundary_anchor_ea = int(boundary_anchor_ea)
    boundary_candidates = tuple(
        block
        for block in normalization_plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
        and block.stable_identity is not None
        and boundary_anchor_ea in block.stable_identity.exact_instruction_eas
    )
    if len(boundary_candidates) != 1:
        raise CanonicalSemanticFragmentRejected(
            f"published canonical boundary 0x{boundary_anchor_ea:X} requires "
            f"one normalization-plan owner, observed {len(boundary_candidates)}",
            reason_code="normalization_plan_owner_count_mismatch",
            anchor_ea=boundary_anchor_ea,
            payload={
                "description": "published canonical boundary",
                "owner_count": len(boundary_candidates),
            },
        )
    (target,) = boundary_candidates
    target_identity = target.stable_identity
    if target_identity is None:
        raise CanonicalSemanticFragmentRejected(
            "published canonical boundary lacks stable identity",
            anchor_ea=boundary_anchor_ea,
        )
    current_owners = _current_owners_containing_identity(
        graph,
        target_identity,
        current_identity_by_serial=current_identity_by_serial,
    )
    if len(current_owners) != 1:
        raise CanonicalSemanticFragmentRejected(
            "published canonical boundary requires one current owner",
            reason_code="published_boundary_current_owner_count_mismatch",
            anchor_ea=boundary_anchor_ea,
            payload={
                "boundary_block_id": target.block_id,
                "boundary_identity": target_identity.diagnostic_label(),
                "owner_labels": tuple(
                    f"blk{serial}@0x{anchor_ea:X}"
                    for serial, anchor_ea, _identity in current_owners
                ),
                "current_identity_inventory": (
                    _current_identity_inventory_for_boundary(
                        graph,
                        target_identity,
                        boundary_anchor_ea,
                        current_identity_by_serial=current_identity_by_serial,
                    )
                ),
                "normalization_incoming_operations": (
                    _normalization_incoming_operation_inventory(
                        graph,
                        normalization_plan,
                        target.block_id,
                        current_identity_by_serial=current_identity_by_serial,
                    )
                ),
            },
        )
    root_serial, root_anchor_ea, root_identity = current_owners[0]
    prohibited_serials = frozenset(
        int(serial) for serial in prohibited_dispatcher_serials
    )
    incoming_predecessors = tuple(
        int(predecessor) for predecessor in graph.predecessors(root_serial)
    )
    outside_predecessors = tuple(
        predecessor
        for predecessor in incoming_predecessors
        if int(predecessor) not in prohibited_serials
    )
    temporary_port_predecessors: tuple[int, ...] = ()
    if not outside_predecessors:
        incoming_inventory = tuple(
            {
                "block": (
                    f"blk{predecessor}@0x{int(graph.blocks[predecessor].start_ea):X}"
                ),
                "prohibited": predecessor in prohibited_serials,
                "stable_identity": (
                    None
                    if current_identity_by_serial.get(predecessor) is None
                    else current_identity_by_serial[predecessor].diagnostic_label()
                ),
            }
            for predecessor in incoming_predecessors
        )
        if (
            temporary_dispatcher_entry_port_obligation_id is None
            or len(incoming_predecessors) != 1
            or not all(
                predecessor in prohibited_serials
                for predecessor in incoming_predecessors
            )
        ):
            raise CanonicalSemanticFragmentRejected(
                "published canonical boundary has no entry-connectable predecessor",
                reason_code="published_boundary_predecessor_missing",
                anchor_ea=boundary_anchor_ea,
                payload={
                    "boundary_block_id": target.block_id,
                    "boundary_identity": target_identity.diagnostic_label(),
                    "current_owner": f"blk{root_serial}@0x{root_anchor_ea:X}",
                    "current_owner_identity": root_identity.diagnostic_label(),
                    "incoming_predecessors": incoming_inventory,
                },
            )
        temporary_port_predecessors = incoming_predecessors

    (
        target_blocks,
        target_operations,
        native_body,
        nested_route_proofs,
        nested_route_decisions,
        nested_return_carriers,
        nested_terminal_returns,
        nested_terminal_routes,
    ) = _resolved_detached_target_component(
        graph,
        normalization_plan,
        target,
        available_evidence,
        canonical_proof_ids=(f"published-boundary@0x{boundary_anchor_ea:X}",),
        excluded_proof_ids=frozenset(),
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=normalization_authority,
        prohibited_dispatcher_serials=prohibited_serials,
        replaced_current_owner_serials=frozenset({int(root_serial)}),
    )
    if not nested_route_proofs:
        raise CanonicalSemanticFragmentRejected(
            "published canonical boundary owns no semantic route",
            reason_code="published_boundary_semantic_route_missing",
            anchor_ea=boundary_anchor_ea,
            payload={
                "boundary_block_id": target.block_id,
                "boundary_identity": target_identity.diagnostic_label(),
                "target_block_ids": tuple(block.block_id for block in target_blocks),
                "target_operation_ids": tuple(
                    operation.operation_id for operation in target_operations
                ),
                "nested_state_route_projection": tuple(
                    decision.diagnostic_payload() for decision in nested_route_decisions
                ),
            },
        )
    if len(native_body.entry_block_ids) != 1:
        raise CanonicalSemanticFragmentRejected(
            "resolved canonical boundary requires one detached root",
            reason_code="published_boundary_imported_root_count_mismatch",
            anchor_ea=boundary_anchor_ea,
            payload={"entry_block_ids": native_body.entry_block_ids},
        )
    (detached_root_id,) = native_body.entry_block_ids
    imported_root_matches = tuple(
        block
        for block in target_blocks
        if block.block_id == detached_root_id
        and block.role is FragmentBlockRole.IMPORTED
    )
    if len(imported_root_matches) != 1:
        raise CanonicalSemanticFragmentRejected(
            "resolved canonical boundary lost its imported root",
            reason_code="published_boundary_imported_root_missing",
            anchor_ea=boundary_anchor_ea,
        )
    root_operations = tuple(
        operation
        for operation in target_operations
        if operation.source_block_id == detached_root_id
    )
    if len(root_operations) != 1:
        raise CanonicalSemanticFragmentRejected(
            "resolved canonical boundary requires one root operation",
            reason_code="published_boundary_root_operation_count_mismatch",
            anchor_ea=boundary_anchor_ea,
            payload={
                "operation_ids": tuple(
                    operation.operation_id for operation in root_operations
                )
            },
        )

    original_id = f"published-boundary@0x{boundary_anchor_ea:X}:original"
    replacement_id = f"published-boundary@0x{boundary_anchor_ea:X}:replacement"
    rewritten_operations = tuple(
        replace(
            operation,
            source_block_id=(
                replacement_id
                if operation.source_block_id == detached_root_id
                else operation.source_block_id
            ),
            edges=tuple(
                replace(
                    edge,
                    target_block_id=(
                        replacement_id
                        if edge.target_block_id == detached_root_id
                        else edge.target_block_id
                    ),
                )
                for edge in operation.edges
            ),
        )
        for operation in target_operations
    )
    rewritten_return_carriers = tuple(
        replace(
            carrier,
            block_id=(
                replacement_id
                if carrier.block_id == detached_root_id
                else carrier.block_id
            ),
        )
        for carrier in nested_return_carriers
    )
    rewritten_terminal_returns = tuple(
        replace(
            terminal_return,
            block_id=(
                replacement_id
                if terminal_return.block_id == detached_root_id
                else terminal_return.block_id
            ),
        )
        for terminal_return in nested_terminal_returns
    )
    remaining_imported_blocks = tuple(
        block
        for block in target_blocks
        if block.role is FragmentBlockRole.IMPORTED
        and block.block_id != detached_root_id
    )
    remaining_imported_ids = frozenset(
        block.block_id for block in remaining_imported_blocks
    )
    rewritten_root_operation = next(
        operation
        for operation in rewritten_operations
        if operation.source_block_id == replacement_id
    )
    imported_entry_ids = tuple(
        dict.fromkeys(
            edge.target_block_id
            for edge in rewritten_root_operation.edges
            if edge.target_block_id in remaining_imported_ids
        )
    )
    native_bodies: tuple[FragmentNativeBody, ...] = ()
    if remaining_imported_blocks:
        if not imported_entry_ids:
            raise CanonicalSemanticFragmentRejected(
                "resolved canonical boundary body lacks a root-owned entry",
                reason_code="published_boundary_body_entry_missing",
                anchor_ea=boundary_anchor_ea,
            )
        native_bodies = (
            replace(
                native_body,
                block_ids=tuple(
                    block_id
                    for block_id in native_body.block_ids
                    if block_id in remaining_imported_ids
                ),
                entry_block_ids=imported_entry_ids,
                terminal_block_ids=tuple(
                    block_id
                    for block_id in native_body.terminal_block_ids
                    if block_id in remaining_imported_ids
                ),
                native_ranges=_merged_imported_ranges(
                    remaining_imported_blocks,
                    rewritten_operations,
                ),
                proof_ids=tuple(
                    proof_id
                    for proof_id in native_body.proof_ids
                    if proof_id != rewritten_root_operation.operation_id
                ),
            ),
        )

    block_by_id: dict[str, FragmentBlock] = {
        block.block_id: block
        for block in target_blocks
        if block.role is FragmentBlockRole.EXTERNAL
    }

    def add_current_external(serial: int) -> str:
        serial = int(serial)
        block = graph.blocks.get(serial)
        identity = current_identity_by_serial.get(serial)
        if block is None or identity is None:
            raise CanonicalSemanticFragmentRejected(
                "canonical boundary external block lacks current identity authority",
                reason_code="current_external_identity_missing",
                anchor_ea=boundary_anchor_ea,
            )
        block_id = f"native[{stable_block_identity_token(identity)}]"
        candidate = FragmentBlock(
            block_id=block_id,
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=stable_block_identity_semantic_anchor(identity),
            stable_identity=identity,
        )
        existing = block_by_id.get(block_id)
        if existing is not None and existing != candidate:
            raise CanonicalSemanticFragmentRejected(
                "canonical boundary external identity conflicts",
                reason_code="external_identity_conflict",
                anchor_ea=int(block.start_ea),
                payload={"block_id": block_id},
            )
        block_by_id[block_id] = candidate
        return block_id

    for predecessor in outside_predecessors:
        add_current_external(predecessor)
    temporary_predecessor_ids = tuple(
        add_current_external(predecessor) for predecessor in temporary_port_predecessors
    )
    prohibited_witness_serials = (
        ()
        if temporary_port_predecessors
        else _portable_dispatcher_scc_witnesses(
            graph,
            tuple(int(serial) for serial in prohibited_dispatcher_serials),
            current_identity_by_serial=current_identity_by_serial,
            modified_current_serials=frozenset({int(root_serial)}),
        )
    )
    prohibited_ids = tuple(
        add_current_external(serial) for serial in prohibited_witness_serials
    )
    block_by_id[original_id] = FragmentBlock(
        block_id=original_id,
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=boundary_anchor_ea,
        stable_identity=root_identity,
    )
    block_by_id[replacement_id] = FragmentBlock(
        block_id=replacement_id,
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=boundary_anchor_ea,
        stable_identity=root_identity,
        replaces_block_id=original_id,
    )
    for block in remaining_imported_blocks:
        block_by_id[block.block_id] = block

    route_group_id = "+".join(proof.proof_id for proof in nested_route_proofs)
    boundary_ports = tuple(
        FragmentBoundaryPort(
            port_id=f"temporary-dispatcher-entry@0x{boundary_anchor_ea:X}",
            kind=FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_ENTRY,
            predecessor_block_id=predecessor_id,
            root_block_id=replacement_id,
            retirement_obligation_id=str(temporary_dispatcher_entry_port_obligation_id),
        )
        for predecessor_id in temporary_predecessor_ids
    )
    return FragmentPlan(
        plan_id=(
            f"canonical-boundary-composition:{available_evidence.atomic_group_id}:"
            f"0x{boundary_anchor_ea:X}"
        ),
        atomic_group_id=(
            f"{available_evidence.atomic_group_id}:boundary@0x{boundary_anchor_ea:X}:"
            f"{route_group_id}"
        ),
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=available_evidence.native_key,
        blocks=tuple(block_by_id.values()),
        roots=(replacement_id,),
        owned_originals=(original_id,),
        prohibited_dispatcher_blocks=prohibited_ids,
        operations=rewritten_operations,
        normalization_authority=normalization_authority,
        native_bodies=native_bodies,
        return_carriers=rewritten_return_carriers,
        terminal_returns=rewritten_terminal_returns,
        terminal_routes=nested_terminal_routes,
        boundary_ports=boundary_ports,
    )


def _external_identity(
    graph: FlowGraph,
    serial: int,
    *,
    native_key,
) -> StableBlockIdentity:
    block = graph.blocks.get(int(serial))
    if block is None:
        raise CanonicalSemanticFragmentRejected(
            f"canonical fragment references absent block {serial}"
        )
    identity = stable_block_identity_from_snapshot(
        block,
        native_key=native_key,
    )
    if identity is None:
        raise CanonicalSemanticFragmentRejected(
            "canonical fragment external block lacks stable native identity"
        )
    return identity


def build_canonical_semantic_fragment_plan(
    graph: FlowGraph,
    bound: BoundCanonicalSemanticEvidence,
    *,
    prohibited_dispatcher_serials: Iterable[int] = (),
) -> FragmentPlan:
    """Build one serial-free fragment plan for a fully bound atomic group."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("canonical semantic fragment requires a FlowGraph")
    if not isinstance(bound, BoundCanonicalSemanticEvidence):
        raise TypeError("canonical semantic fragment requires bound canonical evidence")

    evidence = bound.evidence
    if tuple(route.evidence for route in bound.routes) != evidence.route_proofs:
        raise CanonicalSemanticFragmentRejected(
            "bound route set does not match atomic evidence"
        )
    prohibited_serials = tuple(
        dict.fromkeys(int(value) for value in prohibited_dispatcher_serials)
    )
    prohibited_serial_set = frozenset(prohibited_serials)
    source_serials = tuple(int(route.source.serial) for route in bound.routes)
    if len(set(source_serials)) != len(source_serials):
        raise CanonicalSemanticFragmentRejected(
            "canonical fragment requires one route proof per source block"
        )
    blocks: list[FragmentBlock] = []
    owned_originals: list[str] = []
    replacement_id_by_serial: dict[int, str] = {}
    external_id_by_serial: dict[int, str] = {}
    external_owner_serial_by_identity: dict[StableBlockIdentity, int] = {}

    for route in bound.routes:
        proof = route.evidence
        serial = int(route.source.serial)
        original_id = f"route:{proof.proof_id}:original"
        replacement_id = f"route:{proof.proof_id}:replacement"
        blocks.extend(
            (
                FragmentBlock(
                    block_id=original_id,
                    role=FragmentBlockRole.ORIGINAL,
                    materialization=(FragmentBlockMaterialization.REUSE_PUBLISHED),
                    semantic_anchor_ea=int(route.source.anchor_ea),
                    stable_identity=route.source.identity,
                ),
                FragmentBlock(
                    block_id=replacement_id,
                    role=FragmentBlockRole.REPLACEMENT,
                    materialization=(FragmentBlockMaterialization.CLONE_PUBLISHED),
                    semantic_anchor_ea=int(route.source.anchor_ea),
                    stable_identity=route.source.identity,
                    replaces_block_id=original_id,
                ),
            )
        )
        owned_originals.append(original_id)
        replacement_id_by_serial[serial] = replacement_id

    terminal_replacement_id_by_serial: dict[int, str] = {}
    for route in bound.routes:
        proof = route.evidence
        if proof.proof_kind is not SemanticRouteProofKind.TERMINAL_RETURN:
            continue
        if len(route.destinations) != 1:
            raise CanonicalSemanticFragmentRejected(
                "terminal semantic route requires one bound destination"
            )
        destination = route.destinations[0].block
        serial = int(destination.serial)
        existing_terminal = terminal_replacement_id_by_serial.get(serial)
        if existing_terminal is not None:
            existing_block = next(
                block for block in blocks if block.block_id == existing_terminal
            )
            if (
                existing_block.stable_identity != destination.identity
                or existing_block.semantic_anchor_ea != int(destination.anchor_ea)
            ):
                raise CanonicalSemanticFragmentRejected(
                    "shared terminal return block identity drifted"
                )
            continue
        if serial in replacement_id_by_serial:
            raise CanonicalSemanticFragmentRejected(
                "terminal return block cannot also own an outgoing route"
            )
        original_id = f"terminal:{proof.proof_id}:original"
        replacement_id = f"terminal:{proof.proof_id}:replacement"
        blocks.extend(
            (
                FragmentBlock(
                    block_id=original_id,
                    role=FragmentBlockRole.ORIGINAL,
                    materialization=(FragmentBlockMaterialization.REUSE_PUBLISHED),
                    semantic_anchor_ea=int(destination.anchor_ea),
                    stable_identity=destination.identity,
                ),
                FragmentBlock(
                    block_id=replacement_id,
                    role=FragmentBlockRole.REPLACEMENT,
                    materialization=(FragmentBlockMaterialization.CLONE_PUBLISHED),
                    semantic_anchor_ea=int(destination.anchor_ea),
                    stable_identity=destination.identity,
                    replaces_block_id=original_id,
                ),
            )
        )
        owned_originals.append(original_id)
        replacement_id_by_serial[serial] = replacement_id
        terminal_replacement_id_by_serial[serial] = replacement_id

    def external_block_id(
        serial: int,
        *,
        identity: StableBlockIdentity | None = None,
        anchor_ea: int | None = None,
    ) -> str:
        serial = int(serial)
        requested_identity = identity
        block = graph.blocks.get(serial)
        if block is None:
            raise CanonicalSemanticFragmentRejected(
                f"canonical fragment references absent block {serial}"
            )
        identity = identity or _external_identity(
            graph,
            serial,
            native_key=evidence.native_key,
        )
        anchor_ea = int(
            stable_block_identity_semantic_anchor(identity)
            if anchor_ea is None
            else anchor_ea
        )
        block_anchor_eas = {
            int(block.start_ea),
            *(int(instruction.ea) for instruction in block.insn_snapshots),
        }
        if anchor_ea not in block_anchor_eas:
            raise CanonicalSemanticFragmentRejected(
                "canonical fragment external anchor is not in its bound block"
            )
        existing = external_id_by_serial.get(serial)
        if existing is not None:
            existing_block = next(
                block for block in blocks if block.block_id == existing
            )
            if (
                requested_identity is not None
                and existing_block.stable_identity != requested_identity
            ):
                raise CanonicalSemanticFragmentRejected(
                    "canonical fragment external identity drifted"
                )
            return existing
        _claim_current_external_identity(
            serial,
            identity,
            owner_serial_by_identity=(external_owner_serial_by_identity),
        )
        block_id = f"native[{stable_block_identity_token(identity)}]"
        if any(item.block_id == block_id for item in blocks):
            raise CanonicalSemanticFragmentRejected(
                "canonical fragment external block id is ambiguous"
            )
        blocks.append(
            FragmentBlock(
                block_id=block_id,
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=anchor_ea,
                stable_identity=identity,
            )
        )
        external_id_by_serial[serial] = block_id
        return block_id

    def block_id_for_bound(block: BoundSemanticBlock) -> str:
        replacement_id = replacement_id_by_serial.get(int(block.serial))
        if replacement_id is not None:
            return replacement_id
        return external_block_id(
            block.serial,
            identity=block.identity,
            anchor_ea=block.anchor_ea,
        )

    operations: list[FragmentOperation] = []
    data_flow_obligations: list[FragmentDataFlowObligation] = []
    return_carriers: list[FragmentReturnCarrier] = []
    terminal_returns: list[FragmentTerminalReturn] = []
    terminal_routes: list[FragmentTerminalRoute] = []
    terminal_return_id_by_serial: dict[int, str] = {}
    for route in bound.routes:
        proof = route.evidence
        edges: list[FragmentEdge] = []
        for destination in route.destinations:
            target_serial = int(destination.block.serial)
            target_id = replacement_id_by_serial.get(target_serial)
            if target_id is None:
                target_id = external_block_id(
                    target_serial,
                    identity=destination.block.identity,
                    anchor_ea=destination.block.anchor_ea,
                )
            edges.append(
                FragmentEdge(
                    role=destination.evidence.role,
                    target_block_id=target_id,
                )
            )
        predicate_anchor_ea = None
        if proof.shape is SemanticRouteShape.CONDITIONAL:
            if route.predicate is None:
                raise CanonicalSemanticFragmentRejected(
                    "canonical conditional route lacks its bound predicate"
                )
            predicate_anchor_ea = int(route.predicate.consumer.anchor_ea)
        operation_id = f"route:{proof.proof_id}"
        operations.append(
            FragmentOperation(
                operation_id=operation_id,
                source_block_id=replacement_id_by_serial[int(route.source.serial)],
                edges=tuple(edges),
                predicate_anchor_ea=predicate_anchor_ea,
                direct_transfer_rewrite=_direct_transfer_rewrite(proof),
            )
        )
        predicate = route.predicate
        if (
            predicate is not None
            and predicate.evidence.kind is SemanticPredicateKind.STORAGE_EQUALS
        ):
            storage_identity = predicate.evidence.storage_identity
            if storage_identity is None:
                raise CanonicalSemanticFragmentRejected(
                    "storage predicate lacks portable storage identity"
                )
            for corridor_block in predicate.corridor:
                block_id_for_bound(corridor_block)
            value_id = f"predicate:{proof.proof_id}"
            definition = FragmentValueSite(
                site_id=f"{value_id}:definition",
                block_id=block_id_for_bound(predicate.origin),
                value_id=value_id,
                instruction_ea=predicate.origin.anchor_ea,
                storage_identity=storage_identity,
                width=predicate.evidence.width,
            )
            use = FragmentValueSite(
                site_id=f"{value_id}:consumer",
                block_id=block_id_for_bound(predicate.consumer),
                value_id=value_id,
                instruction_ea=predicate.consumer.anchor_ea,
                storage_identity=storage_identity,
                width=predicate.evidence.width,
            )
            data_flow_obligations.append(
                FragmentDataFlowObligation(
                    obligation_id=f"{value_id}:use-def",
                    role=FragmentDataFlowRole.CONDITION,
                    definition=definition,
                    uses=(use,),
                )
            )
        for carrier in route.carriers:
            for corridor_block in carrier.corridor:
                block_id_for_bound(corridor_block)
            value_id = f"carrier:{proof.proof_id}:{carrier.evidence.carrier_id}"
            definition = FragmentValueSite(
                site_id=f"{value_id}:definition",
                block_id=block_id_for_bound(carrier.definition),
                value_id=value_id,
                instruction_ea=carrier.definition.anchor_ea,
                storage_identity=carrier.evidence.storage_identity,
                width=carrier.evidence.width,
            )
            uses = tuple(
                FragmentValueSite(
                    site_id=f"{value_id}:consumer:{index}",
                    block_id=block_id_for_bound(consumer),
                    value_id=value_id,
                    instruction_ea=consumer.anchor_ea,
                    storage_identity=carrier.evidence.storage_identity,
                    width=carrier.evidence.width,
                )
                for index, consumer in enumerate(carrier.consumers)
            )
            data_flow_obligations.append(
                FragmentDataFlowObligation(
                    obligation_id=f"{value_id}:use-def",
                    role=FragmentDataFlowRole.CARRIER,
                    definition=definition,
                    uses=uses,
                )
            )
        terminal_carrier = proof.terminal_return_carrier
        if terminal_carrier is not None:
            destination_serial = int(route.destinations[0].block.serial)
            terminal_block_id = terminal_replacement_id_by_serial.get(
                destination_serial
            )
            if terminal_block_id is None:
                raise CanonicalSemanticFragmentRejected(
                    "terminal semantic route lacks an owned return block"
                )
            source_block_id = replacement_id_by_serial[int(route.source.serial)]
            carrier_id = f"return-carrier:{proof.proof_id}"
            return_carriers.append(
                FragmentReturnCarrier(
                    carrier_id=carrier_id,
                    block_id=source_block_id,
                    state_write_ea=terminal_carrier.state_write_ea,
                    carrier_ea=terminal_carrier.carrier_ea,
                    operation=terminal_carrier.operation,
                    source=FragmentReturnSource(
                        kind=FragmentReturnSourceKind(
                            terminal_carrier.source.kind.value
                        ),
                        width=terminal_carrier.source.width,
                        storage_identity=(terminal_carrier.source.storage_identity),
                        constant=terminal_carrier.source.constant,
                    ),
                    return_width=terminal_carrier.return_width,
                    corridor_instruction_eas=(
                        terminal_carrier.corridor_instruction_eas
                    ),
                )
            )
            return_id = terminal_return_id_by_serial.get(destination_serial)
            if return_id is None:
                return_id = (
                    f"terminal-return:0x{terminal_carrier.request.terminal_target_ea:X}"
                )
                terminal_returns.append(
                    FragmentTerminalReturn(
                        return_id=return_id,
                        block_id=terminal_block_id,
                        instruction_ea=terminal_carrier.terminal_return_ea,
                        return_width=terminal_carrier.return_width,
                    )
                )
                terminal_return_id_by_serial[destination_serial] = return_id
            else:
                existing_return = next(
                    item for item in terminal_returns if item.return_id == return_id
                )
                if existing_return.return_width != terminal_carrier.return_width:
                    raise CanonicalSemanticFragmentRejected(
                        "terminal routes disagree on return width"
                    )
            terminal_routes.append(
                FragmentTerminalRoute(
                    terminal_route_id=f"terminal-route:{proof.proof_id}",
                    operation_id=operation_id,
                    carrier_id=carrier_id,
                    return_id=return_id,
                )
            )

    roots: list[str] = []
    owned_serial_set = frozenset(replacement_id_by_serial)
    for route in bound.routes:
        serial = int(route.source.serial)
        outside_predecessors = tuple(
            int(predecessor)
            for predecessor in graph.predecessors(serial)
            if int(predecessor) not in owned_serial_set
            and int(predecessor) not in prohibited_serial_set
        )
        if not outside_predecessors:
            continue
        roots.append(replacement_id_by_serial[serial])
        for predecessor in outside_predecessors:
            external_block_id(predecessor)
    if not roots:
        raise CanonicalSemanticFragmentRejected(
            "canonical fragment has no externally owned publication root"
        )

    prohibited_ids: list[str] = []
    for serial in prohibited_serials:
        if serial in owned_serial_set:
            raise CanonicalSemanticFragmentRejected(
                "canonical fragment cannot own a prohibited dispatcher"
            )
        block_id = external_block_id(serial)
        if block_id not in prohibited_ids:
            prohibited_ids.append(block_id)

    return FragmentPlan(
        plan_id=(
            f"canonical-semantic-plan:{evidence.atomic_group_id}:g{evidence.generation}"
        ),
        atomic_group_id=evidence.atomic_group_id,
        publication_purpose=(FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING),
        native_key=evidence.native_key,
        blocks=tuple(blocks),
        roots=tuple(roots),
        owned_originals=tuple(owned_originals),
        prohibited_dispatcher_blocks=tuple(prohibited_ids),
        operations=tuple(operations),
        return_carriers=tuple(return_carriers),
        terminal_returns=tuple(terminal_returns),
        terminal_routes=tuple(terminal_routes),
        data_flow_obligations=tuple(data_flow_obligations),
    )


__all__ = [
    "CanonicalSemanticFragmentRejected",
    "build_canonical_semantic_fragment_plan",
    "compose_canonical_semantic_boundary_fragment_plan",
    "compose_canonical_semantic_fragment_plan",
]
