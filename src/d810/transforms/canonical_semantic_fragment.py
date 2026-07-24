"""Lower bound canonical route evidence into a portable semantic fragment."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace

from d810.analyses.control_flow.semantic_route_evidence import (
    BoundCanonicalSemanticEvidence,
    BoundSemanticBlock,
    CanonicalSemanticEvidence,
    SemanticPredicateKind,
    SemanticRouteProofKind,
    SemanticRouteShape,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    stable_block_identity_semantic_anchor,
    stable_block_identity_from_snapshot,
    stable_block_identity_token,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentEdge,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
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


def _identity_contains(
    owner: StableBlockIdentity,
    candidate: StableBlockIdentity,
) -> bool:
    return bool(
        owner.native_key == candidate.native_key
        and all(
            any(
                int(owner_interval.start_ea)
                <= int(candidate_interval.start_ea)
                and int(candidate_interval.end_ea)
                <= int(owner_interval.end_ea)
                for owner_interval in owner.native_ranges.intervals
            )
            for candidate_interval in candidate.native_ranges.intervals
        )
        and candidate.exact_instruction_eas.issubset(
            owner.exact_instruction_eas
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
        for block in graph.blocks.values()
        if (
            identity := stable_block_identity_from_snapshot(
                block,
                native_key=retained_identity.native_key,
            )
        )
        is not None
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
) -> tuple[tuple[int, int], ...]:
    """Return current block serials and anchors wholly owned by one identity."""
    owners = []
    for block in graph.blocks.values():
        current_identity = stable_block_identity_from_snapshot(
            block,
            native_key=identity.native_key,
        )
        if current_identity is None or not _identity_contains(
            identity,
            current_identity,
        ):
            continue
        owners.append((int(block.serial), int(block.start_ea)))
    return tuple(owners)


def _merged_imported_ranges(
    plan: FragmentPlan,
    block_ids: frozenset[str],
    operations: tuple[FragmentOperation, ...],
) -> tuple[NativeEaInterval, ...]:
    intervals = [
        interval
        for block_id in block_ids
        for interval in plan.block(block_id).stable_identity.native_ranges.intervals
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
    intervals.sort(
        key=lambda interval: (int(interval.start_ea), int(interval.end_ea))
    )
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


def _detached_target_component(
    plan: FragmentPlan,
    target: FragmentBlock,
    *,
    canonical_proof_id: str,
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
    selected_ids: set[str] = set()
    selected_operation_ids: set[str] = set()
    pending = [target.block_id]
    while pending:
        block_id = pending.pop()
        if block_id in selected_ids:
            continue
        if block_id not in native_block_ids:
            raise CanonicalSemanticFragmentRejected(
                "detached canonical target component escapes its native body"
            )
        selected_ids.add(block_id)
        operation = operation_by_source.get(block_id)
        if operation is None:
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
                pending.append(edge_target.block_id)
            else:
                selected_ids.add(edge_target.block_id)

    selected_operations = tuple(
        operation
        for operation in plan.operations
        if operation.operation_id in selected_operation_ids
    )
    selected_imported_ids = frozenset(
        block_id
        for block_id in selected_ids
        if plan.block(block_id).role is FragmentBlockRole.IMPORTED
    )
    scoped_body_id = (
        f"{native_body.body_id}:canonical:{canonical_proof_id}"
    )
    boundary_id_by_source_id: dict[str, str] = {}
    projected_boundary_by_id: dict[str, FragmentBlock] = {}
    for block in plan.blocks:
        if (
            block.block_id not in selected_ids
            or block.block_id in selected_imported_ids
        ):
            continue
        identity = block.stable_identity
        if (
            block.role
            not in {
                FragmentBlockRole.EXTERNAL,
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
            semantic_anchor_ea=(
                stable_block_identity_semantic_anchor(identity)
            ),
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

    selected_operations = tuple(
        replace(
            operation,
            edges=tuple(
                replace(
                    edge,
                    target_block_id=boundary_id_by_source_id.get(
                        edge.target_block_id,
                        edge.target_block_id,
                    ),
                )
                for edge in operation.edges
            ),
        )
        for operation in selected_operations
    )
    selected_blocks = (
        *tuple(projected_boundary_by_id.values()),
        *tuple(
            replace(block, native_body_id=scoped_body_id)
            for block in plan.blocks
            if block.block_id in selected_imported_ids
        ),
    )
    selected_native_body = FragmentNativeBody(
        body_id=scoped_body_id,
        block_ids=tuple(
            block_id
            for block_id in native_body.block_ids
            if block_id in selected_imported_ids
        ),
        entry_block_ids=(target.block_id,),
        terminal_block_ids=tuple(
            block_id
            for block_id in native_body.terminal_block_ids
            if block_id in selected_imported_ids
        ),
        native_ranges=_merged_imported_ranges(
            plan,
            selected_imported_ids,
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


def compose_canonical_semantic_fragment_plan(
    graph: FlowGraph,
    normalization_plan: FragmentPlan,
    evidence: CanonicalSemanticEvidence,
    *,
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
    if len(evidence.route_proofs) != 1:
        raise CanonicalSemanticFragmentRejected(
            "canonical composition currently requires one route proof"
        )
    (proof,) = evidence.route_proofs
    if (
        proof.proof_kind is not SemanticRouteProofKind.STATE_ASSIGNMENT
        or proof.shape is not SemanticRouteShape.DIRECT
        or len(proof.destinations) != 1
        or proof.predicate is not None
        or proof.carriers
        or proof.terminal_return_carrier is not None
        or proof.state_write is None
    ):
        raise CanonicalSemanticFragmentRejected(
            "canonical composition requires one complete direct state assignment"
        )

    source = _unique_plan_block(
        normalization_plan,
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
        retained_identity=retained_source_identity,
        state_write_identity=state_write.identity,
        state_write_ea=state_write.instruction_ea,
        delivery_ea=proof.source_anchor_ea,
        corridor_instruction_eas=state_write.corridor_instruction_eas,
    )
    source_anchor_ea = int(state_write.instruction_ea)
    (destination,) = proof.destinations
    target = _unique_plan_block(
        normalization_plan,
        destination.target_identity,
        destination.target_anchor_ea,
        roles=frozenset({FragmentBlockRole.IMPORTED}),
        description="canonical route target",
    )
    target_blocks, target_operations, native_body = (
        _detached_target_component(
            normalization_plan,
            target,
            canonical_proof_id=proof.proof_id,
        )
    )
    target_external_blocks = tuple(
        block
        for block in target_blocks
        if block.role is FragmentBlockRole.EXTERNAL
    )
    target_imported_blocks = tuple(
        block
        for block in target_blocks
        if block.role is FragmentBlockRole.IMPORTED
    )
    if len(target_external_blocks) + len(target_imported_blocks) != len(
        target_blocks
    ):
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
                    "current_owner": (
                        f"blk{owner_serial}@0x{owner_anchor_ea:X}"
                    ),
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
        identity = _external_identity(
            graph,
            serial,
            native_key=evidence.native_key,
        )
        _claim_current_external_identity(
            serial,
            identity,
            owner_serial_by_identity=(
                external_owner_serial_by_identity
            ),
        )
        semantic_anchor_ea = stable_block_identity_semantic_anchor(identity)
        block_id = f"native[{stable_block_identity_token(identity)}]"
        existing_block = next(
            (
                item
                for item in blocks
                if item.block_id == block_id
            ),
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
                        "current_owner": (
                            f"blk{serial}@0x{semantic_anchor_ea:X}"
                        ),
                    },
                )
            external_id_by_serial[serial] = block_id
            return block_id
        blocks.append(
            FragmentBlock(
                block_id=block_id,
                role=FragmentBlockRole.EXTERNAL,
                materialization=(
                    FragmentBlockMaterialization.REUSE_PUBLISHED
                ),
                semantic_anchor_ea=semantic_anchor_ea,
                stable_identity=identity,
            )
        )
        external_id_by_serial[serial] = block_id
        return block_id

    prohibited_serials = tuple(
        dict.fromkeys(int(value) for value in prohibited_dispatcher_serials)
    )
    prohibited_serial_set = frozenset(prohibited_serials)
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
        external_block_id(serial) for serial in prohibited_serials
    )

    blocks.extend(
        (
            FragmentBlock(
                block_id=original_id,
                role=FragmentBlockRole.ORIGINAL,
                materialization=(
                    FragmentBlockMaterialization.REUSE_PUBLISHED
                ),
                semantic_anchor_ea=source_anchor_ea,
                stable_identity=source_identity,
            ),
            FragmentBlock(
                block_id=replacement_id,
                role=FragmentBlockRole.REPLACEMENT,
                materialization=(
                    FragmentBlockMaterialization.CLONE_PUBLISHED
                ),
                semantic_anchor_ea=source_anchor_ea,
                stable_identity=source_identity,
                replaces_block_id=original_id,
            ),
        )
    )
    blocks.extend(target_imported_blocks)
    operations = (
        FragmentOperation(
            operation_id=f"route:{proof.proof_id}",
            source_block_id=replacement_id,
            edges=(
                FragmentEdge(
                    role=destination.role,
                    target_block_id=target.block_id,
                ),
            ),
        ),
        *target_operations,
    )
    return FragmentPlan(
        plan_id=(
            f"canonical-composition:{evidence.atomic_group_id}:"
            f"{proof.proof_id}"
        ),
        atomic_group_id=evidence.atomic_group_id,
        publication_purpose=(
            FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
        ),
        native_key=evidence.native_key,
        blocks=tuple(blocks),
        roots=(replacement_id,),
        owned_originals=(original_id,),
        prohibited_dispatcher_blocks=prohibited_ids,
        operations=operations,
        normalization_authority=normalization_authority,
        native_bodies=(native_body,),
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
        raise TypeError(
            "canonical semantic fragment requires bound canonical evidence"
        )

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
                    materialization=(
                        FragmentBlockMaterialization.REUSE_PUBLISHED
                    ),
                    semantic_anchor_ea=int(route.source.anchor_ea),
                    stable_identity=route.source.identity,
                ),
                FragmentBlock(
                    block_id=replacement_id,
                    role=FragmentBlockRole.REPLACEMENT,
                    materialization=(
                        FragmentBlockMaterialization.CLONE_PUBLISHED
                    ),
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
                or existing_block.semantic_anchor_ea
                != int(destination.anchor_ea)
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
                    materialization=(
                        FragmentBlockMaterialization.REUSE_PUBLISHED
                    ),
                    semantic_anchor_ea=int(destination.anchor_ea),
                    stable_identity=destination.identity,
                ),
                FragmentBlock(
                    block_id=replacement_id,
                    role=FragmentBlockRole.REPLACEMENT,
                    materialization=(
                        FragmentBlockMaterialization.CLONE_PUBLISHED
                    ),
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
            *(
                int(instruction.ea)
                for instruction in block.insn_snapshots
            ),
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
            owner_serial_by_identity=(
                external_owner_serial_by_identity
            ),
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
                        storage_identity=(
                            terminal_carrier.source.storage_identity
                        ),
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
                return_id = f"terminal-return:0x{terminal_carrier.request.terminal_target_ea:X}"
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
                    item
                    for item in terminal_returns
                    if item.return_id == return_id
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
            f"canonical-semantic-plan:"
            f"{evidence.atomic_group_id}:g{evidence.generation}"
        ),
        atomic_group_id=evidence.atomic_group_id,
        publication_purpose=(
            FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
        ),
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
    "compose_canonical_semantic_fragment_plan",
]
