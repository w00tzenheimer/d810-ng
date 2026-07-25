"""Pure off-side projection for one prepared detached direct route."""

from __future__ import annotations

from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.canonical_semantic_fragment import DetachedDirectRoutePlan
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef
from d810.transforms.fragment_plan import (
    FragmentPlan,
    FragmentPublicationPurpose,
)
from d810.transforms.prepared_native_body import (
    PreparedNativeBodyFact,
    PreparedNativeEdgeFact,
)


class DetachedDirectRouteProjectionRejected(ValueError):
    """Typed prewrite failure to project one detached direct route."""

    live_mutation_started = False
    failure_phase = "projection"

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        anchor_ea: int,
        payload: dict[str, object] | None = None,
    ) -> None:
        reason_code = str(reason_code).strip()
        if not reason_code:
            raise ValueError("projection rejection requires a reason code")
        anchor_ea = int(anchor_ea)
        if anchor_ea < 0:
            raise ValueError("projection rejection anchor must be non-negative")
        self.reason_code = reason_code
        self.anchor_ea = anchor_ea
        self.payload = dict(payload or {})
        super().__init__(str(message))


def _reject(
    message: str,
    *,
    reason_code: str,
    anchor_ea: int,
    payload: dict[str, object] | None = None,
) -> None:
    raise DetachedDirectRouteProjectionRejected(
        message,
        reason_code=reason_code,
        anchor_ea=anchor_ea,
        payload=payload,
    )


def _operations_by_source(plan: FragmentPlan) -> dict[str, tuple[object, ...]]:
    return {
        block.block_id: tuple(
            operation
            for operation in plan.operations
            if operation.source_block_id == block.block_id
        )
        for block in plan.blocks
    }


def _prepared_successors(
    operations: tuple[object, ...],
) -> tuple[PreparedNativeEdgeFact, ...]:
    return tuple(
        PreparedNativeEdgeFact(edge.role, edge.target_block_id)
        for operation in operations
        for edge in operation.edges
    )


def _prepared_predecessors(
    block_ids: tuple[str, ...],
    operations_by_source: dict[str, tuple[object, ...]],
) -> dict[str, tuple[str, ...]]:
    predecessors: dict[str, list[str]] = {block_id: [] for block_id in block_ids}
    for source_id in block_ids:
        for operation in operations_by_source.get(source_id, ()):
            for edge in operation.edges:
                if edge.target_block_id in predecessors:
                    predecessors[edge.target_block_id].append(source_id)
    return {
        block_id: tuple(source_ids) for block_id, source_ids in predecessors.items()
    }


def _instruction_snapshots(
    prepared_block,
    *,
    rewrite_anchor_ea: int | None = None,
) -> tuple[InsnSnapshot, ...]:
    snapshots = []
    for index, instruction in enumerate(prepared_block.instructions):
        rewrite = rewrite_anchor_ea is not None and index == len(
            prepared_block.instructions
        ) - 1
        snapshots.append(
            InsnSnapshot(
                opcode=-1 if rewrite else int(instruction.opcode),
                ea=int(instruction.native_ea),
                operands=(),
                kind=InsnKind.GOTO if rewrite else instruction.kind,
                native_ea=int(instruction.native_ea),
            )
        )
    return tuple(snapshots)


def project_detached_direct_route(
    normalization_plan: FragmentPlan,
    detached_plan: DetachedDirectRoutePlan,
    prepared_body: PreparedNativeBodyFact,
    *,
    snapshot_id: str,
) -> CfgProjection:
    """Project one complete direct route without reserving or mutating live CFG state."""
    if not isinstance(normalization_plan, FragmentPlan):
        raise TypeError("detached projection requires a FragmentPlan")
    if not isinstance(detached_plan, DetachedDirectRoutePlan):
        raise TypeError("detached projection requires a DetachedDirectRoutePlan")
    if not isinstance(prepared_body, PreparedNativeBodyFact):
        raise TypeError("detached projection requires prepared native-body facts")
    snapshot_id = str(snapshot_id).strip()
    if not snapshot_id:
        raise ValueError("detached projection requires a snapshot id")

    rewrite = detached_plan.operation.direct_transfer_rewrite
    assert rewrite is not None
    reference_route = rewrite.reference_route
    assert reference_route is not None
    rewrite_anchor_ea = int(rewrite.rewrite_anchor_ea)
    if (
        normalization_plan.publication_purpose
        is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        or detached_plan.normalization_authority.source_plan_id
        != normalization_plan.plan_id
        or detached_plan.normalization_authority.source_atomic_group_id
        != normalization_plan.atomic_group_id
        or prepared_body.plan_id != normalization_plan.plan_id
    ):
        _reject(
            "detached route projection authority differs from prepared normalization",
            reason_code="detached_projection_authority_drift",
            anchor_ea=rewrite_anchor_ea,
        )

    body_matches = tuple(
        body
        for body in normalization_plan.native_bodies
        if body.body_id == detached_plan.source_block.native_body_id
    )
    if len(body_matches) != 1 or body_matches[0].body_id != prepared_body.body_id:
        _reject(
            "detached route projection lacks one prepared native-body owner",
            reason_code="prepared_native_body_owner_mismatch",
            anchor_ea=rewrite_anchor_ea,
            payload={"prepared_body_id": prepared_body.body_id},
        )
    (native_body,) = body_matches
    block_ids = tuple(block.block_id for block in prepared_body.blocks)
    if block_ids != native_body.block_ids:
        _reject(
            "prepared native-body inventory differs from normalization intent",
            reason_code="prepared_native_body_inventory_drift",
            anchor_ea=rewrite_anchor_ea,
            payload={
                "prepared_block_ids": block_ids,
                "planned_block_ids": native_body.block_ids,
            },
        )

    operations_by_source = _operations_by_source(normalization_plan)
    expected_predecessors = _prepared_predecessors(
        native_body.block_ids,
        operations_by_source,
    )
    for prepared_block in prepared_body.blocks:
        plan_block = normalization_plan.block(prepared_block.block_id)
        expected_successors = _prepared_successors(
            operations_by_source.get(prepared_block.block_id, ())
        )
        if (
            prepared_block.semantic_anchor_ea != plan_block.semantic_anchor_ea
            or prepared_block.stable_identity != plan_block.stable_identity
            or prepared_block.successors != expected_successors
            or prepared_block.predecessor_block_ids
            != expected_predecessors[prepared_block.block_id]
        ):
            reason_code = (
                "prepared_source_raw_operation_drift"
                if prepared_block.block_id == detached_plan.source_block.block_id
                else "prepared_native_body_topology_drift"
            )
            _reject(
                "prepared native-body topology differs from normalization intent",
                reason_code=reason_code,
                anchor_ea=rewrite_anchor_ea,
                payload={"block_id": prepared_block.block_id},
            )
        if any(
            not prepared_block.stable_identity.native_ranges.contains(
                int(instruction.native_ea)
            )
            for instruction in prepared_block.instructions
        ):
            _reject(
                "prepared instruction escapes its stable native owner",
                reason_code="prepared_instruction_identity_drift",
                anchor_ea=rewrite_anchor_ea,
                payload={"block_id": prepared_block.block_id},
            )

    source = prepared_body.block(detached_plan.source_block.block_id)
    target = prepared_body.block(detached_plan.target_block.block_id)
    raw_roles = tuple(edge.role for edge in source.successors)
    if (
        source.successors
        != tuple(
            PreparedNativeEdgeFact(edge.role, edge.target_block_id)
            for edge in detached_plan.superseded_operation.edges
        )
        or frozenset(raw_roles)
        != frozenset(
            {
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
        or source.terminator_kind is not InsnKind.COND_JUMP
        or source.terminator_ea != rewrite_anchor_ea
        or not source.instructions
        or int(source.instructions[-1].native_ea) != rewrite_anchor_ea
    ):
        _reject(
            "prepared source does not retain the complete raw conditional",
            reason_code="prepared_source_raw_operation_drift",
            anchor_ea=rewrite_anchor_ea,
        )
    direct_target_ea = int(reference_route.direct_target_ea)
    if (
        target.semantic_anchor_ea != direct_target_ea
        or not target.stable_identity.native_ranges.contains(direct_target_ea)
    ):
        _reject(
            "prepared direct target differs from reference route authority",
            reason_code="prepared_direct_target_drift",
            anchor_ea=rewrite_anchor_ea,
            payload={"direct_target_ea": direct_target_ea},
        )

    corridor_blocks = tuple(
        prepared_body.block(block_id) for block_id in detached_plan.corridor_block_ids
    )
    if tuple(block.semantic_anchor_ea for block in corridor_blocks) != tuple(
        normalization_plan.block(block_id).semantic_anchor_ea
        for block_id in detached_plan.corridor_block_ids
    ):
        _reject(
            "detached proof corridor changed prepared native ownership",
            reason_code="prepared_corridor_owner_drift",
            anchor_ea=rewrite_anchor_ea,
        )
    for instruction_ea in rewrite.proof_corridor_instruction_eas:
        owners = tuple(
            block
            for block in corridor_blocks
            if block.stable_identity.native_ranges.contains(int(instruction_ea))
            and any(
                int(instruction.native_ea) == int(instruction_ea)
                for instruction in block.instructions
            )
        )
        if len(owners) != 1:
            _reject(
                "detached proof corridor lacks one prepared instruction owner",
                reason_code="prepared_corridor_instruction_owner_mismatch",
                anchor_ea=int(instruction_ea),
                payload={
                    "owner_block_ids": tuple(block.block_id for block in owners),
                },
            )

    node_by_block_id = {
        block.block_id: index for index, block in enumerate(prepared_body.blocks)
    }
    projected_successors = {
        block.block_id: tuple(edge.target_block_id for edge in block.successors)
        for block in prepared_body.blocks
    }
    projected_successors[source.block_id] = (target.block_id,)
    projected_predecessors: dict[str, list[str]] = {
        block_id: [] for block_id in node_by_block_id
    }
    for source_id, successor_ids in projected_successors.items():
        for successor_id in successor_ids:
            if successor_id in projected_predecessors:
                projected_predecessors[successor_id].append(source_id)

    blocks = {}
    for prepared_block in prepared_body.blocks:
        is_source = prepared_block.block_id == source.block_id
        instructions = _instruction_snapshots(
            prepared_block,
            rewrite_anchor_ea=rewrite_anchor_ea if is_source else None,
        )
        successor_ids = projected_successors[prepared_block.block_id]
        kind = (
            BlockKind.ONE_WAY
            if is_source
            else {
                0: BlockKind.ZERO_WAY,
                1: BlockKind.ONE_WAY,
                2: BlockKind.TWO_WAY,
            }.get(len(successor_ids), BlockKind.N_WAY)
        )
        node = node_by_block_id[prepared_block.block_id]
        blocks[node] = BlockSnapshot(
            serial=node,
            block_type=-1,
            succs=tuple(node_by_block_id[block_id] for block_id in successor_ids),
            preds=tuple(
                node_by_block_id[block_id]
                for block_id in projected_predecessors[prepared_block.block_id]
            ),
            flags=int(prepared_block.block_flags),
            start_ea=int(prepared_block.semantic_anchor_ea),
            insn_snapshots=instructions,
            kind=kind,
            tail_kind=InsnKind.GOTO if is_source else prepared_block.terminator_kind,
            native_start_ea=int(prepared_block.semantic_anchor_ea),
        )

    corridor_owner_eas = tuple(
        int(block.semantic_anchor_ea) for block in corridor_blocks
    )
    graph = FlowGraph(
        blocks=blocks,
        entry_serial=node_by_block_id[source.block_id],
        func_ea=int(reference_route.function_ea),
        metadata={
            "projection_kind": "detached_direct_route",
            "normalization_plan_id": normalization_plan.plan_id,
            "detached_plan_id": detached_plan.plan_id,
            "evidence_generation": int(detached_plan.evidence_generation),
            "native_body_id": prepared_body.body_id,
            "reference_route_id": reference_route.route_id,
            "source_block_id": source.block_id,
            "source_owner_ea": int(detached_plan.source_block.semantic_anchor_ea),
            "rewrite_anchor_ea": rewrite_anchor_ea,
            "target_block_id": target.block_id,
            "direct_target_ea": direct_target_ea,
            "superseded_operation_id": (
                detached_plan.superseded_operation.operation_id
            ),
            "superseded_edge_roles": tuple(role.value for role in raw_roles),
            "projected_operation_id": detached_plan.operation.operation_id,
            "projected_terminator": InsnKind.GOTO.value,
            "projected_edge_roles": (SemanticEdgeRole.DIRECT.value,),
            "corridor_block_ids": detached_plan.corridor_block_ids,
            "corridor_owner_eas": corridor_owner_eas,
            "proof_corridor_instruction_eas": tuple(
                int(ea) for ea in rewrite.proof_corridor_instruction_eas
            ),
            "live_mutation_started": False,
            "publication_eligible": False,
            "receipt_created": False,
        },
    )
    focus_block_ids = tuple(
        dict.fromkeys(
            (
                source.block_id,
                target.block_id,
                *detached_plan.corridor_block_ids,
            )
        )
    )
    return CfgProjection(
        plan_id=detached_plan.plan_id,
        snapshot_id=snapshot_id,
        graph=graph,
        focus_refs=tuple(
            PlanBlockRef(detached_plan.plan_id, block_id)
            for block_id in focus_block_ids
        ),
    )


__all__ = [
    "DetachedDirectRouteProjectionRejected",
    "project_detached_direct_route",
]
