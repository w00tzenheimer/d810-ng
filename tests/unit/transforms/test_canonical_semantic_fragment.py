"""Canonical semantic-route evidence lowers to portable fragment plans."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_canonical_semantic_evidence,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
    TerminalReturnCarrierSource,
    TerminalReturnCarrierSourceKind,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    stable_block_identity_from_snapshot,
    stable_block_identity_token,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms import canonical_semantic_fragment as canonical_fragment
from d810.transforms.canonical_semantic_fragment import (
    CanonicalSemanticFragmentRejected,
    build_canonical_semantic_fragment_plan,
    compose_canonical_semantic_boundary_fragment_plan,
    compose_canonical_semantic_fragment_plan,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentBoundaryPortKind,
    FragmentConditionalSelectEnvelope,
    FragmentComputedBranchNormalization,
    FragmentDataFlowRole,
    FragmentEdge,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentReturnSourceKind,
    FragmentStoragePredicateMaterialization,
    FragmentWorkItemScope,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 1),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _wide_identity(start_ea: int, end_ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=range(start_ea, end_ea),
    )


def _block(
    serial: int,
    ea: int,
    *,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insn_eas: tuple[int, ...] | None = None,
) -> BlockSnapshot:
    insn_eas = (ea,) if insn_eas is None else insn_eas
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=tuple(
            InsnSnapshot(opcode=0, ea=insn_ea, operands=()) for insn_ea in insn_eas
        ),
    )


def _current_identity_authority(
    graph: FlowGraph,
) -> dict[int, StableBlockIdentity]:
    authority = {}
    for serial, block in graph.blocks.items():
        identity = stable_block_identity_from_snapshot(
            block,
            native_key=NATIVE_KEY,
        )
        assert identity is not None
        authority[int(serial)] = identity
    return authority


def _direct_bound_evidence() -> tuple[FlowGraph, object]:
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(20, 0x1100, succs=(30,), preds=(10,)),
            30: _block(30, 0x1400, succs=(20,), preds=(20,)),
            40: _block(40, 0x1200, succs=(), preds=()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    source_identity = _identity(0x1100)
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=3,
        atomic_group_id="canonical-semantic:g3",
        route_proofs=(
            SemanticRouteProof(
                proof_id="state-assignment@0x1100",
                atomic_group_id="canonical-semantic:g3",
                proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
                shape=SemanticRouteShape.DIRECT,
                source_identity=source_identity,
                source_anchor_ea=0x1100,
                delivery_region=NativeEaInterval(0x1100, 0x1101),
                destinations=(
                    SemanticRouteDestination(
                        role=SemanticEdgeRole.DIRECT,
                        state_constant=0xAABBCCDD,
                        target_identity=_identity(0x1200),
                        target_anchor_ea=0x1200,
                    ),
                ),
                state_write=SemanticStateWriteProof(
                    identity=source_identity,
                    instruction_ea=0x1100,
                    state_variable=StorageIdentity(
                        StorageIdentityKind.REGISTER,
                        20,
                    ),
                    width=4,
                    state_constant=0xAABBCCDD,
                    corridor_instruction_eas=(0x1100,),
                    authority_transfer_ea=None,
                    preserved_call_instruction_eas=(),
                ),
            ),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    return graph, bound


def test_direct_semantic_route_builds_closed_portable_fragment_plan() -> None:
    graph, bound = _direct_bound_evidence()

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    assert (
        plan.publication_purpose
        is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
    )
    assert plan.atomic_group_id == "canonical-semantic:g3"
    assert len(plan.roots) == 1
    root = plan.block(plan.roots[0])
    assert root.role is FragmentBlockRole.REPLACEMENT
    assert root.semantic_anchor_ea == 0x1100
    assert plan.block(str(root.replaces_block_id)).role is FragmentBlockRole.ORIGINAL
    assert tuple(
        (edge.role, plan.block(edge.target_block_id).semantic_anchor_ea)
        for edge in plan.operations[0].edges
    ) == ((SemanticEdgeRole.DIRECT, 0x1200),)
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for block_id in plan.prohibited_dispatcher_blocks
    ) == (0x1400,)
    assert any(
        block.role is FragmentBlockRole.EXTERNAL and block.semantic_anchor_ea == 0x1000
        for block in plan.blocks
    )
    assert all("serial" not in block.block_id for block in plan.blocks)


def _live_source_detached_target_case() -> tuple[
    FlowGraph,
    FragmentPlan,
    CanonicalSemanticEvidence,
]:
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(20, 0x1100, succs=(90,), preds=(10,)),
            90: _block(90, 0x1400, succs=(20,), preds=(20,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    detached_body_id = "native-body:detached"
    normalization_plan = FragmentPlan(
        plan_id="frontend-normalization:g3:complete",
        atomic_group_id="frontend-normalization:g3",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=NATIVE_KEY,
        blocks=(
            FragmentBlock(
                block_id="live-route-source",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x1100,
                stable_identity=_identity(0x1100),
            ),
            FragmentBlock(
                block_id="unrelated-original",
                role=FragmentBlockRole.ORIGINAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x1300,
                stable_identity=_identity(0x1300),
            ),
            FragmentBlock(
                block_id="unrelated-replacement",
                role=FragmentBlockRole.REPLACEMENT,
                materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
                semantic_anchor_ea=0x1300,
                stable_identity=_identity(0x1300),
                replaces_block_id="unrelated-original",
            ),
            FragmentBlock(
                block_id="unrelated-exit",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x1500,
                stable_identity=_identity(0x1500),
            ),
            FragmentBlock(
                block_id="detached-target",
                role=FragmentBlockRole.IMPORTED,
                materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
                semantic_anchor_ea=0x1200,
                stable_identity=_identity(0x1200),
                native_body_id=detached_body_id,
            ),
        ),
        roots=("unrelated-replacement",),
        owned_originals=("unrelated-original",),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="unrelated-normalization",
                source_block_id="unrelated-replacement",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="unrelated-exit",
                    ),
                ),
            ),
        ),
        work_item_scope=FragmentWorkItemScope(
            work_item_id="frontend-normalization:g3:complete",
            selected_obligation_ids=("unrelated-normalization",),
            remaining_obligation_ids=("detached-normalization",),
            unreachable_obligation_ids=(),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=detached_body_id,
                block_ids=("detached-target",),
                entry_block_ids=("detached-target",),
                terminal_block_ids=("detached-target",),
                native_ranges=(NativeEaInterval(0x1200, 0x1201),),
                proof_ids=("detached-normalization",),
            ),
        ),
    )
    source_identity = _identity(0x1100)
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=3,
        atomic_group_id="canonical-semantic:g3:route@0x1100",
        route_proofs=(
            SemanticRouteProof(
                proof_id="state-assignment@0x1100",
                atomic_group_id="canonical-semantic:g3:route@0x1100",
                proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
                shape=SemanticRouteShape.DIRECT,
                source_identity=source_identity,
                source_anchor_ea=0x1100,
                delivery_region=NativeEaInterval(0x1100, 0x1101),
                destinations=(
                    SemanticRouteDestination(
                        role=SemanticEdgeRole.DIRECT,
                        state_constant=0xAABBCCDD,
                        target_identity=_identity(0x1200),
                        target_anchor_ea=0x1200,
                    ),
                ),
                state_write=SemanticStateWriteProof(
                    identity=source_identity,
                    instruction_ea=0x1100,
                    state_variable=StorageIdentity(
                        StorageIdentityKind.REGISTER,
                        20,
                    ),
                    width=4,
                    state_constant=0xAABBCCDD,
                    corridor_instruction_eas=(0x1100,),
                    authority_transfer_ea=None,
                    preserved_call_instruction_eas=(),
                ),
            ),
        ),
    )
    return graph, normalization_plan, evidence


def _omitted_delivery_source_case() -> tuple[
    FlowGraph,
    FragmentPlan,
    CanonicalSemanticEvidence,
]:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    delivery_ea = 0x1110
    retained_source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1100, delivery_ea),
        native_key=NATIVE_KEY,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=tuple(
            replace(
                block,
                semantic_anchor_ea=delivery_ea,
                stable_identity=retained_source_identity,
            )
            if block.block_id == "live-route-source"
            else block
            for block in normalization_plan.blocks
        ),
    )
    (proof,) = evidence.route_proofs
    evidence = replace(
        evidence,
        route_proofs=(
            replace(
                proof,
                proof_id=f"state-assignment@0x{delivery_ea:X}",
                source_identity=_identity(delivery_ea),
                source_anchor_ea=delivery_ea,
                delivery_region=NativeEaInterval(delivery_ea, delivery_ea + 1),
                state_write=replace(
                    proof.state_write,
                    identity=_identity(0x1100),
                    instruction_ea=0x1100,
                    corridor_instruction_eas=(0x1100, delivery_ea),
                ),
            ),
        ),
    )
    return graph, normalization_plan, evidence


def _normalization_authority(
    plan: FragmentPlan,
    evidence: CanonicalSemanticEvidence,
    *,
    published_operation_ids: tuple[str, ...] | None = None,
) -> NormalizationWorkItemAuthority:
    scope = plan.work_item_scope
    assert scope is not None
    return NormalizationWorkItemAuthority(
        evidence_generation=evidence.generation,
        publication_revision=1,
        source_plan_id=plan.plan_id,
        source_atomic_group_id=plan.atomic_group_id,
        work_item_id=scope.work_item_id,
        published_operation_ids=(
            scope.selected_obligation_ids
            if published_operation_ids is None
            else published_operation_ids
        ),
        selected_obligation_ids=scope.selected_obligation_ids,
        remaining_obligation_ids=scope.remaining_obligation_ids,
        unreachable_obligation_ids=scope.unreachable_obligation_ids,
    )


def test_canonical_route_composes_live_source_with_detached_target_body() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    assert (
        plan.publication_purpose
        is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
    )
    assert plan.work_item_scope is None
    assert tuple(plan.block(root).semantic_anchor_ea for root in plan.roots) == (
        0x1100,
    )
    root = plan.block(plan.roots[0])
    assert root.role is FragmentBlockRole.REPLACEMENT
    assert plan.block(str(root.replaces_block_id)).role is FragmentBlockRole.ORIGINAL
    assert tuple(
        block.semantic_anchor_ea
        for block in plan.blocks
        if block.role is FragmentBlockRole.EXTERNAL
    ) == (0x1000, 0x1400)
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for block_id in plan.prohibited_dispatcher_blocks
    ) == (0x1400,)
    assert len(plan.operations) == 1
    operation = plan.operations[0]
    assert plan.block(operation.source_block_id) == root
    assert tuple(
        (edge.role, plan.block(edge.target_block_id).semantic_anchor_ea)
        for edge in operation.edges
    ) == ((SemanticEdgeRole.DIRECT, 0x1200),)
    assert len(plan.native_bodies) == 1
    native_body = plan.native_bodies[0]
    assert native_body.entry_block_ids == native_body.terminal_block_ids
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for block_id in native_body.entry_block_ids
    ) == (0x1200,)
    assert all(
        block.semantic_anchor_ea not in {0x1300, 0x1500} for block in plan.blocks
    )


def test_detached_semantic_consumer_supersedes_raw_dispatcher_atomically() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    (native_body,) = normalization_plan.native_bodies
    consumer_id = native_body.entry_block_ids[0]
    consumer_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1200, 0x1210),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1200,),
    )
    taken = FragmentBlock(
        block_id="detached-taken",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=native_body.body_id,
    )
    fallthrough = FragmentBlock(
        block_id="detached-fallthrough",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1260,
        stable_identity=_identity(0x1260),
        native_body_id=native_body.body_id,
    )
    raw_dispatcher = FragmentBlock(
        block_id="raw-dispatcher",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1400,
        stable_identity=_identity(0x1400),
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *(
                replace(block, stable_identity=consumer_identity)
                if block.block_id == consumer_id
                else block
                for block in normalization_plan.blocks
            ),
            taken,
            fallthrough,
            raw_dispatcher,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="raw-consumer-dispatch",
                source_block_id=consumer_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    taken.block_id,
                    fallthrough.block_id,
                ),
                terminal_block_ids=(
                    taken.block_id,
                    fallthrough.block_id,
                ),
                native_ranges=(
                    NativeEaInterval(0x1200, 0x1210),
                    NativeEaInterval(0x1250, 0x1251),
                    NativeEaInterval(0x1260, 0x1261),
                ),
                proof_ids=(
                    *native_body.proof_ids,
                    "raw-consumer-dispatch",
                ),
            ),
        ),
    )
    (direct_proof,) = evidence.route_proofs
    portable_producer_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1110),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100,),
    )
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    carrier_storage = StorageIdentity(StorageIdentityKind.STACK, 0x44)
    state_choice = SemanticRouteProof(
        proof_id="state-choice@0x1200",
        atomic_group_id=evidence.atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=consumer_identity,
        source_anchor_ea=0x1200,
        source_owner_identity=consumer_identity,
        source_owner_anchor_ea=0x1200,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=0x22,
                target_identity=taken.stable_identity,
                target_anchor_ea=0x1250,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=0x33,
                target_identity=fallthrough.stable_identity,
                target_anchor_ea=0x1260,
            ),
        ),
        predicate=SemanticPredicateProof(
            kind=SemanticPredicateKind.STORAGE_EQUALS,
            origin=SemanticCorridorPoint(portable_producer_identity, 0x1100),
            consumer=SemanticCorridorPoint(consumer_identity, 0x1200),
            corridor=(
                SemanticCorridorPoint(portable_producer_identity, 0x1100),
                SemanticCorridorPoint(consumer_identity, 0x1200),
            ),
            storage_identity=predicate_storage,
            width=4,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id="entry-state",
                definition=SemanticCorridorPoint(
                    portable_producer_identity,
                    0x1100,
                ),
                consumers=(SemanticCorridorPoint(consumer_identity, 0x1200),),
                corridor=(
                    SemanticCorridorPoint(
                        portable_producer_identity,
                        0x1100,
                    ),
                    SemanticCorridorPoint(consumer_identity, 0x1200),
                ),
                storage_identity=carrier_storage,
                width=4,
                state_values=(0x22, 0x33),
                permitted_write_eas=frozenset({0x1100}),
            ),
        ),
    )
    evidence = replace(
        evidence,
        route_proofs=(direct_proof, state_choice),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    operations = {operation.operation_id: operation for operation in plan.operations}
    assert "raw-consumer-dispatch" not in operations
    semantic_operation = operations[f"route:{state_choice.proof_id}"]
    assert semantic_operation.predicate_anchor_ea == 0x1200
    assert semantic_operation.storage_predicate_materialization == (
        FragmentStoragePredicateMaterialization(
            predicate_kind=PredicateKind.EQ,
            storage_identity=predicate_storage,
            width=4,
            compare_constant=0,
            cut_after_ea=0x1200,
        )
    )
    assert tuple(
        plan.block(edge.target_block_id).semantic_anchor_ea
        for edge in semantic_operation.edges
    ) == (0x1250, 0x1260)
    assert all(
        plan.block(edge.target_block_id).semantic_anchor_ea != 0x1400
        for operation in plan.operations
        for edge in operation.edges
    )
    assert {obligation.role for obligation in plan.data_flow_obligations} == {
        FragmentDataFlowRole.CONDITION,
        FragmentDataFlowRole.CARRIER,
    }
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for body in plan.native_bodies
        for block_id in body.block_ids
    ) == (0x1200, 0x1250, 0x1260)


def test_nested_imported_state_assignment_supersedes_raw_dispatcher_edge() -> None:
    graph, normalization_plan, root_evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(30, 0x1300, succs=(), preds=()),
        },
    )
    (native_body,) = normalization_plan.native_bodies
    route_source = FragmentBlock(
        block_id="nested-route-source",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1210,
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x1210, 0x1220),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(0x1210, 0x1212, 0x1214, 0x1218),
        ),
        native_body_id=native_body.body_id,
    )
    route_target = FragmentBlock(
        block_id="nested-route-target",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=native_body.body_id,
    )
    raw_dispatcher = FragmentBlock(
        block_id="nested-raw-dispatcher",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1300,
        stable_identity=_identity(0x1300),
        native_body_id=native_body.body_id,
    )
    raw_dispatcher_terminal = FragmentBlock(
        block_id="nested-raw-dispatcher-terminal",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1310,
        stable_identity=_identity(0x1310),
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            route_source,
            route_target,
            raw_dispatcher,
            raw_dispatcher_terminal,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="native-body-edge@0x1200",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=route_source.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-indirect-transfer@0x121F",
                source_block_id=route_source.block_id,
                predicate_anchor_ea=0x1218,
                computed_branch_normalization=FragmentComputedBranchNormalization(
                    predicate_kind=PredicateKind.SLT,
                    normalization_start_ea=0x1214,
                    condition_producer_ea=0x1212,
                    unresolved_transfer_ea=0x121F,
                    relocated_instruction_eas=(0x121A, 0x121C),
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id=route_target.block_id,
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1300",
                source_block_id=raw_dispatcher.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_dispatcher_terminal.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    route_source.block_id,
                    route_target.block_id,
                    raw_dispatcher.block_id,
                    raw_dispatcher_terminal.block_id,
                ),
                terminal_block_ids=(
                    route_target.block_id,
                    raw_dispatcher_terminal.block_id,
                ),
                native_ranges=(
                    NativeEaInterval(0x1200, 0x1201),
                    NativeEaInterval(0x1210, 0x1220),
                    NativeEaInterval(0x1250, 0x1251),
                    NativeEaInterval(0x1300, 0x1301),
                    NativeEaInterval(0x1310, 0x1311),
                ),
                proof_ids=(
                    *native_body.proof_ids,
                    "native-body-edge@0x1200",
                    "native-indirect-transfer@0x121F",
                    "native-body-edge@0x1300",
                ),
            ),
        ),
    )
    (root_proof,) = root_evidence.route_proofs
    nested_proof = SemanticRouteProof(
        proof_id="state-assignment@0x1218",
        atomic_group_id=root_evidence.atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x1218, 0x1220),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(0x1218,),
        ),
        source_anchor_ea=0x1218,
        delivery_region=NativeEaInterval(0x1214, 0x1220),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=0x44,
                target_identity=route_target.stable_identity,
                target_anchor_ea=0x1250,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x1210, 0x1218),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=(0x1210,),
            ),
            instruction_ea=0x1210,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0x44,
            corridor_instruction_eas=(0x1210, 0x1212, 0x1218),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )
    available_evidence = replace(
        root_evidence,
        route_proofs=(root_proof, nested_proof),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        root_evidence,
        available_evidence=available_evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            root_evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    operations = {operation.operation_id: operation for operation in plan.operations}
    assert "native-indirect-transfer@0x121F" not in operations
    nested_operation = operations[f"route:{nested_proof.proof_id}"]
    assert nested_operation.source_block_id == route_source.block_id
    assert nested_operation.direct_transfer_rewrite is not None
    assert nested_operation.direct_transfer_rewrite.route_proof_id == (
        nested_proof.proof_id
    )
    assert nested_operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x1218
    assert nested_operation.direct_transfer_rewrite.proof_corridor_instruction_eas == (
        0x1210,
        0x1212,
        0x1218,
    )
    assert nested_operation.direct_transfer_rewrite.superseded_instruction_eas == (
        0x1218,
    )
    assert (
        nested_operation.direct_transfer_rewrite.source_computed_branch_normalization
        is not None
    )
    assert (
        nested_operation.direct_transfer_rewrite.source_computed_branch_normalization.relocated_instruction_eas
        == (0x121A, 0x121C)
    )
    assert (
        nested_operation.direct_transfer_rewrite.source_predicate_anchor_ea == 0x1218
    )
    assert tuple(
        (
            edge.role,
            plan.block(edge.target_block_id).semantic_anchor_ea,
        )
        for edge in nested_operation.edges
    ) == ((SemanticEdgeRole.DIRECT, 0x1250),)
    assert all(
        edge.target_block_id != raw_dispatcher.block_id
        for operation in plan.operations
        for edge in operation.edges
    )
    (planned_native_body,) = plan.native_bodies
    assert f"route:{nested_proof.proof_id}" in planned_native_body.proof_ids


def test_nested_imported_state_assignments_reach_fixpoint() -> None:
    graph, normalization_plan, root_evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(30, 0x1300, succs=(), preds=()),
        },
    )
    (native_body,) = normalization_plan.native_bodies
    first_source = FragmentBlock(
        block_id="nested-route-source-1",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1210,
        stable_identity=_wide_identity(0x1210, 0x1220),
        native_body_id=native_body.body_id,
    )
    second_source = FragmentBlock(
        block_id="nested-route-source-2",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1220,
        stable_identity=_wide_identity(0x1220, 0x1230),
        native_body_id=native_body.body_id,
    )
    route_target = FragmentBlock(
        block_id="nested-route-target",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=native_body.body_id,
    )
    raw_dispatcher = FragmentBlock(
        block_id="nested-raw-dispatcher",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1300,
        stable_identity=_identity(0x1300),
        native_body_id=native_body.body_id,
    )
    raw_terminal = FragmentBlock(
        block_id="nested-raw-terminal",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1310,
        stable_identity=_identity(0x1310),
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            first_source,
            second_source,
            route_target,
            raw_dispatcher,
            raw_terminal,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="native-body-edge@0x1200",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=first_source.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1218",
                source_block_id=first_source.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1228",
                source_block_id=second_source.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1300",
                source_block_id=raw_dispatcher.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_terminal.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    first_source.block_id,
                    second_source.block_id,
                    route_target.block_id,
                    raw_dispatcher.block_id,
                    raw_terminal.block_id,
                ),
                terminal_block_ids=(route_target.block_id, raw_terminal.block_id),
                native_ranges=(
                    NativeEaInterval(0x1200, 0x1201),
                    NativeEaInterval(0x1210, 0x1220),
                    NativeEaInterval(0x1220, 0x1230),
                    NativeEaInterval(0x1250, 0x1251),
                    NativeEaInterval(0x1300, 0x1301),
                    NativeEaInterval(0x1310, 0x1311),
                ),
                proof_ids=(
                    *native_body.proof_ids,
                    "native-body-edge@0x1200",
                    "native-body-edge@0x1218",
                    "native-body-edge@0x1228",
                    "native-body-edge@0x1300",
                ),
            ),
        ),
    )

    def nested_proof(
        *,
        proof_id: str,
        write_ea: int,
        delivery_ea: int,
        target: FragmentBlock,
        state_constant: int,
    ) -> SemanticRouteProof:
        return SemanticRouteProof(
            proof_id=proof_id,
            atomic_group_id=root_evidence.atomic_group_id,
            proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
            shape=SemanticRouteShape.DIRECT,
            source_identity=_identity(delivery_ea),
            source_anchor_ea=delivery_ea,
            delivery_region=NativeEaInterval(delivery_ea, delivery_ea + 1),
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=target.stable_identity,
                    target_anchor_ea=target.semantic_anchor_ea,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=_identity(write_ea),
                instruction_ea=write_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(write_ea, delivery_ea),
                authority_transfer_ea=None,
                preserved_call_instruction_eas=(),
            ),
        )

    first_proof = nested_proof(
        proof_id="state-assignment@0x1218",
        write_ea=0x1210,
        delivery_ea=0x1218,
        target=second_source,
        state_constant=0x44,
    )
    second_proof = nested_proof(
        proof_id="state-assignment@0x1228",
        write_ea=0x1220,
        delivery_ea=0x1228,
        target=route_target,
        state_constant=0x55,
    )
    available_evidence = replace(
        root_evidence,
        route_proofs=(*root_evidence.route_proofs, first_proof, second_proof),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        root_evidence,
        available_evidence=available_evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            root_evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    operations = {operation.operation_id: operation for operation in plan.operations}
    assert f"route:{first_proof.proof_id}" in operations
    assert f"route:{second_proof.proof_id}" in operations
    assert "native-body-edge@0x1218" not in operations
    assert "native-body-edge@0x1228" not in operations
    assert all(
        plan.block(edge.target_block_id).semantic_anchor_ea != 0x1300
        for operation in plan.operations
        for edge in operation.edges
    )


def test_published_boundary_reimports_owned_split_and_closes_route() -> None:
    graph, normalization_plan, root_evidence = _live_source_detached_target_case()
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(90,), preds=()),
            30: _block(
                30,
                0x1005,
                succs=(90,),
                preds=(90,),
                insn_eas=(0x1200, 0x1210),
            ),
            90: _block(90, 0x1400, succs=(30,), preds=(10, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    current_identity_by_serial = _current_identity_authority(graph)
    current_identity_by_serial[30] = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1200, 0x1211),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1200, 0x1210),
    )
    (native_body,) = normalization_plan.native_bodies
    route_source = FragmentBlock(
        block_id="boundary-route-source",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1210,
        stable_identity=_identity(0x1210),
        native_body_id=native_body.body_id,
    )
    raw_dispatcher = FragmentBlock(
        block_id="boundary-raw-dispatcher",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1300,
        stable_identity=_identity(0x1300),
        native_body_id=native_body.body_id,
    )
    raw_terminal = FragmentBlock(
        block_id="boundary-raw-terminal",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1310,
        stable_identity=_identity(0x1310),
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            route_source,
            raw_dispatcher,
            raw_terminal,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="boundary-call-fallthrough@0x1200",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CALL_FALLTHROUGH,
                        target_block_id=route_source.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1210",
                source_block_id=route_source.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1300",
                source_block_id=raw_dispatcher.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_terminal.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    route_source.block_id,
                    raw_dispatcher.block_id,
                    raw_terminal.block_id,
                ),
                terminal_block_ids=(raw_terminal.block_id,),
                native_ranges=(
                    NativeEaInterval(0x1200, 0x1201),
                    NativeEaInterval(0x1210, 0x1211),
                    NativeEaInterval(0x1300, 0x1301),
                    NativeEaInterval(0x1310, 0x1311),
                ),
                proof_ids=(
                    *native_body.proof_ids,
                    "boundary-call-fallthrough@0x1200",
                    "native-body-edge@0x1210",
                    "native-body-edge@0x1300",
                ),
            ),
        ),
    )
    nested_proof = SemanticRouteProof(
        proof_id="state-assignment@0x1210",
        atomic_group_id=root_evidence.atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=_identity(0x1210),
        source_anchor_ea=0x1210,
        delivery_region=NativeEaInterval(0x1210, 0x1211),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=0x44,
                target_identity=_identity(0x1200),
                target_anchor_ea=0x1200,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=_identity(0x1210),
            instruction_ea=0x1210,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0x44,
            corridor_instruction_eas=(0x1210,),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )
    available_evidence = replace(
        root_evidence,
        route_proofs=(nested_proof,),
    )

    plan = compose_canonical_semantic_boundary_fragment_plan(
        graph,
        normalization_plan,
        boundary_anchor_ea=0x1200,
        available_evidence=available_evidence,
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=_normalization_authority(
            normalization_plan,
            available_evidence,
        ),
        prohibited_dispatcher_serials=(90,),
        temporary_dispatcher_entry_port_obligation_id=("publish-semantic-entry@0x1200"),
    )

    (root_id,) = plan.roots
    root = plan.block(root_id)
    assert root.role is FragmentBlockRole.REPLACEMENT
    assert root.semantic_anchor_ea == 0x1200
    original = plan.block(str(root.replaces_block_id))
    assert original.role is FragmentBlockRole.ORIGINAL
    assert original.semantic_anchor_ea == 0x1200
    operations = {operation.operation_id: operation for operation in plan.operations}
    root_operation = operations["boundary-call-fallthrough@0x1200"]
    assert root_operation.source_block_id == root_id
    assert tuple(edge.role for edge in root_operation.edges) == (
        SemanticEdgeRole.CALL_FALLTHROUGH,
    )
    route_operation = operations[f"route:{nested_proof.proof_id}"]
    assert route_operation.direct_transfer_rewrite is not None
    assert tuple(
        plan.block(edge.target_block_id).semantic_anchor_ea
        for edge in route_operation.edges
    ) == (0x1200,)
    (planned_body,) = plan.native_bodies
    assert tuple(
        plan.block(block_id).semantic_anchor_ea for block_id in planned_body.block_ids
    ) == (0x1210,)
    assert planned_body.entry_block_ids == (route_source.block_id,)
    assert all(
        block.semantic_anchor_ea not in {0x1300, 0x1310}
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
    )
    assert any(
        block.role is FragmentBlockRole.EXTERNAL and block.semantic_anchor_ea == 0x1400
        for block in plan.blocks
    )
    (boundary_port,) = plan.boundary_ports
    assert boundary_port.kind is FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_ENTRY
    assert boundary_port.root_block_id == root_id
    assert plan.block(boundary_port.predecessor_block_id).semantic_anchor_ea == 0x1400
    assert boundary_port.retirement_obligation_id == "publish-semantic-entry@0x1200"


@pytest.mark.parametrize("terminal_has_live_owner", (False, True))
def test_published_boundary_projects_nested_terminal_route_atomically(
    terminal_has_live_owner: bool,
) -> None:
    graph, normalization_plan, root_evidence = _live_source_detached_target_case()
    blocks = {
        10: _block(10, 0x1000, succs=(90,), preds=()),
        30: _block(
            30,
            0x1200,
            succs=(90,),
            preds=(90,),
            insn_eas=(0x1200, 0x1210, 0x1215, 0x1218),
        ),
        90: _block(90, 0x1400, succs=(30,), preds=(10, 30)),
    }
    if terminal_has_live_owner:
        blocks[40] = _block(
            40,
            0x1320,
            succs=(),
            preds=(),
            insn_eas=(0x1320, 0x1328),
        )
    graph = FlowGraph(
        blocks=blocks,
        entry_serial=10,
        func_ea=0x1000,
    )
    (native_body,) = normalization_plan.native_bodies
    staged_capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1210, 0x1219),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1210, 0x1218),
    )
    capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1210, 0x1219),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1210, 0x1215, 0x1218),
    )
    staged_terminal_identity = StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x1320, 0x1321),
            NativeEaInterval(0x1328, 0x1329),
        ),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1320,),
    )
    terminal_identity = StableBlockIdentity.from_instruction_eas(
        (0x1320, 0x1328),
        native_key=NATIVE_KEY,
    )
    route_source = FragmentBlock(
        block_id="boundary-terminal-source",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1210,
        stable_identity=staged_capture_identity,
        native_body_id=native_body.body_id,
    )
    raw_dispatcher = FragmentBlock(
        block_id="boundary-terminal-dispatcher",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1300,
        stable_identity=_identity(0x1300),
        native_body_id=native_body.body_id,
    )
    terminal_target = FragmentBlock(
        block_id="boundary-terminal-target",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1320,
        stable_identity=staged_terminal_identity,
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            route_source,
            raw_dispatcher,
            terminal_target,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="boundary-terminal-fallthrough@0x1200",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CALL_FALLTHROUGH,
                        target_block_id=route_source.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-indirect-transfer@0x1218",
                source_block_id=route_source.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-body-edge@0x1300",
                source_block_id=raw_dispatcher.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=terminal_target.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    route_source.block_id,
                    raw_dispatcher.block_id,
                    terminal_target.block_id,
                ),
                terminal_block_ids=(terminal_target.block_id,),
                native_ranges=(
                    NativeEaInterval(0x1200, 0x1201),
                    NativeEaInterval(0x1210, 0x1219),
                    NativeEaInterval(0x1300, 0x1301),
                    NativeEaInterval(0x1320, 0x1321),
                    NativeEaInterval(0x1328, 0x1329),
                ),
                proof_ids=(
                    *native_body.proof_ids,
                    "boundary-terminal-fallthrough@0x1200",
                    "native-indirect-transfer@0x1218",
                    "native-body-edge@0x1300",
                ),
            ),
        ),
    )
    state_constant = 0x19A7218A
    carrier = TerminalReturnCarrierEvidence(
        request=TerminalReturnCarrierRequest(
            source_handler_ea=0x1210,
            terminal_target_ea=0x1320,
            state_var_reg=20,
            state_constant=state_constant,
        ),
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        state_write_ea=0x1210,
        carrier_ea=0x1215,
        terminal_return_ea=0x1328,
        operation=ValueOpKind.MOVE,
        source=TerminalReturnCarrierSource(
            kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
            width=4,
            storage_identity=StorageIdentity(
                StorageIdentityKind.GLOBAL,
                0x48B8A4,
            ),
        ),
        return_width=4,
        corridor_instruction_eas=(0x1210, 0x1215),
    )
    terminal_proof = SemanticRouteProof(
        proof_id="terminal-return@0x1218:0x19A7218A",
        atomic_group_id=root_evidence.atomic_group_id,
        proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
        shape=SemanticRouteShape.DIRECT,
        source_identity=capture_identity,
        source_anchor_ea=0x1218,
        delivery_region=NativeEaInterval(0x1218, 0x1219),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=state_constant,
                target_identity=staged_terminal_identity,
                target_anchor_ea=0x1320,
                terminal=True,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=capture_identity,
            instruction_ea=0x1210,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=state_constant,
            corridor_instruction_eas=(0x1210, 0x1215, 0x1218),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
        terminal_return_carrier=carrier,
    )
    available_evidence = replace(
        root_evidence,
        route_proofs=(terminal_proof,),
    )

    plan = compose_canonical_semantic_boundary_fragment_plan(
        graph,
        normalization_plan,
        boundary_anchor_ea=0x1200,
        available_evidence=available_evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            available_evidence,
        ),
        prohibited_dispatcher_serials=(90,),
        temporary_dispatcher_entry_port_obligation_id=("publish-semantic-entry@0x1200"),
    )

    operation = next(
        item
        for item in plan.operations
        if item.operation_id == f"route:{terminal_proof.proof_id}"
    )
    source = plan.block(operation.source_block_id)
    assert source.stable_identity is not None
    assert source.stable_identity.exact_instruction_eas == frozenset(
        {0x1210, 0x1215, 0x1218}
    )
    assert source.block_id == (
        f"native[{stable_block_identity_token(source.stable_identity)}]:imported"
    )
    assert operation.direct_transfer_rewrite is not None
    assert len(plan.return_carriers) == 1
    assert plan.return_carriers[0].block_id == operation.source_block_id
    assert len(plan.terminal_returns) == 1
    assert operation.edges[0].target_block_id == plan.terminal_returns[0].block_id
    terminal = plan.block(plan.terminal_returns[0].block_id)
    assert terminal.role is FragmentBlockRole.IMPORTED
    assert terminal.stable_identity is not None
    assert terminal.stable_identity.exact_instruction_eas == frozenset({0x1320, 0x1328})
    assert terminal.block_id == (
        f"native[{stable_block_identity_token(terminal.stable_identity)}]:imported"
    )
    assert len(plan.terminal_routes) == 1
    assert plan.terminal_routes[0].operation_id == operation.operation_id
    assert all(
        block.semantic_anchor_ea != 0x1300
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
    )


def test_nested_terminal_staging_rejection_inventories_both_endpoints() -> None:
    source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1210, 0x1215, 0x1218),
        native_key=NATIVE_KEY,
    )
    destination_identity = StableBlockIdentity.from_instruction_eas(
        (0x1320, 0x1328),
        native_key=NATIVE_KEY,
    )
    source = FragmentBlock(
        block_id="terminal-source",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1210,
        stable_identity=source_identity,
        native_body_id="terminal-body",
    )
    destination = FragmentBlock(
        block_id="terminal-destination",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1320,
        stable_identity=destination_identity,
    )
    state_constant = 0x19A7218A
    carrier = TerminalReturnCarrierEvidence(
        request=TerminalReturnCarrierRequest(
            source_handler_ea=0x1210,
            terminal_target_ea=0x1320,
            state_var_reg=20,
            state_constant=state_constant,
        ),
        capture_identity=source_identity,
        terminal_identity=destination_identity,
        state_write_ea=0x1210,
        carrier_ea=0x1215,
        terminal_return_ea=0x1328,
        operation=ValueOpKind.MOVE,
        source=TerminalReturnCarrierSource(
            kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
            width=4,
            storage_identity=StorageIdentity(
                StorageIdentityKind.GLOBAL,
                0x48B8A4,
            ),
        ),
        return_width=4,
        corridor_instruction_eas=(0x1210, 0x1215),
    )
    proof = SemanticRouteProof(
        proof_id="terminal-return@0x1218:0x19A7218A",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
        shape=SemanticRouteShape.DIRECT,
        source_identity=source_identity,
        source_anchor_ea=0x1218,
        delivery_region=NativeEaInterval(0x1218, 0x1219),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=state_constant,
                target_identity=destination_identity,
                target_anchor_ea=0x1320,
                terminal=True,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=source_identity,
            instruction_ea=0x1210,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=state_constant,
            corridor_instruction_eas=(0x1210, 0x1215, 0x1218),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
        terminal_return_carrier=carrier,
    )
    operation = FragmentOperation(
        operation_id=f"route:{proof.proof_id}",
        source_block_id=source.block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=destination.block_id,
            ),
        ),
    )

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        canonical_fragment._nested_terminal_effects(
            (source, destination),
            (operation,),
            (proof,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "nested_terminal_route_staged_owner_missing"
    assert rejection.anchor_ea == 0x1218
    assert rejection.payload == {
        "route_proof_id": proof.proof_id,
        "operation_id": operation.operation_id,
        "source_block_id": source.block_id,
        "source_role": FragmentBlockRole.IMPORTED.value,
        "source_identity": source_identity.diagnostic_label(),
        "destination_block_id": destination.block_id,
        "destination_role": FragmentBlockRole.EXTERNAL.value,
        "destination_identity": destination_identity.diagnostic_label(),
        "target_block_id": destination.block_id,
    }


def test_published_boundary_rejection_records_prohibited_predecessor() -> None:
    _graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(90,), preds=()),
            30: _block(30, 0x1200, succs=(90,), preds=(90,)),
            90: _block(90, 0x1400, succs=(30,), preds=(10, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    current_identity_by_serial = _current_identity_authority(graph)

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        compose_canonical_semantic_boundary_fragment_plan(
            graph,
            normalization_plan,
            boundary_anchor_ea=0x1200,
            available_evidence=evidence,
            current_identity_by_serial=current_identity_by_serial,
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "published_boundary_predecessor_missing"
    assert rejection.anchor_ea == 0x1200
    assert rejection.payload == {
        "boundary_block_id": "detached-target",
        "boundary_identity": _identity(0x1200).diagnostic_label(),
        "current_owner": "blk30@0x1200",
        "current_owner_identity": _identity(0x1200).diagnostic_label(),
        "incoming_predecessors": (
            {
                "block": "blk90@0x1400",
                "prohibited": True,
                "stable_identity": _identity(0x1400).diagnostic_label(),
            },
        ),
    }


def test_published_boundary_missing_route_records_projection_inventory() -> None:
    _graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(30,), preds=()),
            30: _block(30, 0x1200, succs=(90,), preds=(10, 90)),
            90: _block(90, 0x1400, succs=(30,), preds=(30,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        compose_canonical_semantic_boundary_fragment_plan(
            graph,
            normalization_plan,
            boundary_anchor_ea=0x1200,
            available_evidence=evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "published_boundary_semantic_route_missing"
    assert rejection.anchor_ea == 0x1200
    assert rejection.payload["boundary_block_id"] == "detached-target"
    assert (
        rejection.payload["boundary_identity"] == _identity(0x1200).diagnostic_label()
    )
    assert rejection.payload["target_block_ids"] == ("detached-target",)
    assert rejection.payload["target_operation_ids"] == ()
    (decision,) = rejection.payload["nested_state_route_projection"]
    assert decision["route_proof_id"] == "state-assignment@0x1100"


def test_published_boundary_owner_mismatch_records_overlapping_identities() -> None:
    _graph, normalization_plan, evidence = _live_source_detached_target_case()
    boundary_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1200, 0x1210),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1200,),
    )
    overlapping_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1204, 0x1214),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1204,),
    )
    incoming_operation = replace(
        normalization_plan.operations[0],
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id="detached-target",
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id="unrelated-exit",
            ),
        ),
        predicate_anchor_ea=0x1300,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=tuple(
            replace(block, stable_identity=boundary_identity)
            if block.block_id == "detached-target"
            else block
            for block in normalization_plan.blocks
        ),
        native_bodies=tuple(
            replace(body, native_ranges=(NativeEaInterval(0x1200, 0x1210),))
            for body in normalization_plan.native_bodies
        ),
        operations=(incoming_operation,),
    )
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(90,), preds=()),
            30: _block(30, 0x1204, succs=(90,), preds=(90,)),
            40: _block(40, 0x1300, succs=(), preds=()),
            90: _block(90, 0x1400, succs=(30,), preds=(10, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    current_identity_by_serial = _current_identity_authority(graph)
    current_identity_by_serial[30] = overlapping_identity

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        compose_canonical_semantic_boundary_fragment_plan(
            graph,
            normalization_plan,
            boundary_anchor_ea=0x1200,
            available_evidence=evidence,
            current_identity_by_serial=current_identity_by_serial,
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "published_boundary_current_owner_count_mismatch"
    assert rejection.anchor_ea == 0x1200
    assert rejection.payload == {
        "boundary_block_id": "detached-target",
        "boundary_identity": boundary_identity.diagnostic_label(),
        "owner_labels": (),
        "current_identity_inventory": (
            {
                "block": "blk30@0x1204",
                "contains_anchor": False,
                "overlaps_boundary_identity": True,
                "stable_identity": overlapping_identity.diagnostic_label(),
            },
        ),
        "normalization_incoming_operations": (
            {
                "operation_id": "unrelated-normalization",
                "source_block_id": "unrelated-replacement",
                "source_anchor_ea": "0x1300",
                "source_identity": _identity(0x1300).diagnostic_label(),
                "source_owner_labels": ("blk40@0x1300",),
                "source_current_identity_inventory": (
                    {
                        "block": "blk40@0x1300",
                        "contains_anchor": True,
                        "overlaps_boundary_identity": True,
                        "stable_identity": _identity(0x1300).diagnostic_label(),
                    },
                ),
                "edges": (
                    {
                        "role": "conditional_taken",
                        "target_block_id": "detached-target",
                        "target_anchor_ea": "0x1200",
                        "target_identity": boundary_identity.diagnostic_label(),
                        "enters_boundary": True,
                    },
                    {
                        "role": "conditional_fallthrough",
                        "target_block_id": "unrelated-exit",
                        "target_anchor_ea": "0x1500",
                        "target_identity": _identity(0x1500).diagnostic_label(),
                        "enters_boundary": False,
                    },
                ),
            },
        ),
    }


def test_detached_component_rebinds_published_replacement_boundary_as_external() -> (
    None
):
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    (native_body,) = normalization_plan.native_bodies
    normalization_plan = replace(
        normalization_plan,
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="unrelated-replacement",
                    ),
                ),
            ),
        ),
        native_bodies=(replace(native_body, terminal_block_ids=()),),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    detached_operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id == "detached-normalization"
    )
    (detached_edge,) = detached_operation.edges
    boundary = plan.block(detached_edge.target_block_id)
    assert boundary.role is FragmentBlockRole.EXTERNAL
    assert boundary.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED
    assert boundary.semantic_anchor_ea == 0x1300
    assert boundary.replaces_block_id is None
    assert tuple(
        block.semantic_anchor_ea
        for block in plan.blocks
        if block.stable_identity == _identity(0x1300)
    ) == (0x1300,)
    assert tuple(
        plan.block(block_id).semantic_anchor_ea for block_id in plan.owned_originals
    ) == (0x1100,)


def test_detached_component_reimports_prohibited_frontend_replacement() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(
                30,
                0x1250,
                succs=(),
                preds=(),
            ),
            90: _block(
                90,
                0x1400,
                succs=(20,),
                preds=(20,),
                insn_eas=(0x1402,),
            ),
        },
    )
    dispatcher_identity = _wide_identity(0x1400, 0x1408)
    selected_identity = _identity(0x1406)
    join_identity = _wide_identity(0x1410, 0x1414)
    proof_owned_transfer = FragmentBlock(
        block_id="proof-owned-transfer",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=normalization_plan.native_bodies[0].body_id,
    )
    other_target = FragmentBlock(
        block_id="other-semantic-target",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1600,
        stable_identity=_identity(0x1600),
    )
    selected_value = FragmentBlock(
        block_id="dispatcher-selected-value",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1406,
        stable_identity=selected_identity,
    )
    join = FragmentBlock(
        block_id="dispatcher-select-join",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1410,
        stable_identity=join_identity,
    )
    (native_body,) = normalization_plan.native_bodies
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *tuple(
                replace(
                    block,
                    semantic_anchor_ea=0x1400,
                    stable_identity=dispatcher_identity,
                )
                if block.block_id in {"unrelated-original", "unrelated-replacement"}
                else block
                for block in normalization_plan.blocks
            ),
            proof_owned_transfer,
            selected_value,
            join,
            other_target,
        ),
        operations=(
            FragmentOperation(
                operation_id="dispatcher-normalization",
                source_block_id="unrelated-replacement",
                predicate_anchor_ea=0x1402,
                computed_branch_normalization=(
                    FragmentComputedBranchNormalization(
                        predicate_kind=PredicateKind.SLT,
                        normalization_start_ea=0x1402,
                        condition_producer_ea=0x1400,
                        unresolved_transfer_ea=0x1412,
                        conditional_select_envelope=(
                            FragmentConditionalSelectEnvelope(
                                predicate_ea=0x1406,
                                observed_predicate_kind=PredicateKind.SGE,
                                selected_value_block_id=selected_value.block_id,
                                join_block_id=join.block_id,
                            )
                        ),
                    )
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id="unrelated-exit",
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=other_target.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=proof_owned_transfer.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="proof-owned-transfer",
                source_block_id=proof_owned_transfer.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="unrelated-replacement",
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(*native_body.block_ids, proof_owned_transfer.block_id),
                terminal_block_ids=(),
                native_ranges=(
                    *native_body.native_ranges,
                    NativeEaInterval(0x1250, 0x1251),
                ),
                proof_ids=(*native_body.proof_ids, "proof-owned-transfer"),
            ),
        ),
        work_item_scope=replace(
            normalization_plan.work_item_scope,
            selected_obligation_ids=(
                "dispatcher-normalization",
                "proof-owned-transfer",
            ),
        ),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    dispatcher_operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id == "dispatcher-normalization"
    )
    dispatcher = plan.block(dispatcher_operation.source_block_id)
    assert dispatcher.role is FragmentBlockRole.IMPORTED
    assert dispatcher.materialization is FragmentBlockMaterialization.IMPORT_NATIVE
    assert dispatcher.replaces_block_id is None
    normalization = dispatcher_operation.computed_branch_normalization
    assert normalization is not None
    envelope = normalization.conditional_select_envelope
    assert isinstance(envelope, FragmentImportedConditionalSelectEnvelope)
    assert envelope.source_branch_ea == 0x1406
    assert envelope.selected_value_ea == 0x1406
    assert envelope.selected_value_identity == selected_identity
    assert envelope.join_identity == join_identity
    prohibited_ids = frozenset(plan.prohibited_dispatcher_blocks)
    assert prohibited_ids
    assert all(
        edge.target_block_id not in prohibited_ids
        for operation in plan.operations
        for edge in operation.edges
    )
    (planned_body,) = plan.native_bodies
    assert dispatcher.block_id in planned_body.block_ids
    assert dispatcher_operation.operation_id in planned_body.proof_ids
    planned_transfer = next(
        block
        for block in plan.blocks
        if block.semantic_anchor_ea == 0x1250
        and block.role is FragmentBlockRole.IMPORTED
    )
    assert planned_transfer.block_id in planned_body.block_ids


def test_detached_component_stops_at_unique_current_imported_successor() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(
                30,
                0x1250,
                succs=(),
                preds=(),
                insn_eas=(0x1250, 0x1251),
            ),
        },
    )
    (native_body,) = normalization_plan.native_bodies
    published_successor = FragmentBlock(
        block_id="detached-successor",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(*normalization_plan.blocks, published_successor),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=published_successor.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    published_successor.block_id,
                ),
                terminal_block_ids=(published_successor.block_id,),
                native_ranges=(
                    *native_body.native_ranges,
                    NativeEaInterval(0x1250, 0x1251),
                ),
            ),
        ),
    )
    current_identity_by_serial = _current_identity_authority(graph)

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    (native_body,) = plan.native_bodies
    assert native_body.block_ids == ("detached-target",)
    assert native_body.terminal_block_ids == ()
    operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id == "detached-normalization"
    )
    (edge,) = operation.edges
    successor = plan.block(edge.target_block_id)
    assert successor.role is FragmentBlockRole.EXTERNAL
    assert successor.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED
    assert successor.stable_identity == current_identity_by_serial[30]


@pytest.mark.parametrize("authority_matches", (False, True))
def test_call_backed_nested_route_keeps_published_corridor_staged(
    authority_matches: bool,
) -> None:
    graph, normalization_plan, root_evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(
                30,
                0x1250,
                succs=(),
                preds=(),
                insn_eas=(0x1250, 0x1251, 0x1255),
            ),
            40: _block(
                40,
                0x1260,
                succs=(),
                preds=(),
                insn_eas=(0x1260, 0x1264, 0x1268),
            ),
        },
    )
    current_identity_by_serial = _current_identity_authority(graph)
    call_block = FragmentBlock(
        block_id="call-backed-write",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=current_identity_by_serial[30],
        native_body_id=normalization_plan.native_bodies[0].body_id,
    )
    route_source = FragmentBlock(
        block_id="call-backed-delivery",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1260,
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x1260, 0x1269),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(0x1260, 0x1264),
        ),
        native_body_id=normalization_plan.native_bodies[0].body_id,
    )
    raw_dispatcher = FragmentBlock(
        block_id="call-backed-raw-dispatcher",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1350,
        stable_identity=_identity(0x1350),
        native_body_id=normalization_plan.native_bodies[0].body_id,
    )
    (native_body,) = normalization_plan.native_bodies
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            call_block,
            route_source,
            raw_dispatcher,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=call_block.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="call-backed-fallthrough@0x1255",
                source_block_id=call_block.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CALL_FALLTHROUGH,
                        target_block_id=route_source.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="native-indirect-transfer@0x1268",
                source_block_id=route_source.block_id,
                predicate_anchor_ea=0x1264,
                computed_branch_normalization=FragmentComputedBranchNormalization(
                    predicate_kind=PredicateKind.SLT,
                    normalization_start_ea=0x1264,
                    condition_producer_ea=0x1260,
                    unresolved_transfer_ea=0x1268,
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id=raw_dispatcher.block_id,
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id="unrelated-exit",
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    call_block.block_id,
                    route_source.block_id,
                    raw_dispatcher.block_id,
                ),
                terminal_block_ids=(raw_dispatcher.block_id,),
                native_ranges=(
                    *native_body.native_ranges,
                    *current_identity_by_serial[30].native_ranges.intervals,
                    NativeEaInterval(0x1260, 0x1269),
                    NativeEaInterval(0x1350, 0x1351),
                ),
                proof_ids=(
                    *native_body.proof_ids,
                    "call-backed-fallthrough@0x1255",
                    "native-indirect-transfer@0x1268",
                ),
            ),
        ),
    )
    nested_proof = SemanticRouteProof(
        proof_id="state-assignment@0x1264:0x55",
        atomic_group_id=root_evidence.atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=route_source.stable_identity,
        source_anchor_ea=0x1264,
        delivery_region=NativeEaInterval(0x1264, 0x1269),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=0x55,
                target_identity=_identity(0x1500),
                target_anchor_ea=0x1500,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=current_identity_by_serial[30],
            instruction_ea=0x1251,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0x55,
            corridor_instruction_eas=(0x1251, 0x1255, 0x1260, 0x1264),
            authority_transfer_ea=0x1268 if authority_matches else 0x1267,
            preserved_call_instruction_eas=(0x1255,),
        ),
    )
    available_evidence = replace(
        root_evidence,
        route_proofs=(*root_evidence.route_proofs, nested_proof),
    )

    if not authority_matches:
        with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
            compose_canonical_semantic_fragment_plan(
                graph,
                normalization_plan,
                root_evidence,
                available_evidence=available_evidence,
                current_identity_by_serial=current_identity_by_serial,
                normalization_authority=_normalization_authority(
                    normalization_plan,
                    root_evidence,
                ),
                prohibited_dispatcher_serials=(90,),
            )
        assert exc_info.value.reason_code == (
            "call_backed_route_transfer_authority_mismatch"
        )
        assert exc_info.value.anchor_ea == 0x1267
        return

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        root_evidence,
        available_evidence=available_evidence,
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=_normalization_authority(
            normalization_plan,
            root_evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    operations = {operation.operation_id: operation for operation in plan.operations}
    call_operation = operations["call-backed-fallthrough@0x1255"]
    assert tuple(edge.role for edge in call_operation.edges) == (
        SemanticEdgeRole.CALL_FALLTHROUGH,
    )
    route_operation = operations[f"route:{nested_proof.proof_id}"]
    assert route_operation.direct_transfer_rewrite is not None
    assert tuple(
        plan.block(edge.target_block_id).semantic_anchor_ea
        for edge in route_operation.edges
    ) == (0x1500,)
    imported_anchors = {
        block.semantic_anchor_ea
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
    }
    assert {0x1250, 0x1260}.issubset(imported_anchors)
    assert 0x1350 not in imported_anchors


@pytest.mark.parametrize("topology_receipted", (False, True))
def test_detached_component_requires_receipted_current_imported_successor_topology(
    topology_receipted: bool,
) -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(
                30,
                0x1250,
                succs=(),
                preds=(),
                insn_eas=(0x1250, 0x1251),
            ),
        },
    )
    (native_body,) = normalization_plan.native_bodies
    published_successor = FragmentBlock(
        block_id="detached-successor",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=native_body.body_id,
    )
    terminal = FragmentBlock(
        block_id="detached-terminal",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1260,
        stable_identity=_identity(0x1260),
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            published_successor,
            terminal,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=published_successor.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="successor-normalization",
                source_block_id=published_successor.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CALL_FALLTHROUGH,
                        target_block_id=terminal.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    published_successor.block_id,
                    terminal.block_id,
                ),
                terminal_block_ids=(terminal.block_id,),
                native_ranges=(
                    *native_body.native_ranges,
                    NativeEaInterval(0x1250, 0x1251),
                    NativeEaInterval(0x1260, 0x1261),
                ),
                proof_ids=(*native_body.proof_ids, "successor-normalization"),
            ),
        ),
    )
    nested_proof = SemanticRouteProof(
        proof_id="state-assignment@0x1600",
        atomic_group_id=evidence.atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=_identity(0x1600),
        source_anchor_ea=0x1600,
        delivery_region=NativeEaInterval(0x1600, 0x1601),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=0x55,
                target_identity=_identity(0x1200),
                target_anchor_ea=0x1200,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=_identity(0x1600),
            instruction_ea=0x1600,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0x55,
            corridor_instruction_eas=(0x1600,),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )
    available_evidence = replace(
        evidence,
        route_proofs=(*evidence.route_proofs, nested_proof),
    )

    authority = _normalization_authority(
        normalization_plan,
        evidence,
        published_operation_ids=(
            (
                *normalization_plan.work_item_scope.selected_obligation_ids,
                "successor-normalization",
            )
            if topology_receipted
            else normalization_plan.work_item_scope.selected_obligation_ids
        ),
    )
    if topology_receipted:
        plan = compose_canonical_semantic_fragment_plan(
            graph,
            normalization_plan,
            evidence,
            available_evidence=available_evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=authority,
            prohibited_dispatcher_serials=(90,),
        )
        operation = next(
            operation
            for operation in plan.operations
            if operation.operation_id == "detached-normalization"
        )
        (edge,) = operation.edges
        boundary = plan.block(edge.target_block_id)
        assert boundary.role is FragmentBlockRole.EXTERNAL
        assert boundary.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED
        assert boundary.stable_identity == _current_identity_authority(graph)[30]
        return

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="published imported boundary retains unresolved semantic topology",
    ) as exc_info:
        compose_canonical_semantic_fragment_plan(
            graph,
            normalization_plan,
            evidence,
            available_evidence=available_evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=authority,
            prohibited_dispatcher_serials=(90,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == ("published_imported_boundary_topology_unresolved")
    assert rejection.anchor_ea == 0x1250
    assert rejection.payload == {
        "boundary_block_id": published_successor.block_id,
        "current_owner": "blk30@0x1250",
        "operation_id": "successor-normalization",
        "incoming_operation_id": "detached-normalization",
        "incoming_source_block_id": "detached-target",
        "incoming_source_anchor_ea": "0x1200",
        "incoming_edge_role": "direct",
        "nested_state_route_projection": (
            {
                "route_proof_id": nested_proof.proof_id,
                "source_anchor_ea": "0x1600",
                "disposition": "skipped",
                "reason": "source_not_in_component",
                "projection_round": 1,
                "source_block_ids": (),
                "corridor_block_ids": (),
            },
        ),
    }


def test_detached_component_stops_at_receipted_semantic_conditional() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(
                30,
                0x1250,
                succs=(),
                preds=(),
                insn_eas=(0x1250, 0x1251, 0x1252, 0x1253),
            ),
        },
    )
    (native_body,) = normalization_plan.native_bodies
    published_successor = FragmentBlock(
        block_id="detached-successor",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_wide_identity(0x1250, 0x1254),
        native_body_id=native_body.body_id,
    )
    taken = FragmentBlock(
        block_id="detached-taken",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1260,
        stable_identity=_identity(0x1260),
        native_body_id=native_body.body_id,
    )
    fallthrough = FragmentBlock(
        block_id="detached-fallthrough",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1270,
        stable_identity=_identity(0x1270),
        native_body_id=native_body.body_id,
    )
    successor_operation_id = "successor-normalization"
    normalization_plan = replace(
        normalization_plan,
        blocks=(
            *normalization_plan.blocks,
            published_successor,
            taken,
            fallthrough,
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=published_successor.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id=successor_operation_id,
                source_block_id=published_successor.block_id,
                predicate_anchor_ea=0x1251,
                computed_branch_normalization=(
                    FragmentComputedBranchNormalization(
                        predicate_kind=PredicateKind.SLT,
                        normalization_start_ea=0x1251,
                        condition_producer_ea=0x1250,
                        unresolved_transfer_ea=0x1253,
                    )
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id=taken.block_id,
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=fallthrough.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    published_successor.block_id,
                    taken.block_id,
                    fallthrough.block_id,
                ),
                terminal_block_ids=(taken.block_id, fallthrough.block_id),
                native_ranges=(
                    *native_body.native_ranges,
                    NativeEaInterval(0x1250, 0x1254),
                    NativeEaInterval(0x1260, 0x1261),
                    NativeEaInterval(0x1270, 0x1271),
                ),
                proof_ids=(*native_body.proof_ids, successor_operation_id),
            ),
        ),
        work_item_scope=replace(
            normalization_plan.work_item_scope,
            selected_obligation_ids=(
                *normalization_plan.work_item_scope.selected_obligation_ids,
                successor_operation_id,
            ),
        ),
    )
    current_identity_by_serial = _current_identity_authority(graph)

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    (planned_body,) = plan.native_bodies
    assert planned_body.block_ids == ("detached-target",)
    assert planned_body.terminal_block_ids == ()
    operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id == "detached-normalization"
    )
    (edge,) = operation.edges
    successor = plan.block(edge.target_block_id)
    assert successor.role is FragmentBlockRole.EXTERNAL
    assert successor.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED
    assert successor.stable_identity == current_identity_by_serial[30]


def test_receipt_does_not_close_unlowered_conditional_topology() -> None:
    _graph, normalization_plan, evidence = _live_source_detached_target_case()
    (native_body,) = normalization_plan.native_bodies
    operation_id = "native-body-edge@0x1250"
    operation = FragmentOperation(
        operation_id=operation_id,
        source_block_id="detached-target",
        predicate_anchor_ea=0x1200,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id="unrelated-exit",
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id="live-route-source",
            ),
        ),
    )
    native_body = replace(
        native_body,
        proof_ids=(*native_body.proof_ids, operation_id),
    )
    scope = normalization_plan.work_item_scope
    assert scope is not None
    authority = NormalizationWorkItemAuthority(
        evidence_generation=evidence.generation,
        publication_revision=1,
        source_plan_id=normalization_plan.plan_id,
        source_atomic_group_id=normalization_plan.atomic_group_id,
        work_item_id=scope.work_item_id,
        published_operation_ids=(operation_id,),
        selected_obligation_ids=(operation_id,),
        remaining_obligation_ids=(),
        unreachable_obligation_ids=(),
    )

    assert not canonical_fragment._receipted_semantic_operation_closes_boundary(
        operation,
        native_body,
        authority,
    )


def test_detached_component_rejects_ambiguous_current_imported_successor() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            30: _block(30, 0x1250, succs=(), preds=()),
            31: _block(31, 0x1250, succs=(), preds=()),
        },
    )
    (native_body,) = normalization_plan.native_bodies
    published_successor = FragmentBlock(
        block_id="detached-successor",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x1250,
        stable_identity=_identity(0x1250),
        native_body_id=native_body.body_id,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=(*normalization_plan.blocks, published_successor),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=published_successor.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    published_successor.block_id,
                ),
                terminal_block_ids=(published_successor.block_id,),
                native_ranges=(
                    *native_body.native_ranges,
                    NativeEaInterval(0x1250, 0x1251),
                ),
            ),
        ),
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="published imported boundary has multiple current owners",
    ) as exc_info:
        compose_canonical_semantic_fragment_plan(
            graph,
            normalization_plan,
            evidence,
            available_evidence=evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    rejection = exc_info.value
    assert (
        rejection.reason_code == "published_imported_boundary_current_owner_ambiguous"
    )
    assert rejection.payload["current_owner_labels"] == (
        "blk30@0x1250",
        "blk31@0x1250",
    )


def test_projected_boundary_reuses_its_unique_current_owner_role() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            90: _block(
                90,
                0x1301,
                succs=(20,),
                preds=(20,),
            ),
        },
    )
    boundary_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1300, 0x1302),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1300, 0x1301),
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=tuple(
            replace(
                block,
                stable_identity=boundary_identity,
            )
            if block.block_id
            in {
                "unrelated-original",
                "unrelated-replacement",
            }
            else block
            for block in normalization_plan.blocks
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="unrelated-replacement",
                    ),
                ),
            ),
        ),
        native_bodies=tuple(
            replace(body, terminal_block_ids=())
            for body in normalization_plan.native_bodies
        ),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    detached_operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id == "detached-normalization"
    )
    (detached_edge,) = detached_operation.edges
    (prohibited_block_id,) = plan.prohibited_dispatcher_blocks
    assert detached_edge.target_block_id == prohibited_block_id
    boundary = plan.block(prohibited_block_id)
    assert boundary.stable_identity == boundary_identity
    assert tuple(
        block.block_id
        for block in plan.blocks
        if block.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED
        and block.stable_identity is not None
        and 0x1301 in block.stable_identity.exact_instruction_eas
    ) == (boundary.block_id,)


def test_projected_boundary_rejects_multiple_current_owner_roles(
    monkeypatch,
) -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    (native_body,) = normalization_plan.native_bodies
    normalization_plan = replace(
        normalization_plan,
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="unrelated-replacement",
                    ),
                ),
            ),
        ),
        native_bodies=(replace(native_body, terminal_block_ids=()),),
    )
    monkeypatch.setattr(
        canonical_fragment,
        "_current_owners_contained_by_identity",
        lambda _graph, _identity, **_kwargs: (
            (90, 0x1400),
            (91, 0x1410),
        ),
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="projected canonical boundary has multiple current owners",
    ) as exc_info:
        compose_canonical_semantic_fragment_plan(
            graph,
            normalization_plan,
            evidence,
            available_evidence=evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "projected_boundary_current_owner_ambiguous"
    assert rejection.payload["current_owner_labels"] == (
        "blk90@0x1400",
        "blk91@0x1410",
    )


def test_detached_component_keeps_proof_owned_imported_branch_normalization() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    (native_body,) = normalization_plan.native_bodies
    detached_identity = _wide_identity(0x1200, 0x1210)
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=PredicateKind.EQ,
        normalization_start_ea=0x1202,
        condition_producer_ea=0x1203,
        unresolved_transfer_ea=0x1208,
    )
    normalization_plan = replace(
        normalization_plan,
        blocks=tuple(
            replace(block, stable_identity=detached_identity)
            if block.block_id == "detached-target"
            else block
            for block in normalization_plan.blocks
        ),
        operations=(
            *normalization_plan.operations,
            FragmentOperation(
                operation_id="detached-normalization",
                source_block_id="detached-target",
                predicate_anchor_ea=0x1204,
                computed_branch_normalization=normalization,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id="unrelated-replacement",
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id="unrelated-exit",
                    ),
                ),
            ),
        ),
        native_bodies=(
            replace(
                native_body,
                terminal_block_ids=(),
                native_ranges=(NativeEaInterval(0x1200, 0x1210),),
            ),
        ),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id == "detached-normalization"
    )
    assert operation.computed_branch_normalization is normalization
    assert plan.block(operation.source_block_id).role is FragmentBlockRole.IMPORTED


def test_canonical_route_rebinds_retained_corridor_to_live_source_subset() -> None:
    graph, normalization_plan, evidence = _omitted_delivery_source_case()

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    root = plan.block(plan.roots[0])
    assert root.semantic_anchor_ea == 0x1100
    assert root.stable_identity == _identity(0x1100)
    assert (
        normalization_plan.block("live-route-source").stable_identity
        != root.stable_identity
    )
    route_operation = next(
        operation
        for operation in plan.operations
        if operation.operation_id.startswith("route:state-assignment@0x1110")
    )
    assert route_operation.direct_transfer_rewrite is not None
    assert route_operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x1110
    assert route_operation.direct_transfer_rewrite.proof_corridor_instruction_eas == (
        0x1100,
        0x1110,
    )
    assert route_operation.direct_transfer_rewrite.superseded_instruction_eas == (
        0x1110,
    )


def test_canonical_composition_ids_external_blocks_by_stable_identity() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            10: _block(
                10,
                0x1000,
                succs=(20,),
                preds=(),
                insn_eas=(0x1001,),
            ),
            90: _block(
                90,
                0x1000,
                succs=(20,),
                preds=(20,),
                insn_eas=(0x1400,),
            ),
        },
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial=_current_identity_authority(graph),
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90,),
    )

    external_blocks = tuple(
        block for block in plan.blocks if block.role is FragmentBlockRole.EXTERNAL
    )
    assert len(external_blocks) == 2
    assert len({block.block_id for block in external_blocks}) == 2
    assert tuple(sorted(block.semantic_anchor_ea for block in external_blocks)) == (
        0x1001,
        0x1400,
    )
    assert all("serial" not in block.block_id for block in external_blocks)


def test_canonical_composition_uses_current_external_identity_authority() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            90: _block(
                90,
                0x40A560,
                succs=(20,),
                preds=(20,),
                insn_eas=(0x40A5D0,),
            ),
        },
    )
    imported_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40A5CA, 0x40A5E5),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40A5D0,),
    )

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        current_identity_by_serial={
            10: _identity(0x1000),
            20: _identity(0x1100),
            90: imported_identity,
        },
        prohibited_dispatcher_serials=(90,),
    )

    (prohibited_block_id,) = plan.prohibited_dispatcher_blocks
    prohibited = plan.block(prohibited_block_id)
    assert prohibited.stable_identity == imported_identity
    assert prohibited.semantic_anchor_ea == 0x40A5D0
    assert "0x40A560" not in prohibited.block_id


def test_canonical_composition_uses_one_portable_dispatcher_scc_witness() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            90: _block(
                90,
                0x40A560,
                succs=(91,),
                preds=(20, 91),
            ),
            91: _block(
                91,
                0x40A5F0,
                succs=(90,),
                preds=(90,),
            ),
            92: _block(
                92,
                0x40A560,
                succs=(),
                preds=(),
            ),
        },
    )
    shared_entry_identity = _identity(0x40A560)
    portable_router_identity = _identity(0x40A5F0)

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial={
            10: _identity(0x1000),
            20: _identity(0x1100),
            90: shared_entry_identity,
            91: portable_router_identity,
            92: shared_entry_identity,
        },
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90, 91),
    )

    (prohibited_block_id,) = plan.prohibited_dispatcher_blocks
    prohibited = plan.block(prohibited_block_id)
    assert prohibited.stable_identity == portable_router_identity
    assert prohibited.semantic_anchor_ea == 0x40A5F0


def test_canonical_composition_does_not_guess_dispatcher_scc_witness() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            90: _block(
                90,
                0x40A560,
                succs=(91,),
                preds=(20, 91),
            ),
            91: _block(
                91,
                0x40A5F0,
                succs=(90,),
                preds=(90,),
            ),
            92: _block(92, 0x40A560, succs=(), preds=()),
            93: _block(93, 0x40A5F0, succs=(), preds=()),
        },
    )
    shared_entry_identity = _identity(0x40A560)
    shared_router_identity = _identity(0x40A5F0)

    plan = compose_canonical_semantic_fragment_plan(
        graph,
        normalization_plan,
        evidence,
        available_evidence=evidence,
        current_identity_by_serial={
            10: _identity(0x1000),
            20: _identity(0x1100),
            90: shared_entry_identity,
            91: shared_router_identity,
            92: shared_entry_identity,
            93: shared_router_identity,
        },
        normalization_authority=_normalization_authority(
            normalization_plan,
            evidence,
        ),
        prohibited_dispatcher_serials=(90, 91),
    )

    assert tuple(
        plan.block(block_id).stable_identity
        for block_id in plan.prohibited_dispatcher_blocks
    ) == (shared_entry_identity, shared_router_identity)


def test_canonical_composition_rejects_shared_external_stable_identity() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            10: _block(
                10,
                0x1000,
                succs=(20,),
                preds=(),
                insn_eas=(0x1001,),
            ),
            90: _block(
                90,
                0x1000,
                succs=(20,),
                preds=(20,),
                insn_eas=(0x1001,),
            ),
        },
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="external stable identity has multiple current owners",
    ) as exc_info:
        compose_canonical_semantic_fragment_plan(
            graph,
            normalization_plan,
            evidence,
            available_evidence=evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    assert exc_info.value.reason_code == "external_identity_ambiguous"
    assert exc_info.value.anchor_ea == 0x1001
    assert exc_info.value.payload == {
        "candidate_owner": "blk90@0x1001",
        "existing_owner": "blk10@0x1001",
        "stable_identity": (
            "input=sha256:test-input-a function-rva=0x1000 "
            "exact-ea=[0x1001] native-ea=[0x1000-0x1002]"
        ),
    }


def test_canonical_route_rejects_split_materialized_delivery_ownership() -> None:
    graph, normalization_plan, evidence = _omitted_delivery_source_case()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            25: _block(25, 0x1110, succs=(), preds=()),
        },
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="canonical route corridor has split current-graph ownership",
    ) as exc_info:
        compose_canonical_semantic_fragment_plan(
            graph,
            normalization_plan,
            evidence,
            available_evidence=evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )

    assert exc_info.value.reason_code == "split_route_corridor_ownership"
    assert exc_info.value.anchor_ea == 0x1110


def test_canonical_composition_rejects_ambiguous_detached_target_owner() -> None:
    graph, normalization_plan, evidence = _live_source_detached_target_case()
    (native_body,) = normalization_plan.native_bodies
    duplicate_target = replace(
        normalization_plan.block("detached-target"),
        block_id="detached-target-duplicate",
    )
    ambiguous = replace(
        normalization_plan,
        blocks=(*normalization_plan.blocks, duplicate_target),
        native_bodies=(
            replace(
                native_body,
                block_ids=(
                    *native_body.block_ids,
                    duplicate_target.block_id,
                ),
                terminal_block_ids=(
                    *native_body.terminal_block_ids,
                    duplicate_target.block_id,
                ),
            ),
        ),
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match=(
            "canonical route target 0x1200 requires one "
            "normalization-plan owner, observed 2"
        ),
    ):
        compose_canonical_semantic_fragment_plan(
            graph,
            ambiguous,
            evidence,
            available_evidence=evidence,
            current_identity_by_serial=_current_identity_authority(graph),
            normalization_authority=_normalization_authority(
                normalization_plan,
                evidence,
            ),
            prohibited_dispatcher_serials=(90,),
        )


def test_partial_bound_atomic_group_is_rejected() -> None:
    graph, bound = _direct_bound_evidence()

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="bound route set does not match atomic evidence",
    ):
        build_canonical_semantic_fragment_plan(
            graph,
            replace(bound, routes=()),
            prohibited_dispatcher_serials=(30,),
        )


def test_storage_conditional_keeps_both_arms_and_data_flow_in_one_plan() -> None:
    producer_identity = _wide_identity(0x1080, 0x1090)
    source_identity = _identity(0x1100)
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(15,), preds=()),
            15: _block(
                15,
                0x1080,
                succs=(20,),
                preds=(10,),
                insn_eas=(0x1080, 0x1088),
            ),
            20: _block(20, 0x1100, succs=(30,), preds=(15,)),
            30: _block(30, 0x1400, succs=(20,), preds=(20,)),
            40: _block(40, 0x1200, succs=(), preds=()),
            50: _block(50, 0x1300, succs=(), preds=()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    carrier_storage = StorageIdentity(StorageIdentityKind.STACK, 0x48)
    proof = SemanticRouteProof(
        proof_id="state-choice@0x1100",
        atomic_group_id="canonical-semantic:g4",
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=source_identity,
        source_anchor_ea=0x1100,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=0xAABBCCDD,
                target_identity=_identity(0x1200),
                target_anchor_ea=0x1200,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=0x11223344,
                target_identity=_identity(0x1300),
                target_anchor_ea=0x1300,
            ),
        ),
        predicate=SemanticPredicateProof(
            kind=SemanticPredicateKind.STORAGE_EQUALS,
            origin=SemanticCorridorPoint(producer_identity, 0x1080),
            consumer=SemanticCorridorPoint(source_identity, 0x1100),
            corridor=(
                SemanticCorridorPoint(producer_identity, 0x1080),
                SemanticCorridorPoint(source_identity, 0x1100),
            ),
            storage_identity=predicate_storage,
            width=4,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id="entry-state-choice",
                definition=SemanticCorridorPoint(producer_identity, 0x1088),
                consumers=(SemanticCorridorPoint(source_identity, 0x1100),),
                corridor=(
                    SemanticCorridorPoint(producer_identity, 0x1088),
                    SemanticCorridorPoint(source_identity, 0x1100),
                ),
                storage_identity=carrier_storage,
                width=4,
                state_values=(0xAABBCCDD, 0x11223344),
                permitted_write_eas=frozenset({0x1088}),
            ),
        ),
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=4,
        atomic_group_id="canonical-semantic:g4",
        route_proofs=(proof,),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    operation = plan.operations[0]
    assert operation.predicate_anchor_ea == 0x1100
    assert operation.roles == frozenset(
        {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    assert {obligation.role for obligation in plan.data_flow_obligations} == {
        FragmentDataFlowRole.CONDITION,
        FragmentDataFlowRole.CARRIER,
    }
    condition = next(
        obligation
        for obligation in plan.data_flow_obligations
        if obligation.role is FragmentDataFlowRole.CONDITION
    )
    assert condition.definition.storage_identity == predicate_storage
    assert condition.definition.instruction_ea == 0x1080
    assert condition.uses[0].instruction_ea == 0x1100
    carrier = next(
        obligation
        for obligation in plan.data_flow_obligations
        if obligation.role is FragmentDataFlowRole.CARRIER
    )
    assert carrier.definition.storage_identity == carrier_storage
    assert carrier.definition.instruction_ea == 0x1088
    assert carrier.uses[0].instruction_ea == 0x1100


def test_terminal_route_groups_carrier_return_and_edge_atomically() -> None:
    capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1110),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100, 0x1105),
    )
    terminal_identity = StableBlockIdentity.from_instruction_eas(
        (0x1200, 0x1208),
        native_key=NATIVE_KEY,
    )
    state_constant = 0x19A7218A
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(
                20,
                0x1100,
                succs=(30,),
                preds=(10,),
                insn_eas=(0x1100, 0x1105),
            ),
            30: _block(30, 0x1400, succs=(20, 40), preds=(20,)),
            40: _block(
                40,
                0x1200,
                succs=(),
                preds=(30,),
                insn_eas=(0x1200, 0x1208),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    carrier = TerminalReturnCarrierEvidence(
        request=TerminalReturnCarrierRequest(
            source_handler_ea=0x1100,
            terminal_target_ea=0x1200,
            state_var_reg=20,
            state_constant=state_constant,
        ),
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        state_write_ea=0x1100,
        carrier_ea=0x1105,
        terminal_return_ea=0x1208,
        operation=ValueOpKind.MOVE,
        source=TerminalReturnCarrierSource(
            kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
            width=4,
            storage_identity=StorageIdentity(
                StorageIdentityKind.GLOBAL,
                0x48B8A4,
            ),
        ),
        return_width=4,
        corridor_instruction_eas=(0x1100, 0x1105),
    )
    proof = SemanticRouteProof(
        proof_id="terminal-return@0x1100",
        atomic_group_id="canonical-semantic:g5",
        proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
        shape=SemanticRouteShape.DIRECT,
        source_identity=capture_identity,
        source_anchor_ea=0x1100,
        delivery_region=NativeEaInterval(0x1100, 0x1101),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=state_constant,
                target_identity=terminal_identity,
                target_anchor_ea=0x1200,
                terminal=True,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=capture_identity,
            instruction_ea=0x1100,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=state_constant,
            corridor_instruction_eas=(0x1100,),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
        terminal_return_carrier=carrier,
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=5,
        atomic_group_id="canonical-semantic:g5",
        route_proofs=(proof,),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    assert len(plan.return_carriers) == 1
    assert plan.return_carriers[0].carrier_ea == 0x1105
    assert plan.return_carriers[0].source.kind is FragmentReturnSourceKind.STORAGE_VALUE
    assert len(plan.terminal_returns) == 1
    terminal_return = plan.terminal_returns[0]
    assert terminal_return.instruction_ea == 0x1208
    assert plan.block(terminal_return.block_id).role is FragmentBlockRole.REPLACEMENT
    assert len(plan.terminal_routes) == 1
    assert plan.terminal_routes[0].operation_id == plan.operations[0].operation_id
    assert len(plan.owned_originals) == 2


def test_terminal_routes_share_one_owned_return_block_atomically() -> None:
    terminal_identity = _identity(0x1200)
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20, 25), preds=()),
            20: _block(
                20,
                0x1100,
                succs=(30,),
                preds=(10,),
                insn_eas=(0x1100, 0x1105),
            ),
            25: _block(
                25,
                0x1150,
                succs=(30,),
                preds=(10,),
                insn_eas=(0x1150, 0x1155),
            ),
            30: _block(30, 0x1400, succs=(20, 25, 40), preds=(20, 25)),
            40: _block(40, 0x1200, succs=(), preds=(30,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    def terminal_proof(
        source_ea: int,
        carrier_ea: int,
        state_constant: int,
    ) -> SemanticRouteProof:
        capture_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 0x10),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(source_ea, carrier_ea),
        )
        carrier = TerminalReturnCarrierEvidence(
            request=TerminalReturnCarrierRequest(
                source_handler_ea=source_ea,
                terminal_target_ea=0x1200,
                state_var_reg=20,
                state_constant=state_constant,
            ),
            capture_identity=capture_identity,
            terminal_identity=terminal_identity,
            state_write_ea=source_ea,
            carrier_ea=carrier_ea,
            terminal_return_ea=0x1200,
            operation=ValueOpKind.MOVE,
            source=TerminalReturnCarrierSource(
                kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
                width=4,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.GLOBAL,
                    0x48B8A4,
                ),
            ),
            return_width=4,
            corridor_instruction_eas=(source_ea, carrier_ea),
        )
        return SemanticRouteProof(
            proof_id=f"terminal-return@0x{source_ea:X}",
            atomic_group_id="canonical-semantic:shared-terminal",
            proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
            shape=SemanticRouteShape.DIRECT,
            source_identity=capture_identity,
            source_anchor_ea=source_ea,
            delivery_region=NativeEaInterval(source_ea, source_ea + 1),
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=terminal_identity,
                    target_anchor_ea=0x1200,
                    terminal=True,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=capture_identity,
                instruction_ea=source_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(source_ea,),
                authority_transfer_ea=None,
                preserved_call_instruction_eas=(),
            ),
            terminal_return_carrier=carrier,
        )

    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=6,
        atomic_group_id="canonical-semantic:shared-terminal",
        route_proofs=(
            terminal_proof(0x1100, 0x1105, 0x11),
            terminal_proof(0x1150, 0x1155, 0x22),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    assert len(plan.return_carriers) == 2
    assert len(plan.terminal_routes) == 2
    assert len(plan.terminal_returns) == 1
    assert len(plan.owned_originals) == 3
    assert {route.return_id for route in plan.terminal_routes} == {
        plan.terminal_returns[0].return_id
    }


def test_dispatcher_fed_semantic_target_remains_internal_not_a_root() -> None:
    def direct_proof(
        source_ea: int,
        target_ea: int,
        state_constant: int,
    ) -> SemanticRouteProof:
        source_identity = _identity(source_ea)
        return SemanticRouteProof(
            proof_id=f"state-assignment@0x{source_ea:X}",
            atomic_group_id="canonical-semantic:g6",
            proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
            shape=SemanticRouteShape.DIRECT,
            source_identity=source_identity,
            source_anchor_ea=source_ea,
            delivery_region=NativeEaInterval(source_ea, source_ea + 1),
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=_identity(target_ea),
                    target_anchor_ea=target_ea,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=source_identity,
                instruction_ea=source_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(source_ea,),
                authority_transfer_ea=None,
                preserved_call_instruction_eas=(),
            ),
        )

    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(20, 0x1100, succs=(90,), preds=(10,)),
            30: _block(30, 0x1200, succs=(90,), preds=(90,)),
            40: _block(40, 0x1300, succs=(), preds=()),
            90: _block(90, 0x1400, succs=(20, 30), preds=(20, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=6,
        atomic_group_id="canonical-semantic:g6",
        route_proofs=(
            direct_proof(0x1100, 0x1200, 0x11),
            direct_proof(0x1200, 0x1300, 0x22),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(90,),
    )

    assert tuple(plan.block(root).semantic_anchor_ea for root in plan.roots) == (
        0x1100,
    )
    first_operation = next(
        operation
        for operation in plan.operations
        if plan.block(operation.source_block_id).semantic_anchor_ea == 0x1100
    )
    assert (
        plan.block(first_operation.edges[0].target_block_id).role
        is FragmentBlockRole.REPLACEMENT
    )
    assert (
        plan.block(first_operation.edges[0].target_block_id).semantic_anchor_ea
        == 0x1200
    )


def test_shared_external_target_rejects_bound_identity_drift() -> None:
    def direct_proof(source_ea: int, state_constant: int) -> SemanticRouteProof:
        source_identity = _identity(source_ea)
        return SemanticRouteProof(
            proof_id=f"state-assignment@0x{source_ea:X}",
            atomic_group_id="canonical-semantic:shared-external",
            proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
            shape=SemanticRouteShape.DIRECT,
            source_identity=source_identity,
            source_anchor_ea=source_ea,
            delivery_region=NativeEaInterval(source_ea, source_ea + 1),
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=_identity(0x1300),
                    target_anchor_ea=0x1300,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=source_identity,
                instruction_ea=source_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(source_ea,),
                authority_transfer_ea=None,
                preserved_call_instruction_eas=(),
            ),
        )

    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20, 30), preds=()),
            20: _block(20, 0x1100, succs=(90,), preds=(10,)),
            30: _block(30, 0x1200, succs=(90,), preds=(10,)),
            40: _block(40, 0x1300, succs=(), preds=(90,)),
            90: _block(90, 0x1400, succs=(20, 30, 40), preds=(20, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="canonical-semantic:shared-external",
        route_proofs=(
            direct_proof(0x1100, 0x11),
            direct_proof(0x1200, 0x22),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    second_route = bound.routes[1]
    second_destination = second_route.destinations[0]
    corrupted = replace(
        bound,
        routes=(
            bound.routes[0],
            replace(
                second_route,
                destinations=(
                    replace(
                        second_destination,
                        block=replace(
                            second_destination.block,
                            identity=_wide_identity(0x1300, 0x1310),
                        ),
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="external identity drifted",
    ):
        build_canonical_semantic_fragment_plan(
            graph,
            corrupted,
            prohibited_dispatcher_serials=(90,),
        )
