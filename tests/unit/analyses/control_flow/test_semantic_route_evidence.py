"""Portable semantic-route evidence and all-or-nothing live binding."""

from __future__ import annotations

from dataclasses import replace
import copy
import gc
import weakref

import pytest
import d810.analyses.control_flow.semantic_route_evidence as route_evidence

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteAssessment,
    CanonicalRouteMaterialization,
    CanonicalRouteAssessmentPhase,
    CanonicalRouteAssessmentRejection,
    CanonicalSemanticEvidence,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteEvidenceRejected,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteDeliveryKind,
    SemanticStateWriteProof,
    assess_canonical_route,
    bind_canonical_semantic_evidence,
    validate_canonical_route_materialization,
    validate_canonical_route_assessment,
)
from d810.transforms.unflatten_authority.ids import canonical_bytes
from d810.capabilities.semantic_routes import CanonicalSemanticEvidenceCapability
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.flowgraph import InsnKind, MopSnapshot, OperandKind
from d810.ir.expressions import ValueOpKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _proof() -> SemanticRouteProof:
    source = _identity(0x1100)
    return SemanticRouteProof(
        proof_id="state-assignment@0x1100",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=source,
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
            identity=source,
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
    )


def _storage_choice_proof() -> SemanticRouteProof:
    source = _identity(0x1100)
    producer = _identity(0x1080)
    return SemanticRouteProof(
        proof_id="state-choice@0x1100",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=source,
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
            origin=SemanticCorridorPoint(producer, 0x1080),
            consumer=SemanticCorridorPoint(source, 0x1100),
            corridor=(
                SemanticCorridorPoint(producer, 0x1080),
                SemanticCorridorPoint(source, 0x1100),
            ),
            storage_identity=StorageIdentity(
                StorageIdentityKind.STACK,
                0x40,
            ),
            width=4,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id="entry-state-choice",
                definition=SemanticCorridorPoint(producer, 0x1088),
                consumers=(SemanticCorridorPoint(source, 0x1100),),
                corridor=(
                    SemanticCorridorPoint(producer, 0x1088),
                    SemanticCorridorPoint(source, 0x1100),
                ),
                storage_identity=StorageIdentity(
                    StorageIdentityKind.STACK,
                    0x48,
                ),
                width=4,
                state_values=(0xAABBCCDD, 0x11223344),
                permitted_write_eas=frozenset({0x1088}),
            ),
        ),
    )


def _evidence(*proofs: SemanticRouteProof) -> CanonicalSemanticEvidence:
    return CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=3,
        atomic_group_id="canonical-semantic:g3",
        route_proofs=proofs or (_proof(),),
    )


def _block(
    serial: int,
    ea: int,
    *,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insn_eas: tuple[int, ...] = (),
) -> BlockSnapshot:
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


def _graph(*, include_target: bool = True) -> FlowGraph:
    blocks = {
        0: _block(0, 0x1000, succs=(1,), preds=()),
        1: BlockSnapshot(
            serial=1,
            block_type=1,
            succs=(0,),
            preds=(0,),
            flags=0,
            start_ea=0x1100,
            insn_snapshots=(
                InsnSnapshot(
                    opcode=0,
                    ea=0x1100,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0xAABBCCDD),
                    d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
                    kind=InsnKind.MOV,
                    value_op_kind=ValueOpKind.MOVE,
                ),
            ),
        ),
    }
    if include_target:
        blocks[2] = _block(2, 0x1200, succs=(), preds=())
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)


def _direct_graph(*, reciprocal: bool = True) -> FlowGraph:
    graph = _graph()
    target = graph.blocks[2]
    source = graph.blocks[1]
    return FlowGraph(
        blocks={
            **graph.blocks,
            1: replace(source, succs=(2,)),
            2: replace(target, preds=(1,) if reciprocal else ()),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )


def test_direct_assignment_proof_requires_matching_state_write() -> None:
    proof = _proof()

    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="state assignment requires its exact state write",
    ):
        replace(proof, state_write=None)
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="state constant",
    ):
        replace(
            proof,
            destinations=(
                replace(
                    proof.destinations[0],
                    state_constant=0x11223344,
                ),
            ),
        )


def test_direct_state_assignment_replays_delivery_edge() -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )

    bound = bind_canonical_semantic_evidence(_direct_graph(), _evidence(proof))
    assert bound is not None


def test_route_assessment_is_minted_only_by_the_trusted_binding_kernel() -> None:
    materialization = CanonicalRouteMaterialization.capture(
            _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE,
            generation=3,
    )
    assessment = assess_canonical_route(materialization, _evidence())
    assert type(assessment) is CanonicalRouteAssessment
    assert assessment.accepted
    assert assessment.rejection_reason is None
    assert assessment.evidence_id == assessment.evidence.atomic_group_id
    assert assessment.proof_ids == tuple(
        sorted(proof.proof_id for proof in assessment.evidence.route_proofs)
    )
    assert validate_canonical_route_assessment(assessment) is assessment
    with pytest.raises(TypeError, match="minted"):
        CanonicalRouteAssessment()
    with pytest.raises(TypeError):
        replace(assessment, graph_fingerprint="sha256:" + "b" * 64)
    object.__setattr__(assessment, "evidence_id", "forged-evidence-id")
    with pytest.raises(ValueError):
        validate_canonical_route_assessment(assessment)


def test_materialization_and_assessment_require_exact_registry_identity() -> None:
    for name in (
        "_register_materialization", "_register_assessment",
        "_materialization_state", "_assessment_state",
    ):
        assert not hasattr(route_evidence, name)

    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    clone = object.__new__(CanonicalRouteMaterialization)
    for name in CanonicalRouteMaterialization.__dataclass_fields__:
        object.__setattr__(clone, name, getattr(materialization, name))
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_materialization(clone)
    object.__setattr__(materialization, "generation", 4)
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_materialization(materialization)
    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    object.__setattr__(materialization.blocks[1], "succs", (999,))
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_materialization(materialization)

    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    assessment = assess_canonical_route(materialization, _evidence())
    assessment_clone = object.__new__(CanonicalRouteAssessment)
    for name in CanonicalRouteAssessment.__dataclass_fields__:
        object.__setattr__(assessment_clone, name, getattr(assessment, name))
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment_clone)
    object.__setattr__(assessment, "graph_fingerprint", "sha256:" + "f" * 64)
    object.__setattr__(assessment, "_seal", "sha256:" + "0" * 64)
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment)


def test_route_authority_registry_does_not_retain_results() -> None:
    """The closed identity registries must not become process-lifetime owners."""

    materializations: list[CanonicalRouteMaterialization] = []
    assessments: list[CanonicalRouteAssessment] = []
    materialization_refs: list[weakref.ReferenceType[CanonicalRouteMaterialization]] = []
    assessment_refs: list[weakref.ReferenceType[CanonicalRouteAssessment]] = []
    for _ in range(25):
        materialization = CanonicalRouteMaterialization.capture(
            _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
        )
        assessment = assess_canonical_route(materialization, _evidence())
        materializations.append(materialization)
        assessments.append(assessment)
        materialization_refs.append(weakref.ref(materialization))
        assessment_refs.append(weakref.ref(assessment))

    assert all(reference() is not None for reference in materialization_refs)
    assert all(reference() is not None for reference in assessment_refs)
    del materializations, assessments
    del materialization, assessment
    gc.collect()
    assert all(reference() is None for reference in materialization_refs)
    assert all(reference() is None for reference in assessment_refs)


def test_route_assessment_rejects_unbound_unique_endpoint_without_authority() -> None:
    assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            _graph(include_target=False), phase=CanonicalRouteAssessmentPhase.PROJECTED,
            generation=4,
        ), _evidence(),
    )
    assert assessment.rejected
    assert assessment.bound_evidence is None
    assert assessment.rejection_reason is CanonicalRouteAssessmentRejection.ROUTE_BINDING_FAILED


def test_route_assessment_is_in_memory_and_seals_bound_mapping() -> None:
    assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE,
            generation=3,
        ), _evidence(),
    )
    with pytest.raises(TypeError, match="canonical encoding"):
        canonical_bytes(assessment)
    with pytest.raises(TypeError, match="copied"):
        copy.copy(assessment)
    forged_bound = replace(assessment.bound_evidence, routes=())
    object.__setattr__(assessment, "bound_evidence", forged_bound)
    with pytest.raises(ValueError):
        validate_canonical_route_assessment(assessment)


@pytest.mark.parametrize("family", ("destinations", "carriers"))
def test_bound_route_nested_collections_require_exact_tuples(family: str) -> None:
    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    assessment = assess_canonical_route(materialization, _evidence())
    route = assessment.bound_evidence.routes[0]
    if family == "destinations":
        forged_route = replace(route, destinations=list(route.destinations))
    elif family == "carriers":
        forged_route = replace(route, carriers=list(route.carriers))
    forged_bound = replace(assessment.bound_evidence, routes=(forged_route,))
    object.__setattr__(assessment, "bound_evidence", forged_bound)
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment)


@pytest.mark.parametrize("reciprocal", (False,))
def test_direct_state_assignment_rejects_delivery_edge_drift(reciprocal: bool) -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )

    assert bind_canonical_semantic_evidence(
        _direct_graph(reciprocal=reciprocal), _evidence(proof)
    ) is None


def test_direct_state_assignment_accepts_extra_target_predecessor() -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )
    graph = _direct_graph()
    target = graph.blocks[2]
    graph = replace(graph, blocks={**graph.blocks, 2: replace(target, preds=(1, 0))})

    assert bind_canonical_semantic_evidence(graph, _evidence(proof)) is not None


def test_direct_state_assignment_rejects_extra_source_successor() -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )
    graph = _direct_graph()
    source = graph.blocks[1]
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(source, succs=(2, 0)),
        },
    )

    assert bind_canonical_semantic_evidence(graph, _evidence(proof)) is None


@pytest.mark.parametrize("transfer_kind", ("goto", "nop"))
def test_direct_state_assignment_replays_authority_transfer(transfer_kind: str) -> None:
    from d810.ir.semantics import CallKind

    source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1100, 0x1101, 0x1102, 0x1103),
        native_key=NATIVE_KEY,
    )
    baseline = _proof()
    state_write = replace(
        baseline.state_write,
        identity=source_identity,
        delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        corridor_instruction_eas=(0x1100, 0x1101, 0x1102),
        preserved_call_instruction_eas=(0x1101,),
        authority_transfer_ea=0x1103,
    )
    proof = replace(
        baseline,
        source_identity=source_identity,
        source_anchor_ea=0x1102,
        delivery_region=NativeEaInterval(0x1100, 0x1104),
        state_write=state_write,
    )
    graph = _direct_graph()
    source = graph.blocks[1]
    transfer = (
        InsnSnapshot(
            opcode=0,
            ea=0x1103,
            operands=(),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
            kind=InsnKind.GOTO,
        )
        if transfer_kind == "goto"
        else InsnSnapshot(opcode=0, ea=0x1103, operands=(), kind=InsnKind.NOP)
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(
                    source.insn_snapshots[0],
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1101,
                        operands=(),
                        kind=InsnKind.CALL,
                        call_kind=CallKind.DIRECT,
                        is_call=True,
                    ),
                    InsnSnapshot(opcode=0, ea=0x1102, operands=(), kind=InsnKind.NOP),
                    transfer,
                ),
            ),
        },
    )

    bound = bind_canonical_semantic_evidence(graph, _evidence(proof))
    if transfer_kind == "goto":
        assert bound is not None
    else:
        assert bound is None


def test_direct_proof_separates_anchor_identity_from_delivery_region() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1101),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100,),
    )
    baseline = _proof()

    proof = replace(
        baseline,
        source_identity=source,
        delivery_region=NativeEaInterval(0x1100, 0x1110),
        state_write=replace(baseline.state_write, identity=source),
    )

    assert proof.source_identity.native_ranges.intervals == (
        NativeEaInterval(0x1100, 0x1101),
    )
    assert proof.delivery_region == NativeEaInterval(0x1100, 0x1110)


def test_conditional_proof_requires_both_semantic_arms() -> None:
    proof = _proof()

    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="both conditional roles",
    ):
        replace(
            proof,
            proof_kind=SemanticRouteProofKind.STATE_CHOICE,
            shape=SemanticRouteShape.CONDITIONAL,
            delivery_region=None,
            predicate=SemanticPredicateProof(
                kind=SemanticPredicateKind.PRESERVE_LIVE,
                origin=SemanticCorridorPoint(_identity(0x1100), 0x1100),
                consumer=SemanticCorridorPoint(_identity(0x1100), 0x1100),
                corridor=(SemanticCorridorPoint(_identity(0x1100), 0x1100),),
                true_is_taken=True,
            ),
            state_write=None,
        )


def test_storage_predicate_requires_carrier_and_complete_corridors() -> None:
    source = _identity(0x1100)
    producer = _identity(0x1080)
    target_a = _identity(0x1200)
    target_b = _identity(0x1300)
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    carrier_storage = StorageIdentity(StorageIdentityKind.STACK, 0x48)
    predicate = SemanticPredicateProof(
        kind=SemanticPredicateKind.STORAGE_EQUALS,
        origin=SemanticCorridorPoint(producer, 0x1080),
        consumer=SemanticCorridorPoint(source, 0x1100),
        corridor=(
            SemanticCorridorPoint(producer, 0x1080),
            SemanticCorridorPoint(source, 0x1100),
        ),
        storage_identity=predicate_storage,
        width=4,
        compare_constant=0,
    )
    carrier = SemanticCarrierProof(
        carrier_id="entry-state-choice",
        definition=SemanticCorridorPoint(producer, 0x1088),
        consumers=(SemanticCorridorPoint(source, 0x1100),),
        corridor=(
            SemanticCorridorPoint(producer, 0x1088),
            SemanticCorridorPoint(source, 0x1100),
        ),
        storage_identity=carrier_storage,
        width=4,
        state_values=(0xAABBCCDD, 0x11223344),
        permitted_write_eas=frozenset({0x1088}),
    )
    proof = SemanticRouteProof(
        proof_id="state-choice@0x1100",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=source,
        source_anchor_ea=0x1100,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=0xAABBCCDD,
                target_identity=target_a,
                target_anchor_ea=0x1200,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=0x11223344,
                target_identity=target_b,
                target_anchor_ea=0x1300,
            ),
        ),
        predicate=predicate,
        carriers=(carrier,),
    )

    assert proof.predicate == predicate
    assert proof.carriers == (carrier,)
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="storage predicate requires one carrier proof",
    ):
        replace(proof, carriers=())
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="corridor must end at its consumer",
    ):
        replace(
            predicate,
            corridor=(SemanticCorridorPoint(producer, 0x1080),),
        )
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="carrier state values must match destination states",
    ):
        replace(
            proof,
            carriers=(
                replace(
                    carrier,
                    state_values=(0xAABBCCDD, 0x55667788),
                ),
            ),
        )


def test_atomic_group_binding_abstains_instead_of_partially_binding() -> None:
    evidence = _evidence()

    assert (
        bind_canonical_semantic_evidence(_graph(include_target=False), evidence) is None
    )

    bound = bind_canonical_semantic_evidence(_graph(), evidence)

    assert bound is not None
    assert bound.atomic_group_id == evidence.atomic_group_id
    assert len(bound.routes) == 1
    assert bound.routes[0].source.serial == 1
    assert bound.routes[0].source.anchor_ea == 0x1100
    assert bound.routes[0].destinations[0].block.serial == 2
    assert bound.routes[0].destinations[0].block.anchor_ea == 0x1200


def test_binding_uses_exact_identity_when_branch_ea_has_a_helper_owner() -> None:
    source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1100, 0x1105),
        native_key=NATIVE_KEY,
    )
    proof = replace(
        _proof(),
        source_identity=source_identity,
        source_anchor_ea=0x1105,
        delivery_region=NativeEaInterval(0x1105, 0x1106),
        state_write=SemanticStateWriteProof(
            identity=source_identity,
            instruction_ea=0x1100,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0xAABBCCDD,
            corridor_instruction_eas=(0x1100, 0x1105),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )
    graph = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(1,), preds=()),
            1: replace(
                _block(
                    1,
                    0x1100,
                    succs=(3, 5),
                    preds=(0,),
                    insn_eas=(0x1100, 0x1105),
                ),
                insn_snapshots=(
                    InsnSnapshot(
                        0,
                        0x1100,
                        (),
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            size=4,
                            value=0xAABBCCDD,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            size=4,
                            reg=20,
                        ),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                    InsnSnapshot(0, 0x1105, (), kind=InsnKind.NOP),
                ),
            ),
            2: _block(2, 0x1200, succs=(), preds=(3, 5)),
            3: _block(3, 0x1105, succs=(2,), preds=(1,)),
            5: _block(
                5,
                0x1105,
                succs=(2,),
                preds=(1,),
                insn_eas=(0x1105,),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    bound = bind_canonical_semantic_evidence(graph, _evidence(proof))

    assert bound is not None
    assert bound.routes[0].source.serial == 1
    assert bound.routes[0].source.anchor_ea == 0x1105


def test_conditional_corridors_bind_all_or_abstain() -> None:
    proof = _storage_choice_proof()
    graph = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(1,), preds=()),
            1: _block(
                1,
                0x1080,
                succs=(2,),
                preds=(0,),
                insn_eas=(0x1080, 0x1088),
            ),
            2: _block(2, 0x1100, succs=(3, 4), preds=(1,)),
            3: _block(3, 0x1200, succs=(), preds=(2,)),
            4: _block(4, 0x1300, succs=(), preds=(2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    bound = bind_canonical_semantic_evidence(
        graph,
        _evidence(proof),
    )

    assert bound is None

    graph_without_producer = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(2,), preds=()),
            2: _block(2, 0x1100, succs=(3, 4), preds=(0,)),
            3: _block(3, 0x1200, succs=(), preds=(2,)),
            4: _block(4, 0x1300, succs=(), preds=(2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert (
        bind_canonical_semantic_evidence(
            graph_without_producer,
            _evidence(proof),
        )
        is None
    )


def test_semantic_evidence_capability_is_structural() -> None:
    evidence = _evidence()

    class _Provider:
        def evidence_for(self, function_ea: int):
            return evidence if int(function_ea) == 0x1000 else None

    assert isinstance(_Provider(), CanonicalSemanticEvidenceCapability)
