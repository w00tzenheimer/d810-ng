"""Portable semantic-route evidence and all-or-nothing live binding."""

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
    SemanticRouteEvidenceRejected,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_canonical_semantic_evidence,
)
from d810.capabilities.semantic_routes import CanonicalSemanticEvidenceCapability
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
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
        1: _block(1, 0x1100, succs=(0,), preds=(0,)),
    }
    if include_target:
        blocks[2] = _block(2, 0x1200, succs=(), preds=())
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)


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
        ),
    )
    graph = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(1,), preds=()),
            1: _block(
                1,
                0x1100,
                succs=(3, 5),
                preds=(0,),
                insn_eas=(0x1100, 0x1105),
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

    assert bound is not None
    assert bound.routes[0].predicate is not None
    assert tuple(
        (block.serial, block.anchor_ea) for block in bound.routes[0].predicate.corridor
    ) == ((1, 0x1080), (2, 0x1100))
    assert tuple(
        (block.serial, block.anchor_ea)
        for block in bound.routes[0].carriers[0].corridor
    ) == ((1, 0x1088), (2, 0x1100))

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
