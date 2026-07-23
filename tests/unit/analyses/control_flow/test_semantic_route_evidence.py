"""Portable semantic-route evidence and all-or-nothing live binding."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
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
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
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
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=(),
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
            predicate_anchor_ea=0x1100,
            state_write=None,
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


def test_semantic_evidence_capability_is_structural() -> None:
    evidence = _evidence()

    class _Provider:
        def evidence_for(self, function_ea: int):
            return evidence if int(function_ea) == 0x1000 else None

    assert isinstance(_Provider(), CanonicalSemanticEvidenceCapability)
