"""Runtime authority references for the route group -> proof join.

Every join in the semantic-route vertical keys on an arena reference, not on a
content-derived string.  These tests pin the three properties that makes safe:
a bundle that never entered an arena cannot be joined at all, a decoded bundle
has to be rebound explicitly before it can be, and neither operation moves a
single canonical byte or content ID.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    RouteAuthorityBinding,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_route_evidence,
    canonical_semantic_evidence_from_proofs,
    materialize_route_evidence,
    route_join_binding,
    runtime_semantic_route_scope,
)
from d810.core.runtime_identity import (
    RuntimeAuthorityArena,
    RuntimeAuthorityKind,
    RuntimeAuthorityScope,
    RuntimeJoinRejected,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.unflatten_authority.ids import canonical_bytes
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _proof(ea: int = 0x1100, state: int = 0xAABBCCDD) -> SemanticRouteProof:
    source = _identity(ea)
    return SemanticRouteProof(
        proof_id=f"state-assignment@{ea:#x}",
        atomic_group_id="producer-label:g3",
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=source,
        source_anchor_ea=ea,
        delivery_region=NativeEaInterval(ea, ea + 1),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=state,
                target_identity=_identity(ea + 0x100),
                target_anchor_ea=ea + 0x100,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=source,
            instruction_ea=ea,
            state_variable=StorageIdentity(StorageIdentityKind.REGISTER, 20),
            width=4,
            state_constant=state,
            corridor_instruction_eas=(ea,),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )


def _bundle() -> CanonicalSemanticEvidence:
    return canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(), _proof(0x1400, 0x11223344)),
    )


def _decoded(evidence: CanonicalSemanticEvidence) -> CanonicalSemanticEvidence:
    """Rebuild the bundle field by field, exactly as a decoder does."""

    return CanonicalSemanticEvidence(
        native_key=evidence.native_key,
        generation=evidence.generation,
        atomic_group_id=evidence.atomic_group_id,
        route_proofs=evidence.route_proofs,
    )


def test_producer_bundle_is_bound_and_resolves_every_proof() -> None:
    evidence = _bundle()
    binding = route_join_binding(evidence)

    assert type(binding) is RouteAuthorityBinding
    assert binding.group_ref.kind is RuntimeAuthorityKind.ROUTE_GROUP
    assert len(binding.proof_refs) == len(evidence.route_proofs)
    assert all(
        ref.kind is RuntimeAuthorityKind.ROUTE_PROOF for ref in binding.proof_refs
    )
    for proof, ref in zip(evidence.route_proofs, binding.proof_refs, strict=True):
        assert binding.ref_for(proof) == ref
        assert binding.proof_for(ref) is proof


def test_mint_order_agrees_with_the_canonical_proof_order() -> None:
    """Runtime iteration is deterministic because mint order is canonical order."""

    evidence = _bundle()
    binding = route_join_binding(evidence)

    ordinals = [binding.order_key(ref) for ref in binding.proof_refs]
    assert ordinals == sorted(ordinals)
    assert tuple(sorted(evidence.route_proofs, key=lambda item: item.proof_id)) == (
        evidence.route_proofs
    )


def test_an_unbound_bundle_is_rejected_at_the_join_not_silently_adopted() -> None:
    decoded = _decoded(_bundle())

    assert decoded.route_binding is None
    with pytest.raises(RuntimeJoinRejected, match="not bound to a runtime authority"):
        route_join_binding(decoded)


def test_rebind_admits_a_decoded_bundle_and_moves_no_canonical_byte() -> None:
    evidence = _bundle()
    decoded = _decoded(evidence)
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 3))

    rebound = bind_route_evidence(decoded, arena=arena)

    assert canonical_bytes(rebound) == canonical_bytes(decoded)
    assert rebound.atomic_group_id == decoded.atomic_group_id
    assert tuple(item.proof_id for item in rebound.route_proofs) == tuple(
        item.proof_id for item in decoded.route_proofs
    )
    assert rebound == decoded
    binding = route_join_binding(rebound)
    assert binding.arena is arena
    assert binding.proof_for(binding.proof_refs[0]) is rebound.route_proofs[0]


def test_rebind_refuses_to_readopt_an_already_bound_bundle() -> None:
    evidence = _bundle()
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 3))

    with pytest.raises(RuntimeJoinRejected, match="already bound"):
        bind_route_evidence(evidence, arena=arena)


def test_a_reference_from_another_arena_is_refused_by_this_binding() -> None:
    first = _bundle()
    second = _bundle()
    foreign = route_join_binding(second).proof_refs[0]

    binding = route_join_binding(first)
    with pytest.raises(RuntimeJoinRejected, match="another runtime authority"):
        binding.proof_for(foreign)
    with pytest.raises(RuntimeJoinRejected, match="another runtime authority"):
        binding.order_key(foreign)


def test_a_replaced_copy_of_a_bound_proof_is_not_joinable() -> None:
    """A copy is a different record, so it fails closed rather than aliasing."""

    evidence = _bundle()
    binding = route_join_binding(evidence)
    copy = replace(evidence.route_proofs[0], diagnostic_provenance=(("x", "y"),))

    with pytest.raises(RuntimeJoinRejected, match="not a proof of this route bundle"):
        binding.ref_for(copy)


def test_materialize_returns_the_unbound_canonical_value() -> None:
    evidence = _bundle()

    persisted = materialize_route_evidence(evidence)

    assert persisted.route_binding is None
    assert persisted == evidence
    assert canonical_bytes(persisted) == canonical_bytes(evidence)
    with pytest.raises(RuntimeJoinRejected):
        route_join_binding(persisted)


def test_the_binding_is_outside_the_wire_schema_and_the_equality() -> None:
    evidence = _bundle()
    decoded = _decoded(evidence)

    assert evidence == decoded
    assert hash(evidence) == hash(decoded)
    assert canonical_bytes(evidence) == canonical_bytes(decoded)
    assert "_runtime_binding" not in repr(evidence)


def test_a_closed_arena_ends_the_binding_authority() -> None:
    evidence = _bundle()
    binding = route_join_binding(evidence)
    proof = evidence.route_proofs[0]
    ref = binding.ref_for(proof)

    binding.arena.close()

    assert not binding.is_live
    with pytest.raises(RuntimeJoinRejected, match="closed"):
        binding.proof_for(ref)
    with pytest.raises(RuntimeJoinRejected, match="closed"):
        route_join_binding(evidence)


def test_rebind_refuses_a_closed_arena() -> None:
    decoded = _decoded(_bundle())
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 3))
    arena.close()

    with pytest.raises(RuntimeJoinRejected, match="closed"):
        bind_route_evidence(decoded, arena=arena)


def test_rebind_requires_an_arena_that_owns_nothing_of_this_bundle() -> None:
    """A fresh arena is required; a shared scope does not make a shared bundle."""

    scope = RuntimeAuthorityScope("0x1000:g3")
    first = RuntimeAuthorityArena(scope)
    second = RuntimeAuthorityArena(scope)
    decoded = _decoded(_bundle())

    left = bind_route_evidence(decoded, arena=first)
    right = bind_route_evidence(decoded, arena=second)

    assert route_join_binding(left).proof_refs != route_join_binding(right).proof_refs


def test_a_deep_copy_of_a_bound_bundle_is_unbound() -> None:
    """Copy reconstruction must not fabricate a second authority (channel 4)."""

    evidence = _bundle()

    copied = deepcopy(evidence)

    assert copied == evidence
    assert copied.route_binding is None
    assert copied.route_proofs[0] is not evidence.route_proofs[0]
    with pytest.raises(RuntimeJoinRejected, match="not bound"):
        route_join_binding(copied)
    # The original keeps its authority; copying answered a question about the
    # copy, not about the original.
    assert route_join_binding(evidence).proof_for(
        route_join_binding(evidence).proof_refs[0]
    ) is evidence.route_proofs[0]


def test_the_binding_refuses_a_reference_of_the_wrong_kind() -> None:
    evidence = _bundle()
    binding = route_join_binding(evidence)

    with pytest.raises(RuntimeJoinRejected, match="route proofs only"):
        binding.proof_for(binding.group_ref)
    with pytest.raises(TypeError, match="runtime reference"):
        binding.proof_for("route_proof000001")
    with pytest.raises(TypeError, match="runtime reference"):
        binding.order_key("route_proof000001")


def test_a_reference_is_never_persisted_in_the_canonical_bytes() -> None:
    """The rebind adds authority, never content: nothing of it is encoded."""

    evidence = _bundle()
    binding = route_join_binding(evidence)
    encoded = canonical_bytes(evidence)

    for ref in (binding.group_ref, *binding.proof_refs):
        assert ref.render().encode("ascii") not in encoded
    assert b"runtime:" not in encoded
    assert b"RouteAuthorityBinding" not in encoded
    assert b"_runtime_binding" not in encoded
    # The bundle's own identities are what is encoded, and they are the
    # content-derived fingerprints the producer minted.
    assert evidence.atomic_group_id.encode("ascii") in encoded
    assert evidence.atomic_group_id.startswith("sha256:")
