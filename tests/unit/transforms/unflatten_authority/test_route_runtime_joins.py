"""The route-group -> proof join keys on arena references, not content IDs.

The authority question a membership join asks is "is this exact record a proof
of this exact bundle".  These tests pin that it is answered by the arena, that
it costs no canonical encoding, and that the two boundaries which must stay
content-keyed forever really do.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

import d810.transforms.unflatten_authority.bind as bind
import d810.transforms.unflatten_authority.ids as authority_ids
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_route_evidence,
    canonical_semantic_evidence_from_proofs,
    materialize_route_evidence,
    runtime_semantic_route_scope,
)
from d810.core.runtime_identity import (
    RUNTIME_AUTHORITY_SIDECAR_FIELDS,
    RuntimeAuthorityArena,
    RuntimeAuthorityKind,
    RuntimeJoinRejected,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.unflatten_authority.producer_api import bundle_route_proof_refs
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


REJECTION = "selected route proof is foreign to canonical evidence"


def test_membership_join_returns_one_reference_per_bundle_proof() -> None:
    evidence = _bundle()

    refs = bundle_route_proof_refs(
        evidence, evidence.route_proofs, rejection=REJECTION,
    )

    assert len(refs) == len(evidence.route_proofs)
    assert all(ref.kind is RuntimeAuthorityKind.ROUTE_PROOF for ref in refs)
    assert len(set(refs)) == len(refs)


def test_membership_join_refuses_a_content_equal_copy() -> None:
    """The join is about identity; a copy has the same content and no authority."""

    evidence = _bundle()
    copy = replace(evidence.route_proofs[0])

    assert copy == evidence.route_proofs[0]
    assert copy.proof_id == evidence.route_proofs[0].proof_id
    with pytest.raises(ValueError, match=REJECTION):
        bundle_route_proof_refs(evidence, (copy,), rejection=REJECTION)


def test_membership_join_refuses_a_proof_from_another_bundle() -> None:
    first = _bundle()
    second = _bundle()

    assert first == second
    with pytest.raises(ValueError, match=REJECTION):
        bundle_route_proof_refs(
            first, (second.route_proofs[0],), rejection=REJECTION,
        )


def test_membership_join_costs_no_canonical_encoding(monkeypatch) -> None:
    """The whole point: joining must not walk or hash a record graph."""

    evidence = _bundle()

    def refuse(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("a runtime join must not encode canonical bytes")

    monkeypatch.setattr(authority_ids, "canonical_bytes", refuse)
    monkeypatch.setattr(authority_ids, "_record_content_id", refuse)

    refs = bundle_route_proof_refs(
        evidence, evidence.route_proofs, rejection=REJECTION,
    )

    assert len(refs) == len(evidence.route_proofs)


def test_an_unbound_bundle_cannot_be_joined_at_all() -> None:
    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)

    with pytest.raises(RuntimeJoinRejected, match="not bound"):
        bundle_route_proof_refs(
            unbound, unbound.route_proofs, rejection=REJECTION,
        )


def test_rebinding_an_unbound_bundle_makes_the_join_available_again() -> None:
    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 3))

    rebound = bind_route_evidence(unbound, arena=arena)

    refs = bundle_route_proof_refs(
        rebound, rebound.route_proofs, rejection=REJECTION,
    )
    assert len(refs) == len(rebound.route_proofs)
    # The rebind moved no content: the fingerprints are the ones the producer
    # minted, and they are still reproducible from the bundle's own bytes.
    assert authority_ids.canonical_bytes(rebound) == authority_ids.canonical_bytes(
        evidence
    )
    # ...and the two arenas are two authorities over one value: neither
    # inherits the other's references, even though both name the same records.
    assert refs != bundle_route_proof_refs(
        evidence, evidence.route_proofs, rejection=REJECTION,
    )


def test_ingestion_dedup_stays_content_keyed() -> None:
    """Producer inputs have no arena yet, so their merge is a content merge.

    ``_canonical_authoritative_proofs`` runs *before* any identity is minted:
    its inputs carry producer labels, not canonical IDs and not references.
    There is nothing for a reference to key on, so this boundary is
    content-keyed by construction and must stay that way.
    """

    proof = _proof()
    labelled = replace(proof, diagnostic_provenance=(("fact_id", "a"),))
    other = replace(proof, diagnostic_provenance=(("fact_id", "b"),))

    merged = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (labelled, other),
    )

    assert len(merged.route_proofs) == 1
    assert merged.route_proofs[0].diagnostic_provenance == (
        ("fact_id", "a"), ("fact_id", "b"),
    )


def test_canonical_proof_id_uniqueness_stays_a_content_check() -> None:
    """Fingerprint uniqueness is a content invariant, not an authority join.

    Two bundle proofs may never share a content ID -- that would mean the
    bundle's own fingerprints do not identify its content.  A reference-keyed
    version of this check is vacuous, because references are unique by
    construction, so it must keep reading the content ID.
    """

    evidence = _bundle()
    forged = object.__new__(CanonicalSemanticEvidence)
    duplicated = (evidence.route_proofs[0], evidence.route_proofs[0])
    object.__setattr__(forged, "native_key", evidence.native_key)
    object.__setattr__(forged, "generation", evidence.generation)
    object.__setattr__(forged, "atomic_group_id", evidence.atomic_group_id)
    object.__setattr__(forged, "route_proofs", duplicated)
    object.__setattr__(forged, "_runtime_identity", None)
    object.__setattr__(forged, "_runtime_binding", None)

    with pytest.raises(Exception, match="duplicate proof ids"):
        CanonicalSemanticEvidence.__post_init__(forged)


def test_registry_snapshot_and_detached_copy_ignore_the_runtime_sidecar() -> None:
    """The registry seal covers the canonical schema, never a live arena.

    ``bind._registry_structural_snapshot`` and ``bind._detached_canonical_copy``
    enumerate ``dataclasses.fields`` rather than the canonical schema, so they
    would otherwise see a sidecar holding an arena: the snapshot has no
    representation for it and a detached copy must not duplicate it.  Both
    skip it, which makes a bound and an unbound bundle produce the same seal
    and makes every detached copy unbound.
    """

    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)

    assert bind._registry_structural_snapshot(
        evidence
    ) == bind._registry_structural_snapshot(unbound)

    detached = bind._detached_canonical_copy(evidence, {})

    assert type(detached) is CanonicalSemanticEvidence
    assert detached.route_binding is None
    assert detached == evidence


def test_the_sidecar_skip_cannot_reach_a_canonical_field() -> None:
    """The closed name set is the guard; prove it excludes nothing canonical."""

    tables = {**authority_ids._RECORD_FIELDS, **authority_ids._EXTERNAL_FIELDS}
    canonical_names = {name for names in tables.values() for name in names}

    assert not (canonical_names & RUNTIME_AUTHORITY_SIDECAR_FIELDS)
    assert not any(name.startswith("_") for name in canonical_names)
