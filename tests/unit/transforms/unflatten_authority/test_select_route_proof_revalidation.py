"""Select-time evidence revalidation: content vs context, nested mutation.

Ticket d81-dod5. These tests document the construction-to-selection interval.
They do not change production `_select_route_proof`.
"""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticRouteEvidenceRejected,
)
from d810.transforms.unflatten_authority.producer_api import _select_route_proof
from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
    _accepted,
    _native_bound_production_inputs,
    _unsafe_evidence,
    _unsafe_field_replace,
    build_canonical_semantic_evidence,
)


def _match_first(proof) -> bool:
    return True


def _match_proof_id(proof_id: str):
    def matches(proof) -> bool:
        return proof.proof_id == proof_id

    return matches


def test_constructed_evidence_already_validated_before_select():
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    selected = _select_route_proof(
        evidence,
        _match_proof_id(evidence.route_proofs[0].proof_id),
        "probe",
    )
    assert selected is evidence.route_proofs[0]
    assert selected is _select_route_proof(
        evidence,
        _match_proof_id(evidence.route_proofs[0].proof_id),
        "probe",
    )


def test_new_without_post_init_is_still_typed_canonical_evidence():
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    forged = _unsafe_evidence(evidence, evidence.route_proofs)
    assert type(forged) is CanonicalSemanticEvidence
    assert forged is not evidence


def test_root_id_forgery_is_rejected_by_post_init_not_by_type_or_matcher():
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    forged = object.__new__(CanonicalSemanticEvidence)
    object.__setattr__(forged, "native_key", evidence.native_key)
    object.__setattr__(forged, "generation", evidence.generation)
    object.__setattr__(forged, "atomic_group_id", "sha256:" + "1" * 64)
    object.__setattr__(forged, "route_proofs", evidence.route_proofs)
    assert type(forged) is CanonicalSemanticEvidence
    with pytest.raises(SemanticRouteEvidenceRejected):
        CanonicalSemanticEvidence.__post_init__(forged)
    with pytest.raises(SemanticRouteEvidenceRejected):
        _select_route_proof(forged, _match_first, "probe")


def test_nested_descendant_setattr_keeps_root_slots_and_object_ids():
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    route_proofs = evidence.route_proofs
    native_key = evidence.native_key
    proof = evidence.route_proofs[0]
    destination = proof.destinations[0]
    object.__setattr__(destination, "target_anchor_ea", int(destination.target_anchor_ea) ^ 1)
    assert evidence.route_proofs is route_proofs
    assert evidence.route_proofs[0] is proof
    assert proof.destinations[0] is destination
    assert evidence.native_key is native_key
    with pytest.raises(SemanticRouteEvidenceRejected):
        CanonicalSemanticEvidence.__post_init__(evidence)


def test_nested_replaced_destination_keeps_root_tuple_identity():
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    route_proofs = evidence.route_proofs
    proof = evidence.route_proofs[0]
    destination = proof.destinations[0]
    forged_dest = _unsafe_field_replace(
        destination,
        target_anchor_ea=int(destination.target_anchor_ea) ^ 1,
    )
    object.__setattr__(proof, "destinations", (forged_dest, *proof.destinations[1:]))
    assert evidence.route_proofs is route_proofs
    assert evidence.route_proofs[0] is proof
    assert proof.destinations[0] is not destination
    with pytest.raises(SemanticRouteEvidenceRejected):
        CanonicalSemanticEvidence.__post_init__(evidence)


def test_select_without_post_init_would_accept_nested_setattr(monkeypatch):
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]
    destination = proof.destinations[0]
    object.__setattr__(destination, "target_anchor_ea", int(destination.target_anchor_ea) ^ 1)

    def no_content_revalidation(value):
        return None

    monkeypatch.setattr(CanonicalSemanticEvidence, "__post_init__", no_content_revalidation)
    monkeypatch.setattr(type(proof), "__post_init__", no_content_revalidation)
    monkeypatch.setattr(type(destination), "__post_init__", no_content_revalidation)
    selected = _select_route_proof(
        evidence,
        _match_proof_id(proof.proof_id),
        "probe",
    )
    assert selected is proof
