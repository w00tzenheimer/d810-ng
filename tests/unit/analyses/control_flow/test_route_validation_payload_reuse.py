"""Content-ID validation owns its encoded payloads for one invocation only."""

from dataclasses import replace
from collections.abc import Mapping
from unittest.mock import patch

import pytest

from d810.analyses.control_flow import semantic_route_evidence as routes
from tests.unit.analyses.control_flow.test_semantic_route_evidence import _proof
from tests.unit.analyses.control_flow.test_route_structural_identity import _physical_proof_with_attrs


def _evidence():
    proof = _proof()
    return routes.canonical_semantic_evidence_from_proofs(proof.native_key, 1, (proof,))


def _validate(evidence, proofs=None):
    routes._validate_content_derived_ids(
        native_key=evidence.native_key,
        generation=evidence.generation,
        atomic_group_id=evidence.atomic_group_id,
        route_proofs=evidence.route_proofs if proofs is None else proofs,
    )


def test_content_id_validation_encodes_each_occurrence_once():
    evidence = _evidence()
    payload = routes._stable_route_proof_payload
    with patch.object(routes, "_stable_route_proof_payload", wraps=payload) as walks:
        _validate(evidence)
    assert walks.call_count == len(evidence.route_proofs)


def test_repeated_payload_still_checks_every_occurrence_id():
    evidence = _evidence()
    proof = evidence.route_proofs[0]
    forged = replace(proof, proof_id="sha256:" + "0" * 64)
    with pytest.raises(routes.SemanticRouteEvidenceRejected, match="proof id is not content-derived"):
        _validate(evidence, (proof, forged))


def test_repeated_payload_still_checks_every_occurrence_group():
    evidence = _evidence()
    proof = evidence.route_proofs[0]
    forged = replace(proof, atomic_group_id="sha256:" + "0" * 64)
    with pytest.raises(routes.SemanticRouteEvidenceRejected, match="proof group id is not content-derived"):
        _validate(evidence, (proof, forged))


def test_next_validation_reclassifies_changed_content():
    evidence = _evidence()
    proof = evidence.route_proofs[0]
    anchor = proof.source_anchor_ea
    _validate(evidence)
    try:
        object.__setattr__(proof, "source_anchor_ea", anchor + 1)
        with pytest.raises(routes.SemanticRouteEvidenceRejected, match="atomic group id is not content-derived"):
            _validate(evidence)
    finally:
        object.__setattr__(proof, "source_anchor_ea", anchor)
    _validate(evidence)


def test_validation_matches_independent_legacy_group_and_proof_encoding():
    evidence = _evidence()
    proof = evidence.route_proofs[0]
    assert routes._canonical_route_group_id(
        native_key=evidence.native_key,
        generation=evidence.generation,
        proofs=evidence.route_proofs,
    ) == evidence.atomic_group_id
    assert routes._canonical_route_proof_id(
        atomic_group_id=evidence.atomic_group_id, proof=proof,
    ) == proof.proof_id
    _validate(evidence)


def test_duplicate_classification_keeps_constructor_normalization_in_group_id():
    proof = _proof()
    object.__setattr__(proof, "destinations", list(proof.destinations))
    proofs = (proof, proof)
    group = routes._canonical_route_group_id(
        native_key=proof.native_key, generation=1, proofs=proofs,
    )
    object.__setattr__(proof, "atomic_group_id", group)
    object.__setattr__(proof, "proof_id", routes._canonical_route_proof_id(
        atomic_group_id=group, proof=proof,
    ))
    routes._validate_content_derived_ids(
        native_key=proof.native_key, generation=1,
        atomic_group_id=group, route_proofs=proofs,
    )


def test_open_mapping_callback_cannot_hide_a_prior_proof_mutation():
    class Trigger(Mapping):
        def __init__(self, number):
            self.number = number
            self.callback = None

        def __len__(self):
            return 1

        def __iter__(self):
            return iter(("value",))

        def __getitem__(self, key):
            return self.number

        def items(self):
            if self.callback:
                callback, self.callback = self.callback, None
                callback()
            return {"value": self.number}.items()

    proofs = tuple(replace(
        _physical_proof_with_attrs({"custom": Trigger(index)}),
        proof_id=f"input-{index}",
    ) for index in range(2))
    evidence = routes.canonical_semantic_evidence_from_proofs(proofs[0].native_key, 1, proofs)
    first, second = evidence.route_proofs
    trigger = second.state_write.physical_state_write.source_instruction.opcode_attrs["custom"]
    original = first.source_anchor_ea
    trigger.callback = lambda: object.__setattr__(first, "source_anchor_ea", original + 1)
    try:
        with pytest.raises(routes.SemanticRouteEvidenceRejected, match="atomic group id is not content-derived"):
            _validate(evidence)
    finally:
        object.__setattr__(first, "source_anchor_ea", original)
