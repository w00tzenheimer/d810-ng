"""Content-ID validation owns its encoded payloads for one invocation only."""

from dataclasses import replace
from collections.abc import Mapping
from unittest.mock import patch

import pytest

from d810.analyses.control_flow import semantic_route_evidence as routes
from d810.core.runtime_identity import RuntimeAuthorityScope
from d810.transforms.unflatten_authority.ids import canonical_bytes
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


def test_opcode_attrs_do_not_distinguish_canonical_route_identity():
    """Backend provenance must not split otherwise identical route authority."""
    left = _physical_proof_with_attrs({"custom": {"version": 1}})
    right = _physical_proof_with_attrs({"custom": {"version": 2}})

    left_evidence = routes.canonical_semantic_evidence_from_proofs(
        left.native_key, 1, (left,)
    )
    right_evidence = routes.canonical_semantic_evidence_from_proofs(
        right.native_key, 1, (right,)
    )

    assert left_evidence.atomic_group_id == right_evidence.atomic_group_id
    assert (
        left_evidence.route_proofs[0].proof_id
        == right_evidence.route_proofs[0].proof_id
    )


def test_opcode_attrs_do_not_split_duplicate_route_occurrences():
    """Classification must coalesce proofs whose only difference is provenance."""
    left = _physical_proof_with_attrs({"custom": {"version": 1}})
    right = _physical_proof_with_attrs({"custom": {"version": 2}})

    evidence = routes.canonical_semantic_evidence_from_proofs(
        left.native_key,
        1,
        (left, right),
    )

    assert len(evidence.route_proofs) == 1
    assert (
        evidence.route_proofs[0]
        .state_write.physical_state_write.source_instruction.opcode_attrs
        == {}
    )


@pytest.mark.parametrize("share_input_id", [False, True])
def test_runtime_ingestion_ignores_opcode_attrs_when_coalescing(
    share_input_id,
):
    left = _physical_proof_with_attrs({"custom": {"version": 1}})
    right = _physical_proof_with_attrs({"custom": {"version": 2}})
    if not share_input_id:
        right = replace(right, proof_id="second-producer-label")

    evidence = routes.runtime_semantic_evidence_from_proofs(
        left.native_key,
        1,
        (left, right),
        scope=RuntimeAuthorityScope(f"runtime-coalesce-{share_input_id}"),
    )

    assert len(evidence.route_proofs) == 1


def test_reversing_opcode_attr_duplicates_preserves_persisted_evidence():
    left = _physical_proof_with_attrs({"custom": {"version": 1}})
    right = _physical_proof_with_attrs({"custom": {"version": 2}})

    with routes.route_authority_phase("forward-attrs"):
        forward = routes.canonical_semantic_evidence_from_proofs(
            left.native_key, 1, (left, right)
        )
        forward_bytes = canonical_bytes(routes.materialize_route_evidence(forward))
    with routes.route_authority_phase("reverse-attrs"):
        reverse = routes.canonical_semantic_evidence_from_proofs(
            left.native_key, 1, (right, left)
        )
        reverse_bytes = canonical_bytes(routes.materialize_route_evidence(reverse))

    assert reverse_bytes == forward_bytes


def test_fallback_classifier_normalizes_duplicate_opcode_attrs():
    left = _physical_proof_with_attrs({"custom": {"version": 1}})
    right = _physical_proof_with_attrs({"custom": {"version": 2}})

    forward, _ = routes._canonical_authoritative_proof_inputs((left, right))
    reverse, _ = routes._canonical_authoritative_proof_inputs((right, left))

    assert canonical_bytes(reverse) == canonical_bytes(forward)


def test_runtime_duplicate_metadata_is_input_order_independent():
    left = _physical_proof_with_attrs({"custom": {"version": 1}})
    right = replace(
        _physical_proof_with_attrs({"custom": {"version": 2}}),
        proof_id="second-producer-label",
    )

    forward = routes.runtime_semantic_evidence_from_proofs(
        left.native_key,
        1,
        (left, right),
        scope=RuntimeAuthorityScope("runtime-order"),
    )
    reverse = routes.runtime_semantic_evidence_from_proofs(
        left.native_key,
        1,
        (right, left),
        scope=RuntimeAuthorityScope("runtime-order"),
    )

    assert canonical_bytes(
        routes.materialize_route_evidence(reverse)
    ) == canonical_bytes(routes.materialize_route_evidence(forward))


def _state_transform_proof_with_attrs(attrs, *, proof_id):
    from tests.unit.transforms.unflatten_authority.test_bind import (
        _compiler_corridor_unsupported_case,
    )

    authority, *_ = _compiler_corridor_unsupported_case(
        proof_kind=routes.SemanticRouteProofKind.STATE_TRANSFORM,
    )
    proof = authority.proposal.route_evidence.route_proofs[0]
    transform = proof.state_transform
    instruction = replace(transform.program[0], attrs=attrs)
    return replace(
        proof,
        proof_id=proof_id,
        atomic_group_id="producer-group",
        state_transform=replace(
            transform,
            program=(instruction, *transform.program[1:]),
        ),
    )


def test_runtime_ingestion_accepts_opaque_state_transform_attrs():
    proof = _state_transform_proof_with_attrs(
        {"opaque": object()},
        proof_id="producer-open-attrs",
    )

    evidence = routes.runtime_semantic_evidence_from_proofs(
        proof.native_key,
        1,
        (proof,),
        scope=RuntimeAuthorityScope("open-instruction-attrs"),
    )

    assert len(evidence.route_proofs) == 1


def test_runtime_ingestion_keeps_state_transform_attrs_authoritative():
    left = _state_transform_proof_with_attrs(
        {"marker": 1},
        proof_id="shared-producer-id",
    )
    right = _state_transform_proof_with_attrs(
        {"marker": 2},
        proof_id="shared-producer-id",
    )

    with pytest.raises(
        routes.SemanticRouteEvidenceRejected,
        match="divergent authoritative payload.*state_transform",
    ):
        routes._runtime_authoritative_proofs((left, right))
    distinct = routes._runtime_authoritative_proofs(
        (left, replace(right, proof_id="second-producer-id"))
    )
    assert len(distinct) == 2


def test_opcode_attrs_nested_mutation_is_outside_route_id_validation():
    """Changing ignored backend provenance must not stale route authority IDs."""
    proof = _physical_proof_with_attrs({"custom": {"version": 1}})
    evidence = routes.canonical_semantic_evidence_from_proofs(
        proof.native_key, 1, (proof,)
    )
    attrs = (
        evidence.route_proofs[0]
        .state_write.physical_state_write.source_instruction.opcode_attrs
    )

    attrs["custom"]["version"] = 2

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


def test_ignored_opcode_attrs_callback_cannot_mutate_route_authority():
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

    proof = _physical_proof_with_attrs({"custom": Trigger(1)})
    evidence = routes.canonical_semantic_evidence_from_proofs(
        proof.native_key, 1, (proof,)
    )
    canonical = evidence.route_proofs[0]
    trigger = (
        canonical.state_write.physical_state_write.source_instruction
        .opcode_attrs["custom"]
    )
    original = canonical.source_anchor_ea
    called = []
    trigger.callback = lambda: (
        called.append(True),
        object.__setattr__(canonical, "source_anchor_ea", original + 1),
    )

    _validate(evidence)

    assert called == []
    assert canonical.source_anchor_ea == original
