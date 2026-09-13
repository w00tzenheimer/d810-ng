"""Regressions for program-aware route-proof validation reuse."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from d810.analyses.control_flow import semantic_route_evidence as routes
from d810.transforms.unflatten_authority import producer_api
from tests.unit.analyses.control_flow.test_route_validation_payload_reuse import (
    _state_transform_proof_with_attrs,
)
from tests.unit.transforms.unflatten_authority.helpers import exact_fixture


FAMILY = "state transition"


@pytest.fixture()
def evidence():
    producer_api.reset_validated_route_selection()
    _source, proposal, _exclusion, _refs = exact_fixture()
    yield proposal.route_evidence
    producer_api.reset_validated_route_selection()


def _matcher(evidence):
    selected = evidence.route_proofs[0]
    return lambda proof: proof is selected


def _spy():
    return patch.object(
        producer_api,
        "_revalidate_canonical_evidence",
        wraps=producer_api._revalidate_canonical_evidence,
    )


def _program_evidence():
    proof = _state_transform_proof_with_attrs(
        {"mutable": {"version": 1}},
        proof_id="producer-program-proof",
    )
    return routes.canonical_semantic_evidence_from_proofs(
        proof.native_key, 1, (proof,)
    )


def test_program_free_binding_revalidates_once(evidence):
    snapshot = object()
    with _spy() as spy:
        first = producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
        second = producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
    assert spy.call_count == 1
    assert first is second is evidence.route_proofs[0]


def test_program_bearing_bundle_always_revalidates():
    evidence = _program_evidence()
    snapshot = object()
    with _spy() as spy:
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
    assert spy.call_count == 2


def test_program_attrs_mutation_is_caught_on_next_selection():
    evidence = _program_evidence()
    snapshot = object()
    producer_api._select_route_proof(
        evidence, _matcher(evidence), FAMILY, snapshot=snapshot
    )
    attrs = evidence.route_proofs[0].state_transform.program[0].attrs
    attrs["mutable"]["version"] = 2
    with pytest.raises(
        routes.SemanticRouteEvidenceRejected,
        match="content-derived|atomic group",
    ):
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )


def test_changed_snapshot_forces_program_free_revalidation(evidence):
    with _spy() as spy:
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=object()
        )
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=object()
        )
    assert spy.call_count == 2


def test_rebound_proof_container_forces_revalidation(evidence):
    snapshot = object()
    with _spy() as spy:
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
        routes.CanonicalSemanticEvidence.__post_init__(evidence)
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
    assert spy.call_count == 2


def test_reset_forces_revalidation(evidence):
    snapshot = object()
    with _spy() as spy:
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
        producer_api.reset_validated_route_selection()
        producer_api._select_route_proof(
            evidence, _matcher(evidence), FAMILY, snapshot=snapshot
        )
    assert spy.call_count == 2


def test_matcher_and_single_match_guard_run_on_cache_hit(evidence):
    snapshot = object()
    producer_api._select_route_proof(
        evidence, _matcher(evidence), FAMILY, snapshot=snapshot
    )
    calls = 0

    def no_match(_proof):
        nonlocal calls
        calls += 1
        return False

    with pytest.raises(ValueError, match="zero or multiple"):
        producer_api._select_route_proof(
            evidence, no_match, FAMILY, snapshot=snapshot
        )
    assert calls == len(evidence.route_proofs)


def test_noncanonical_input_and_uncallable_matcher_still_reject(evidence):
    snapshot = object()
    producer_api._select_route_proof(
        evidence, _matcher(evidence), FAMILY, snapshot=snapshot
    )
    with pytest.raises(TypeError, match="requires canonical semantic evidence"):
        producer_api._select_route_proof(
            object(), lambda proof: True, FAMILY, snapshot=snapshot
        )
    with pytest.raises(TypeError, match="matcher must be callable"):
        producer_api._select_route_proof(
            evidence, "not-callable", FAMILY, snapshot=snapshot
        )
