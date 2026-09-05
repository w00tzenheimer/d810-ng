"""The observed-side seam refusal reports its own stage, not the inventory's.

This is the behavioural half of
``tests/unit/transforms/unflatten_authority/test_transaction_runtime_authority.py::
test_the_observed_seam_refusal_has_its_own_provenance``.  It lives here because
the observed revalidation fixture needs ``d810.hexrays`` (the patch binding and
the MBA identity index), which a unit test may not import.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import fields, replace
from pathlib import Path

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    RouteRebindVerification,
    canonical_semantic_evidence_from_proofs,
    materialize_route_evidence,
    route_authority_phase,
)
from d810.core.runtime_identity import RuntimeJoinRejected
from d810.transforms.unflatten_authority.canonical_session import (
    active_canonical_session,
)
from d810.hexrays.mutation import patch_transaction
from d810.hexrays.mutation.patch_transaction import (
    PatchTransactionExecution,
    PreparedPatchCfgTransaction,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.patch_binding import bind_patch_plan
from d810.transforms.cfg_transaction import CfgProjection
from d810.transforms.unflatten_authority import transaction_api
from tests.unit.transforms.unflatten_authority.helpers import (
    observed_patch_binding_for_test,
)
from tests.unit.transforms.unflatten_authority.test_transaction_api import (
    _c1_direct_preparation_case,
)


def fields_by_name(record) -> dict:
    return {item.name: item for item in fields(record)}


_LIVE_MATURITY = 8  # MMAT_GLBOPT1; the live binder needs a real provider stage


def _bound_authority(bundle_state: str = "live"):
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    if bundle_state != "live":
        proposal = plan.unflatten_proposal
        if bundle_state == "dead":
            # Exactly what the emission does: build the bundle inside a phase
            # that ends before either transaction phase runs.
            with route_authority_phase("test-emission"):
                evidence = canonical_semantic_evidence_from_proofs(
                    native_key=proposal.route_evidence.native_key,
                    generation=proposal.route_evidence.generation,
                    proofs=proposal.route_evidence.route_proofs,
                )
        else:
            evidence = materialize_route_evidence(proposal.route_evidence)
        plan = replace(
            plan,
            unflatten_proposal=replace(proposal, route_evidence=evidence),
        )
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert preparation.prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=fixture.attempt_id.generation,
        maturity=_LIVE_MATURITY,
        native_key=refs[0][0].identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=fixture.attempt_id.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(fixture.attempt_id, quantity=len(source.blocks))
    binding = transaction_api.bind_prepared_unflatten_authority(
        prepared=preparation.prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    )
    assert binding.authority is not None
    return {
        "authority": binding.authority,
        "observed": projected,
        "observed_generation": fixture.attempt_id.generation,
        "generic_gates": gates,
        "observed_patch_binding": observed_patch_binding_for_test(binding.authority),
    }


def test_the_observed_seam_is_reached_and_reports_its_own_stage(
    monkeypatch, caplog,
) -> None:
    arguments = _bound_authority()

    reached: list[object] = []
    real = transaction_api._record_route_authority_rebind

    def _observed(evidence, *, phase):
        reached.append(phase)
        return real(evidence, phase=phase)

    monkeypatch.setattr(transaction_api, "_record_route_authority_rebind", _observed)
    accepted = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert accepted.accepted
    assert reached  # the seam really is on the observed production path

    def _refused(evidence, *, phase):
        raise RuntimeJoinRejected("the observed seam refuses this bundle")

    monkeypatch.setattr(transaction_api, "_record_route_authority_rebind", _refused)
    with caplog.at_level(logging.WARNING, logger="d810.transforms.unflatten_authority.transaction_api"):
        refused = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert not refused.accepted
    messages = [record.getMessage() for record in caplog.records]
    assert any("observed_route_authority_rebind" in message for message in messages)
    assert not any("observed_inventory" in message for message in messages)


def test_the_commit_receipt_carries_the_projected_seam_verification() -> None:
    """The receipt is the surface that outlives both sessions and both arenas.

    A committed receipt is read long after the transaction: the canonical
    validation sessions are closed, the producer's arena is gone and so is the
    transaction's, so ``transaction_route_verification`` cannot answer any
    more.  The value therefore has to be carried, and this is where it lands.
    """

    receipt = PatchTransactionExecution(
        applied_count=1,
        graph=_bound_authority()["observed"],
        receipt=object(),
        projected_route_authority_verification=(
            RouteRebindVerification.PRODUCER_ARENA_CLOSED
        ),
    )

    assert receipt.projected_route_authority_verification is (
        RouteRebindVerification.PRODUCER_ARENA_CLOSED
    )
    # Non-authoritative: absent is the default and is not a rejection.
    assert PatchTransactionExecution(
        applied_count=1, graph=receipt.graph, receipt=object(),
    ).projected_route_authority_verification is None
    assert (
        fields_by_name(PreparedPatchCfgTransaction)[
            "projected_route_authority_verification"
        ].default
        is None
    )


def test_the_participant_copies_the_verification_off_the_preparation_result() -> None:
    """The wiring, without needing a live MBA to drive a whole transaction."""

    tree = ast.parse(Path(patch_transaction.__file__).read_text())
    reads = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "route_authority_verification"
    ]
    assert len(reads) == 1

    passed = {
        keyword.arg
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {
            "PreparedPatchCfgTransaction", "PatchTransactionExecution",
        }
        for keyword in node.keywords
    }
    assert "projected_route_authority_verification" in passed


@pytest.mark.parametrize(
    "bundle_state,expected",
    (
        ("live", RouteRebindVerification.PRODUCER_RECORDS_VERIFIED),
        ("dead", RouteRebindVerification.PRODUCER_ARENA_CLOSED),
        ("absent", RouteRebindVerification.PRODUCER_UNBOUND),
    ),
)
def test_the_observed_verdict_carries_what_the_seam_verified(
    bundle_state: str, expected: RouteRebindVerification,
) -> None:
    """The observed phase returns only a verdict, so the verdict carries it.

    Read after the whole revalidation has returned: the observed session is
    closed and both arenas are gone, so this is the only surviving answer to
    "what could the seam verify".
    """

    arguments = _bound_authority(bundle_state)

    verdict = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert verdict.route_authority_verification is expected
    assert active_canonical_session() is None
    # Non-authoritative: the weakest outcome does not reject anything.
    assert verdict.accepted


def test_a_rejected_observed_verdict_carries_it_too(monkeypatch) -> None:
    """A rejection is exactly when a reader most wants the provenance."""

    arguments = _bound_authority("dead")
    real = transaction_api._build_semantic_graph_inventory

    def _broken(*args, **kwargs):
        raise ValueError("observed inventory refused for this test")

    monkeypatch.setattr(transaction_api, "_build_semantic_graph_inventory", _broken)
    verdict = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert not verdict.accepted
    assert "observed_inventory" in (verdict.rejection_detail or "")
    assert verdict.route_authority_verification is (
        RouteRebindVerification.PRODUCER_ARENA_CLOSED
    )
    assert real is not _broken
