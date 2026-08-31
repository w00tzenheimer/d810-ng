"""Focused canonical authority diagnostic projections."""

from __future__ import annotations

from dataclasses import replace
import re
from types import SimpleNamespace

import pytest

from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority.diagnostics import (
    CanonicalPhaseCounters,
    PhaseTimings,
    build_phase_payload,
    native_bound_transition_route_receipts_from_plan,
    phase_observation,
)
from d810.transforms.unflatten_authority.evaluate import (
    build_semantic_case,
    evaluate_case,
)
from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode
from d810.transforms.cfg_transaction import TransactionAttemptId
from .test_evaluate import _complete_inputs, _role_subject


@pytest.mark.parametrize("fact_kind", ("native_bound", "state_carrier"))
def test_native_bound_receipt_projects_from_canonical_plan(fact_kind: str) -> None:
    """Typed plans diagnose from selected proof and step, never legacy metadata."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticRouteDestination,
        SemanticRouteProof,
        SemanticRouteProofKind,
        SemanticRouteShape,
        SemanticStateWriteDeliveryKind,
        SemanticStateWriteProof,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.ir.block_identity import NativeEaInterval
    from d810.ir.semantic_edge import SemanticEdgeRole
    from d810.transforms.graph_modification import RedirectGoto
    from d810.transforms.unflatten_authority import producer_api
    from tests.typed_patch_authority import compile_patch_plan
    from .helpers import exact_fixture

    source, base, _exclusion, refs = exact_fixture()
    state = base.plan_inputs.state_identity
    proof = SemanticRouteProof(
        proof_id="native-bound-diagnostic",
        atomic_group_id="native-bound-diagnostic-group",
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=refs[0].identity,
        source_anchor_ea=0x1000,
        delivery_region=NativeEaInterval(0x1000, 0x1001),
        destinations=(SemanticRouteDestination(
            SemanticEdgeRole.DIRECT,
            7,
            refs[2].identity,
            0x3000,
        ),),
        state_write=SemanticStateWriteProof(
            refs[0].identity,
            0x1000,
            state,
            4,
            7,
            (0x1000,),
            None,
            (),
            SemanticStateWriteDeliveryKind.INDIRECT,
        ),
        diagnostic_provenance=(
            ("fact_id", "transition:state=0x7:target=2:resolver=exact"),
            ("fact_kind", fact_kind),
        ),
    )
    evidence = canonical_semantic_evidence_from_proofs(
        base.route_evidence.native_key,
        base.route_evidence.generation,
        (proof,),
    )
    proposal = producer_api.build_proposal(
        plan_id=base.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=base.source_identity_catalog.generation,
        canonical_route_evidence=evidence,
        selected_route_proof_ids=(evidence.route_proofs[0].proof_id,),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=state,
        use_def_witness=base.use_def_witness,
    )
    plan = compile_patch_plan(
        (RedirectGoto(0, 1, 2),),
        source,
        plan_id=base.plan_id,
        source_generation=base.source_identity_catalog.generation,
        block_refs_by_serial=refs,
    )
    plan = replace(plan, unflatten_proposal=proposal)

    assert native_bound_transition_route_receipts_from_plan(plan) == (
        __import__(
            "d810.transforms.unflatten_authority.legacy_codec",
            fromlist=["NativeBoundTransitionRouteReceipt"],
        ).NativeBoundTransitionRouteReceipt(
            fact_id="transition:state=0x7:target=2:resolver=exact",
            native_ea=0x1000,
            current_block="blk0@0x1000",
            state=7,
            target=2,
            target_block="blk2@0x3000",
            operation_key=("block_goto_change", 0, 1, 2),
        ),
    )


def test_one_anchored_fact_observation_per_authoritative_phase() -> None:
    verdict = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority_id("authority"),
        binding_id=None,
        case_id=None,
        candidate_fingerprint=authority_id("candidate"),
        safety_case=None,
        failed_obligations=(),
    )
    observation = phase_observation(
        verdict,
        maturity="MMAT_GLBOPT1",
        source_ea=0x401000,
        timings=PhaseTimings(inventory_ms=0.5),
    )
    assert observation.fact_id.startswith("sha256:")
    assert observation.kind == "unflatten_authority_phase"
    assert observation.semantic_key == authority_id("authority")
    assert observation.phase == "projected_preflight"
    assert observation.source_ea == 0x401000
    assert observation.block_fingerprint == authority_id("candidate")
    assert observation.payload["binding_id"] is None
    assert observation.payload["loss_ledger"] == ()
    assert observation.payload["schema_version"] == 2
    assert observation.payload["rule_set_version"] == 1
    assert observation.payload["verdict"] == "rejected"
    assert observation.payload["log_lines"]
    assert build_phase_payload(verdict)["schema"] == "unflatten_authority_phase.v2"


def test_direct_diagnostics_project_receipted_ledgers_without_rebuilding_them(
    monkeypatch,
) -> None:
    """Accepted records render the transaction occurrences, not view products."""
    from .test_views import _bound_direct_authority_cases
    import d810.transforms.unflatten_authority.diagnostics as diagnostics

    prepared, accepted = _bound_direct_authority_cases(exact_effect_loss=True)
    observed_case = accepted.observed_case
    verdict = model.UnflattenAuthorityVerdict(
        accepted=True,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.ACCEPTED,
        authority_id=observed_case.authority_id,
        binding_id=accepted.bound_authority.binding_id,
        case_id=observed_case.case_id,
        candidate_fingerprint=observed_case.candidate_fingerprint,
        safety_case=observed_case,
        failed_obligations=(),
        observed_acceptance=accepted,
        loss_ledger=accepted.observed_ledger,
    )
    monkeypatch.setattr(
        diagnostics,
        "observed_loss_delta",
        lambda _projected, _observed: pytest.fail(
            "accepted diagnostics rebuilt a delta"
        ),
    )

    payload = build_phase_payload(verdict)

    assert (
        payload["authority_id"] == prepared.authority_id == observed_case.authority_id
    )
    assert tuple(row["anchor"] for row in payload["loss_ledger"]) == tuple(
        row.anchored_location for row in accepted.observed_ledger.rows
    )
    assert tuple(row["anchor"] for row in payload["observed_only_loss"]) == tuple(
        row.anchored_location for row in accepted.delta.rows
    )
    assert payload["loss_summary"]["observed_only"] == tuple(
        row.anchored_location for row in accepted.delta.rows
    )


def test_direct_projected_diagnostics_require_the_prepared_ledger_occurrence() -> None:
    """Projected acceptance is rendered from preparation, never from its case."""
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert result.prepared is not None
    payload = build_phase_payload(
        result.verdict,
        prepared_authority=result.prepared,
    )

    assert payload["authority_id"] == result.prepared.authority_id
    assert tuple(row["anchor"] for row in payload["loss_ledger"]) == tuple(
        row.anchored_location for row in result.prepared.projected_loss_ledger.rows
    )


def test_observed_precase_with_projected_case_is_total_and_typed() -> None:
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert preparation.prepared is not None
    projected_case = preparation.prepared.projected_case
    verdict = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        authority_id=projected_case.authority_id,
        binding_id=None,
        case_id=None,
        candidate_fingerprint=authority_id("observed-precase"),
        safety_case=None,
        failed_obligations=(),
    )
    payload = build_phase_payload(verdict, projected_case=projected_case)
    assert payload["source_fingerprint"] == projected_case.source_fingerprint
    assert payload["loss_ledger"] == ()
    assert payload["observed_only_loss"] == ()
    assert (
        payload["observed_only_loss_rejection"]["reason"]
        == "canonical_observed_ledger_missing"
    )


def test_accepted_observed_diagnostics_do_not_reclassify_a_receipted_ledger(
    monkeypatch,
) -> None:
    from .test_views import _bound_direct_authority_cases

    prepared, accepted = _bound_direct_authority_cases(exact_effect_loss=True)
    observed_case = accepted.observed_case
    verdict = model.UnflattenAuthorityVerdict(
        accepted=True,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.ACCEPTED,
        authority_id=observed_case.authority_id,
        binding_id=accepted.bound_authority.binding_id,
        case_id=observed_case.case_id,
        candidate_fingerprint=observed_case.candidate_fingerprint,
        safety_case=observed_case,
        failed_obligations=(),
        observed_acceptance=accepted,
        loss_ledger=accepted.observed_ledger,
    )

    observation = phase_observation(
        verdict,
        maturity="MMAT_GLBOPT1",
        source_ea=0x401000,
        correlation=TransactionAttemptId(
            authority_id("diagnostic-plan"),
            authority_id("diagnostic-session"),
            3,
            authority_id("diagnostic-attempt"),
        ),
    )

    records = observation.payload["observed_loss_reclassification"]
    assert records == ()
    assert observation.payload["authority_id"] == observed_case.authority_id
    assert observation.payload["plan_id"] == authority_id("diagnostic-plan")
    assert observation.payload["session_id"] == authority_id("diagnostic-session")
    assert observation.payload["generation"] == 3

    import d810.hexrays.observability as authority_observability
    from d810.core import observability_preanalysis

    captured = []
    monkeypatch.setattr(
        authority_observability,
        "request_capture_mba_snapshot",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not capture MBA")),
    )
    monkeypatch.setattr(
        authority_observability,
        "mba_to_block_snapshots",
        lambda _mba: (_ for _ in ()).throw(AssertionError("must not serialize MBA")),
    )
    monkeypatch.setattr(
        authority_observability, "_has_subscribers", lambda _event: True
    )
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_fact_observations_for_latest_snapshot",
        lambda source_ea, observations: captured.append((source_ea, observations)),
    )
    authority_observability.observe_unflatten_authority_phase(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=0),
        verdict=verdict,
        observation_factory=lambda: (observation,),
    )
    assert len(captured) == 1
    assert captured[0][0] == 0x401000
    persisted = captured[0][1][0]
    assert (
        persisted.fact_id
        == f"{observation.fact_id}:attempt:{observation.payload['attempt_id']}"
    )
    assert persisted.payload["canonical_fact_id"] == observation.fact_id


def test_precase_fact_id_excludes_attempt_correlation() -> None:
    verdict = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority_id("stable-precase-authority"),
        binding_id=None,
        case_id=None,
        candidate_fingerprint=authority_id("stable-precase-candidate"),
        safety_case=None,
        failed_obligations=(),
    )
    correlations = tuple(
        TransactionAttemptId(
            authority_id("stable-precase-plan"),
            authority_id("stable-precase-session"),
            7,
            authority_id(attempt),
        )
        for attempt in ("attempt-one", "attempt-two")
    )
    rows = tuple(
        phase_observation(
            verdict,
            maturity="MMAT_GLBOPT1",
            source_ea=0x401000,
            correlation=correlation,
        )
        for correlation in correlations
    )
    assert rows[0].fact_id == rows[1].fact_id
    assert rows[0].payload["attempt_id"] != rows[1].payload["attempt_id"]


def test_observed_precase_fact_id_excludes_attempt_bound_binding_id() -> None:
    verdicts = tuple(
        model.UnflattenAuthorityVerdict(
            accepted=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            reason=model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
            authority_id=authority_id("stable-observed-precase-authority"),
            binding_id=authority_id(binding),
            case_id=None,
            candidate_fingerprint=authority_id("stable-observed-precase-candidate"),
            safety_case=None,
            failed_obligations=(),
        )
        for binding in ("binding-attempt-one", "binding-attempt-two")
    )
    rows = tuple(
        phase_observation(
            verdict,
            maturity="MMAT_GLBOPT1",
            source_ea=0x401000,
        )
        for verdict in verdicts
    )
    assert rows[0].fact_id == rows[1].fact_id
    assert rows[0].payload["binding_id"] != rows[1].payload["binding_id"]


def test_canonical_phase_counters_are_derived_from_case_metrics() -> None:
    from .test_views import _bound_direct_authority_cases

    prepared, _accepted = _bound_direct_authority_cases()
    counters = CanonicalPhaseCounters.from_case(prepared.projected_case)
    assert counters.source_inventory_builds == 1
    assert counters.candidate_inventory_builds == 1
    assert counters.view_graph_traversals == 0


def test_complete_phase_timings_require_the_canonical_component_sum() -> None:
    with pytest.raises(ValueError, match="must equal"):
        PhaseTimings(
            inventory_ms=1.0,
            binding_ms=2.0,
            evaluation_ms=3.0,
            views_ms=4.0,
            total_authority_ms=11.0,
        )
    assert (
        PhaseTimings(
            inventory_ms=1.0,
            binding_ms=2.0,
            evaluation_ms=3.0,
            views_ms=4.0,
            total_authority_ms=10.0,
        ).total_authority_ms
        == 10.0
    )


def test_one_anchored_fact_observation_per_case_phase_has_exact_ids_and_labels() -> (
    None
):
    from .test_views import _bound_direct_authority_cases

    prepared, accepted = _bound_direct_authority_cases(exact_effect_loss=True)
    attempt = accepted.bound_authority.attempt_id
    projected = model.UnflattenAuthorityVerdict(
        accepted=True,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.ACCEPTED,
        authority_id=prepared.authority_id,
        binding_id=None,
        case_id=prepared.projected_case.case_id,
        candidate_fingerprint=prepared.projected_case.candidate_fingerprint,
        safety_case=prepared.projected_case,
        failed_obligations=(),
        loss_ledger=prepared.projected_loss_ledger,
    )
    observed = model.UnflattenAuthorityVerdict(
        accepted=True,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.ACCEPTED,
        authority_id=accepted.observed_case.authority_id,
        binding_id=accepted.bound_authority.binding_id,
        case_id=accepted.observed_case.case_id,
        candidate_fingerprint=accepted.observed_case.candidate_fingerprint,
        safety_case=accepted.observed_case,
        failed_obligations=(),
        observed_acceptance=accepted,
        loss_ledger=accepted.observed_ledger,
    )
    rows = (
        phase_observation(
            projected,
            maturity="MMAT_GLBOPT1",
            source_ea=0x401000,
            correlation=attempt,
            prepared_authority=prepared,
        ),
        phase_observation(
            observed,
            maturity="MMAT_GLBOPT1",
            source_ea=0x401000,
            correlation=attempt,
        ),
    )
    authority = prepared.authority_id
    assert len(rows) == 2
    assert {row.phase for row in rows} == {"projected_preflight", "observed_post_apply"}
    assert {row.payload["authority_id"] for row in rows} == {authority}
    assert len({row.fact_id for row in rows}) == 2
    assert all(row.payload["case_id"] for row in rows)
    assert rows[0].payload["binding_id"] is None
    assert rows[1].payload["binding_id"] == observed.binding_id
    assert all(row.payload["plan_id"] == attempt.plan_id for row in rows)
    assert all(row.payload["attempt_id"] == attempt.attempt_id for row in rows)
    assert all(row.payload["session_id"] == attempt.session_id for row in rows)
    assert all(row.payload["generation"] == attempt.generation for row in rows)
    assert all(
        "serial" not in binding for row in rows for binding in row.payload["bindings"]
    )
    assert all(
        re.fullmatch(r"(blk[0-9]+|subject:[^@]+)(@0x[0-9a-f]+)?", item["subject"])
        for row in rows
        for item in row.payload["obligation_states"]
    )
    assert all(
        re.fullmatch(r"sha256:[0-9a-f]{64}", item["subject_id"])
        for row in rows
        for item in row.payload["obligation_states"]
    )
    assert all(
        set(item) == {"subject", "subject_id", "dimension", "state"}
        for row in rows
        for item in row.payload["coverage"]
    )
    assert all(
        re.fullmatch(r"sha256:[0-9a-f]{64}", item["subject_id"])
        for row in rows
        for item in row.payload["loss_ledger"]
    )
    assert all(
        set(item["conclusion"]) == {"subject", "subject_id", "dimension"}
        and re.fullmatch(r"sha256:[0-9a-f]{64}", item["conclusion"]["subject_id"])
        for row in rows
        for item in row.payload["explanations"]
    )
