"""Focused canonical authority diagnostic projections."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority.diagnostics import (
    LegacyPhaseOutcome,
    PhaseTimings,
    ShadowParityCounters,
    compare_shadow_parity,
    require_shadow_parity,
    build_phase_payload,
    phase_observation,
)
from d810.transforms.unflatten_authority.legacy_codec import (
    LegacyShadowCodecReceipt,
    capture_legacy_unflatten_shadow,
    adapt_legacy_unflatten_shadow,
)
from d810.transforms.unflatten_authority.evaluate import build_semantic_case, evaluate_case
from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode
from .test_evaluate import _complete_inputs, _role_subject


def _codec_receipt() -> LegacyShadowCodecReceipt:
    from .test_legacy_codec import _real_full_shadow_fixture

    proposal, context, metadata = _real_full_shadow_fixture()
    _ordinary, shadow = capture_legacy_unflatten_shadow(
        plan_id=proposal.plan_id, snapshot_id="parity-snapshot",
        source_generation=1,
        metadata=tuple((key, value) for key, value in metadata.items()),
    )
    assert shadow is not None
    return adapt_legacy_unflatten_shadow(shadow, context=context)


def test_one_anchored_fact_observation_per_authoritative_phase() -> None:
    verdict = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority_id("authority"), binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("candidate"), safety_case=None,
        failed_obligations=(),
    )

    observation = phase_observation(
        verdict,
        maturity="MMAT_GLBOPT1",
        source_ea=0x401000,
        timings=PhaseTimings(inventory_ms=0.5),
    )

    assert observation.fact_id == f"plan:{authority_id('authority')}:precase-rejection"
    assert observation.kind == "unflatten_authority_phase"
    assert observation.semantic_key == authority_id("authority")
    assert observation.phase == "projected_preflight"
    assert observation.source_ea == 0x401000
    assert observation.block_fingerprint == authority_id("candidate")
    assert build_phase_payload(verdict)["schema"] == "unflatten_authority_phase.v1"


def test_payload_projects_only_the_semantic_loss_ledger() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "diagnostic-ledger")
    case = build_semantic_case(
        authority_id=authority_id("diagnostic-ledger"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    verdict = evaluate_case(case)
    payload = build_phase_payload(verdict)
    ledger = views.semantic_loss_ledger(case)
    assert payload["source_fingerprint"] == case.source_fingerprint
    assert len(payload["loss_ledger"]) == len(ledger.rows)
    assert len(payload["failed_obligations"]) == len(verdict.failed_obligations)
    assert all("classification" in row for row in payload["loss_ledger"])
    assert all(row.anchored_location.startswith("blk") for row in ledger.rows)
    assert all(row.source_binding.status is model.SubjectBindingStatus.UNIQUE for row in ledger.rows)
    assert all(row.candidate_binding.status is model.SubjectBindingStatus.MISSING for row in ledger.rows)
    assert "kind" not in model.SemanticLossRow.__dataclass_fields__
    assert canonical_decode(canonical_bytes(ledger.rows[0])) == ledger.rows[0]
    with pytest.raises(ValueError):
        replace(ledger.rows[0], evidence=())


def test_observed_precase_with_projected_case_is_total_and_typed() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "diagnostic-precase")
    projected_case = build_semantic_case(
        authority_id=authority_id("diagnostic-precase"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
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
    assert payload["observed_only_loss_rejection"]["reason"] == "observed_case_missing"


def test_shadow_parity_compares_legacy_and_canonical_per_phase() -> None:
    authority = authority_id("parity-authority")
    projected = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority, binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("parity-projected"), safety_case=None,
        failed_obligations=(),
    )
    observed = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        authority_id=authority, binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("parity-observed"), safety_case=None,
        failed_obligations=(),
    )

    payload = compare_shadow_parity(
        LegacyPhaseOutcome(
            projected.phase, False,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED, (),
        ),
        projected,
        LegacyPhaseOutcome(
            observed.phase, False,
            model.UnflattenAuthorityReason.LIVE_BINDING_FAILED, (),
        ),
        observed,
        projected_counters=ShadowParityCounters(1, 1, 1, 0),
        observed_counters=ShadowParityCounters(1, 1, 1, 0),
        codec_receipt=_codec_receipt(),
    )
    assert payload.projected.accepted_equal is True
    assert payload.observed.accepted_equal is True
    assert payload.authority_id == authority


def test_phase_observation_separates_projected_receipt_from_observed_final_parity() -> None:
    authority = authority_id("phase-boundary")
    projected = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority, binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("phase-projected"), safety_case=None,
        failed_obligations=(),
    )
    observed = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        authority_id=authority, binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("phase-observed"), safety_case=None,
        failed_obligations=(),
    )
    receipt = _codec_receipt()
    parity = compare_shadow_parity(
        LegacyPhaseOutcome(projected.phase, False, projected.reason, ()), projected,
        LegacyPhaseOutcome(observed.phase, False, observed.reason, ()), observed,
        projected_counters=ShadowParityCounters(1, 1, 1, 0),
        observed_counters=ShadowParityCounters(1, 1, 1, 0),
        codec_receipt=receipt,
    )
    projected_observation = phase_observation(
        projected, maturity="MMAT_GLBOPT1", source_ea=0x401000,
        timings=PhaseTimings(inventory_ms=1.0, binding_ms=2.0, evaluation_ms=3.0),
        codec_receipt=receipt,
    )
    assert "parity" not in projected_observation.payload
    assert projected_observation.payload["codec"]["captured_keys"] == receipt.consumed_keys
    projected_timing = projected_observation.payload["timings"]
    assert projected_timing["views_ms"] is not None
    assert projected_timing["total_authority_ms"] == pytest.approx(
        projected_timing["inventory_ms"]
        + projected_timing["binding_ms"]
        + projected_timing["evaluation_ms"]
        + projected_timing["views_ms"]
    )
    observed_observation = phase_observation(
        observed, maturity="MMAT_GLBOPT1", source_ea=0x401000,
        timings=PhaseTimings(inventory_ms=1.0, binding_ms=2.0, evaluation_ms=3.0),
        codec_receipt=receipt, parity_payload=parity,
    )
    assert observed_observation.payload["parity"] == parity.to_payload()


def test_shadow_parity_payload_serializes_exact_legacy_loss_labels() -> None:
    authority = authority_id("loss-labels")
    projected = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority, binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("loss-projected"), safety_case=None,
        failed_obligations=(),
    )
    observed = replace(
        projected,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
    )
    parity = compare_shadow_parity(
        LegacyPhaseOutcome(projected.phase, False, projected.reason, ((7, 0x401234),)),
        projected,
        LegacyPhaseOutcome(observed.phase, False, observed.reason, ((8, 0x402345),)),
        observed,
        projected_counters=ShadowParityCounters(1, 1, 1, 0),
        observed_counters=ShadowParityCounters(1, 1, 1, 0),
        codec_receipt=_codec_receipt(),
    )
    assert parity.to_payload()["legacy_anchored_loss_labels"] == {
        "projected": ("blk7@0x401234",),
        "observed": ("blk8@0x402345",),
    }


def test_shadow_parity_rejects_legacy_canonical_mismatch_in_either_phase() -> None:
    projected = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority_id("parity-mismatch"), binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("parity-projected"), safety_case=None,
        failed_obligations=(),
    )
    observed = replace(
        projected,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        reason=model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
    )
    projected_legacy = LegacyPhaseOutcome(
        projected.phase, False, model.UnflattenAuthorityReason.LIVE_BINDING_FAILED, (),
    )
    observed_legacy = LegacyPhaseOutcome(
        observed.phase, False, model.UnflattenAuthorityReason.LIVE_BINDING_FAILED, (),
    )
    payload = compare_shadow_parity(
        projected_legacy,
        projected,
        observed_legacy,
        observed,
        projected_counters=ShadowParityCounters(1, 1, 1, 0),
        observed_counters=ShadowParityCounters(1, 1, 1, 0),
        codec_receipt=_codec_receipt(),
    )
    assert payload.parity_ok is False
    with pytest.raises(ValueError, match="projected.*reason"):
        require_shadow_parity(payload)

    payload = compare_shadow_parity(
        LegacyPhaseOutcome(
            projected.phase, False,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED, (),
        ),
        projected,
        LegacyPhaseOutcome(
            observed.phase, False,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED, (),
        ),
        observed,
        projected_counters=ShadowParityCounters(1, 1, 1, 0),
        observed_counters=ShadowParityCounters(1, 1, 1, 0),
        codec_receipt=_codec_receipt(),
    )
    assert payload.parity_ok is False
    with pytest.raises(ValueError, match="observed.*reason"):
        require_shadow_parity(payload)


def test_shadow_parity_uses_real_projected_and_observed_case_provenance() -> None:
    """Observed source inventory reuse still renders the cumulative oracle tuple."""

    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.views import semantic_loss_ledger
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from .test_transaction_api import _full_corridor_fixture

    source, plan, projected, generic_gates = _full_corridor_fixture()
    attempt = transaction_api.TransactionAttemptId(
        plan.plan_id, authority_id("parity-session"), 1,
        authority_id("parity-attempt"),
    )
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=transaction_api.CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=generic_gates,
    )
    assert prepared.prepared is not None
    refs = {block.block_ref: block for block in plan.unflatten_proposal.source_identity_catalog.blocks}
    index = MbaBlockIdentityIndex.from_bindings(
        generation=attempt.generation,
        maturity=None,
        native_key=next(iter(refs)).identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=attempt.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in plan.source_coordinates),
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    bound = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared.prepared,
        patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
    )
    assert bound.authority is not None
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound.authority,
        observed=projected,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert observed.accepted
    projected_verdict = prepared.verdict
    observed_verdict = observed
    assert projected_verdict.safety_case is not None
    assert observed_verdict.safety_case is not None

    def outcome(verdict):
        rows = semantic_loss_ledger(verdict.safety_case).rows
        return LegacyPhaseOutcome(
            verdict.phase,
            verdict.accepted,
            verdict.reason,
            tuple(sorted((row.source_serial, row.source_anchor_ea) for row in rows)),
        )

    payload = compare_shadow_parity(
        outcome(projected_verdict), projected_verdict,
        outcome(observed_verdict), observed_verdict,
        projected_counters=ShadowParityCounters.from_case(projected_verdict.safety_case),
        observed_counters=ShadowParityCounters.from_case(observed_verdict.safety_case),
        codec_receipt=_codec_receipt(),
    )
    assert payload.parity_ok
    assert payload.projected_case_id != payload.observed_case_id
    assert payload.projected_counters.tuple == (1, 1, 1, 0)
    assert payload.observed_counters.tuple == (1, 1, 1, 0)
    codec_payload = payload.to_payload()["codec"]
    assert codec_payload["all_adapted"] is True
    assert tuple(codec_payload["captured_keys"]) == payload.codec_receipt.consumed_keys
    assert build_phase_payload(observed_verdict)["metrics"] == {
        "source_inventory_builds": 1,
        "candidate_inventory_builds": 1,
        "inventory_ms": observed_verdict.safety_case.phase_metrics.phase_build_metrics.inventory_ms,
        "index_folds": 1,
        "view_graph_traversals": 0,
        "local_phase_build": {
            "source_inventory_builds": 0,
            "candidate_inventory_builds": 1,
        },
    }
