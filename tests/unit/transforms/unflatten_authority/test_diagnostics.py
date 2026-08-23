"""Focused canonical authority diagnostic projections."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority.diagnostics import (
    PhaseTimings,
    build_phase_payload,
    phase_observation,
)
from d810.transforms.unflatten_authority.evaluate import build_semantic_case, evaluate_case
from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode
from .test_evaluate import _complete_inputs, _role_subject


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
