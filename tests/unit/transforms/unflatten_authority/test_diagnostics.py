"""Focused canonical authority diagnostic projections."""

from __future__ import annotations

from dataclasses import replace
import re

import pytest

from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority.diagnostics import (
    CanonicalPhaseCounters,
    PhaseTimings,
    build_phase_payload,
    phase_observation,
)
from d810.transforms.unflatten_authority.evaluate import build_semantic_case, evaluate_case
from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode
from d810.transforms.cfg_transaction import TransactionAttemptId
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
        verdict, maturity="MMAT_GLBOPT1", source_ea=0x401000,
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
    assert observation.payload["schema_version"] == 1
    assert observation.payload["rule_set_version"] == 1
    assert observation.payload["verdict"] == "rejected"
    assert observation.payload["log_lines"]
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
    assert all(
        {"supports", "refutes"} <= set(row)
        for row in payload["obligation_states"]
    )
    assert len(payload["explanations"]) == len(case.justifications)
    assert all(row.anchored_location.startswith("blk") for row in ledger.rows)
    assert all(row.source_binding.status is model.SubjectBindingStatus.UNIQUE for row in ledger.rows)
    assert all(row.candidate_binding.status is model.SubjectBindingStatus.MISSING for row in ledger.rows)
    assert all(
        re.fullmatch(r"blk[0-9]+@0x[0-9a-f]+", row["anchor"])
        for row in payload["loss_ledger"]
    )
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
        authority_id=projected_case.authority_id, binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("observed-precase"), safety_case=None,
        failed_obligations=(),
    )
    payload = build_phase_payload(verdict, projected_case=projected_case)
    assert payload["source_fingerprint"] == projected_case.source_fingerprint
    assert payload["loss_ledger"] == ()
    assert payload["observed_only_loss"] == ()
    assert payload["observed_only_loss_rejection"]["reason"] == "observed_case_missing"


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
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "diagnostic-counters")
    case = build_semantic_case(
        authority_id=authority_id("diagnostic-counters"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    assert CanonicalPhaseCounters.from_case(case).tuple == (1, 1, 1, 0)


def test_complete_phase_timings_require_the_canonical_component_sum() -> None:
    with pytest.raises(ValueError, match="must equal"):
        PhaseTimings(
            inventory_ms=1.0,
            binding_ms=2.0,
            evaluation_ms=3.0,
            views_ms=4.0,
            total_authority_ms=11.0,
        )
    assert PhaseTimings(
        inventory_ms=1.0,
        binding_ms=2.0,
        evaluation_ms=3.0,
        views_ms=4.0,
        total_authority_ms=10.0,
    ).total_authority_ms == 10.0


def test_one_anchored_fact_observation_per_case_phase_has_exact_ids_and_labels() -> None:
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _full_corridor_fixture

    source, plan, projected_graph, generic_gates = _full_corridor_fixture()
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("diagnostic-session"), 1,
        authority_id("diagnostic-attempt"),
    )
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=transaction_api.CfgProjection(
            plan.plan_id, plan.snapshot_id, projected_graph,
        ),
        plan=plan,
        attempt_id=attempt,
        generic_gates=generic_gates,
    )
    projected = prepared.verdict
    assert prepared.prepared is not None
    assert projected.safety_case is not None
    refs = {
        block.block_ref: block
        for block in plan.unflatten_proposal.source_identity_catalog.blocks
    }
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
        observed=projected_graph,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert observed.accepted
    authority = projected.authority_id
    rows = tuple(
        phase_observation(
            verdict, maturity="MMAT_GLBOPT1", source_ea=0x401000,
            correlation=attempt,
        )
        for verdict in (projected, observed)
    )
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
    assert all("serial" not in binding for row in rows for binding in row.payload["bindings"])
    assert all(
        re.fullmatch(r"(blk[0-9]+|subject:[^@]+)(@0x[0-9a-f]+)?", item["subject"])
        for row in rows for item in row.payload["obligation_states"]
    )
