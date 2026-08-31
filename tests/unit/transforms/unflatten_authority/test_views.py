"""Graph-free evaluator views."""

from __future__ import annotations

from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority import model
from .test_evaluate import _complete_inputs, _role_subject, authority_id
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
from d810.transforms.unflatten_authority.ids import _subject_factory
import pytest
from dataclasses import FrozenInstanceError, replace
from .helpers import observed_patch_binding_for_test


def _bound_direct_authority_cases(*, exact_effect_loss: bool = False):
    """Return the exact source/projected/observed authority occurrences."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import (
        _c1_direct_preparation_case,
        _c2_exact_direct_preparation_case,
    )

    if exact_effect_loss:
        source, plan, projected, attempt, gates = _c2_exact_direct_preparation_case()
    else:
        fixture, source, plan, projected, gates = _c1_direct_preparation_case()
        attempt = fixture.attempt_id
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert preparation.prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=attempt.generation,
        maturity=None,
        native_key=refs[0][0].identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=attempt.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    binding = transaction_api.bind_prepared_unflatten_authority(
        prepared=preparation.prepared,
        patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
    )
    assert binding.authority is not None
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=binding.authority,
        observed=projected,
        observed_generation=attempt.generation,
        generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(binding.authority),
    )
    assert observed.accepted and observed.observed_acceptance is not None
    return preparation.prepared, observed.observed_acceptance


def test_views_export_read_only_case_projections() -> None:
    assert views.VIEW_GRAPH_TRAVERSALS == 0
    assert callable(views.obligation_states)
    assert callable(views.failed_obligations)
    assert callable(views.evidence_ids)
    assert callable(views.exact_effect_loss_view)
    assert views.ExactEffectLossView.__dataclass_params__ is not None
    assert "case" in __import__("inspect").signature(views.exact_effect_loss_view).parameters
    assert "retirement_rows" in views.__all__
    assert "corridor_coverage_rows" in views.__all__
    assert "terminal_cycle_rows" in views.__all__
    assert "detached_component_rows" in views.__all__
    assert callable(views.detached_component_rows)


def test_compatibility_projection_is_immutable_and_phase_anchored() -> None:
    projected = model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id("compat-projected-authority"),
        None,
        None,
        authority_id("compat-projected-candidate"),
        None,
        (),
    )
    observed = model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        authority_id("compat-observed-authority"),
        authority_id("compat-observed-binding"),
        None,
        authority_id("compat-observed-candidate"),
        None,
        (),
    )

    projected_view = views.compatibility_projection(projected, "removal")
    observed_view = views.compatibility_projection(observed, "coverage")
    assert projected_view is not None and observed_view is not None
    assert projected_view.phase == "projected_preflight"
    assert projected_view.authority_id == projected.authority_id
    assert observed_view.phase == "observed_post_apply"
    assert observed_view.authority_id == observed.authority_id
    assert observed_view.binding_id == observed.binding_id
    assert observed_view.to_payload()["validation_status"] == "rejected"
    assert observed_view.to_payload()["candidate_fingerprint"] == observed.candidate_fingerprint
    with pytest.raises(FrozenInstanceError):
        projected_view.passed = False
    assert views.VIEW_GRAPH_TRAVERSALS == 0


def test_compatibility_projection_preserves_case_owned_ids_and_failed_states() -> None:
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    attempt = fixture.attempt_id
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert result.prepared is not None
    assert result.verdict.accepted
    assert result.verdict.safety_case is not None
    view = views.compatibility_projection(result.verdict, "coverage")
    assert view is not None
    assert view.case_id == result.verdict.case_id
    assert view.candidate_fingerprint == result.verdict.candidate_fingerprint
    assert view.failed_obligation_states == ()
    payload = view.to_payload()
    assert payload["case_id"] == result.verdict.case_id
    assert payload["validation_status"] == "accepted"
    projected_ledger = result.prepared.projected_loss_ledger
    assert projected_ledger.case is result.prepared.projected_case
    assert result.verdict.loss_ledger is projected_ledger
    with pytest.raises(ValueError, match="one unambiguous retirement claim"):
        views.retirement_rows(result.prepared.projected_case, projected_ledger)


def test_terminal_cycle_view_projects_only_cycle_and_terminal_authority() -> None:
    from .test_bind import _terminal_cycle_derived_inputs

    _proposal, claim, inputs, _source, _candidate, _residual = (
        _terminal_cycle_derived_inputs()
    )
    case = build_semantic_case(
        authority_id=authority_id("terminal-cycle-view"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    view = views.terminal_cycle_rows(case, claim.claim_id)
    assert view.claim_id == claim.claim_id
    assert view.cycle_subject_id == claim.cycle_subject.subject_id
    assert view.cleanup_source_subject_id == claim.cleanup_source_subject.subject_id
    assert view.terminal_subject_id == claim.terminal_subject.subject_id
    assert view.route_proof_ids == claim.terminal_route_proof_ids
    assert view.structural_justification_ids
    assert view.terminal_justification_ids
    terminal_justifications = {
        item.justification_id: item
        for item in case.justifications
        if item.justification_id in view.terminal_justification_ids
    }
    assert terminal_justifications
    assert all(
        item.claim_id == claim.claim_id
        and item.rule is model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
        for item in terminal_justifications.values()
    )


def test_semantic_loss_ledger_and_observed_delta_are_closed_projections() -> None:
    assert tuple(model.SemanticLossKind) == (
        model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        model.SemanticLossKind.EQUIVALENT_SEMANTIC_ROUTE,
        model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT,
        model.SemanticLossKind.TERMINAL_CYCLE_BREAK,
        model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION,
        model.SemanticLossKind.DETACHED_DEAD_HANDLER_COMPONENT,
        model.SemanticLossKind.COMPOSITE_ALLOWED,
        model.SemanticLossKind.UNCLASSIFIED,
        model.SemanticLossKind.CONFLICTING,
    )
    assert callable(views.semantic_loss_ledger)
    assert callable(views.observed_only_loss)


def test_loss_rows_require_exact_source_binding_provenance() -> None:
    assert "source_binding" in model.SemanticLossRow.__dataclass_fields__
    assert "case" in model.SemanticLossRow.__dataclass_fields__
    assert "justifications" in model.SemanticLossRow.__dataclass_fields__


def test_compatibility_loss_row_is_not_an_authority_row() -> None:
    prepared, _accepted = _bound_direct_authority_cases(exact_effect_loss=True)
    row = views.semantic_loss_projection(prepared.projected_loss_ledger).rows[0]
    assert type(row) is views.SemanticLossProjectionRow
    assert "case" not in row.__dataclass_fields__
    assert row.source_subject in prepared.projected_case.subjects
    assert row.kind is model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT
    assert row.classification_kinds == (
        model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT,
    )


def test_observed_delta_rejects_wrong_phase_before_comparing_rows() -> None:
    prepared, _accepted = _bound_direct_authority_cases()
    with pytest.raises(ValueError, match="observed case"):
        views.observed_only_loss(
            prepared.projected_loss_ledger,
            prepared.projected_loss_ledger,
        )


def test_compatibility_observed_delta_is_a_non_authoritative_projection() -> None:
    prepared, accepted = _bound_direct_authority_cases(exact_effect_loss=True)
    projected_ledger = prepared.projected_loss_ledger
    observed_ledger = accepted.observed_ledger
    projection = views.observed_loss_delta(projected_ledger, observed_ledger)

    assert projection.rows == ()
    assert projection.reclassifications == ()
    assert "authority_id" not in projection.__dataclass_fields__
    assert "ledger_id" not in projection.__dataclass_fields__
    assert views.observed_only_loss(projected_ledger, observed_ledger) == ()
