"""Graph-free evaluator views."""

from __future__ import annotations

from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority import model
from .test_evaluate import _complete_inputs, _role_subject, authority_id
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
from d810.transforms.unflatten_authority.ids import _subject_factory
import pytest
from dataclasses import FrozenInstanceError, replace


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
    from .test_transaction_api import _full_corridor_fixture

    source, plan, projected, gates = _full_corridor_fixture()
    attempt = TransactionAttemptId(
        plan.plan_id,
        authority_id("compat-case-session"),
        1,
        authority_id("compat-case-attempt"),
    )
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
    retirement = views.retirement_rows(result.prepared.projected_case)
    assert retirement.retired_member_subject_ids
    assert retirement.retained_member_subject_ids
    structural_cells = {
        cell.key.subject.subject_id: cell
        for cell in result.prepared.projected_case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
    }
    assert all(
        structural_cells[subject_id].state is model.ObligationState.SATISFIED
        for subject_id in (
            *retirement.retired_member_subject_ids,
            *retirement.retained_member_subject_ids,
        )
    )


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


def test_corridor_coverage_view_projects_the_case_owned_aggregate() -> None:
    entry = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0")
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    corridor = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=entry.block_ref,
        anchor_ea=entry.anchor_ea,
        locator=model.CorridorSubjectLocator(
            authority_id("view-corridor-locator"), entry.block_ref, entry.anchor_ea,
            (member0.block_ref, member1.block_ref),
            (member0.anchor_ea, member1.anchor_ea),
        ),
    )
    case = build_semantic_case(
        authority_id=authority_id("view-corridor-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(
                _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source"),
                entry, member0, member1, corridor,
            ),
        ),
    )
    with pytest.raises(ValueError, match="canonical evidence row"):
        views.corridor_coverage_rows(case)


def test_corridor_coverage_view_projects_an_accepted_phase_result() -> None:
    from .test_transaction_api import _full_corridor_fixture
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api

    source, plan, projected, gates = _full_corridor_fixture()
    inputs = transaction_api.derive_unflatten_preparation_inputs(
        source,
        CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan,
        plan.unflatten_proposal,
        gates,
    )
    case = build_semantic_case(
        authority_id=authority_id("view-full-corridor-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    view = views.corridor_coverage_rows(case)
    assert view.state is model.ObligationState.SATISFIED
    assert view.enumeration_complete
    assert view.covered_path_ids
    assert not view.residual_path_ids


def test_semantic_loss_ledger_and_observed_delta_are_closed_projections() -> None:
    assert tuple(model.SemanticLossKind) == (
        model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        model.SemanticLossKind.EQUIVALENT_SEMANTIC_ROUTE,
        model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT,
        model.SemanticLossKind.TERMINAL_CYCLE_BREAK,
        model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION,
        model.SemanticLossKind.DETACHED_DEAD_HANDLER_COMPONENT,
        model.SemanticLossKind.UNCLASSIFIED,
        model.SemanticLossKind.CONFLICTING,
    )
    assert callable(views.semantic_loss_ledger)
    assert callable(views.observed_only_loss)


def test_loss_rows_require_exact_source_binding_provenance() -> None:
    assert "source_binding" in model.SemanticLossRow.__dataclass_fields__
    assert "case" in model.SemanticLossRow.__dataclass_fields__
    assert "justifications" in model.SemanticLossRow.__dataclass_fields__


def test_loss_row_is_closed_over_its_parent_case() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "row-parent")
    case = build_semantic_case(
        authority_id=authority_id("row-parent"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    row = views.semantic_loss_ledger(case).rows[0]
    foreign = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "row-foreign")
    with pytest.raises(ValueError, match="exact case"):
        replace(row, source_subject=foreign)
    foreign_case = build_semantic_case(
        authority_id=authority_id("row-other"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    with pytest.raises(ValueError, match="exact case"):
        model.SemanticLossLedger(
            case=foreign_case,
            authority_id=foreign_case.authority_id,
            case_id=foreign_case.case_id,
            phase=foreign_case.phase,
            source_fingerprint=foreign_case.source_fingerprint,
            candidate_fingerprint=foreign_case.candidate_fingerprint,
            rows=(row,),
        )


def test_observed_delta_rejects_wrong_phase_before_comparing_rows() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "delta-phase")
    case = build_semantic_case(
        authority_id=authority_id("delta-phase"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    with pytest.raises(ValueError, match="observed case"):
        views.observed_only_loss(case, case)


def test_observed_delta_projects_kind_reclassification_without_observed_only_loss(
    monkeypatch,
) -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "kind-drift")
    projected_case = build_semantic_case(
        authority_id=authority_id("kind-drift"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    observed_case = build_semantic_case(
        authority_id=authority_id("kind-drift"),
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=_complete_inputs(
            source_subjects=(subject,), candidate_subjects=(),
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        ),
    )
    original_kind = model.SemanticLossRow.kind
    monkeypatch.setattr(
        model.SemanticLossRow,
        "kind",
        property(
            lambda row: (
                model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE
                if row.source_subject.subject_id == subject.subject_id
                and row.case.phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
                else model.SemanticLossKind.UNCLASSIFIED
                if row.source_subject.subject_id == subject.subject_id
                else original_kind.fget(row)
            )
        ),
    )

    projection = views.observed_loss_delta(projected_case, observed_case)

    assert projection.observed_only.rows == ()
    assert len(projection.reclassifications) == 1
    drift = projection.reclassifications[0]
    assert drift.anchored_location == "blk0@0x1000"
    assert drift.projected_kind is model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE
    assert drift.observed_kind is model.SemanticLossKind.UNCLASSIFIED
    assert drift.projected_evidence_ids
    assert drift.observed_evidence_ids
    with pytest.raises(ValueError, match="classification drift"):
        views.observed_only_loss(projected_case, observed_case)


def test_retirement_rows_rejects_empty_or_nonretirement_cases() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "retirement-empty")
    case = build_semantic_case(
        authority_id=authority_id("retirement-empty"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    with pytest.raises(ValueError, match="one unambiguous retirement claim"):
        views.retirement_rows(case)
