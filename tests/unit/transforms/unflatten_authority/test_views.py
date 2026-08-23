"""Graph-free evaluator views."""

from __future__ import annotations

from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority import model
from .test_evaluate import _complete_inputs, _role_subject, authority_id
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
from d810.transforms.unflatten_authority.ids import _subject_factory
import pytest
from dataclasses import replace


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


def test_retirement_rows_rejects_empty_or_nonretirement_cases() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "retirement-empty")
    case = build_semantic_case(
        authority_id=authority_id("retirement-empty"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    with pytest.raises(ValueError, match="one unambiguous retirement claim"):
        views.retirement_rows(case)
