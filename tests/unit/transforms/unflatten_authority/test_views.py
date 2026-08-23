"""Graph-free evaluator views."""

from __future__ import annotations

from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority import model
from .test_evaluate import _complete_inputs, _role_subject, authority_id
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
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
