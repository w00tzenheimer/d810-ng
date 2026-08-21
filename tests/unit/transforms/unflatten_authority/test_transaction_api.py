"""Focused total route-selection tests for the transaction facade."""

from __future__ import annotations

from d810.transforms.plan import PatchPlan
from d810.transforms.unflatten_authority.model import (
    UnflattenAuthorityReason,
    UnflattenAuthorityNotApplicable,
    UnflattenPlanRoute,
)
from d810.transforms.unflatten_authority.transaction_api import select_plan_route

from .helpers import import_authority_model
from .test_model import _valid_proposal
from .test_proposal import _shadow


def _typed_plan() -> PatchPlan:
    model = import_authority_model()
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    return PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=proposal,
    )


def test_select_plan_route_is_total_and_has_disjoint_result_shapes() -> None:
    ordinary = select_plan_route(PatchPlan(plan_id="ordinary", snapshot_id="snap"))
    assert isinstance(ordinary, UnflattenAuthorityNotApplicable)
    assert ordinary.route is UnflattenPlanRoute.ORDINARY

    typed = select_plan_route(_typed_plan())
    assert typed.route is UnflattenPlanRoute.TYPED_PROPOSAL
    assert typed.proposal is not None
    assert typed.proposal.plan_id == _typed_plan().plan_id
    assert not isinstance(typed, UnflattenAuthorityNotApplicable)


def test_reserved_legacy_only_route_requires_explicit_adaptation() -> None:
    plan = PatchPlan(
        plan_id="legacy",
        snapshot_id="snap",
        metadata=(("use_def_severance_audit", {"clean": True}),),
    )
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.key == "use_def_severance_audit"
    assert result.detail_code == "legacy_metadata_requires_explicit_codec_adaptation"


def test_typed_plan_with_reserved_key_rejects_dual_authority() -> None:
    typed = _typed_plan().with_metadata(
        concrete_state_route_provenance=("legacy",)
    )
    result = select_plan_route(typed)
    assert result.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL
    assert result.key == "concrete_state_route_provenance"


def test_exact_shadow_is_allowed_but_mapping_lookalike_is_rejected() -> None:
    typed = _typed_plan()
    object.__setattr__(typed, "legacy_unflatten_shadow", _shadow(typed.plan_id))
    selected = select_plan_route(typed)
    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL

    forged = _typed_plan()
    object.__setattr__(forged, "legacy_unflatten_shadow", {"schema_version": 1})
    rejected = select_plan_route(forged)
    assert rejected.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert rejected.detail_code == "shadow_type_is_not_closed"


def test_shadow_plan_snapshot_and_generation_drift_rejects() -> None:
    for field, value, detail in (
        ("plan_id", "wrong-plan", "shadow_plan_id_mismatch"),
        ("snapshot_id", "wrong-snapshot", "shadow_snapshot_id_mismatch"),
    ):
        plan = _typed_plan()
        shadow = _shadow(plan.plan_id)
        if field == "plan_id":
            shadow = type(shadow)(1, value, shadow.snapshot_id, shadow.source_generation, shadow.entries)
        else:
            shadow = type(shadow)(1, shadow.plan_id, value, shadow.source_generation, shadow.entries)
        object.__setattr__(plan, "legacy_unflatten_shadow", shadow)
        result = select_plan_route(plan)
        assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
        assert result.detail_code == detail

    plan = _typed_plan()
    shadow = _shadow(plan.plan_id)
    object.__setattr__(plan, "legacy_unflatten_shadow", type(shadow)(
        1, shadow.plan_id, shadow.snapshot_id, 4, shadow.entries
    ))
    result = select_plan_route(plan)
    assert result.detail_code == "shadow_source_generation_mismatch"


def test_mapping_proposal_is_rejected_without_truthy_authority() -> None:
    plan = _typed_plan()
    object.__setattr__(plan, "unflatten_proposal", {"plan_id": plan.plan_id})
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_type_is_not_closed"
